/*
 * xfuzz-rt — the Xfuzz coverage runtime.
 *
 * This is the only C in the project, and it is compiled into the *target*,
 * never into Xfuzz itself (ADR-0017). It does three things:
 *
 *   1. Records edge coverage into a shared memory map the fuzzer reads.
 *   2. Runs a fork server, so the fuzzer can spawn a pre-initialised copy of
 *      the target instead of paying execve and dynamic linking on every input.
 *   3. Stays inert when no fuzzer is attached, so an instrumented binary is
 *      still an ordinary program you can run and debug by hand.
 *
 * It is deliberately small. Every line here runs inside the target on every
 * execution, and it has to be auditable by whoever agrees to link it into their
 * software.
 *
 * Build:
 *   clang -fsanitize-coverage=trace-pc-guard -c xfuzz-rt.c
 * or let cmd/xfuzz-cc do it.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>

/* Must match feedback.DefaultMapSize on the fuzzer side. */
#define XFUZZ_MAP_SIZE (1 << 16)

/* The comparison log. Must match feedback.CmpRegionSize and the record layout
 * in feedback.CmpRecord; a mismatch means the fuzzer reads a different table
 * than the target writes, and every operand it recovers is nonsense. */
#define XFUZZ_CMP_SIZE     (1 << 18)
#define XFUZZ_CMP_OPERAND  16
#define XFUZZ_CMP_ENTRIES  ((XFUZZ_CMP_SIZE - 16) / 40)

/* The inline-counter region, for a compiler whose instrumentation increments a
 * counter array rather than calling back. Must match feedback.CounterRegionSize.
 *
 * The first page is a header the fuzzer reads; the target's counter array is
 * mapped over the pages after it. See xfuzz_counters_init for why. */
#define XFUZZ_CNT_SIZE   (1 << 18)
#define XFUZZ_CNT_MAGIC  0x434E5432u /* "CNT2" */

/* The block trace, for directed fuzzing. Must match feedback.BlockRegionSize. */
#define XFUZZ_BB_SIZE    (1 << 20)
#define XFUZZ_BB_ENTRIES ((XFUZZ_BB_SIZE - 32) / 8)

/* Default control and status descriptors, matching AFL so that a binary built
 * against either runtime can be driven by either fuzzer (ASR-0013). Both are
 * overridable through the environment, because passing descriptor 198 through
 * Go's exec requires contortions that passing descriptor 3 does not. */
#define XFUZZ_DEFAULT_CTL_FD 198
#define XFUZZ_DEFAULT_ST_FD  199

/* Handshake word. The fuzzer checks it to distinguish a runtime that is present
 * from a target that happened to write four bytes to that descriptor.
 *
 * It also selects the protocol. AFL's fork server replies to each command with
 * the child pid immediately and the exit status later, which costs the fuzzer
 * two blocking reads — and therefore two goroutine parks — per execution. At a
 * few thousand executions a second that scheduling round trip is a large share
 * of the total. This runtime instead reports the pid and the status together,
 * once, and enforces the timeout inside the child, so the fuzzer blocks once. */
#define XFUZZ_HELLO 0x58465A32u /* "XFZ2" */

/* A local map used until (or unless) shared memory is attached, so an
 * instrumented binary run without a fuzzer neither crashes nor needs a
 * conditional on the hottest path in the program. */
static uint8_t xfuzz_local_map[XFUZZ_MAP_SIZE];

/* Declared early because the block trace publishes its address as the anchor a
 * fuzzer recovers the load base from. */
uint8_t *xfuzz_map(void);

uint8_t *__xfuzz_area = xfuzz_local_map;

/* The previous location, shifted. XOR-ing consecutive block identifiers turns
 * block coverage into edge coverage: it is the transition that carries the
 * information, not the arrival. Thread-local so that concurrent threads do not
 * interleave into fabricated edges. */
static __thread uint32_t xfuzz_prev_loc;

static uint32_t xfuzz_next_id = 1;

/* Spread a sequential counter across the map.
 *
 * Block identifiers must not be consecutive integers. The edge index is
 * prev_loc ^ loc with prev_loc = previous_loc >> 1, so small clustered
 * identifiers produce small clustered indices, and distinct edges collide.
 * That collision is invisible — coverage simply reports nothing new for an
 * input that genuinely went somewhere new — and it is exactly the failure a
 * fuzzer cannot diagnose from the outside. Measured on the planted-bug
 * targets, sequential identifiers made two different depths of a comparison
 * ladder indistinguishable; hashed identifiers separate them. */
static uint32_t xfuzz_spread(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    x *= 0x846CA68Bu;
    x ^= x >> 16;
    return x & (XFUZZ_MAP_SIZE - 1);
}

/* Called once per instrumented translation unit. Guards start at zero; the
 * runtime assigns each a non-zero identifier. */
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    if (start == stop || *start) return;
    for (uint32_t *p = start; p < stop; p++) {
        uint32_t id = xfuzz_spread(xfuzz_next_id++);
        /* Zero means "not instrumented", so step past it. */
        while (id == 0) id = xfuzz_spread(xfuzz_next_id++);
        *p = id;
    }
}

/*
 * The block trace.
 *
 * Coverage says whether an input went somewhere new. Directed fuzzing needs to
 * know whether it went somewhere *closer*, and that question cannot be answered
 * from the coverage map: the map holds hashed edge identities, and the distance
 * to a target is a property of an address. So a directed campaign asks for the
 * addresses themselves.
 *
 * One store and one increment per basic block executed, which is several times
 * what the coverage update costs and is why this is attached only when a
 * campaign asks for direction. The region is bounded and the overflow counted
 * rather than wrapped, for the same reason the comparison table is: the blocks
 * an execution runs first are the ones nearest its entry to the program.
 *
 * The addresses are where the code is loaded, which for a position-independent
 * binary is somewhere new on every run. The header carries the runtime address
 * of a known function so the fuzzer can subtract it from its link-time address
 * and recover the base — without which every execution would report a different
 * set of blocks for the same path.
 */
struct xfuzz_bb_hdr {
    uint32_t count;
    uint32_t capacity;
    uint32_t dropped;
    uint32_t reserved;
    uint64_t anchor; /* runtime address of xfuzz_map */
    uint64_t unused;
};

static struct xfuzz_bb_hdr *xfuzz_bb;
static uint64_t *xfuzz_bb_pcs;

/* Called on every instrumented basic block. This is the hottest code in the
 * system: a few instructions here multiply by billions of executions. */
void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    uint32_t loc = *guard;
    __xfuzz_area[(xfuzz_prev_loc ^ loc) & (XFUZZ_MAP_SIZE - 1)]++;
    xfuzz_prev_loc = loc >> 1;

    /* Inert unless a directed campaign attached the region: one load, one test
     * and a not-taken branch for every other campaign. */
    struct xfuzz_bb_hdr *h = xfuzz_bb;
    if (!h) return;
    if (h->count >= h->capacity) {
        h->dropped++;
        return;
    }
    xfuzz_bb_pcs[h->count++] = (uint64_t)(uintptr_t)__builtin_return_address(0);
}

/*
 * Comparison logging.
 *
 * A fuzzer that cannot get past `if (magic != 0xDEADBEEF)` is stuck behind a
 * one-in-four-billion guess, and no amount of mutation fixes that. What does
 * fix it is knowing what the comparison wanted: record both operands of every
 * comparison the program performs, and the fuzzer can find the value it
 * supplied in its own input and substitute the value the program expected.
 * That turns a four-byte magic number from a four-billion-to-one guess into a
 * single directed edit (ADR-0007).
 *
 * The same records answer a second question. A comparison that failed on one
 * byte out of four is closer to passing than one that failed on all four, and
 * treating "closer" as new coverage lets a campaign climb a comparison it
 * cannot jump. That is value profiling, and it needs exactly this data.
 *
 * The table is a flat array in a second shared region, written from the front
 * and truncated when full. Truncated rather than wrapped: the first comparisons
 * an execution performs are the ones nearest the input's entry to the program,
 * which is where a substitution is most likely to matter, and a wrap would
 * throw those away in favour of whatever a loop did ten thousand iterations
 * later.
 *
 * Everything here is inert unless a fuzzer attached the region. That is one
 * predictable branch per comparison in a target nobody is fuzzing, which is the
 * price of not needing two builds of the program.
 */

#define XFUZZ_CMP_INT 1 /* an integer comparison: operands are little-endian */
#define XFUZZ_CMP_MEM 2 /* a memory or string comparison: operands are bytes */

struct xfuzz_cmp_hdr {
    uint32_t count;    /* entries written */
    uint32_t capacity; /* entries the region can hold */
    uint32_t dropped;  /* entries lost because the table was full */
    uint32_t reserved;
};

struct xfuzz_cmp_rec {
    uint32_t loc;  /* the comparison's identity, spread across the table */
    uint8_t kind;  /* XFUZZ_CMP_INT or XFUZZ_CMP_MEM */
    uint8_t size;  /* bytes of each operand that are meaningful */
    uint16_t hit;  /* how many bytes matched, for a memory comparison */
    uint8_t a[XFUZZ_CMP_OPERAND];
    uint8_t b[XFUZZ_CMP_OPERAND];
};

static struct xfuzz_cmp_hdr *xfuzz_cmp;
static struct xfuzz_cmp_rec *xfuzz_cmp_recs;

/* Record one comparison. Returns immediately when no fuzzer is attached. */
static void xfuzz_cmp_log(uint8_t kind, uint8_t size, uint16_t hit,
                          const void *a, const void *b, uintptr_t pc) {
    struct xfuzz_cmp_hdr *h = xfuzz_cmp;
    if (!h) return;
    if (h->count >= h->capacity) {
        h->dropped++;
        return;
    }
    struct xfuzz_cmp_rec *r = &xfuzz_cmp_recs[h->count++];
    r->loc = xfuzz_spread((uint32_t)(pc ^ (pc >> 32)));
    r->kind = kind;
    r->size = size;
    r->hit = hit;
    if (size > XFUZZ_CMP_OPERAND) size = XFUZZ_CMP_OPERAND;
    memcpy(r->a, a, size);
    memcpy(r->b, b, size);
}

static void xfuzz_cmp_int(uint64_t a, uint64_t b, uint8_t size, uintptr_t pc) {
    /* Equal operands say nothing: the comparison already passed, and there is
     * nothing for the fuzzer to substitute or to get closer to. Skipping them
     * is most of what keeps the table from filling with a loop counter. */
    if (a == b) return;
    xfuzz_cmp_log(XFUZZ_CMP_INT, size, 0, &a, &b, pc);
}

/* The suffix on these callbacks is the operand width in *bytes*, not in bits:
 * __sanitizer_cov_trace_cmp1 compares two bytes' worth, cmp8 two eight-byte
 * words. Reading it as bits divides every width by eight, which makes a
 * four-byte comparison record a size of zero and an eight-byte one a size of
 * one — so the reader drops the narrow comparisons entirely and decodes the
 * wide ones as their lowest byte. Everything still compiles and runs; the
 * table simply arrives almost empty and the substitutions that would use it
 * never happen. */
#define XFUZZ_TRACE_CMP(bytes, type)                                           \
    void __sanitizer_cov_trace_cmp##bytes(type a, type b) {                    \
        xfuzz_cmp_int((uint64_t)a, (uint64_t)b, bytes,                         \
                      (uintptr_t)__builtin_return_address(0));                 \
    }                                                                          \
    void __sanitizer_cov_trace_const_cmp##bytes(type a, type b) {              \
        xfuzz_cmp_int((uint64_t)a, (uint64_t)b, bytes,                         \
                      (uintptr_t)__builtin_return_address(0));                 \
    }

XFUZZ_TRACE_CMP(1, uint8_t)
XFUZZ_TRACE_CMP(2, uint16_t)
XFUZZ_TRACE_CMP(4, uint32_t)
XFUZZ_TRACE_CMP(8, uint64_t)

/* A switch is a comparison against every one of its labels. Recording all of
 * them is what lets the fuzzer reach a case it has never taken: the label it
 * needs is in the table even though the program never compared against it in
 * any way a single comparison hook would see. */
void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {
    if (!xfuzz_cmp || !cases) return;
    uint64_t n = cases[0];
    uint64_t bits = cases[1];
    uint8_t size = (uint8_t)(bits / 8);
    if (size == 0 || size > 8) size = 8;
    for (uint64_t i = 0; i < n; i++) {
        xfuzz_cmp_int(val, cases[2 + i], size,
                      (uintptr_t)__builtin_return_address(0) + i);
    }
}

/* The memory-comparison hooks.
 *
 * These are called by the sanitizer runtime's interceptors, so they fire only
 * when the target was also built with a sanitizer. Defining them regardless
 * costs nothing and means a build that has one gets string and buffer
 * comparisons logged for free — which is where a format's magic bytes usually
 * live, as opposed to its integer fields.
 *
 * The matching prefix is recorded as well as the operands. A comparison that
 * matched three bytes of four is nearly right, and that is precisely the signal
 * value profiling turns into coverage. */
static uint16_t xfuzz_common_prefix(const uint8_t *a, const uint8_t *b, size_t n) {
    size_t i = 0;
    while (i < n && a[i] == b[i]) i++;
    return (uint16_t)(i > 0xFFFF ? 0xFFFF : i);
}

void __sanitizer_weak_hook_memcmp(void *pc, const void *a, const void *b,
                                  size_t n, int result) {
    if (!xfuzz_cmp || result == 0 || n == 0 || !a || !b) return;
    size_t size = n > XFUZZ_CMP_OPERAND ? XFUZZ_CMP_OPERAND : n;
    xfuzz_cmp_log(XFUZZ_CMP_MEM, (uint8_t)size,
                  xfuzz_common_prefix(a, b, size), a, b, (uintptr_t)pc);
}

void __sanitizer_weak_hook_strncmp(void *pc, const char *a, const char *b,
                                   size_t n, int result) {
    if (!xfuzz_cmp || result == 0 || !a || !b) return;
    size_t len = 0;
    while (len < n && len < XFUZZ_CMP_OPERAND && a[len] && b[len]) len++;
    if (len == 0) return;
    xfuzz_cmp_log(XFUZZ_CMP_MEM, (uint8_t)len,
                  xfuzz_common_prefix((const uint8_t *)a, (const uint8_t *)b, len),
                  a, b, (uintptr_t)pc);
}

void __sanitizer_weak_hook_strcmp(void *pc, const char *a, const char *b, int result) {
    if (!xfuzz_cmp || result == 0 || !a || !b) return;
    size_t len = 0;
    while (len < XFUZZ_CMP_OPERAND && a[len] && b[len]) len++;
    if (len == 0) return;
    xfuzz_cmp_log(XFUZZ_CMP_MEM, (uint8_t)len,
                  xfuzz_common_prefix((const uint8_t *)a, (const uint8_t *)b, len),
                  a, b, (uintptr_t)pc);
}

/*
 * Inline counters.
 *
 * Clang's trace-pc-guard gives the runtime a callback per block, so coverage
 * can be written straight into the shared map. Some compilers instrument
 * differently: Go's -d=libfuzzer increments a byte in an array of its own and
 * never calls anything, so there is no place to put a fold. The obvious answer
 * — copy the array into the map when the process exits — does not work for the
 * two cases that matter most. Go's runtime exits through the kernel and never
 * runs a C exit handler, and a target that crashes never reaches one either,
 * which loses the coverage of exactly the input worth keeping.
 *
 * So the array is not copied at all: the pages holding it are re-mapped onto
 * the shared region, and every increment the target performs lands directly in
 * memory the fuzzer can read. No fold, no exit hook, and a crash keeps its
 * coverage because the writes were never in this process's private memory.
 *
 * The remapping is page-granular, so it takes whatever else shares those pages
 * with it. That is safe in the direction that matters — the target still reads
 * and writes its own data normally, and the fuzzer simply does not look at the
 * bytes outside the counter range — and the page contents are saved and
 * restored around the mapping so nothing is lost.
 */
struct xfuzz_cnt_hdr {
    uint32_t magic;
    uint32_t offset; /* byte offset of counters[0] from the start of the region */
    uint32_t count;  /* how many counters the target registered */
    uint32_t failed; /* non-zero if the remapping did not take */
};

static struct xfuzz_cnt_hdr *xfuzz_cnt;

/* Called once per instrumented object with the bounds of its counter array. */
void __sanitizer_cov_8bit_counters_init(uint8_t *start, uint8_t *stop) {
    if (!start || start >= stop) return;

    const char *id = getenv("XFUZZ_CNT_ID");
    if (!id || !*id) return;
    int fd = open(id, O_RDWR);
    if (fd < 0) return;

    /* The header lives in the first page, which the counter mapping must not
     * cover — so the counters start one page into the region. */
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) { close(fd); return; }

    void *h = mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (h == MAP_FAILED) { close(fd); return; }
    xfuzz_cnt = (struct xfuzz_cnt_hdr *)h;
    xfuzz_cnt->magic = XFUZZ_CNT_MAGIC;
    xfuzz_cnt->count = (uint32_t)(stop - start);
    xfuzz_cnt->failed = 0;

    uintptr_t lo = (uintptr_t)start & ~(uintptr_t)(page - 1);
    uintptr_t hi = ((uintptr_t)stop + (uintptr_t)page - 1) & ~(uintptr_t)(page - 1);
    size_t len = (size_t)(hi - lo);
    /* From the start of the region, not from the start of the mapped pages, so
     * the fuzzer does not have to know the target's page size to find them. */
    xfuzz_cnt->offset = (uint32_t)((size_t)page + ((uintptr_t)start - lo));

    /* Only what fits. A target with more counters than the region holds gets
     * none rather than a truncated array the fuzzer would read as real. */
    if (len + (size_t)page > XFUZZ_CNT_SIZE) {
        xfuzz_cnt->failed = 1;
        close(fd);
        return;
    }

    void *save = malloc(len);
    if (!save) { xfuzz_cnt->failed = 2; close(fd); return; }
    memcpy(save, (void *)lo, len);

    void *m = mmap((void *)lo, len, PROT_READ | PROT_WRITE,
                   MAP_FIXED | MAP_SHARED, fd, page);
    if (m == MAP_FAILED) {
        xfuzz_cnt->failed = 3;
        free(save);
        close(fd);
        return;
    }
    memcpy((void *)lo, save, len);
    free(save);
    close(fd);
}

/* The PC table that accompanies the counters. Recorded rather than used: the
 * addresses would give a directed campaign what the block trace gives it for a
 * clang-instrumented target, and nothing reads them yet. */
void __sanitizer_cov_pcs_init(const uintptr_t *beg, const uintptr_t *end) {
    (void)beg;
    (void)end;
}

static int xfuzz_fd_from_env(const char *name, int fallback) {
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    long n = strtol(v, NULL, 10);
    if (n < 0 || n > 65535) return fallback;
    return (int)n;
}

/* Map a region the fuzzer published, or return NULL. */
static void *xfuzz_attach(const char *name, size_t size) {
    const char *id = getenv(name);
    if (!id || !*id) return NULL;

    int fd = open(id, O_RDWR);
    if (fd < 0) return NULL;

    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    return p == MAP_FAILED ? NULL : p;
}

/* Attach the shared coverage map, if the fuzzer published one. */
static void xfuzz_attach_map(void) {
    void *p = xfuzz_attach("XFUZZ_SHM_ID", XFUZZ_MAP_SIZE);
    if (p) __xfuzz_area = (uint8_t *)p;
}

/* Attach the comparison table, if the campaign asked for one.
 *
 * Separate from the coverage map and separately optional, because it is
 * separately expensive: a campaign that does not need it should not pay for the
 * writes, and one that does should not have to rebuild the target to get them.
 * The capacity is published by the target rather than assumed by the fuzzer, so
 * that a target built against an older runtime is read correctly instead of
 * being read past its end. */
/* Attach the block trace, if a directed campaign asked for one. */
static void xfuzz_attach_bb(void) {
    void *p = xfuzz_attach("XFUZZ_BB_ID", XFUZZ_BB_SIZE);
    if (!p) return;
    xfuzz_bb = (struct xfuzz_bb_hdr *)p;
    xfuzz_bb_pcs = (uint64_t *)((uint8_t *)p + sizeof(struct xfuzz_bb_hdr));
    xfuzz_bb->capacity = XFUZZ_BB_ENTRIES;
    xfuzz_bb->count = 0;
    xfuzz_bb->dropped = 0;
    xfuzz_bb->anchor = (uint64_t)(uintptr_t)&xfuzz_map;
}

static void xfuzz_attach_cmp(void) {
    void *p = xfuzz_attach("XFUZZ_CMP_ID", XFUZZ_CMP_SIZE);
    if (!p) return;
    xfuzz_cmp = (struct xfuzz_cmp_hdr *)p;
    xfuzz_cmp_recs = (struct xfuzz_cmp_rec *)((uint8_t *)p + sizeof(struct xfuzz_cmp_hdr));
    xfuzz_cmp->capacity = XFUZZ_CMP_ENTRIES;
    xfuzz_cmp->count = 0;
    xfuzz_cmp->dropped = 0;
}

/*
 * The fork server.
 *
 * The saving is that everything before this point — dynamic linking, static
 * initialisers, whatever the program does at startup — happens once instead of
 * once per input. For a target that links a few shared libraries that is most
 * of its runtime, which is why this tier reaches thousands of executions a
 * second where one-exec-per-input reaches hundreds.
 *
 * The parent loops here forever. Each forked child returns, falls out of the
 * constructor, and proceeds into main as an ordinary program.
 */
static void xfuzz_fork_server(void) {
    int ctl = xfuzz_fd_from_env("XFUZZ_CTL_FD", XFUZZ_DEFAULT_CTL_FD);
    int st  = xfuzz_fd_from_env("XFUZZ_ST_FD",  XFUZZ_DEFAULT_ST_FD);

    uint32_t hello = XFUZZ_HELLO;
    /* If nobody is listening, this fails and the program runs normally. That is
     * what keeps an instrumented binary usable by hand. */
    if (write(st, &hello, 4) != 4) return;

    for (;;) {
        /* The command word is the per-execution timeout in milliseconds, or
         * zero for none. Carrying it here rather than having the fuzzer watch
         * the clock is what lets the child police its own deadline. */
        uint32_t timeout_ms;
        ssize_t n = read(ctl, &timeout_ms, 4);
        if (n != 4) _exit(0); /* the fuzzer went away */

        pid_t pid = fork();
        if (pid < 0) _exit(1);
        if (pid == 0) {
            /* The child does not need the control channel, and holding it open
             * would stop the fuzzer ever seeing end-of-file. */
            close(ctl);
            close(st);
            if (timeout_ms) {
                /* SIGALRM terminates by default, so a target that loops is
                 * killed by the kernel rather than by the fuzzer noticing
                 * later. The status then shows signal 14, which the fuzzer
                 * reads as a timeout rather than a crash. */
                struct itimerval it;
                it.it_value.tv_sec = timeout_ms / 1000;
                it.it_value.tv_usec = (timeout_ms % 1000) * 1000;
                it.it_interval.tv_sec = 0;
                it.it_interval.tv_usec = 0;
                setitimer(ITIMER_REAL, &it, 0);
            }
            return;
        }

        int status;
        while (waitpid(pid, &status, 0) < 0) {
            /* Interrupted by a signal; keep waiting. */
        }

        /* The pid and the status go back together, in one write. The fuzzer
         * therefore blocks exactly once per execution. The pid is still sent
         * because it is what lets the fuzzer clean up if it ever has to give up
         * on a child the timer did not reach. */
        uint32_t reply[2];
        reply[0] = (uint32_t)pid;
        reply[1] = (uint32_t)status;
        if (write(st, reply, sizeof reply) != (ssize_t)sizeof reply) _exit(1);
    }
}

static int xfuzz_started;

/*
 * Start the runtime.
 *
 * Called automatically before main. A target that does expensive setup inside
 * main can call xfuzz_manual_init() after that setup instead, so the fork
 * server snapshots the initialised state — the "deferred" mode, worth a large
 * multiple on targets that parse configuration or build tables at startup.
 */
void xfuzz_manual_init(void) {
    if (xfuzz_started) return;
    xfuzz_started = 1;
    xfuzz_attach_map();
    xfuzz_attach_cmp();
    xfuzz_attach_bb();
    if (getenv("XFUZZ_FORKSERVER")) xfuzz_fork_server();
}

__attribute__((constructor(101))) static void xfuzz_auto_init(void) {
    if (getenv("XFUZZ_DEFER_INIT")) return;
    xfuzz_manual_init();
}

/* Exposed for tests and for a harness that wants to inspect its own coverage. */
uint8_t *xfuzz_map(void) { return __xfuzz_area; }
unsigned xfuzz_map_size(void) { return XFUZZ_MAP_SIZE; }
unsigned xfuzz_cmp_capacity(void) { return XFUZZ_CMP_ENTRIES; }
unsigned xfuzz_cmp_count(void) { return xfuzz_cmp ? xfuzz_cmp->count : 0; }
