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

/* Called on every instrumented basic block. This is the hottest code in the
 * system: a few instructions here multiply by billions of executions. */
void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    uint32_t loc = *guard;
    __xfuzz_area[(xfuzz_prev_loc ^ loc) & (XFUZZ_MAP_SIZE - 1)]++;
    xfuzz_prev_loc = loc >> 1;
}

static int xfuzz_fd_from_env(const char *name, int fallback) {
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    long n = strtol(v, NULL, 10);
    if (n < 0 || n > 65535) return fallback;
    return (int)n;
}

/* Attach the shared coverage map, if the fuzzer published one. */
static void xfuzz_attach_map(void) {
    const char *id = getenv("XFUZZ_SHM_ID");
    if (!id || !*id) return;

    int fd = open(id, O_RDWR);
    if (fd < 0) return;

    void *p = mmap(NULL, XFUZZ_MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (p != MAP_FAILED) __xfuzz_area = (uint8_t *)p;
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
    if (getenv("XFUZZ_FORKSERVER")) xfuzz_fork_server();
}

__attribute__((constructor(101))) static void xfuzz_auto_init(void) {
    if (getenv("XFUZZ_DEFER_INIT")) return;
    xfuzz_manual_init();
}

/* Exposed for tests and for a harness that wants to inspect its own coverage. */
uint8_t *xfuzz_map(void) { return __xfuzz_area; }
unsigned xfuzz_map_size(void) { return XFUZZ_MAP_SIZE; }
