/*
 * escape — a target that tries to get out.
 *
 * The other targets in this directory measure whether the fuzzer can find bugs.
 * This one measures whether the sandbox holds, which is the other half of the
 * claim: a fuzzer that finds bugs and lets its targets out is not a tool anybody
 * can run.
 *
 * Every mode here is a real failure mode, not a synthetic one. Targets under
 * fuzzing write outside their directory, fork without bound, allocate without
 * bound, and — once someone is fuzzing a parser that runs as root — try
 * privileged syscalls. Each mode prints what happened and exits non-zero when
 * it was stopped, so a test can tell "blocked" from "the program did not run".
 *
 * It is deliberately not instrumented and has no planted bugs: it is not a
 * fuzzing target, it is the thing the sandbox is pointed at.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/types.h>

static int write_outside(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) {
        printf("blocked errno=%d %s\n", errno, strerror(errno));
        return 3;
    }
    if (fputs("escaped\n", f) < 0 || fclose(f) != 0) {
        printf("blocked errno=%d %s\n", errno, strerror(errno));
        return 3;
    }
    printf("wrote %s\n", path);
    return 0;
}

/* Forks until the kernel refuses. A contained target reaches its limit in the
 * low hundreds; an uncontained one would take the host down, so the loop stops
 * itself at a bound far above any plausible limit and reports that it was never
 * contained. */
static int fork_bomb(void) {
    int made = 0;
    for (;;) {
        pid_t p = fork();
        if (p < 0) {
            printf("blocked forks=%d errno=%d %s\n", made, errno, strerror(errno));
            return 3;
        }
        if (p == 0) {
            /* Children hold their slot briefly and leave. They must not fork
             * themselves: the point is to exhaust the limit, not the host. */
            usleep(400000);
            _exit(0);
        }
        if (++made >= 4000) {
            printf("unbounded forks=%d\n", made);
            return 0;
        }
    }
}

/* Allocates and touches memory until the allocator or the OOM killer stops it.
 * Touching matters: a cgroup limit counts resident pages, and an allocation
 * that is never written costs nothing. */
static int exhaust_memory(unsigned long long cap_mb) {
    const size_t block = 8u << 20;
    unsigned long long total = 0;
    for (;;) {
        char *p = malloc(block);
        if (!p) {
            printf("blocked allocated=%llu\n", total);
            return 3;
        }
        memset(p, 1, block);
        total += block;
        if (total >= cap_mb * 1024ull * 1024ull) {
            printf("unbounded allocated=%llu\n", total);
            return 0;
        }
    }
}

/* Calls a syscall the denylist names. It is called directly rather than through
 * a libc wrapper so that what is tested is the filter and not glibc's opinion. */
static int privileged_syscall(void) {
    long r = syscall(SYS_mount, "none", "/mnt", "tmpfs", 0UL, NULL);
    if (r < 0) {
        printf("blocked errno=%d %s\n", errno, strerror(errno));
        return 3;
    }
    printf("mounted\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: escape MODE [arg]\n");
        return 2;
    }
    const char *mode = argv[1];

    if (!strcmp(mode, "identity")) {
        printf("uid=%d gid=%d\n", (int)getuid(), (int)getgid());
        return 0;
    }
    if (!strcmp(mode, "write-outside")) {
        return write_outside(argc > 2 ? argv[2] : "/xfuzz-escaped");
    }
    if (!strcmp(mode, "fork-bomb")) {
        return fork_bomb();
    }
    if (!strcmp(mode, "memory")) {
        return exhaust_memory(argc > 2 ? strtoull(argv[2], NULL, 10) : 4096);
    }
    if (!strcmp(mode, "privileged-syscall")) {
        return privileged_syscall();
    }
    if (!strcmp(mode, "cwd")) {
        char buf[4096];
        if (!getcwd(buf, sizeof buf)) { perror("getcwd"); return 1; }
        printf("cwd=%s\n", buf);
        return 0;
    }
    fprintf(stderr, "escape: unknown mode %s\n", mode);
    return 2;
}
