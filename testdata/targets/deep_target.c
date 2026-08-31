/*
 * deep_target — a bug at the bottom of one branch of a wide program.
 *
 * The target for directed fuzzing. Its shape is the one that makes direction
 * worth having: most of the program is reachable and uninteresting, the bug is
 * behind a chain of calls that only one input prefix enters, and a
 * coverage-guided campaign spends its budget proportionally — which means almost
 * all of it somewhere else.
 *
 * The wide part is deliberate. Twelve sibling branches, each with its own nested
 * work, give a coverage-guided campaign plenty of new edges to find that lead
 * nowhere near the bug. A directed campaign is told where to go and should
 * spend its budget on the one branch that gets there.
 *
 * XFUZZ-BUGS: 1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static void bug(int n) {
    fprintf(stderr, "XFUZZ-BUG-%d\n", n);
    fflush(stderr);
    abort();
}

/* The chain the bug sits at the bottom of. Each level is a separate function so
 * that the call graph has real depth for a distance map to measure along. */
__attribute__((noinline)) static void level4(const unsigned char *p, size_t n) {
    if (n >= 5 && p[4] == 0x7F) bug(1);
}
__attribute__((noinline)) static void level3(const unsigned char *p, size_t n) {
    if (n >= 4 && p[3] == 'D') level4(p, n);
}
__attribute__((noinline)) static void level2(const unsigned char *p, size_t n) {
    if (n >= 3 && p[2] == 'C') level3(p, n);
}
__attribute__((noinline)) static void level1(const unsigned char *p, size_t n) {
    if (n >= 2 && p[1] == 'B') level2(p, n);
}

/* The wide, uninteresting part: work that produces coverage and leads nowhere. */
__attribute__((noinline)) static void sibling(int which, const unsigned char *p, size_t n) {
    unsigned acc = which;
    for (size_t i = 1; i < n && i < 8; i++) {
        if (p[i] & 1) acc += p[i];
        else if (p[i] & 2) acc ^= p[i];
        else if (p[i] & 4) acc -= p[i];
        else acc *= 3;
    }
    if (acc == 0xDEAD) printf("sibling %d unlikely\n", which);
    printf("sibling %d %u\n", which, acc);
}

int main(void) {
    unsigned char b[64];
    size_t n = fread(b, 1, sizeof b, stdin);
    if (n < 1) return 0;

    if (b[0] == 'A') { level1(b, n); return 0; }

    /* Every other first byte lands in one of the siblings. */
    sibling(b[0] % 12, b, n);
    return 0;
}
