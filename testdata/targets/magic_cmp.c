/*
 * magic_cmp — comparisons a fuzzer cannot guess, and nothing else.
 *
 * A target for the comparison-logging path specifically. Every branch here is
 * an equality test against a constant wide enough that random mutation will
 * never produce it: at one chance in four billion per attempt for the 32-bit
 * gate and one in eighteen quintillion for the 64-bit one, a campaign without
 * comparison logging does not reach the bug in any run that will ever finish.
 *
 * That is the point. The bug is not hidden behind depth or behind structure —
 * it is hidden behind exactly the thing input-to-state substitution exists to
 * defeat, so a campaign that reaches it did so because the substitution worked.
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

static uint32_t le32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t le64(const unsigned char *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

static void parse(const unsigned char *data, size_t len) {
    /* One length check, up front, for all three gates.
     *
     * Deliberately not one per gate. With a check before each, trimming shrinks
     * a corpus entry to exactly the length the gate it satisfied needs — the
     * shorter input covers the same code, which is what trimming is for — and
     * the next gate is then unreachable until mutation happens to grow the
     * input again without disturbing the twelve bytes in front of it. The
     * campaign then stalls for a reason that has nothing to do with the
     * comparison it is supposed to be testing, and the target stops measuring
     * what it exists to measure. */
    if (len < 14) return;

    /* A 32-bit gate. Guessing it takes four billion attempts; reading it out of
     * the comparison log and writing it back takes one. */
    if (le32(data) != 0xC0FFEE01u) return;
    printf("gate1\n");

    /* A 64-bit one behind it, so a campaign that got past the first by luck
     * cannot get past the second the same way. */
    if (le64(data + 4) != 0x0123456789ABCDEFull) return;
    printf("gate2\n");

    /* And a 16-bit tail, so the narrower widths are exercised too. */
    uint16_t tail = (uint16_t)(data[12] | (data[13] << 8));
    if (tail != 0xBEEF) return;
    bug(1);
}

int main(int argc, char **argv) {
    unsigned char buf[256];
    size_t n = 0;
    if (argc > 1) {
        FILE *f = fopen(argv[1], "rb");
        if (!f) return 1;
        n = fread(buf, 1, sizeof buf, f);
        fclose(f);
    } else {
        n = fread(buf, 1, sizeof buf, stdin);
    }
    parse(buf, n);
    return 0;
}
