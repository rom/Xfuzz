/*
 * simple_parser — three shallow planted bugs.
 *
 * Format:
 *   byte 0     opcode
 *   byte 1     length
 *   byte 2..   payload
 *
 * Every bug is guarded by a distinct condition, so finding one says nothing
 * about finding the others, and a fuzzer that reaches all three has genuinely
 * explored the input space rather than got lucky once.
 *
 * XFUZZ-BUGS: 3
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void bug(int n) {
    /* An unambiguous fault. See testdata/targets/README.md for why these are
     * explicit rather than left for a sanitizer to notice. */
    fprintf(stderr, "XFUZZ-BUG-%d\n", n);
    fflush(stderr);
    abort();
}

static void parse(const unsigned char *data, size_t len) {
    if (len < 2) return;

    unsigned char op = data[0];
    unsigned char declared = data[1];
    const unsigned char *payload = data + 2;
    size_t avail = len - 2;

    switch (op) {
    case 'A': {
        /* Bug 1: the declared length is trusted over the actual one. Reachable
         * from any input starting with 'A' and a large second byte, so a
         * fuzzer that mutates the first two bytes at all should find it. */
        char buf[16];
        if (declared > sizeof(buf)) bug(1);
        memcpy(buf, payload, declared < avail ? declared : avail);
        if (buf[0] == 'z') printf("A-z\n");
        break;
    }

    case 'B': {
        /* Bug 2: a division whose divisor comes from the input. Needs the
         * opcode and one specific payload byte, so it is a step deeper than
         * bug 1 and rewards keeping an input that reached the 'B' branch. */
        if (avail < 2) return;
        int divisor = payload[0];
        int value = payload[1];
        if (payload[0] == 0 && payload[1] == 0xFF) bug(2);
        if (divisor != 0) printf("B-%d\n", value / divisor);
        break;
    }

    case 'C': {
        /* Bug 3: a ladder of four byte comparisons, reachable one step at a
         * time. Random mutation alone will not hit it; coverage guidance
         * keeping each partial match is what makes it reachable, which is
         * precisely what this bug is here to measure.
         *
         * The constants are 16, 32, 64 and 127 — boundary values a byte-level
         * mutator produces deliberately rather than by chance. That is the
         * calibration this target needs: it is the *shallow* one, and its job
         * is to check that coverage guidance can climb a ladder at all.
         *
         * An earlier version used 0x30 for the third step. It is not a boundary
         * value, so reaching it meant a one-in-fourteen-thousand guess against a
         * corpus entry that mutation had grown to fifty-five bytes — and the
         * campaign reliably climbed two steps and stalled. That is a real and
         * interesting limit, but it belongs to magic_parser: it is what
         * comparison logging (v0.3) and corpus trimming (M4) exist to solve, not
         * what basic coverage guidance is expected to do.
         *
         * The volatile store between the steps is load-bearing. Without it the
         * optimiser folds the comparisons into a single test, and the four
         * bytes become one 32-bit magic value: coverage then reports nothing
         * new until all four are right at once, and no amount of guidance
         * helps. That collapse is real and worth knowing about — it is why
         * comparison logging exists, and it is scheduled for v0.3 — but a
         * target meant to test ladder-walking has to actually be a ladder. */
        static volatile int stage;
        if (avail < 4) return;
        if (payload[0] != 16) return;
        stage = 1;
        if (payload[1] != 32) return;
        stage = 2;
        if (payload[2] != 64) return;
        stage = 3;
        if (payload[3] == 127) bug(3);
        printf("C-partial-%d\n", stage);
        break;
    }

    default:
        break;
    }
}

int main(void) {
    static unsigned char buf[1 << 16];
    size_t len = fread(buf, 1, sizeof(buf), stdin);
    parse(buf, len);
    return 0;
}
