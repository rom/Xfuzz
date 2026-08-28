/*
 * magic_parser — four bugs behind magic values.
 *
 * This is the target that says whether a fuzzer can get past a comparison
 * against a constant. Random mutation essentially never produces a four-byte
 * magic number: at one in four billion per attempt, a campaign would need
 * longer than it will ever run. Getting here requires a dictionary now, and
 * comparison logging or value profiling later, which is the point of keeping a
 * target whose bugs are unreachable by mutation alone.
 *
 * Layout:
 *   "XFZ!"          header, required for anything below
 *   u8  section
 *   ...             section-specific
 *
 * XFUZZ-BUGS: 4
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

static uint32_t be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void parse(const unsigned char *data, size_t len) {
    /* The header gates everything. Four bytes, but they are in every dictionary
     * a user would write for this format, which is exactly the point. */
    if (len < 5) return;
    if (memcmp(data, "XFZ!", 4) != 0) return;

    unsigned char section = data[4];
    const unsigned char *body = data + 5;
    size_t avail = len - 5;

    switch (section) {
    case 1:
        /* Bug 1: one byte past the header. Cheap once the header is known,
         * which makes it the check that the header was actually reached. */
        if (avail >= 1 && body[0] == 0x41) bug(1);
        break;

    case 2:
        /* Bug 2: a second four-byte magic. Two independent magics in sequence,
         * so a dictionary has to supply both. */
        if (avail >= 4 && be32(body) == 0xDEADBEEFu) bug(2);
        break;

    case 3: {
        /* Bug 3: a length field that must agree with the actual payload. This
         * is the one structured mutation with fixup handles naturally and
         * byte-level mutation does not. */
        if (avail < 3) return;
        uint16_t declared = (uint16_t)((body[0] << 8) | body[1]);
        size_t actual = avail - 2;
        if (declared == actual && actual >= 8 && body[2] == 0x7F) bug(3);
        break;
    }

    case 4: {
        /* Bug 4: a checksum over the body must be correct. Unreachable by
         * mutation of the body alone, because changing the body invalidates the
         * checksum; it needs either a schema that knows to recompute it or a
         * solver that can invert it. */
        if (avail < 5) return;
        uint32_t claimed = be32(body);
        uint32_t sum = 0;
        for (size_t i = 4; i < avail; i++) sum = sum * 31u + body[i];
        if (claimed == sum && avail >= 12) bug(4);
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
