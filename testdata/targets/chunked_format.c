/*
 * chunked_format — five bugs behind per-chunk checksums.
 *
 * This is the target for triage rather than for discovery. Every bug sits
 * behind a CRC-32 that covers the chunk it is in, so byte-level mutation cannot
 * reach any of them: change the payload and the checksum no longer matches;
 * change the checksum and the payload is no longer the one that triggers the
 * bug. Reaching them needs a structured input with a derived checksum field —
 * which is the whole argument for the IR (ADR-0005), stated as a target instead
 * of as a claim.
 *
 * What it is calibrated for is bucketing. Five bugs, on five distinct paths,
 * ending in three different signals:
 *
 *   bug 1  SIGABRT   an oversized chunk with a marker byte
 *   bug 2  SIGABRT   an out-of-range table index
 *   bug 3  SIGABRT   four depth chunks in a row
 *   bug 4  SIGFPE    division by a zero divisor
 *   bug 5  SIGSEGV   a null dereference
 *
 * A bucketing strategy that groups on the signal alone must find three buckets
 * here, not five. That is the point: it makes the difference between signal
 * bucketing and coverage bucketing measurable rather than asserted.
 *
 * Layout:
 *   "XCHK"                  magic
 *   u8                      version, must be 1
 *   chunk*                  until the input is exhausted
 *
 *   chunk:
 *     u32be tag
 *     u32be length
 *     u8[length] payload
 *     u32be crc              CRC-32 (IEEE) over tag, length, and payload
 *
 * XFUZZ-BUGS: 5
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define TAG_SIZE 0x53495A45u /* "SIZE" */
#define TAG_IDXT 0x49445854u /* "IDXT" */
#define TAG_DPTH 0x44505448u /* "DPTH" */
#define TAG_MATH 0x4D415448u /* "MATH" */
#define TAG_PTRV 0x50545256u /* "PTRV" */

#define MAX_CHUNKS 64
#define MAX_PAYLOAD 4096

static void bug(int n) {
    fprintf(stderr, "XFUZZ-BUG-%d\n", n);
    fflush(stderr);
    abort();
}

static uint32_t be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* CRC-32 (IEEE), the reflected table-less form. It has to be exactly the
 * algorithm the grammar's crc32() computes, or the gate is unopenable rather
 * than merely hard, and the target would be measuring nothing. */
static uint32_t crc32_ieee(const unsigned char *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int k = 0; k < 8; k++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1)));
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

/* volatile so the compiler cannot fold the division away at -O2 and quietly
 * delete bug 4. */
static volatile uint32_t sink;

static void handle_size(const unsigned char *payload, uint32_t len) {
    /* Bug 1: a chunk that declares itself large and starts with a marker.
     * Shallow once the checksum can be recomputed, which makes it the check
     * that the checksum gate is actually being opened. */
    if (len >= 64 && payload[0] == 0xFF) bug(1);
}

static void handle_idxt(const unsigned char *payload, uint32_t len) {
    /* Bug 2: an index into a fixed table, unchecked at the top end. The classic
     * shape, and one a length-aware mutator reaches by pushing a field to its
     * boundary rather than by luck. */
    static unsigned char table[192];
    if (len < 3) return;
    uint16_t idx = (uint16_t)((payload[0] << 8) | payload[1]);
    if (idx >= sizeof(table)) bug(2);
    table[idx] = payload[2];
    sink = table[idx];
}

static void handle_math(const unsigned char *payload, uint32_t len) {
    /* Bug 4: division by zero. A different fatal signal from the aborts, so a
     * signal-only bucketing strategy can tell this one apart and a coverage
     * strategy has something to agree with. */
    if (len < 8) return;
    uint32_t numerator = be32(payload);
    uint32_t divisor = be32(payload + 4);
    if (numerator > 0x1000u) {
        fprintf(stderr, "XFUZZ-BUG-4\n");
        fflush(stderr);
        sink = numerator / divisor;
    }
}

static void handle_ptrv(const unsigned char *payload, uint32_t len) {
    /* Bug 5: a null dereference behind a two-byte gate. */
    if (len < 2) return;
    if (payload[0] == 0x2A && payload[1] == 0x2B) {
        unsigned char *p = NULL;
        fprintf(stderr, "XFUZZ-BUG-5\n");
        fflush(stderr);
        *p = 1;
    }
}

static void parse(const unsigned char *data, size_t len) {
    if (len < 5) return;
    if (memcmp(data, "XCHK", 4) != 0) return;
    if (data[4] != 1) return;

    size_t off = 5;
    int chunks = 0;
    int depth_run = 0;

    while (off + 12 <= len && chunks < MAX_CHUNKS) {
        uint32_t tag = be32(data + off);
        uint32_t declared = be32(data + off + 4);

        /* A length that does not fit is a truncated file, not a bug. Rejecting
         * it here rather than reading past the end is what keeps the target's
         * own bugs the only bugs it has. */
        if (declared > MAX_PAYLOAD) return;
        if (off + 12 + (size_t)declared > len) return;

        const unsigned char *payload = data + off + 8;
        uint32_t claimed = be32(data + off + 8 + declared);
        uint32_t actual = crc32_ieee(data + off, 8 + (size_t)declared);

        /* The gate. Everything below is unreachable without a checksum that
         * agrees with the bytes it covers. */
        if (claimed != actual) return;

        chunks++;
        off += 12 + (size_t)declared;

        if (tag == TAG_DPTH) {
            depth_run++;
            /* Bug 3: four consecutive depth chunks, each with a valid checksum.
             * Reaching it needs the repeat-structure mutators — duplicating a
             * subtree — and the fixup pass to re-derive four checksums. */
            if (depth_run >= 4) bug(3);
            continue;
        }
        depth_run = 0;

        switch (tag) {
        case TAG_SIZE: handle_size(payload, declared); break;
        case TAG_IDXT: handle_idxt(payload, declared); break;
        case TAG_MATH: handle_math(payload, declared); break;
        case TAG_PTRV: handle_ptrv(payload, declared); break;
        default: break;
        }
    }
}

int main(void) {
    static unsigned char buf[1 << 16];
    size_t len = fread(buf, 1, sizeof(buf), stdin);
    parse(buf, len);
    return 0;
}
