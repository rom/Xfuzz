/*
 * hang — a target that loops forever on a specific input.
 *
 * It exists to check that a timeout is actually enforced rather than merely
 * configured. A fuzzer that cannot stop a looping target stops with it.
 *
 * XFUZZ-BUGS: 0 (a hang is a finding, but not a crash)
 */

#include <stdio.h>

int main(void) {
    unsigned char buf[64];
    size_t len = fread(buf, 1, sizeof buf, stdin);
    if (len > 0 && buf[0] == 'H') {
        volatile unsigned long spin = 0;
        for (;;) spin++;
    }
    return 0;
}
