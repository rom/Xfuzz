/*
 * nop — a target that does nothing.
 *
 * It exists to measure the floor: with this as the target, everything a
 * measurement reports is the fork server protocol and the fork itself, with no
 * work of the target's own mixed in. Comparing a real target against this is
 * how "the fuzzer is slow" gets separated from "the target is slow".
 *
 * XFUZZ-BUGS: 0
 */
int main(void) { return 0; }
