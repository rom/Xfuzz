// Package binary reads an executable and recovers enough structure to fuzz it
// without its source.
//
// Three things, in increasing order of ambition: where the code is (ELF, PE and
// Mach-O, on any host, for any of them), where one instruction ends and the next
// begins (an x86-64 length decoder), and where the basic blocks and the calls
// between them are (recursive descent from every entry point the file names).
//
// That is the whole basis of the binary-only path. The T5 tier needs block
// addresses to put breakpoints on; directed fuzzing needs a call graph and
// intra-procedural control flow to measure distance along. Both come from here,
// so both agree about what a block is.
//
// It is deliberately not a disassembler. Nothing here renders an instruction,
// names a register, or resolves an operand. Length and control flow are what the
// fuzzer needs, they are the two things that can be recovered reliably from
// stripped code, and stopping there is what keeps this a file you can audit
// rather than a table generator.
//
// Recovery from stripped code is inherently partial: data in the text section,
// jump tables, and hand-written assembly all defeat it in ways that cannot be
// detected from inside. Every result therefore carries its own confidence, and
// callers are expected to degrade rather than to trust.
//
// See docs/adr/ADR-0002-pluggable-multi-backend-instrumentation.md.
package binary
