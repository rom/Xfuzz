// Package tracer implements the T5 backends: ways of watching a native binary
// run when nothing can be asked of the program itself.
//
// Three of them, from ADR-0002, and they differ in what they depend on rather
// than in what they produce. ptrace-bb needs only the kernel and plants trap
// instructions at block starts recovered by static analysis. qemu needs
// user-mode emulation installed and reads the translation blocks it reports.
// frida needs the Frida tooling installed and reads the coverage its Stalker
// agent writes.
//
// All three answer the same question — which basic blocks did this execution
// enter — and pkg/executor folds that answer into a coverage map identically
// whichever produced it. That is the point of having an interface here: a
// corpus is not portable between backends, but the engine above them cannot
// tell which one is running.
//
// Availability is probed, never assumed. A backend whose external tool is
// missing says so before a campaign starts, with the name of what is missing,
// rather than producing empty coverage that looks like a target with no
// branches.
//
// See docs/adr/ADR-0002-pluggable-multi-backend-instrumentation.md and
// docs/adr/ADR-0009-tiered-executors.md.
package tracer
