// Package ir defines the unified structured input representation that every
// Xfuzz mutator and generator operates on.
//
// An input is a tree of typed nodes. A file is one tree; a protocol message is
// one tree; a session is a Repeat of them; a stateless input is a session of
// length one. An unstructured blob is a single Bytes node, so byte-level
// fuzzing is a special case of structured fuzzing rather than a separate path.
//
// Derived nodes (LengthOf, CountOf, OffsetOf, ChecksumOver) are recomputed by a
// fixup pass in dependency order after every mutation, which is what allows
// structural mutation to produce inputs that survive a target's validation
// layer. Each fixup is individually suppressible so that validation code is
// itself fuzzable.
//
// Constraints:
//   - Must not import pkg/executor: the core must not know how inputs are
//     delivered.
//   - Steady-state mutation must not allocate; nodes come from an Arena with
//     copy-on-write subtrees.
//
// See docs/adr/ADR-0005-unified-structured-input-ir.md.
package ir
