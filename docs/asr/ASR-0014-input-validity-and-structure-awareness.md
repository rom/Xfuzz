# ASR-0014: Input validity and structure awareness

- **Status:** Accepted
- **Priority:** Must
- **Date:** 2026-08-28
- **Source:** Product brief — "formats, grammar, mutations, corpus or generation"

## Requirement

Xfuzz must produce inputs that survive a target's *validation* layer often enough
to reach its *processing* layer, for formats and protocols with:

- length and count fields that must agree with actual content
- offsets and pointers that must resolve
- checksums, CRCs, hashes, and magic values
- tag/type/value dependencies and nested containers
- ordering and cardinality constraints

Both **mutation** of existing inputs and **generation** from a specification must
operate on the same representation, and the fuzzer must be able to *deliberately*
violate each constraint class to fuzz the validation code itself.

## Rationale

Byte-level mutation of a structured format spends nearly all executions being
rejected by a length check or a CRC in the first few instructions. This is the
single largest source of wasted throughput in practice, and it is why
grammar-aware fuzzing exists. But pure generation loses the value of a real-world
corpus. The requirement is therefore that structure and mutation be the same
mechanism, not competing modes — and, crucially, that constraint enforcement be
*optional per constraint*, since "the CRC is always right" would make checksum
validation code unfuzzable.

## Architectural impact

- Forces a typed, tree-structured **input IR** shared by mutators and generators,
  with byte blobs as the degenerate case rather than the base case.
- Requires **derived fields** (length-of, count-of, offset-of, checksum-over) to
  be modelled as first-class relationships and recomputed by a **fixup pass**
  after mutation — this is the mechanism that makes structured mutation viable.
- Fixups must be individually suppressible so the fuzzer can emit deliberately
  inconsistent inputs on a controlled fraction of executions.
- Requires bidirectional codecs (parse and serialise) so that real corpus files
  can be lifted into the IR and mutated structurally.
- Parsing must be **best-effort and partial**: real corpora contain malformed
  files, and a strict parser would reject exactly the interesting seeds. Unparsed
  regions must degrade to opaque byte nodes rather than failing the import.
- Requires an authoring path (native grammar DSL) *and* importers, plus tooling
  to develop grammars interactively — an unusable grammar language is equivalent
  to no grammar support.

## Acceptance criteria

- A structured campaign against a checksum-protected format achieves a
  substantially higher valid-input rate than byte-level mutation of the same
  corpus, measured and reported.
- Fixups can be disabled per-constraint, and doing so demonstrably reaches
  validation-failure code paths.
- Malformed corpus files import as partially structured inputs without error.
- Round-trip `parse → serialise` is byte-exact for unmutated inputs, enforced by
  property tests.

## Satisfied by

ADR-0005, ADR-0007, ADR-0010, ADR-0021
