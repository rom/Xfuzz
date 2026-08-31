# ASR-0013: Corpus and format interoperability

- **Status:** Accepted
- **Priority:** Should
- **Date:** 2026-08-28
- **Source:** Design decision — hybrid corpus store with AFL export

## Requirement

Xfuzz must interoperate with the existing fuzzing ecosystem even though it shares
no code with it:

- **Import** AFL/AFL++-style corpus directories, libFuzzer corpus directories,
  AFL dictionaries (`.dict`), and existing seed sets.
- **Export** corpora and findings as AFL-style `queue/`, `crashes/`, `hangs/`
  directory trees usable by other tools.
- **Consume** existing harnesses: a `LLVMFuzzerTestOneInput`-style entry point
  must be fuzzable without rewriting it.
- **Speak** the AFL fork-server protocol so binaries instrumented by existing
  compilers can be driven by Xfuzz.
- **Import** external format descriptions rather than requiring every grammar to
  be authored from scratch.

## Rationale

Xfuzz is a novel engine (ADR-0001), but the world's seed corpora, dictionaries,
harnesses, and instrumented builds already exist and represent enormous sunk
effort. Requiring users to abandon them is a hard adoption barrier for no
architectural benefit. Interoperability at the *data and protocol* level costs
little and preserves independence at the *implementation* level.

## Architectural impact

- The corpus store's internal representation must be decoupled from any external
  layout; import/export are explicit adapters, never the storage model
  (which must serve queries and long-lived triage state — ASR-0011).
- Since inputs are structured (ASR-0014) but external corpora are flat bytes,
  every format needs a lossless "raw bytes" representation and a defined
  promotion path from raw to structured via a codec.
- Speaking the fork-server protocol constrains the executor's handshake and
  shared-memory layout to a documented, externally compatible format.
- Grammar importers (protobuf descriptors, ASN.1, ABNF, Kaitai, JSON Schema, and
  similar) are a plugin family, not core.

## Acceptance criteria

- An AFL corpus directory imports and fuzzes without conversion steps.
- Exported findings are consumable by standard external tooling.
- An existing libFuzzer-style harness runs under Xfuzz with a documented shim.
- Round-trip import/export of a corpus preserves every input byte-exactly.

## Satisfied by

ADR-0001, ADR-0005, ADR-0008, ADR-0031
