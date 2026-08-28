# ADR-0005: Unified structured input IR

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0001, ASR-0002, ASR-0013, ASR-0014

## Context

ASR-0014 requires inputs that survive validation layers — length fields,
checksums, offsets, tag/value dependencies — while ASR-0001 requires one engine
across file formats, protocol messages, API requests, and UI event sequences.
Conventional designs split here: byte-level mutational fuzzers and grammar-based
generators are separate tools with separate corpora, and neither alone is
adequate (mutation wastes throughput on rejected inputs; generation discards the
value of real-world corpora).

## Decision

Define a **single typed input IR** that both mutation and generation operate on.
An input is a tree of typed nodes:

| Node | Purpose |
| --- | --- |
| `Bytes` | Opaque byte run — the degenerate/unstructured case |
| `Int` | Integer with width, signedness, endianness |
| `Str` | Text with encoding and charset constraints |
| `Struct` | Ordered named fields |
| `Repeat` | Homogeneous sequence with cardinality bounds |
| `Choice` | Tagged alternation (grammar alternatives, union types) |
| `Opt` | Presence-optional subtree |
| `Ref` | Reference to another node by path |
| `Derived` | Value computed from other nodes |

`Derived` is the load-bearing element. It models `LengthOf`, `CountOf`,
`OffsetOf`, `ChecksumOver(alg, range)`, and user-defined relations. After any
mutation, a **fixup pass** recomputes derived nodes in dependency order, so a
structurally mutated input remains internally consistent and passes validation.

Each fixup is **individually suppressible**, with a configurable probability of
deliberate violation per constraint class. This is essential rather than
cosmetic: a fuzzer that always produces correct checksums can never test checksum
validation code.

Consequences of one IR across domains:

- A **file** is one IR tree.
- A **protocol message** is one IR tree; a **session** is a `Repeat` of them.
- A **stateless input** is a session of length one — so ASR-0002's two modes are
  one representation.
- A **UI interaction** is a `Repeat` of event nodes.
- An **unstructured blob** is a single `Bytes` node, so byte-level fuzzing is a
  special case of structured fuzzing, not a separate path (ASR-0013).

**Codecs** (`Encode`/`Decode`) lift real corpus files into the IR and serialise
back. Decoding is **best-effort and partial**: unparsed regions degrade to
`Bytes` nodes rather than failing, because real corpora are full of malformed
files and those are often the most valuable seeds.

**Schemas** describe formats and come from a native grammar DSL (`.xfg`) or from
importers (protobuf descriptors, ASN.1, ABNF, Kaitai Struct, JSON Schema,
OpenAPI). Importers are plugins (ADR-0010), not core.

Mutators are typed and dispatch on node kind: bit/byte-level operators on
`Bytes`, boundary-value and arithmetic operators on `Int`, alternative-switching
on `Choice`, insert/delete/reorder/duplicate on `Repeat`, and splice/crossover
between compatible subtrees across corpus entries.

## Consequences

**Positive**

- One corpus, one mutation engine, one scheduler across all domains and both
  state modes — the structural precondition for the whole product.
- Structure-aware mutation with automatic fixups is the single largest available
  throughput win on validating targets.
- Sequence-level mutation for stateful fuzzing is free: `Repeat` operators.
- Grammar-aware *generation* and corpus-driven *mutation* become the same
  mechanism over the same representation, and can be freely interleaved.

**Negative**

- Substantially more complex than `[]byte`. Every mutator, every codec, and the
  hot loop pay for it.
- Tree operations allocate; ASR-0007 demands an allocation-free steady state, so
  the IR requires arena/pool-backed nodes, copy-on-write subtrees, and careful
  benchmarking. This is the main performance risk in the design.
- Fixup ordering must handle cyclic and nested dependencies (a checksum over a
  region containing a length field) with a defined, tested resolution order.
- Codec correctness is critical and subtle; round-trip property tests are
  mandatory (ADR-0021).

**Neutral**

- Byte-level fuzzing remains available at near-zero overhead via single-`Bytes`
  inputs, so unstructured targets lose nothing.

## Alternatives considered

- **Mutation-first, grammar later.** Lower initial complexity. Rejected:
  retrofitting structure into a `[]byte` corpus means rewriting every mutator,
  the corpus, and the scheduler — the exact retrofit this ADR exists to avoid.
- **Grammar/generation-first.** High validity rates. Rejected: it makes real
  corpora second-class, and corpus-derived seeds are the most valuable input
  source in practice.
- **Bring-your-own codecs only.** Maximum flexibility, minimal core. Rejected: it
  pushes the hardest work onto users and yields no shared mutation intelligence
  across formats.
