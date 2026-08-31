# ADR-0031: An imported grammar is a documented subset with a report

- **Status:** Accepted
- **Date:** 2026-08-31
- **Serves:** ASR-0001, ASR-0009, ASR-0013

## Context

[ADR-0005](ADR-0005-unified-structured-input-ir.md) makes structured
mutation the engine's default and a grammar the thing that unlocks it. But
writing a grammar for a real format takes hours, so a fuzzer whose structured
mode requires one runs unstructured against almost every target it meets.

The descriptions already exist. A standard carries its ABNF in the RFC that
defines it; a few hundred binary formats have a Kaitai definition somebody wrote
for a hex editor; a service has a `.proto`; an API has an OpenAPI document; a
protocol has an ASN.1 module. Reading those is the difference between structured
fuzzing being a feature people use and one they mean to get around to.

Every one of those languages can express things the Xfuzz grammar cannot, and
some can express things nothing can generate. So the question is not whether to
import but what an import is allowed to claim.

## Decision

**An importer returns two things, always both: a schema and a report of
everything it could not translate, with the reason.** A converter that silently
dropped what it could not handle would produce a grammar that looks complete and
generates inputs a parser rejects at the first field, and the campaign would
spend its budget discovering that. The report is what makes the feature
trustworthy, and `xfuzz grammar import` prints it to standard error so the
grammar can be redirected and the limits still read.

**Six importers, each a documented subset**: ABNF (RFC 5234 with RFC 7405's case
markers), Kaitai Struct, JSON Schema, OpenAPI, Protocol Buffers, and ASN.1 in
its DER encoding. Where a source language has a construct with no counterpart,
the importer emits the nearest generatable shape and records what was lost —
never a shape that looks right and is not.

**The line is between description and predicate.** A size bound translates,
because this language has size bounds. A *value* constraint does not: `INTEGER
(1..255)`, `minimum: 100` and a regular expression are predicates, and a
generator honouring one would be a constraint solver. Those are reported.

**Variable-length integers are the largest single gap and are named as such.**
Protobuf's varints and DER's long-form lengths are integers whose width depends
on their value, and the schema language has only fixed-width ones. Both importers
generate the one-byte form — exact for every value below 128, which covers most
of what a real message carries — bound their payloads so nested structures stay
inside it, and report the limit. Constants are exact at any size: a protobuf key
and a DER tag are fixed by the declaration, so their encodings are computed once
and written as immutable literals.

**A description usually has more than one entry point and a schema has one
root.** Unreachable types stay in the grammar and are reported rather than
dropped, and `Reroot` picks another; dropping them would throw away most of an
RFC, and leaving them silently would let somebody fuzz the wrong entry point and
never know.

**Every import is checked three ways in test**: the schema validates, it
survives being rendered and re-parsed by the tool's own grammar parser, and it
generates a non-empty input through the real generator and fixup path. The last
is what catches an importer whose every construct was legal and whose output no
decoder accepts.

## Consequences

**Positive**

- Structured fuzzing becomes available for a target whose format somebody has
  already described, which is most of them, at the cost of one command.
- The report makes the grammar's coverage a number rather than an impression, so
  a person can decide whether to hand-write the missing part.
- The importers are ordinary Go over an existing schema type, so nothing
  downstream — the codec, the mutators, the fixup pass — knows an import
  happened.

**Negative**

- Six parsers for six languages, each of which will meet documents this subset
  does not cover. Each is self-fuzzed for that reason (ADR-0021).
- An imported grammar is usually worse than a hand-written one, and the report
  is the only thing stopping that from being invisible.
- Protobuf and ASN.1 grammars are bounded to small messages by the varint gap.
  Closing it means a variable-width integer in the IR, which touches the
  encoder, the fixup pass and every mutator.

**Neutral**

- An importer is deterministic by construction — every map is iterated in sorted
  order — because a grammar that differed between two imports of one document
  would break campaign reproducibility before a campaign had started (ASR-0008).

## Alternatives considered

- **Generate a codec rather than a grammar.** More faithful: a codec can parse
  the varints a grammar cannot generate. Rejected as the first step because a
  codec is code, and generating code makes the output unreviewable and the
  failure modes compile errors rather than reports.
- **Import at campaign time rather than to a file.** Fewer steps. Rejected: the
  output is the artefact somebody edits, and hiding it means the parts an
  importer could not translate are never fixed by hand.
- **One universal intermediate format that everything converts through.**
  Rejected: the six languages disagree about what a format *is* — a byte layout,
  a value grammar, a message schema, an HTTP surface — and the intermediate
  would be either the union of all of them or the intersection, which is empty.
