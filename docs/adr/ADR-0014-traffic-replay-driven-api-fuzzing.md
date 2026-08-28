# ADR-0014: Traffic-replay-driven API fuzzing

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0001, ASR-0002, ASR-0010

## Context

API fuzzing (REST, GraphQL, gRPC) can be seeded from a **specification**
(OpenAPI, GraphQL introspection, protobuf descriptors) or from **captured
traffic** (HAR, pcap, proxy recordings).

Specifications are convenient but frequently absent, stale, or incomplete — and
the endpoints missing from the spec are disproportionately the interesting ones.
Captured traffic reflects what the API *actually does*, including undocumented
endpoints, real authentication material, and real inter-request data
dependencies.

## Decision

Make **captured traffic the primary seed source** for API fuzzing.

- **Capture sources**: HAR files, pcap, an Xfuzz recording proxy (HTTP/HTTPS with
  operator-supplied CA), and gRPC transcripts.
- **Lift** captured requests into the IR (ADR-0005): method, path, query, headers,
  and body decode into a typed tree, with unrecognised bodies degrading to
  `Bytes`. Content-type-aware codecs handle JSON, form encoding, multipart, and
  protobuf.
- **Sessions**, not isolated requests: a capture is an ordered sequence, so it
  becomes an IR `Repeat` — the same representation as a protocol session
  (ADR-0006). This preserves the login → create → use → delete structure that
  makes API bugs reachable.
- **Data dependencies** are inferred from the capture by value correlation:
  a value appearing in one response and a later request becomes a `Ref`, so a
  mutated session still chains correctly (a created id flows into the request
  that uses it).
- **Auth material** is recognised and, by default, **held fixed and redacted at
  rest** — fuzzing a bearer token yields nothing but 401s, and captured
  credentials are exactly the sensitive data ASR-0010 requires care with.
- **Oracles** go beyond crashes: 5xx responses, schema violations against
  observed response shapes, latency outliers, and — because captures carry
  identity — **authorization oracles**: replaying an identity-A session with
  identity-B credentials and flagging success is how BOLA/IDOR classes are found.

Specification import (OpenAPI/GraphQL/gRPC reflection) is **not rejected** — it
becomes an additional grammar importer feeding the same IR, layered on later
(ADR-0010, ADR-0020). Traffic is what v1 is designed around.

## Consequences

**Positive**

- Works against undocumented, internal, and legacy APIs — the common case in real
  engagements.
- Real captures carry valid auth, correct sequencing, and realistic values, so
  the effective input-validity rate starts high with no grammar authoring.
- Data-dependency inference makes mutated sequences stay coherent, which is what
  separates useful API fuzzing from a 400-response generator.
- Identity-aware oracles reach authorization logic flaws, a class pure crash
  fuzzing cannot see.

**Negative**

- Requires the operator to *have* traffic; a fresh API with no captured usage has
  a cold-start problem that spec import would solve. This is the main cost of the
  decision, and the reason spec import remains on the roadmap.
- Coverage is bounded by what the capture exercised — unused endpoints stay
  unfuzzed, so capture completeness becomes an operator responsibility that must
  be surfaced in the console.
- Captures routinely contain credentials, tokens, and personal data, making
  redaction, at-rest handling, and export controls mandatory rather than optional.
- Correlation-based dependency inference produces false positives that must be
  reviewable and overridable.

**Neutral**

- Because everything lands in the shared IR, adding spec import later changes the
  seed source only, not the engine.

## Alternatives considered

- **Spec-driven with stateful sequences.** Strong when a spec exists. Rejected as
  primary: specs are frequently absent or stale, and operation chaining must then
  be *guessed* rather than observed. Deferred to a later phase as a second seed
  source.
- **Spec-driven, stateless.** Much simpler. Rejected: it misses the entire class
  of sequence- and state-dependent API bugs, violating ASR-0002.
- **Both, equally, in v1.** Most complete. Rejected only on scope; the
  architecture keeps the path open.
