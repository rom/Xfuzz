# ADR-0008: Hybrid corpus store with AFL export

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0008, ASR-0011, ASR-0012, ASR-0013, ASR-0015

> **Amendment (v0.9).** The corpus gains an operation this record does not
> describe: **distillation**, which re-measures every entry and keeps the
> smallest subset that still reaches everything the corpus reached, dropping the
> rest. It is a different question from the favoured set — that asks which entry
> is the cheapest way to reach each feature and uses the answer to bias the
> schedule, leaving every entry in place — and it is what makes a day-old corpus
> something a person can read or hand to somebody else. Greedy set cover, which
> is within a logarithmic factor of optimal and takes milliseconds; deterministic
> by construction, because a corpus that distilled differently on each run would
> mean a resumed campaign fuzzing something other than its checkpoint describes.
> It is off unless `storage.distill_interval` asks for it, because it costs one
> execution per entry, and it refuses a campaign with no coverage: there would be
> nothing to compare, and dropping any entry would be dropping it at random.

## Context

The store must serve three uses with different access patterns:

1. **Hot path** — admit new corpus entries at high rates without stalling the
   fuzz loop.
2. **Query** — the console needs rich queries over findings and corpus (filter by
   bucket, triage state, coverage delta, discovery time) — ASR-0011, ASR-0012.
3. **Interoperability** — import and export AFL/libFuzzer directory layouts —
   ASR-0013.

Plus: bounded disk use, atomic checkpointing for resumability, and a versioned
on-disk schema (ASR-0015).

## Decision

A **hybrid store**: an embedded SQL database for metadata and indexes, a
content-addressed blob store for payloads, and directory import/export adapters
for interoperability.

- **Metadata** — embedded SQL (`modernc.org/sqlite`, pure Go, no cgo per
  ADR-0017): corpus entries, coverage summaries, findings, buckets, triage state,
  provenance, campaign checkpoints, audit log. Gives the console real queries for
  free and gives triage the mutable, long-lived records it needs.
- **Payloads** — content-addressed blobs on disk, keyed by digest, with
  compression and de-duplication. Large inputs stay out of the database; identical
  inputs cost storage once; the digest is a natural stable identity for
  provenance and replay (ASR-0008).
- **Interop adapters** — explicit import/export to AFL-style `queue/`,
  `crashes/`, `hangs/` trees and libFuzzer corpus directories, plus `.dict`
  import. Never the storage model — only an adapter over it.

The store is *not* on the hot path: only *interesting* inputs are written, which
is rare relative to execution rate. Writes are batched and asynchronous with
bounded buffers, and the fuzz loop never blocks on the store.

**Disk budgets** are first-class: per-campaign limits on corpus and findings
storage with a defined culling policy (corpus minimisation by coverage
redundancy; findings capped per bucket) when budgets are reached, and the culling
is reported rather than silent.

**Checkpointing** writes corpus frontier, scheduler state, per-worker RNG
position, and coverage state as one atomic transaction, so resume is consistent
(ASR-0012).

The on-disk schema carries a **version stamp**; a newer version fails to open
with an explicit error rather than corrupting state.

## Consequences

**Positive**

- The console gets expressive querying without a hand-rolled index layer.
- Triage state, bucketing, and re-bucketing (ASR-0011) are natural database
  operations rather than filesystem gymnastics.
- Content addressing gives de-duplication, integrity checking, and stable
  provenance identity in one mechanism.
- Embedded engines preserve single-artifact, air-gapped deployment (ASR-0015).

**Negative**

- Two storage subsystems to keep consistent; blob garbage collection against
  database references is a real correctness concern needing its own tests.
- SQLite has known write-concurrency limits; with N worker processes writing,
  writes must funnel through the daemon (which ADR-0003 already establishes) with
  WAL mode and batching.
- Pure-Go SQLite is slower than the cgo build; acceptable because the store is
  off the hot path, but it must be verified rather than assumed (ASR-0007).

**Neutral**

- AFL-layout compatibility is preserved as an adapter, so ecosystem
  interoperability costs nothing architecturally.

## Alternatives considered

- **AFL-compatible on-disk directories as the primary model.** Familiar and
  simple. Rejected: no query capability for the console, no place for triage
  state, poor at scale (hundreds of thousands of files in one directory), and no
  atomic checkpointing.
- **Embedded KV only (Pebble/bbolt).** Fast and simple. Rejected: every console
  query becomes a hand-rolled index, and triage/finding queries are exactly the
  workload a relational store handles well.
- **Everything in SQL, blobs included.** One subsystem. Rejected: large inputs in
  a database bloat it, slow backups, and complicate export.
