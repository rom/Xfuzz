// Package store persists corpora, coverage, findings, and audit records.
//
// Hybrid by design: embedded SQL for metadata and indexes (so the console gets
// real queries and triage gets mutable long-lived records), plus a
// content-addressed blob store for payloads (so large inputs stay out of the
// database, identical inputs cost storage once, and the digest doubles as
// stable provenance identity).
//
// The store is off the hot path: only interesting inputs are written. Writes
// are batched and asynchronous, disk budgets are enforced with reported
// culling, and checkpoints are atomic across corpus, scheduler, coverage, and
// RNG position.
//
// See docs/adr/ADR-0008-hybrid-corpus-store-with-afl-export.md.
package store
