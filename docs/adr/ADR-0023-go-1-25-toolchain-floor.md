# ADR-0023: Go 1.25 as the toolchain floor

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0015

## Context

[ADR-0008](ADR-0008-hybrid-corpus-store-with-afl-export.md) chose `modernc.org/sqlite` for the metadata
store, and [ADR-0017](ADR-0017-pure-go-core-cgo-behind-build-tags.md) requires the
default build to work with `CGO_ENABLED=0`. That combination is the reason the
store exists at all in a single static binary: `modernc.org/sqlite` is SQLite
transpiled to Go rather than bound to it.

Its dependency chain — `modernc.org/libc`, itself a translation of musl — sets
`go 1.25.0` in its module file. Go's module resolution is transitive on that
directive, so the choice is between pinning an old SQLite release, vendoring, or
adopting the floor.

Pinning does not work. The last `modernc.org/sqlite` release declaring `go 1.24`
depends on a `modernc.org/libc` that declares `go 1.25.0`, so the pin buys
nothing but an older SQLite with older fixes.

## Decision

`go.mod` declares `go 1.25.0`. Go 1.25 or later is required to build Xfuzz.

The toolchain directive is left to Go's own management: a developer on 1.24 gets
the newer toolchain downloaded automatically on first build, which is the
mechanism Go provides for exactly this and needs no special handling here.

## Consequences

**Positive**

- The store uses a current SQLite with current fixes, in a build that still needs
  no C compiler.
- One floor rather than a pin that would have to be revisited on every dependency
  update.

**Negative**

- Distributions shipping Go 1.24 cannot build Xfuzz from source without a
  toolchain download, which needs network access at first build.
- The floor is set by a transitive dependency rather than by anything Xfuzz uses,
  which is an uncomfortable place for a constraint to come from. It is recorded
  here so that it is visible rather than discovered.

**Neutral**

- The floor is stated in `README.md` beside the build instructions, and CI reads
  it from `go.mod` rather than repeating it.

## Alternatives considered

- **Pin `modernc.org/sqlite` to a Go 1.24-compatible release.** Rejected: no such
  release exists once its own dependencies are resolved.
- **Vendor and patch the `go` directives.** Rejected: it makes every dependency
  update a manual merge, for a constraint that costs nothing to accept.
- **Replace the SQL store with a bespoke on-disk format.** Rejected: ADR-0008's
  reasoning stands — the console needs real queries and triage needs mutable
  long-lived records, and writing a query engine to avoid a toolchain floor is a
  poor trade.
- **Use a cgo SQLite binding.** Rejected outright by ADR-0017.
