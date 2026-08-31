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

`go.mod` declares a floor and no patch component. Go 1.26 or later is required
to build Xfuzz.

The toolchain directive is left to Go's own management: a developer below the
floor gets the newer toolchain downloaded automatically on first build, which is
the mechanism Go provides for exactly this and needs no special handling here.

### Amended 2026-08-31: the floor moves, and it carries no patch

Two things were wrong with the original, and both were found by `govulncheck` on
the first CI run this project ever completed.

**CI derived its toolchain from the floor.** The Neutral note below is real and
was the mechanism: CI read the version from `go.mod`, `actions/setup-go`
installed exactly what it found, and `GOTOOLCHAIN=local` forbade upgrading past
it. So every job built on `go1.25.0`, the release cut a year earlier.
govulncheck reported **27 standard-library vulnerabilities reachable from this
code** — in `crypto/tls`, `crypto/x509`, `net/http`, `net/url`,
`encoding/asn1`, `encoding/pem` — each `Found in: go1.25`, each `Fixed in:` a
1.25 patch that CI was structurally unable to reach.

Dropping the patch component is *not* the fix, which is worth writing down
because it was the first thing tried. `go 1.26` resolves to `go1.26.0` — the
**oldest** patch of that line, not the newest; verified by running the build,
which downloaded exactly `go1.26.0`. A floor cannot self-patch, because a floor
is a minimum and the minimum is what a resolver picks.

So the two roles are now separated. **`go.mod` states the minimum** a builder
needs and nothing more. **CI builds and tests on `stable`**, so the toolchain
under test carries current fixes and govulncheck sees a patched standard
library; the release workflow does the same, so shipped binaries do too. One
job — `floor` — still reads go.mod, because a floor nothing exercises is a
number that happens to be written down rather than a claim.

**And the floor still had to move.** Go supports the two most recent major
releases; with 1.27 current, 1.25 is out of support and will take no further
security fixes. Moving to the newest *patched 1.25* would have cleared today's
27 findings and left the project on a line that gets no more — trading a gate
that fails for one that is silent. 1.26 is the oldest supported line, so it is
the least disruptive floor that is still maintained.

This is now a standing obligation rather than a one-off: when Go's support
window moves, this floor moves with it, and `govulncheck` in CI is what says
when.

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
- A floor is now a maintenance commitment: it expires when Go's support window
  moves past it, and leaving it stale ships known-vulnerable standard library
  code to everyone who builds from source.

**Neutral**

- The floor is stated in `README.md` beside the build instructions. CI reads it
  from `go.mod` in the `floor` job only; every other job runs on `stable`, for
  the reason in the amendment above.

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
