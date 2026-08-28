# ADR-0019: Module path and repository identity

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** — (project convention)

## Context

The Go module path appears in every import statement in the project and is
expensive to change once code exists. The repository is
`https://github.com/rom/Xfuzz`.

Note that Go module paths are **case-sensitive**, even though GitHub URLs are
not. A module declared as `github.com/rom/xfuzz` against a repository named
`Xfuzz` produces a mismatch that surfaces as confusing resolution failures with
the module proxy (which case-escapes uppercase letters as `!x`).

## Decision

- **Module path:** `github.com/rom/Xfuzz` — matching the repository name exactly,
  including capitalisation.
- **Product name:** Xfuzz.
- **Binaries:** `xfuzz` (CLI), `xfuzzd` (daemon), `xfuzz-cc` (compiler wrapper),
  `xfuzz-rt` (target runtime, a C artifact).
- **Go package names** are lowercase per Go convention (`engine`, `ir`, `corpus`);
  only the module path carries the capital.
- Public API surface lives under `pkg/`; everything else under `internal/` so it
  is not importable and stays free to change.

Since the repository is private and the module is proprietary (ADR-0018), the
path functions as an identity rather than a public download location; matching
the repository name keeps tooling — `go mod`, IDEs, private proxies — working
without special configuration.

## Consequences

**Positive**

- `go get`, module proxies, and IDE resolution work without configuration.
- No later rename of every import statement.
- `internal/` boundaries let the architecture evolve without breaking any
  consumer.

**Negative**

- The capital `X` is easy to mistype and will produce occasional confusing
  errors; documentation and examples must be consistent.
- Migrating to a vanity path later would still be a repository-wide change,
  though a straightforward mechanical one.

**Neutral**

- A vanity domain (`xfuzz.io/xfuzz`) remains available later if the product is
  ever published; it would require a `go-import` meta endpoint.

## Alternatives considered

- **`github.com/rom/xfuzz` (lowercase).** Rejected: mismatches the repository
  name and creates module-proxy case-escaping confusion.
- **Vanity domain path.** Host-independent and more product-like. Rejected for
  now: it needs a domain and a hosted meta endpoint for no present benefit on a
  private repository.
- **Bare `xfuzz`.** Fine for a never-imported binary. Rejected: it breaks any
  future use as a library and confuses tooling.
