# ADR-0018: Proprietary commercial license

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** — (business constraint with architectural consequences)

## Context

Xfuzz can be released as open source, source-available, open-core, or fully
proprietary. The choice is a business decision, but it imposes hard constraints
on dependency selection and on the ecosystem-interoperability strategy.

## Decision

**Xfuzz is proprietary commercial software. All rights reserved.**

- `LICENSE` carries a proprietary notice; there is no OSS licence grant.
- Source is closed. Distribution is by commercial agreement.

The architecturally binding consequence is **dependency licence hygiene**, which
must be enforced from the first commit rather than audited later:

| Class | Licences | Policy |
| --- | --- | --- |
| Allowed | Apache-2.0, MIT, BSD-2/3-Clause, ISC, Unlicense, Zlib | Permitted with attribution in `NOTICE` |
| Conditional | MPL-2.0 | Permitted only as an unmodified library |
| Forbidden | GPL-2.0/3.0, AGPL-3.0, LGPL (static linking), SSPL, BUSL | Never |

This is a live constraint, not a formality: much of the existing fuzzing
ecosystem is GPL-licensed — AFL++ and honggfuzz among them. ADR-0001's decision
to build a novel engine with no runtime dependency on those projects is therefore
also what keeps this licence position tenable. Interoperability is limited to
**data formats and wire protocols**, which carry no licence obligation.

Enforcement:

- `NOTICE` is the authoritative third-party inventory; every direct and
  transitive dependency appears there with its licence before it may be imported.
- CI runs a licence scan that fails the build on any forbidden or unknown licence
  (`docs/TESTS.md` § License compliance).
- Vendored or reimplemented algorithms from GPL sources are prohibited;
  reimplementation from published papers and specifications is the required path.

## Consequences

**Positive**

- Full commercial freedom over distribution and pricing.
- Dependency discipline is enforced mechanically from day one, when it is cheap,
  rather than discovered during a pre-release audit, when it is not.
- Reinforces ADR-0001's independence with a second, independent justification.

**Negative**

- No community contribution, external review, or ecosystem effect — for a
  security tool, external scrutiny has real value that is being given up.
- Adoption is harder: practitioners default to open tooling, and a proprietary
  fuzzer must demonstrably outperform free alternatives.
- Some attractive dependencies are unavailable, requiring reimplementation.
- Publishing research findings gets harder when the tool cannot be shared for
  reproduction.

**Neutral**

- The decision is reversible toward openness (proprietary → open) but not back;
  the dependency policy above is a superset of what any OSS licence would demand,
  so opening later stays possible.

## Alternatives considered

- **Commercial with source-available (BUSL-1.1 / Elastic-style).** Readable and
  self-hostable while restricting commercial use. Rejected for now; the closest
  alternative and the most likely future reconsideration.
- **Open core** — open engine and CLI, proprietary console and orchestration.
  Rejected: it would force an awkward split precisely through the daemon boundary
  (ADR-0003) that the architecture treats as unified.
- **Fully open source (Apache-2.0).** Best for adoption and scrutiny. Rejected on
  business grounds.
