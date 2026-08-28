# ASR-0015: Operability and deployment

- **Status:** Accepted
- **Priority:** Should
- **Date:** 2026-08-28
- **Source:** Derived — the tool must be deployable where the targets are

## Requirement

1. **Single-artifact deployment** — a self-contained binary per platform with the
   web console embedded, no runtime dependency on a language runtime, database
   server, or network-fetched asset.
2. **Air-gap capable** — full functionality with no outbound internet access.
3. **Container- and CI-friendly** — runs headless, non-interactive, with
   machine-readable output and meaningful exit codes.
4. **Bounded resource use** — disk, memory, and file-descriptor consumption are
   configurable and enforced; a long campaign must not fill the disk unattended.
5. **Upgrade safety** — on-disk state is versioned, with migration or a clear
   refusal, never silent corruption.

## Rationale

Fuzzing runs where targets run: locked-down lab hosts, offline networks,
short-lived CI containers. A tool needing a package manager at install time, a
database service, or a CDN for its UI is a tool that will not be deployed in the
environments where it is most needed. Unbounded disk growth is the classic way a
week-long campaign dies at day three.

## Architectural impact

- The web console must build to static assets embedded at compile time
  (`embed.FS`), with no external font, script, or style fetches at runtime.
- Storage must be an **embedded** engine, ruling out any client/server database.
- Requires explicit disk-budget accounting in the corpus and findings stores,
  with a defined eviction/culling policy when budgets are reached.
- CI mode requires a bounded, non-interactive execution model: run until a
  time/exec/coverage budget is exhausted, emit a machine-readable report, and
  exit with a code reflecting findings — which makes "campaign termination
  conditions" a core config concept rather than an afterthought.
- On-disk schema needs a version stamp and a migration path from first release.

## Acceptance criteria

- A single downloaded binary runs a campaign and serves the console on a host
  with no internet access and no other software installed.
- A CI campaign honours its budget, writes a report, and exits non-zero when new
  findings appear.
- Disk budgets are enforced; exceeding them culls per policy and is reported.
- Opening state from a newer version fails with an explicit version error.

## Satisfied by

ADR-0003, ADR-0008, ADR-0011, ADR-0015, ADR-0016, ADR-0017, ADR-0023
