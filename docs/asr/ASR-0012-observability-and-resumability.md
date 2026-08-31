# ASR-0012: Observability and resumability

- **Status:** Accepted
- **Priority:** Must
- **Date:** 2026-08-28
- **Source:** Derived — campaigns run for days and must be interrogable and interruptible

## Requirement

1. **Live metrics** — executions/s, coverage, corpus size, findings, stability,
   engine overhead, per-mutator yield, per-state progress, worker health.
2. **Historical series** — metrics retained over the campaign's life to show
   coverage-over-time and detect plateaus.
3. **Resumability** — a campaign survives daemon restart, host reboot, and
   deliberate pause, resuming from its persisted corpus and progress.
4. **Introspection** — the operator can answer "why is this slow / why is
   coverage flat / which feedback admitted this seed / which mutator is paying
   off" from the tool itself.
5. **Export** — metrics exportable to Prometheus/OpenTelemetry; events to
   structured logs.

## Rationale

A fuzzing campaign is a long-running experiment whose most common failure mode is
silent: it runs for a week, looks busy, and achieves nothing because the harness
rejected every input, the target restarts on each execution, or coverage
instrumentation was never active. Observability is what converts that invisible
failure into a diagnosis. Resumability is what makes multi-day campaigns
practical.

## Architectural impact

- Requires a **persistent campaign state model** with atomic checkpointing;
  corpus, coverage frontier, scheduler state, and RNG position must all be
  restorable together and consistently.
- Statistics must be aggregated hierarchically (per-worker → per-campaign) with
  bounded, downsampled retention — an unbounded metric history is a memory leak.
- The event stream needs a defined delivery contract (at-most-once, downsampled,
  lossy-by-design for high-rate events) so the UI cannot back-pressure the engine.
- Per-mutator and per-feedback accounting must be cheap enough to leave on
  permanently (counters, not traces).
- Health diagnostics ("stability is 40 %", "0 % of inputs reach the harness",
  "coverage map is empty") must be first-class, surfaced automatically rather
  than inferred by the operator.

## Acceptance criteria

- Killing the daemon mid-campaign and restarting loses at most a configurable
  bounded window of progress and never corrupts the corpus.
- The console shows coverage-over-time and per-mutator yield for a live campaign.
- Common misconfigurations are detected and reported as named diagnostics.
- Metrics scrape endpoint and structured-log output are documented.

## Satisfied by

ADR-0003, ADR-0008, ADR-0011, ADR-0024, ADR-0029
