# ADR-0029: Direction is block distance, measured over a recovered graph

- **Status:** Accepted
- **Date:** 2026-08-31
- **Serves:** ASR-0004, ASR-0008, ASR-0012

## Context

[ADR-0007](ADR-0007-composable-feedback-pipeline.md) makes directed fuzzing a
composition — `Any(MapFeedback, DistanceFeedback(targets))` with a
distance-weighted schedule — and records under its negative consequences that
"directed mode requires an offline distance-map analysis artifact with a
lifecycle, cache, and staleness rule against the target binary". It does not say
what distance is measured over, where the runtime measurement comes from, or what
happens when the artifact cannot be built.

Those are the questions that decide whether directed fuzzing works or merely
appears to. Every failure in this feature has the same shape: the campaign runs
perfectly, reports progress, and steers nowhere.

## Decision

**Distance is the number of basic blocks to the nearest target along the
interprocedural control-flow graph recovered by `pkg/binary`**, computed once by
a single breadth-first search backwards from the targets. Backwards, so one
traversal answers the question for every block rather than a search per
execution. Edges are intra-procedural successors plus an edge from a block that
calls a function to that function's entry; a call does not end a block, so that
one edge covers both the call and the return.

**Targets are named in whichever form the evidence came in**: a function name, a
`file.c:123` from a patch, or an address from a crash report. Requiring the
address form would mean an operator disassembling their own binary before they
could start. Each form fails differently and each failure says what to do next —
an unresolvable address usually came from a different build, an unresolvable
function was stripped or inlined, an unresolvable line was optimised away.

**Three refusals, rather than three silent degradations.** A target address
inside no recovered block is refused: that is the staleness rule ADR-0007 asks
for, in the form that actually catches the mistake. Targets with no predecessors
in the recovered graph are refused: nothing could be measured as getting closer
to them. And a campaign may require a minimum share of the program to be able to
reach its target at all, because direction measured over five per cent of a
binary is not direction — it is every input scoring the same, which looks exactly
like a directed campaign that has not made progress yet.

**Block addresses come from two places and the feedback does not care which.** A
tier that watches the process reports them already, so directed fuzzing works
against a binary nobody can rebuild — which is where it is most wanted. An
instrumented build writes them into a third shared region, and the runtime
publishes the address of a known symbol so the load base can be recovered.
`pkg/feedback` reaches the distances through a two-method interface, so the core
does not depend on binary analysis and a campaign can supply distances from
somewhere else entirely.

**An address is resolved to its containing block, not matched exactly.** Almost
nothing reports a block by its first address: the runtime reports the return
address of its own callback, and a tracer reports wherever its breakpoint or
translation unit began.

**A seed's distance is the mean over the executed blocks that have one.** Blocks
with no route to a target are excluded rather than scored as far — an execution
that spent its time in unrelated code should not look worse than one that barely
ran. An execution where *nothing* had a distance reports the maximum, not zero:
the score is normalised with zero meaning *at* the target, so reporting nothing
as zero would tell the schedule that an input which never came near the target
had arrived at it.

**The schedule is weighted, at a fixed moderate factor.** A distance feedback
decides which inputs to keep; without a schedule that spends more of the budget
on them, a corpus of ten thousand entries of which four are near the target gives
those four a four-in-ten-thousand share of the machine. AFLGo anneals this
weight, starting undirected and tightening over time; time is exactly what
ASR-0008 forbids as a fuzzing input, so the weight is constant.

## Consequences

**Positive**

- Directed fuzzing composes with the binary-only tier rather than competing with
  it: the case where a patch has to be exercised in a binary nobody can rebuild
  is the one both features were built for.
- The artifact's quality is reported rather than assumed. How many blocks reach a
  target, out of how many were recovered, and how far the furthest is, all go in
  the ready message — because a coverage number cannot show that the direction
  behind it was meaningless.
- Reproducibility is preserved. Every input to the weighting is derived from the
  corpus, not from the clock.

**Negative**

- Recovery is partial in the ways static analysis always is: an indirect branch
  contributes no edges, so a target reachable only through a computed call has a
  distance map covering almost nothing. That is why the minimum-reachability
  refusal exists and why the reachable fraction is reported.
- The distance is an upper bound on the true one, since missing edges can only
  make a block look further away.
- The block trace costs a store per basic block executed, several times what the
  coverage update costs. It is attached only for directed campaigns.
- A mean over reachable blocks is coarse when few blocks are reachable. It is
  still the right shape: a minimum would be dominated by whichever single block
  happened to be nearest and would stop distinguishing inputs as soon as any of
  them reached the target's function.

## Alternatives considered

- **AFLGo's two-level approximation** — call-graph distance between functions,
  combined harmonically with intra-procedural distance to call sites. Rejected:
  it exists because the compiler pass has function-level and block-level
  information separately, and `pkg/binary` recovers one interprocedural graph
  directly, where a single search is both simpler and exact with respect to the
  graph it has.
- **Instrumenting distance into the target**, as AFLGo does, so the target
  accumulates a distance rather than reporting addresses. Faster per execution.
  Rejected: it requires a compiler pass, ties the artifact to the build rather
  than to the binary, and makes directed fuzzing unavailable for exactly the
  targets that need it most — the ones that cannot be rebuilt.
- **Annealing the schedule weight over time**, as AFLGo does. Rejected on
  ASR-0008: a campaign whose seed selection depends on elapsed time does not
  reproduce, and reproducibility is worth more here than the last increment of
  convergence speed.
