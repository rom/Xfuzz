# ADR-0035: The campaign learns the protocol before it fuzzes it

- **Status:** Accepted
- **Date:** 2026-08-31
- **Serves:** ASR-0002, ASR-0004, ASR-0008

## Context

[ADR-0006](ADR-0006-explicit-state-machine-with-state-feedback.md) chose an
explicit state machine with state feedback, and deferred active automata
learning by name — saying it warrants its own record. This is that record.

What it deferred is a different use of the same executions. Inference labels
whatever sequences the mutator happened to produce: a state it never stumbled
into is a state it never learns about, and a protocol behind a handshake, an
authentication and a mode change spends most of a budget rediscovering its own
prefix. Learning *chooses* the sequences — what happens after this exact prefix,
followed by this exact suffix — and what comes back is a machine with a path to
every state it found.

The paths are the point. A learned machine is interesting to look at; a set of
access sequences is a corpus that starts from every reachable state.

## Decision

**Angluin's L*, in its Mealy form.** A Mealy machine and not a DFA because a
protocol answers every message with something: the observable is not "was this
word accepted" but "what did it say", which is one output symbol per input
symbol. The observation table's rows are access sequences and its columns are
distinguishing suffixes, and the loop closes the table, proposes a machine, and
asks for a counterexample.

**The output alphabet is the campaign's own state labels.** This is what makes
learning fit rather than bolt on: the state function an operator already
configured to say "this response means authenticated" is exactly the function a
Mealy output needs, and a campaign that has one has already done the work.

**The input alphabet is the distinct messages the campaign's seeds contain.**
Asking an operator to write the alphabet out separately would be asking them to
describe what they have already shown. What a campaign configures is how many to
take, because the table has a column per symbol before it has anything else.

**A counterexample adds suffixes, not prefixes.** Angluin's original grows the
rows, which is correct for a DFA whose columns grow with it. In the Mealy form
the columns start as the alphabet, and adding rows alone cannot separate two
states that agree on every single symbol — the learner finds the same
counterexample for ever, and because every word in it is cached it spins without
spending a query. A suffix that explains the counterexample splits at least one
state, so each round makes the table strictly finer.

**Every query is a reset and a session, so every bound is a budget of
sessions.** The learner caches, so no word ever reaches the target twice; it
bounds queries, states, rounds and sequence length; and reaching any bound
returns what was learned so far, marked partial, with which bound was reached.
A partial machine is still a set of access sequences, and a campaign that could
not learn fuzzes from its own seeds — which is what it would have done anyway.

**It claims nothing it cannot show.** L* is exact given a perfect equivalence
oracle, and there is no perfect equivalence oracle for a program nobody has a
model of. The one here samples random sequences up to a bounded length and the
report says how many it checked. A target that answers the same question two
different ways is detected and named — it is not deterministic from a reset, so
no finite machine describes it — rather than modelled from noise.

**The sampling is seeded.** Two runs of the same campaign against the same
target ask the same questions and reach the same machine
([ASR-0008](../asr/ASR-0008-reproducibility-and-determinism.md)).

**Learning never ends a campaign.** It is an optimisation on the starting
corpus, and every outcome — learned, partial, refused, failed — is reported.

## Consequences

**Positive**

- A stateful campaign starts from every state the learner reached, rather than
  from the handshake. Measured against the `stateful_proto` target: three states
  and nine transitions from thirty sessions, two access sequences seeded, in two
  seconds.
- The learned machine is a Graphviz diagram a person can read, which is the
  first artefact this project produces that *describes the target* rather than
  describing the campaign.
- It is a guidance strategy in ASR-0004's sense that plugs into what already
  exists: the state function, the session tier and the corpus, unchanged.

**Negative**

- It costs sessions before the campaign begins, and on a slow tier that is
  minutes. Off unless asked for, and bounded when it is.
- It needs a target that is deterministic from a reset. A protocol whose replies
  carry a counter, or a session tier whose framing is timing-based, will make
  the learner report exactly that — which is useful, and is not a machine.
- The machine is the best explanation of the queries asked, not a proof. An
  operator reading a diagram should read it as evidence.

**Neutral**

- ADR-0006 is unchanged: inference stays, guidance stays, and this runs before
  both. A campaign with learning switched off behaves exactly as it did.

## Alternatives considered

- **Keep inferring only.** What ADR-0006 chose, and it works — the campaign does
  discover states. What it cannot do is tell you which states exist and how to
  get to each, which is the question an operator asks first.
- **Rivest and Schapire's counterexample handling**, which adds one suffix
  rather than all of them, and the TTT algorithm, which is better again.
  Rejected for now on the same grounds ADR-0022 gives for a denylist: the simple
  form is the one whose correctness is obvious, and for a component that decides
  what a campaign believes about a protocol that is worth more than the constant
  factor.
- **A W-method equivalence oracle**, which is exhaustive up to a bounded number
  of extra states and would make the result a real guarantee. It costs
  |S|·|Σ|^k·|W| sessions, which for any k worth having is more sessions than the
  campaign it precedes. Random sampling finds the disagreements reachable by a
  short path, which are the ones a fuzzer would have found anyway.
- **Learn continuously, refining the machine as the campaign runs.** Attractive
  and a different design: it would make every execution a query and the corpus a
  by-product. Worth revisiting; starting with a phase that ends keeps the cost
  visible and the campaign unchanged.
