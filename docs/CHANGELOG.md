# Changelog

All notable changes to Xfuzz are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until v1.0, minor versions may contain breaking changes to the campaign file
format, the plugin protocol, and the on-disk store schema. Each such change is
listed here with its migration path.

## [Unreleased]

### Added — v0.1 release audit (2026-08-30)

**T3, the process pool (ADR-0009, ADR-0026, ASR-0006)**

- `pkg/executor.ProcPool`: a pool of pre-spawned processes, each handed its
  input over stdio, so the cost of creating a process is paid while the previous
  execution is still running. This is the tier ADR-0009 calls "required on
  Windows", where the fork server's descriptors 3 and 4 do not exist. It was in
  the v0.1 scope table with no implementation behind it — found by auditing the
  ADRs against the code, not by a test.
- Measured against T4 on the same target: 1420 exec/s against 559 in the
  benchmark, 302 exec/s against 168 in a real campaign.
- Black-box by construction, and it says so in its capabilities. A process that
  already exists has already run its startup path, so claiming edge coverage
  would attribute the target's initialisation to whichever input arrived first.
- `executor: pool` in the campaign file; `auto` picks it over the subprocess
  tier whenever there is no coverage map to fill.

**Benchmarks for every implemented tier (definition of done, clause 3)**

- `BenchmarkInProc`, `BenchmarkSession`, `BenchmarkProcPool` and
  `BenchmarkSubprocessNop`, shaped so their numbers are comparable: same target,
  same mutation, one execution per iteration, so what separates them is the cost
  of the boundary and nothing else. Four of the five tiers previously had no
  benchmark, which means the gate clause 3 asks for could only ever have held
  for one of them.

**A pinnable campaign seed (ADR-0016, ASR-0008)**

- `seed:` in the campaign file. ASR-0008's second acceptance criterion is about
  "the same campaign file and seed" and there was no way to supply one: the
  daemon drew a seed, recorded it, and reported it, so a campaign could be
  described after the fact but never repeated.
- In the file rather than behind a `--seed` flag, because ADR-0016 puts what
  decides a run in the artefact — and because YAML holds a 64-bit integer
  exactly where a JSON number is an IEEE double. 12345678901234567 goes in and
  comes back out of `xfuzz status` unchanged.

**Configurable health thresholds (ASR-0007, ASR-0008)**

- `health:` — `min_stability`, `max_overhead`, `min_execs_per_second`,
  `coverage_stall`. `internal/metrics` documented these as judgements "a
  campaign against an unusual target may legitimately disagree" with, and no
  campaign could: the defaults were passed as a literal at the one call site.
  ASR-0008 requires the stability threshold in particular to be configurable.
- Validation rejects `min_stability: 90`, which reads as ninety percent, means
  nine thousand, and would silently retire the diagnostic it configures.

**Clause 4 and clause 5, as tests rather than claims**

- `test/e2e/determinism_test.go`: two runs of one file and seed, under separate
  daemons in separate data directories, must find the same corpus by the same
  derivation — provenance compared, not only digests, because two runs that
  diverge and reconverge are lucky rather than deterministic. A third run with
  another seed is required to differ, or the test would pass on a fuzzer that
  ignored its seed.
- The same file measures cross-host replay as literally as one machine allows:
  a second set of binaries, a second data directory, a second daemon, a target
  rebuilt at its own path, and the store carried across with `cp -a`. The seed
  deliberately does not travel.
- A `security` CI job. `make test-security` has existed since M4 and no job
  ever ran it, so twelve of the eighteen properties in section 12 of TESTS.md
  were asserted by a suite nobody ran. It passes — eleven tests, no skips — and
  the job fails on a skip, which is how that suite reports "the mechanism is
  not here".
- `TestTiersAreOrderedAsADR0009Claims`: the per-tier benchmarks gate each tier
  against its own past, and nothing gated them against each other. A tier that
  fell below the one beneath it would keep passing its own benchmark while
  having no reason to exist.

**Documentation**

- [ADR-0026](adr/ADR-0026-gocov-deferred-blackbox-is-the-off-linux-path.md)
  records the `gocov` deferral as a decision rather than an absence, and amends
  the scope tables in ADR-0002 and ADR-0020 that still listed it.
- `docs/GUIDE.md` gains a reference table of every command, held to the binary
  by `cmd/xfuzz/parity_test.go` in both directions; a tier table; and a section
  on repeating a campaign exactly.
- MVP_PLAN § 6.1 records what was run for each clause of the definition of
  done, and § 6.2 states what clause 2 does not cover: `stateful_proto`'s bug 3
  has no established budget.

### Fixed — v0.1 release audit

- **`xfuzz findings` never showed a finding's bucket**, which is the field the
  list is usually being read to answer: is this the same bug again? Both the
  table and the detail view now carry it. The omission had also made two tests
  vacuous — `test/e2e/m6_test.go` decoded a `bucket` key the CLI did not emit,
  so it compared zero against zero and passed however the crashes were grouped.
- **MVP_PLAN § 1.1 documented a Go instrumentation route that does not exist.**
  It offered `-gcflags=all=-d=libfuzzer` against the runtime `xfuzz-cc` ships as
  "the same instrumentation by a shorter route". Building it during the audit,
  it does not link: Go's libfuzzer mode emits against libFuzzer's 8-bit counter
  interface and `runtime/csrc/xfuzz-rt.c` implements trace-pc-guard, which is a
  different contract rather than a subset of one. Corrected, with the working
  route recorded in ADR-0026 for a later version.
- **ADR-0010 still offered "gRPC/stdio" for the plugin transport** after
  ADR-0024 removed gRPC from the project and ADR-0025 settled on stdio.
- **ADR-0009 named the T3 executor `ProcessPool`** where the code calls it
  `ProcPool`, and **ARCHITECTURE described `internal/platform` as `linux/
  darwin/ windows/` subdirectories** it has never had.
- **The API's `seed` field on campaign creation was documented and dead.** It
  said "pins the campaign's root RNG seed" and nothing read it, so a client
  that pinned a seed to get a repeatable campaign got a random one and no
  error. Removed rather than wired: the campaign file is where it belongs.
- **T3 claimed `TimeoutEnforced` and enforced nothing.** `internal/safety`
  gives a peer no deadline, correctly — a peer is a process the fuzzer talks to
  over its whole life — but on this tier the process's life *is* one execution,
  so a hanging target parked its worker for the rest of the campaign. Worse
  than slow: a hang is a finding, so the tier was losing the bugs it was
  pointed at while reporting nothing wrong.
- **T3 spawned replacements against the execution's context**, so any caller
  with a per-execution deadline would have emptied the pool — and a dead warm
  process does not merely slow things down, it reports a *crash* on the next
  execution to take it. The engine passes a long-lived context today, which is
  the only reason this was latent.
- **`make ci` claimed to be "what CI runs on every push"** while running four
  of the ten jobs, and section 10 of TESTS.md listed seven of them.

### Added — M8 Extensions and hardening (2026-08-30)

**The external plugin tier (ADR-0010, ADR-0025, ASR-0009)**

- `pkg/plugin`: a versioned protocol for extensions written in any language.
  Four big-endian length bytes and a JSON object, over the plugin's own standard
  input and output. No dependency, no code generation, no toolchain requirement
  — a plugin is implementable in an afternoon, which is the difference between
  an extension point that exists and one that gets used.
- Feedbacks, mutators and objectives, each satisfying the same Go interface the
  native tier does. The engine cannot tell the tiers apart, and must not be able
  to: that is what makes a plugin an extension rather than a hook.
- Batching where batching is real. A feedback must answer about the execution
  that just happened; a mutator asked for one variant can produce thirty-two,
  and the engine wants them all within the next thirty-two iterations from that
  parent. Measured at eight mutations per round trip in the unit tests.
- A feedback's `Append`/`Discard` rides on that extension's next call rather
  than costing a round trip of its own, so the hot path pays one exchange per
  execution. `Close` flushes what is still owed.
- Failure is sticky and contained. A protocol error, a timeout, or the death of
  the process takes that plugin permanently out of service, kills it, and fails
  its campaign with the first error — a timeout rather than the end-of-file that
  killing then produces — plus whatever the plugin wrote on its standard error.
  A plugin that merely *declines* a call is not dead and is not treated as dead.
- `Mutate` cannot return an error, which is how a plugin mutator would otherwise
  fail silently for the rest of a campaign. The host holds it behind an atomic
  load and the worker asks once per slice.
- `pkg/plugin`'s server half is the reference implementation of the wire format,
  so writing a plugin in Go is filling in a function. `examples/plugins/reference`
  is a worked example of all three extension points in about 130 lines.

**The script tier (ADR-0010, ASR-0008, ASR-0010)**

- `pkg/plugin/script`: campaign-local logic in Starlark. Oracles, mutators and
  state functions, from a file beside the campaign.
- Starlark for hermeticity rather than familiarity: no filesystem, no network,
  no clock, no imports, and deterministic execution. A campaign file may be
  untrusted, and a campaign that is required to replay cannot afford a language
  that can read the time.
- Bounded, because hermetic is not the same as cheap. A step budget stops a
  script that loops; an allocation budget stops one that builds. Starlark's own
  guard is a hard gigabyte per single operation, which catches `"x" * 10**12`
  and nothing else — a loop that concatenates stays under it on every step and
  passes it in total. The budget is checked every few thousand steps against the
  runtime's allocation counter, and a script that exceeds either is cancelled
  naming which.
- An oracle sees the same observation a plugin does, so the two tiers cannot
  drift. A misspelled field is an error naming the ones that exist rather than
  `None` flowing quietly through a comparison and making the oracle always say
  no.
- No script feedbacks, and that is a property rather than a gap: Starlark
  freezes module globals after load, so a script cannot accumulate the novelty
  state a feedback exists to keep. That belongs to the plugin tier, where a
  process can remember.
- `scripts:` in the campaign file, and `state.fn: script` for a protocol whose
  shape someone knows and an inference heuristic does not.
- `examples/scripts/oracle.star` is a worked example of all four uses.

**Wiring (ADR-0012, ADR-0016)**

- `internal/safety.StartPeer`: the spawn boundary now covers long-lived protocol
  peers as well as targets. A plugin is confined exactly as a target is, because
  an extension is untrusted by construction — that is why it runs out of process.
- `internal/extension` resolves a campaign's `extensions:` block into running
  plugins. It exists because two rules meet: `pkg/plugin` may not spawn and
  `internal/safety` should not know a protocol.
- Campaign files gained `extensions:` — a plugin's command, settings, and the
  named feedbacks, objectives and mutators to take from it. A name the plugin
  does not provide is a refusal before the first execution, rather than an
  extension that silently never fires.
- `plugin_calls` and `plugin_seconds` on every metrics snapshot, with a
  `plugin-slow` health diagnostic past 25% of wall clock. ADR-0010 promises a
  slow plugin is diagnosable rather than mysterious; "your campaign is slow" is
  not a finding anyone can act on.

**Fault injection and self-fuzzing (ADR-0021, ASR-0012)**

- The fault-injection suite of TESTS.md section 9, all nine faults, each
  injected for real rather than simulated. The full disk is a two-megabyte
  tmpfs, because a write that fails because the filesystem is full stops
  part-way and what matters is what is left on disk — which a permission error
  never exercises. The corrupted database is overwritten in place at its
  original length, which is what a bad sector looks like from userspace. The
  killed worker is proven restarted by a process identifier that was not in the
  original set, because "a worker is running" also passes when nothing happened.
- Blob quarantine, which the suite required and nothing implemented: a payload
  that does not hash to its own name is moved aside with its reason recorded,
  the corpus entry is dropped and reported, and the campaign carries on. One bad
  file on a disk that is going wrong costs a campaign that entry, not the
  campaign.
- Self-fuzzing targets for every untrusted parser TESTS.md section 8 names,
  wired into CI with a corpus cached across runs. Each asserts a property rather
  than only the absence of a panic, because "it did not crash" is satisfied by a
  parser that accepts everything and understands nothing.

**The schema-driven codec (ADR-0005, ASR-0014)**

- `codec.Schema` decodes any format a `.xfg` grammar describes: total,
  best-effort, and byte-exact on re-encode, with lengths and element counts
  resolved from the sibling fields that declare them.
- Wired in, which is the point. `format.grammar` used to generate seeds and
  nothing else — `codecFor` returned `codec.Raw` whatever the grammar said — so
  a campaign with a grammar mutated bytes and the fixup pass never ran, because
  there was no structure to fix. Writing a grammar bought a better starting
  corpus and none of the thing a grammar is for. An explicit `codec: raw` beside
  a grammar still means byte-level, which is the control arm when measuring what
  structure buys.
- Found by the v0.1 proof obligation, whose two arms were the same campaign run
  twice until this landed.

**Cross-platform (ASR-0003, ASR-0006, ADR-0020)**

- `test/e2e/portable_test.go`: a whole subprocess campaign, black-box, against a
  Go planted-bug target the test builds itself — so it runs on macOS and Windows
  where every other end-to-end test skips for want of clang. A CI job runs it on
  all three platforms.
- It measures what those platforms actually get: no coverage map (shared memory
  is a Unix mechanism), no isolation, novelty feedback instead of coverage, and
  a target that fails the way a managed language fails — exit status 2 and a
  line on standard error rather than a fatal signal. On Linux: 10,154
  executions, both planted bugs found, in two buckets.
- A resume across daemon lifetimes on every platform, because that is where the
  platform differences bite: file locking, path handling, and whether a process
  that died released what it held.
- `xfuzz doctor` is checked against the platform it runs on, so that nobody on
  Windows reads "isolation: strong" and believes it.
- **`gocov` is deferred out of v0.1**, with the reason recorded in MVP_PLAN.
  Go's coverage counters are written in a format no public API decodes;
  collecting them per execution would cost more than the execution. It was
  scoped as the grey-box path off Linux and would not have been one on Windows
  anyway, where there is no coverage map to fill.

**Documentation (definition of done, clause 10)**

- [GUIDE.md](GUIDE.md): install to first finding, then findings, triage,
  reproduction, the console, black-box targets, protocol campaigns, making a
  campaign faster, safety, storage, and the two extension tiers.
- [GRAMMAR.md](GRAMMAR.md): writing a `.xfg` grammar — the type vocabulary,
  derived fields and references, how to build one for a real format outside in,
  and when to suppress a derivation so the consistency checks themselves become
  the target.
- `test/e2e/guide_test.go` walks the guide's first-campaign section literally,
  and checks that every YAML block in both documents validates. A guide is a
  claim about the tool, and a claim nobody checks stops being true.
- `xfuzz doctor` gained the three checks a new install actually fails on: is the
  data directory writable, can a confined process be launched at all, and is the
  console in this build. The second is the valuable one — it exercises the whole
  spawn path rather than the mechanisms it is built from, so a host where every
  capability is present and this fails is diagnosed in a second rather than in a
  campaign.
- Byte counts in a campaign file take units: `512KB`, `64MB`, `2GB`. A plain
  number still means bytes, so every file written before this keeps working, and
  `xfuzz explain` now reports `64KB` where it used to report `65536`.

### Fixed — M8

- A plugin's lifetime is the worker's, not the campaign context's. Tying it to
  the context meant the plugin was killed at the first sign of the campaign
  ending, on the pipe the final commit still had to be written to.
- `Host.Close` reported failures caused by its own shutdown. Every clean stop
  was ending with "write: file already closed" against the plugin's name.
- The API and the console share a listener, and which of them answered was
  decided on the *cleaned* path — so `/v1/campaigns/../../etc/passwd` cleaned to
  `/etc/passwd` and fell through to the console, and a client that asked the API
  a question got an HTML page back. Paths that do not survive cleaning are now
  redirected, as `net/http`'s own mux does; dispatching by hand had meant
  re-earning that. Found by this package's new self-fuzzing target on its first
  run.
- One corrupt payload failed the whole corpus read, so a single bad file took
  down a campaign's seed load rather than costing it one entry.
- M6's stateful criterion was bounded by the clock, which made it a coin flip
  on a busy host: 24,405 sessions at 52/s found three of four planted bugs and
  17,773 at 38/s found one, on identical code. A campaign that reaches the
  handshake compounds — the authenticated state was visited 174 times in one run
  and once in the other — so it is now bounded by sessions, which is what the
  criterion is about, with the clock kept as a backstop.
- A grammar took the codec on a session campaign, where the codec's job is to
  split an input into the messages of a conversation. It would have turned a
  conversation into a single blob and the campaign would have stopped being
  stateful without saying so.
- `xfuzz init` wrote a campaign file that `xfuzz validate` rejected: the
  template set `workers.count: 0` with a comment saying "one per core by
  default", and validation refuses an explicit zero. Two commands into the
  documented path, and it did not work. Found by the test that walks the guide,
  on its first run.
- `xfuzz findings buckets` answered in raw JSON without being asked. A bucket
  count is how many *bugs* a campaign found, as against how many times it found
  them, so it is the most-read listing there is — and it was the least readable.
- A Go panic carried no stack frames into triage, because the frame parser knew
  only the sanitizer format. Bucketing fell through to the message, and a
  message that contains the offending values — "slice bounds out of range
  [:255] with capacity 8" — puts every crash in a bucket of its own. Measured
  on the portable target: 78 buckets for two planted bugs, now 2. Such findings
  are also now reported as kind `panic` rather than `sanitizer`, which was a
  lie about where they came from.

### M8's exit criteria, measured

| Criterion | Result |
| --- | --- |
| Both v0.1 proof-obligation campaigns pass on Linux | Stateless: 1,208,068 executions at 6,711/s sustained on the fork server against a checksum-protected format, four findings in one bucket, each verified 5 of 5 and minimised by up to 45%, with a corpus 48% valid against byte-level mutation's 25%. Stateful: `test/e2e/m6_test.go` |
| macOS and Windows run a subprocess campaign end to end | `test/e2e/portable_test.go`, in CI on all three platforms. The Linux leg: 9,916 executions, both planted bugs, two buckets. The macOS and Windows legs run in CI and have not been executed here |
| All fault-injection tests pass | 9 of 9, each fault injected for real |
| Self-fuzzing runs clean in CI | Ten targets, corpus cached across runs; several million executions locally with no crash. The API target found a real defect on its first run |

### Added — M7 Web console (2026-08-30)

A campaign is configurable, launchable, monitorable and triageable from a
browser, and the console is a page in the same binary rather than a service
beside it.

**The console (ADR-0011, ASR-0015)**

- A TypeScript SPA built with Vite, compiled to static files and embedded via
  `embed.FS`. No CDN, no runtime asset fetch, no external font, and a test that
  walks the bundle looking for any of them: an air-gapped install cannot fetch
  what is missing, and a console that half-loads is worse than one that says it
  is absent.
- Nine views: campaigns, campaign detail, coverage, state machine, findings,
  one finding, corpus, one entry, campaign file, grammar workbench, safety and
  audit.
- No framework. Nine views of tables, numbers and forms do not need one, and a
  large runtime dependency with a permanent upgrade obligation is the cost
  ADR-0011 names for having a console at all. What replaces it is about eighty
  lines of DOM helper; the bundle is 24 kB of JavaScript and 4.6 kB of CSS.
- Behind the `console` build tag, so `go build ./...` needs nothing but the Go
  toolchain and a build without it serves a page saying how to get one.
- It shares the daemon's listener: same socket, same authorization, no
  privileged path of its own. Everything it can do is a route `xfuzz` reaches.

**What building it added to the API**

- `campaign.load` opens a finished campaign from its store. The store recorded
  a configuration *digest* — enough to detect that a file changed, not enough
  to say what it was — so schema 2 keeps the resolved document beside it and a
  campaign is reachable with its file deleted.
- `finding.triage` records a person's judgement: confirmed, duplicate, wontfix,
  invalid, and a note. Kept in its own column, because the triage state is the
  machine's verdict and is rewritten on every re-triage.
- `campaign.edit` applies edits to a campaign document and hands it back with
  its comments, key order, paragraphs and indentation intact.
- `grammar.sample` compiles a grammar and shows what it writes. Pure: no
  campaign, no store, no target, so a grammar can be written before there is
  anything to fuzz with it.

Each has a CLI counterpart — `xfuzz load`, `triage`, `edit`, `grammar` —
because the parity test refuses to let either interface hold a capability the
other lacks (ASR-0005).

### Fixed

- **`seeds.generate` was validated and then ignored.** The campaign file
  refused a generate count without a grammar and refused a negative one, and
  nothing ever acted on it: a campaign with a grammar and no seed files was
  accepted, imported nothing, and started with an empty corpus.
- **A person had nowhere to record a judgement.** Every triage state was the
  machine's verdict. Worse, triage's own account — "5 of 5 runs reproduced" —
  was written into `notes`, the field a person would write in, and the daemon
  read notes back and passed them through `UpdateTriage` to preserve them: a
  read-modify-write is a judgement waiting to be lost to whoever saved theirs
  in between.
- **A 64-bit seed did not survive JSON.** It arrived in the browser as
  14879488505964902000 where the CLI said …903031, because JSON numbers are
  IEEE doubles. A seed is half of what a byte-identical replay needs
  (ASR-0008), so one shown nearly right is worse than one not shown; it is a
  string on the wire now.
- **The API's own root was answered by the console.** `path.Clean` turns
  `/v1/` into `/v1`, which a prefix test does not catch, so a client asking for
  the API root got a web page. Both callers share one rule for it now.
- **The API version was advertised and compared by nobody.** Changing the
  seed's wire type left a stale CLI reporting "cannot unmarshal string into Go
  struct field Status.seed" rather than saying it was older than the daemon.
- **The event bus could panic instead of dropping an event** — see M6's entry;
  found by the race detector while this milestone's work was in flight.

### Added — M6 Stateful protocol fuzzing (2026-08-29)

The second half of the proof obligation. A campaign can now fuzz a conversation
rather than an input, and reach a bug that needs a specific sequence to get to.

**`pkg/state` — the protocol state machine as a feedback signal (ADR-0006)**

- `StateModel` holding states and transitions, declared or inferred, with the
  two counted separately: a target with five states has twenty-five ordered
  pairs, and the bugs live in the pairs nobody expected to be reachable.
- `StateFn` maps a response to a label. `status` reads the leading token, which
  covers SMTP, FTP, POP3, IRC, Redis and HTTP; `fingerprint` hashes the
  response's shape for everything else.
- Each label says how many distinct responses produced it. A state label is a
  hash and a hash explains nothing, so the model keeps one exemplar per label —
  and, where the label covers more than one response, says how many. On
  `stateful_proto` the default `status` function makes "250 stored" and "250
  transfer complete" one state, which is what a status code is *for* and is
  also why a campaign aiming at 250 gets whichever the corpus happens to hold.
  Saying so is the difference between a clustering somebody can fix and one
  they have to guess at.
- Where fingerprinting is concerned, the whole difficulty is the normalisation,
  so it is a named, ordered pipeline a campaign can tune rather than one clever
  function — over raw bytes every nonce becomes a state, and over nothing but
  length distinct states merge. The model keeps one exemplar response per label
  so a bad clustering can be looked at rather than guessed about.
- `StateFeedback` admits a session that reached a new state or made a new move,
  composing with coverage under ADR-0007's algebra. This is the reason ADR-0006
  exists: two sessions can execute identical lines and leave the target in
  entirely different places.
- `StateScheduler` picks a rarely-visited state to aim for, picks a corpus
  entry known to reach it, finds the message that reached it in that entry's
  own trace, and mutates at or after that point. Three choices rather than two:
  aiming at a state without choosing an entry that can reach it leaves the aim
  inert, because an entry that never got there has no informed place to cut. A
  session is a funnel — the handshake has to stay valid for anything past it to
  be reachable — and a fuzzer that does not know it is a funnel keeps kicking
  the entrance.

**T6, the session executor**

- One execution is a whole session: connect, send each message, read each
  reply, close. Messages come from the `Repeat` node's children rather than
  from splitting an encoded stream, so a message boundary is a real boundary
  and the sequence operators need no framing knowledge.
- It dials through a `Dialer` interface, which is the scope guard in a
  campaign — the same shape as `Spawner` is for processes, and the architecture
  lint means an executor that reached the network another way would not
  compile.
- Framing is configuration, not a guess: `idle` needs no protocol knowledge and
  is the default, and its quiet period per message is what caps a stateful
  campaign's throughput; `line` is far faster where it applies.
- The four reset policies are honoured as written, `snapshot` included — which
  is refused by name with what to use instead, because a campaign that asked
  for it and silently got `reconnect` has findings that do not mean what it
  thinks.

**`pkg/codec.Session`** makes a seed file a conversation: one file is one
exchange, one line is one message. An example of the protocol being spoken
correctly is the most useful thing a person can supply to a stateful campaign,
and without this codec the campaign has to rediscover the handshake by
insertion when the seed file already contained it.

**Campaign file, CLI and reporting**

- `session:` and `state:` blocks. The session block's presence is what selects
  the tier — a separate mode switch would let a file ask for sessions and give
  no address, and both halves of that look valid and cannot work.
- `{worker}` in a session address, because each worker runs its own copy of the
  target and a fixed address means the second binds what the first holds.
- State and transition counts are reported beside code coverage, never folded
  into it, and `xfuzz states` renders the graph with the exemplars.

**`testdata/targets/stateful_proto.c`** — four bugs graded by how much of the
state machine each needs: one message; a valid two-step handshake; two bulk
transfers on one connection; and an `AUTH`, `RESET`, `GET` order and no other.
Every near miss stays alive, which is what makes finding the second one
evidence of getting through the funnel rather than of stumbling past it. All
four are reached, the transition-pair use-after-free included, though not all
of them in every run.

### Fixed

Fifteen defects, all of which produced a campaign that looked healthy:

- **The event bus could panic instead of dropping an event.** A subscriber's
  channel was closed by `Close` while a publisher was selecting on it, which is
  a send on a closed channel — a panic, in the daemon's publish path, which
  every worker report goes through. Every send is made under the subscription's
  lock now, which costs nothing for an ordinary event because that send is
  non-blocking by construction; an undroppable one retries rather than blocks,
  so it never holds the lock while waiting and a shutdown never hangs on a slow
  subscriber.
- **Protocol coverage was reported from two clocks.** The state and transition
  counters travelled on the reporting interval and the graph behind them on the
  checkpoint interval, so a finished campaign's status could say ten states
  while its graph held nine. The counters come from the merged graph now, which
  also fixes the count itself: the largest number a worker reported
  under-counts whenever two workers explore different parts of the protocol,
  and the campaign has explored a state when any worker has.
- **A campaign that executed nothing was told its target was broken.** There
  are two causes and naming the wrong one sends the reader to the wrong place:
  a target that will not start, or a budget shorter than the campaign's own
  startup — building a corpus, spawning a sandboxed target, waiting for a
  server to listen. The health check now distinguishes them by how long the
  campaign lived.
- **The scheduler's bias toward rare states was inert on a small model.** "The
  eight rarest" is nearly every state of an eleven-state protocol, so aiming at
  a rare state was close to aiming at a uniformly random one — exactly where the
  model is small enough to be worth exploring. The tail is a fraction of the
  model now, with the configured count as its ceiling.
- **Seed selection was not state-aware**, which left the state choice inert.
  The entry came from the coverage scheduler, so an entry that never reached
  the state being aimed at gave the message choice nothing to work with and it
  degraded to "anywhere". Measured on `stateful_proto`: 8 of 148 corpus entries
  carried a complete handshake, so roughly 95% of the budget went to entries
  that could not reach the state the campaign was aiming for, and the bug
  behind the handshake stayed unreached for the length of a campaign.
- **The fuzzer's own SIGKILL was filed as a finding.** A managed server is
  killed when the context it was started with ends, and a server restarted
  during a session inherited that session's ten-second timeout — so it was
  killed some seconds later, in the middle of a *later* session, and the kill
  was read as the target dying. Every campaign carried a "target terminated
  abnormally" finding, signal 9, against an input that did nothing and that
  reproduced 0 times out of 5. A managed server's life is the campaign's now,
  and a target that dies of a signal it cannot have sent itself is not a
  finding whatever else it is.
- **A restart could report the previous server's death against its
  successor.** The exit flag and result were shared across generations while a
  goroutine reaping the old process was still running. Each generation owns its
  own now, so a stale reaper writes where nothing reads.
- **Bucketing collapsed every digit run, including the one naming the bug.**
  `stateful_proto`'s four bugs each print their own number and all four reduced
  to one bucket key, so a second, different bug was filed as a duplicate of the
  first and discarded. Only addresses and long numbers vary between runs of one
  bug; a line number, an error code or a bug index is part of what the message
  says. The one-line report had the same failure from the other end, truncating
  a bucket key from the right — on the very line announcing that a second bug
  had been found.

- **Trimming destroyed the session it was trimming.** Candidates were delivered
  as one long message rather than as a conversation, so the comparison
  deciding whether to keep a reduction was against an execution that never
  happened; and it preserved code coverage only, which a session that
  authenticated and one that did not both satisfy. A corpus of four-message
  conversations collapsed to three-byte fragments, losing every path past the
  funnel the campaign had spent minutes finding.
- **A trace was recorded against the wrong input.** A mutant's trace went to
  its parent whenever the mutant was not admitted — nearly every execution — so
  the scheduler aimed with a map of somewhere else and the state-then-message
  split was undone on almost every iteration.
- **Coverage read zero on every stateful campaign.** The engine reached for the
  map feedback with a type assertion on the stack root, which stops working the
  moment state guidance is composed alongside it. A stack is a tree, so it is
  now searched.
- **Findings read zero.** A crash and an orderly disconnect are the same event
  on a socket, and only the process status separates them — but the process had
  just died, so its exit was still in flight when the status was read.
- **One mutated message could cost a whole session.** Mutation strips a line's
  terminator, the target waits for the rest, the fuzzer waits for a reply, and
  the full read timeout is charged for every remaining message.
- **A dead server was not restarted** unless the policy said `restart`, so a
  campaign using `reconnect` stopped fuzzing at its first finding.
- **The resolved form of a stateful campaign failed its own validation**, and
  the daemon hands workers that resolved file — so a campaign that validated
  when submitted could not be loaded by the worker meant to run it.

Also: the scope guard treated a Unix socket as a network destination and
refused it for having no port, though there is no remote host to be in or out
of scope; the sandbox now checks that the target can create the socket it is
told to bind, naming the directory and the identity rather than surfacing it as
a server that would not talk; and triage replays a stateful finding as a
session rather than as a blob on standard input, which reported every real bug
as unreproducible.

Triage can also be told a target's own failure vocabulary. The generic marker
prefixes cover assertions and panics; `triage.markers` adds a codebase's own,
threaded through verification as well as bucketing because divergence is also a
question about class. And a corpus loaded from the store is traced before
fuzzing starts: `LoadCorpus` deliberately admits without executing, which for a
stateful campaign means every entry is scheduled without a trace and the
state-then-message split never engages. Only the entries that need it — that
path is also how a worker takes in what its siblings found, every few seconds
for the length of a campaign, and re-running the whole corpus each time would
cost more executions than the campaign spends fuzzing.

### Known issues

- A managed session server can outlive its worker: one per worker survives a
  finished campaign. Every target runs in its own process group so that killing
  it kills what it started, which also means the worker's group does not
  contain it, and a worker that does not complete its own shutdown leaves the
  server behind. A worker now gets a bounded grace period to shut down before
  the supervisor kills it, and a closer that fails now says so on the worker's
  own output as well as to the daemon — the status pipe is closed by then, so
  the report that would have named the cause was going nowhere. Neither has
  been shown to close the hole.

  What it costs is startup, not correctness: the abandoned servers hold no
  address the next campaign wants, but they are contention, and a campaign
  short enough for startup to be most of its budget is where that shows.
  Measured: the milestone's exit criteria pass individually, and the second
  failed once when run straight after the first on a host carrying four
  abandoned servers; separately, a twenty-second campaign on a loaded host can
  reach its time budget having imported no corpus at all. A campaign whose
  budget is shorter than its own startup deserves to be told so, which the
  health check does not yet say.

### Added — M5 Daemon, API, and CLI (2026-08-29)

The tool becomes a tool. A campaign is a file, a daemon runs it, and the command
line is a client of the same API the console will use.

**`pkg/campaign` — the campaign file is the only interface (ADR-0016)**

- YAML schema with includes and profiles, a generated JSON Schema published by
  the daemon, semantic validation separate from schema validation, and
  termination conditions so a campaign in CI ends deterministically (ASR-0015).
- Which keys the file actually contained is recorded, so "unset" and "set to
  zero" are distinguishable. Without it `triage.trials: 0` read as unset and
  silently became five, which is the opposite of what was asked for.
- `explain` renders the fully resolved configuration with every default marked
  as one, and its YAML form is a file that runs the same campaign — which is how
  a run gets pinned to an artefact after the fact.

**`internal/daemon` — campaigns outlive their clients (ADR-0003)**

- Campaign lifecycle, worker supervision with restart budgets, corpus sync
  batched so a burst of discoveries is one broadcast rather than one per entry,
  and ensemble strategies.
- The event bus is lossy by design for high-rate kinds and says so: subscribers
  are coalescing or lossy, and every drop is counted rather than hidden. Metrics
  events carry the campaign's aggregate, not one worker's counters, because a
  coalescing subscriber keeps only the newest and the newest worker is not the
  campaign.
- Triage runs here, on a bounded queue off the message loop: every new finding
  is verified and minimised, and `replay` and `minimize` ask the same runner on
  demand. The subprocess tier rather than the fork server — for the question "is
  this crash real", a fresh process per run is the answer that can be trusted.
- The resolved configuration is written into each run's working directory and
  workers are pointed at that copy, so a worker runs what was submitted rather
  than re-resolving a file whose relative paths mean something else from where
  it stands.

**`internal/api` — six services over HTTP/JSON (ADR-0024)**

- Campaign, metrics, corpus, finding, event and admin services, with a generated
  OpenAPI description and a drift test, over a Unix socket by default.
- Events as server-sent events: a close fit for a stream that is
  server-to-client and droppable, and one that reconnects without client code.
- The route table is data, which is what makes the CLI/API parity test possible
  at all (ASR-0005).

**`internal/worker` and `internal/metrics`**

- A worker builds an engine from a resolved campaign file and speaks the
  protocol over its descriptor pair. Its loop runs in slices bounded by time as
  well as by count: bounded only by a count, a slow target makes one slice last
  as long as it likes, and since commands are handled between slices the worker
  would look alive and silent for the whole of it.
- Counters, a thinned historical series, and named health diagnostics that say
  what to do about each finding rather than only that something is wrong.

**`cmd/xfuzz`, `cmd/xfuzzd`, `cmd/xfuzz-worker`**

- The full command set, including `replay`, `minimize` and `doctor`, with daemon
  auto-start for the single-binary case — which is still the daemon, not an
  in-process bypass.
- No flag alters fuzzing semantics: those live in the campaign file, so what ran
  is a reviewable artefact rather than a shell history entry.

### Measured — M5 exit criteria

| Criterion | Result |
| --- | --- |
| Multi-worker campaigns scale ≥ 0.85 × N | 1.89× on 2 workers (94% efficiency) on a 4-core host, measured as executions completed in a fixed window rather than as a reported rate |
| `xfuzz explain` renders the fully resolved config | Settings the file never mentions are shown and marked `(default)`; the YAML form validates as a campaign file |
| Killing the daemon mid-campaign resumes cleanly | SIGKILL at 13 corpus entries / 19 edges; a new daemon took over on the same data directory and finished at 40 entries / 29 edges with the finding intact, and no worker outlived the daemon |
| CLI/API parity test passes | Both directions, as a unit test over the route table |

### Fixed

Four defects, three of which produced no error at all:

- **A PID namespace changes the semantics of the program inside it.** The first
  process in one is PID 1, and the kernel discards signals sent to PID 1 from
  inside its own namespace unless a handler is installed. `abort(3)` raises
  SIGABRT at itself, so a target executed directly inside a PID namespace never
  aborts: glibc falls back to dereferencing a null pointer and the campaign
  records a segmentation fault where an assertion failed — filed under the wrong
  bucket, and minimised to preserve the wrong failure class. The namespace is
  now used for fork-server targets, whose executions are children, and left out
  for one-shot ones.
- **A campaign file's relative paths were resolved against whichever process
  read the file.** Resolution now always produces absolute paths, the client
  sends an absolute name, and the daemon hands workers the resolved copy it
  wrote itself.
- **A process's exit was published as a single value on a channel**, and three
  parties race for it — `Wait`, `Kill`, and the context watcher. The first took
  it and the others blocked forever on a process that had already died, which
  looks exactly like a target that will not die. It is now a closed channel, and
  the wait after a kill is bounded: a descendant that escapes its process group
  should leak a process, not wedge the fuzzer.
- **A worker's output went to `/dev/null`**, so a worker that died before it
  could speak the protocol left "exited with status 1" as the whole diagnosis.
- **Killing a handle whose process had already been reaped sent a signal
  anyway.** A process group is killed with `kill(-pid)`, and once the leader is
  reaped that pid can be handed to something else — which for a fuzzer creating
  processes by the million is routine rather than remote. The symptom is a
  daemon or a worker vanishing with nothing to trace it to.

Also: shared memory was created owned by the fuzzer while the target runs under
an unprivileged uid, so coverage was always empty — the region is chowned to the
target's identity rather than opened up; a sandboxed target cannot enter a 0700
directory, which is what `t.TempDir` returns and what most build directories
are, so campaigns refuse to start with the blocking component named; health
diagnostics no longer report "2 of 2 workers are not reporting" about a campaign
that finished on its budget; and `Worker.Close` waits for `Run` rather than
releasing the engine underneath it.

### Changed

- `internal/testenv` replaces three drifting copies of the same integration-test
  fixtures. It is allowlisted for `spawn-confinement` in `tools/archlint`, for
  the same reason `tools/` is: it exists to invoke the toolchain.
- `version.Info` carries JSON tags, so the API is snake_case throughout rather
  than snake_case except for one object.
- The engine's 10% overhead budget is not asserted under `-race`, where the
  fuzzer's own code is instrumented and the native target it is measured against
  is not.
- `test/e2e` holds the milestone exit criteria, measured against the shipped
  binaries rather than the packages behind them.
- `make test-integration` runs packages one at a time (`-p 1`). They spawn
  processes and measure throughput, so running them concurrently makes each
  one's numbers a function of what the others happen to be doing — and a
  scaling measurement taken while three other packages fuzz is not a
  measurement.

### Added — M4 Storage, triage, and safety (2026-08-28)

Crashes become findings, and the tool becomes safe to run.

**`internal/store` — the hybrid store (ADR-0008)**

- Content-addressed blob store for payloads, embedded SQL for metadata. Blobs
  are written to a temporary name and renamed, and fsynced before publication,
  because the store writes the blob first and the row second: a crash can then
  only leave an orphan, never a row promising a payload that was never written.
  Reads re-hash and refuse a blob that does not match its name.
- Schema versioning with forward-only migrations, each in its own transaction.
  Opening a store written by a newer build fails rather than reading fields it
  does not understand.
- Campaign, testcase, bucket, and finding records; disk budgets with culling
  that never touches favoured entries or finding reproducers and breaks ties on
  the digest, so two runs of a campaign cull identically; blob collection with a
  grace window, since a live payload is always briefly unreferenced.
- Atomic checkpoints: coverage (deflated — a sparse map compresses to under a
  quarter), execution count, and per-stream RNG positions.
- Hash-chained audit log. Fields are length-prefixed before hashing, so moving a
  character across a field boundary is not an undetectable edit, and the chain
  head is mirrored outside the table so truncation is detectable too. This is
  tamper *evidence*, not tamper *proofing*, and the code says so.

**`pkg/corpusio` — AFL and libFuzzer interoperability**

- Import resolves an AFL output directory to its queue, skips the bookkeeping
  and the crashes directory, de-duplicates by content, and sorts before
  importing so one directory always yields the same corpus in the same order.
- Skips are counted with reasons: a directory of a thousand files where forty
  were dropped looks exactly like one where none were, unless somebody counts.
- Export writes each layout's own convention — AFL's `id:%06d` with its `+cov`
  marker, libFuzzer's SHA-1-of-content — so the other tool's merge recognises
  the corpus rather than duplicating it, and refuses a non-empty destination
  without `Overwrite`.

**`internal/triage` — verification, minimisation, bucketing**

- Verification separates "always", "sometimes", and "never", recording the trial
  count alongside the rate so "not yet examined" and "never reproduces" cannot
  read the same. Divergent classes are kept: a crash that is sometimes a
  segfault and sometimes a hang is one finding with a race in it.
- Four bucketing strategies behind one interface, because each is wrong in a
  different direction, and a chain that tries them in order of evidence quality
  and records which one produced each signature.
- Two minimisers. Byte-level delta debugging cannot reduce a checksum-protected
  format at all — deleting bytes invalidates the length and checksum covering
  them, the parser bails before reaching the bug, and every deletion looks
  necessary. Structured minimisation removes elements from the IR and lets the
  fixup pass recompute what the removal invalidated. Measured on a checksummed
  format: 48% byte-wise, 97% structured.
- Both preserve the failure *class* — kind, signal, and the marker the program
  printed — not merely "it still crashes", which would let a minimiser wander to
  a different bug and hand back its reproducer.
- The worker's queue is bounded and `Submit` never blocks: triage re-runs the
  target hundreds of times per finding, and blocking would turn a productive
  campaign into a stalled one. Overflow is dropped and counted.

**`internal/safety` — confinement, scope, authorization**

- Namespaces, a seccomp denylist built as a BPF program, resource limits,
  cgroups (v1 and v2), and a read-only root. The level reported is computed from
  the mechanisms actually available, and a campaign may require a minimum and
  refuse to start below it.
- `cmd/xfuzz-sandbox` exists because resource limits and a seccomp filter can
  only be installed by the process that will *become* the target, and Go offers
  no hook between fork and exec. It exits 125 rather than continuing when
  confinement fails: a sandbox that quietly did not happen is worse than none.
- Scope guard: default-deny with loopback exempt, names pinned to addresses at
  configuration time, every resolved address of a name required to be in scope,
  public address space refused without a separate acknowledgement, and a prefix
  whose base is private but whose span is not caught. Refusals are audited;
  allows are not unless asked for, or a campaign making a million connections
  would bury the entries that matter.
- Authorization records operator, reference, attestation, and the scope as it
  stood at the moment of attestation, so a later widening is visible.

**`internal/engine`** — snapshot, restore, and corpus loading. A snapshot holds
only what is volatile: accumulated coverage, counters, and RNG stream positions.
Streams are recorded by name, because a snapshot outlives the build that wrote
it. `LoadCorpus` admits stored entries without executing them.

**`testdata/targets`** — `chunked_format` (5 bugs behind per-chunk CRC-32s, on
five distinct paths, ending in three distinct signals) with `chunked_format.xfg`,
and `escape`, which tries to write outside its directory, fork without bound,
allocate without bound, and call a privileged syscall.

### Measured — M4 exit criteria

| Criterion | Result |
| --- | --- |
| `chunked_format` bucket count | Signal bucketing 3, coverage bucketing 5 for 5 bugs, no two sharing a bucket, stable across repeated runs |
| Minimisation ≥ 80% preserving the bucket | 85–96% on the five reproducers, each still triggering its own bug; three differently bloated reproducers of one bug converge on the same bucket and the same 19-byte minimum |
| No sandbox escape | Target runs as uid 65533; a write outside the workdir is refused and one inside still works; a fork bomb stops at 63 against a limit of 64; 2 GiB against a 128 MiB cgroup ends in SIGKILL; `mount(2)` returns EPERM |
| No scope-guard bypass | Unlisted host refused and audited; a remote campaign with no allowlist refuses to start |
| Resume loses at most the checkpoint window | Checkpoint at 30,000 execs / 26 edges, killed at 45,000 / 29, resumed at 30,000 / 26 with all 14 corpus entries: 15,000 lost against a 15,000-execution window, nothing before it |

The full planted-bug campaign still finds every bug through the confined fork
server, in 180 seconds.

### Fixed

Three traps in the sandbox, each of which looked correct in every log line:

- **A uid mapping is not a privilege drop.** A child cloned by root with a user
  namespace mapping that omits uid 0 is still host root; it merely *reports* the
  kernel's overflow id, which looks exactly like an unprivileged uid to
  `getuid()` and to every log. The identity drop is now a real `setuid`, done by
  the helper after the steps that need privilege.
- **That overflow id is 65534.** A target mapped to it sees every file owned by
  anyone outside its namespace — the corpus included — as owned by *itself*, and
  can write all of it. Targets now run as 65533, checked against the kernel's
  own `overflowuid` rather than assumed.
- **A mount namespace created alongside a user namespace inherits its mounts
  locked**, so a read-only root cannot be built in that combination. The sandbox
  probes once with `/bin/true` rather than guessing from kernel versions, and
  where the fuzzer is root the user namespace is left out entirely — root does
  not need it, and it costs the stronger mechanism.

Also: `Sandbox.Check` refuses a workdir the target's new identity cannot reach,
because otherwise giving the target a separate uid makes every execution fail
for a reason that looks nothing like the cause.

### Changed

- Go 1.25 is now the minimum. `modernc.org/sqlite`'s dependency chain requires
  it, and ADR-0008's choice of a pure-Go SQL engine is what keeps `CGO_ENABLED=0`
  cross-builds working (ADR-0017).
- Audit action names are declared by the subsystem that emits them rather than in
  one shared enumeration, which would couple the safety layer to the persistence
  layer for the sake of a handful of strings.
- `tools/archlint` allowlists `cmd/xfuzz-sandbox` for spawn confinement. Like
  `cmd/xfuzz-cc`, it *is* an exec wrapper; the allowlist is in the lint source
  where a reviewer sees it.
- `ForkServer.HandshakeTimeout` is configurable. A target's first execution can
  be slow while its later ones are fast, and one budget for both would have to be
  the larger.
- The planted-bug README documents `chunked_format`'s calibration: its five bugs
  end in three signals so that the difference between signal bucketing and
  coverage bucketing is a measurement rather than an assertion.

### Added — M3 Execution and feedback (2026-08-28)

The engine becomes a fuzzer. Coverage-guided campaigns run end to end against
instrumented native targets and find every planted bug in the test corpus.

**`pkg/feedback` — the guidance pipeline (ADR-0007)**

- `Observer` / `Feedback` / `Objective` with a composable boolean algebra
  (`All`, `Any`, `Not`, `Fast`) with defined short-circuit and commit semantics:
  a child that never saw an execution is never told to commit it.
- Coverage map with AFL-style logarithmic hitcount bucketing, so a loop running
  a different number of times does not read as a new path, and a signature for
  asking whether a shorter input still goes to the same places.
- Output-novelty feedback with a normalisation hook, timing-outlier feedback,
  and crash, hang, OOM, sanitizer and oracle objectives.
- `ExitError` — the harness failed — is explicitly not a fault. Reporting
  infrastructure failures as findings is how a fuzzer loses its credibility.

**`pkg/executor` — tiers T0, T2, T4 (ADR-0009)**

- T0 in-process for Go harnesses, T2 fork server, T4 subprocess with stdin, file
  and argument delivery.
- Capabilities report what is *enforced*, not what is planned: an executor that
  cannot stop a hung target says its timeouts are advisory.
- The spawn boundary. `pkg/executor` declares `Spawner` and
  `SharedMemoryProvider`; `internal/safety` and `internal/platform` implement
  them. ADR-0012 makes confinement mandatory, and the only way to guarantee that
  is to leave executors no other way to start a process.

**`pkg/corpus`** — content-addressed testcases, provenance, and three power
schedules (uniform as a control, round-robin, and a weighted schedule).

**`internal/safety`** — the only thing in Xfuzz that creates a process: process
groups so a timeout kills what the target started, enforced timeouts, and
bounded output capture. Isolation reports `minimal` until M4.

**`internal/engine`** — the fuzz loop, corpus trimming, finding buckets, and
per-worker deterministic RNG streams.

**Instrumentation (ADR-0001)** — `xfuzz-cc` wraps clang and links `xfuzz-rt`, a
small C runtime providing edge coverage over shared memory and a fork server.
An instrumented binary still runs standalone. The runtime is embedded in the
wrapper, and `xfuzz-cc --print-runtime` writes it out, because anyone asked to
link code into their software should be able to read it first.

**Planted-bug targets** — `simple_parser` (3 bugs, shallow), `magic_parser`
(4 bugs behind magic values, with a dictionary), plus `hang` and `nop` for
timeout enforcement and measuring the protocol floor.

**Results**

| Measurement | Result |
| --- | --- |
| Planted bugs found | 3/3 and 4/4 |
| T2 fork server, realistic target with coverage | 2,787 exec/s (89% of the 3,129 exec/s host floor) |
| T4 subprocess | 742 exec/s — the fork server is 3.8× faster |
| Engine overhead | 3.7% |
| Coverage map scan, 64 KB | 9.3 µs, zero allocations |
| Determinism | byte-identical traces across runs |
| Guided against blind | corpus 12 vs 1, coverage 37 vs 0 |

### Fixed

Four bugs found by the tests, each invisible from outside the fuzzer:

- **Coverage instrumented at the wrong level.** Clang defaults
  `-fsanitize-coverage` to `func`, one guard per function, which cannot
  distinguish two inputs taking different branches of the same function.
  Coverage-guided fuzzing silently degrades to random. Now `bb,no-prune`.
- **Sequential block identifiers collided in the edge encoding.** The index is
  `prev>>1 ^ loc`, so clustered identifiers cluster indices and distinct edges
  collapse onto one. Two depths of a comparison ladder were indistinguishable.
  Identifiers are now hashed across the map.
- **The fork server polluted its own coverage map.** Its loop runs in the parent,
  which holds the same shared map, so it incremented counters while the fuzzer
  was clearing and reading them. The symptom was a campaign that was identical
  for tens of thousands of executions and then quietly divergent.
- **The power schedule weighed measured execution time**, which varies with
  machine load — an ASR-0008 violation inside code written to serve ASR-0008.
  Now opt-in via `PreferFast`, off by default.

Also: a timing observer overwrote the spawner's more accurate measurement during
harvest; `ProcSpec.Args` was ambiguous about `argv[0]` and every target was
receiving it twice.

### Changed

- Corpus trimming moved from M4 into the engine. Mutation grows inputs, and a
  mutator picks a position uniformly, so an entry that has drifted to fifty
  bytes gets a fraction of the attention per byte a short one does. Measured: a
  campaign reliably climbed a comparison ladder two steps and stalled; with
  trimming it walks it to the end. That is core engine work, not triage.
- `tools/archlint` exempts `_test.go` files from spawn confinement, since a test
  file is not part of any shipped binary and the rule protects runtime
  behaviour. Production code is still caught, which its own test asserts.
- The planted-bug ladder in `simple_parser` uses boundary values rather than
  arbitrary constants. It is the *shallow* target, and a bug needing comparison
  logging to reach does not belong in it — that belongs to `magic_parser` and to
  v0.3.
- Campaign tests sit behind an `integration` build tag with their own CI job, so
  the pre-commit suite stays under a second.
- ARCHITECTURE § 3.2 carries the implemented interfaces, the spawn boundary, and
  measured per-tier throughput; TESTS.md § 7 documents the two-part throughput
  gate and § 10 the CI matrix that exists.

### Added — M2 Mutation and generation (2026-08-28)

Everything that turns one input into another: the operators, the schedule that
composes them, the grammar language, and generation.

**`pkg/rng` — deterministic randomness**

- Counter-based generator: splittable into independent streams, with an
  addressable position that can be recorded in provenance and seeked back to.
- Eight numbered streams (seed selection, operator selection, operator
  parameters, structure, splice, generation, schedule, state) so that adding a
  stage cannot perturb another stage's sequence and old findings keep replaying.
- Bounded draws use Lemire's multiply-shift, free of the low-bit bias a modulo
  introduces. 0.4 ns per draw, no allocation.

**`pkg/mutate` — 24 operators and a schedule**

- Byte-level: bitflip, byteflip, arithmetic, interesting values, random byte,
  block set, insert, delete, self-copy.
- Structured: integer arithmetic/boundary/random/bitflip, choice switching,
  optional toggling, and sequence insert, delete, duplicate, swap, and shuffle.
- Dictionary: token overwrite and insert, with AFL `.dict` parsing.
- Splice: subtree grafting matched on kind and name, and byte-run crossover.
- Weighted, **operator-first** scheduling. Picking a node first and then an
  applicable operator hands the mix to whichever operator has the broadest
  applicability; it gave subtree splicing eight times the attempts of every byte
  operator combined, with the weights saying otherwise.
- Provenance: every applied operator records its name, the path to the node, and
  the parameter stream's position — enough to reconstruct the input exactly,
  which `TestProvenanceReplaysExactly` checks on every round.
- Per-operator accounting with `Report()` ordered by yield.

**`pkg/schema` — the `.xfg` grammar language**

- Lexer, recursive-descent parser, validator, and a renderer that round-trips.
- Scalar types with explicit width and byte order, bounded and fixed-length
  `bytes`/`str`, `magic`, `repeat<min..max>`, `opt`, `choice`, and named structs.
- Derivations: `len`, `count`, `offset`, and any registered checksum, over a
  single reference or a range, with an optional addend and `selfzero`.
- Unguarded recursion is rejected at parse time, with the fix named: put the
  recursive field behind a `repeat` or an `opt` so generation can stop.

**`pkg/generate` — grammar-driven generation**

- Builds IR trees from a schema with depth, size, and repetition bounds, then
  runs the fixup pass so derived fields are correct.
- `pkg/generate/testdata/png.xfg` describes PNG in the language; generated files
  round-trip through the hand-written Go codec, so the two agree on the format.

**Results**

| Measurement | Result |
| --- | --- |
| Structured vs byte-level mutation, container-valid | **99.6% vs 0.0%** |
| Same mutations, repair pass disabled | 10.4% |
| Generated PNGs passing container validation | 2,000 / 2,000 |
| Mutate + repair + encode | 5.0 µs, 0 allocs |
| Mutation round alone | 1.1 µs, 0 allocs |
| Generate a ~33-chunk PNG | 92 µs, 0 allocs |

### Changed

- `pkg/ir`: nodes gained `MinLen`/`MaxLen` bounds and an `Immutable` flag, with
  `FixedBlob`, `Magic`, and `Bounded` constructors. Byte and sequence operators
  honour them. Without these, mutation resized the PNG chunk type field and
  corrupted the signature — inputs no reader gets past. Container validity rose
  from 47% to 99.6% once the format's real constraints were expressible.
- `pkg/codec`: the PNG codec now declares the signature immutable and the chunk
  type fixed at four bytes.
- `pkg/ir/Arena` gained `Buf`, `GrowBytes`, and `GrowKids`, so mutations that
  lengthen a payload or a sequence stay inside the arena.

### Fixed

- `RepeatShuffle` reported "no change" whenever the first element happened to
  stay put, so a shuffle that permuted everything else went unrecorded — an
  untracked mutation that broke replay. Found by the provenance replay test.
- The mutation scheduler recorded provenance paths into the same buffer the tree
  walk was using, so every recorded path was overwritten by the next one.
- The node-selection walk was a recursive closure, which allocated on every
  mutation round.
- `ir.Fixer` used `sort.Slice` on the hot path, which allocates a reflect-based
  swapper.

### Added — M1 Input IR and codecs (2026-08-28)

The structured input representation from ADR-0005, and the first two codecs.
This was the milestone carrying the design's central risk: whether a typed tree
can be mutated, repaired, and encoded without allocating, at fuzzing rates.

**`pkg/ir` — the unified input representation**

- Nine node kinds (`Bytes`, `Int`, `Str`, `Struct`, `Repeat`, `Choice`, `Opt`,
  `Ref`, `Derived`) with traversal, structural validation, and equality.
- Generic encoding: the wire form of a tree is the concatenation of its leaves
  in document order, so format knowledge is confined to decoding.
- Relative references (`^data`, `^^hdr.len`, `/chunks[0]`) resolved against an
  ancestor chain, with a textual form and parser. Nodes carry no parent
  pointers, which keeps them small and copy-on-write simple.
- Four derivation classes — `Length`, `Count`, `Offset`, `Checksum` — with an
  addend, twelve built-in checksum algorithms, and a registry for more.
- The fixup pass: sizes and offsets computed once (no derived value can change
  any node's size, so they cannot cycle), then checksums ordered by span
  containment with Kahn's algorithm in document order. Mutually covering
  checksums are reported as cycles; a checksum covering its own field requires
  an explicit `SelfZero`, which is how IPv4 and similar formats define it.
- `Suppress` leaves chosen derivations inconsistent on purpose, per class or per
  node — without which a fuzzer could never reach a target's validation code.
- `Arena`: a bump allocator over fixed slabs with `Reset`, plus copy-on-write
  path copying. Payloads are copied rather than shared so in-place byte mutation
  cannot corrupt the corpus entry a clone came from.

**`pkg/codec` — bytes to trees**

- `Codec` interface and registry, with lookup by name and by file extension.
- `raw`: the degenerate codec, so unstructured targets need no special handling
  anywhere else in the engine.
- `png`: signature plus length-prefixed, CRC-protected chunks — the archetype of
  the format family that defeats byte-level fuzzing.
- Decoding is **total and preserving**: malformed input yields a partial tree
  with unrecognised bytes kept in opaque nodes, and values read from the file are
  preserved even when wrong. Decode preserves; fixup repairs.
- `UnparsedBytes` and `StructuredFraction` report how much of a seed a codec
  actually understood — the signal that a campaign's schema does not match its
  corpus.

**Measured** (all zero-alloc, so gated on every platform)

| Operation | Cost |
| --- | --- |
| PNG decode | 148 ns/op, 620 MB/s |
| Clone + mutate + fixup + encode | 1.8 µs/op (~545k/s) |
| Copy-on-write mutation | 69 ns/op |

**Tests**

- Property and round-trip tests per TESTS.md § 3: byte-exact round trip,
  idempotent and order-independent fixups, zero steady-state allocation, no
  aliasing across arena generations.
- `FuzzPNGDecode` checks the round-trip invariant on every input; 3.8M
  executions found no crash and no violation.
- End-to-end: a chunk inserted through the IR and fixed up is accepted by the
  standard library's PNG decoder, which validates every CRC; with checksum
  fixups suppressed it is correctly rejected.

### Changed

- ARCHITECTURE.md § 3.1 now carries the implemented interfaces and the reasoning
  behind two departures from the sketch: scalar detail is stored inline rather
  than behind a `Meta` pointer, and the Arena is a bump allocator with `Reset`
  rather than a free list with `Release`.

### Added — M0 Foundation (2026-08-28)

Repository skeleton and the quality machinery that every later milestone is
measured against. No engine code yet; M1 (input IR and codecs) is next.

**Module skeleton**

- Package layout per ARCHITECTURE.md § 2: `pkg/` (11 packages), `internal/`
  (10 packages), `cmd/` (4 commands), `bench/`, `tools/`.
- Each package carries a `doc.go` stating its responsibility and its
  architectural constraints, with the governing ADR named.
- `internal/version` with link-time build identity and cgo detection, so
  `--version` reports whether the fast paths are available (ADR-0017).
- `cmd/xfuzz`, `cmd/xfuzzd`, `cmd/xfuzz-worker`, `cmd/xfuzz-cc` build and report
  version; they exit non-zero pending implementation rather than pretending.

**Enforcement tooling** — each rule the documentation claims is now a Go test

- `tools/archlint` — the seven layering rules of ARCHITECTURE.md § 2:
  `pkg-no-internal`, `core-no-executor`, `platform-build-tags`,
  `spawn-confinement`, `dial-confinement`, `no-cmd-import`, `no-stdlib-plugin`.
  Exceptions sit in an explicit allowlist. Its own tests assert that every rule
  fires against a deliberately violating fixture.
- `tools/docslint` — ASR/ADR traceability across record headers, both indexes,
  and the ARCHITECTURE matrix, plus link resolution across `docs/`. Also tests
  that it detects injected drift.
- `tools/licensecheck` — the ADR-0018 dependency policy against a
  machine-readable `NOTICE` inventory: missing entries, stale entries, version
  drift, and forbidden or unknown licences all fail the build.
- `tools/benchcmp` — benchmark regression gate with median-of-N sampling and
  provenance-aware gating (timings gate only when both runs come from the same
  host; allocation counts gate everywhere).

**Performance harness**

- `bench/` with the ASR-0007 executor floors as data, a `TestFloorsMatchDocumentation`
  test tying them to TESTS.md § 7, an allocation assertion helper, and a
  committed `bench/baseline.txt`.

**Build and CI**

- `Makefile` with the TESTS.md § 13 target set plus `bench-baseline`,
  `bench-check`, `cross`, `lint-*`, and `ci`.
- `.github/workflows/ci.yml`: lint, test on Linux/macOS/Windows, `CGO_ENABLED=0`
  build, cross-compile matrix, `govulncheck`, and benchmark gating.

### Changed

- `internal/sync` renamed to `internal/corpussync` — the original name would
  shadow the standard library at every use site. ARCHITECTURE.md § 2 updated.
- ARCHITECTURE.md § 2 now states the layering rules as a table naming each
  enforced lint rule, and records `tools/`, `bench/`, `.github/`, and
  `internal/version`.
- TESTS.md § 7 documents the benchmark noise mitigations; § 10 replaces the
  aspirational CI matrix with the one that exists, and states two gaps plainly
  (no race detector on Windows, no native arm64 execution); § 11 adds
  architecture boundaries as a checked layer; § 13 matches the Makefile.
- `NOTICE` restructured with a machine-readable Components table and an explicit
  allowed/conditional/forbidden licence policy.

### Added — Design baseline (2026-08-28)

Initial architecture and design record. No executable code yet; this release
establishes the decisions that the implementation will follow.

**Documentation**

- `docs/DESIGN.md` — product design: problem, principles, core model, capability
  matrix, campaign format, interfaces, non-goals, risks.
- `docs/ARCHITECTURE.md` — components, package layout, core interfaces, fuzz
  loop, data flow, storage model, concurrency, platform abstraction, API surface,
  extension points, traceability matrix.
- `docs/SECURITY.md` — threat model (10 threats), controls, residual risks,
  responsible use, vulnerability reporting.
- `docs/TESTS.md` — ten-layer test strategy targeting the two defining failure
  modes of a fuzzer: silent ineffectiveness and performance regression.
- `docs/MVP_PLAN.md` — nine milestones (M0–M8) to v0.1, with dependencies, exit
  criteria, risk register, and post-v0.1 roadmap.

**Architecturally Significant Requirements** — 15 records in `docs/asr/`

Multi-domain target coverage; stateless and stateful fuzzing; black-, grey-, and
white-box operation; pluggable guidance strategies; dual CLI and web interface;
cross-platform support; throughput and scalability; reproducibility and
determinism; extensibility; safety, isolation, and authorization; finding quality
and triage; observability and resumability; corpus and format interoperability;
input validity and structure awareness; operability and deployment.

**Architecture Decision Records** — 21 records in `docs/adr/`

| ADR | Decision |
| --- | --- |
| 0001 | Novel engine from scratch, no ecosystem runtime dependency |
| 0002 | Pluggable multi-backend instrumentation |
| 0003 | Daemon core with thin CLI and web clients |
| 0004 | v1 domain focus: file formats and network protocols |
| 0005 | Unified structured input IR with derived fields and fixups |
| 0006 | Explicit state machine with state as a feedback signal |
| 0007 | Composable feedback pipeline (Observer → Feedback → Objective → Scheduler) |
| 0008 | Hybrid corpus store: SQL metadata + content-addressed blobs + AFL export |
| 0009 | Tiered executors, T0–T7 |
| 0010 | Three-tier extensibility: native Go, out-of-process plugins, Starlark |
| 0011 | Full campaign console as an embedded SPA |
| 0012 | Sandbox by default and scope guard |
| 0013 | GUI/TUI driver adapters with UI-state feedback |
| 0014 | Traffic-replay-driven API fuzzing |
| 0015 | Single-node multi-core process parallelism |
| 0016 | Config-only campaign definition |
| 0017 | Pure-Go core with cgo behind build tags |
| 0018 | Proprietary commercial license |
| 0019 | Module path `github.com/rom/Xfuzz` |
| 0020 | MVP as an end-to-end thin slice |
| 0021 | Layered, differential, and self-fuzzing test strategy |

**Project scaffolding**

- `go.mod` — module `github.com/rom/Xfuzz`, Go 1.24.
- `LICENSE` — proprietary commercial notice (ADR-0018).
- `NOTICE` — third-party inventory with the dependency licence policy.
- `README.md`, `.gitignore`.

### Open decisions

Deliberately deferred, each requiring its own ADR before implementation:

- Concolic/symbolic backend for hybrid fuzzing (boundary defined in ADR-0007).
- Distributed fuzzing coordinator and corpus sync protocol (out of scope per
  ADR-0015).
- Snapshot-based execution as an executor tier (rejected for v1 in ADR-0006).
- Grammar inference from corpora.

[Unreleased]: https://github.com/rom/Xfuzz/commits/main
