# Using Xfuzz

> From an installed binary to a first finding, without reading any source.

## What Xfuzz is

A fuzzer runs a program against millions of generated inputs and tells you which
ones broke it. Xfuzz runs a **campaign**: a target, a corpus, a mutation
strategy, what counts as interesting, what counts as a bug, and when to stop.

A campaign is described entirely by a file. What that file says is what runs —
there are no hidden flags, and `xfuzz explain` prints the whole resolved
configuration including every default. That is deliberate: a campaign that
cannot be reproduced from a file is a result nobody can check
([ADR-0016](adr/ADR-0016-config-only-campaign-definition.md)).

## Install

```console
$ make build          # into ./bin
$ export PATH="$PWD/bin:$PATH"
```

Five binaries are produced. You only invoke the first:

| Binary | What it is |
| --- | --- |
| `xfuzz` | the CLI — everything you do goes through it |
| `xfuzzd` | the daemon, which owns campaigns and their storage |
| `xfuzz-worker` | one fuzzing process; the daemon starts these |
| `xfuzz-cc` | a compiler wrapper that builds instrumented targets |
| `xfuzz-sandbox` | the Linux confinement helper |

You do not need to start the daemon. `xfuzz` starts a private one on first use
and reuses it afterwards; pass `--no-start` if you would rather it failed.

## Check the machine first

```console
$ xfuzz doctor
```

It reports what this host can actually do — not what the build supports — and
says why anything is missing. The two lines to look at before anything else:

- **`execution`** — a confined process was launched and exited. If this fails,
  no campaign will run, and the reason is here rather than fifteen minutes into
  one.
- **`shared-memory`** — without it there is no coverage map, so only black-box
  campaigns are possible. That is the normal state of affairs on Windows for a
  C target; a Go target has its own route, and `go-coverage` is the line that
  says so.

If you mean to fuzz a terminal program, look at **`pseudo-terminal`** too. It is
the one capability whose absence has no symptom: over pipes a curses program
still starts and still draws something, and it is a different program from the
one anybody runs.

`isolation` says how much confinement this host can provide: `none`, `minimal`,
`moderate` or `strong`. A campaign that asks for more than the host has refuses
to start rather than running unconfined and saying nothing.

## Your first campaign

### 1. Get a target

Xfuzz fuzzes any program that reads input. If you can rebuild it, build it
instrumented — a campaign with coverage feedback is worth many without one:

```console
$ xfuzz-cc -O1 -o target target.c
```

`xfuzz-cc` wraps your compiler and adds edge instrumentation. If you cannot
rebuild — a vendor binary, a stripped one — Xfuzz still works black-box; see
[Fuzzing a binary you cannot rebuild](#fuzzing-a-binary-you-cannot-rebuild).

### 2. Write the campaign file

```console
$ xfuzz init --target ./target --name first -o first.yaml
```

That writes a commented starter file. The parts to look at:

```yaml
name: first

target:
  path: ./target
  input: stdin      # or: file (with @@ in args), or arg
  timeout: 5s

seeds:
  dirs: [./seeds]   # real inputs the target accepts

feedback:
  coverage: sancov
  objectives: [crash, hang, oom, sanitizer]

stop:
  after: 1h
```

**Seeds matter more than anything else in this file.** A corpus of real inputs
is what mutation has to work from; without one, a campaign spends its first
hours rediscovering the file format. Half a dozen small, valid, *different*
files beat a thousand near-identical ones.

If you have none, and the format is one you can describe, generate them:

```yaml
seeds:
  generate: 64
format:
  grammar: ./format.xfg
```

### 3. Check it before running it

```console
$ xfuzz validate first.yaml
$ xfuzz explain first.yaml
```

`validate` reports every problem in the file at once, each with the field and a
hint. `explain` prints the fully resolved configuration — every default filled
in, every profile applied — which is the answer to "what will this actually do".

### 4. Run it

```console
$ xfuzz run first.yaml
```

It follows the campaign and prints progress until the stop condition. Add
`--detach` to return immediately and watch it another way:

```console
$ xfuzz status first        # counters, health, state
$ xfuzz watch first         # the live event stream
$ xfuzz metrics first       # history and diagnostics
```

### 5. Read the findings

```console
$ xfuzz findings first
    ID KIND       TRIAGE       JUDGED          REPRO  SUMMARY
     1 crash      minimized    -           100% of 5  fatal signal SIGABRT
     2 crash      minimized    -           100% of 5  fatal signal SIGABRT

$ xfuzz findings buckets first
    ID FINDINGS KIND       SIGNATURE         SUMMARY
     3       12 crash      signal:crash/sig  fatal signal SIGABRT

1 bucket(s)

$ xfuzz findings get first 1            # everything about one finding
$ xfuzz findings get first 1 -o repro   # write the reproducer to a file
```

Twelve findings, one bug. That is the normal shape of a campaign's output, and
it is why the bucket count is the number to read.

Findings are **bucketed**: many crashes at one place are one bug. The bucket
count in `xfuzz status` is the number that matters, not the finding count.

Each finding is triaged automatically — re-run several times to see whether it
reproduces, then minimised while preserving its failure class. `REPRO` is how
many of those runs failed; `5/5` is a solid bug, `1/5` is one that depends on
something the reproducer does not capture.

Record what you decide about one:

```console
$ xfuzz triage first 1 --as confirmed --note "reported upstream as #4821"
```

Your judgement and the machine's account are kept separately, so re-running
triage never overwrites what you wrote.

### 6. Reproduce it

```console
$ xfuzz replay first 1     # run it again, report whether it still fails
$ xfuzz minimize first 1   # reduce it further
```

A campaign is reproducible from its seed: the same file and the same seed
produce the same sequence of inputs on any machine
([ASR-0008](asr/ASR-0008-reproducibility-and-determinism.md)). `xfuzz status`
prints the seed; put it in the file to replay a whole campaign.

## The web console

If your build has it (`make build-console`), the daemon serves a browser
interface on the same socket, with the same authorization and no privileged path
of its own. It does everything the CLI does — the two are held at parity by a
test — and some things it does better: coverage over time, the protocol state
graph, and editing a campaign file with its samples regenerating as you type.

```console
$ xfuzz info      # prints the URL
```

## Fuzzing a binary you cannot rebuild

No instrumentation means no coverage map, so novelty of the target's *output*
stands in for it. This is a supported mode, not a fallback
([ASR-0003](asr/ASR-0003-black-grey-white-box-operation.md)):

```yaml
target:
  path: ./vendor-binary
feedback:
  coverage: none
  novelty: true
  objectives: [crash, hang, oom, sanitizer]
```

Expect a smaller fraction of the input space explored and a slower rate — a
process per execution rather than a fork server. It still finds bugs, and on
Windows it is how a C target runs: shared memory there is a Unix mechanism in
this build, so an instrumented target has nowhere to write its map. A **Go**
target is a different story on every platform — see below.

With no coverage to collect, `executor: auto` picks the **pool**: processes are
created before their input exists and handed it when it arrives, so the cost of
starting one is paid while the previous one is still running. Measured against
one spawn per execution on the same target: 1,420 against 559 executions a
second. `executor: subprocess` is still there and still always works, which is
what to reach for if a target dislikes being started before it is needed.

### Coverage without rebuilding it

Black box is not the only option. Xfuzz can watch the program run and work out
which basic blocks it entered, which gives a coverage-guided campaign against a
stripped binary with no source, no symbols and nothing linked in:

```yaml
target:
  path: ./vendor-binary
feedback:
  coverage: ptrace-bb      # or qemu, or frida
  objectives: [crash, hang, oom, sanitizer]
```

Nothing else changes. `executor` can stay `auto` — a backend that works by
watching the process selects the tier that watches it — and the corpus, the
mutators and the findings behave as they do anywhere else.

| Backend | How | Signal | Needs |
| --- | --- | --- | --- |
| `ptrace-bb` | A trap instruction at each block, removed after its first hit | Blocks | Linux, and a kernel that permits ptrace |
| `qemu` | User-mode emulation, reading the emulator's own execution log | Edges | `qemu-user` installed |
| `frida` | Dynamic instrumentation through a Stalker agent | Blocks | the `frida` tool installed |

`xfuzz doctor` has a row for each, and says what is missing rather than that a
backend is unavailable — the useful half of the answer is the package name.

**What it costs.** One to two orders of magnitude of throughput, which is why
nothing selects these automatically. Measured on a stripped planted-bug target
over the same forty-five-second window, once watching the process and once
seeing only its output:

```
ptrace-bb   7811 execs, 14 corpus entries, 29 coverage entries, 2 findings
blackbox    9127 execs,  5 corpus entries,                      1 finding
```

Roughly the same number of executions on this target, nearly three times the
corpus, twice the findings.

**What it cannot see.** Xfuzz finds the blocks by analysing the binary, and that
analysis is partial in the ways static analysis always is: an indirect branch —
a jump table, a virtual call, a function pointer — leads somewhere it cannot
compute. The campaign's first status line says how many blocks were recovered,
what fraction of the executable bytes they account for, and how many indirect
branches defeated the analysis. A target that is mostly indirect branches will
report coverage with holes in it, and those numbers are how you find that out on
the first day rather than the fifth.

`qemu` is the exception: the emulator sees every block it runs, including the
ones the analysis missed, and sees them in order — so it is the one backend here
that produces edge coverage. It is also the slowest and needs `qemu-user`
installed.

## Fuzzing a Go program

A Go target needs no C compiler and no source change. Build it through the
wrapper and point the campaign at it:

```console
$ xfuzz-cc --go -o ./target ./cmd/parse
```

```yaml
target:
  path: ./target
  executor: subprocess
feedback:
  coverage: gocov
  objectives: [crash, hang, oom]
```

`coverage:` has no auto mode — the default is `sancov`, which a Go target does
not carry — so `gocov` has to be named. What happens underneath is that Go's own
compiler instruments every package — the standard library included, so
a program that spends its time in `encoding/json` is not invisible — and the
Xfuzz runtime maps the counter array the target increments straight onto the
region the fuzzer reads. Nothing is collected at the end of an execution, which
is why **a run that crashes still reports its coverage**. On the same target and
seeds over 20,000 executions, this kept 12 corpus entries where black box kept 2.

Two things to know:

- **The signal is blocks, not edges.** A counter says a basic block ran; it says
  nothing about the order, so two inputs that took different routes through the
  same blocks look identical. The campaign reports this granularity rather than
  implying edges.
- **No fork server.** The runtime's fork server is entered from a C constructor,
  before the Go runtime has registered the counter array, so there would be
  nothing to map at the moment of the fork. `target.executor: auto` therefore
  resolves to `subprocess` here, and asking for `forkserver` explicitly is
  refused with that reason rather than quietly downgraded.

If the build fails for want of a C compiler, that is expected: the Xfuzz runtime
is C and has to become an object file before Go's linker can be handed it. Any
`cc` will do — it is not instrumenting anything.

## Aiming a campaign at one place

Sometimes the question is not "are there bugs" but "can this line be reached" —
a patch to review, a function a report names, an address from a stack trace.
Coverage-guided fuzzing answers the first question and is indifferent to the
second: it spends its budget proportionally across everything it can reach.

A `directed` block changes that:

```yaml
feedback:
  coverage: sancov
  directed:
    targets:
      - parse_header          # a function
      - decode.c:412          # a line from a patch
      - "0x4015a0"            # an address from a crash report
    min_reachable: 0.05       # refuse to start if too little of the program can get there
```

Xfuzz measures, for every basic block, how many blocks away it is from the
nearest target, and then keeps inputs that came *closer* than anything before
them — even when they covered nothing new — and spends more of the schedule on
them.

The first status line reports what it is working with:

```
directed at 3 location(s); 412 of 1804 blocks reach one (23%), furthest 19
```

That fraction is the number to read. Direction measured over a small part of the
program is not direction: every input scores the same, and the campaign looks
exactly like one that has not made progress yet. `min_reachable` refuses to
start below a threshold you set, which is better than finding out after a week.

Direction works with `sancov` and with all three binary-only backends, so it
composes with the previous section: aiming a campaign at a patch in a binary
nobody can rebuild is the case both features exist for.

## Getting past a magic number

A four-byte magic number is one chance in four billion per attempt. A checksum is
worse. Mutation does not solve either, because there is nothing to climb: every
wrong value is equally wrong and coverage stays flat until the exact value
appears.

If the target was built with `xfuzz-cc`, Xfuzz can read the comparisons the
program actually performed and write what it wanted into the input:

```yaml
feedback:
  coverage: sancov
  cmplog: true
  value_profile: true     # also keep inputs that got *closer* to passing
```

`cmplog` finds the value your input supplied inside your input and substitutes
the value the program expected — one edit instead of four billion guesses. It
tries several encodings, because a program that compares an integer did not
necessarily read it from the input as one: little- and big-endian, decimal, hex,
and the neighbouring values for comparisons that are not equalities.

`value_profile` is the other half. It treats a comparison that nearly passed as
new coverage, so a campaign can climb a comparison it cannot jump — which is
what gets past a checksum, where no single byte is ever individually right. It
admits a great many inputs, so turn it on when `cmplog` alone is not enough
rather than by default.

Measured on a target with three gates — 32, 64 and 16 bits wide — from the same
seed and the same twenty-thousand-execution budget:

```
with cmplog     14 coverage entries, 5 corpus entries, bug found
without          6 coverage entries, 2 corpus entries, nothing
```

Both need an instrumented build; validation refuses the combination rather than
letting a campaign spend the executions and admit nothing. If you want to measure
the instrumentation's own cost on your target, `XFUZZ_NO_CMPLOG=1 xfuzz-cc ...`
builds it without.

## Fuzzing a network protocol

A campaign becomes stateful when it has a `session` block. Xfuzz then sends a
*sequence* of messages, reads the replies, and builds a model of the protocol's
states from them — because two sequences that execute identical lines can leave
a server in different places, and coverage alone cannot tell them apart
([ADR-0006](adr/ADR-0006-explicit-state-machine-with-state-feedback.md)).

```yaml
target:
  path: ./server
session:
  address: tcp:127.0.0.1:900{worker}
  framing: idle
  reset: reconnect
state:
  fn: status          # status, http, fingerprint, constant, or script
  guide: true
```

```console
$ xfuzz states mycampaign               # the states it has found, with examples
$ xfuzz states mycampaign --transitions # and every move between them
```

If the protocol is one nobody has documented and you know its shape, write the
labelling rule yourself in four lines of Starlark — see
[Campaign-local logic](#campaign-local-logic).

## Fuzzing an HTTP API

A campaign becomes an API campaign when it has an `api` block. The starting
point is a *capture* rather than a specification: a recording carries the
requests a client actually sends, the values that chain between them, and the
identity they were sent as, and none of those is in a specification
([ADR-0014](adr/ADR-0014-traffic-replay-driven-api-fuzzing.md)).

Save a session from your browser as a HAR, or a pcap from `tcpdump`, or paste
the requests into a file. Then split it into what a campaign needs:

```console
$ xfuzz capture session.har -o session.http --secrets api.secrets --links
session.har: 14 exchange(s) across 1 host(s); 2 credential(s)
  9 dependenc(ies) inferred
    exchange 0 body /access_token -> exchange 1 header Authorization
    exchange 1 body /id -> exchange 2 path segment 1
  wrote api.secrets (mode 0600)
  wrote session.http (3184 bytes)
```

`session.http` holds placeholders where the credentials were and is safe to
commit. `api.secrets` holds the values and is not — it is read once at startup
and substituted immediately before each request is written, so a token is in
memory for the length of one send and is never in the corpus or the store.

```yaml
api:
  address: tcp:127.0.0.1:8080   # where to send them, which need not be where they were recorded
  capture: ./session.http
  secrets: ./api.secrets
  oracles: [status, schema, latency]
```

The oracles are the point. A service almost never crashes — it is behind a
supervisor, its handler has a recover, and the process outlives anything one
request can do to it — so a campaign judging only crashes finds nothing.

| Oracle | What it reports |
| --- | --- |
| `status` | 5xx, and nothing else. A 4xx is the service saying the fuzzer sent nonsense, which is the expected outcome of nearly every mutation |
| `schema` | A field whose *type* changed from what this endpoint has always produced. A new field is not a violation; services add them |
| `latency` | A response far outside the norm this service has shown, learned rather than declared, with outliers kept out of the norm |
| `authorization` | A session replayed as one identity that should not have succeeded |

The authorization oracle needs to be told what it is comparing against:

```yaml
api:
  identity: mallory
  expect: denied
  oracles: [status, authorization]
```

Replay the same capture twice — once as the owner with `expect: allowed`, once
with another identity's credentials and `expect: denied` — and anything that
still succeeds has no authorization check. This is the class captured traffic
makes reachable and a specification does not.

## Fuzzing a terminal program

A campaign becomes a user-interface campaign when it has a `driver` block. The
input is a sequence of interaction events rather than data, and the program runs
on a pseudo-terminal with an emulator watching what it draws
([ADR-0013](adr/ADR-0013-gui-tui-driver-adapters.md),
[ADR-0030](adr/ADR-0030-terminal-emulation-is-the-tui-observable.md)).

```yaml
target:
  path: ./myapp
driver:
  kind: tui
  cols: 80
  rows: 24
  oracles: [diagnostic, unresponsive, trap]
seeds:
  inline:
    - "key 1\nkey down\nkey enter\n"
    - "key 2\nkey escape\nkey q\n"
```

A seed is a text file of events, one per line, so you can write one by hand and
read a finding without a decoder:

```
key enter          a named key: enter, tab, up, ctrl-c, f5, alt-x
text hello world   literal text typed
click 10 4         a pointer press, sent only if the program asked for mouse reporting
wait 200ms         let it settle longer than usual
resize 80 24       change the terminal size, which the program is told about
```

A line that is not an event is typed literally, so an ordinary file is a usable
seed.

The three oracles are for the three ways an interface fails while the process
stays alive and the exit status stays zero:

| Oracle | What it reports |
| --- | --- |
| `diagnostic` | A stack trace, a panic or an assertion on the screen. A runtime that catches an error at the top of its event loop prints it and keeps running |
| `unresponsive` | The interface stopped changing while events kept arriving — and it was responding earlier, which is what separates a hang from a program that ignores keys it does not bind |
| `trap` | A screen the campaign has reached several times, spent several events in, and never once left |

The tier is slow — a restart per sequence is the dominant cost — so it defaults
to one worker and much smaller triage budgets than a file campaign.

## Importing a grammar somebody else wrote

Writing a grammar takes hours, and most formats already have a description
somebody else debugged. `xfuzz grammar import` reads six of those languages:

```console
$ xfuzz grammar import api.proto -o api.xfg
proto: 9 types, 57 fields; 3 constructs not translated:
  imported definition (1): google/protobuf/timestamp.proto is a separate file...
  varint length (13): a length above 127 needs a multi-byte varint...
  varint scalar (2): a value above 127 needs a multi-byte varint...
wrote api.xfg: 9 type(s), root Order
```

| Language | Extension | Notes |
| --- | --- | --- |
| ABNF | `.abnf` | RFC 5234 with RFC 7405's case markers; the core rules are supplied |
| Kaitai Struct | `.ksy` | `size: field` becomes a length derivation on that field |
| JSON Schema | `.json` | Produces a grammar for JSON *text*, punctuation immutable |
| OpenAPI | `.yaml`, `.json` | Produces HTTP requests, one alternative per operation |
| Protocol Buffers | `.proto` | The wire format; keys are exact, varint values are one byte |
| ASN.1 | `.asn1` | The DER encoding; tags are exact, lengths are short-form |

The report is the part that matters. Every one of these languages can say things
the Xfuzz grammar cannot, and an importer that silently dropped them would give
you a grammar that looks complete and generates inputs the parser rejects at the
first field. What it could not translate is printed to standard error, so the
grammar can be redirected and the limits still read
([ADR-0031](adr/ADR-0031-grammar-imports-are-subsets-with-reports.md)).

A description usually has more than one entry point and a grammar has one root.
Unreachable types stay in the file and are listed in the report; `--root NAME`
picks a different one.

## Making it faster

`xfuzz status` reports health diagnostics as well as counters. The ones that
usually matter:

| Diagnostic | What to do |
| --- | --- |
| `overhead` over 10% | the executor tier is too slow. With an instrumented target, a fork server is several times faster than a subprocess; without one, `executor: pool` is about twice as fast and works on every platform |
| `unstable` below 90% | the target is non-deterministic — a clock, an address, a thread — and coverage guidance is chasing noise |
| `map-saturated` | raise `feedback.map_size` and rebuild; edges are colliding |
| `coverage-stalled` | the campaign has stopped learning: more seeds, a grammar, or a dictionary |
| `plugin-slow` | an extension is costing more than the target |

Two settings are worth knowing:

```yaml
workers:
  count: 8              # one per core by default
format:
  dictionary: ./tokens.dict   # format keywords, AFL format
```

And one worth knowing about, which `executor: auto` already picks for you:

| Tier | How it is chosen | When | Measured here |
| --- | --- | --- | --- |
| T0 | `executor: inproc` | a Go harness, in the fuzzer's own process | 10⁶–10⁷/s |
| T2 | `executor: forkserver` | an instrumented target on Linux or macOS | ~4,100/s |
| T3 | `executor: pool` | any target, any platform — processes are started before their input exists, so the spawn overlaps the previous run | ~1,400/s |
| T4 | `executor: subprocess` | one process per input; always works | ~600/s |
| T6 | a `session:` block | a protocol, where the unit is a conversation rather than a byte string | varies with the target |

`executor: auto` takes the fork server when there is coverage to collect and the
pool when there is not, which is what makes a black-box campaign on Windows
about twice as fast as it would otherwise be. Pin one only to rule the others
out. The session tier is not on that list because it is not a delivery choice: a
campaign with a `session:` block is fuzzing a conversation, and that is a
different shape of campaign rather than a faster way to run the same one.

A dictionary is the cheapest large win for a format with keywords — `IHDR`,
`SELECT`, `\x89PNG`. A grammar is the next one; see
[GRAMMAR.md](GRAMMAR.md).

## Safety

Every target runs confined, by default, on every platform that can
([ADR-0012](adr/ADR-0012-sandbox-by-default-and-scope-guard.md)). A target you
are fuzzing is a program you are deliberately driving into undefined behaviour;
treating it as trusted is how a fuzzing run becomes an incident.

```yaml
safety:
  isolation: strong       # none, minimal, moderate, strong
  memory_limit: 2GB
  process_limit: 64
```

The campaign refuses to start if the host cannot provide the level asked for.
`xfuzz safety NAME` shows what is in force and why it is not higher.

**What each platform can actually give you**
([ADR-0033](adr/ADR-0033-platform-isolation-and-terminal-parity.md)):

| Platform | Mechanism | Best level | What is missing |
| --- | --- | --- | --- |
| Linux | namespaces, a seccomp denylist, cgroups, the `xfuzz-sandbox` helper | `strong` | needs cgroup v2 and a read-only root for `strong`; `moderate` is common |
| macOS | a Seatbelt profile denying writes outside the working directory and denying the network, plus rlimits | `moderate` | no separate identity unless Xfuzz runs as root |
| Windows | a job object capping memory and process count, killing every target when the fuzzer lets go | `minimal` | no filesystem or network confinement: that needs a restricted token, which Xfuzz does not yet create |

The macOS and Windows mechanisms are cross-built and unit-tested but have not
been run on their own operating systems — see MVP_PLAN § 7.6. Treat the levels
above as what the code intends to provide there.

**A campaign that leaves the host needs authorization.** If your target reaches
the network, the scope guard requires an allowlist and a statement of who
authorised the testing — and the whole thing goes in the audit log:

```yaml
safety:
  scope:
    allow: ["10.0.0.0/24:80,443"]
  authorization:
    operator: "you@example.com"
    reference: "PENTEST-2026-014"
    attestation: "authorised to test the declared scope"
```

See [SECURITY.md](SECURITY.md) for the threat model and what is *not* covered.

## Storage, resuming, and cleaning up

A campaign's corpus, findings and metadata live in a store on disk. Everything
survives a restart:

```console
$ xfuzz run first.yaml        # a second run resumes where the first stopped
$ xfuzz load first            # open a finished campaign from its store
$ xfuzz forget first          # stop tracking it; the store stays
```

Bound the space it takes:

```yaml
storage:
  dir: ./store
  max_corpus_bytes: 2GB       # sizes take units: 4096, 512KB, 64MB, 2GB
  max_corpus_entries: 50000
```

And move corpora between tools — Xfuzz reads and writes AFL and libFuzzer
layouts:

```console
$ xfuzz corpus import first --dir ./afl-output/queue
$ xfuzz corpus export first --dir ./out --format afl --favoured
```

## Repeating a campaign exactly

Every campaign has a root seed. Left out of the file, one is drawn and recorded;
`xfuzz status NAME` shows it. Put it in the file and the campaign becomes an
experiment you can run again:

```yaml
seed: 12345678901234567
workers:
  count: 1
stop:
  execs: 20000
```

All three lines matter. One worker, because with several the corpus each of
them sees depends on when the others published theirs, and that is wall-clock.
An execution budget rather than `after:`, because two runs that stop after five
seconds stop in different places on a machine that is doing anything else. With
those, two runs find the same inputs by the same route — `xfuzz corpus list`
shows the derivation of each — which is what makes a fuzzer debuggable at all:
without it, an engine defect and a flaky target look the same.

A **finding** needs none of this. Its reproducer is bytes plus an invocation, so
it travels to another machine on its own:

```console
$ xfuzz findings get first 3 -o repro.bin   # the bytes
$ cp -a ./store /media/usb/                 # or the whole campaign
$ xfuzz load first --store /media/usb/store # on the other machine
$ xfuzz replay first 3 --trials 5
```

If the target is genuinely non-deterministic, replay says so rather than hiding
it: a finding that reproduces four times in five is reported as reproducing four
times in five. Set `health.min_stability` to tell a campaign how much of that is
normal for its target, so the diagnostic fires on the runs where it is not.

## Extending a campaign

### Campaign-local logic

Some bugs are not crashes. "The reply must never contain the admin token" is a
statement about your system that no fuzzer can know, and writing it down should
take four lines rather than a plugin and a build.

```yaml
scripts:
  - name: oracle
    path: ./oracle.star
    objectives: [leaked_secret]
```

```python
# oracle.star
def leaked_secret(x):
    if config["forbidden"] in x.stdout:
        return finding(summary = "the target echoed something it was never sent")
    return None
```

Starlark, chosen because it is hermetic: no filesystem, no network, no clock, no
imports, and deterministic — so a campaign carrying someone else's script is
still safe to run and still replays. Every call is bounded by a step budget and
an allocation budget. `examples/scripts/oracle.star` is a worked example of an
oracle, a mutator and a protocol state function.

### Plugins

For anything heavier, or written in another language, a plugin is a separate
process speaking a small protocol — four length bytes and a JSON object over its
standard input and output
([ADR-0025](adr/ADR-0025-length-prefixed-json-over-stdio-for-plugins.md)):

```yaml
extensions:
  - name: mine
    command: ./my-plugin
    feedbacks: [rarity]
    objectives: [invariant]
    mutators: [aware]
```

It runs confined like any other untrusted process, and a plugin that dies fails
its campaign with a clear error rather than taking the daemon with it.
`examples/plugins/reference` is a worked example in about 130 lines.

## When something goes wrong

| Symptom | Where to look |
| --- | --- |
| the campaign will not start | `xfuzz validate FILE`, then `xfuzz doctor` |
| "shared memory is unavailable" | this host has no coverage map; set `coverage: none` and `novelty: true` |
| "the campaign has no seeds" | `seeds.dirs` is empty or unreadable; check the path is relative to the *campaign file* |
| zero executions | `xfuzz status NAME` health, then `xfuzz workers NAME` |
| findings but no bugs | `xfuzz replay NAME ID` — a finding that does not reproduce usually means the target is not deterministic |
| a stalled campaign | `xfuzz metrics NAME` — `coverage-stalled` says it has stopped learning |
| the daemon does not answer | `xfuzz info`; the socket outlives a killed daemon and a new one takes over |
| "the target cannot execute its own binary" | the sandbox drops to an unprivileged user, and every directory on the path to the target must be traversable by it — the message names the directory and its mode |

Paths in a campaign file resolve against **the file**, not your working
directory, so a campaign is movable. That is the single most common surprise.

## Every command

`xfuzz <command> --help` prints a command's own flags. This table is checked
against the binary by `cmd/xfuzz/parity_test.go`, so it cannot fall behind it.

**Campaign files**

| Command | What it does |
| --- | --- |
| `xfuzz edit` | Change fields in a campaign file, keeping its comments and layout |
| `xfuzz explain` | Print the fully resolved configuration, including every default |
| `xfuzz init` | Write a starter campaign file |
| `xfuzz validate` | Check a campaign file without running it |

**Campaigns**

| Command | What it does |
| --- | --- |
| `xfuzz forget` | Forget a finished campaign, keeping its store |
| `xfuzz list` | List campaigns the daemon has loaded |
| `xfuzz load` | Open a campaign that already exists in a store |
| `xfuzz pause` | Pause a campaign without losing its state |
| `xfuzz resume` | Resume a paused campaign |
| `xfuzz run` | Create and start a campaign, following its progress |
| `xfuzz start` | Start a campaign the daemon already holds |
| `xfuzz status` | Show one campaign's state, counters and health |
| `xfuzz stop` | Stop a campaign |

**Daemon**

| Command | What it does |
| --- | --- |
| `xfuzz doctor` | Report what this host can do, and why anything is missing |
| `xfuzz info` | Show the daemon's version and status |
| `xfuzz schema` | Print the campaign file JSON Schema |
| `xfuzz version` | Print this client's version |

**Inspection**

| Command | What it does |
| --- | --- |
| `xfuzz audit` | Print the audit log and verify its hash chain |
| `xfuzz capture` | Turn a recorded session into a seed, its dependencies, and its secrets |
| `xfuzz corpus` | Browse, fetch, import and export the corpus |
| `xfuzz findings` | List findings and fetch their reproducers |
| `xfuzz grammar` | Compile a grammar, sample it, or import one from another language |
| `xfuzz metrics` | Show counters, history, and health diagnostics |
| `xfuzz minimize` | Reduce a finding's reproducer, preserving its failure class |
| `xfuzz replay` | Re-run a finding's reproducer and report whether it still fails |
| `xfuzz safety` | Show the isolation in force, and why it is not higher |
| `xfuzz states` | Show the protocol state machine a stateful campaign has explored |
| `xfuzz watch` | Follow a campaign's live event stream |
| `xfuzz workers` | Show each worker's state |

**Triage**

| Command | What it does |
| --- | --- |
| `xfuzz triage` | Record a judgement of a finding, and a note |

## Where to go next

- [GRAMMAR.md](GRAMMAR.md) — describing a format so mutation respects it.
- [DESIGN.md](DESIGN.md) — what Xfuzz is and the model behind it.
- [SECURITY.md](SECURITY.md) — the threat model, and responsible use.
- [ARCHITECTURE.md](ARCHITECTURE.md) — how it is built.
- `xfuzz schema` — the campaign file's JSON Schema, for editor completion.
