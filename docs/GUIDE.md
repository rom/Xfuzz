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
  campaigns are possible. That is the normal state of affairs on Windows.

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
process per execution rather than a fork server. It still finds bugs, and it is
how macOS and Windows campaigns run.

With no coverage to collect, `executor: auto` picks the **pool**: processes are
created before their input exists and handed it when it arrives, so the cost of
starting one is paid while the previous one is still running. Measured against
one spawn per execution on the same target: 1,420 against 559 executions a
second. `executor: subprocess` is still there and still always works, which is
what to reach for if a target dislikes being started before it is needed.

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

## Making it faster

`xfuzz status` reports health diagnostics as well as counters. The ones that
usually matter:

| Diagnostic | What to do |
| --- | --- |
| `overhead` over 10% | the executor tier is too slow; a fork server is several times faster than a subprocess |
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
| `xfuzz corpus` | Browse, fetch, import and export the corpus |
| `xfuzz findings` | List findings and fetch their reproducers |
| `xfuzz grammar` | Compile a grammar and show what it generates |
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
