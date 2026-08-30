# ADR-0025: Length-prefixed JSON over stdio for the plugin protocol

- **Status:** Accepted
- **Date:** 2026-08-30
- **Serves:** ASR-0006, ASR-0008, ASR-0009

## Context

[ADR-0010](ADR-0010-three-tier-extensibility.md) established the three extension
tiers and, within the external-plugin tier, named the transport in passing:
"out-of-process over gRPC/stdio". The tier decision has held. The transport is
the part that had to be settled before anything could be built, and there were
two questions inside it: what carries the bytes, and what shape the bytes take.

Three things have changed since ADR-0010 was written.

[ADR-0024](ADR-0024-http-json-api-instead-of-grpc.md) removed gRPC from the API
for reasons that apply here with more force, not less: seven modules, a `protoc`
toolchain on three platforms, and a code generation step — to serve a plugin
author whose entire interest is "receive an execution, return a verdict". A
plugin protocol that requires a compiler toolchain to implement is a plugin
protocol most people will not implement.

The **spawn boundary** turned out to constrain the answer. ADR-0012 makes
confinement mandatory and the architecture lint enforces it: only
`internal/safety` may create a process. `pkg/plugin` cannot spawn its own peer,
so whatever the transport is, it must be something the safety layer can hand
over already open.

And **Windows** matters here in a way it does not for the fork server.
`exec.Cmd.ExtraFiles` — how the fork server passes its control and status pipes
as descriptors 3 and 4 — is not supported on Windows at all. The fork server is
a Linux fast path and can be Linux-only; plugins are the extensibility story for
every user on every platform ([ASR-0006](../asr/ASR-0006-cross-platform-support.md)),
so they cannot inherit that limitation.

## Decision

**Framing: 4-byte big-endian length prefix, then a JSON object.**

Length-prefixed rather than newline-delimited, because a frame carries base64 of
whatever a target wrote — arbitrary bytes, chosen by a fuzzer, specifically to
be hostile — and a delimiter that can appear inside a payload is a parser bug
waiting for the input that contains it. Four fixed bytes rather than a varint,
because every language can read a big-endian `uint32` without a library.

**Encoding: JSON, hand-written on both sides.**

The whole protocol is one `Request` struct and one `Response` struct, each a
flat object with optional fields. No union types, no generated code, no schema
compiler. A plugin author in Python or Rust reads the two structs and is done;
the Go SDK in `pkg/plugin/serve.go` is the reference implementation and is
roughly fifty lines of dispatch.

64-bit values — the campaign seed, a coverage signature — cross the wire as
**strings**, because JSON numbers are doubles in most languages and a seed that
loses its low bits produces a campaign that does not replay
([ASR-0008](../asr/ASR-0008-reproducibility-and-determinism.md)). This is the
same fix the HTTP API needed for the same reason.

**Transport: the plugin's own standard input and output.**

The host writes frames to the plugin's stdin and reads them from its stdout.
Standard error is deliberately outside the protocol: a plugin author will print
while debugging, and a transport that shares a stream with those prints turns a
debugging aid into a corrupted frame. What the plugin writes there is captured
and quoted back when something goes wrong, which is usually the only place a
crashing plugin explains itself.

Stdio also satisfies the spawn boundary without widening it: the safety layer
spawns the process, confined, and hands over two pipes.

**Shape: one call in flight, batch-capable.**

Every exchange is one request and one response, in order, on one connection. The
ID exists to catch a plugin answering the wrong question, not to permit
concurrency; there is no multiplexing to get wrong and no dispatcher for a
plugin author to write.

Batching is where it is real. A feedback must answer about the execution that
just happened, so it is called once per execution whatever the protocol allows —
the batch on the wire serves the callers that genuinely have many observations
at once, such as re-evaluating a corpus. A **mutator** has no such constraint:
asked for one variant it can produce thirty-two, and the engine will want them
all within the next thirty-two iterations from that parent. That is the case
ADR-0010 meant, and it is the one that gets the batch.

**Commits ride along.** A feedback's `Append`/`Discard` settles the previous
judgement. Sending it as its own frame would double the round trips on the hot
path, so it is carried as a field on that extension's *next* call: "settle the
last, then answer this". The engine's own contract guarantees the ordering —
a settlement always follows a judgement and always precedes the next one — so
nothing is lost, and `Close` flushes what is still owed.

**Failure is sticky and contained.** Any protocol error, timeout, or death of
the process puts the host permanently out of service: the first error is kept
(a timeout, not the end-of-file that killing the process then produces), the
process is killed, and every later call returns that same error. A plugin's own
refusal of a call is different and is not fatal — the call failed, the plugin is
alive, and the message is the plugin's own words.

A plugin that stops answering is **killed**, not waited for. The protocol is
synchronous; a plugin that has not answered within its call timeout is not slow,
it is broken, and a fuzz loop must never block on one.

## Consequences

**Positive**

- A plugin is implementable in an afternoon in any language with a JSON library,
  which is the difference between an extension point that exists and one that is
  used.
- No new dependency, no code generation, no toolchain requirement on any of the
  three platforms.
- Works identically on Linux, macOS and Windows, because stdio does.
- The failure modes are enumerable and each has one defined behaviour, which is
  what makes "plugin process dies → campaign fails cleanly" a testable claim
  rather than an aspiration.

**Negative**

- JSON costs more per frame than a binary encoding, and base64 inflates payloads
  by a third. Coverage therefore crosses as a cardinality and a signature rather
  than as the whole map: a 64 KiB map per execution would make the transport the
  campaign's dominant cost. A plugin feedback that needs the raw map is not
  expressible in this tier and must be native.
- One call in flight means a slow plugin serialises the worker that owns it.
  This is visible rather than mysterious — the host reports calls and time spent
  inside, as ADR-0010 requires — but it is a real ceiling.
- Hand-written framing on both sides means the protocol has no machine-checkable
  schema. The Go SDK and the host are held together by tests, not by a compiler.

**Neutral**

- The protocol version is an explicit compatibility commitment, checked in the
  handshake and refused on mismatch with both versions named.

## Alternatives considered

- **gRPC over a Unix socket.** A schema, streaming, and cross-language stubs.
  Rejected for the reasons in ADR-0024, which are sharper here: the audience for
  this tier is precisely the people who do not want a build toolchain.
- **Descriptors 3 and 4, like the fork server.** Consistent with the existing
  spawn boundary and leaves stdio free for the plugin's own use. Rejected:
  `ExtraFiles` does not exist on Windows, and this tier must work everywhere.
- **A Unix socket per plugin.** Bidirectional, and no ambiguity about which
  stream is which. Rejected: it needs a filesystem path to negotiate, a
  connection to accept, and cleanup on crash — three failure modes stdio does
  not have — and Windows named pipes are a different API again.
- **MessagePack or CBOR instead of JSON.** Denser, and no base64 tax on binary
  payloads. Rejected for v1: a dependency or a hand-rolled codec on both sides,
  to save bytes on a path that is already out of process and therefore already
  not the fast path. Worth revisiting if a plugin ever becomes a bottleneck for
  a reason other than what it computes.
- **A callback protocol, where the plugin drives.** Rejected: it inverts the
  timeout, so a plugin that stops calling is indistinguishable from one that is
  thinking.
