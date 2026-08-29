# ADR-0024: HTTP/JSON API instead of gRPC for v1

- **Status:** Accepted
- **Date:** 2026-08-29
- **Serves:** ASR-0005, ASR-0012, ASR-0015

## Context

[ADR-0003](ADR-0003-daemon-core-with-thin-clients.md) decided the daemon
architecture and, within it, named the transport: **gRPC with a REST/JSON
gateway**, on a Unix socket by default. The daemon decision has held up
completely. The transport choice inside it is the part implementation has
something to say about.

Adding gRPC with a gateway pulls in seven modules beyond what the project
already has — `grpc`, `protobuf`, two `genproto` trees, `grpc-gateway`, `x/net`,
`x/text` — each of which must be vetted and listed under
[ADR-0018](ADR-0018-proprietary-commercial-license.md)'s licence policy. It also
adds a **code generation step**: `.proto` files compiled by `protoc` (a C++
binary) or `buf`, with two plugins, producing generated Go that is either
committed or regenerated in CI. That toolchain has to exist on Linux, macOS, and
Windows runners ([ASR-0006](../asr/ASR-0006-cross-platform-support.md)), and on
every contributor's machine.

What that buys, in v1's actual shape:

- **Cross-language clients.** v1 has two clients: a Go CLI and a browser. The Go
  client gets a typed interface from a Go interface just as well; the browser
  cannot speak gRPC without a proxy and consumes JSON either way.
- **A schema.** Real value, and not exclusive to protobuf: an OpenAPI document
  generated from the Go types gives editor completion, client generation, and
  machine-checkable structure, and can be kept honest by a test that fails when
  it drifts — the pattern already used for the traceability matrix and the
  dependency licence inventory.
- **Streaming.** The event stream is *lossy by design*
  ([§ 9](../ARCHITECTURE.md#9-api-surface)): downsampled and batched server-side
  so a browser can never back-pressure the engine. That is a fit for
  server-sent events almost exactly, and SSE needs no proxy, no framing library,
  and reconnects on its own.
- **Distribution.** Genuinely gRPC's strength, and explicitly out of scope:
  [ADR-0015](ADR-0015-single-node-multi-core-parallelism.md) defers distributed
  fuzzing past v1.

## Decision

**The v1 API is HTTP/JSON, described by a generated OpenAPI document. gRPC is
not adopted for v1.**

- The **service decomposition of § 9 is unchanged**. The six services become six
  route groups with the same responsibilities, and the parity test between CLI
  and API still applies to them. This ADR changes how methods are carried, not
  what they are.
- **Transport defaults are unchanged**: a Unix domain socket with filesystem
  permissions, TCP with token authentication opt-in and never the default
  ([ADR-0012](ADR-0012-sandbox-by-default-and-scope-guard.md)).
- **Events stream as SSE** over the same listener.
- The **OpenAPI document is generated from the Go request and response types**
  and checked in, with a test asserting it matches — a schema nobody regenerates
  is a schema that lies.
- **Nothing in the API is designed in a way that a later gRPC transport could
  not carry.** Methods are request/response over serialisable structs, streams
  are server-to-client only, and no route depends on an HTTP-specific mechanism
  beyond content negotiation.

## Consequences

**Positive**

- Zero new runtime dependencies: `net/http` and `encoding/json` are the standard
  library, so the licence inventory and the supply chain stay as they are.
- No code generation, so no `protoc` or `buf` on three CI platforms and no
  generated code in review diffs.
- The browser talks to the daemon directly. A gateway process, and the class of
  bug where the gateway and the service disagree, do not exist.
- `curl` works. For a tool whose users are people who debug systems for a living,
  an API they can hit with the tools already in their hands is worth more than
  one they need a client library for.

**Negative**

- No generated client stubs for other languages. Mitigated by the OpenAPI
  document, which generates them for most languages that would want one.
- JSON is larger and slower to encode than protobuf. Irrelevant here: the API
  carries control-plane traffic and downsampled metrics, not the fuzzing hot
  path, which never crosses a process boundary at all.
- Streaming semantics are weaker than gRPC's — no client streaming, no
  bidirectional streams. The event stream is server-to-client and lossy by
  design, so nothing v1 needs is lost.
- **This is a reversal of a decision that was already accepted**, and reversals
  have a cost in trust. Recorded rather than quietly implemented, which is what
  the ADR mechanism is for.

**Neutral**

- A future gRPC transport remains possible and is not blocked by anything here.
  It would be an addition alongside the HTTP surface, not a replacement, since
  the browser would still need JSON.

## Alternatives considered

- **gRPC with `grpc-gateway`, as ADR-0003 specified.** Rejected for v1 on cost
  versus benefit above, not on dislike: it is the right answer the moment v1.0
  adds a coordinator and cross-host clients.
- **gRPC without a gateway, with the console on JSON.** Rejected: two API
  surfaces to keep in parity, which is exactly what ASR-0005's parity requirement
  exists to prevent.
- **Hand-written gRPC service implementations with no codegen.** Possible and
  perverse: it keeps the wire format while discarding the schema that is the
  reason to want it.
- **WebSocket instead of SSE for events.** Rejected: bidirectional framing for a
  stream that is server-to-client by design, and SSE reconnects without client
  code. Revisit if the console ever needs to send on the same channel.
