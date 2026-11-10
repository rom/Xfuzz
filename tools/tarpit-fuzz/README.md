# tarpit-fuzz

External fuzzer for every protocol handler that the
[rom/tarpit-honeypot](https://github.com/rom/tarpit-honeypot) sensor exposes.

The honeypot ships **197 TCP + 118 UDP = 322 protocol handlers** on its
`banner` / `tarpit` listener modes, from classic internet services through
OT/ICS to the cloud-native control plane. This tool drives each one of them
with **dumb** (protocol-unaware) and **smart** (protocol-aware) payloads,
re-checks liveness after each payload, and reports any handler whose listener
dies, stops accepting connections, or quietly stops responding.

Every protocol is a toggle — enable the ones you deploy, disable the rest,
pin the port if you bound the listener somewhere other than its IANA default.

## What it does

- Covers **all 322** handlers the honeypot accepts in its `handler:` field.
  The list is the same one `tarpit-honeypot list-handlers` prints; the catalogue
  in `protocols/registry.go` matches it one-for-one.
- **Dumb**: random bytes, seeded flips, truncations, oversized length
  prefixes, well-known boundary integers — the operators that find a parser
  that panics on anything.
- **Smart**: 61 protocol-aware generators that build a frame the parser will
  recognise past its first check, then push a structural field past its
  bound. DNS with a label that overruns 63 bytes. Modbus with a MBAP length
  that claims more than the payload holds. MQTT with a varint that never
  terminates. The frames come from the specifications — RFCs, IEC, vendor
  docs — rather than from a trace.
- **Liveness check** after every payload: a TCP listener that refuses the
  next dial is a crash candidate; a configured `/healthz` on the sensor's
  management port is the cheaper check and takes precedence.
- **Replayable crashes**: every run uses a seed; passing the same `--seed`
  reproduces the exact payload sequence that tripped the sensor.
- **Reports** which protocols were exercised, which were skipped (port
  closed), and ranks any findings by crashes → hangs → other anomalies.

## Build

```bash
go build -o bin/tarpit-fuzz ./tools/tarpit-fuzz/cmd
```

Needs Go 1.26 (the Xfuzz go.mod floor). No cgo. No external dependencies
beyond `gopkg.in/yaml.v3`, which the Xfuzz module already pulls in.

## Run

A one-liner against a sensor deployed on the host:

```bash
bin/tarpit-fuzz -c tools/tarpit-fuzz/configs/protocols.yaml \
    --target 127.0.0.1 \
    --liveness http://127.0.0.1:8088/healthz \
    --rounds 10
```

A short soak of a subset:

```bash
bin/tarpit-fuzz --target honeypot.lab \
    --enable tcp:modbus,tcp:s7,tcp:dnp3,udp:bacnet \
    --iterations 4096 --concurrency 8 --rounds 20
```

Only smart fuzzers, verbose findings:

```bash
bin/tarpit-fuzz -c protocols.yaml --kind smart --verbose
```

Replay a crash from a report:

```bash
bin/tarpit-fuzz -c protocols.yaml --seed 1699734812345678900 --enable tcp:modbus
```

## Config

The YAML file at `configs/protocols.yaml` lists every handler with a
sensible IANA port and `enabled: true`. Edit it to turn off what you do
not deploy — the ones that stay on are what the run exercises.

```yaml
target: 127.0.0.1
liveness: http://127.0.0.1:8088/healthz
iterations: 256
rounds: 1
concurrency: 8
timeout: 800ms
kinds: [dumb, smart]
protocols:
  - { name: ssh,        transport: tcp, enabled: true, port: 22 }
  - { name: modbus,     transport: tcp, enabled: true, port: 502 }
  - { name: dns,        transport: udp, enabled: true, port: 53 }
  - { name: coap,       transport: udp, enabled: true, port: 5683 }
  - { name: kubernetes_api, transport: tcp, enabled: false }  # not deployed here
  # ... all 322 handlers listed
```

Command-line flags override the YAML. `--enable` and `--disable` take a
comma-separated list of names, which may be qualified with a transport:

```
--enable tcp:modbus,tcp:s7,tcp:dnp3   # only these three
--disable tcp:scripted,tcp:lua        # subtract from --enable (or from the YAML's enabled set)
```

## Shape of a run

For each enabled protocol, in sorted order (TCP then UDP):

1. **Dial check** — one TCP connect or UDP write. A protocol that is not
   bound on the target skips with no finding and is named in the summary's
   "skipped" list so the operator can see which one and fix the port.
2. **Dumb loop** — `iterations` payloads, each one of six shapes: random
   bytes, seed + bit flips, truncated seed, seed + garbage tail, seed with a
   boundary integer injected, length-prefixed oversize. After every payload
   the sensor's liveness is re-checked. A liveness loss files a crash
   finding naming the iteration.
3. **Smart loop** — `iterations` protocol-aware payloads. The same liveness
   check applies.
4. **Final reachability** — a last dial check: a listener that no longer
   accepts after a clean run is filed as a hang (the handler has quietly
   decided this client is unwelcome).

`rounds` repeats the schedule from the top. Multiple rounds spread any
state-dependent bug beyond the first seed.

## What a report looks like

```
tarpit-fuzz summary
  catalogue    : 322 protocols
  exercised    : 34
  payloads sent: 34816
  responses    : 15423
  skipped      : 0 (port unreachable)
  elapsed      : 2m14.3s
  findings     : 2 (crashes=1 hangs=1)
    [1] tcp:modbus      kind=smart iter=1247 reason="liveness lost after payload"
        payload[260B]: 00 01 00 00 00 06 01 03 ff ff 7f ff ...
    [2] udp:snmp        kind=dumb  iter=2048 reason="endpoint stopped accepting connections"
```

An exit code of 1 means at least one finding was filed.

## Smart-generator coverage

61 handlers currently have a protocol-aware generator (the "smart yes"
column in `tarpit-fuzz --list`). The rest fall back to dumb fuzzing against
their seed. Adding a new generator is three steps:

1. Write it in `protocols/smart/`: `func X(rng *rand.Rand) []byte`.
2. Reference it in `protocols/registry.go`: set `Smart: smart.X` on the row.
3. Add a seed packet to `protocols/seeds.go` if the shape is not already in
   the file.

A generator is worth writing when the honeypot's handler has non-trivial
parsing past the first byte — a length field, a magic header, an option
list, nested TLVs. For a protocol whose honeypot handler reads bytes and
replies with a fixed banner, dumb fuzzing is already enough.

## Why toggles matter

A honeypot is a deployment — it runs some protocols, not others. A tool
that always fuzzes 322 handlers wastes an hour re-confirming that 280
closed ports are still closed. Toggles make a run match a deployment:

- A small OT honeypot: enable the 25 ICS handlers, disable everything else.
- A web-focused deployment: enable HTTP family, Redis, Postgres, Kubernetes.
- A regression run after a sensor change: enable only the handler that
  changed.

The CLI also accepts a handler list on its command line, so CI runs a line
rather than a config file.

## Development

```bash
# Unit tests for the engine (crash detection, toggles, dumb + smart loops):
go test ./tools/tarpit-fuzz/engine/

# Smoke test against a mini honeypot (requires a built tarpit-honeypot):
./scripts/tarpit-fuzz-smoke.sh
```

The engine itself is ~450 lines and the mutator ~130. Each smart generator
is 10–30 lines. Nothing in this tree links against the honeypot's source —
it is an external fuzzer by design, so a crash it finds is a crash that
survives the real network path.
