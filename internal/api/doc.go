// Package api exposes the daemon's gRPC services and their REST/JSON gateway.
//
// This surface is the single source of truth for campaign state. The CLI and
// the web console are both clients of it, and a parity test asserts that
// neither has a capability the other lacks.
//
// Event streaming is lossy by design: high-rate events are downsampled and
// batched server-side so a browser can never back-pressure the engine.
//
// See docs/adr/ADR-0003-daemon-core-with-thin-clients.md.
package api
