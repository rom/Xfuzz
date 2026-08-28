// Package daemon is the control plane: campaign lifecycle, configuration
// resolution, worker supervision, and the event bus.
//
// Campaigns are decoupled from client lifetime — launch from the CLI, observe
// from the browser, triage tomorrow. The daemon is also the single chokepoint
// for authorization, scope enforcement, and audit.
//
// It supervises worker processes but does not spawn them directly: process
// creation goes through internal/safety like every other spawn.
//
// See docs/adr/ADR-0003-daemon-core-with-thin-clients.md.
package daemon
