// Package campaign defines the declarative campaign file — the only interface
// for defining what a campaign does.
//
// A campaign is YAML with a published JSON Schema. The CLI runs, inspects, and
// validates these files; the web console is a comment-preserving visual editor
// over the same format. Neither holds configuration state of its own.
//
// See docs/adr/ADR-0016-config-only-campaign-definition.md.
package campaign
