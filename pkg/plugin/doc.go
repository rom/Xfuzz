// Package plugin hosts the two out-of-core extension tiers: an out-of-process
// protocol for plugins written in any language, and a hermetic Starlark
// interpreter for campaign-local logic.
//
// Both are generated from and validated against the same Go interfaces that
// the native tier implements, so semantics cannot drift between tiers.
// Starlark is chosen specifically because it is hermetic by construction — no
// filesystem, network, or clock access — which preserves campaign determinism
// and keeps untrusted campaign files safe.
//
// Go's standard library plugin package is deliberately not used: it is
// Linux-only, toolchain-version-locked, and offers no isolation.
//
// This package is the out-of-process half; the Starlark host is the script
// subpackage. They deliberately share the observation and finding types, so
// that what an oracle sees is the same whichever tier it is written in.
//
// See docs/adr/ADR-0010-three-tier-extensibility.md and
// docs/adr/ADR-0025-length-prefixed-json-over-stdio-for-plugins.md.
package plugin
