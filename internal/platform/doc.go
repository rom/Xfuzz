// Package platform contains every OS-specific mechanism: process control,
// shared memory, isolation primitives, and coverage transport.
//
// This is the only package permitted to carry GOOS or GOARCH build constraints;
// the rule is enforced by tools/archlint. Implementations are pure Go by
// default, with native code confined behind //go:build cgo and always paired
// with a pure-Go fallback, so that CGO_ENABLED=0 GOOS=<any> produces a working
// binary — slower or less featureful, never broken.
//
// Capability differences are declared and reported rather than discovered
// through failure.
//
// See docs/adr/ADR-0017-pure-go-core-cgo-behind-build-tags.md.
package platform
