// Package corpussync distributes newly interesting inputs between the worker
// processes of a campaign.
//
// Workers share no memory. Discovery is published to the daemon's event bus and
// fanned out to siblings, which is also exactly where a future distributed
// coordinator would attach without redesign.
//
// Named corpussync rather than sync to avoid shadowing the standard library.
//
// See docs/adr/ADR-0015-single-node-multi-core-parallelism.md.
package corpussync
