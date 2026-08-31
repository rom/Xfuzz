// Package capture reads recorded HTTP traffic into one representation.
//
// ADR-0014 makes captured traffic the primary seed source for API fuzzing, on
// the grounds that specifications are frequently absent, stale or incomplete —
// and that the endpoints missing from a specification are disproportionately the
// interesting ones. A capture reflects what the API actually does, including
// undocumented endpoints, real authentication material, and the real
// inter-request data dependencies that make a sequence coherent.
//
// Three sources, one shape. A HAR file is what a browser's developer tools
// export; a pcap is what a packet capture produces and needs its streams
// reassembling before there is an exchange to read; a recording proxy is what an
// operator runs when they have neither. All three land in the same Exchange, so
// everything downstream — lifting into the IR, inferring dependencies, spotting
// credentials — is written once.
//
// The package is deliberately read-only and dependency-free. The proxy, which
// has to reach out to an upstream server, lives in internal/ where the scope
// guard is (ADR-0012); reading a file that someone else recorded does not.
//
// See docs/adr/ADR-0014-traffic-replay-driven-api-fuzzing.md.
package capture
