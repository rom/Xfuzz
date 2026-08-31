//go:build linux && !amd64

package platform

import "syscall"

// Breakpoint tracing on Linux is implemented for x86-64 and no other
// architecture, and this file is what says so at compile time rather than at
// run time on a host nobody tested.
//
// It is not an omission that will be filled in by writing the register access
// for another architecture. The blocks this backend plants breakpoints on come
// from pkg/binary, whose instruction decoder is an x86-64 decoder and which
// refuses any other image with ErrUnsupportedArch — so on a machine that is not
// x86-64 there is nothing to plant, and a tracer that could set registers would
// still have no addresses to set them for. Adding another architecture means
// adding a decoder for it first; ADR-0002's other backends, which read a trace
// out of an emulator rather than producing one, are the portable answer in the
// meantime.
//
// Reported as unavailable rather than approximated, for the reason trace_other.go
// gives: a campaign that asked for block coverage and silently got none looks
// exactly like a target with no branches.

const traceArchSupported = false

const traceTrap byte = 0

func trapAddr(*syscall.PtraceRegs) uintptr { return 0 }

func rewindToTrap(*syscall.PtraceRegs) {}
