//go:build linux && amd64

package platform

import "syscall"

// The breakpoint mechanics, which are the one part of this backend that is
// architecture rather than kernel.
//
// Two facts differ per architecture and nothing else does: how a trap is
// encoded, and where the instruction pointer is left once it has fired. On
// x86-64 the trap is the one-byte INT3 and the processor has already advanced
// past it when the tracer sees the stop, so the address that was hit is one
// behind the instruction pointer and continuing means winding it back.

// traceArchSupported reports whether this architecture has an implementation.
const traceArchSupported = true

// traceTrap is the instruction that raises SIGTRAP, and it is one byte, which
// is why a breakpoint here can be planted over any instruction without
// disturbing the one after it.
const traceTrap byte = 0xCC

// trapAddr is the address of the trap that fired.
func trapAddr(regs *syscall.PtraceRegs) uintptr { return uintptr(regs.Rip - 1) }

// rewindToTrap puts the instruction pointer back on the restored instruction,
// so the program continues as though the breakpoint had never been there.
func rewindToTrap(regs *syscall.PtraceRegs) { regs.Rip-- }
