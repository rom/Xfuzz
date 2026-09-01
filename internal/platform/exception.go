package platform

// How a Windows fatal exception becomes a signal number.
//
// Every part of Xfuzz above the platform layer classifies a crash by its
// signal: ProcResult.ExitKind calls an execution a crash when the signal is
// non-zero, triage buckets by it, and the crash oracles read it. Windows has no
// signals — a target that dereferences a null pointer exits with the exception
// code 0xC0000005 — so without a translation a Windows campaign records every
// crash as a clean exit and reports that it found nothing.
//
// That is not a hypothetical: it was the state of the tree until platform
// parity was taken seriously, and it is invisible from the outside, because a
// fuzzer that finds nothing looks exactly like a target with no bugs.
//
// So the codes are translated to the signal a Unix host would have raised for
// the same fault. It is a deliberate lie about the mechanism in service of the
// truth about the failure: an access violation and a segmentation fault are the
// same bug, and filing them in the same bucket is what lets a corpus and its
// findings move between platforms (ASR-0011).

// The NTSTATUS codes a fuzzed target actually dies of.
const (
	ExceptionAccessViolation     = 0xC0000005
	ExceptionInPageError         = 0xC0000006
	ExceptionIllegalInstruction  = 0xC000001D
	ExceptionPrivilegedInstr     = 0xC0000096
	ExceptionArrayBounds         = 0xC000008C
	ExceptionFloatDivideByZero   = 0xC000008E
	ExceptionIntegerDivideByZero = 0xC0000094
	ExceptionStackOverflow       = 0xC00000FD
	ExceptionHeapCorruption      = 0xC0000374
	ExceptionStackBufferOverrun  = 0xC0000409
	ExceptionNoncontinuable      = 0xC0000025
	ExceptionInvalidDisposition  = 0xC0000026
	ExceptionBreakpoint          = 0x80000003
	ExceptionControlC            = 0xC000013A
)

// The signal numbers, written out rather than taken from the syscall package.
//
// A cross-build for Windows has no POSIX signal constants, and taking them from
// the host's syscall package would put the build machine's numbering into the
// target's classification. These are the values every Linux ABI uses and the
// ones the rest of Xfuzz already compares against.
const (
	sigIll  = 4
	sigTrap = 5
	sigAbrt = 6
	sigFpe  = 8
	sigSegv = 11
	sigInt  = 2
)

// SignalKilled is what a process the fuzzer terminated reports having died of.
//
// A Unix kernel says it without being asked: KillGroup sends SIGKILL and the
// wait status carries it. Windows leaves no trace at all — TerminateProcess
// sets an exit code, and nothing in the status distinguishes the target the
// fuzzer stopped from one that returned the same number of its own accord. So
// the killer states it, in the same terms, for the same reason the exception
// codes above are translated: everything above this layer classifies by signal,
// and a deliberate shutdown that reads as "exited 1" reads as a child that
// failed.
const SignalKilled = 9

// ExceptionSignal maps a Windows exit code to the signal the same fault would
// have raised on Unix, or zero if the code is an ordinary exit.
//
// Exported and free of build tags so it can be tested from any host: the
// mapping is the part that can be wrong in a way nobody notices, and behind
// //go:build windows it would be exercised on no machine in CI.
func ExceptionSignal(code uint32) int {
	switch code {
	case ExceptionAccessViolation, ExceptionInPageError, ExceptionArrayBounds,
		ExceptionStackOverflow:
		return sigSegv
	case ExceptionIllegalInstruction, ExceptionPrivilegedInstr:
		return sigIll
	case ExceptionIntegerDivideByZero, ExceptionFloatDivideByZero:
		return sigFpe
	case ExceptionStackBufferOverrun, ExceptionHeapCorruption,
		ExceptionNoncontinuable, ExceptionInvalidDisposition:
		// The security-cookie check and the heap's own consistency check both
		// call __fastfail rather than raising a fault, which is what abort()
		// does on Unix — and like an abort it means the program detected the
		// corruption itself.
		return sigAbrt
	case ExceptionBreakpoint:
		return sigTrap
	case ExceptionControlC:
		return sigInt
	}
	// Anything else in the NTSTATUS error range is a fault the target did not
	// survive, whether or not this list names it. Reporting it as a crash of
	// unknown kind is right; reporting it as a clean exit would lose the
	// finding, and a list of exception codes is never complete.
	if code&0xF0000000 == 0xC0000000 {
		return sigAbrt
	}
	return 0
}
