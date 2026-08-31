package platform

import "testing"

func TestExceptionSignalTranslatesTheFaultsATargetDiesOf(t *testing.T) {
	for code, want := range map[uint32]int{
		ExceptionAccessViolation:     sigSegv,
		ExceptionStackOverflow:       sigSegv,
		ExceptionInPageError:         sigSegv,
		ExceptionArrayBounds:         sigSegv,
		ExceptionIllegalInstruction:  sigIll,
		ExceptionPrivilegedInstr:     sigIll,
		ExceptionIntegerDivideByZero: sigFpe,
		ExceptionFloatDivideByZero:   sigFpe,
		ExceptionStackBufferOverrun:  sigAbrt,
		ExceptionHeapCorruption:      sigAbrt,
		ExceptionBreakpoint:          sigTrap,
		ExceptionControlC:            sigInt,
	} {
		if got := ExceptionSignal(code); got != want {
			t.Errorf("ExceptionSignal(%#x) = %d, want %d", code, got, want)
		}
	}
}

func TestOrdinaryExitCodesAreNotCrashes(t *testing.T) {
	// The other half of the mapping, and the half that would turn every
	// campaign into a stream of false findings if it were wrong: a target that
	// exits 1 because its input was invalid has not crashed.
	for _, code := range []uint32{0, 1, 2, 3, 42, 255, 0x7FFFFFFF} {
		if got := ExceptionSignal(code); got != 0 {
			t.Errorf("ExceptionSignal(%#x) = %d, want 0: an ordinary exit was called a crash",
				code, got)
		}
	}
}

func TestAnUnlistedFaultIsStillACrash(t *testing.T) {
	// The list of exception codes is never complete, and a code it does not
	// name must not be reported as a clean exit: a lost finding is worse than a
	// finding filed in a coarse bucket, because nobody can tell it happened.
	for _, code := range []uint32{0xC0000017, 0xC0000420, 0xC0000135} {
		if ExceptionSignal(code) == 0 {
			t.Errorf("ExceptionSignal(%#x) = 0: an unhandled exception was called a clean exit",
				code)
		}
	}
}
