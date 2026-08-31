// Package vt is a terminal emulator: bytes in, a screen out.
//
// A TUI has exactly one observable, and it is the screen. The program writes
// escape sequences to a pseudo-terminal and a terminal draws them; nothing else
// about what it is doing is visible from outside. So a fuzzer that wants to know
// whether a keystroke reached a new part of a program has to do what the
// terminal does — interpret the sequences and hold the resulting grid — or it
// has no feedback at all.
//
// This is why ADR-0013 puts TUI ahead of desktop GUI. The emulator is a few
// thousand lines of pure Go with no display server, no accessibility bus and no
// platform behind it; it runs identically in CI and on a developer's machine,
// and it is deterministic in the way that matters: the same byte stream always
// produces the same grid. The program upstream of it is not deterministic — it
// has timers and a clock in the status bar — but that is a normalisation problem
// (pkg/feedback) rather than an emulation one.
//
// The emulator is also, deliberately, one of the parsers Xfuzz fuzzes itself
// with. It reads adversarial input by construction: the whole point is to
// interpret bytes from a program that is being actively mutated into misbehaving.
// Every limit here — parameter counts, string lengths, screen dimensions — is
// there because a fuzzer will find it.
//
// # What is emulated
//
// Enough of xterm/VT100 that a real TUI renders correctly: cursor movement,
// erase and insert/delete, the scrolling region, SGR attributes including
// 256-colour and 24-bit colour, the alternate screen buffer, autowrap, and
// UTF-8 with a compact width table for the wide and combining ranges.
//
// # What is not
//
// Scrollback (a fuzzer looks at the screen, not at its history), tab stops
// beyond the default eight-column grid, double-width and double-height lines,
// character sets other than the default and the line-drawing set, mouse
// reporting (the driver sends clicks, it does not read them back), and reflow on
// resize. Each of those is a real terminal feature that no observed TUI needs in
// order for its screen to be compared against itself.
package vt
