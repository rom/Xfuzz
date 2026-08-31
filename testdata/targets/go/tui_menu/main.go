// Command tui_menu is a terminal program with a planted bug, for the T7 tier.
//
// It is a small but complete TUI: it takes the alternate screen buffer, puts the
// terminal in raw mode, hides the cursor, reads single keystrokes, redraws on
// SIGWINCH, and restores everything on the way out. All of that is here because
// a driver that could not handle it could not drive anything real — a target
// that reads lines from a pipe would prove nothing about a fuzzer meant to drive
// programs that do not.
//
// The bug: deleting the last item in the list leaves the selection pointing one
// past the end, and the next redraw reads it. Two keystrokes in the right order
// find it; no single keystroke does, which is the property that makes a
// *sequence* the unit of input for this tier.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"

	"golang.org/x/sys/unix"
)

type app struct {
	out    *os.File
	screen string
	items  []string
	sel    int
	cols   int
	rows   int
	depth  int
}

func main() {
	a := &app{out: os.Stdout, screen: "menu", items: []string{"alpha", "beta", "gamma"}}
	restore, err := raw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "raw mode:", err)
		os.Exit(1)
	}
	defer restore()

	a.size()
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, unix.SIGWINCH)
	go func() {
		for range winch {
			a.size()
			a.draw()
		}
	}()

	fmt.Fprint(a.out, "\x1b[?1049h\x1b[?25l")
	defer fmt.Fprint(a.out, "\x1b[?25h\x1b[?1049l")
	a.draw()

	buf := make([]byte, 64)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			return
		}
		for _, k := range decode(buf[:n]) {
			if !a.key(k) {
				return
			}
		}
		a.draw()
	}
}

func (a *app) size() {
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		a.cols, a.rows = 80, 24
		return
	}
	a.cols, a.rows = int(ws.Col), int(ws.Row)
}

// key handles one keystroke and reports whether to keep running.
func (a *app) key(k string) bool {
	switch a.screen {
	case "menu":
		switch k {
		case "q":
			return false
		case "1":
			a.screen, a.sel = "list", 0
		case "2":
			a.screen = "settings"
		}
	case "settings":
		if k == "escape" || k == "q" {
			a.screen = "menu"
		}
	case "list":
		switch k {
		case "escape":
			a.screen = "menu"
		case "q":
			return false
		case "j", "down":
			if a.sel < len(a.items)-1 {
				a.sel++
			}
		case "k", "up":
			if a.sel > 0 {
				a.sel--
			}
		case "d":
			// The bug. Removing the selected item shortens the list without
			// moving the selection, so deleting the last one leaves sel ==
			// len(items) and the next redraw reads one past the end.
			if a.sel < len(a.items) {
				a.items = append(a.items[:a.sel], a.items[a.sel+1:]...)
			}
		case "enter":
			a.screen = "detail"
		}
	case "detail":
		if k == "escape" || k == "q" {
			a.screen = "list"
		}
		a.depth++
	}
	return true
}

func (a *app) draw() {
	var b strings.Builder
	b.WriteString("\x1b[2J\x1b[H")
	fmt.Fprintf(&b, "\x1b[1;36mtui_menu\x1b[0m  %dx%d\r\n", a.cols, a.rows)
	b.WriteString(strings.Repeat("-", min(a.cols, 40)) + "\r\n")

	switch a.screen {
	case "menu":
		b.WriteString("1) items\r\n2) settings\r\nq) quit\r\n")
	case "settings":
		b.WriteString("no settings yet\r\n\r\nesc) back\r\n")
	case "list":
		for i, it := range a.items {
			marker := "  "
			if i == a.sel {
				marker = "\x1b[7m> "
			}
			fmt.Fprintf(&b, "%s%s\x1b[0m\r\n", marker, it)
		}
		b.WriteString("\r\nj/k) move  d) delete  enter) open  esc) back\r\n")
		// One past the end here, once the last item has been deleted.
		fmt.Fprintf(&b, "selected: %s\r\n", a.items[a.sel])
	case "detail":
		fmt.Fprintf(&b, "item: %s\r\ndepth: %d\r\n\r\nesc) back\r\n", a.items[a.sel], a.depth)
	}
	fmt.Fprint(a.out, b.String())
}

// decode turns the bytes a terminal sends into key names.
func decode(b []byte) []string {
	var out []string
	for i := 0; i < len(b); {
		switch {
		case b[i] == 0x1b && i+2 < len(b) && b[i+1] == '[':
			switch b[i+2] {
			case 'A':
				out = append(out, "up")
			case 'B':
				out = append(out, "down")
			case 'C':
				out = append(out, "right")
			case 'D':
				out = append(out, "left")
			}
			i += 3
		case b[i] == 0x1b:
			out = append(out, "escape")
			i++
		case b[i] == '\r' || b[i] == '\n':
			out = append(out, "enter")
			i++
		default:
			out = append(out, string(b[i]))
			i++
		}
	}
	return out
}

// raw puts the terminal into the mode a full-screen program needs: no line
// buffering, no echo, and no signal generation from control characters.
func raw(fd int) (func(), error) {
	prev, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	t := *prev
	t.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	t.Oflag &^= unix.OPOST
	t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	t.Cflag &^= unix.CSIZE | unix.PARENB
	t.Cflag |= unix.CS8
	t.Cc[unix.VMIN], t.Cc[unix.VTIME] = 1, 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &t); err != nil {
		return nil, err
	}
	return func() { unix.IoctlSetTermios(fd, unix.TCSETS, prev) }, nil
}
