// Package atspi speaks the AT-SPI2 accessibility protocol.
//
// It is the mechanism behind the `gui-atspi` driver backend (ADR-0013): a
// desktop application on Linux publishes its interface as a tree of accessible
// objects over D-Bus — every button, field and label, with its role, its name,
// its state and where it is on screen — and the same bus carries a way to
// synthesise a keystroke or a click. That is the whole of what a fuzzer needs,
// and it is what makes a GTK or Qt program drivable by the same event sequence
// a terminal program is.
//
// Why the tree and not a screenshot: a screenshot is pixels, and two screens
// that differ by an animation frame are different pixels and the same screen.
// The accessibility tree is what the application says about itself, so a state
// built from it changes when the interface changes and not when it repaints.
// It is also the only observable that says which widget has focus, which is
// what decides where the next keystroke goes.
//
// The D-Bus wire format is godbus's rather than this project's, and that is a
// different call from the one made for the WebSocket client beside it. A
// WebSocket frame is a header and a mask; D-Bus is a general-purpose
// serialisation format with a type language, alignment rules and an
// authentication handshake, and a reimplementation would be several times the
// size of the thing it serves — with the failure mode that a marshalling bug
// looks like an application that says something strange rather than like a bug.
package atspi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/godbus/dbus/v5"
)

// The names AT-SPI publishes under.
const (
	// BusService answers where the accessibility bus is. It lives on the
	// ordinary session bus, because the accessibility bus is a second bus
	// entirely — a separate daemon, so that assistive technology traffic does
	// not compete with everything else on the session bus.
	BusService   = "org.a11y.Bus"
	BusPath      = "/org/a11y/bus"
	BusInterface = "org.a11y.Bus"

	// Registry is the well-known name on the accessibility bus, and RootPath
	// its root: the list of applications currently publishing a tree.
	Registry = "org.a11y.atspi.Registry"
	RootPath = dbus.ObjectPath("/org/a11y/atspi/accessible/root")

	// DECPath is the device event controller, which is how a keystroke or a
	// click is synthesised.
	DECPath = dbus.ObjectPath("/org/a11y/atspi/registry/deviceeventcontroller")

	IfaceAccessible   = "org.a11y.atspi.Accessible"
	IfaceComponent    = "org.a11y.atspi.Component"
	IfaceAction       = "org.a11y.atspi.Action"
	IfaceText         = "org.a11y.atspi.Text"
	IfaceEditableText = "org.a11y.atspi.EditableText"
	IfaceDEC          = "org.a11y.atspi.DeviceEventController"
)

// Synthesis kinds for GenerateKeyboardEvent.
const (
	KeyPress        uint32 = 0
	KeyRelease      uint32 = 1
	KeyPressRelease uint32 = 2
	KeySym          uint32 = 3
	KeyString       uint32 = 4
)

// ErrNoBus is returned where there is no accessibility bus to talk to, which is
// every headless machine and every desktop with assistive technology switched
// off.
var ErrNoBus = errors.New("atspi: no accessibility bus: a desktop campaign needs " +
	"a session bus with at-spi running, and this host has none")

// Conn is a connection to the accessibility bus.
type Conn struct {
	session *dbus.Conn
	bus     *dbus.Conn
	addr    string
}

// Address returns where the accessibility bus is listening.
//
// Asked of the session bus rather than guessed, because the address is a
// per-session socket and the environment variable that sometimes carries it is
// set by a desktop session that a fuzzer does not have. AT_SPI_BUS is honoured
// first for the case where a campaign was told explicitly.
func Address(session *dbus.Conn) (string, error) {
	if a := os.Getenv("AT_SPI_BUS"); a != "" {
		return a, nil
	}
	if session == nil {
		return "", ErrNoBus
	}
	var addr string
	obj := session.Object(BusService, BusPath)
	if err := obj.Call(BusInterface+".GetAddress", 0).Store(&addr); err != nil {
		return "", fmt.Errorf("atspi: asking the session bus for the accessibility bus: %w", err)
	}
	if addr == "" {
		return "", ErrNoBus
	}
	return addr, nil
}

// Dial connects to the accessibility bus.
func Dial(ctx context.Context) (*Conn, error) {
	session, err := dbus.SessionBusPrivate()
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", ErrNoBus, err)
	}
	if err := session.Auth(nil); err != nil {
		session.Close()
		return nil, fmt.Errorf("%w (session bus authentication: %v)", ErrNoBus, err)
	}
	if err := session.Hello(); err != nil {
		session.Close()
		return nil, fmt.Errorf("%w (session bus handshake: %v)", ErrNoBus, err)
	}

	addr, err := Address(session)
	if err != nil {
		session.Close()
		return nil, err
	}
	bus, err := dbus.Dial(addr)
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("atspi: connecting to the accessibility bus at %s: %w", addr, err)
	}
	if err := bus.Auth(nil); err != nil {
		bus.Close()
		session.Close()
		return nil, fmt.Errorf("atspi: authenticating to the accessibility bus: %w", err)
	}
	if err := bus.Hello(); err != nil {
		bus.Close()
		session.Close()
		return nil, fmt.Errorf("atspi: handshake with the accessibility bus: %w", err)
	}
	return &Conn{session: session, bus: bus, addr: addr}, nil
}

// Available reports whether this host has an accessibility bus at all.
//
// Probed by connecting, for the reason every other capability in Xfuzz is
// probed: a build that contains the code says nothing about whether the machine
// running it has a desktop session, and discovering that after a campaign has
// started means having told the operator it was fuzzing when it was not.
func Available() bool {
	c, err := Dial(context.Background())
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// Close releases both connections.
func (c *Conn) Close() error {
	var err error
	if c.bus != nil {
		err = c.bus.Close()
		c.bus = nil
	}
	if c.session != nil {
		if serr := c.session.Close(); err == nil {
			err = serr
		}
		c.session = nil
	}
	return err
}

// Ref names one accessible object: which application publishes it, and where.
type Ref struct {
	Name string
	Path dbus.ObjectPath
}

// Valid reports whether a reference points anywhere.
//
// AT-SPI uses a null path to mean "no object" — a parent that does not exist, a
// child that has gone — rather than an error, so a caller that did not check
// would make a call against nothing and get a timeout.
func (r Ref) Valid() bool {
	return r.Name != "" && r.Path != "" && r.Path != "/org/a11y/atspi/null"
}

func (r Ref) String() string { return r.Name + string(r.Path) }

// Root returns the registry's root, whose children are the applications.
func (c *Conn) Root() Ref { return Ref{Name: Registry, Path: RootPath} }

func (c *Conn) obj(r Ref) dbus.BusObject { return c.bus.Object(r.Name, r.Path) }

// Children returns an object's children.
func (c *Conn) Children(r Ref) ([]Ref, error) {
	var out []struct {
		Name string
		Path dbus.ObjectPath
	}
	if err := c.obj(r).Call(IfaceAccessible+".GetChildren", 0).Store(&out); err != nil {
		return nil, fmt.Errorf("atspi: listing the children of %s: %w", r, err)
	}
	refs := make([]Ref, 0, len(out))
	for _, e := range out {
		refs = append(refs, Ref{Name: e.Name, Path: e.Path})
	}
	return refs, nil
}

// Label returns an object's accessible name.
func (c *Conn) Label(r Ref) (string, error) {
	v, err := c.obj(r).GetProperty(IfaceAccessible + ".Name")
	if err != nil {
		return "", err
	}
	s, _ := v.Value().(string)
	return s, nil
}

// RoleName returns what kind of thing an object is: push button, entry, label.
func (c *Conn) RoleName(r Ref) (string, error) {
	var name string
	if err := c.obj(r).Call(IfaceAccessible+".GetRoleName", 0).Store(&name); err != nil {
		return "", err
	}
	return name, nil
}

// States returns the state bitmap, as AT-SPI's pair of 32-bit words.
func (c *Conn) States(r Ref) ([]uint32, error) {
	var bits []uint32
	if err := c.obj(r).Call(IfaceAccessible+".GetState", 0).Store(&bits); err != nil {
		return nil, err
	}
	return bits, nil
}

// Interfaces returns which AT-SPI interfaces an object implements, which is how
// a caller knows whether it can be typed into or activated.
func (c *Conn) Interfaces(r Ref) ([]string, error) {
	var ifaces []string
	if err := c.obj(r).Call(IfaceAccessible+".GetInterfaces", 0).Store(&ifaces); err != nil {
		return nil, err
	}
	return ifaces, nil
}

// Text returns an object's text content.
func (c *Conn) Text(r Ref) (string, error) {
	var s string
	if err := c.obj(r).Call(IfaceText+".GetText", 0, int32(0), int32(-1)).Store(&s); err != nil {
		return "", err
	}
	return s, nil
}

// ApplicationPID returns the process behind an application node.
//
// Asked of the bus daemon rather than of the application, because an
// application's own idea of its identity is a string it chose and two copies of
// the same program are indistinguishable by it. The connection's process is
// exact, which is what a driver needs to tell its target from every other
// program on the desktop.
func (c *Conn) ApplicationPID(busName string) (int, error) {
	var pid uint32
	err := c.bus.BusObject().Call("org.freedesktop.DBus.GetConnectionUnixProcessID", 0, busName).Store(&pid)
	if err != nil {
		return 0, err
	}
	return int(pid), nil
}

// Applications returns the trees currently published.
func (c *Conn) Applications() ([]Ref, error) { return c.Children(c.Root()) }

// FindApplication returns the application published by a given process.
func (c *Conn) FindApplication(pid int) (Ref, bool) {
	apps, err := c.Applications()
	if err != nil {
		return Ref{}, false
	}
	for _, app := range apps {
		if got, err := c.ApplicationPID(app.Name); err == nil && got == pid {
			return app, true
		}
	}
	return Ref{}, false
}

// GrabFocus asks an object to take the keyboard focus.
func (c *Conn) GrabFocus(r Ref) error {
	var ok bool
	return c.obj(r).Call(IfaceComponent+".GrabFocus", 0).Store(&ok)
}

// TypeString synthesises a literal string as keystrokes.
//
// One call rather than a keystroke per rune: at-spi maps each character to a
// key and presses the modifiers a capital or a symbol needs, which is a table
// this package would otherwise have to carry and get wrong for every keyboard
// layout but one.
func (c *Conn) TypeString(s string) error {
	return c.registryObj(DECPath).Call(IfaceDEC+".GenerateKeyboardEvent", 0,
		int32(0), s, KeyString).Err
}

// PressKeysym synthesises one key by its X keysym.
func (c *Conn) PressKeysym(sym int32) error {
	return c.registryObj(DECPath).Call(IfaceDEC+".GenerateKeyboardEvent", 0,
		sym, "", KeySym).Err
}

// Click synthesises a press and release of the primary button at a point.
//
// Screen coordinates, which is what the accessibility tree reports extents in
// when asked for them that way — so a campaign that clicks where a widget says
// it is does not need to know about window position.
func (c *Conn) Click(x, y int32) error {
	return c.registryObj(DECPath).Call(IfaceDEC+".GenerateMouseEvent", 0, x, y, "b1c").Err
}

func (c *Conn) registryObj(path dbus.ObjectPath) dbus.BusObject {
	return c.bus.Object(Registry, path)
}

// Extents returns where an object is, in screen coordinates.
func (c *Conn) Extents(r Ref) (x, y, w, h int32, err error) {
	var e struct{ X, Y, W, H int32 }
	// Coordinate type 0 is screen; 1 is relative to the window. Screen, because
	// the click that follows is synthesised at the pointer level and the
	// pointer does not know about windows.
	if err := c.obj(r).Call(IfaceComponent+".GetExtents", 0, uint32(0)).Store(&e); err != nil {
		return 0, 0, 0, 0, err
	}
	return e.X, e.Y, e.W, e.H, nil
}

// StateNames turns AT-SPI's bitmap into the names a fingerprint carries.
//
// Only the states that distinguish one screen from another are named. A
// complete list would put "focusable", "sensitive" and "visible" on every
// widget in the tree, which is noise in a fingerprint: it makes every state
// longer without making any two states more different.
func StateNames(bits []uint32) []string {
	var out []string
	for _, s := range interestingStates {
		if hasState(bits, s.bit) {
			out = append(out, s.name)
		}
	}
	return out
}

type stateBit struct {
	bit  uint
	name string
}

// The AT-SPI state numbers, from the protocol's own enumeration.
var interestingStates = []stateBit{
	{2, "armed"}, {3, "busy"}, {4, "checked"}, {5, "collapsed"},
	{6, "defunct"}, {10, "expanded"}, {12, "focused"}, {15, "iconified"},
	{16, "modal"}, {20, "pressed"}, {23, "selected"}, {27, "stale"},
	{32, "indeterminate"}, {36, "invalid-entry"}, {40, "visited"},
}

// hidden reports whether an object is not currently on screen.
//
// SHOWING is state 25 and VISIBLE is 30; an object needs both. This is the one
// negative worth carrying in a fingerprint, because a dialog appearing is a new
// screen and the widgets it covers are the same widgets they were.
func hidden(bits []uint32) bool {
	return !hasState(bits, 25) || !hasState(bits, 30)
}

func hasState(bits []uint32, n uint) bool {
	word := n / 32
	if int(word) >= len(bits) {
		return false
	}
	return bits[word]&(1<<(n%32)) != 0
}

// Snapshot renders an application's interface as text.
//
// The same shape the web backend produces from a DOM and the terminal backend
// from a screen, because the campaign above them does the same thing with all
// three: normalise it, hash it, and ask whether it has seen it before. What
// goes in is what makes two screens different — the shape of the tree, what
// each thing is, what it is called, whether it is showing, and which one has
// focus. What stays out is what a keystroke changes without changing the
// screen: the contents of a text field appear as "set" or "empty" rather than
// verbatim, or every keystroke would be a new state and the model would learn
// nothing.
func (c *Conn) Snapshot(app Ref, maxNodes, maxDepth int) string {
	var b strings.Builder
	n := 0
	var walk func(r Ref, depth int)
	walk = func(r Ref, depth int) {
		if n >= maxNodes || depth > maxDepth || !r.Valid() {
			return
		}
		n++
		role, _ := c.RoleName(r)
		label, _ := c.Label(r)
		bits, _ := c.States(r)
		ifaces, _ := c.Interfaces(r)

		b.WriteString(strings.Repeat(" ", depth))
		b.WriteString(role)
		if label != "" {
			b.WriteString("#" + label)
		}
		if hasInterface(ifaces, IfaceText) {
			if txt, err := c.Text(r); err == nil {
				if txt == "" {
					b.WriteString("[empty]")
				} else if hasInterface(ifaces, IfaceEditableText) {
					// Editable text is what the fuzzer types into, so its
					// contents are the thing that must not reach the
					// fingerprint. A label's text is part of the screen and does.
					b.WriteString("[set]")
				} else {
					b.WriteString("[" + oneLine(txt) + "]")
				}
			}
		}
		for _, s := range StateNames(bits) {
			b.WriteString(":" + s)
		}
		if hidden(bits) {
			b.WriteString(":hidden")
		}
		b.WriteByte('\n')

		kids, err := c.Children(r)
		if err != nil {
			return
		}
		for _, k := range kids {
			walk(k, depth+1)
		}
	}
	walk(app, 0)
	return b.String()
}

func hasInterface(ifaces []string, want string) bool {
	for _, i := range ifaces {
		if i == want {
			return true
		}
	}
	return false
}

// oneLine flattens and bounds a label so one long text does not become the
// whole fingerprint.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	const max = 120
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
