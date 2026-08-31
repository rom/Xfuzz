#!/usr/bin/env python3
"""A small GTK application with a planted bug, for the gui-atspi driver.

The bug is the shape a desktop application actually fails in: an exception
inside a signal handler. GTK catches it, prints a traceback, and carries on —
the process does not die, the exit status is zero, and the only evidence is on
standard error and in the screen the application is left showing. That is what
the interface oracles are for (ADR-0013).

Python and GTK rather than a compiled program, because what is being tested is
the driver rather than the target: the accessibility tree a toolkit publishes is
the same tree whatever built the window.
"""

import sys

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402


class Form(Gtk.Window):
    def __init__(self):
        super().__init__(title="xfuzz gui target")
        self.set_default_size(320, 220)
        self.opened = 0

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_top(8)
        box.set_margin_start(8)
        self.add(box)

        self.entry = Gtk.Entry()
        self.entry.get_accessible().set_name("query")
        box.pack_start(self.entry, False, False, 0)

        self.go = Gtk.Button(label="go")
        self.go.get_accessible().set_name("go")
        self.go.connect("clicked", self.on_go)
        box.pack_start(self.go, False, False, 0)

        self.panel = Gtk.Label(label="")
        self.panel.get_accessible().set_name("panel")
        box.pack_start(self.panel, False, False, 0)

        self.status = Gtk.Label(label="ready")
        self.status.get_accessible().set_name("status")
        box.pack_start(self.status, False, False, 0)

    def on_go(self, _button):
        text = self.entry.get_text()
        self.opened += 1
        if self.opened >= 2:
            # The planted bug: reachable only by activating the button twice,
            # which is what an event-sequence mutator finds by duplicating an
            # event rather than by guessing a string.
            raise ValueError("planted: the panel was opened twice")
        self.panel.set_text("panel open: " + text)
        self.status.set_text("opened")


def main():
    win = Form()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    Gtk.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
