package driver

import (
	"context"
	"os"
	"strings"
	"time"
)

// What a harness needs from the session it runs in.
//
// A campaign gives its target an environment built from the campaign file and
// nothing else, and that is right for a parser: an inherited environment is a
// hidden input, and a finding that depends on one does not reproduce on another
// machine (ASR-0008). A desktop application is different in a way that is not
// negotiable — without a display it does not draw, and without a session bus it
// publishes no accessibility tree — so the campaign would start, the target
// would run, and it would never appear to the driver at all.
//
// So the driver backends pass through a named list and nothing else. Not the
// whole environment: these are the variables that say *where the session is*,
// and everything that would make a finding machine-specific stays out.

// SessionVars are the variables a windowed or accessible program needs.
var SessionVars = []string{
	// Where to draw.
	"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY",
	// Where the session bus is, which is where the accessibility bus is
	// advertised.
	"DBUS_SESSION_BUS_ADDRESS", "AT_SPI_BUS",
	// Where per-user runtime sockets live, which is where both of the above
	// often are.
	"XDG_RUNTIME_DIR",
	// A toolkit that cannot find a home directory refuses to start rather than
	// running without its settings.
	"HOME", "USER", "LOGNAME",
	// Some toolkits need to be told to publish an accessibility tree at all.
	"GTK_MODULES", "QT_ACCESSIBILITY", "QT_LINUX_ACCESSIBILITY_ALWAYS_ON",
	// A program started with no PATH cannot find its own helpers.
	"PATH",
}

// WithSessionEnv returns the campaign's environment plus the session variables
// it did not set itself.
//
// The campaign wins where it named a variable: an operator who set DISPLAY
// meant that display, and silently overriding it would make the campaign file
// stop describing what ran.
func WithSessionEnv(env []string) []string {
	set := make(map[string]bool, len(env))
	for _, e := range env {
		if k, _, ok := strings.Cut(e, "="); ok {
			set[k] = true
		}
	}
	out := append([]string(nil), env...)
	for _, k := range SessionVars {
		if set[k] {
			continue
		}
		if v, ok := os.LookupEnv(k); ok {
			out = append(out, k+"="+v)
		}
	}
	return out
}

// closeCtx returns a context bounded by d, and cancelled when the backend is
// closed.
//
// Reset takes no context — executor.DriverBackend's Reset cannot, because a
// reset is a property of the backend rather than of one execution — so a
// restart that cannot complete would otherwise ignore a campaign being stopped
// and hold the worker open for its whole start timeout. Measured: a worker that
// had been asked to stop sat for thirty seconds waiting for an application to
// republish a tree it was never going to publish.
func closeCtx(done <-chan struct{}, d time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	go func() {
		select {
		case <-done:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}
