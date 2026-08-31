package cdp

import (
	"context"
	"encoding/json"
	"fmt"
)

// The commands the driver sends, and nothing else.
//
// The protocol has some hundreds of methods. What a fuzzer needs is: open a
// page, point it somewhere, type, click, resize, read what the document became,
// and get rid of a modal dialog that would otherwise block every subsequent
// command. Each one here is a method the driver calls; a method nothing calls
// would be protocol surface nobody has run.

// Page is one attached browser tab.
type Page struct {
	conn    *Conn
	session string
	target  string
}

// NewPage opens a tab and attaches to it.
//
// Attached in flattened mode, so its messages travel on the browser's own
// connection tagged with a session identifier rather than on a second socket.
// One socket means one reader, one place a dead browser is noticed, and no
// chance of a page's connection outliving the browser's.
func (c *Conn) NewPage(ctx context.Context, width, height int) (*Page, error) {
	var created struct {
		TargetID string `json:"targetId"`
	}
	if err := c.Call(ctx, "", "Target.createTarget",
		map[string]any{"url": "about:blank"}, &created); err != nil {
		return nil, err
	}
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := c.Call(ctx, "", "Target.attachToTarget",
		map[string]any{"targetId": created.TargetID, "flatten": true}, &attached); err != nil {
		return nil, err
	}
	p := &Page{conn: c, session: attached.SessionID, target: created.TargetID}

	// Each domain must be enabled before it reports anything. Runtime is where
	// an uncaught exception arrives, Log where a console error does, Page where
	// navigation and dialogs do, and Inspector where a renderer crash does —
	// which between them are every way a page fails without the process dying.
	for _, domain := range []string{"Page.enable", "Runtime.enable", "Log.enable", "Inspector.enable"} {
		if err := p.Call(ctx, domain, nil, nil); err != nil {
			return nil, err
		}
	}
	if width > 0 && height > 0 {
		if err := p.SetSize(ctx, width, height); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// SessionID identifies this page's messages on the shared connection.
func (p *Page) SessionID() string { return p.session }

// Call sends a command to this page.
func (p *Page) Call(ctx context.Context, method string, params, result any) error {
	return p.conn.Call(ctx, p.session, method, params, result)
}

// Navigate points the page at a URL and reports a navigation the browser
// refused.
//
// The refusal matters and is easy to miss: navigating to a URL that does not
// resolve succeeds at the protocol level and leaves an error page, so a campaign
// whose target was never reachable would fuzz Chrome's error page for an hour
// and report that it found nothing.
func (p *Page) Navigate(ctx context.Context, url string) error {
	var res struct {
		ErrorText string `json:"errorText"`
	}
	if err := p.Call(ctx, "Page.navigate", map[string]any{"url": url}, &res); err != nil {
		return err
	}
	if res.ErrorText != "" {
		return fmt.Errorf("cdp: navigating to %s: %s", url, res.ErrorText)
	}
	return nil
}

// SetSize changes the viewport, which is an input: a page that lays out
// correctly at 1280 and misplaces a button at 400 has a bug only one of them
// finds.
func (p *Page) SetSize(ctx context.Context, width, height int) error {
	return p.Call(ctx, "Emulation.setDeviceMetricsOverride", map[string]any{
		"width": width, "height": height, "deviceScaleFactor": 1, "mobile": false,
	}, nil)
}

// Key is one keystroke as the protocol wants it.
type Key struct {
	// Key is the DOM key value: "Enter", "ArrowUp", "a".
	Key string

	// Code is the physical key: "Enter", "ArrowUp", "KeyA".
	Code string

	// VK is the legacy virtual key code, which older page code still reads.
	VK int

	// Text is what the keystroke inserts, empty for a key that only navigates.
	// Its presence is what makes the browser treat the event as text entry.
	Text string

	// Modifiers is the protocol's bitmask: alt 1, ctrl 2, meta 4, shift 8.
	Modifiers int
}

// SendKey dispatches a keystroke as a press and a release.
//
// Both halves, always. A page that listens for keyup — which is what a search
// box that filters as you type usually does — sees nothing from a press alone,
// and the campaign would deliver thousands of keystrokes that the application
// never reacts to.
func (p *Page) SendKey(ctx context.Context, k Key) error {
	down := map[string]any{
		"type":                  "rawKeyDown",
		"key":                   k.Key,
		"code":                  k.Code,
		"windowsVirtualKeyCode": k.VK,
		"nativeVirtualKeyCode":  k.VK,
		"modifiers":             k.Modifiers,
	}
	if k.Text != "" {
		// keyDown rather than rawKeyDown: the difference is whether the browser
		// inserts the text, and rawKeyDown does not.
		down["type"] = "keyDown"
		down["text"] = k.Text
		down["unmodifiedText"] = k.Text
	}
	if err := p.Call(ctx, "Input.dispatchKeyEvent", down, nil); err != nil {
		return err
	}
	return p.Call(ctx, "Input.dispatchKeyEvent", map[string]any{
		"type":                  "keyUp",
		"key":                   k.Key,
		"code":                  k.Code,
		"windowsVirtualKeyCode": k.VK,
		"nativeVirtualKeyCode":  k.VK,
		"modifiers":             k.Modifiers,
	}, nil)
}

// InsertText types a literal string.
//
// One command rather than a keystroke per rune, because a mutator produces text
// no keyboard has — combining marks, right-to-left overrides, unpaired
// surrogates — and turning that into key codes would be a second, worse
// implementation of what the browser already does.
func (p *Page) InsertText(ctx context.Context, text string) error {
	return p.Call(ctx, "Input.insertText", map[string]any{"text": text}, nil)
}

// Click presses and releases the primary button at a point.
func (p *Page) Click(ctx context.Context, x, y int) error {
	for _, t := range []string{"mousePressed", "mouseReleased"} {
		if err := p.Call(ctx, "Input.dispatchMouseEvent", map[string]any{
			"type": t, "x": x, "y": y, "button": "left", "clickCount": 1,
			"buttons": 1,
		}, nil); err != nil {
			return err
		}
	}
	return nil
}

// EvalError is a script that threw rather than returned.
type EvalError struct{ Text string }

func (e *EvalError) Error() string { return "cdp: the page's script threw: " + e.Text }

// EvalString runs an expression and returns its value as a string.
func (p *Page) EvalString(ctx context.Context, expr string) (string, error) {
	var res struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text      string `json:"text"`
			Exception *struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	err := p.Call(ctx, "Runtime.evaluate", map[string]any{
		"expression": expr, "returnByValue": true, "awaitPromise": false,
	}, &res)
	if err != nil {
		return "", err
	}
	if res.ExceptionDetails != nil {
		text := res.ExceptionDetails.Text
		if res.ExceptionDetails.Exception != nil && res.ExceptionDetails.Exception.Description != "" {
			text = res.ExceptionDetails.Exception.Description
		}
		return "", &EvalError{Text: text}
	}
	var s string
	if len(res.Result.Value) > 0 {
		if err := json.Unmarshal(res.Result.Value, &s); err != nil {
			// A value that is not a string — the expression returned undefined,
			// or a number. Handing back the raw JSON is more useful than an
			// error, because the caller asked for a fingerprint and any stable
			// rendering is one.
			return string(res.Result.Value), nil
		}
	}
	return s, nil
}

// DismissDialog answers a modal the page opened.
//
// Not optional. alert() blocks the renderer until something answers it, and
// every subsequent command on that page times out — so one alert() in a fuzzed
// path would stall the campaign rather than end the sequence.
func (p *Page) DismissDialog(ctx context.Context, accept bool) error {
	return p.Call(ctx, "Page.handleJavaScriptDialog", map[string]any{"accept": accept}, nil)
}

// Close closes the tab.
func (p *Page) Close(ctx context.Context) error {
	return p.conn.Call(ctx, "", "Target.closeTarget",
		map[string]any{"targetId": p.target}, nil)
}
