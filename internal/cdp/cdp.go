// Package cdp speaks the Chrome DevTools Protocol.
//
// It is the mechanism behind the `web` driver backend (ADR-0013): a browser
// exposes every operation a fuzzer needs — navigate, dispatch a key, click at a
// point, read the document, hear about an uncaught exception — over one
// WebSocket carrying JSON. That makes a web application drivable by the same
// event sequence a terminal program is driven by, which is the whole reason the
// domain fits behind the T7 interface rather than needing a second product.
//
// The package is deliberately not a browser automation library. It carries the
// commands the driver sends and nothing else: no selectors, no waiting on
// elements, no page object model. A fuzzer sends keystrokes at whatever has
// focus and reads what the document became, and everything a convenience layer
// would add is a decision about *which* element to interact with — which is the
// fuzzer's decision to make badly on purpose.
package cdp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// Conn is a DevTools connection.
//
// One connection carries every session: the protocol's flattened mode puts a
// session identifier on each message rather than opening a socket per page,
// which means one reader goroutine and one place where a dead browser is
// noticed.
type Conn struct {
	ws *wsConn

	mu      sync.Mutex
	nextID  int64
	pending map[int64]chan *message
	handler func(Event)
	err     error
	closed  bool

	done chan struct{}
}

// Event is an unsolicited message from the browser.
type Event struct {
	// Method is the protocol event name: Runtime.exceptionThrown.
	Method string

	// SessionID names the page it came from, empty for the browser itself.
	SessionID string

	// Params is the event's payload, undecoded. The driver looks at a handful
	// of fields on a handful of events, so decoding every event into a typed
	// struct would be several hundred lines of protocol that nothing reads.
	Params json.RawMessage
}

// message is one protocol frame in either direction.
type message struct {
	ID        int64           `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *protoError     `json:"error,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
}

// protoError is the browser's refusal of a command.
type protoError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

func (e *protoError) Error() string {
	if e.Data != "" {
		return fmt.Sprintf("%s (%d): %s", e.Message, e.Code, e.Data)
	}
	return fmt.Sprintf("%s (%d)", e.Message, e.Code)
}

// ErrClosed is returned once the connection is gone.
var ErrClosed = errors.New("cdp: the connection to the browser is closed")

// Dial connects to a DevTools endpoint and starts reading it.
func Dial(ctx context.Context, dial DialFunc, endpoint string) (*Conn, error) {
	ws, err := wsDial(ctx, dial, endpoint)
	if err != nil {
		return nil, err
	}
	c := &Conn{ws: ws, pending: map[int64]chan *message{}, done: make(chan struct{})}
	go c.read()
	return c, nil
}

// OnEvent registers the handler for unsolicited messages.
//
// One handler rather than a subscription per method: the driver wants every
// event, because what it does with them is decide whether the page is still
// settling and whether anything went wrong, and both questions are asked of the
// whole stream.
func (c *Conn) OnEvent(fn func(Event)) {
	c.mu.Lock()
	c.handler = fn
	c.mu.Unlock()
}

// read is the single reader. Every message either answers a pending command or
// is an event.
func (c *Conn) read() {
	defer close(c.done)
	for {
		raw, err := c.ws.ReadMessage()
		if err != nil {
			c.fail(err)
			return
		}
		var m message
		if err := json.Unmarshal(raw, &m); err != nil {
			// A frame that is not the protocol means the stream is no longer
			// the protocol: continuing would answer the next command with
			// somebody else's reply.
			c.fail(fmt.Errorf("cdp: the browser sent a message that is not protocol JSON: %w", err))
			return
		}
		if m.ID != 0 {
			c.mu.Lock()
			ch := c.pending[m.ID]
			delete(c.pending, m.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- &m
			}
			continue
		}
		if m.Method == "" {
			continue
		}
		c.mu.Lock()
		h := c.handler
		c.mu.Unlock()
		if h != nil {
			h(Event{Method: m.Method, SessionID: m.SessionID, Params: m.Params})
		}
	}
}

// fail records why the connection ended and wakes everyone waiting on it.
func (c *Conn) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	pending := c.pending
	c.pending = map[int64]chan *message{}
	c.closed = true
	c.mu.Unlock()
	for _, ch := range pending {
		close(ch)
	}
}

// Err returns why the connection ended, or nil while it is live.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Done returns a channel closed when the connection ends.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Call sends a command and waits for its reply.
//
// sessionID selects the page; empty addresses the browser itself. result may be
// nil for a command whose reply carries nothing worth reading, which is most of
// the input commands.
func (c *Conn) Call(ctx context.Context, sessionID, method string, params, result any) error {
	var p json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("cdp: encoding %s: %w", method, err)
		}
		p = b
	}

	c.mu.Lock()
	if c.closed {
		err := c.err
		c.mu.Unlock()
		if err != nil {
			return err
		}
		return ErrClosed
	}
	c.nextID++
	id := c.nextID
	ch := make(chan *message, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	req, err := json.Marshal(message{ID: id, Method: method, Params: p, SessionID: sessionID})
	if err != nil {
		c.forget(id)
		return fmt.Errorf("cdp: encoding %s: %w", method, err)
	}
	if err := c.ws.WriteText(req); err != nil {
		c.forget(id)
		return err
	}

	select {
	case <-ctx.Done():
		// The command is still outstanding at the browser; forgetting it here
		// means its eventual reply is dropped rather than delivered to whoever
		// asks next, which is what the identifier is for.
		c.forget(id)
		// Named, because "context deadline exceeded" on its own says a browser
		// stopped answering and not what it stopped answering — and which
		// command hangs is most of the diagnosis.
		return fmt.Errorf("cdp: %s did not answer: %w", method, ctx.Err())
	case m, ok := <-ch:
		if !ok || m == nil {
			if e := c.Err(); e != nil {
				return e
			}
			return ErrClosed
		}
		if m.Error != nil {
			return fmt.Errorf("cdp: %s: %w", method, m.Error)
		}
		if result != nil && len(m.Result) > 0 {
			if err := json.Unmarshal(m.Result, result); err != nil {
				return fmt.Errorf("cdp: decoding the reply to %s: %w", method, err)
			}
		}
		return nil
	}
}

func (c *Conn) forget(id int64) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

// Close ends the connection.
func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	return c.ws.Close()
}
