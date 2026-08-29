package campaign

import (
	"fmt"
	"strconv"
	"strings"
)

// WorkerPlaceholder is replaced with the worker's index in a session address.
//
// Workers each run their own copy of the target, so the address has to differ
// per worker or the second one binds what the first already holds. Making it a
// placeholder rather than an automatic suffix keeps the campaign file in control
// of where it lands — a port needs the number at the end, a socket path needs it
// before the extension, and guessing wrong produces an address that looks right
// and does not work.
const WorkerPlaceholder = "{worker}"

// SplitAddress separates a session address into a network and an address.
//
// The scheme is required rather than inferred. "127.0.0.1:9000" is a plausible
// TCP address and a plausible filename, and a campaign that meant one and got
// the other fails with a message about the wrong thing.
func SplitAddress(addr string) (network, address string, err error) {
	scheme, rest, ok := strings.Cut(addr, ":")
	if !ok || rest == "" {
		return "", "", fmt.Errorf("%q has no scheme", addr)
	}
	switch scheme {
	case "unix":
		return "unix", rest, nil
	case "tcp", "tcp4", "tcp6":
		if !strings.Contains(rest, ":") {
			return "", "", fmt.Errorf("%q names no port", addr)
		}
		if err := checkHostPort(rest); err != nil {
			return "", "", err
		}
		return scheme, rest, nil
	default:
		return "", "", fmt.Errorf("%q is not a supported scheme", scheme)
	}
}

// checkHostPort rejects a port that is not a number in range, unless it still
// holds the worker placeholder — which is resolved before anything dials.
func checkHostPort(hostport string) error {
	i := strings.LastIndex(hostport, ":")
	port := hostport[i+1:]
	if strings.Contains(port, WorkerPlaceholder) {
		return nil
	}
	return checkPort(port)
}

// ResolveAddress substitutes the worker index into a session address.
//
// For a port the index is added to it, and for anything else it is substituted
// literally — a worker needs its own port number, not the string "tcp:127.0.0.1:
// 90000".
func ResolveAddress(addr string, worker int) string {
	if !strings.Contains(addr, WorkerPlaceholder) {
		return addr
	}
	scheme, rest, err := SplitAddress(addr)
	if err != nil || scheme == "unix" {
		return strings.ReplaceAll(addr, WorkerPlaceholder, strconv.Itoa(worker))
	}

	i := strings.LastIndex(rest, ":")
	host, port := rest[:i], rest[i+1:]
	if base, perr := strconv.Atoi(strings.ReplaceAll(port, WorkerPlaceholder, "")); perr == nil && port != WorkerPlaceholder {
		// A port written as "9000{worker}" would give 90000 for worker 0, which
		// is not a port at all. Adding the index to the base is what somebody
		// writing this means.
		return scheme + ":" + host + ":" + strconv.Itoa(base+worker)
	}
	return scheme + ":" + host + ":" + strings.ReplaceAll(port, WorkerPlaceholder, strconv.Itoa(worker))
}

// ParseTransition reads a declared transition, written "from->to".
func ParseTransition(s string) (from, to string, err error) {
	f, t, ok := strings.Cut(s, "->")
	if !ok {
		return "", "", fmt.Errorf("%q is not a transition", s)
	}
	f, t = strings.TrimSpace(f), strings.TrimSpace(t)
	if f == "" || t == "" {
		return "", "", fmt.Errorf("%q names no %s state",
			s, map[bool]string{true: "source", false: "destination"}[f == ""])
	}
	return f, t, nil
}
