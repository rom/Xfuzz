package smart

import (
	"fmt"
	"math/rand"
	"strings"
)

// Smart generators for the line-oriented text protocols. Each one is a
// command followed by CRLF; the parser tokenises on space and reads a
// terminator. The mutations are "an argument that is very long", "a
// terminator in the wrong place", "an argument with escape sequences", and
// "a command the server has not heard of" — which together exercise the
// parser's command table, its line-length cap, and its continuation logic.

// textCommands is the shape every one of these generators follows.
func textCommand(rng *rand.Rand, verbs []string, argShapes []string) []byte {
	verb := pickString(rng, verbs)
	arg := pickString(rng, argShapes)
	sep := pickString(rng, []string{" ", "\t", strings.Repeat(" ", 100), " \r "})
	term := pickString(rng, []string{"\r\n", "\n", "\r", "\r\n\r\n", ""})
	return []byte(verb + sep + arg + term)
}

// textArgs is the bank the per-protocol generators pick an argument from.
var textArgs = []string{
	strings.Repeat("A", 1<<10),
	strings.Repeat("A", 1<<14),
	"",
	"\x00\x00\x00",
	"../" + strings.Repeat("../", 32),
	"$(id)",
	"`id`",
	"${jndi:ldap://x/a}",
	"' OR 1=1 --",
	"\xff\xff\xff\xff",
	strings.Repeat("a\r\n", 32),
}

// Rlogin: a four-field null-separated handshake, then a text session.
func Rlogin(rng *rand.Rand) []byte {
	fields := []string{
		pickString(rng, textArgs), pickString(rng, textArgs),
		pickString(rng, textArgs), pickString(rng, textArgs),
	}
	return []byte("\x00" + strings.Join(fields, "\x00") + "\x00")
}

// Rsh: localuser + remoteuser + command, each null-terminated.
func Rsh(rng *rand.Rand) []byte {
	return []byte("\x00" + pickString(rng, textArgs) + "\x00" + pickString(rng, textArgs) + "\x00" + pickString(rng, textArgs) + "\x00")
}

// Rexec: user + password + command, null-separated. The password field is
// what to push on — a server with no cap on it keeps reading.
func Rexec(rng *rand.Rand) []byte {
	return []byte("\x00" + pickString(rng, textArgs) + "\x00" + strings.Repeat("P", 1+rng.Intn(1<<16)) + "\x00" + pickString(rng, textArgs) + "\x00")
}

// NNTP: text commands that terminate on CRLF.
func NNTP(rng *rand.Rand) []byte {
	return textCommand(rng,
		[]string{"CAPABILITIES", "LIST", "GROUP", "ARTICLE", "HEAD", "BODY", "STAT", "POST", "QUIT", "AUTHINFO USER", "AUTHINFO PASS"},
		textArgs)
}

// IRC: a text line-based protocol with three or four tokens per line.
func IRC(rng *rand.Rand) []byte {
	cmds := []string{"NICK", "USER", "JOIN", "PART", "PRIVMSG", "NOTICE", "MODE", "WHO", "WHOIS", "KICK", "TOPIC", "CAP LS 302", "AUTHENTICATE"}
	return textCommand(rng, cmds, textArgs)
}

// XMPP opens with an XML stream. The mutation targets are oversized
// attributes, nested tags that recurse, and premature stream end.
func XMPP(rng *rand.Rand) []byte {
	to := pickString(rng, textArgs)
	versions := []string{"1.0", "0.9", strings.Repeat("9", 100)}
	return []byte(fmt.Sprintf("<?xml version='1.0'?><stream:stream to='%s' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='%s'>%s",
		to, pickString(rng, versions),
		pickString(rng, []string{"", "<auth mechanism='PLAIN'>" + strings.Repeat("A", 1<<10) + "</auth>", "</stream:stream>"})))
}

// Finger: one-liner lookup.
func Finger(rng *rand.Rand) []byte {
	return []byte(pickString(rng, textArgs) + "\r\n")
}

// Gopher: one selector, newline-terminated.
func Gopher(rng *rand.Rand) []byte {
	return []byte("/" + pickString(rng, textArgs) + "\r\n")
}

// Git protocol: pkt-line framed command, then capabilities.
func Git(rng *rand.Rand) []byte {
	cmds := []string{"git-upload-pack", "git-receive-pack", "git-upload-archive"}
	cmd := pickString(rng, cmds)
	repo := pickString(rng, textArgs)
	body := cmd + " /" + repo + ".git\x00host=fuzz\x00"
	ln := len(body) + 4
	hdr := fmt.Sprintf("%04x", ln)
	if rng.Intn(4) == 0 {
		hdr = "ffff"
	}
	return []byte(hdr + body)
}

// SVN: parenthesised S-expression greeting.
func SVN(rng *rand.Rand) []byte {
	args := []string{
		"( 2 ( edit-pipeline svndiff1 ) 25:svn://example.com/" + pickString(rng, textArgs) + " )",
		"( 99 ( " + strings.Repeat("x ", 1024) + " ) 0: )",
		"( 2 ( ) 0: )",
		strings.Repeat("(", 1024),
	}
	return []byte(pickString(rng, args))
}

// STOMP: text-framed with null terminator.
func STOMP(rng *rand.Rand) []byte {
	frames := []string{
		"CONNECT\naccept-version:1.2\nhost:fuzz\n\n\x00",
		"SEND\ndestination:/queue/" + pickString(rng, textArgs) + "\ncontent-length:9999999\n\nshort\x00",
		"SUBSCRIBE\nid:1\ndestination:" + strings.Repeat("d", 1<<10) + "\n\n\x00",
		"UNKNOWN\n\n\x00",
	}
	return []byte(pickString(rng, frames))
}

// NATS: a one-line protocol with CONNECT, PUB, SUB.
func NATS(rng *rand.Rand) []byte {
	lines := []string{
		`CONNECT {"verbose":false,"pedantic":false}`,
		`PUB subject 5`,
		`SUB subject 1`,
		`PING`,
		`PONG`,
		`CONNECT ` + strings.Repeat(`{"x":1,`, 256) + `}`,
	}
	return []byte(pickString(rng, lines) + "\r\n")
}

// Rsync starts with a version-string handshake.
func Rsync(rng *rand.Rand) []byte {
	versions := []string{"@RSYNCD: 31.0\n", "@RSYNCD: 99.9\n", "@RSYNCD: AUTHREQD " + strings.Repeat("c", 100) + "\n", "@RSYNCD: " + strings.Repeat("X", 1<<10) + "\n"}
	return []byte(pickString(rng, versions))
}

// AsteriskAMI: colon-separated key:value lines, blank-line terminated.
func AsteriskAMI(rng *rand.Rand) []byte {
	actions := []string{"Login", "Logoff", "Originate", "Command", "GetVar", "SetVar", "Ping", "CoreStatus", "Reload"}
	var b strings.Builder
	fmt.Fprintf(&b, "Action: %s\r\n", pickString(rng, actions))
	for i := 0; i < 1+rng.Intn(5); i++ {
		fmt.Fprintf(&b, "Key%d: %s\r\n", i, pickString(rng, textArgs))
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

// VMwareAuthd: USER then PASS, line-based.
func VMwareAuthd(rng *rand.Rand) []byte {
	cmd := pickString(rng, []string{"USER", "PASS", "LIST", "AUTH", "UNKNOWN"})
	return []byte(cmd + " " + pickString(rng, textArgs) + "\n")
}

// ATG: tank-gauge text protocol with 0x01 prefix and I-codes.
func ATG(rng *rand.Rand) []byte {
	codes := []string{"I20100", "I20200", "I60100", "I20300", "S60100", "C00100"}
	return []byte("\x01" + pickString(rng, codes) + pickString(rng, textArgs) + "\r\n")
}

// MBUS: a request with a short line header followed by the meter payload.
func Mbus(rng *rand.Rand) []byte {
	start := byte(pickString(rng, []string{"\x68", "\x10", "\xe5"})[0])
	ln := byte(1 + rng.Intn(0xff))
	if rng.Intn(4) == 0 {
		ln = 0xff
	}
	out := []byte{start, ln, ln, start, 0x53, 0xfe, 0x50}
	n := rng.Intn(64)
	rest := make([]byte, n)
	_, _ = rng.Read(rest)
	return append(out, rest...)
}

// Lantronix: raw byte frame with a leading magic.
func Lantronix(rng *rand.Rand) []byte {
	magics := [][]byte{{0x00, 0x00, 0x00, 0xf6}, {0x00, 0x00, 0x00, 0xf8}, {0x01, 0x00, 0x00, 0x00}}
	m := magics[rng.Intn(len(magics))]
	n := rng.Intn(256)
	rest := make([]byte, n)
	_, _ = rng.Read(rest)
	return append(m, rest...)
}

// Tn3270: IAC-prefixed terminal negotiation.
func Tn3270(rng *rand.Rand) []byte {
	// Reuse the Telnet smart generator — tn3270 is Telnet with specific
	// option bytes (bind, terminal-type), and the Telnet mutator explores
	// the whole option space.
	return Telnet(rng)
}

// Ident: "port,port\r\n" with mutated numbers.
func Ident(rng *rand.Rand) []byte {
	return []byte(fmt.Sprintf("%d,%d\r\n", rng.Intn(1<<32), rng.Intn(1<<32)))
}

// Socks: v4 or v5 handshake with mutated fields.
func Socks(rng *rand.Rand) []byte {
	if rng.Intn(2) == 0 {
		// v4 CONNECT
		return []byte{0x04, 0x01, byte(rng.Intn(0x100)), byte(rng.Intn(0x100)),
			byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100)),
			'u', 0x00}
	}
	// v5 nmethods list
	n := byte(rng.Intn(0xff))
	out := []byte{0x05, n}
	for i := 0; i < int(n) && i < 255; i++ {
		out = append(out, byte(rng.Intn(0x100)))
	}
	return out
}

// Beanstalkd: text verbs with YAML bodies.
func Beanstalkd(rng *rand.Rand) []byte {
	cmds := []string{
		"stats\r\n",
		"stats-tube " + pickString(rng, textArgs) + "\r\n",
		"use " + pickString(rng, textArgs) + "\r\n",
		"put 1 0 60 " + fmt.Sprint(rng.Intn(1<<20)) + "\r\nshort\r\n",
		"peek-ready\r\n",
		"delete " + fmt.Sprint(rng.Intn(1<<30)) + "\r\n",
		"list-tubes\r\n",
	}
	return []byte(pickString(rng, cmds))
}

// JDWP: after the ASCII handshake, binary packet headers.
func JDWP(rng *rand.Rand) []byte {
	if rng.Intn(2) == 0 {
		return []byte("JDWP-Handshake")
	}
	// Packet: length(4) id(4) flags(1) cmdset(1) cmd(1)
	id := rng.Uint32()
	flags := byte(rng.Intn(0x100))
	cmdset := byte(rng.Intn(0x100))
	cmd := byte(rng.Intn(0x100))
	data := make([]byte, rng.Intn(64))
	_, _ = rng.Read(data)
	ln := uint32(11 + len(data))
	if rng.Intn(4) == 0 {
		ln = 0xffffffff
	}
	out := []byte{
		byte(ln >> 24), byte(ln >> 16), byte(ln >> 8), byte(ln),
		byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id),
		flags, cmdset, cmd,
	}
	return append(out, data...)
}

// EPMD: Erlang port mapper, 2-byte length then op byte.
func EPMD(rng *rand.Rand) []byte {
	ops := []byte{0x6e, 0x78, 0x73, 0x7a}
	op := ops[rng.Intn(len(ops))]
	body := []byte{op}
	n := rng.Intn(1 << 14)
	if rng.Intn(4) == 0 {
		n = 0xffff
	}
	rest := make([]byte, rng.Intn(64))
	_, _ = rng.Read(rest)
	body = append(body, rest...)
	hdr := []byte{byte(n >> 8), byte(n)}
	return append(hdr, body...)
}

// BGP: 19-byte header plus a mutated body.
func BGP(rng *rand.Rand) []byte {
	msgType := byte(1 + rng.Intn(4))
	body := make([]byte, 10+rng.Intn(256))
	_, _ = rng.Read(body)
	ln := uint16(19 + len(body))
	if rng.Intn(4) == 0 {
		ln = 0xffff
	}
	out := make([]byte, 19, 19+len(body))
	for i := 0; i < 16; i++ {
		out[i] = 0xff
	}
	out[16] = byte(ln >> 8)
	out[17] = byte(ln)
	out[18] = msgType
	return append(out, body...)
}
