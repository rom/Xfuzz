package worker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/internal/extension"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/campaign"
)

// A campaign's state function can come from Starlark, which is the last hop
// between a loaded script and the state machine it labels responses for.
//
// Untagged, because it builds no target and spawns nothing: a script tier that
// needed an instrumented binary to test would be a script tier nobody could
// iterate on.
func TestAStatefulCampaignCanLabelResponsesWithAScript(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proto.star")
	src := "def label(resp):\n" +
		"    if len(resp) < 1:\n" +
		"        return None\n" +
		"    return \"reply-%d\" % list(resp.elems())[0]\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &campaign.Resolved{Path: filepath.Join(dir, "campaign.yaml")}
	cfg.Scripts = []campaign.Script{{Name: "proto", Path: "proto.star"}}
	cfg.State = &campaign.State{Fn: "script", Script: "proto:label"}

	set, err := extension.Load(context.Background(), safety.NewSpawner(), cfg, 7, "test")
	if err != nil {
		t.Fatalf("loading the script: %v", err)
	}
	defer set.Close()

	g, err := guidanceFor(cfg, set)
	if err != nil {
		t.Fatalf("building guidance from a script state function: %v", err)
	}
	if got := g.Observer.Fn().Label([]byte{9, 9}); got != "reply-9" {
		t.Errorf("label = %q, want reply-9", got)
	}
	if got := g.Observer.Fn().Name(); !strings.HasPrefix(got, "proto:") {
		t.Errorf("the state function is not named after its script: %q", got)
	}
}

func TestAStateScriptThatIsNotThereIsRefusedRatherThanIgnored(t *testing.T) {
	cfg := &campaign.Resolved{}
	cfg.State = &campaign.State{Fn: "script", Script: "missing:label"}

	set, err := extension.Load(context.Background(), safety.NewSpawner(), cfg, 7, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()

	if _, err := guidanceFor(cfg, set); err == nil {
		t.Fatal("a state function naming a script that does not exist was accepted")
	} else if !strings.Contains(err.Error(), "missing") {
		t.Errorf("the refusal does not name the script: %v", err)
	}
}

// A grammar chooses the codec, except where it would be the wrong one.
//
// On a stateless campaign a grammar means "decode inputs as this structure",
// which is the whole reason to write one. On a session campaign the codec's job
// is to split an input into the messages of a conversation, and a grammar
// describes one message rather than a sequence of them — so taking it would
// turn a conversation into a single blob and the campaign would stop being
// stateful without saying so.
func TestAGrammarChoosesTheCodecExceptOnASessionCampaign(t *testing.T) {
	dir := t.TempDir()
	grammar := filepath.Join(dir, "f.xfg")
	if err := os.WriteFile(grammar, []byte("format m {\n  a: u8\n  b: bytes<0..8>\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	stateless := &campaign.Resolved{}
	stateless.Format = &campaign.Format{Grammar: grammar, Codec: "raw"}
	c, err := codecFor(stateless)
	if err != nil {
		t.Fatal(err)
	}
	if c.Name() != "m" {
		t.Errorf("a stateless campaign with a grammar got the %q codec, want the grammar's", c.Name())
	}

	// An explicit codec still wins: grammar-generated seeds mutated at the byte
	// level is the control arm when measuring what structure buys.
	explicit := &campaign.Resolved{Set: campaign.KeySet{"format.codec": true}}
	explicit.Format = &campaign.Format{Grammar: grammar, Codec: "raw"}
	if c, err := codecFor(explicit); err != nil {
		t.Fatal(err)
	} else if c.Name() != "raw" {
		t.Errorf("an explicit codec: raw was overridden by the grammar, got %q", c.Name())
	}

	session := &campaign.Resolved{}
	session.Format = &campaign.Format{Grammar: grammar, Codec: "session"}
	session.Session = &campaign.Session{Address: "tcp:127.0.0.1:9"}
	if c, err := codecFor(session); err != nil {
		t.Fatal(err)
	} else if c.Name() != "session" {
		t.Errorf("a session campaign with a grammar got the %q codec; "+
			"it would stop splitting the conversation into messages", c.Name())
	}
}
