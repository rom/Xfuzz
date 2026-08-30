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
