package daemon

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/rom/Xfuzz/internal/safety"
)

// The worker launch contract.
//
// A worker is told three things: which campaign file to run, which worker it is,
// and where the store lives. Everything else it reads from the file, which is
// the point of the file being the only interface (ADR-0016) — a worker
// configured by twenty flags would be a second configuration surface that could
// disagree with the first.

// Environment variables the daemon sets for a worker.
const (
	// EnvWorkerID is the worker's index. It derives every RNG stream, so it
	// must be stable across a restart (ASR-0008).
	EnvWorkerID = "XFUZZ_WORKER_ID"

	// EnvCampaignSeed is the campaign's root seed.
	EnvCampaignSeed = "XFUZZ_CAMPAIGN_SEED"

	// EnvStrategy names the ensemble strategy this worker was assigned.
	EnvStrategy = "XFUZZ_STRATEGY"

	// EnvControlFD and EnvStatusFD tell the worker which descriptors carry the
	// protocol. They mirror the fork server's own convention so there is one
	// way descriptors are passed in this codebase rather than two.
	EnvControlFD = "XFUZZ_CTL_FD"
	EnvStatusFD  = "XFUZZ_ST_FD"

	// WorkerControlFD and WorkerStatusFD are where the spawner places them.
	WorkerControlFD = 3
	WorkerStatusFD  = 4
)

// CampaignFileName is what the daemon calls the copy of the campaign it writes
// into a run's working directory.
const CampaignFileName = "campaign.yaml"

// campaignFile is the file workers are given.
func (c *Campaign) campaignFile() string {
	return filepath.Join(c.workDir, CampaignFileName)
}

// writeCampaignFile materialises the resolved configuration beside the run.
//
// Workers are given this copy rather than the path the client named, for four
// reasons that are really one: the client's path is not the daemon's. It is
// relative to a working directory the worker does not share; it may not exist
// on the daemon's machine at all; its includes and profiles would have to be
// resolved a second time, by a different process, and could resolve
// differently; and it can be edited while the campaign runs.
//
// The copy is the fully resolved form, with every path already absolute, so it
// means the same thing from anywhere — and it leaves the run's directory
// holding exactly the configuration that produced it, which is what makes a
// campaign a reviewable artefact rather than a shell history entry (ADR-0016).
func (c *Campaign) writeCampaignFile() error {
	doc, err := c.Config.YAML()
	if err != nil {
		return fmt.Errorf("daemon: rendering the resolved campaign: %w", err)
	}
	if err := os.WriteFile(c.campaignFile(), doc, 0o644); err != nil {
		return fmt.Errorf("daemon: writing the campaign file: %w", err)
	}
	return nil
}

// workerArgs returns the worker's argument vector.
func (c *Campaign) workerArgs(id int) []string {
	args := []string{
		"--campaign", c.campaignFile(),
		"--worker", strconv.Itoa(id),
	}
	// No --profile: the file above is already resolved, so applying the
	// profiles again would be applying them twice.
	//
	// The store the daemon actually opened, not the one the file asked for. A
	// campaign that names no directory still has a store — the daemon's default
	// — and a worker told only what the file said looks for one that does not
	// exist and reports that it has nothing to fuzz from.
	if c.store != nil {
		args = append(args, "--store", c.store.Dir())
	}
	return args
}

// workerEnv returns the worker's environment.
func (c *Campaign) workerEnv(id int) []string {
	env := []string{
		EnvWorkerID + "=" + strconv.Itoa(id),
		EnvCampaignSeed + "=" + strconv.FormatUint(c.Seed, 10),
		EnvControlFD + "=" + strconv.Itoa(WorkerControlFD),
		EnvStatusFD + "=" + strconv.Itoa(WorkerStatusFD),
	}
	if s := c.strategyFor(id); s != "" {
		env = append(env, EnvStrategy+"="+s)
	}
	for k, v := range c.Config.Target.Env {
		env = append(env, k+"="+v)
	}
	return env
}

// drawSeed produces a campaign seed.
//
// From the system's randomness rather than from the clock: two campaigns
// started in the same second must not explore the same sequence, and a
// clock-derived seed makes that likely on a machine that starts a batch of them
// (ASR-0008).
func drawSeed() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("daemon: no system randomness to seed a campaign: %v", err))
	}
	s := binary.LittleEndian.Uint64(b[:])
	if s == 0 {
		// Zero means "draw one" everywhere else, so it is the one value a drawn
		// seed must not be.
		s = 1
	}
	return s
}

// WorkerBinaryName is the worker executable.
const WorkerBinaryName = "xfuzz-worker"

// findWorkerBinary locates xfuzz-worker through the spawn boundary's own
// lookup, so there is one rule about where Xfuzz finds its binaries rather than
// two.
func findWorkerBinary() string {
	if p, err := safety.FindTool(WorkerBinaryName); err == nil {
		return p
	}
	// Returned unresolved rather than empty, so the failure is "xfuzz-worker:
	// no such file" at the spawn rather than a confusing empty path.
	return WorkerBinaryName
}
