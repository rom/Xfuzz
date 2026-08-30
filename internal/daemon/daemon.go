// Package daemon is the control plane: campaign lifecycle, configuration
// resolution, worker supervision, and the event bus.
//
// Campaigns are decoupled from client lifetime — launch from the CLI, observe
// from the browser, triage tomorrow. The daemon is also the single chokepoint
// for authorization, scope enforcement, and audit (ADR-0003).
//
// It supervises worker processes but does not spawn them directly: process
// creation goes through internal/safety like every other spawn.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/rom/Xfuzz/internal/store"
	"github.com/rom/Xfuzz/internal/version"
	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/corpus"
)

// ErrNoCampaign is returned for a campaign the daemon does not know about.
var ErrNoCampaign = errors.New("daemon: no such campaign")

// Options configure a daemon.
type Options struct {
	// DataDir holds stores, sockets, and worker working directories. Empty
	// uses the platform's user data directory.
	DataDir string

	// WorkerBinary is the xfuzz-worker executable. Empty looks beside the
	// running binary and then on PATH, the same lookup the sandbox helper uses,
	// so a released tarball works with no configuration.
	WorkerBinary string

	// Spawner starts worker processes. Nil uses a trusted spawner.
	Spawner Spawner

	// MaxCampaigns caps how many campaigns may run at once. A daemon with no
	// cap is one core-count typo away from a machine that has to be rebooted.
	MaxCampaigns int

	// EventInterval bounds how often coalescing subscribers are woken.
	EventInterval time.Duration

	// Retention bounds each campaign's metrics history.
	Retention time.Duration
}

// DefaultMaxCampaigns is how many campaigns may run at once by default.
const DefaultMaxCampaigns = 8

// Daemon holds the running campaigns.
type Daemon struct {
	opts    Options
	bus     *Bus
	started time.Time

	mu        sync.RWMutex
	campaigns map[string]*Campaign
	stores    map[string]*store.Store
	closed    bool
}

// New returns a daemon. It does not listen; that is internal/api's job.
func New(opts Options) (*Daemon, error) {
	if opts.DataDir == "" {
		dir, err := DefaultDataDir()
		if err != nil {
			return nil, err
		}
		opts.DataDir = dir
	}
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("daemon: creating %s: %w", opts.DataDir, err)
	}
	if opts.MaxCampaigns <= 0 {
		opts.MaxCampaigns = DefaultMaxCampaigns
	}
	if opts.EventInterval == 0 {
		opts.EventInterval = 250 * time.Millisecond
	}
	if opts.WorkerBinary == "" {
		opts.WorkerBinary = findWorkerBinary()
	}

	return &Daemon{
		opts:      opts,
		bus:       NewBus(opts.EventInterval),
		started:   time.Now(),
		campaigns: map[string]*Campaign{},
		stores:    map[string]*store.Store{},
	}, nil
}

// Bus returns the event bus, which the API subscribes to.
func (d *Daemon) Bus() *Bus { return d.bus }

// DataDir returns the daemon's data directory.
func (d *Daemon) DataDir() string { return d.opts.DataDir }

// Info describes the daemon, for the admin service.
type Info struct {
	Version      version.Info `json:"version"`
	Pid          int          `json:"pid"`
	Started      time.Time    `json:"started"`
	Uptime       string       `json:"uptime"`
	DataDir      string       `json:"data_dir"`
	WorkerBinary string       `json:"worker_binary"`
	Campaigns    int          `json:"campaigns"`
	MaxCampaigns int          `json:"max_campaigns"`
	Subscribers  int          `json:"subscribers"`
}

// Info returns the daemon's own status.
func (d *Daemon) Info() Info {
	d.mu.RLock()
	n := len(d.campaigns)
	d.mu.RUnlock()

	return Info{
		Version:      version.Get(),
		Pid:          os.Getpid(),
		Started:      d.started,
		Uptime:       time.Since(d.started).Round(time.Second).String(),
		DataDir:      d.opts.DataDir,
		WorkerBinary: d.opts.WorkerBinary,
		Campaigns:    n,
		MaxCampaigns: d.opts.MaxCampaigns,
		Subscribers:  d.bus.Subscribers(),
	}
}

// Create prepares a campaign from a resolved file without starting it.
func (d *Daemon) Create(ctx context.Context, cfg *campaign.Resolved) (*Campaign, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, errors.New("daemon: shutting down")
	}
	if _, dup := d.campaigns[cfg.Name]; dup {
		d.mu.Unlock()
		return nil, fmt.Errorf("daemon: campaign %q already exists", cfg.Name)
	}
	if len(d.campaigns) >= d.opts.MaxCampaigns {
		d.mu.Unlock()
		return nil, fmt.Errorf("daemon: %d campaigns are already loaded, which is the limit",
			d.opts.MaxCampaigns)
	}
	d.mu.Unlock()

	st, err := d.storeAt(cfg.Storage.Dir)
	if err != nil {
		return nil, err
	}
	return d.register(ctx, cfg, st)
}

// register builds a campaign against a store and adds it to the registry.
//
// Shared by Create and Load, so that a campaign the daemon was given and one it
// found in a store are the same object built the same way. Anything that held
// only for one of them would be a rule nobody could predict from the outside.
func (d *Daemon) register(ctx context.Context, cfg *campaign.Resolved, st *store.Store) (*Campaign, error) {
	workDir := filepath.Join(d.opts.DataDir, "run", cfg.Name)
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return nil, fmt.Errorf("daemon: creating %s: %w", workDir, err)
	}

	spawner := d.opts.Spawner
	if spawner == nil {
		spawner = trustedSpawner()
	}

	c, err := NewCampaign(ctx, cfg, CampaignOptions{
		Store:        st,
		Bus:          d.bus,
		Spawner:      spawner,
		WorkerBinary: d.opts.WorkerBinary,
		WorkDir:      workDir,
		// The file's seed, or zero to draw one. A pinned seed is what makes a
		// campaign a repeatable experiment (ASR-0008); a resumed campaign keeps
		// the seed the store recorded and ignores this, which NewCampaign does.
		Seed:      cfg.Seed,
		Retention: d.opts.Retention,
	})
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	d.campaigns[cfg.Name] = c
	d.mu.Unlock()
	return c, nil
}

// Campaign returns a loaded campaign by name.
func (d *Daemon) Campaign(name string) (*Campaign, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	c, ok := d.campaigns[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNoCampaign, name)
	}
	return c, nil
}

// Campaigns returns every loaded campaign, by name.
func (d *Daemon) Campaigns() []*Campaign {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]*Campaign, 0, len(d.campaigns))
	for _, c := range d.campaigns {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Config.Name < out[j].Config.Name })
	return out
}

// Forget removes a finished campaign from the daemon.
//
// The store keeps everything; this only frees the in-memory supervision. A
// campaign whose findings are still being triaged tomorrow does not need its
// worker table held open today.
func (d *Daemon) Forget(name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.campaigns[name]
	if !ok {
		return fmt.Errorf("%w: %q", ErrNoCampaign, name)
	}
	if s := c.State(); s == StateRunning || s == StatePaused {
		return fmt.Errorf("daemon: campaign %q is %s; stop it first", name, s)
	}
	delete(d.campaigns, name)
	return c.Close()
}

// Close stops every campaign and releases the stores.
func (d *Daemon) Close(ctx context.Context) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	cs := make([]*Campaign, 0, len(d.campaigns))
	for _, c := range d.campaigns {
		cs = append(cs, c)
	}
	stores := make([]*store.Store, 0, len(d.stores))
	for _, s := range d.stores {
		stores = append(stores, s)
	}
	d.mu.Unlock()

	// Campaigns first, so a worker's last checkpoint is written before the
	// store it would be written to is closed.
	for _, c := range cs {
		if s := c.State(); s == StateRunning || s == StatePaused {
			_ = c.Stop(ctx, "daemon shutting down")
		}
		_ = c.Close()
	}
	var firstErr error
	for _, s := range stores {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// DefaultDataDir returns the daemon's data directory.
func DefaultDataDir() (string, error) {
	if dir := os.Getenv("XFUZZ_DATA_DIR"); dir != "" {
		return dir, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return "", fmt.Errorf("daemon: no data directory: %w", err)
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "xfuzz"), nil
}

// Load registers a campaign that already exists in a store.
//
// The other half of ADR-0003's "triage tomorrow": a campaign's findings, corpus
// and state machine outlive the run, and reading them should not require the
// file that produced it. The store carries the resolved document (schema 2), so
// what is loaded is exactly what ran — the same configuration, the same seed,
// the same corpus — rather than a reconstruction.
//
// The result is an ordinary campaign, deliberately. A loaded campaign that
// could only be read would be a second kind of campaign with its own rules
// about what works on it; instead, what it can do follows from the state it is
// in, which is the same answer as for a campaign the daemon has held all along.
func (d *Daemon) Load(ctx context.Context, dir, name string) (*Campaign, error) {
	if name == "" {
		return nil, errors.New("daemon: loading a campaign needs its name")
	}
	d.mu.RLock()
	existing, loaded := d.campaigns[name]
	d.mu.RUnlock()
	if loaded {
		// Not an error. Loading what is already loaded is what a console does
		// when somebody opens the same campaign twice, and the useful answer is
		// the campaign rather than a complaint about it.
		return existing, nil
	}

	st, err := d.storeAt(dir)
	if err != nil {
		return nil, err
	}
	rec, err := st.Campaign(ctx, name)
	if err != nil {
		return nil, err
	}
	if rec.ConfigDocument == "" {
		return nil, fmt.Errorf("daemon: campaign %q was recorded without its configuration, "+
			"by a build older than store schema 2; run it from its campaign file instead", name)
	}

	cfg, err := campaign.Parse([]byte(rec.ConfigDocument), name)
	if err != nil {
		return nil, fmt.Errorf("daemon: the stored configuration for %q does not parse: %w", name, err)
	}
	return d.register(ctx, cfg, st)
}

// storeAt opens the store rooted at dir, or the daemon's own when dir is empty.
//
// Stores are shared by directory rather than by campaign, because two campaigns
// pointed at one directory are pointed at one SQLite database, and opening it
// twice in one process is how a daemon deadlocks against itself.
func (d *Daemon) storeAt(dir string) (*store.Store, error) {
	if dir == "" {
		dir = filepath.Join(d.opts.DataDir, "store")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if st, ok := d.stores[abs]; ok {
		return st, nil
	}
	st, err := store.Open(abs)
	if err != nil {
		return nil, err
	}
	// A corpus entry whose payload cannot be read is dropped rather than
	// failing the campaign, and this is what stops that being silent. A corpus
	// that quietly shrank is a campaign whose results nobody can explain
	// afterwards (TESTS.md section 9).
	st.OnDropped(func(dg corpus.Digest, derr error) {
		d.bus.Publish(Event{Kind: EventLog, Data: map[string]any{
			"level": "warn",
			"text": fmt.Sprintf("corpus entry %s dropped: %v; "+
				"a corrupt payload is quarantined under %s and the campaign continues",
				dg.Short(), derr, filepath.Join(abs, "blobs", store.QuarantineDir)),
		}})
	})
	d.stores[abs] = st
	return st, nil
}
