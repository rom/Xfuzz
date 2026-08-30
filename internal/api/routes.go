package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rom/Xfuzz/internal/daemon"
	"github.com/rom/Xfuzz/internal/metrics"
	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/internal/store"
	"github.com/rom/Xfuzz/internal/version"
	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/corpusio"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/generate"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/rng"
	"github.com/rom/Xfuzz/pkg/schema"
)

// register declares the API surface.
//
// Every capability is defined once here. CLI commands and console views are
// both defined against this list and a parity test asserts neither side has a
// capability the other lacks (ASR-0005) — which only works because the list is
// data rather than a series of registrations.
func (s *Server) register() {
	// CampaignService: validate, create, start, pause, resume, stop, explain.
	s.route(Route{Method: "POST", Path: "/v1/campaigns/validate", Service: ServiceCampaign,
		Name: "campaign.validate", Summary: "Validate a campaign document without creating anything",
		handler: s.campaignValidate})
	s.route(Route{Method: "POST", Path: "/v1/campaigns/explain", Service: ServiceCampaign,
		Name: "campaign.explain", Summary: "Render a campaign's fully resolved configuration",
		handler: s.campaignExplain})
	s.route(Route{Method: "GET", Path: "/v1/campaigns", Service: ServiceCampaign,
		Name: "campaign.list", Summary: "List loaded campaigns", handler: s.campaignList})
	s.route(Route{Method: "POST", Path: "/v1/campaigns", Service: ServiceCampaign,
		Name: "campaign.create", Summary: "Create a campaign from a document", Mutating: true,
		handler: s.campaignCreate})
	s.route(Route{Method: "POST", Path: "/v1/campaigns/edit", Service: ServiceCampaign,
		Name: "campaign.edit", Summary: "Apply edits to a campaign document, preserving its comments",
		handler: s.campaignEdit})
	s.route(Route{Method: "POST", Path: "/v1/campaigns/load", Service: ServiceCampaign,
		Name: "campaign.load", Summary: "Load a campaign that already exists in a store",
		Mutating: true, handler: s.campaignLoad})
	s.route(Route{Method: "GET", Path: "/v1/campaigns/{name}", Service: ServiceCampaign,
		Name: "campaign.get", Summary: "Get one campaign's status", handler: s.campaignGet})
	s.route(Route{Method: "POST", Path: "/v1/campaigns/{name}/start", Service: ServiceCampaign,
		Name: "campaign.start", Summary: "Start a campaign", Mutating: true, handler: s.campaignStart})
	s.route(Route{Method: "POST", Path: "/v1/campaigns/{name}/pause", Service: ServiceCampaign,
		Name: "campaign.pause", Summary: "Pause a campaign", Mutating: true, handler: s.campaignPause})
	s.route(Route{Method: "POST", Path: "/v1/campaigns/{name}/resume", Service: ServiceCampaign,
		Name: "campaign.resume", Summary: "Resume a paused campaign", Mutating: true, handler: s.campaignResume})
	s.route(Route{Method: "POST", Path: "/v1/campaigns/{name}/stop", Service: ServiceCampaign,
		Name: "campaign.stop", Summary: "Stop a campaign", Mutating: true, handler: s.campaignStop})
	s.route(Route{Method: "DELETE", Path: "/v1/campaigns/{name}", Service: ServiceCampaign,
		Name: "campaign.forget", Summary: "Forget a finished campaign, keeping its store", Mutating: true,
		handler: s.campaignForget})

	// MetricsService: live metrics, historical series, health diagnostics.
	s.route(Route{Method: "GET", Path: "/v1/campaigns/{name}/metrics", Service: ServiceMetrics,
		Name: "metrics.get", Summary: "Current counters", handler: s.metricsGet})
	s.route(Route{Method: "GET", Path: "/v1/campaigns/{name}/metrics/history", Service: ServiceMetrics,
		Name: "metrics.history", Summary: "Downsampled historical series", handler: s.metricsHistory})
	s.route(Route{Method: "GET", Path: "/v1/campaigns/{name}/states", Service: ServiceMetrics,
		Name: "metrics.states", Summary: "The protocol state machine the campaign has explored",
		handler: s.metricsStates})
	s.route(Route{Method: "GET", Path: "/v1/campaigns/{name}/health", Service: ServiceMetrics,
		Name: "metrics.health", Summary: "Named health diagnostics", handler: s.metricsHealth})

	// CorpusService: browse, inspect, import, export.
	s.route(Route{Method: "GET", Path: "/v1/campaigns/{name}/corpus", Service: ServiceCorpus,
		Name: "corpus.list", Summary: "List corpus entries", handler: s.corpusList})
	s.route(Route{Method: "GET", Path: "/v1/campaigns/{name}/corpus/{digest}", Service: ServiceCorpus,
		Name: "corpus.get", Summary: "Fetch one corpus entry with its payload", handler: s.corpusGet})
	s.route(Route{Method: "POST", Path: "/v1/campaigns/{name}/corpus/import", Service: ServiceCorpus,
		Name: "corpus.import", Summary: "Import a corpus directory", Mutating: true, handler: s.corpusImport})
	s.route(Route{Method: "POST", Path: "/v1/campaigns/{name}/corpus/export", Service: ServiceCorpus,
		Name: "corpus.export", Summary: "Export the corpus to a directory", Mutating: true, handler: s.corpusExport})

	// FindingService: list, inspect, triage state.
	s.route(Route{Method: "GET", Path: "/v1/campaigns/{name}/findings", Service: ServiceFinding,
		Name: "finding.list", Summary: "List findings", handler: s.findingList})
	s.route(Route{Method: "GET", Path: "/v1/campaigns/{name}/findings/{id}", Service: ServiceFinding,
		Name: "finding.get", Summary: "Fetch one finding with its reproducer", handler: s.findingGet})
	s.route(Route{Method: "GET", Path: "/v1/campaigns/{name}/buckets", Service: ServiceFinding,
		Name: "finding.buckets", Summary: "List finding buckets", handler: s.findingBuckets})
	s.route(Route{Method: "POST", Path: "/v1/campaigns/{name}/findings/{id}/triage", Service: ServiceFinding,
		Name: "finding.triage", Summary: "Record a person's judgement of a finding, and their note",
		Mutating: true, handler: s.findingTriage})
	s.route(Route{Method: "POST", Path: "/v1/campaigns/{name}/findings/{id}/replay", Service: ServiceFinding,
		Name: "finding.replay", Summary: "Re-run a finding's reproducer and record whether it still fails",
		Mutating: true, handler: s.findingReplay})
	s.route(Route{Method: "POST", Path: "/v1/campaigns/{name}/findings/{id}/minimize", Service: ServiceFinding,
		Name: "finding.minimize", Summary: "Reduce a finding's reproducer, preserving its failure class",
		Mutating: true, handler: s.findingMinimize})

	// EventService: the live stream.
	s.route(Route{Method: "GET", Path: "/v1/events", Service: ServiceEvent,
		Name: "event.stream", Summary: "Server-sent event stream, downsampled server-side",
		handler: s.eventStream})

	// AdminService: version, workers, capabilities, audit.
	s.route(Route{Method: "GET", Path: "/v1/info", Service: ServiceAdmin,
		Name: "admin.info", Summary: "Daemon version and status", handler: s.adminInfo})
	s.route(Route{Method: "GET", Path: "/v1/capabilities", Service: ServiceAdmin,
		Name: "admin.capabilities", Summary: "What this host can do, and why anything is missing",
		handler: s.adminCapabilities})
	s.route(Route{Method: "GET", Path: "/v1/campaigns/{name}/workers", Service: ServiceAdmin,
		Name: "admin.workers", Summary: "Worker states", handler: s.adminWorkers})
	s.route(Route{Method: "GET", Path: "/v1/campaigns/{name}/safety", Service: ServiceAdmin,
		Name: "admin.safety", Summary: "Isolation level in force and why it is not higher",
		handler: s.adminSafety})
	s.route(Route{Method: "GET", Path: "/v1/audit", Service: ServiceAdmin,
		Name: "admin.audit", Summary: "Audit log with its chain verification", handler: s.adminAudit})
	s.route(Route{Method: "POST", Path: "/v1/grammar/sample", Service: ServiceCampaign,
		Name: "grammar.sample", Summary: "Generate sample inputs from a grammar",
		handler: s.grammarSample})
	s.route(Route{Method: "GET", Path: "/v1/schema", Service: ServiceAdmin,
		Name: "admin.schema", Summary: "The campaign file JSON Schema", handler: s.adminSchema})
	s.route(Route{Method: "GET", Path: "/v1/openapi.json", Service: ServiceAdmin,
		Name: "admin.openapi", Summary: "This API's OpenAPI description", handler: s.adminOpenAPI})
}

// --- campaign ---------------------------------------------------------------

// CampaignRequest carries a campaign document.
//
// The document rather than a path: a client may be on another machine, and a
// path it names is a path on the daemon's filesystem, which is a request to read
// an arbitrary file. Includes are refused for the same reason (pkg/campaign).
type CampaignRequest struct {
	// Document is the campaign file's contents.
	Document string `json:"document"`

	// Name identifies the document in error messages.
	Name string `json:"name,omitempty"`

	// Profiles are the overlays to apply.
	Profiles []string `json:"profiles,omitempty"`
}

// The seed is deliberately not a field here. It was one, as a bare JSON
// number, and nothing read it: a client that pinned a seed to get a repeatable
// campaign got a random one and no error. It belongs in the document, where
// ADR-0016 puts everything that decides what runs and where `xfuzz explain`
// already shows it, rather than in a request field that makes the artefact
// incomplete — and where a 64-bit value would have to survive an IEEE double.

// campaignInvalid carries a validation failure with its list intact.
type campaignInvalid struct {
	headline string
	details  []string
}

func (e *campaignInvalid) Error() string { return e.headline }

func asInvalid(err error) error {
	var inv *campaign.Invalid
	if !errors.As(err, &inv) {
		return err
	}
	details := make([]string, 0, len(inv.Problems))
	for _, p := range inv.Problems {
		details = append(details, p.String())
	}
	return &campaignInvalid{
		headline: fmt.Sprintf("the campaign has %d problem%s", len(inv.Problems), plural(len(inv.Problems))),
		details:  details,
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func (s *Server) resolve(r *http.Request) (*campaign.Resolved, *CampaignRequest, error) {
	var req CampaignRequest
	if err := decodeBody(r, &req); err != nil {
		// The seed used to be a field here and was never read, so a client that
		// pinned one got a random campaign and no complaint. Now that the field
		// is gone the decoder refuses it, which is better — but "unknown field
		// seed" tells somebody their request is wrong without telling them what
		// to do, and the answer is one line in the document they are already
		// sending.
		if strings.Contains(err.Error(), `unknown field "seed"`) {
			return nil, nil, fmt.Errorf(
				"the seed is not a request field: put `seed: <number>` in the campaign " +
					"document instead, where `xfuzz explain` reports it and the file " +
					"stays a complete record of what ran")
		}
		return nil, nil, err
	}
	if req.Name == "" {
		req.Name = "(request body)"
	}
	cfg, err := campaign.Parse([]byte(req.Document), req.Name, req.Profiles...)
	if err != nil {
		return nil, &req, asInvalid(err)
	}
	return cfg, &req, nil
}

// ValidateResponse is what validation reports.
type ValidateResponse struct {
	Valid    bool     `json:"valid"`
	Name     string   `json:"name,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

func (s *Server) campaignValidate(w http.ResponseWriter, r *http.Request) {
	cfg, _, err := s.resolve(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	resp := ValidateResponse{Valid: true, Name: cfg.Name}
	if cfg.Stop.IsZero() {
		// Not an error — an interactive campaign that runs until interrupted is
		// legitimate — but a CI user needs to know before their pipeline hangs.
		resp.Warnings = append(resp.Warnings,
			"no termination condition: this campaign runs until interrupted")
	}
	writeJSON(w, http.StatusOK, resp)
}

// ExplainResponse is the fully resolved configuration.
type ExplainResponse struct {
	Name     string   `json:"name"`
	Profiles []string `json:"profiles,omitempty"`

	// Text is the human-readable rendering, with defaults marked.
	Text string `json:"text"`

	// YAML is the resolved configuration as a campaign file, which runs the
	// same campaign — that is how a run gets pinned to an artefact after the
	// fact.
	YAML string `json:"yaml"`
}

func (s *Server) campaignExplain(w http.ResponseWriter, r *http.Request) {
	cfg, _, err := s.resolve(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	y, err := cfg.YAML()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, ExplainResponse{
		Name: cfg.Name, Profiles: cfg.Profiles, Text: cfg.ExplainString(), YAML: string(y),
	})
}

func (s *Server) campaignList(w http.ResponseWriter, r *http.Request) {
	cs := s.daemon.Campaigns()
	out := make([]daemon.Status, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Status())
	}
	writeJSON(w, http.StatusOK, map[string]any{"campaigns": out})
}

// grammarSample generates inputs from a grammar the client is writing.
//
// The workbench's whole purpose (ADR-0011): a grammar is a program, and the
// only way to know what one produces is to look at what it produces. Sampling
// is pure — it reads a document and returns bytes — so it needs no campaign, no
// store and no target, which is what lets somebody write a grammar before there
// is anything to fuzz with it.
//
// Seeded explicitly, so that the same grammar and the same seed give the same
// samples: a workbench whose output changed every time it was asked would make
// "did my edit change anything" unanswerable.
func (s *Server) grammarSample(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Grammar string `json:"grammar"`
		Count   int    `json:"count,omitempty"`
		Seed    Seed64 `json:"seed,omitempty"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Count <= 0 {
		req.Count = defaultGrammarSamples
	}
	if req.Count > maxGrammarSamples {
		req.Count = maxGrammarSamples
	}

	sch, err := schema.Parse([]byte(req.Grammar), "grammar")
	if err != nil {
		// A grammar under construction does not parse most of the time, so
		// this is the workbench's ordinary answer rather than a failure: the
		// message is the thing the author needs.
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error()})
		return
	}

	gen := generate.New(sch)
	rand := rng.Derive(uint64(req.Seed), 0, rng.StreamGenerate)
	arena := ir.NewArena()
	samples := make([]sampleView, 0, req.Count)
	for i := 0; i < req.Count; i++ {
		arena.Reset()
		node, gerr := gen.Generate(arena, rand)
		if gerr != nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"valid": false, "error": gerr.Error(), "samples": samples,
			})
			return
		}
		payload := ir.Encode(node)
		samples = append(samples, sampleView{Bytes: payload, Size: len(payload)})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"valid": true, "root": sch.Root, "types": len(sch.Types), "samples": samples,
	})
}

// sampleView is one generated input. The size travels with it because a
// workbench's first question about a grammar is usually how big it goes.
type sampleView struct {
	Bytes []byte `json:"bytes"`
	Size  int    `json:"size"`
}

// How many samples a workbench gets by default, and the most it may ask for.
// Bounded because generation is unbounded work a client can request.
const (
	defaultGrammarSamples = 8
	maxGrammarSamples     = 256
)

// campaignEdit applies field edits to a campaign document and hands it back.
//
// Not a store, and not a launch: the console edits campaigns by editing their
// file (ADR-0011), so what this returns is the file, for the client to save or
// to submit like any other. The daemon never becomes the place a campaign
// definition lives, which is what keeps a console launch equivalent to
// committing the file and running the CLI.
//
// The edited document is resolved before it is returned, so the answer says
// whether it is a campaign as well as what it now reads — and it is resolved by
// the same code path a file is, rather than by a second implementation that
// could come to disagree with it.
func (s *Server) campaignEdit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Document string         `json:"document"`
		Name     string         `json:"name,omitempty"`
		Set      map[string]any `json:"set,omitempty"`
		Unset    []string       `json:"unset,omitempty"`
		Profiles []string       `json:"profiles,omitempty"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	doc, err := campaign.ParseDocument([]byte(req.Document))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	for _, path := range sortedKeys(req.Set) {
		if err := doc.Set(path, req.Set[path]); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	for _, path := range req.Unset {
		doc.Unset(path)
	}

	out, err := doc.Bytes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	name := req.Name
	if name == "" {
		name = "edited campaign"
	}
	resp := map[string]any{"document": string(out), "valid": true}
	if _, rerr := doc.Resolved(name, req.Profiles...); rerr != nil {
		// The document still comes back. An editor that threw away the text
		// because it does not yet validate would be an editor nobody could
		// make two changes in.
		resp["valid"] = false
		resp["error"] = rerr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// sortedKeys orders the edits so that applying the same set twice produces the
// same document, whatever order the client's JSON happened to serialise in.
func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// campaignLoad opens a campaign the daemon does not hold, from its store.
//
// The store's own record of what ran, rather than a document supplied here: a
// load that took a configuration would be a create wearing another name, and
// the point is to reach a finished campaign when the file is gone.
func (s *Server) campaignLoad(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name  string `json:"name"`
		Store string `json:"store,omitempty"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	c, err := s.daemon.Load(r.Context(), req.Store, req.Name)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, c.Status())
}

func (s *Server) campaignCreate(w http.ResponseWriter, r *http.Request) {
	cfg, _, err := s.resolve(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	c, err := s.daemon.Create(r.Context(), cfg)
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusCreated, c.Status())
}

func (s *Server) campaign(r *http.Request) (*daemon.Campaign, error) {
	return s.daemon.Campaign(r.PathValue("name"))
}

func (s *Server) campaignGet(w http.ResponseWriter, r *http.Request) {
	c, err := s.campaign(r)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, c.Status())
}

func (s *Server) campaignStart(w http.ResponseWriter, r *http.Request) {
	s.act(w, r, func(ctx context.Context, c *daemon.Campaign) error { return c.Start(ctx) })
}

func (s *Server) campaignPause(w http.ResponseWriter, r *http.Request) {
	s.act(w, r, func(ctx context.Context, c *daemon.Campaign) error { return c.Pause(ctx) })
}

func (s *Server) campaignResume(w http.ResponseWriter, r *http.Request) {
	s.act(w, r, func(ctx context.Context, c *daemon.Campaign) error { return c.Resume(ctx) })
}

func (s *Server) campaignStop(w http.ResponseWriter, r *http.Request) {
	reason := r.URL.Query().Get("reason")
	s.act(w, r, func(ctx context.Context, c *daemon.Campaign) error { return c.Stop(ctx, reason) })
}

func (s *Server) act(w http.ResponseWriter, r *http.Request, fn func(context.Context, *daemon.Campaign) error) {
	c, err := s.campaign(r)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	// The daemon's context, not the request's: a campaign must outlive the
	// client that started it (ADR-0003), and using r.Context() here would stop
	// it the moment the CLI exited.
	if err := fn(context.WithoutCancel(r.Context()), c); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, c.Status())
}

func (s *Server) campaignForget(w http.ResponseWriter, r *http.Request) {
	if err := s.daemon.Forget(r.PathValue("name")); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"forgotten": r.PathValue("name")})
}

// --- metrics ----------------------------------------------------------------

func (s *Server) metricsGet(w http.ResponseWriter, r *http.Request) {
	c, err := s.campaign(r)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, c.Status().Metrics)
}

func (s *Server) metricsHistory(w http.ResponseWriter, r *http.Request) {
	c, err := s.campaign(r)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"points": c.Metrics().History()})
}

func (s *Server) metricsHealth(w http.ResponseWriter, r *http.Request) {
	c, err := s.campaign(r)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	st := c.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"diagnostics": st.Health,
		"worst":       metrics.Worst(st.Health).String(),
	})
}

// --- corpus -----------------------------------------------------------------

func (s *Server) corpusList(w http.ResponseWriter, r *http.Request) {
	c, st, err := s.campaignStore(r)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	q := store.TestcaseQuery{
		Order:        r.URL.Query().Get("order"),
		FavouredOnly: r.URL.Query().Get("favoured") == "true",
		Limit:        intParam(r, "limit", 200),
	}
	entries, err := st.Testcases(r.Context(), c.ID(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]corpusEntryView, 0, len(entries))
	for _, tc := range entries {
		out = append(out, viewOf(tc))
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out, "count": len(out)})
}

func (s *Server) corpusGet(w http.ResponseWriter, r *http.Request) {
	c, st, err := s.campaignStore(r)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	d, err := parseDigest(r.PathValue("digest"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	tc, err := st.Testcase(r.Context(), c.ID(), d)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	v := viewOf(tc)
	v.Payload = tc.Bytes
	writeJSON(w, http.StatusOK, v)
}

// ImportRequest asks the daemon to read a corpus directory.
type ImportRequest struct {
	Dir    string `json:"dir"`
	Format string `json:"format,omitempty"`
}

func (s *Server) corpusImport(w http.ResponseWriter, r *http.Request) {
	c, st, err := s.campaignStore(r)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	var req ImportRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	format, err := corpusio.ParseFormat(req.Format)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	rep, err := st.ImportCorpus(r.Context(), c.ID(), req.Dir, corpusio.ImportOptions{Format: format})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// ExportRequest asks the daemon to write the corpus out.
type ExportRequest struct {
	Dir          string `json:"dir"`
	Format       string `json:"format,omitempty"`
	FavouredOnly bool   `json:"favoured_only,omitempty"`
	Overwrite    bool   `json:"overwrite,omitempty"`
}

func (s *Server) corpusExport(w http.ResponseWriter, r *http.Request) {
	c, st, err := s.campaignStore(r)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	var req ExportRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	format, err := corpusio.ParseFormat(req.Format)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	rep, err := st.ExportCorpus(r.Context(), c.ID(), req.Dir, corpusio.ExportOptions{
		Format: format, FavouredOnly: req.FavouredOnly, Overwrite: req.Overwrite,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// --- findings ---------------------------------------------------------------

func (s *Server) findingList(w http.ResponseWriter, r *http.Request) {
	c, st, err := s.campaignStore(r)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	var fs []*store.Finding
	if state := r.URL.Query().Get("state"); state != "" {
		fs, err = st.FindingsInState(r.Context(), c.ID(), state)
	} else {
		fs, err = st.Findings(r.Context(), c.ID())
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]findingView, 0, len(fs))
	for _, f := range fs {
		out = append(out, findingViewOf(f))
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": out, "count": len(out)})
}

func (s *Server) findingGet(w http.ResponseWriter, r *http.Request) {
	_, st, err := s.campaignStore(r)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("%q is not a finding id", r.PathValue("id")))
		return
	}
	f, err := st.Finding(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	v := findingViewOf(f)
	// The reproducer, which is the point of asking for one finding rather than
	// the list.
	digest := f.Digest
	if !f.Minimized.IsZero() {
		digest = f.Minimized
	}
	if payload, err := st.Blobs().Get(digest); err == nil {
		v.Reproducer = payload
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) findingBuckets(w http.ResponseWriter, r *http.Request) {
	c, st, err := s.campaignStore(r)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	strategy := r.URL.Query().Get("strategy")
	if strategy == "" {
		strategy = c.Config.Triage.Strategy
	}
	bs, err := st.Buckets(r.Context(), c.ID(), strategy)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	views := bucketViewsOf(bs)
	writeJSON(w, http.StatusOK, map[string]any{"strategy": strategy, "buckets": views, "count": len(views)})
}

// TriageRequest bounds an on-demand triage run.
type TriageRequest struct {
	// Trials is how many times replay runs the reproducer. Zero uses the
	// campaign's own triage.trials.
	Trials int `json:"trials,omitempty"`

	// Budget is how many executions minimisation may spend. Zero uses the
	// campaign's own triage.minimize_budget.
	Budget int `json:"budget,omitempty"`
}

// findingTriage records a judgement and a note.
//
// The judgement is a person's and the triage state is the machine's, so this
// writes only the former: a console that could set "verified" would be
// asserting something it has not checked.
func (s *Server) findingTriage(w http.ResponseWriter, r *http.Request) {
	c, id, ok := s.findingTarget(w, r)
	if !ok {
		return
	}
	var req struct {
		Disposition string `json:"disposition"`
		Notes       string `json:"notes"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	f, err := c.SetDisposition(r.Context(), id, req.Disposition, req.Notes)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, findingViewOf(f))
}

func (s *Server) findingReplay(w http.ResponseWriter, r *http.Request) {
	c, id, ok := s.findingTarget(w, r)
	if !ok {
		return
	}
	var req TriageRequest
	_ = decodeOptional(r, &req)

	rep, err := c.Replay(r.Context(), id, req.Trials)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) findingMinimize(w http.ResponseWriter, r *http.Request) {
	c, id, ok := s.findingTarget(w, r)
	if !ok {
		return
	}
	var req TriageRequest
	_ = decodeOptional(r, &req)

	rep, err := c.Minimize(r.Context(), id, req.Budget)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// findingTarget resolves the campaign and finding a request names, answering
// the client itself when either is wrong.
func (s *Server) findingTarget(w http.ResponseWriter, r *http.Request) (*daemon.Campaign, int64, bool) {
	c, err := s.daemon.Campaign(r.PathValue("name"))
	if err != nil {
		writeError(w, statusFor(err), err)
		return nil, 0, false
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("%q is not a finding id", r.PathValue("id")))
		return nil, 0, false
	}
	return c, id, true
}

// --- admin ------------------------------------------------------------------

func (s *Server) adminInfo(w http.ResponseWriter, r *http.Request) {
	info := s.daemon.Info()
	writeJSON(w, http.StatusOK, map[string]any{"daemon": info, "api": APIVersion})
}

func (s *Server) adminWorkers(w http.ResponseWriter, r *http.Request) {
	c, err := s.campaign(r)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"workers": c.Workers()})
}

func (s *Server) adminSafety(w http.ResponseWriter, r *http.Request) {
	c, err := s.campaign(r)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	allowed, denied := c.Scope().Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"isolation": c.Sandbox().Level().String(),
		// The whole explanation, not just the level: a campaign refused for
		// insufficient isolation has to be told what is missing, and the remedy
		// is usually one line of host configuration.
		"explanation": c.Sandbox().Explain(),
		"scope":       c.Scope().Summary(),
		"connections": map[string]uint64{"allowed": allowed, "denied": denied},
	})
}

func (s *Server) adminAudit(w http.ResponseWriter, r *http.Request) {
	cs := s.daemon.Campaigns()
	if len(cs) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"entries": []any{}, "verified": 0})
		return
	}
	st, err := s.storeOf(cs[0])
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	entries, err := st.AuditLog(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	verified, verr := st.VerifyAudit(r.Context())
	resp := map[string]any{"entries": entries, "verified": verified, "intact": verr == nil}
	if verr != nil {
		// Reported in the body rather than as an error status: the log is
		// readable and the tampering is the thing the caller asked about.
		resp["tampering"] = verr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) adminSchema(w http.ResponseWriter, r *http.Request) {
	b, err := campaign.JSONSchema()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/schema+json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func (s *Server) adminOpenAPI(w http.ResponseWriter, r *http.Request) {
	b, err := s.OpenAPI()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// --- helpers ----------------------------------------------------------------

func (s *Server) campaignStore(r *http.Request) (*daemon.Campaign, *store.Store, error) {
	c, err := s.campaign(r)
	if err != nil {
		return nil, nil, err
	}
	st, err := s.storeOf(c)
	return c, st, err
}

func intParam(r *http.Request, name string, def int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func durationOrDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// --- capabilities -----------------------------------------------------------

// Capability is one thing the host can or cannot do.
//
// Available and a reason together, because "not available" with no reason is a
// message nobody can act on — which is the whole point of the doctor command
// (ASR-0006, ADR-0002).
type Capability struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Detail    string `json:"detail,omitempty"`
}

// CapabilitiesResponse describes what this host can do.
type CapabilitiesResponse struct {
	Platform     string       `json:"platform"`
	Version      version.Info `json:"version"`
	Isolation    string       `json:"isolation"`
	Explanation  string       `json:"explanation"`
	Capabilities []Capability `json:"capabilities"`
	Notes        []string     `json:"notes,omitempty"`
}

// adminCapabilities reports what the running host provides.
//
// Probed rather than assumed: a build that contains the code for a mechanism
// tells you nothing about whether the kernel, the filesystem, or the container
// this daemon runs in will let it work. Everything here is measured on the host
// answering the request.
func (s *Server) adminCapabilities(w http.ResponseWriter, r *http.Request) {
	sandbox := &safety.Sandbox{}
	defer sandbox.Close()
	level, caps := sandbox.Probe()

	cs := []Capability{
		{Name: "user-namespace", Available: caps.UserNS,
			Detail: "how an unprivileged fuzzer gets the other namespaces at all"},
		{Name: "mount-namespace", Available: caps.MountNS,
			Detail: "a read-only root, so a target cannot write to the corpus"},
		{Name: "pid-namespace", Available: caps.PIDNS,
			Detail: "a target cannot see or signal anything outside its own run"},
		{Name: "network-namespace", Available: caps.NetNS,
			Detail: "a target reaches nothing unless the campaign allows it"},
		{Name: "seccomp", Available: caps.Seccomp,
			Detail: "the syscall denylist (ADR-0022)"},
		{Name: "rlimits", Available: caps.Rlimits,
			Detail: "memory, process and file-size ceilings"},
		{Name: "cgroups", Available: caps.Cgroups != platform.CgroupNone,
			Detail: cgroupDetail(caps.Cgroups)},
		{Name: "process-groups", Available: platform.ProcessGroupsSupported(),
			Detail: "killing a target's whole tree rather than leaking its children"},
		{Name: "shared-memory", Available: platform.NewSharedMemoryProvider().Available(),
			Detail: "the coverage map; without it only black-box campaigns are possible"},
	}
	cs = append(cs, foundTool(safety.HelperName,
		"installs limits and the denylist in the process that becomes the target"))
	cs = append(cs, foundTool(daemon.WorkerBinaryName, "runs a campaign's workers"))
	cs = append(cs, foundTool("clang", "builds instrumented targets through xfuzz-cc"))

	// The three things a new install gets wrong that the mechanism checks
	// above do not cover. Each is something someone hits on their first
	// campaign and cannot diagnose from the failure it produces.
	cs = append(cs,
		writableDir(s.daemon.DataDir()),
		spawnWorks(r.Context()),
		Capability{Name: "web-console", Available: ConsoleBuilt(),
			Detail: consoleDetail()},
	)

	writeJSON(w, http.StatusOK, CapabilitiesResponse{
		Platform:     runtime.GOOS + "/" + runtime.GOARCH,
		Version:      version.Get(),
		Isolation:    level.String(),
		Explanation:  sandbox.Explain(),
		Capabilities: cs,
		Notes:        caps.Notes,
	})
}

func cgroupDetail(mode string) string {
	switch mode {
	case platform.CgroupV2:
		return "memory and process limits applied at clone time, so a target cannot fork out of them"
	case platform.CgroupV1:
		return "v1 only: a process is added after it exists, so a target that forks immediately " +
			"can escape the limit — which is why v1 does not count towards strong isolation"
	default:
		return "no cgroup interface: memory limits rest on rlimits alone"
	}
}

// foundTool reports whether a helper binary can be found, and says where the
// lookup goes so that a missing one is fixable rather than mysterious.
func foundTool(name, purpose string) Capability {
	path, err := safety.FindTool(name)
	if err != nil {
		return Capability{Name: name, Available: false,
			Detail: purpose + "; not found beside the running binary or on PATH"}
	}
	return Capability{Name: name, Available: true, Detail: purpose + "; " + path}
}

// metricsStates serves the campaign's protocol state machine.
func (s *Server) metricsStates(w http.ResponseWriter, r *http.Request) {
	c, err := s.campaign(r)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	m := c.StateModel()
	writeJSON(w, http.StatusOK, map[string]any{
		"fn":          m.Fn,
		"states":      m.States,
		"transitions": m.Transitions,
		"illegal":     m.Illegal,
		"count":       len(m.States),
	})
}

// writableDir reports whether the daemon can write where it keeps everything.
//
// A data directory that is read-only, or on a filesystem with nothing left,
// fails a campaign at its first corpus write — several minutes in, with an
// error about a blob rather than about the directory.
func writableDir(dir string) Capability {
	c := Capability{Name: "data-directory", Detail: dir}
	if dir == "" {
		c.Detail = "no data directory is configured"
		return c
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		c.Detail = dir + "; cannot be created: " + err.Error()
		return c
	}
	probe := filepath.Join(dir, ".xfuzz-doctor")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		c.Detail = dir + "; not writable: " + err.Error()
		return c
	}
	os.Remove(probe)
	c.Available = true
	c.Detail = dir + "; stores, sockets and worker working directories live here"
	return c
}

// spawnWorks launches one confined process and waits for it.
//
// The single most useful check here, because it exercises the whole path a
// campaign depends on — the spawner, the sandbox, the helper where one is used,
// the process group — rather than the mechanisms it is built from. A host where
// every capability above is present and this fails is a host where no campaign
// will run, and knowing that in a second beats discovering it in a campaign.
//
// The daemon's own binary is the subject, because it is the one executable that
// certainly exists, certainly runs on this platform, and certainly exits.
func spawnWorks(ctx context.Context) Capability {
	c := Capability{Name: "execution"}

	self, err := os.Executable()
	if err != nil {
		c.Detail = "cannot find this daemon's own binary to test with: " + err.Error()
		return c
	}
	// An explicit sandbox rather than the spawner's lazy default, so that this
	// check owns it and can release it. A namespace or a cgroup left behind by
	// a diagnostic would be a leak on every call to `xfuzz doctor`.
	sb := &safety.Sandbox{}
	defer sb.Close()

	sp := safety.NewSpawner()
	sp.Sandbox = sb
	sp.DefaultTimeout = 10 * time.Second

	res, err := sp.Run(ctx, executor.ProcSpec{
		Path: self, Args: []string{self, "--version"},
		CaptureOutput: true, Timeout: 10 * time.Second,
	})
	switch {
	case err != nil:
		c.Detail = "a confined process could not be launched: " + err.Error()
	case res.TimedOut:
		c.Detail = "a confined process was launched and did not exit within ten seconds"
	case res.ExitCode != 0 || res.Signal != 0:
		c.Detail = fmt.Sprintf("a confined process exited %d (signal %d): %s",
			res.ExitCode, res.Signal, strings.TrimSpace(string(res.Stderr)))
	default:
		c.Available = true
		c.Detail = fmt.Sprintf("a confined process ran and exited cleanly in %s", res.Duration.Round(time.Millisecond))
	}
	return c
}

// consoleDetail says what a build without the console means and how to get one.
func consoleDetail() string {
	if ConsoleBuilt() {
		return "this daemon serves the web console on its own listener"
	}
	return "this daemon was built without the console; rebuild with `make build-console` " +
		"or use the CLI, which reaches every route the console does"
}
