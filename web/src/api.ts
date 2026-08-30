// The console's only way to reach the daemon.
//
// Every view goes through this, and this goes through the same HTTP/JSON
// surface `xfuzz` uses (ADR-0011): the console has no privileged path of its
// own, so anything it can do is a route somebody can also curl.

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method, headers: {} };
  if (body !== undefined) {
    init.headers = { "Content-Type": "application/json" };
    init.body = JSON.stringify(body);
  }
  const res = await fetch(path, init);
  const text = await res.text();

  if (!res.ok) {
    // The daemon answers errors as {"error": "..."}, and the message is
    // written for a person. Showing the body when it is not JSON matters more
    // than a tidy failure: an HTML error page here means something is in front
    // of the daemon that should not be.
    let message = text || res.statusText;
    try {
      const parsed = JSON.parse(text) as { error?: string };
      if (parsed.error) message = parsed.error;
    } catch {
      /* not JSON; the raw body is the better message */
    }
    throw new ApiError(res.status, message);
  }
  return (text ? JSON.parse(text) : {}) as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  del: <T>(path: string) => request<T>("DELETE", path),
};

// --- the shapes the views read -------------------------------------------
//
// Hand-written rather than generated, and deliberately partial: each is the
// part of a response the console actually uses. A generated client would carry
// every field of every route and still need this narrowing at each call site.

export interface CampaignStatus {
  name: string;
  state: string;
  reason?: string;
  // A string, not a number: a 64-bit seed does not survive an IEEE double, and
  // a seed shown wrong is worse than a seed not shown (ASR-0008).
  seed: string;
  isolation: string;
  started?: string;
  stopped?: string;
  workers: WorkerStatus[];
  metrics: Metrics;
}

export interface Metrics {
  execs: number;
  execs_per_second: number;
  coverage: number;
  map_density: number;
  corpus_size: number;
  findings: number;
  buckets: number;
  crashes: number;
  timeouts: number;
  stability: number;
  overhead: number;
  // Present only on a stateful campaign; protocol coverage is reported beside
  // code coverage and never folded into it (ADR-0006).
  states?: number;
  transitions?: number;
  illegal_moves?: number;
}

export interface WorkerStatus {
  id: number;
  state: string;
  pid: number;
  restarts: number;
  strategy: string;
  err?: string;
}

export interface Diagnostic {
  name: string;
  severity: string;
  summary: string;
  remedy: string;
}

export interface Finding {
  id: number;
  kind: string;
  signal: number;
  summary: string;
  detail?: string;
  frames?: string[];
  bucket: number;
  triage_state: string;
  disposition?: string;
  diagnosis?: string;
  notes?: string;
  repro_trials: number;
  repro_rate: number;
  original_size: number;
  minimized_size?: number;
  reduction?: number;
  found_at_exec: number;
  created: string;
  reproducer?: string;
}

export interface Bucket {
  id: number;
  strategy: string;
  signature: string;
  kind?: string;
  summary?: string;
  count: number;
  first_seen: string;
}

export interface CorpusEntry {
  digest: string;
  size: number;
  coverage: number;
  favoured: boolean;
  depth: number;
  origin: string;
  parent?: string;
  discovered: string;
  exec_time_ms?: number;
}

export interface StateModel {
  fn: string;
  states: { label: string; count: number; exemplar?: string; variants?: number }[];
  transitions: { from: string; to: string; count: number }[];
  illegal?: { from: string; to: string; count: number }[];
}

export interface SeriesPoint {
  at: string;
  execs: number;
  coverage: number;
  corpus_size: number;
  findings: number;
  execs_per_second: number;
}

export interface Safety {
  isolation: string;
  reasons?: string[];
  scope?: { allow: string[]; deny: string[] };
  sandbox?: Record<string, unknown>;
}

export interface AuditEntry {
  id: number;
  at: string;
  actor: string;
  action: string;
  detail: string;
}

export interface Info {
  daemon: { version: string; pid: number; campaigns: number; data_dir: string; uptime_ms: number };
}

export const service = {
  campaigns: () => api.get<{ campaigns: CampaignStatus[] }>("/v1/campaigns"),
  campaign: (name: string) => api.get<CampaignStatus>(`/v1/campaigns/${enc(name)}`),
  action: (name: string, what: string) =>
    api.post<CampaignStatus>(`/v1/campaigns/${enc(name)}/${what}`),
  health: (name: string) =>
    api.get<{ diagnostics: Diagnostic[] }>(`/v1/campaigns/${enc(name)}/health`),
  history: (name: string) =>
    api.get<{ points: SeriesPoint[] }>(`/v1/campaigns/${enc(name)}/metrics/history`),
  states: (name: string) => api.get<StateModel>(`/v1/campaigns/${enc(name)}/states`),
  findings: (name: string) =>
    api.get<{ findings: Finding[]; count: number }>(`/v1/campaigns/${enc(name)}/findings`),
  finding: (name: string, id: number) =>
    api.get<Finding>(`/v1/campaigns/${enc(name)}/findings/${id}`),
  buckets: (name: string) =>
    api.get<{ buckets: Bucket[] }>(`/v1/campaigns/${enc(name)}/buckets`),
  triage: (name: string, id: number, disposition: string, notes: string) =>
    api.post<Finding>(`/v1/campaigns/${enc(name)}/findings/${id}/triage`, {
      disposition,
      notes,
    }),
  replay: (name: string, id: number) =>
    api.post<{ trials: number; reproduced: number; rate: number; state: string }>(
      `/v1/campaigns/${enc(name)}/findings/${id}/replay`,
    ),
  corpus: (name: string, limit = 200) =>
    api.get<{ entries: CorpusEntry[] }>(`/v1/campaigns/${enc(name)}/corpus?limit=${limit}`),
  corpusEntry: (name: string, digest: string) =>
    api.get<CorpusEntry & { payload: string; tree?: string }>(
      `/v1/campaigns/${enc(name)}/corpus/${digest}`,
    ),
  workers: (name: string) => api.get<{ workers: WorkerStatus[] }>(`/v1/campaigns/${enc(name)}/workers`),
  safety: (name: string) => api.get<Safety>(`/v1/campaigns/${enc(name)}/safety`),
  audit: () => api.get<{ entries: AuditEntry[]; verified: boolean }>("/v1/audit"),
  info: () => api.get<Info>("/v1/info"),
  load: (name: string, store: string) =>
    api.post<CampaignStatus>("/v1/campaigns/load", { name, store }),
  edit: (document: string, set: Record<string, unknown>, unset: string[], name?: string) =>
    api.post<{ document: string; valid: boolean; error?: string }>("/v1/campaigns/edit", {
      document,
      set,
      unset,
      name,
    }),
  validate: (document: string, name: string) =>
    api.post<{ valid: boolean; name: string; warnings?: string[] }>("/v1/campaigns/validate", {
      document,
      name,
    }),
  explain: (document: string, name: string) =>
    api.post<{ text: string; yaml: string }>("/v1/campaigns/explain", { document, name }),
  create: (document: string, name: string) =>
    api.post<CampaignStatus>("/v1/campaigns", { document, name }),
  sample: (grammar: string, count: number, seed: number) =>
    api.post<{
      valid: boolean;
      error?: string;
      root?: string;
      types?: number;
      samples?: { bytes: string; size: number }[];
    }>("/v1/grammar/sample", { grammar, count, seed }),
};

function enc(name: string): string {
  return encodeURIComponent(name);
}
