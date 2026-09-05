// Findings: the view ASR-0011 puts at the centre of the product.
//
// Bucketed, because a campaign that reports one bug ten thousand times has
// reported nothing. And judgeable, because triage is a person's work and the
// machine's verdict is only half of it.

import { service, type Bucket, type Finding } from "../api";
import { el, replace, table } from "../dom";
import { bytes, count, decodeBase64, hex, percent } from "../format";
import { go, href } from "../router";
import { badge, empty, error, panel } from "./common";

const DISPOSITIONS = ["", "confirmed", "duplicate", "wontfix", "invalid"];

export async function findingsView(root: HTMLElement, name: string): Promise<void> {
  let findings: Finding[];
  let buckets: Bucket[];
  try {
    [findings, buckets] = await Promise.all([
      service.findings(name).then((r) => r.findings ?? []),
      service.buckets(name).then((r) => r.buckets ?? []).catch(() => []),
    ]);
  } catch (e) {
    replace(root, error(e instanceof Error ? e.message : String(e)));
    return;
  }

  replace(
    root,
    el(
      "header",
      { class: "view" },
      el("h2", null, "Findings"),
      el("span", { class: "sub" }, el("a", { href: href("campaign", name) }, name)),
      el("span", { class: "sub" }, `${findings.length} finding(s) in ${buckets.length} bucket(s)`),
    ),
  );

  if (!findings.length) {
    root.appendChild(empty("No findings yet."));
    return;
  }

  if (buckets.length) {
    root.appendChild(
      panel(
        "buckets",
        table(
          ["Signature", "Kind", "Summary", "Count", "Strategy"],
          buckets,
          (b) => [
            el("span", { class: "mono" }, b.signature),
            b.kind ?? "",
            b.summary ?? "",
            el("span", { class: "num" }, String(b.count)),
            b.strategy,
          ],
        ),
      ),
    );
  }

  root.appendChild(
    panel(
      "findings",
      table(
        ["ID", "Kind", "Summary", "Triage", "Judged", "Repro", "Size"],
        findings,
        (f) => [
          String(f.id),
          f.kind,
          f.summary,
          badge(f.triage_state),
          f.disposition ? badge(f.disposition, "on") : el("span", { class: "muted" }, "—"),
          f.repro_trials
            ? `${percent(f.repro_rate)} of ${f.repro_trials}`
            : el("span", { class: "muted" }, "not checked"),
          bytes(f.minimized_size || f.original_size),
        ],
        (f) => go("finding", name, String(f.id)),
      ),
    ),
  );
}

export async function findingView(root: HTMLElement, name: string, id: number): Promise<void> {
  let f: Finding;
  try {
    f = await service.finding(name, id);
  } catch (e) {
    replace(root, error(e instanceof Error ? e.message : String(e)));
    return;
  }

  const judged = el("div");
  const details = el("div");
  const draw = (finding: Finding) => replace(details, ...detailPanels(finding));

  replace(
    root,
    el(
      "header",
      { class: "view" },
      el("h2", null, `Finding ${f.id}`),
      badge(f.kind, f.kind === "crash" ? "bad" : undefined),
      el("span", { class: "sub" }, f.summary),
      el("span", { class: "sub" }, el("a", { href: href("findings", name) }, "all findings")),
    ),
    judged,
    details,
  );
  draw(f);

  // Minimisation changes what the panels below show — the sizes, the state,
  // the reproducer itself — so they are redrawn from a fresh read, while the
  // judgement form above keeps its own report of what just happened.
  const refresh = async () => {
    const fresh = await service.finding(name, id).catch(() => null);
    if (fresh) draw(fresh);
  };
  replace(judged, judgementForm(name, f, refresh));
}

// detailPanels is everything the machine knows about a finding.
function detailPanels(f: Finding): (HTMLElement | null)[] {
  const raw = f.reproducer ? decodeBase64(f.reproducer) : new Uint8Array();
  return [
    f.detail
      ? panel("what the target said", el("pre", { class: "wrap" }, f.detail))
      : null,
    f.frames?.length
      ? panel("frames", el("pre", null, f.frames.join("\n")))
      : null,
    panel(
      "triage",
      table(
        ["", ""],
        [
          ["state", f.triage_state] as const,
          ["reproduced", f.repro_trials ? `${f.repro_rate * f.repro_trials} of ${f.repro_trials} (${percent(f.repro_rate)})` : "not checked"] as const,
          ["diagnosis", f.diagnosis ?? "—"] as const,
          ["original size", bytes(f.original_size)] as const,
          ["minimised", f.minimized_size ? `${bytes(f.minimized_size)} (${percent(f.reduction ?? 0)} smaller)` : "—"] as const,
          ["found at", `${count(f.found_at_exec)} executions`] as const,
        ],
        (r) => [el("span", { class: "muted" }, r[0]), r[1]],
      ),
    ),
    panel(
      `reproducer (${bytes(raw.length)})`,
      // The bytes as a file, because the hex is for reading and a bug report
      // wants the input itself — and because the hex stops at 512 bytes.
      raw.length
        ? el("div", { class: "row" }, el("a", { href: blobURL(raw), download: `finding-${f.id}.bin` }, "download"))
        : null,
      el("pre", null, raw.length ? hex(raw) : "no reproducer stored"),
    ),
  ];
}

/** blobURL makes bytes addressable by a link, so the browser can save them. */
function blobURL(raw: Uint8Array<ArrayBuffer>): string {
  return URL.createObjectURL(new Blob([raw], { type: "application/octet-stream" }));
}

// judgementForm records what a person decided.
//
// Separate from the triage state above it, and shown as such: the machine says
// whether it reproduces, and this says what somebody concluded. Re-running
// triage rewrites the first and never the second.
function judgementForm(name: string, f: Finding, refresh: () => Promise<void>): HTMLElement {
  const select = el("select", null,
    ...DISPOSITIONS.map((d) =>
      el("option", { value: d, selected: (f.disposition ?? "") === d }, d || "pending"),
    ),
  );
  const notes = el("input", { type: "text", placeholder: "why", value: f.notes ?? "" });
  const status = el("span", { class: "muted" });
  const failed = (e: unknown) =>
    replace(status, el("span", { class: "err" }, e instanceof Error ? e.message : String(e)));

  const save = async () => {
    try {
      const updated = await service.triage(name, f.id, select.value, notes.value);
      replace(status, `saved — ${updated.disposition || "pending"}`);
    } catch (e) {
      failed(e);
    }
  };
  const replay = async () => {
    replace(status, "replaying…");
    try {
      const r = await service.replay(name, f.id);
      replace(status, `${r.reproduced} of ${r.trials} reproduced — ${r.state}`);
    } catch (e) {
      failed(e);
    }
  };
  // Minimise starts from the input as the engine found it, not from the last
  // result, so asking again is asking for a better job; the daemon spends the
  // campaign's own triage.minimize_budget on it.
  const minimize = async () => {
    replace(status, "minimising…");
    try {
      const r = await service.minimize(name, f.id);
      replace(
        status,
        `${bytes(r.original_size)} to ${bytes(r.minimized_size)} (${percent(r.reduction)} smaller) in ${count(r.runs)} runs — ${r.triage_state}`,
      );
      await refresh();
    } catch (e) {
      failed(e);
    }
  };

  return panel(
    "judgement",
    el(
      "div",
      { class: "row" },
      select,
      notes,
      el("button", { class: "primary", onclick: save }, "Save"),
      el("button", { onclick: replay }, "Replay"),
      el("button", { onclick: minimize }, "Minimise"),
      status,
    ),
  );
}
