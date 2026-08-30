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

  const raw = f.reproducer ? decodeBase64(f.reproducer) : new Uint8Array();
  const judged = el("div");

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
      el("pre", null, raw.length ? hex(raw) : "no reproducer stored"),
    ),
  );

  replace(judged, judgementForm(name, f));
}

// judgementForm records what a person decided.
//
// Separate from the triage state above it, and shown as such: the machine says
// whether it reproduces, and this says what somebody concluded. Re-running
// triage rewrites the first and never the second.
function judgementForm(name: string, f: Finding): HTMLElement {
  const select = el("select", null,
    ...DISPOSITIONS.map((d) =>
      el("option", { value: d, selected: (f.disposition ?? "") === d }, d || "pending"),
    ),
  );
  const notes = el("input", { type: "text", placeholder: "why", value: f.notes ?? "" });
  const status = el("span", { class: "muted" });

  const save = async () => {
    try {
      const updated = await service.triage(name, f.id, select.value, notes.value);
      replace(status, `saved — ${updated.disposition || "pending"}`);
    } catch (e) {
      replace(status, el("span", { class: "err" }, e instanceof Error ? e.message : String(e)));
    }
  };
  const replay = async () => {
    replace(status, "replaying…");
    try {
      const r = await service.replay(name, f.id);
      replace(status, `${r.reproduced} of ${r.trials} reproduced — ${r.state}`);
    } catch (e) {
      replace(status, el("span", { class: "err" }, e instanceof Error ? e.message : String(e)));
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
      status,
    ),
  );
}
