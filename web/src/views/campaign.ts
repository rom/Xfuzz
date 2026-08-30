// One campaign, live.
//
// Everything here comes off the event stream once loaded: the first render is
// a fetch so the page is complete on arrival, and after that the stream keeps
// it current without the console polling a running engine.

import { service, type CampaignStatus, type Diagnostic, type SeriesPoint } from "../api";
import { el, replace, table } from "../dom";
import type { Live } from "../events";
import { href } from "../router";
import { diagnostics, error, metricStats, panel, sparkline, stateBadge } from "./common";
import { summaryLine } from "./campaigns";

export async function campaignView(root: HTMLElement, name: string, live: Live): Promise<void> {
  let status: CampaignStatus;
  let health: Diagnostic[] = [];
  let history: SeriesPoint[] = [];
  try {
    status = await service.campaign(name);
    [health, history] = await Promise.all([
      service.health(name).then((h) => h.diagnostics ?? []).catch(() => []),
      service.history(name).then((h) => h.points ?? []).catch(() => []),
    ]);
  } catch (e) {
    replace(root, error(e instanceof Error ? e.message : String(e)));
    return;
  }

  const stats = metricStats(status);
  const workers = el("div");
  const health$ = el("div");

  replace(
    root,
    el(
      "header",
      { class: "view" },
      el("h2", null, name),
      stateBadge(status.state),
      summaryLine(status),
      el("span", { class: "sub" }, el("a", { href: href("findings", name) }, "findings"), " · ",
        el("a", { href: href("coverage", name) }, "coverage"), " · ",
        el("a", { href: href("corpus", name) }, "corpus"), " · ",
        el("a", { href: href("safety", name) }, "safety")),
    ),
    stats,
    health$,
    history.length > 1 ? panel("coverage over time", sparkline(history, (p) => p.coverage, "edges")) : null,
    history.length > 1
      ? panel("throughput over time", sparkline(history, (p) => p.execs_per_second, "executions per second"))
      : null,
    workers,
  );

  const drawHealth = (list: Diagnostic[]) => replace(health$, diagnostics(list));
  const drawWorkers = (c: CampaignStatus) =>
    replace(
      workers,
      panel(
        "workers",
        c.workers?.length
          ? table(
              ["ID", "State", "PID", "Restarts", "Strategy", "Error"],
              c.workers,
              (w) => [
                String(w.id),
                stateBadge(w.state),
                w.pid ? String(w.pid) : "—",
                String(w.restarts),
                w.strategy || "—",
                w.err ? el("span", { class: "err" }, w.err) : "",
              ],
            )
          : el("div", { class: "muted" }, "no workers"),
      ),
    );

  drawHealth(health);
  drawWorkers(status);

  // Metrics arrive coalesced, so each one is the current picture rather than a
  // delta — which is what makes a dropped message harmless.
  // Every event kind this page shows lands on one refresh, because the stream
  // is lossy by design and each message means "something changed" rather than
  // carrying the change itself. Re-reading the campaign is one small request
  // against a daemon that has the numbers in memory.
  let pending = false;
  live.watch(["metrics", "worker", "campaign"], name, () => {
    if (pending) return;
    pending = true;
    void (async () => {
      const fresh = await service.campaign(name).catch(() => null);
      pending = false;
      if (!fresh) return;
      replace(stats, ...Array.from(metricStats(fresh).childNodes));
      drawWorkers(fresh);
      const h = await service.health(name).catch(() => null);
      if (h) drawHealth(h.diagnostics ?? []);
    })();
  });
}
