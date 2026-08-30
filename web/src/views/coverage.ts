// Coverage: how much, and whether it is still going up.
//
// The plateau is the question this view exists to answer. A campaign whose
// coverage has been flat for an hour is a campaign to change or stop, and that
// is invisible in a single number however often it is refreshed.

import { service, type SeriesPoint } from "../api";
import { el, replace, table } from "../dom";
import { count, duration, percent } from "../format";
import { href } from "../router";
import { empty, error, panel, sparkline, stat } from "./common";

export async function coverageView(root: HTMLElement, name: string): Promise<void> {
  let points: SeriesPoint[];
  let density = 0;
  try {
    const [history, status] = await Promise.all([service.history(name), service.campaign(name)]);
    points = history.points ?? [];
    density = status.metrics.map_density;
  } catch (e) {
    replace(root, error(e instanceof Error ? e.message : String(e)));
    return;
  }

  replace(
    root,
    el(
      "header",
      { class: "view" },
      el("h2", null, "Coverage"),
      el("span", { class: "sub" }, el("a", { href: href("campaign", name) }, name)),
    ),
  );

  if (points.length < 2) {
    root.appendChild(empty("Not enough history yet. The series fills as the campaign runs."));
    return;
  }

  const last = points[points.length - 1]!;
  const plateau = plateauFor(points);

  root.appendChild(
    panel(
      "",
      el(
        "div",
        { class: "stats" },
        stat("edges", count(last.coverage)),
        stat("map density", percent(density, 2), density > 0.5 ? "edges are colliding" : "healthy"),
        stat("corpus", count(last.corpus_size)),
        stat(
          "last new coverage",
          plateau === null ? "—" : duration(plateau),
          plateau !== null && plateau > 30 * 60_000 ? "stalled" : "",
        ),
      ),
    ),
  );

  root.appendChild(panel("coverage over time", sparkline(points, (p) => p.coverage, "edges")));
  root.appendChild(panel("corpus over time", sparkline(points, (p) => p.corpus_size, "entries")));

  // The tail as numbers as well as a shape: a chart says whether it is rising,
  // and only the numbers say by how much.
  const tail = points.slice(-12);
  root.appendChild(
    panel(
      "recent points",
      table(
        ["At", "Execs", "Edges", "Corpus", "Findings"],
        tail,
        (p) => [
          new Date(p.at).toLocaleTimeString(),
          el("span", { class: "num" }, count(p.execs)),
          el("span", { class: "num" }, count(p.coverage)),
          el("span", { class: "num" }, count(p.corpus_size)),
          el("span", { class: "num" }, String(p.findings)),
        ],
      ),
    ),
  );
}

/** plateauFor returns how long since coverage last rose, in ms, or null. */
function plateauFor(points: SeriesPoint[]): number | null {
  const last = points[points.length - 1];
  if (!last) return null;
  for (let i = points.length - 2; i >= 0; i--) {
    const p = points[i]!;
    if (p.coverage < last.coverage) {
      return Date.parse(last.at) - Date.parse(points[i + 1]!.at);
    }
  }
  return Date.parse(last.at) - Date.parse(points[0]!.at);
}
