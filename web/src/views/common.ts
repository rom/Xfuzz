// Pieces more than one view needs.

import { el, table, type Child } from "../dom";
import type { CampaignStatus, Diagnostic, SeriesPoint } from "../api";
import { count, duration, percent, rate } from "../format";

export function panel(title: string, ...children: Child[]): HTMLElement {
  return el("div", { class: "panel" }, title ? el("h3", null, title) : null, ...children);
}

export function stat(label: string, value: string, note?: string): HTMLElement {
  return el(
    "div",
    { class: "stat" },
    el("div", { class: "k" }, label),
    el("div", { class: "v" }, value),
    note ? el("div", { class: "n" }, note) : null,
  );
}

export function badge(text: string, kind?: string): HTMLElement {
  return el("span", { class: kind ? `badge ${kind}` : "badge" }, text);
}

/** stateBadge colours a campaign or worker state without inventing a vocabulary. */
export function stateBadge(state: string): HTMLElement {
  const kind =
    state === "running" ? "running" : state === "failed" ? "failed" : undefined;
  return kind ? badge(state, kind) : badge(state);
}

export function empty(message: string): HTMLElement {
  return el("div", { class: "empty" }, message);
}

export function error(message: string): HTMLElement {
  return el("div", { class: "panel" }, el("div", { class: "err" }, message));
}

/** metricStats is the row of numbers every campaign view leads with. */
export function metricStats(c: CampaignStatus): HTMLElement {
  const m = c.metrics;
  const cells = [
    stat("executions", count(m.execs), rate(m.execs_per_second)),
    stat("coverage", count(m.coverage), `${percent(m.map_density, 1)} of the map`),
    stat("corpus", count(m.corpus_size)),
    stat("findings", count(m.findings), `${m.buckets} bucket(s)`),
    stat("stability", percent(m.stability, 1)),
    // Elapsed comes from the campaign's own timestamps rather than a counter,
    // so that a finished campaign shows how long it ran rather than how long
    // ago it was.
    stat("elapsed", duration(elapsedOf(c))),
  ];
  if ((m.states ?? 0) > 0) {
    // Protocol coverage sits beside code coverage and never inside it: a
    // campaign can hold edges flat while discovering a state (ADR-0006).
    cells.splice(2, 0, stat("protocol", `${m.states}`, `${m.transitions} transitions`));
  }
  return el("div", { class: "panel" }, el("div", { class: "stats" }, ...cells));
}

export function diagnostics(list: Diagnostic[]): HTMLElement | null {
  if (!list.length) return null;
  return panel(
    "health",
    ...list.map((d) =>
      el(
        "div",
        { class: `diag ${d.severity}` },
        el("div", { class: "summary" }, d.summary),
        d.remedy ? el("div", { class: "remedy" }, d.remedy) : null,
      ),
    ),
  );
}

/** sparkline draws one series. Small, axis-light, and honest about scale. */
export function sparkline(points: SeriesPoint[], pick: (p: SeriesPoint) => number, label: string): SVGSVGElement {
  const values = points.map(pick);
  const max = Math.max(1, ...values);
  const w = 600;
  const h = 120;
  // The plot starts below the label rather than behind it. A caption written
  // across the series it describes is the one place a chart can be actively
  // harder to read than the numbers it replaced.
  const top = 16;

  const step = values.length > 1 ? w / (values.length - 1) : w;
  const coords = values.map((v, i) => [i * step, h - (v / max) * (h - top - 4)] as const);
  const line = coords.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const area = `${line} L${w},${h} L0,${h} Z`;

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "chart");
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  svg.setAttribute("preserveAspectRatio", "none");

  const add = (tag: string, attrs: Record<string, string>, text?: string) => {
    const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    if (text !== undefined) n.textContent = text;
    svg.appendChild(n);
    return n;
  };
  if (values.length > 1) {
    add("path", { class: "area", d: area });
    add("path", { class: "line", d: line });
  }
  add("line", { class: "axis", x1: "0", y1: String(h), x2: String(w), y2: String(h) });
  // The maximum, written out: a sparkline without a scale is a shape, and a
  // shape does not tell you whether coverage went up by ten edges or ten
  // thousand.
  add("text", { x: "0", y: "10" }, `${label} — peak ${count(max)}`);
  return svg;
}

export function kv(rows: [string, Child][]): HTMLElement {
  return table(
    ["", ""],
    rows,
    (r) => [el("span", { class: "muted" }, r[0]), r[1]],
  );
}

/** elapsedOf is how long a campaign ran, or has been running. */
export function elapsedOf(c: CampaignStatus): number | undefined {
  if (!c.started) return undefined;
  const from = Date.parse(c.started);
  if (Number.isNaN(from)) return undefined;
  const stopped = c.stopped ? Date.parse(c.stopped) : NaN;
  const to = !Number.isNaN(stopped) && stopped > from ? stopped : Date.now();
  return to - from;
}
