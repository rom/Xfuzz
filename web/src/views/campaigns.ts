// Campaigns: what is running, how it is doing, and what to do about it.

import { service, type CampaignStatus } from "../api";
import { el, replace, table } from "../dom";
import { count, duration, percent, rate } from "../format";
import { go, href } from "../router";
import { elapsedOf, empty, error, panel, stateBadge } from "./common";

export async function campaignsView(root: HTMLElement): Promise<void> {
  replace(root, el("header", { class: "view" }, el("h2", null, "Campaigns")));

  let list: CampaignStatus[];
  try {
    list = (await service.campaigns()).campaigns ?? [];
  } catch (e) {
    root.appendChild(error(String(e instanceof Error ? e.message : e)));
    return;
  }

  root.appendChild(loadForm());

  if (!list.length) {
    root.appendChild(
      empty("No campaigns are loaded. Start one with `xfuzz run FILE`, or open a finished one from its store above."),
    );
    return;
  }

  root.appendChild(
    panel(
      "",
      table(
        ["Name", "State", "Execs", "Rate", "Coverage", "Corpus", "Findings", "Elapsed", ""],
        list,
        (c) => [
          el("a", { href: href("campaign", c.name) }, c.name),
          stateBadge(c.state),
          el("span", { class: "num" }, count(c.metrics.execs)),
          el("span", { class: "num" }, rate(c.metrics.execs_per_second)),
          el("span", { class: "num" }, count(c.metrics.coverage)),
          el("span", { class: "num" }, count(c.metrics.corpus_size)),
          el("span", { class: "num" }, `${c.metrics.findings} / ${c.metrics.buckets}`),
          duration(elapsedOf(c)),
          actions(c),
        ],
      ),
    ),
  );
}

// actions offers only what the campaign's state allows.
//
// A stop button on a finished campaign is a button that exists to return an
// error, and a console that offers it is one whose buttons cannot be trusted.
function actions(c: CampaignStatus): HTMLElement {
  const redraw = () => {
    go("campaigns");
    window.dispatchEvent(new HashChangeEvent("hashchange"));
  };
  const run = async (what: string) => {
    try {
      await service.action(c.name, what);
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    }
    redraw();
  };
  // Forget is the one action that removes a row, so it asks first — and says
  // what it does not do, because "forget" reads as "delete" to somebody who
  // has not read the daemon's docs: the store is kept, and the form above
  // opens it again by name.
  const forget = async () => {
    if (!confirm(`Forget ${c.name}? Its store is kept, and it can be opened again from it.`)) {
      return;
    }
    try {
      await service.forget(c.name);
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    }
    redraw();
  };

  const buttons: HTMLElement[] = [];
  switch (c.state) {
    case "running":
      buttons.push(el("button", { onclick: () => run("pause") }, "Pause"));
      buttons.push(el("button", { onclick: () => run("stop") }, "Stop"));
      break;
    case "paused":
      buttons.push(el("button", { onclick: () => run("resume") }, "Resume"));
      buttons.push(el("button", { onclick: () => run("stop") }, "Stop"));
      break;
    case "created":
      buttons.push(el("button", { class: "primary", onclick: () => run("start") }, "Start"));
      buttons.push(el("button", { onclick: forget }, "Forget"));
      break;
    default:
      // Finished, failed: its findings and corpus are still worth reading, and
      // that is what the name links to. The daemon refuses to forget a campaign
      // that is running or paused, which is why the button is only here.
      buttons.push(el("button", { onclick: forget }, "Forget"));
      break;
  }
  return el("div", { class: "row" }, ...buttons);
}

// loadForm opens a campaign the daemon does not hold, from a store.
//
// The console's answer to "triage tomorrow" (ADR-0003): a campaign whose run
// ended weeks ago is reachable by name, without the file that produced it.
function loadForm(): HTMLElement {
  const name = el("input", { type: "text", placeholder: "campaign name" });
  const store = el("input", { type: "text", placeholder: "store directory (optional)" });
  const status = el("span", { class: "muted" });

  const open = async () => {
    if (!name.value.trim()) return;
    try {
      await service.load(name.value.trim(), store.value.trim());
      go("campaign", name.value.trim());
    } catch (e) {
      replace(status, el("span", { class: "err" }, e instanceof Error ? e.message : String(e)));
    }
  };
  return panel(
    "open a finished campaign",
    el(
      "div",
      { class: "row" },
      name,
      store,
      el("button", { onclick: open }, "Open"),
      status,
    ),
  );
}

/** summaryLine is the one-line campaign description other views reuse. */
export function summaryLine(c: CampaignStatus): HTMLElement {
  return el(
    "div",
    { class: "sub" },
    `${c.state}`,
    c.reason ? ` — ${c.reason}` : "",
    ` · seed ${c.seed} · isolation ${c.isolation} · stability ${percent(c.metrics.stability, 1)}`,
  );
}
