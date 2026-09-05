// The console's entry point: navigation, routing, and one event stream.

import "./style.css";

import { ApiError, onUnauthorized, service, setToken } from "./api";
import { el, replace } from "./dom";
import { Live } from "./events";
import { current, href, onChange } from "./router";
import { panel } from "./views/common";
import { campaignsView } from "./views/campaigns";
import { campaignView } from "./views/campaign";
import { configView } from "./views/config";
import { corpusView, entryView } from "./views/corpus";
import { doctorView } from "./views/doctor";
import { findingView, findingsView } from "./views/findings";
import { coverageView } from "./views/coverage";
import { grammarView } from "./views/grammar";
import { safetyView } from "./views/safety";
import { statesView } from "./views/states";

const live = new Live();

// The campaign-scoped views, in the order somebody works through them:
// what is happening, what it found, what it kept, and what it was allowed to do.
const CAMPAIGN_VIEWS: [string, string][] = [
  ["campaign", "Overview"],
  ["findings", "Findings"],
  ["coverage", "Coverage"],
  ["states", "State machine"],
  ["corpus", "Corpus"],
  ["safety", "Safety"],
];

const TOOL_VIEWS: [string, string][] = [
  ["config", "Campaign file"],
  ["grammar", "Grammar"],
];

// About the daemon's host rather than any campaign or file.
const HOST_VIEWS: [string, string][] = [["doctor", "Doctor"]];

function main(): void {
  const app = document.getElementById("app");
  if (!app) return;

  const nav = el("nav");
  // The gate is where the token form goes, and it is not main: a refused view
  // keeps drawing into main after it fails — its error panel, and on a view
  // that makes two requests, its whole layout after the second — so a form
  // drawn there was drawn over. Views own main and nothing else.
  const gate = el("div");
  const main$ = el("main");
  replace(app, el("div", { class: "shell" }, nav, el("div", null, gate, main$)));

  const render = () => {
    const route = current();
    // Every view starts from a clean stream: a page that kept the previous
    // view's subscription would be a subscriber nobody is reading, which is
    // exactly what the daemon's bounded queue is there to notice.
    live.stop();
    asking = false;
    replace(gate);
    main$.hidden = false;
    drawNav(nav, route.view, route.args[0]);
    void draw(main$, route.view, route.args);
  };

  onUnauthorized(() => askForToken(gate, main$));
  onChange(render);
  render();
  void footer(nav);
}

// askForToken puts the one question the daemon has in front of the view.
//
// Once per render: a view that was refused made several requests, and each
// would otherwise put up the same form over the last. The view goes on
// failing into main behind it, hidden, and is redrawn on the next render.
let asking = false;

function askForToken(gate: HTMLElement, main$: HTMLElement): void {
  if (asking) return;
  asking = true;
  main$.hidden = true;
  drawTokenForm(gate);
}

function drawTokenForm(root: HTMLElement): void {
  const input = el("input", { type: "password", placeholder: "the daemon's --token" });
  const use = () => {
    if (!input.value) return;
    setToken(input.value);
    // Reload rather than redraw: the nav's own request failed too, and a
    // fresh start with the cookie in place is the state a browser that had
    // it all along would be in.
    location.reload();
  };

  replace(
    root,
    el("header", { class: "view" }, el("h2", null, "This daemon asks for a token")),
    panel(
      "",
      el(
        "div",
        { class: "muted" },
        "It is the value xfuzzd was started with. It is kept in a cookie for this browser session and sent with every request, the event stream included.",
      ),
      el(
        "form",
        {
          onsubmit: (e) => {
            e.preventDefault();
            use();
          },
        },
        el("div", { class: "row" }, input, el("button", { class: "primary", type: "submit" }, "Use token")),
      ),
    ),
  );
  input.focus();
}

async function draw(root: HTMLElement, view: string, args: string[]): Promise<void> {
  const name = args[0] ?? "";
  switch (view) {
    case "campaigns":
      return campaignsView(root);
    case "campaign":
      return name ? campaignView(root, name, live) : campaignsView(root);
    case "findings":
      return findingsView(root, name);
    case "finding":
      return findingView(root, name, Number(args[1] ?? 0));
    case "coverage":
      return coverageView(root, name);
    case "states":
      return statesView(root, name);
    case "corpus":
      return corpusView(root, name);
    case "entry":
      return entryView(root, name, args[1] ?? "");
    case "safety":
      return safetyView(root, name);
    case "config":
      return configView(root);
    case "grammar":
      return grammarView(root);
    case "doctor":
      return doctorView(root);
    default:
      return campaignsView(root);
  }
}

function drawNav(nav: HTMLElement, view: string, name: string | undefined): void {
  const link = (target: string, label: string, ...args: string[]) =>
    el("a", { href: href(target, ...args), class: view === target ? "on" : "" }, label);

  replace(
    nav,
    el("h1", null, "xfuzz"),
    link("campaigns", "Campaigns"),
    // The campaign-scoped views appear once a campaign is in scope, because a
    // "Findings" link with nothing to show is a link that leads to an error.
    name
      ? el(
          "div",
          null,
          el("div", { class: "group" }, name),
          ...CAMPAIGN_VIEWS.map(([t, label]) => link(t, label, name)),
        )
      : null,
    el("div", { class: "group" }, "author"),
    ...TOOL_VIEWS.map(([t, label]) => link(t, label)),
    el("div", { class: "group" }, "host"),
    ...HOST_VIEWS.map(([t, label]) => link(t, label)),
  );
}

/** footer names the daemon this console is talking to. */
async function footer(nav: HTMLElement): Promise<void> {
  try {
    const info = await service.info();
    nav.appendChild(
      el(
        "div",
        { class: "group", title: info.daemon.data_dir },
        `xfuzzd ${info.daemon.version.version}`,
      ),
    );
  } catch (e) {
    // Refused and unreachable are different problems with different fixes,
    // and the footer is the one place that is drawn whatever the view.
    const refused = e instanceof ApiError && e.status === 401;
    nav.appendChild(el("div", { class: "group err" }, refused ? "token required" : "daemon unreachable"));
  }
}

main();
