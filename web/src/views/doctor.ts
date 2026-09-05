// The doctor: what this host can do, and why anything is missing.
//
// The same report `xfuzz doctor` prints, from the same route. It describes the
// daemon's host rather than the browser's, because the daemon is the process
// that runs targets and the one whose capabilities matter — and every row is
// probed on the machine answering, not read off the platform name: a kernel
// that has namespaces and a container that forbids them look the same until
// somebody tries (ADR-0012).

import { service, type Capabilities } from "../api";
import { el, replace, table } from "../dom";
import { badge, error, panel, stat } from "./common";

export async function doctorView(root: HTMLElement): Promise<void> {
  let rep: Capabilities;
  try {
    rep = await service.capabilities();
  } catch (e) {
    replace(root, error(e instanceof Error ? e.message : String(e)));
    return;
  }

  const caps = rep.capabilities ?? [];
  const missing = caps.filter((c) => !c.available).length;

  replace(
    root,
    el(
      "header",
      { class: "view" },
      el("h2", null, "Doctor"),
      el("span", { class: "sub" }, "what the daemon's host can do"),
    ),
    panel(
      "",
      el(
        "div",
        { class: "stats" },
        stat("platform", rep.platform),
        stat("version", rep.version.version, `${rep.version.go}${rep.version.cgo ? "" : ", no cgo"}`),
        stat("isolation", rep.isolation),
        stat("missing", String(missing), missing ? "each says why below" : "nothing on this host"),
      ),
    ),
    // Why the isolation level is what it is: "moderate" on its own reads like
    // a choice, and the explanation says which mechanism the host lacks.
    rep.explanation ? panel("isolation", el("div", null, rep.explanation)) : null,
    panel(
      "capabilities",
      table(
        ["", "Capability", "What it is for, or why it is missing"],
        caps,
        (c) => [
          c.available ? badge("yes", "ok") : badge("no", "bad"),
          el("span", { class: "mono" }, c.name),
          c.detail ?? "",
        ],
      ),
    ),
    rep.notes?.length
      ? panel("notes", el("ul", null, ...rep.notes.map((n) => el("li", null, n))))
      : null,
  );
}
