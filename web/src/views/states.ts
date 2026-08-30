// The protocol state machine a stateful campaign has explored.
//
// A state label is a hash, so every label is shown with the response that
// produced it (ADR-0006) — and with how many *different* responses share it,
// because a label covering several is the commonest reason a campaign aiming
// at a state keeps landing somewhere it has been.

import { service, type StateModel } from "../api";
import { el, replace, table } from "../dom";
import { href } from "../router";
import { badge, empty, error, panel, stat } from "./common";

export async function statesView(root: HTMLElement, name: string): Promise<void> {
  let model: StateModel;
  try {
    model = await service.states(name);
  } catch (e) {
    replace(root, error(e instanceof Error ? e.message : String(e)));
    return;
  }

  const states = model.states ?? [];
  const moves = model.transitions ?? [];

  replace(
    root,
    el(
      "header",
      { class: "view" },
      el("h2", null, "State machine"),
      el("span", { class: "sub" }, el("a", { href: href("campaign", name) }, name)),
      model.fn ? badge(`state function: ${model.fn}`) : null,
    ),
  );

  if (!states.length) {
    root.appendChild(
      empty("This campaign has no protocol state machine. Add a session: block to fuzz a conversation."),
    );
    return;
  }

  root.appendChild(
    panel(
      "",
      el(
        "div",
        { class: "stats" },
        stat("states", String(states.length)),
        stat("transitions", String(moves.length)),
        stat("illegal moves", String((model.illegal ?? []).length),
          model.illegal?.length ? "outside the declared model" : ""),
      ),
    ),
  );

  // The frontier first: the rarely-visited states are where the unexplored
  // protocol is, and they are what the scheduler is aiming at.
  const rare = [...states].sort((a, b) => a.count - b.count).slice(0, 8);
  root.appendChild(
    panel(
      "least visited — where the unexplored protocol is",
      el("div", { class: "graph" },
        ...rare.map((s) =>
          el("span", { class: "node" }, s.label, el("span", { class: "n" }, String(s.count))),
        ),
      ),
    ),
  );

  root.appendChild(
    panel(
      "states",
      table(
        ["Label", "Visits", "Responses", "What the target said"],
        states,
        (s) => [
          el("span", { class: "mono" }, s.label),
          el("span", { class: "num" }, String(s.count)),
          // More than one response under a label is the clustering being
          // coarse. It may be right — a status code is meant to merge — but it
          // is never something to discover by accident.
          (s.variants ?? 1) > 1
            ? badge(`${s.variants} distinct`, "warn")
            : el("span", { class: "muted" }, "1"),
          el("span", { class: "mono" }, s.exemplar ?? ""),
        ],
      ),
    ),
  );

  root.appendChild(
    panel(
      "transitions",
      table(
        ["From", "To", "Count"],
        moves,
        (t) => [
          el("span", { class: "mono" }, t.from),
          el("span", { class: "mono" }, t.to),
          el("span", { class: "num" }, String(t.count)),
        ],
      ),
    ),
  );

  if (model.illegal?.length) {
    root.appendChild(
      panel(
        "outside the declared model",
        table(
          ["From", "To", "Count"],
          model.illegal,
          (t) => [
            el("span", { class: "mono" }, t.from),
            el("span", { class: "mono" }, t.to),
            el("span", { class: "num" }, String(t.count)),
          ],
        ),
      ),
    );
  }
}
