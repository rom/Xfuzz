// The grammar workbench.
//
// A grammar is a program, and the only way to know what one produces is to look
// at what it produces. Sampling needs no campaign and no target, so a grammar
// can be written before there is anything to fuzz with it.

import { service } from "../api";
import { el, replace } from "../dom";
import { bytes, decodeBase64, hex } from "../format";
import { badge, error, panel } from "./common";

const STARTER = `# A grammar. Fields are laid out in order; derived values are
# recomputed after every mutation, which is what a checksum needs.

format message {
  magic:  magic "MSG"
  length: u16be = len(^body)
  body:   bytes<1..64>
}
`;

export function grammarView(root: HTMLElement): void {
  const text = el("textarea", null, STARTER) as HTMLTextAreaElement;
  const seed = el("input", { type: "text", value: "0", placeholder: "seed" });
  const output = el("div");
  const status = el("div", { class: "row" });

  const sample = async () => {
    // Sent as a string, never as a number. A seed is a 64-bit identifier and a
    // JSON number is an IEEE double, so pasting a campaign's own seed here —
    // the obvious thing to do with one — would sample a different campaign's
    // grammar and look right while doing it.
    const typed = seed.value.trim();
    const n = /^[0-9]+$/.test(typed) ? typed : "0";
    try {
      const r = await service.sample(text.value, 6, n);
      if (!r.valid) {
        // A grammar under construction does not compile most of the time, so
        // the parser's message is the answer rather than a failure.
        replace(status, badge("does not compile", "bad"));
        replace(output, panel("", el("pre", { class: "wrap err" }, r.error ?? "")));
        return;
      }
      replace(status,
        badge(`${r.types} type(s), root ${r.root}`, "on"));
      replace(
        output,
        ...(r.samples ?? []).map((s, i) => {
          const raw = decodeBase64(s.bytes);
          return panel(`sample ${i + 1} — ${bytes(s.size)}`, el("pre", null, hex(raw, 256)));
        }),
      );
    } catch (e) {
      replace(output, error(e instanceof Error ? e.message : String(e)));
    }
  };

  replace(
    root,
    el("header", { class: "view" }, el("h2", null, "Grammar workbench"),
      el("span", { class: "sub" }, "the same seed always gives the same samples")),
    panel(
      "",
      text,
      el(
        "div",
        { class: "row" },
        el("button", { class: "primary", onclick: sample }, "Sample"),
        el("span", { class: "muted" }, "seed"),
        seed,
        status,
      ),
    ),
    output,
  );
  void sample();
}
