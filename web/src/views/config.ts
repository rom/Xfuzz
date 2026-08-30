// The config editor.
//
// It edits the campaign *file* (ADR-0011). Every change goes through
// campaign.edit, which preserves comments and key order, so what somebody
// leaves here is a file they can commit — and a console launch is the same
// thing as committing that file and running the CLI.
//
// Which is also why this is not a generated form over the schema. A form would
// hide the format the campaign is written in, and the format is the interface.

import { service } from "../api";
import { el, replace } from "../dom";
import { badge, error, panel } from "./common";

const STARTER = `# A campaign. Every field is optional except the target.
name: example

target:
  path: ./target
  input: stdin

seeds:
  inline: ["seed"]

feedback:
  coverage: sancov

workers:
  count: 2

stop:
  after: 10m
`;

export function configView(root: HTMLElement): void {
  const text = el("textarea", null, STARTER) as HTMLTextAreaElement;
  const status = el("div", { class: "row" });
  const explained = el("div");

  const setField = el("input", { type: "text", placeholder: "workers.count" });
  const setValue = el("input", { type: "text", placeholder: "4" });

  const say = (...children: Parameters<typeof replace> extends [unknown, ...infer R] ? R : never) =>
    replace(status, ...children);

  const validate = async () => {
    try {
      const r = await service.validate(text.value, "console");
      say(r.valid ? badge("valid", "on") : badge("invalid", "bad"),
        ...(r.warnings ?? []).map((wmsg) => el("span", { class: "muted" }, wmsg)));
    } catch (e) {
      say(el("span", { class: "err" }, e instanceof Error ? e.message : String(e)));
    }
  };

  const explain = async () => {
    try {
      const r = await service.explain(text.value, "console");
      replace(explained, panel("resolved configuration, every default marked", el("pre", null, r.text)));
    } catch (e) {
      replace(explained, error(e instanceof Error ? e.message : String(e)));
    }
  };

  // The edit goes to the daemon rather than being applied here, so that the
  // console and `xfuzz edit` cannot drift into two different notions of what
  // editing a campaign file means.
  const applyEdit = async () => {
    const path = setField.value.trim();
    if (!path) return;
    try {
      const r = await service.edit(text.value, { [path]: coerce(setValue.value) }, [], "console");
      text.value = r.document;
      say(r.valid ? badge("valid", "on") : badge("invalid", "bad"),
        r.error ? el("span", { class: "muted" }, r.error) : null);
    } catch (e) {
      say(el("span", { class: "err" }, e instanceof Error ? e.message : String(e)));
    }
  };

  const launch = async () => {
    try {
      const created = await service.create(text.value, "console");
      await service.action(created.name, "start");
      location.hash = `#/campaign/${encodeURIComponent(created.name)}`;
    } catch (e) {
      say(el("span", { class: "err" }, e instanceof Error ? e.message : String(e)));
    }
  };

  replace(
    root,
    el("header", { class: "view" }, el("h2", null, "Campaign file"),
      el("span", { class: "sub" }, "edits keep comments, key order and layout")),
    panel(
      "",
      text,
      el(
        "div",
        { class: "row" },
        el("button", { onclick: validate }, "Validate"),
        el("button", { onclick: explain }, "Explain"),
        el("button", { class: "primary", onclick: launch }, "Launch"),
      ),
      el(
        "div",
        { class: "row" },
        el("span", { class: "muted" }, "set field"),
        setField,
        setValue,
        el("button", { onclick: applyEdit }, "Apply"),
      ),
      status,
    ),
    explained,
  );
}

/** coerce reads a typed value out of a text box, so 4 stays a number. */
function coerce(raw: string): unknown {
  const s = raw.trim();
  if (s === "true") return true;
  if (s === "false") return false;
  if (s !== "" && !Number.isNaN(Number(s))) return Number(s);
  return s;
}
