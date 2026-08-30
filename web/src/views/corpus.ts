// The corpus browser: what the campaign kept, and why.
//
// Provenance is the point. An entry is a mutation of another entry by a named
// operator, and being able to walk back from a finding to the seed it came from
// is what makes a corpus something to reason about rather than a pile of files.

import { service, type CorpusEntry } from "../api";
import { el, replace, table } from "../dom";
import { ago, bytes, count, decodeBase64, hex } from "../format";
import { go, href } from "../router";
import { badge, empty, error, panel } from "./common";

export async function corpusView(root: HTMLElement, name: string): Promise<void> {
  let entries: CorpusEntry[];
  try {
    entries = (await service.corpus(name)).entries ?? [];
  } catch (e) {
    replace(root, error(e instanceof Error ? e.message : String(e)));
    return;
  }

  replace(
    root,
    el(
      "header",
      { class: "view" },
      el("h2", null, "Corpus"),
      el("span", { class: "sub" }, el("a", { href: href("campaign", name) }, name)),
      el("span", { class: "sub" }, `${entries.length} entries shown`),
    ),
  );

  if (!entries.length) {
    root.appendChild(empty("The corpus is empty."));
    return;
  }

  root.appendChild(
    panel(
      "",
      table(
        ["Digest", "Size", "Coverage", "Depth", "Origin", "Found"],
        entries,
        (e) => [
          el("span", { class: "mono" }, e.digest.slice(0, 16)),
          el("span", { class: "num" }, bytes(e.size)),
          el("span", { class: "num" }, count(e.coverage)),
          el("span", { class: "num" }, String(e.depth)),
          e.favoured ? badge(`${e.origin} · favoured`, "on") : badge(e.origin || "—"),
          ago(e.discovered),
        ],
        (e) => go("entry", name, e.digest),
      ),
    ),
  );
}

export async function entryView(root: HTMLElement, name: string, digest: string): Promise<void> {
  let entry: CorpusEntry & { payload: string; tree?: string };
  try {
    entry = await service.corpusEntry(name, digest);
  } catch (e) {
    replace(root, error(e instanceof Error ? e.message : String(e)));
    return;
  }

  const raw = entry.payload ? decodeBase64(entry.payload) : new Uint8Array();

  replace(
    root,
    el(
      "header",
      { class: "view" },
      el("h2", null, "Corpus entry"),
      el("span", { class: "sub mono" }, digest.slice(0, 24)),
      el("span", { class: "sub" }, el("a", { href: href("corpus", name) }, "back to the corpus")),
    ),
    panel(
      "provenance",
      table(
        ["", ""],
        [
          ["size", bytes(entry.size)] as const,
          ["coverage", count(entry.coverage)] as const,
          ["depth", String(entry.depth)] as const,
          ["origin", entry.origin || "—"] as const,
          ["parent", entry.parent ?? "—"] as const,
          ["favoured", entry.favoured ? "yes" : "no"] as const,
          ["discovered", ago(entry.discovered)] as const,
        ],
        (r) => [el("span", { class: "muted" }, r[0]), el("span", { class: "mono" }, r[1])],
      ),
    ),
    // Both renderings, because they answer different questions: the tree says
    // what the input means and the hex says what it is (ADR-0005).
    entry.tree ? panel("structure", el("pre", null, entry.tree)) : null,
    panel(`bytes (${bytes(raw.length)})`, el("pre", null, raw.length ? hex(raw, 1024) : "empty")),
  );
}
