// The corpus browser: what the campaign kept, and why.
//
// Provenance is the point. An entry is a mutation of another entry by a named
// operator, and being able to walk back from a finding to the seed it came from
// is what makes a corpus something to reason about rather than a pile of files.

import { CORPUS_FORMATS, service, type CorpusEntry } from "../api";
import { el, replace, table } from "../dom";
import { ago, bytes, count, decodeBase64, hex } from "../format";
import { go, href } from "../router";
import { badge, empty, error, panel } from "./common";

export async function corpusView(root: HTMLElement, name: string): Promise<void> {
  const shown = el("span", { class: "sub" });
  const entries$ = el("div");

  // The table is drawn on its own so that an import can redraw it without
  // taking the import's own report off the screen.
  const draw = async () => {
    let entries: CorpusEntry[];
    try {
      entries = (await service.corpus(name)).entries ?? [];
    } catch (e) {
      replace(entries$, error(e instanceof Error ? e.message : String(e)));
      return;
    }
    replace(shown, `${entries.length} entries shown`);
    if (!entries.length) {
      replace(entries$, empty("The corpus is empty."));
      return;
    }
    replace(
      entries$,
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
  };

  replace(
    root,
    el(
      "header",
      { class: "view" },
      el("h2", null, "Corpus"),
      el("span", { class: "sub" }, el("a", { href: href("campaign", name) }, name)),
      shown,
    ),
    entries$,
    transferForm(name, draw),
  );
  await draw();
}

// transferForm moves the corpus in from, or out to, another fuzzer's layout.
//
// The directory is on the daemon's host, and the form says so. A browser
// cannot hand over a directory, and the daemon is the process that holds the
// store, so this names a path where the daemon is rather than uploading
// anything — the same request `xfuzz corpus import --dir` makes, with the
// same answer (ADR-0008).
function transferForm(name: string, redraw: () => Promise<void>): HTMLElement {
  const dir = el("input", { type: "text", placeholder: "directory on the daemon's host" });
  const format = el("select", null, ...CORPUS_FORMATS.map((f) => el("option", { value: f }, f)));
  const favoured = el("input", { type: "checkbox" });
  const overwrite = el("input", { type: "checkbox" });
  const report = el("div");

  const said = (title: string, rows: [string, string][]) =>
    replace(
      report,
      panel(title, table(["", ""], rows, (r) => [el("span", { class: "muted" }, r[0]), r[1]])),
    );
  const failed = (e: unknown) => replace(report, error(e instanceof Error ? e.message : String(e)));

  const doImport = async () => {
    const path = dir.value.trim();
    if (!path) return;
    try {
      const r = await service.importCorpus(name, path, format.value);
      // The duplicates are the number that says whether a merge was worth
      // doing, and the skip reasons are the number that says whether the
      // format was right; both are shown rather than folded into a total.
      const reasons = Object.entries(r.Reasons ?? {})
        .map(([why, n]) => `${why}×${n}`)
        .join(", ");
      said("imported", [
        ["read", `${r.Dir} as ${r.Format}`],
        ["imported", `${count(r.Imported)} entries, ${bytes(r.Bytes)}`],
        ["duplicates", String(r.Duplicate)],
        ["skipped", r.Skipped ? `${r.Skipped} (${reasons})` : "0"],
      ]);
      await redraw();
    } catch (e) {
      failed(e);
    }
  };

  const doExport = async () => {
    const path = dir.value.trim();
    if (!path) return;
    try {
      const r = await service.exportCorpus(name, path, format.value, favoured.checked, overwrite.checked);
      said("exported", [
        ["written", `${count(r.Written)} entries, ${bytes(r.Bytes)}`],
        ["to", `${r.Dir} as ${r.Format}`],
        ["skipped", String(r.Skipped)],
      ]);
    } catch (e) {
      failed(e);
    }
  };

  return el(
    "div",
    null,
    panel(
      "import and export",
      el(
        "div",
        { class: "row" },
        dir,
        format,
        el("button", { onclick: doImport }, "Import"),
        el("button", { onclick: doExport }, "Export"),
      ),
      el(
        "div",
        { class: "row muted" },
        el("label", null, favoured, " export only the favoured set — it reaches everything the whole corpus does"),
        el("label", null, overwrite, " export into a directory that already holds files"),
      ),
    ),
    report,
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
