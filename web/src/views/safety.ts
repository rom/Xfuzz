// Safety: what isolation is actually in force, and why it is not more.
//
// ADR-0012 makes the sandbox default and the scope guard mandatory, and
// SECURITY.md's claim is that a campaign says what it is enforcing rather than
// leaving it to be inferred. This view is where that is said — which is why it
// reads the route's own shape and nothing else: an earlier version read a
// list the route never sent and told every host that nothing was missing.

import { service, type AuditEntry, type Safety } from "../api";
import { el, replace, table } from "../dom";
import { count } from "../format";
import { href } from "../router";
import { badge, empty, error, panel, stat } from "./common";

export async function safetyView(root: HTMLElement, name: string): Promise<void> {
  let safety: Safety | null = null;
  let audit: { entries: AuditEntry[]; verified: boolean } | null = null;
  let failure = "";
  try {
    safety = await service.safety(name);
  } catch (e) {
    failure = e instanceof Error ? e.message : String(e);
  }
  audit = await service.audit().catch(() => null);

  replace(
    root,
    el(
      "header",
      { class: "view" },
      el("h2", null, "Safety"),
      el("span", { class: "sub" }, el("a", { href: href("campaign", name) }, name)),
    ),
  );
  if (failure) {
    root.appendChild(error(failure));
  }

  if (safety) {
    const reasons = safety.reasons ?? [];
    root.appendChild(
      panel(
        "isolation",
        el("div", { class: "row" }, badge(safety.isolation, "on")),
        // Why it is not higher is the useful half. "Moderate" on its own reads
        // like a choice; the reasons say which capability the host lacks —
        // and which of the campaign's own limits this host will not enforce.
        reasons.length
          ? el("ul", null, ...reasons.map((r) => el("li", null, r)))
          : el("div", { class: "muted" }, "nothing is missing on this host"),
      ),
    );

    const allow = safety.allow ?? [];
    const c = safety.connections;
    root.appendChild(
      panel(
        "network scope",
        el(
          "div",
          { class: "stats" },
          stat("loopback", safety.loopback ? "allowed" : "refused"),
          stat("destinations", String(allow.length), allow.length ? "" : "nothing beyond loopback"),
          stat("connections", c ? count(c.allowed) : "—", c ? `${count(c.denied)} refused` : ""),
        ),
        allow.length
          ? el("ul", null, ...allow.map((a) => el("li", { class: "mono" }, a)))
          : null,
        // Said rather than implied: there is no deny list to show because
        // everything the rules do not name is refused (ADR-0012).
        el("div", { class: "muted" }, "Every destination not listed is refused."),
      ),
    );
  }

  if (audit) {
    root.appendChild(
      panel(
        "audit log",
        el(
          "div",
          { class: "row" },
          audit.verified
            ? badge("chain verified", "on")
            : badge("chain broken — entries have been altered or removed", "bad"),
        ),
        audit.entries?.length
          ? table(
              ["At", "Actor", "Action", "Detail"],
              audit.entries.slice(-50).reverse(),
              (e) => [
                new Date(e.at).toLocaleString(),
                e.actor || "—",
                el("span", { class: "mono" }, e.action),
                e.detail,
              ],
            )
          : empty("nothing recorded yet"),
      ),
    );
  }
}
