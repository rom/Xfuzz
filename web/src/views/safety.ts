// Safety: what isolation is actually in force, and why it is not more.
//
// ADR-0012 makes the sandbox default and the scope guard mandatory, and
// SECURITY.md's claim is that a campaign says what it is enforcing rather than
// leaving it to be inferred. This view is where that is said.

import { service, type AuditEntry, type Safety } from "../api";
import { el, replace, table } from "../dom";
import { href } from "../router";
import { badge, empty, error, panel } from "./common";

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
    root.appendChild(
      panel(
        "isolation",
        el("div", { class: "row" }, badge(safety.isolation, "on")),
        // Why it is not higher is the useful half. "Moderate" on its own reads
        // like a choice; the reasons say which capability the host lacks.
        safety.reasons?.length
          ? el("ul", null, ...safety.reasons.map((r) => el("li", null, r)))
          : el("div", { class: "muted" }, "nothing is missing on this host"),
      ),
    );

    const scope = safety.scope;
    root.appendChild(
      panel(
        "network scope",
        scope && (scope.allow?.length || scope.deny?.length)
          ? el(
              "div",
              null,
              scope.allow?.length
                ? el("div", null, el("span", { class: "muted" }, "allow "), scope.allow.join(", "))
                : null,
              scope.deny?.length
                ? el("div", null, el("span", { class: "muted" }, "deny "), scope.deny.join(", "))
                : null,
            )
          : el("div", { class: "muted" }, "no destination is allowed; the target cannot reach the network"),
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
