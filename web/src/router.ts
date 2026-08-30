// Hash routing.
//
// The hash rather than the History API, for one reason: the daemon serves this
// from a Unix socket behind whatever a person points at it, and a hash route
// needs no server-side rewriting to survive a reload. The Go handler falls back
// to index.html anyway, so both work — this one also works when somebody serves
// the bundle from a directory.

export type Route = { view: string; args: string[] };

export function current(): Route {
  const raw = location.hash.replace(/^#\/?/, "");
  const parts = raw.split("/").filter(Boolean).map(decodeURIComponent);
  const [view = "campaigns", ...args] = parts;
  return { view, args };
}

export function go(view: string, ...args: string[]): void {
  const path = [view, ...args.map(encodeURIComponent)].join("/");
  location.hash = `#/${path}`;
}

export function href(view: string, ...args: string[]): string {
  return `#/${[view, ...args.map(encodeURIComponent)].join("/")}`;
}

export function onChange(fn: () => void): void {
  window.addEventListener("hashchange", fn);
}
