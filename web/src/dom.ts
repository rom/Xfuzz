// A very small rendering helper, in place of a framework.
//
// The console is ten views of tables, numbers and forms. A framework would be
// a large runtime dependency and a permanent upgrade obligation inside a
// systems project, which is the cost ADR-0011 names for having a console at
// all; this is about eighty lines and does what those views need.

export type Child = Node | string | number | null | undefined | false;

interface Attrs {
  class?: string;
  id?: string;
  title?: string;
  href?: string;
  download?: string;
  list?: string;
  type?: string;
  value?: string;
  placeholder?: string;
  rows?: number;
  disabled?: boolean;
  selected?: boolean;
  onclick?: (e: MouseEvent) => void;
  oninput?: (e: Event) => void;
  onchange?: (e: Event) => void;
  onsubmit?: (e: SubmitEvent) => void;
  dataset?: Record<string, string>;
}

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs?: Attrs | null,
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [key, value] of Object.entries(attrs)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === "dataset") {
        Object.assign(node.dataset, value as Record<string, string>);
      } else if (key.startsWith("on")) {
        node.addEventListener(key.slice(2), value as EventListener);
      } else if (key === "class") {
        node.className = String(value);
      } else if (key === "value" && node instanceof HTMLInputElement) {
        node.value = String(value);
      } else if (key === "disabled" || key === "selected") {
        node.toggleAttribute(key, Boolean(value));
      } else {
        node.setAttribute(key, String(value));
      }
    }
  }
  append(node, children);
  return node;
}

export function append(parent: Node, children: Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    parent.appendChild(
      // Text rather than innerHTML, everywhere and without exception. A
      // finding's detail is the target's own output and a campaign's name came
      // from a file: both are somebody else's bytes, and neither is markup.
      typeof child === "string" || typeof child === "number"
        ? document.createTextNode(String(child))
        : child,
    );
  }
}

export function clear(node: Node): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/** replace swaps a node's children for new ones in one go. */
export function replace(node: Node, ...children: Child[]): void {
  clear(node);
  append(node, children);
}

/** table builds a table from a header row and a row renderer. */
export function table<T>(
  headers: string[],
  rows: T[],
  cells: (row: T) => Child[],
  onRow?: (row: T) => void,
): HTMLElement {
  const head = el("tr", null, ...headers.map((h) => el("th", null, h)));
  const body = rows.map((row) => {
    const tr = el("tr", onRow ? { class: "clickable", onclick: () => onRow(row) } : null,
      ...cells(row).map((c) => el("td", null, c)));
    return tr;
  });
  return el("table", null, el("thead", null, head), el("tbody", null, ...body));
}
