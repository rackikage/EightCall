// DOM helpers. Every one of these sets text via textContent/property, never
// innerHTML — the telemetry this dashboard watches carries adversary-shaped
// strings on purpose (log lines, denial reasons), and they must never be
// able to become markup in the operator's own page.

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  cls?: string,
  text?: string | number | null,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

export function fill(host: HTMLElement, nodes: (Node | null | undefined)[] | Node): void {
  host.textContent = "";
  const list = Array.isArray(nodes) ? nodes : [nodes];
  for (const n of list) if (n) host.appendChild(n);
}

export function metaLine(pairs: Array<[string, string | number]>): HTMLElement {
  const p = el("p", "meta-line");
  for (const [k, v] of pairs) {
    const span = el("span");
    span.appendChild(document.createTextNode(k + " "));
    span.appendChild(el("b", undefined, v));
    p.appendChild(span);
  }
  return p;
}
