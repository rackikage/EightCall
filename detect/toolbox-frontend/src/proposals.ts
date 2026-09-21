// The approval queue panel. Scripts are PROPOSED here and fired only after the
// operator authorizes: authorize types the proposal id back, then the server
// re-binds args, asks the gate, and runs the same spine as /api/run. Nothing in
// this file acts on its own.
//
// All observed text is written with textContent (see dom.ts) — proposal notes
// and denial reasons are strings the telemetry may carry on purpose.

import { api, type Proposal } from "./api";
import { el, fill } from "./dom";

const STATUS_CLASS: Record<string, string> = {
  pending: "warn",
  authorized: "ok",
  fired: "ok",
  failed: "fail",
  rejected: "fail",
};

function badge(status: string): HTMLElement {
  return el("span", `badge ${STATUS_CLASS[status] ?? ""}`, status);
}

function row(p: Proposal, reload: () => void): HTMLElement {
  const box = el("div", "cap");
  const head = el("div", "cap-head");
  head.appendChild(el("span", "cap-label", p.capability));
  head.appendChild(badge(p.status));
  head.appendChild(el("span", "cap-id mono", p.id));
  box.appendChild(head);

  const meta = el("p", "meta-line");
  meta.appendChild(el("span", undefined, `by ${p.created_by}`));
  if (p.note) meta.appendChild(el("span", undefined, p.note));
  if (p.decision_id) meta.appendChild(el("span", undefined, `allow ${p.decision_id}`));
  if (p.reason) meta.appendChild(el("span", undefined, p.reason));
  box.appendChild(meta);

  box.appendChild(el("pre", "out mono", JSON.stringify(p.args ?? {}, null, 2)));

  if (p.status === "pending") {
    const ctl = el("div", "cap-controls");

    const approve = el("button", "primary", "authorize") as HTMLButtonElement;
    approve.addEventListener("click", async () => {
      const typed = window.prompt(
        `Authorize ${p.capability}\n\nThis will fire through the gate.\nType the proposal id to confirm:\n${p.id}`,
      );
      if (typed !== p.id) return;
      const { status, body } = await api.authorizeProposal(p.id, p.id);
      if (!body.ok) window.alert(`${status} — ${body.error ?? "refused"}`);
      reload();
    });

    const reject = el("button", "danger", "reject") as HTMLButtonElement;
    reject.addEventListener("click", async () => {
      const reason = window.prompt("Reason for rejection (optional):") ?? "";
      await api.rejectProposal(p.id, reason);
      reload();
    });

    ctl.append(approve, reject);
    box.appendChild(ctl);
  }
  return box;
}

export function proposalsPanel(): HTMLElement {
  const section = el("section", "panel");
  const head = el("div", "panel-head");
  head.appendChild(el("h2", undefined, "proposals"));
  const refresh = el("button", undefined, "refresh") as HTMLButtonElement;
  head.appendChild(refresh);
  section.appendChild(head);
  section.appendChild(
    el(
      "p",
      "hint",
      "Scripts are proposed, never fired directly. Authorize types the proposal id back; " +
        "the server then re-binds args, asks the gate, and runs the same spine as a manual run.",
    ),
  );

  const body = el("div");
  section.appendChild(body);

  const load = async () => {
    fill(body, el("p", "empty", "loading…"));
    try {
      const { body: doc } = await api.proposals();
      const items = (doc.proposals ?? []).slice().reverse();
      if (!items.length) {
        fill(body, el("p", "empty", "no proposals"));
        return;
      }
      fill(body, items.map((p) => row(p, load)));
    } catch (e) {
      fill(body, el("p", "err", (e as Error).message));
    }
  };

  refresh.addEventListener("click", load);
  load();
  return section;
}
