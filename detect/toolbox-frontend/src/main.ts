import "./style.css";
import "./theme.css";
import { api, pointer, type Capability, type ArgSpec, type Envelope, type Opt, type RegistryDoc } from "./api";
import { el, fill } from "./dom";
import { proposalsPanel } from "./proposals";

// The whole UI is derived from /api/registry. There is no per-capability code
// in this file: controls come from an entry's `args`, routing comes from its
// `runner`, presentation comes from its `output.kind`. Adding a command to the
// registry makes it appear here with no edit.
//
// All observed text is written with textContent (see dom.ts) — the telemetry carries
// adversary-shaped strings on purpose and they must never become markup.

const app = document.getElementById("app")!;
app.textContent = "";

let REG: RegistryDoc | null = null;
const argState = new Map<string, Record<string, unknown>>(); // capId -> args
const previewTokens = new Map<string, string>(); // previewCapId -> token
const timers = new Map<string, ReturnType<typeof setInterval>>();

// ---------------------------------------------------------------- shell ---

const topbar = el("div", "topbar");
const mark = el("div", "mark");
mark.appendChild(document.createTextNode("detect"));
mark.appendChild(el("span", undefined, "toolbox"));
topbar.appendChild(mark);
const statusRow = el("div", "status-row");
topbar.appendChild(statusRow);
const toolrow = el("div", "toolrow");
const refreshBtn = el("button", undefined, "refresh");
const themeBtn = el("button", undefined, "theme");
toolrow.append(refreshBtn, themeBtn);
topbar.appendChild(toolrow);
app.appendChild(topbar);

const panelHost = el("div");
app.appendChild(panelHost);

const footer = el("footer");
const stamp = el("span", undefined, "—");
const shaNote = el("span");
footer.append(stamp, shaNote);
app.appendChild(footer);

function pill(id: string, label: string) {
  const span = el("span");
  span.id = id;
  span.appendChild(el("span", "dot"));
  span.appendChild(document.createTextNode(label + " "));
  const b = el("b", "val", "…");
  span.appendChild(b);
  statusRow.appendChild(span);
}
pill("pill-srv", "server");
pill("pill-reg", "registry");

function setPill(id: string, state: "ok" | "bad" | "warn" | "", text: string) {
  const n = document.getElementById(id);
  if (!n) return;
  n.className = state;
  n.querySelector(".val")!.textContent = text;
}

// ------------------------------------------------------------- controls ---

function argsOf(cap: Capability): ArgSpec[] {
  if (Array.isArray(cap.args)) return cap.args;
  const target = REG?.capabilities.find((c) => c.id === (cap.args as { from: string }).from);
  return target && Array.isArray(target.args) ? target.args : [];
}

function stateFor(cap: Capability): Record<string, unknown> {
  let s = argState.get(cap.id);
  if (!s) {
    s = {};
    for (const a of argsOf(cap)) if (a.default !== undefined) s[a.name] = a.default;
    argState.set(cap.id, s);
  }
  return s;
}

async function buildControl(cap: Capability, arg: ArgSpec, onChange: () => void): Promise<HTMLElement | null> {
  const st = stateFor(cap);
  const wrap = el("label", "ctl-arg");
  wrap.appendChild(el("span", "ctl-label", arg.label));

  if (arg.kind === "server") {
    wrap.appendChild(el("span", "ctl-server", "server-generated"));
    return wrap;
  }

  if (arg.kind === "int") {
    const input = el("input") as HTMLInputElement;
    input.type = "number";
    if (arg.min !== undefined) input.min = String(arg.min);
    if (arg.max !== undefined) input.max = String(arg.max);
    if (st[arg.name] !== undefined) input.value = String(st[arg.name]);
    input.addEventListener("change", () => {
      st[arg.name] = input.value === "" ? undefined : Number(input.value);
      onChange();
    });
    wrap.appendChild(input);
    return wrap;
  }

  if (arg.kind === "bool") {
    const input = el("input") as HTMLInputElement;
    input.type = "checkbox";
    input.checked = Boolean(st[arg.name]);
    input.addEventListener("change", () => {
      st[arg.name] = input.checked;
      onChange();
    });
    wrap.appendChild(input);
    return wrap;
  }

  // enum / multi-enum: options always come from the server
  const dep = arg.depends_on ? String(st[arg.depends_on] ?? "") : undefined;
  let opts: Opt[] = [];
  try {
    const { body } = await api.options(cap.id, arg.name, dep || undefined);
    opts = body.options ?? [];
  } catch {
    opts = [];
  }

  if (arg.kind === "multi-enum") {
    const chips = el("span", "chips");
    const selected = new Set<string>((st[arg.name] as string[]) ?? []);
    for (const o of opts) {
      const chip = el("button", "chip", o.label) as HTMLButtonElement;
      chip.type = "button";
      chip.setAttribute("aria-pressed", selected.has(o.value) ? "true" : "false");
      chip.addEventListener("click", () => {
        selected.has(o.value) ? selected.delete(o.value) : selected.add(o.value);
        st[arg.name] = Array.from(selected);
        chip.setAttribute("aria-pressed", selected.has(o.value) ? "true" : "false");
        onChange();
      });
      chips.appendChild(chip);
    }
    if (!opts.length) chips.appendChild(el("span", "ctl-server", "no options"));
    wrap.appendChild(chips);
    return wrap;
  }

  const select = el("select") as HTMLSelectElement;
  if (!arg.required) {
    const blank = document.createElement("option");
    blank.value = "";
    blank.textContent = "—";
    select.appendChild(blank);
  }
  for (const o of opts) {
    const opt = document.createElement("option");
    opt.value = o.value;
    opt.textContent = o.label;
    select.appendChild(opt);
  }
  const current = st[arg.name];
  if (current !== undefined && opts.some((o) => o.value === current)) select.value = String(current);
  else if (arg.required && opts.length) {
    select.value = opts[0].value;
    st[arg.name] = opts[0].value;
  }
  select.addEventListener("change", () => {
    st[arg.name] = select.value || undefined;
    onChange();
  });
  wrap.appendChild(select);
  return wrap;
}

// ------------------------------------------------------------ renderers ---

function tag(text: string, good: boolean): HTMLElement {
  return el("span", `c-tag ${good ? "ok" : "fail"}`, text);
}

function renderOutput(cap: Capability, env: Envelope): HTMLElement {
  const host = el("div", "out");
  const spec = cap.output;
  const out = (env.output ?? {}) as NonNullable<Envelope["output"]>;
  const data = out.data;

  const kind = spec.kind;

  if (kind === "table") {
    if (spec.facts?.length) {
      const facts = el("p", "meta-line");
      for (const f of spec.facts) {
        const v = pointer(data, f.path);
        const span = el("span");
        span.appendChild(document.createTextNode(f.label + " "));
        if (f.as === "tag") span.appendChild(tag(String(v), v === true || v === "PASS" || v === "allow"));
        else span.appendChild(el("b", undefined, v === undefined || v === null ? "—" : String(v)));
        facts.appendChild(span);
      }
      host.appendChild(facts);
    }
    let rows = (pointer(data, spec.rows ?? "") as unknown[]) ?? [];
    if (!Array.isArray(rows)) rows = [];
    if (spec.reverse) rows = rows.slice().reverse();
    if (!rows.length) {
      host.appendChild(el("p", "empty", spec.empty ?? "nothing to show"));
      return host;
    }
    const table = el("div", "rows");
    const head = el("div", "row gen-row");
    head.style.gridTemplateColumns = `repeat(${spec.columns?.length ?? 1}, minmax(0,1fr))`;
    for (const c of spec.columns ?? []) head.appendChild(el("span", "col-head", c.label));
    table.appendChild(head);
    for (const r of rows.slice(0, 200)) {
      const tr = el("div", "row gen-row");
      tr.style.gridTemplateColumns = `repeat(${spec.columns?.length ?? 1}, minmax(0,1fr))`;
      for (const c of spec.columns ?? []) {
        const v = pointer(r, c.path);
        if (c.as === "tag") tr.appendChild(tag(String(v ?? "—"), v === "allow" || v === true || v === "ok"));
        else tr.appendChild(el("span", c.as === "code" ? "c-wrap mono" : "c-wrap c-dim", v === undefined || v === null ? "—" : String(v)));
      }
      table.appendChild(tr);
    }
    host.appendChild(table);
    return host;
  }

  if (kind === "argv-preview") {
    const argv = (pointer(data, spec.argv ?? "/argv") as string[]) ?? env.attribution?.argv ?? [];
    host.appendChild(el("p", "argv mono", "$ " + (Array.isArray(argv) ? argv.join(" ") : String(argv))));
    if (out.stderr) host.appendChild(el("pre", "out mono", out.stderr));
    return host;
  }

  if (kind === "pass-fail") {
    const verdict = spec.verdict ? pointer(data, spec.verdict) : (data as any)?.result;
    const good = verdict === "PASS" || verdict === true || out.exit_code === 0;
    host.appendChild(tag(String(verdict ?? (good ? "PASS" : "FAIL")), good));
    if (out.stdout) host.appendChild(el("pre", "out mono", out.stdout));
    return host;
  }

  if (kind === "log-stream") {
    const lines = (out.lines as string[]) ?? [];
    const box = el("div", "demo-log");
    if (!lines.length) box.appendChild(el("div", "empty", "no output yet"));
    else for (const l of lines.slice(-200)) box.appendChild(el("div", undefined, l));
    host.appendChild(box);
    return host;
  }

  if (kind === "json" || kind === "json-stream") {
    const text = out.stdout ?? JSON.stringify(data, null, 2);
    host.appendChild(el("pre", "out mono", text ?? ""));
    return host;
  }

  // text-lines (and any future kind) degrade to readable output
  const text = [out.stdout, out.stderr].filter(Boolean).join("\n");
  host.appendChild(el("pre", "out mono", text || "(no output)"));
  return host;
}

// ------------------------------------------------------------ capability --

async function renderCapability(cap: Capability): Promise<HTMLElement> {
  const box = el("div", "cap");
  const head = el("div", "cap-head");
  head.appendChild(el("span", "cap-label", cap.label));
  if (cap.mutating) head.appendChild(el("span", "badge mut", "mutating"));
  if (cap.authz) head.appendChild(el("span", "badge gated", "gated"));
  if (cap.enabled === false) head.appendChild(el("span", "badge off", "disabled"));
  head.appendChild(el("span", "cap-id mono", cap.id));
  box.appendChild(head);
  box.appendChild(el("p", "cap-summary", cap.summary));

  const result = el("div", "cap-result");
  const controls = el("div", "cap-controls");

  const rerenderControls = async () => {
    const built: HTMLElement[] = [];
    for (const a of argsOf(cap)) {
      const c = await buildControl(cap, a, () => {
        // a dependent arg's option set changes when its parent changes
        if (argsOf(cap).some((x) => x.depends_on === a.name)) rerenderControls();
      });
      if (c) built.push(c);
    }
    fill(controls, [...built, ...actions(cap, result)]);
  };
  await rerenderControls();

  box.append(controls, result);
  if (cap.docs?.hazard) box.appendChild(el("p", "hazard", cap.docs.hazard));
  if (cap.writes?.length) box.appendChild(el("p", "hint", "writes: " + cap.writes.join(", ")));
  if (cap.enabled === false && cap.docs?.notes) box.appendChild(el("p", "hint", cap.docs.notes));
  return box;
}

function actions(cap: Capability, result: HTMLElement): HTMLElement[] {
  if (cap.enabled === false) return [];
  const out: HTMLElement[] = [];

  const invoke = async (extra: { confirm?: string; preview_token?: string } = {}) => {
    fill(result, el("p", "empty", "running…"));
    const args = { ...stateFor(cap) };
    try {
      const { status, body } =
        cap.runner === "read_view" ? await api.read(cap.id, args) : await api.run(cap.id, { args, ...extra });
      if (!body.ok && body.error) {
        fill(result, el("p", "err", `${status} — ${body.error}`));
        return;
      }
      if (body.preview_token) previewTokens.set(cap.id, body.preview_token);
      const rendered = renderOutput(cap, body);
      const meta = el("p", "hint");
      const bits = [`${body.duration_ms ?? 0}ms`];
      if (body.attribution?.authz_decision_id) bits.push(`allow ${body.attribution.authz_decision_id}`);
      if (body.preview_token) bits.push("preview token held");
      meta.textContent = bits.join(" · ");
      fill(result, [rendered, meta]);
      if (cap.runner === "service") pollService(cap, result);
    } catch (e) {
      fill(result, el("p", "err", (e as Error).message));
    }
  };

  if (cap.runner === "service") {
    const start = el("button", "primary", "start") as HTMLButtonElement;
    start.addEventListener("click", () => invoke({ confirm: "yes" }));
    const stop = el("button", "danger", "stop") as HTMLButtonElement;
    stop.addEventListener("click", async () => {
      await api.serviceStop(cap.id);
      pollService(cap, result);
    });
    out.push(start, stop);
    pollService(cap, result);
    return out;
  }

  const label = cap.runner === "read_view" ? "load" : "run";
  const btn = el("button", cap.mutating ? "primary" : undefined, label) as HTMLButtonElement;
  btn.addEventListener("click", async () => {
    const mode = cap.confirm ?? "none";
    const extra: { confirm?: string; preview_token?: string } = {};
    if (mode === "click") {
      if (!window.confirm(`${cap.label}\n\n${cap.summary}\n\nWrites: ${(cap.writes ?? ["—"]).join(", ")}\n\nProceed?`))
        return;
      extra.confirm = "yes";
    } else if (mode === "type-id") {
      const typed = window.prompt(`This contacts a real host.\n\nType the capability id to confirm:\n${cap.id}`);
      if (typed !== cap.id) return;
      extra.confirm = cap.id;
    }
    if (cap.requires_preview) {
      const tok = previewTokens.get(cap.requires_preview);
      if (!tok) {
        fill(result, el("p", "err", `run "${cap.requires_preview}" first — an execute needs the preview you saw`));
        return;
      }
      extra.preview_token = tok;
      previewTokens.delete(cap.requires_preview);
    }
    await invoke(extra);
  });
  out.push(btn);
  return out;
}

async function pollService(cap: Capability, result: HTMLElement) {
  const tick = async () => {
    const { body } = await api.serviceStatus(cap.id);
    const box = el("div", "out");
    const meta = el("p", "meta-line");
    const s = el("span");
    s.appendChild(document.createTextNode("state "));
    s.appendChild(tag(body.running ? "running" : "idle", body.running));
    meta.appendChild(s);
    if (body.pid) {
      const p = el("span");
      p.appendChild(document.createTextNode("pid "));
      p.appendChild(el("b", undefined, body.pid));
      meta.appendChild(p);
    }
    if (body.exit_code !== null && body.exit_code !== undefined) {
      const x = el("span");
      x.appendChild(document.createTextNode("exit "));
      x.appendChild(el("b", undefined, body.exit_code));
      meta.appendChild(x);
    }
    box.appendChild(meta);
    const log = el("div", "demo-log");
    if (!body.lines.length) log.appendChild(el("div", "empty", "no output yet"));
    else for (const l of body.lines.slice(-200)) log.appendChild(el("div", undefined, l));
    box.appendChild(log);
    fill(result, box);
    log.scrollTop = log.scrollHeight;

    if (!body.running) {
      const t = timers.get(cap.id);
      if (t) {
        clearInterval(t);
        timers.delete(cap.id);
      }
    }
  };
  await tick();
  if (!timers.has(cap.id)) timers.set(cap.id, setInterval(tick, 1000));
}

// --------------------------------------------------------------- assembly --

async function boot() {
  stamp.textContent = "loading registry…";
  const [{ body: reg }, { body: health }] = await Promise.all([api.registry(), api.healthz()]);
  REG = reg;
  setPill("pill-srv", health.status === "ok" ? "ok" : "bad", health.sidecar === "ok" ? "ok" : `sidecar ${health.sidecar}`);
  setPill("pill-reg", "ok", `${reg.capabilities.length} caps`);
  shaNote.textContent = `registry ${reg.sha256 ?? ""}`;

  const panels = new Map<string, Capability[]>();
  for (const c of reg.capabilities) {
    const key = c.dashboard?.panel ?? c.group ?? "other";
    if (!panels.has(key)) panels.set(key, []);
    panels.get(key)!.push(c);
  }

  panelHost.textContent = "";
  // The approval queue sits first: it is the operator's decision surface.
  panelHost.appendChild(proposalsPanel());

  const ordered = Array.from(panels.entries()).sort((a, b) => {
    const oa = Math.min(...a[1].map((c) => c.dashboard?.order ?? 99));
    const ob = Math.min(...b[1].map((c) => c.dashboard?.order ?? 99));
    return oa - ob;
  });

  for (const [panel, caps] of ordered) {
    const section = el("section", "panel");
    const head = el("div", "panel-head");
    head.appendChild(el("h2", undefined, panel));
    section.appendChild(head);
    caps.sort((a, b) => (a.dashboard?.order ?? 99) - (b.dashboard?.order ?? 99));
    for (const c of caps) section.appendChild(await renderCapability(c));
    panelHost.appendChild(section);
  }
  stamp.textContent = "updated " + new Date().toLocaleTimeString();
}

refreshBtn.addEventListener("click", boot);

const THEMES = ["system", "light", "dark"] as const;
function applyTheme(name: string) {
  if (name === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", name);
  try {
    localStorage.setItem("detect-toolbox-theme", name);
  } catch {
    /* blocked storage: theme just does not persist */
  }
}
(function initTheme() {
  let stored = "system";
  try {
    stored = localStorage.getItem("detect-toolbox-theme") || "system";
  } catch {
    stored = "system";
  }
  if (!(THEMES as readonly string[]).includes(stored)) stored = "system";
  applyTheme(stored);
  themeBtn.addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-theme") || "system";
    applyTheme(THEMES[(THEMES.indexOf(cur as any) + 1) % THEMES.length]);
  });
})();

boot().catch((e) => {
  fill(panelHost, el("p", "err", "failed to load registry: " + (e as Error).message));
});
