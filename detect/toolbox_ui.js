/* Control panel for the detect toolbox.
 *
 * Every panel is a GET against the read-only API. There is deliberately no
 * code path here that POSTs, mutates policy, or asks a node to act: acting
 * needs a signed request through authz_gate.py, which a browser cannot mint.
 *
 * All observed content (log lines, denial reasons, node notes) is written with
 * textContent, never innerHTML — the telemetry carries adversary-shaped strings on
 * purpose, and they must not be able to become markup in the operator's page.
 */
"use strict";

const $ = (id) => document.getElementById(id);

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function cell(tag, text, cls) {
  const node = el(tag, cls);
  node.textContent = text === undefined || text === null ? "—" : String(text);
  return node;
}

function table(headers, rows) {
  const t = el("table");
  const thead = el("thead");
  const hr = el("tr");
  headers.forEach((h) => hr.appendChild(cell("th", h)));
  thead.appendChild(hr);
  t.appendChild(thead);
  const tbody = el("tbody");
  rows.forEach((cells) => {
    const tr = el("tr");
    cells.forEach((c) => tr.appendChild(c));
    tbody.appendChild(tr);
  });
  t.appendChild(tbody);
  return t;
}

function kv(pairs) {
  const wrap = el("p", "kv");
  pairs.forEach(([k, v]) => {
    const span = el("span");
    span.appendChild(document.createTextNode(k + " "));
    span.appendChild(el("b", null, v));
    wrap.appendChild(span);
  });
  return wrap;
}

function setPill(id, state, text) {
  const pill = $(id);
  pill.className = "pill" + (state ? " " + state : "");
  pill.querySelector("b").textContent = text;
}

function fill(hostId, nodes) {
  const host = $(hostId);
  host.textContent = "";
  (Array.isArray(nodes) ? nodes : [nodes]).forEach((n) => n && host.appendChild(n));
}

function showError(hostId, message) {
  fill(hostId, el("p", "err", message));
}

async function getJSON(path) {
  const resp = await fetch(path, { headers: { Accept: "application/json" } });
  const body = await resp.json().catch(() => ({ error: "response was not JSON" }));
  return { status: resp.status, body };
}

/* --- gate ------------------------------------------------------------- */

async function loadGate() {
  const limit = Number($("gate-limit").value) || 25;
  try {
    const { body } = await getJSON("/gate?limit=" + encodeURIComponent(limit));
    if (body.error) throw new Error(body.error);
    const chain = body.chain || {};
    const ok = chain.ok === true;
    setPill("pill-chain", ok ? "ok" : "bad",
      ok ? "OK · " + chain.records : "BROKEN at seq " + chain.first_bad_seq);

    const parts = [kv([
      ["records", chain.records],
      ["chain", ok ? "verified" : "BROKEN at seq " + chain.first_bad_seq],
      ["allow", body.window.allow],
      ["deny", body.window.deny],
      ["showing", body.window.returned + "/" + body.window.limit],
    ])];

    if (!body.decisions.length) {
      parts.push(el("p", "empty", "no decisions recorded yet"));
    } else {
      const rows = body.decisions.slice().reverse().map((d) => [
        cell("td", d.seq, "num"),
        cell("td", (d.decision || "?").toUpperCase(), "tag " + (d.decision || "")),
        cell("td", d.action),
        cell("td", d.target, "wrap"),
        cell("td", d.reason, "wrap"),
      ]);
      parts.push(table(["seq", "decision", "action", "target", "reason"], rows));
    }
    parts.push(el("p", "empty", "hash chain is tamper-evident, not tamper-proof"));
    fill("gate-body", parts);
  } catch (err) {
    setPill("pill-chain", "bad", "unread");
    showError("gate-body", "gate view failed: " + err.message);
  }
}

/* --- detections ------------------------------------------------------- */

async function loadDetections() {
  try {
    const { body } = await getJSON("/detections");
    if (body.error) throw new Error(body.error);
    const pass = body.result === "PASS";
    setPill("pill-det", pass ? "ok" : "bad", body.result);

    const rows = body.checks.map((c) => [
      cell("td", c.ok ? "ok" : "FAIL", "tag " + (c.ok ? "ok" : "fail")),
      cell("td", c.rule, "wrap"),
      cell("td", c.fixture, "wrap"),
      cell("td", c.expect),
      cell("td", c.events, "num"),
      cell("td", c.hits, "num"),
    ]);
    const parts = [table(["", "rule", "fixture", "expect", "events", "hits"], rows)];

    const gaps = (body.coverage && body.coverage.without_fixtures) || [];
    if (gaps.length) {
      const note = el("p", "empty");
      note.textContent = gaps.length + " of " + body.coverage.rules +
        " rules have no proving fixture: " + gaps.join(", ");
      parts.push(note);
    }
    body.checks.filter((c) => c.error).forEach((c) => {
      parts.push(el("p", "err", c.rule + ": " + c.error));
    });
    fill("det-body", parts);
  } catch (err) {
    setPill("pill-det", "bad", "unread");
    showError("det-body", "detections failed: " + err.message);
  }
}

/* --- fleet ------------------------------------------------------------ */

function nodeCard(n) {
  const card = el("div", "node");
  card.appendChild(el("h3", null, n.node_id + (n.alias ? " (" + n.alias + ")" : "")));
  const dl = el("dl");
  const add = (k, v) => {
    dl.appendChild(el("dt", null, k));
    dl.appendChild(el("dd", null, v === undefined || v === null || v === "" ? "—" : v));
  };
  add("type", n.device_type);
  add("address", n.port ? n.address + ":" + n.port : n.address);
  add("sshd", n.sshd === true ? "yes" : n.sshd === false ? "no" : "—");
  add("caps", (n.allowed_capabilities || []).join(", ") || "none");
  add("tasks", (n.tasks || []).join(", ") || "none");
  if (n.note) add("note", n.note);
  card.appendChild(dl);
  return card;
}

async function loadFleet() {
  try {
    const { body } = await getJSON("/fleet");
    if (body.error) throw new Error(body.error);
    const inv = body.inventory || {};
    const parts = [kv([
      ["revision", inv.revision || "—"],
      ["nodes", (inv.nodes || []).length],
      ["events", (body.telemetry && body.telemetry.records) || 0],
    ])];

    const nodes = el("div", "nodes");
    (inv.nodes || []).forEach((n) => nodes.appendChild(nodeCard(n)));
    if (!(inv.nodes || []).length) nodes.appendChild(el("p", "empty", "inventory is empty"));
    parts.push(nodes);

    if (Array.isArray(body.layers)) {
      const stack = el("ul", "stack");
      body.layers.forEach((layer) => {
        const li = el("li");
        li.appendChild(el("span", "lv", layer.level !== undefined ? layer.level : "·"));
        li.appendChild(el("span", null, (layer.layer || layer.name || "?") +
          (layer.attested === undefined ? "" : layer.attested ? " · attested" : " · not attested")));
        stack.appendChild(li);
      });
      parts.push(stack);
    } else if (body.layers && body.layers.error) {
      parts.push(el("p", "err", "layers: " + body.layers.error));
    }

    const tel = body.telemetry || {};
    if (tel.by_event && Object.keys(tel.by_event).length) {
      const rows = Object.keys(tel.by_event).sort().map((k) => [
        cell("td", k, "wrap"), cell("td", tel.by_event[k], "num"),
      ]);
      parts.push(table(["event", "count"], rows));
    }
    if (tel.error) parts.push(el("p", "err", "telemetry: " + tel.error));
    fill("fleet-body", parts);
  } catch (err) {
    showError("fleet-body", "fleet view failed: " + err.message);
  }
}

/* --- tail ------------------------------------------------------------- */

const selectedLabels = new Set();

function renderChips(labels) {
  const host = $("tail-labels");
  host.textContent = "";
  labels.forEach((label) => {
    const chip = el("button", "chip", label);
    chip.type = "button";
    chip.setAttribute("aria-pressed", selectedLabels.has(label) ? "true" : "false");
    chip.addEventListener("click", () => {
      if (selectedLabels.has(label)) selectedLabels.delete(label);
      else selectedLabels.add(label);
      renderChips(labels);
      loadTail();
    });
    host.appendChild(chip);
  });
}

async function loadTail() {
  const lines = Number($("tail-lines").value) || 50;
  try {
    if (!selectedLabels.size) {
      const { body } = await getJSON("/tail");
      const labels = body.labels || [];
      if (labels.length) selectedLabels.add(labels[0]);
      renderChips(labels);
      if (!labels.length) {
        fill("tail-body", el("p", "empty", "no labels in the operator allowlist"));
        return;
      }
    }
    const query = Array.from(selectedLabels).map((l) => "label=" + encodeURIComponent(l)).join("&");
    const { status, body } = await getJSON("/tail?" + query + "&lines=" + encodeURIComponent(lines));
    if (status === 403) {
      showError("tail-body", "refused: " + body.error + " — approved: " + (body.approved || []).join(", "));
      return;
    }
    if (body.error) throw new Error(body.error);

    const parts = [kv([
      ["labels", (body.labels || []).join(", ")],
      ["lines", body.lines],
      ["returned", body.returned],
    ])];
    if (!body.records.length) {
      parts.push(el("p", "empty", "nothing in the window"));
    } else {
      const list = el("ul", "logs");
      body.records.slice().reverse().forEach((r) => {
        const li = el("li");
        const meta = el("div", "meta");
        meta.appendChild(el("span", null, r.ts || "—"));
        meta.appendChild(el("span", null, r.source || "—"));
        if (r.trace_id) meta.appendChild(el("span", null, "trace " + r.trace_id.slice(0, 12)));
        if (r.findings) meta.appendChild(el("span", null, r.findings + " redacted"));
        li.appendChild(meta);
        li.appendChild(el("p", "line", r.line !== undefined ? r.line : JSON.stringify(r)));
        list.appendChild(li);
      });
      parts.push(list);
    }
    fill("tail-body", parts);
  } catch (err) {
    showError("tail-body", "tail failed: " + err.message);
  }
}

/* --- shell ------------------------------------------------------------ */

async function loadHealth() {
  try {
    const { body } = await getJSON("/healthz");
    setPill("pill-srv", body.status === "ok" ? "ok" : "warn", body.status || "?");
  } catch (err) {
    setPill("pill-srv", "bad", "unreachable");
  }
}

async function loadAll() {
  $("stamp").textContent = "refreshing…";
  await Promise.all([loadHealth(), loadGate(), loadDetections(), loadFleet(), loadTail()]);
  $("stamp").textContent = "updated " + new Date().toLocaleTimeString();
}

let autoTimer = null;

function setAuto(seconds) {
  if (autoTimer) {
    clearInterval(autoTimer);
    autoTimer = null;
  }
  if (seconds > 0) autoTimer = setInterval(loadAll, seconds * 1000);
}

const THEMES = ["system", "light", "dark"];

function applyTheme(name) {
  if (name === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", name);
  try {
    localStorage.setItem("detect-toolbox-theme", name);
  } catch (err) {
    /* private window or blocked storage: the theme just does not persist */
  }
}

function initTheme() {
  let stored = "system";
  try {
    stored = localStorage.getItem("detect-toolbox-theme") || "system";
  } catch (err) {
    stored = "system";
  }
  if (!THEMES.includes(stored)) stored = "system";
  applyTheme(stored);
  $("theme").addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme") || "system";
    applyTheme(THEMES[(THEMES.indexOf(current) + 1) % THEMES.length]);
  });
}

function init() {
  initTheme();
  $("refresh").addEventListener("click", loadAll);
  $("det-run").addEventListener("click", loadDetections);
  $("gate-limit").addEventListener("change", loadGate);
  $("tail-lines").addEventListener("change", loadTail);
  $("auto").addEventListener("change", (e) => setAuto(Number(e.target.value)));
  loadAll();
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
else init();
