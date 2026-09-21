'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');
const reg = require(path.join(__dirname, 'registry.js'));

const HOME = os.homedir();
const ROOT = path.join(HOME, 'toolbox');
const MONITOR_PATH = path.join(ROOT, 'monitor.json');
const RUNS_DIR = path.join(ROOT, 'runs');
const expand = p => p.startsWith('~') ? path.join(HOME, p.slice(1)) : p;
const cfg = () => reg.loadConfig();

// ---- explicit state, read ONLY from the folder name ----
function stateOf(name){
  const n = name.toLowerCase();
  if (n.includes('(r)')) return 'ready';      // Ready  -> eligible for dispatch
  if (n.includes('(t)')) return 'thinking';   // Thinking -> inspect only
  return null;                                // unlabelled -> leave alone
}

// ---- discover real, tagged folders under the watch roots ----
function discover(){
  const c = cfg();
  const roots = (c.watchRoots && c.watchRoots.length ? c.watchRoots : ['~/toolbox/watch']).map(expand);
  const depth = c.watchDepth || 3;
  const ignore = c.ignore || [];
  const found = [];
  function walk(dir, d){
    let ents; try { ents = fs.readdirSync(dir, { withFileTypes:true }); } catch(e){ return; }
    for (const e of ents){
      if (!e.isDirectory() || ignore.includes(e.name)) continue;
      const full = path.join(dir, e.name);
      const st = stateOf(e.name);
      if (st){ found.push({ folder: full, name: e.name, state: st }); continue; } // tagged = atomic, don't descend
      if (d < depth) walk(full, d + 1);
    }
  }
  for (const r of roots) if (fs.existsSync(r)) walk(r, 0);
  return found;
}

// ---- resolve a folder's DEFINED launch target (never a catch-all) ----
function resolveTarget(folder, name){
  for (const fn of ['tb.launch.json', '.tb-launch.json']){
    const p = path.join(folder, fn);
    if (fs.existsSync(p)){ try { return normalize(JSON.parse(fs.readFileSync(p,'utf8'))); } catch(e){} }
  }
  const lt = cfg().launchTargets || {};
  for (const key of Object.keys(lt)){
    let m = false; try { m = new RegExp(key).test(name); } catch(e){ m = name.includes(key); }
    if (m) return normalize(lt[key]);
  }
  return null;
}
function normalize(j){
  if (!j) return null;
  const t = { script: j.script || j.main || null, nodes: j.nodes || [], args: j.args || [] };
  return (t.script || t.nodes.length) ? t : null;
}
function interpreterFor(p){ return reg.INTERPRETERS[path.extname(p).toLowerCase()] || 'bash'; }
function resolveScriptPath(ref){
  if (!ref) return null;
  if (String(ref).includes('/')){ const p = expand(ref); return { path:p, interpreter:interpreterFor(p), name:path.basename(p) }; }
  const it = reg.load().items.find(x => x.id === ref);
  return it ? { path: it.path, interpreter: it.interpreter, name: it.name } : null;
}

// ---- launch ONE script/node for a dispatch; detached, logged, exit-tracked ----
function launchOne(dispatchId, tag, ref, folder, args){
  const r = resolveScriptPath(ref);
  if (!r) return { node: ref, status: 'error', error: 'unresolved id/path' };
  if (!fs.existsSync(r.path)) return { node: ref, path: r.path, status: 'error', error: 'file missing' };
  fs.mkdirSync(RUNS_DIR, { recursive: true });
  const safe = (dispatchId + '__' + tag).replace(/[^a-zA-Z0-9_.-]/g, '_');
  const logf = path.join(RUNS_DIR, safe + '.log');
  const exitf = path.join(RUNS_DIR, safe + '.exit');
  try { fs.unlinkSync(exitf); } catch(e){}
  const q = a => `'${String(a).replace(/'/g, `'\\''`)}'`;
  const argv = [r.path, folder, ...args].map(q).join(' ');
  const cmd = `${r.interpreter} ${argv} > ${q(logf)} 2>&1; echo $? > ${q(exitf)}`;
  const child = spawn('/bin/sh', ['-c', cmd], { cwd: folder, detached: true, stdio: 'ignore' });
  const pid = child.pid; child.unref();
  return { node: ref, label: r.name, path: r.path, interpreter: r.interpreter,
           pid, log: logf, exit: exitf, startedAt: new Date().toISOString(), status: 'running' };
}

function dispatch(entry){
  const t = entry.target;
  const id = crypto.createHash('md5').update(entry.folder + '|' + JSON.stringify(t)).digest('hex').slice(0, 10);
  const runs = [];
  if (t.script) runs.push(launchOne(id, 'main', t.script, entry.folder, t.args));
  (t.nodes || []).forEach((n, i) => runs.push(launchOne(id, 'node' + i + '_' + n, n, entry.folder, t.args)));
  return { id, dispatchedAt: new Date().toISOString(), runs, status: 'running' };
}

function refreshRun(run){
  if (!run || run.status === 'error') return run;
  try {
    if (run.exit && fs.existsSync(run.exit)){
      const code = parseInt(String(fs.readFileSync(run.exit,'utf8')).trim(), 10);
      run.exitCode = isNaN(code) ? null : code;
      run.status = code === 0 ? 'done' : 'failed';
    } else {
      let alive = false; try { process.kill(run.pid, 0); alive = true; } catch(e){}
      run.status = alive ? 'running' : 'ended';
    }
    if (run.log && fs.existsSync(run.log)) run.outputTail = fs.readFileSync(run.log,'utf8').slice(-4000);
  } catch(e){}
  return run;
}
function refreshDispatch(d){
  if (!d) return d;
  d.runs = (d.runs || []).map(refreshRun);
  const s = d.runs.map(r => r.status);
  d.status = s.includes('running') ? 'running'
           : (s.includes('failed') || s.includes('error')) ? 'failed'
           : s.every(x => x === 'done') ? 'done' : 'partial';
  return d;
}

const loadMonitor = () => { try { return JSON.parse(fs.readFileSync(MONITOR_PATH,'utf8')); } catch(e){ return { generated:null, entries:{} }; } };
const saveMonitor = m => { m.generated = new Date().toISOString(); fs.writeFileSync(MONITOR_PATH, JSON.stringify(m, null, 2)); };

// refresh dispatch states only — NO new dispatch, NO discovery side effects
function refreshOnly(){
  const m = loadMonitor();
  for (const e of Object.values(m.entries || {})) if (e.dispatch) e.dispatch = refreshDispatch(e.dispatch);
  saveMonitor(m); return m;
}

// the strict reconcile: disk truth -> monitor
function reconcile(opts = {}){
  const m = loadMonitor();
  const entries = m.entries || {};
  const seen = new Set();
  for (const d of discover()){
    seen.add(d.folder);
    let e = entries[d.folder] || (entries[d.folder] = { folder: d.folder, firstSeen: new Date().toISOString() });
    e.name = d.name; e.state = d.state; e.present = true; e.lastSeen = new Date().toISOString();

    if (d.state === 'thinking'){
      e.target = resolveTarget(d.folder, d.name) || null;   // may inspect/infer
      e.dispatch = null;                                    // but NEVER dispatch
      e.note = 'thinking — inspect only, not dispatched';
    } else if (d.state === 'ready'){
      const target = resolveTarget(d.folder, d.name);
      e.target = target;
      if (!target){ e.note = 'ready, but no defined launch target — not dispatched'; }
      else {
        const sig = crypto.createHash('md5').update(JSON.stringify(target)).digest('hex').slice(0, 8);
        if (!e.dispatch || e.dispatchSig !== sig || opts.force){
          e.dispatch = dispatch(e); e.dispatchSig = sig; e.note = 'dispatched';
        } else {
          e.dispatch = refreshDispatch(e.dispatch);        // already fired: just track it
        }
      }
    }
  }
  // reconcile vanished folders — keep real dispatch history, drop phantoms
  for (const k of Object.keys(entries)){
    if (seen.has(k)) continue;
    if (entries[k].dispatch){ entries[k].present = false; entries[k].state = 'gone'; entries[k].note = 'folder gone from disk (dispatch history kept)'; entries[k].dispatch = refreshDispatch(entries[k].dispatch); }
    else delete entries[k];   // never dispatched + not on disk = hypothetical, remove
  }
  m.entries = entries; saveMonitor(m); return m;
}

module.exports = { discover, reconcile, refreshOnly, loadMonitor, resolveTarget, RUNS_DIR, MONITOR_PATH };
