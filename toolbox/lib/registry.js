'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');

const HOME = os.homedir();
const ROOT = path.join(HOME, 'toolbox');
const CONFIG_PATH = path.join(ROOT, 'config.json');
const REGISTRY_PATH = path.join(ROOT, 'registry.json');
const INTERPRETERS = { '.sh':'bash', '.py':'python3', '.js':'node', '.ts':'node', '.rb':'ruby' };

const expand = p => p.startsWith('~') ? path.join(HOME, p.slice(1)) : p;
const loadConfig = () => JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
const slugify = s => s.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
const titleize = s => s.replace(/[_-]+/g,' ').replace(/\b\w/g, c => c.toUpperCase());

// Read up to first 2KB of a script for self-describing metadata:
//   # @tb name: ...   # @tb desc: ...   # @tb category: ...
function readMeta(file){
  let head = '';
  try {
    const fd = fs.openSync(file, 'r');
    const buf = Buffer.alloc(2048);
    const n = fs.readSync(fd, buf, 0, 2048, 0);
    fs.closeSync(fd);
    head = buf.slice(0, n).toString('utf8');
  } catch(e){ return {}; }
  const lines = head.split('\n').slice(0, 25);
  const meta = {};
  for (const l of lines){
    let m;
    if ((m = l.match(/@tb\s+name:\s*(.+)/i)))                 meta.name = m[1].trim();
    if ((m = l.match(/@tb\s+desc(?:ription)?:\s*(.+)/i)))     meta.description = m[1].trim();
    if ((m = l.match(/@tb\s+cat(?:egory)?:\s*(.+)/i)))        meta.category = m[1].trim();
  }
  // fallback: first human comment line becomes the description
  if (!meta.description){
    for (const l of lines){
      const t = l.trim();
      if (t.startsWith('#!') || /@tb/.test(t)) continue;
      const c = t.match(/^#+\s*(.+)/) || t.match(/^\/\/\s*(.+)/) || t.match(/^"""\s*(.+)/);
      if (c && c[1] && c[1].length > 3){ meta.description = c[1].trim(); break; }
    }
  }
  return meta;
}

function walk(dir, maxDepth, ignore, exts, out, depth = 0){
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch(e){ return; }
  for (const e of entries){
    const full = path.join(dir, e.name);
    if (ignore.some(ig => full.includes('/' + ig))) continue;
    if (e.isDirectory()){
      if (depth < maxDepth) walk(full, maxDepth, ignore, exts, out, depth + 1);
    } else if (e.isFile()){
      if (exts.includes(path.extname(e.name).toLowerCase())) out.push(full);
    }
  }
}

function build(){
  const cfg = loadConfig();
  const files = [];
  for (const src of cfg.sources){
    const dir = expand(src);
    const md = (dir === HOME) ? 0 : (cfg.maxDepth || 2);   // home: top-level only (no noise)
    walk(dir, md, cfg.ignore || [], cfg.extensions, files);
  }
  const seen = new Set();
  const items = [];
  for (const f of files.sort()){
    if (seen.has(f) || f.startsWith(ROOT)) continue;
    seen.add(f);
    const ext = path.extname(f).toLowerCase();
    const base = path.basename(f, ext);
    const meta = readMeta(f);
    const name = meta.name || titleize(base);
    const category = meta.category || path.basename(path.dirname(f));
    let id = slugify(meta.name || base), uid = id, i = 2;
    while (items.find(x => x.id === uid)) uid = id + '-' + (i++);
    let st; try { st = fs.statSync(f); } catch(e){ st = { mtimeMs:0, size:0 }; }
    items.push({
      id: uid, name, description: meta.description || '', category,
      path: f, lang: ext.slice(1), interpreter: INTERPRETERS[ext] || 'bash',
      mtime: Math.round(st.mtimeMs), size: st.size
    });
  }
  items.sort((a,b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
  const registry = { generated: new Date().toISOString(), count: items.length, items };
  fs.writeFileSync(REGISTRY_PATH, JSON.stringify(registry, null, 2));
  return registry;
}

function load(){
  try { return JSON.parse(fs.readFileSync(REGISTRY_PATH, 'utf8')); }
  catch(e){ return build(); }
}

module.exports = { build, load, loadConfig, ROOT, REGISTRY_PATH, INTERPRETERS };
