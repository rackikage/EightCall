'use strict';
const http = require('http');
const path = require('path');
const { spawn } = require('child_process');
const reg = require(path.join(__dirname, 'lib', 'registry.js'));
const mon = require(path.join(__dirname, 'lib', 'monitor.js'));
const cfg = reg.loadConfig();
const HOST = cfg.host || '127.0.0.1';
const PORT = cfg.port || 7842;
const RUN_TIMEOUT = (cfg.runTimeoutSec || 45) * 1000;

function page(){
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>toolbox</title>
<style>
 :root{--bg:#000;--panel:#0a0a16;--line:#1c1c33;--fg:#E8E8FF;--dim:#6a6a9a;
  --cyan:#00F0FF;--mag:#E05CFF;--violet:#B967FF;--mint:#05FFA1;--rose:#FF2E63;--gold:#FFD300}
 *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--fg);
  font-family:"VictorMono Nerd Font","Victor Mono",ui-monospace,Menlo,monospace;min-height:100vh;padding:36px 16px}
 .wrap{max-width:820px;margin:0 auto}
 h1{font-size:22px;margin:0 0 2px;letter-spacing:1px}
 h1 .g{background:linear-gradient(90deg,var(--cyan),var(--violet),var(--mag));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
 .sub{color:var(--dim);font-size:12px;margin-bottom:22px}
 h2{font-size:12px;text-transform:uppercase;letter-spacing:2px;color:var(--violet);margin:26px 0 10px;display:flex;align-items:center;gap:10px}
 h2 button{margin-left:auto}
 .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px}
 button{border:0;border-radius:9px;padding:9px 16px;font:inherit;font-weight:700;font-size:13px;cursor:pointer;transition:.15s}
 .run{background:var(--cyan);color:#001015} .run:hover{box-shadow:0 0 20px rgba(0,240,255,.5)}
 .ghost{background:transparent;color:var(--violet);border:1px solid var(--line)} .ghost:hover{border-color:var(--violet)}
 #mon.busy{opacity:.5}
 .ent{border:1px solid var(--line);border-left-width:3px;border-radius:10px;padding:12px 14px;margin-bottom:10px;background:#05050e}
 .ent.ready{border-left-color:var(--mint)} .ent.thinking{border-left-color:var(--gold)} .ent.gone{border-left-color:var(--dim);opacity:.6}
 .badge{font-weight:700;font-size:11px;letter-spacing:1px;padding:2px 8px;border-radius:6px}
 .badge.ready{color:#012;background:var(--mint)} .badge.thinking{color:#210;background:var(--gold)} .badge.gone{color:#fff;background:#333}
 .nm{margin-left:10px;font-weight:700} .path{color:var(--dim);font-size:11px;margin:6px 0}
 .note{font-size:12px;color:var(--dim)} .note.warn{color:var(--gold)}
 .disp{color:var(--violet);font-size:12px;margin-top:6px}
 .run.done{color:var(--mint)} .run.failed,.run.error{color:var(--rose)} .run.running{color:var(--gold)} .run.ended{color:var(--dim)}
 .run{font-size:12px;margin:3px 0 0 8px;background:none;padding:0;cursor:default;font-weight:400}
 pre.tail{margin:6px 0 0 8px;background:#000;border:1px solid var(--line);border-radius:7px;padding:8px;font-size:11px;max-height:150px;overflow:auto;white-space:pre-wrap;color:#9fb}
 .empty{color:var(--dim);font-size:13px;text-align:center;padding:18px}
 label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:var(--violet);margin:0 0 8px}
 .row{display:flex;gap:10px;flex-wrap:wrap}
 select{flex:1;min-width:220px;background:#05050e;color:var(--fg);border:1px solid var(--line);border-radius:10px;padding:11px 13px;font:inherit;font-size:14px;outline:none;appearance:none;cursor:pointer}
 select:focus{border-color:var(--cyan)} optgroup{color:var(--gold)} option{color:var(--fg);background:#05050e}
 pre#out{margin:14px 0 0;background:#05050e;border:1px solid var(--line);border-radius:10px;padding:14px;min-height:80px;max-height:40vh;overflow:auto;white-space:pre-wrap;font-size:13px;color:#cfe}
 pre#out.ok{color:var(--mint)} pre#out.err{color:var(--rose)} pre#out.running{color:var(--gold)}
 .foot{color:var(--dim);font-size:11px;margin-top:22px;text-align:center}
</style></head><body><div class="wrap">
 <h1>🧰 <span class="g">toolbox</span></h1>
 <div class="sub">disk → discover (r)/(t) → dispatch → monitor · localhost only</div>

 <h2>monitor <button class="ghost" onclick="reindex()">↻ Re-index</button></h2>
 <div id="mon" class="card"><div class="empty">loading…</div></div>

 <h2>manual run</h2>
 <div class="card">
  <label for="sel">choose a script</label>
  <div class="row"><select id="sel"></select><button class="run" onclick="run()">▶ Run</button></div>
  <pre id="out">Pick a script and hit Run.</pre>
 </div>
 <div class="foot">~/toolbox · <code>tb index</code> / <code>tb status</code> / <code>tb serve</code></div>
</div>
<script>
const $=s=>document.querySelector(s), el=(t,c)=>{const e=document.createElement(t);if(c)e.className=c;return e};
async function loadMon(){
  let m; try{ m=await (await fetch('/api/monitor')).json(); }catch(e){ return; }
  const box=$('#mon'); const ents=Object.values(m.entries||{});
  box.innerHTML='';
  if(!ents.length){ box.innerHTML='<div class=empty>Nothing discovered. Drop a "(r) name" folder with a tb.launch.json into a watch root, then Re-index.</div>'; return; }
  ents.forEach(e=>{
    const c=el('div','ent '+e.state), h=el('div');
    const b=el('span','badge '+e.state); b.textContent=e.state==='ready'?'(r) READY':e.state==='thinking'?'(t) THINKING':e.state.toUpperCase();
    const nm=el('span','nm'); nm.textContent=e.name; h.appendChild(b); h.appendChild(nm); c.appendChild(h);
    const p=el('div','path'); p.textContent=e.folder; c.appendChild(p);
    if(e.state==='thinking'){ const n=el('div','note'); n.textContent='inspect-only — not dispatched'; c.appendChild(n); }
    else if(e.state==='ready'&&!e.target){ const n=el('div','note warn'); n.textContent='no launch target — not dispatched'; c.appendChild(n); }
    else if(e.dispatch){
      const d=el('div','disp'); d.textContent='dispatch '+e.dispatch.id+' · '+e.dispatch.status; c.appendChild(d);
      (e.dispatch.runs||[]).forEach(r=>{
        const rr=el('div','run '+r.status);
        rr.textContent=r.status+'  '+(r.label||r.node)+(r.exitCode!=null?' (exit '+r.exitCode+')':r.error?' ('+r.error+')':''); c.appendChild(rr);
        if(r.outputTail){ const pre=el('pre','tail'); pre.textContent=r.outputTail; c.appendChild(pre); }
      });
    }
    if(e.state==='gone'){ const n=el('div','note'); n.textContent=e.note||'gone'; c.appendChild(n); }
    box.appendChild(c);
  });
}
async function reindex(){ $('#mon').classList.add('busy'); try{ await fetch('/api/index',{method:'POST'}); }catch(e){} await loadMon(); $('#mon').classList.remove('busy'); }
async function loadReg(){
  const r=await (await fetch('/api/registry')).json(); const sel=$('#sel'); sel.innerHTML=''; const cats={};
  r.items.forEach(it=>{(cats[it.category]=cats[it.category]||[]).push(it)});
  Object.keys(cats).sort().forEach(cat=>{const og=document.createElement('optgroup');og.label=cat;
    cats[cat].forEach(it=>{const o=document.createElement('option');o.value=it.id;o.textContent=it.name+(it.description?'  —  '+it.description:'');og.appendChild(o)});sel.appendChild(og)});
}
async function run(){
  const id=$('#sel').value; if(!id)return; const out=$('#out'); out.className='running'; out.textContent='▶ running '+id+' …';
  try{ const j=await (await fetch('/api/run',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id})})).json();
    if(j.error){out.className='err';out.textContent='error: '+j.error;return;}
    out.className=j.exit===0?'ok':'err'; out.textContent=(j.output||'(no output)')+'\\n\\n[exit '+j.exit+']';
  }catch(e){ out.className='err'; out.textContent='request failed: '+e; }
}
loadReg(); loadMon(); setInterval(loadMon,4000);
</script></body></html>`;
}

const server = http.createServer((req, res) => {
  const send = (code, obj) => { res.writeHead(code, {'content-type':'application/json'}); res.end(JSON.stringify(obj)); };
  if (req.method==='GET' && req.url==='/'){ res.writeHead(200,{'content-type':'text/html; charset=utf-8'}); return res.end(page()); }
  if (req.method==='GET' && req.url==='/api/registry') return send(200, reg.load());
  if (req.method==='GET' && req.url==='/api/monitor') return send(200, mon.refreshOnly());
  if (req.method==='POST' && req.url==='/api/index')  return send(200, mon.reconcile({}));
  if (req.method==='POST' && req.url==='/api/scan'){ const r=reg.build(); return send(200,{count:r.count}); }
  if (req.method==='POST' && req.url==='/api/run'){
    let body=''; req.on('data',d=>{body+=d;if(body.length>1e5)req.destroy()});
    req.on('end',()=>{ let id;try{id=JSON.parse(body).id}catch(e){return send(400,{error:'bad json'})}
      const it=reg.load().items.find(x=>x.id===id); if(!it)return send(404,{error:'unknown script id'});
      let out='',done=false; const p=spawn(it.interpreter,[it.path],{cwd:path.dirname(it.path)});
      const to=setTimeout(()=>{if(!done){p.kill('SIGKILL');out+='\n[timed out]'}},RUN_TIMEOUT);
      const cap=d=>{out+=d;if(out.length>2e5)out=out.slice(-2e5)};
      p.stdout.on('data',cap); p.stderr.on('data',cap);
      p.on('close',code=>{done=true;clearTimeout(to);send(200,{id,name:it.name,exit:code,output:out})});
      p.on('error',err=>{done=true;clearTimeout(to);send(500,{error:String(err)})});
    }); return;
  }
  res.writeHead(404); res.end('not found');
});
server.listen(PORT, HOST, () => console.log(`\n  🧰 toolbox → http://${HOST}:${PORT}  (${reg.load().count} scripts, monitor live)\n`));
