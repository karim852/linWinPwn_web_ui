/* linWinPwn Web Console - frontend
   Everything is driven from the web:
     - menus/options = buttons (sidebar + action rail)
     - every question the script asks (">> " prompts, choice lists, y/N,
       "press ENTER to continue", tool consoles) = a form under the output
   The terminal is only an output view; typing in it is optional. */
(() => {
"use strict";

const TOKEN = new URLSearchParams(location.search).get("token") || "";
const qs  = (s, r=document) => r.querySelector(s);
const qsa = (s, r=document) => [...r.querySelectorAll(s)];
const api = (p, opt={}) => fetch(p + (p.includes("?")?"&":"?") + "token=" + encodeURIComponent(TOKEN),
  Object.assign({headers:{"Content-Type":"application/json","X-Auth-Token":TOKEN}}, opt));
const esc = s => String(s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

const ICONS = {globe:"🌐",sitemap:"🗂",certificate:"🏷",server:"🖧",shield:"🛡",key:"🔑",
  ticket:"🎫",folder:"📁",bug:"🐞",database:"🗄",unlock:"🔓",pencil:"✎",terminal:"⌨",
  network:"📡",fingerprint:"🔏",gear:"⚙"};

/* Menu headers printed by linWinPwn.sh -> menu id in menus.json (null = main) */
const HEADER_MAP = {
  "Main menu":null, "AD Enum menu":"ad", "ADCS menu":"adcs", "SCCM menu":"sccm",
  "GPO menu":"gpo", "BruteForce menu":"brute", "Kerberos Attacks menu":"kerberos",
  "SMB Shares menu":"shares", "Vuln Checks menu":"vulns", "MSSQL Enumeration menu":"mssql",
  "Password Dump menu":"pwd", "Modification menu":"modif", "Command Execution menu":"cmdexec",
  "Network Scan menu":"netscan", "Auth menu":"auth", "Config menu":"config",
};

let MENUS = [];
let CURRENT = null;            // menu shown in the action rail
let CUR_MENU = null;           // menu the script is actually in (from its headers)
let SESSION_RUNNING = false;
let RUN_STATE = "off";         // off | running | ready | input
let LAST_CFG = null;

/* ======================= terminals ======================= */
function makeTerm(elId, wsPath, opts={}) {
  const term = new Terminal({
    fontFamily:'ui-monospace,"JetBrains Mono",Menlo,Consolas,monospace',
    fontSize:13, cursorBlink:true, scrollback:10000, convertEol:false,
    theme:{background:"#05080c",foreground:"#d7e2f0",cursor:"#39d0d8",
           black:"#0b0f14",brightBlack:"#56687e",green:"#49c17a",cyan:"#39d0d8",
           yellow:"#f0a63a",red:"#e0625f",blue:"#7fa6e0",magenta:"#c58af0"}
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  try { term.loadAddon(new WebLinksAddon.WebLinksAddon()); } catch(e){}
  term.open(qs(elId));
  setTimeout(()=>{try{fit.fit();}catch(e){}}, 30);

  let ws=null, retry=null, connected=false, firstMsg=true;
  function connect() {
    const proto = location.protocol==="https:"?"wss":"ws";
    const sock = new WebSocket(`${proto}://${location.host}${wsPath}?token=${encodeURIComponent(TOKEN)}`);
    ws = sock;
    // every handler checks it still belongs to the current socket: the close event
    // of a replaced socket can arrive after the new one opened
    sock.onopen = () => { if (sock !== ws) return; connected=true; firstMsg=true; sendResize(); opts.onopen && opts.onopen(); };
    sock.onmessage = ev => { if (sock !== ws) return; const f = firstMsg; firstMsg = false;
      term.write(ev.data); opts.onoutput && opts.onoutput(ev.data, f); };
    sock.onclose = () => { if (sock !== ws) return; connected=false; opts.onclose && opts.onclose();
      if(opts.autoReconnect){ clearTimeout(retry); retry=setTimeout(connect,1500);} };
    sock.onerror = () => {};
  }
  function sendResize(){ if(ws&&connected) ws.send("\x00json:"+JSON.stringify(
    {type:"resize",rows:term.rows,cols:term.cols})); }
  function send(d){ if(ws&&connected){ ws.send(d); return true;} return false; }
  term.onData(d => { if(!opts.typeable || opts.typeable()) send(d); });
  window.addEventListener("resize", ()=>{try{fit.fit();sendResize();}catch(e){}});

  return { term, connect, send,
           reconnect(){ const old = ws; connected = false; connect(); try{ old && old.close(); }catch(e){} },
           refit(){ try{fit.fit();sendResize();}catch(e){} } };
}

const lwpTerm = makeTerm("#termLwp","/ws/linwinpwn",{
  autoReconnect:false,
  typeable:()=>qs("#lwpTypeable").checked,
  onoutput:onLwpOutput,
});
let shellTerm = null;

/* ======================= output analysis ======================= */
const ANSI_RE = /\x1b\[[0-9;?]*[ -\/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[()][0-9A-B]|\x1b[=>]/g;
let PLAIN = "";              // ANSI-stripped rolling buffer
let LINE_ACC = "";           // partial line for history parsing
let analyzeTimer = null, consoleTimer = null;
let PROMPT_SIG = null;       // avoid re-rendering the same prompt (keeps user typing)

function onLwpOutput(data, isReplay) {
  const skipFeed = isReplay && RES_RESTORED;
  const clean = data.replace(ANSI_RE, "").replace(/\r(?!\n)/g, "\n").replace(/\r/g, "");
  PLAIN = (PLAIN + clean).slice(-20000);
  // history: complete lines only
  LINE_ACC += clean;
  const parts = LINE_ACC.split("\n"); LINE_ACC = parts.pop();
  parts.forEach(l => {
    const m = l.match(/\[i\] (?:Running|Printing) command: (.+)$/);
    if (m) addHistory(m[1].trim());
    if (!skipFeed) feedLine(l);
  });
  if (RUN_STATE !== "input") setRunState("running");
  clearTimeout(analyzeTimer); clearTimeout(consoleTimer);
  analyzeTimer = setTimeout(analyze, 220);
}

function analyze() {
  if (!SESSION_RUNNING) return;
  const lines = PLAIN.slice(-8000).split("\n");
  const last = lines[lines.length-1];
  const lastTrim = last.trim();

  /* 1) question: read -rp ">> " */
  if (lastTrim === ">>") {
    const ctx = collectContext(lines, lines.length-2, 14);
    return showQuestion(ctx);
  }

  /* 2) menu prompt or choice list: read -rp "> " */
  if (lastTrim === ">") {
    const block = blockAbove(lines, lines.length-2, 90);
    // module menu?
    for (let i=block.length-1;i>=0;i--) {
      const h = block[i].match(/\[([A-Za-z0-9 ]+ menu)\]/);
      if (h && h[1] in HEADER_MAP) { return menuReady(HEADER_MAP[h[1]]); }
    }
    return showChoice(block);
  }

  /* 3) "press ENTER to continue" (read -rp "") */
  if (lastTrim === "") {
    const prev = lastNonEmpty(lines, lines.length-2);
    if (prev && /press ENTER to continue/i.test(prev.text)) {
      const ctx = collectContext(lines, prev.idx-1, 6).lines;
      return showPanel({kind:"continue", title:prev.text.replace(/^\[\*\]\s*/,""),
        context:ctx.join("\n"), input:false, sig:"c"+PLAIN.length});
    }
  }

  /* 4) unterminated line that stays still = a tool console waiting for input
        (evil-winrm, smbclient, mssqlclient, ldap consoles...) */
  if (lastTrim.length > 0) {
    consoleTimer = setTimeout(() => {
      const nowLast = PLAIN.split("\n").pop();
      if (nowLast === last) showPanel({kind:"console", title:"The program is waiting for input",
        context:last, input:true, placeholder:"command / answer", sig:"k"+PLAIN.length});
    }, 900);
    return;
  }
  hidePanel(); setRunState("running");
}

function lastNonEmpty(lines, from){
  for (let i=from;i>=0 && i>from-6;i--) if (lines[i].trim()) return {idx:i, text:lines[i].trim()};
  return null;
}
/* lines above a prompt, stopping at the previous answered prompt / command */
function blockAbove(lines, from, max) {
  const out=[];
  for (let i=from;i>=0 && out.length<max;i--) {
    const t = lines[i];
    if (/^>{1,2} \S/.test(t.trim())) break;   // previous answered prompt: "> 3" / ">> foo"
    out.unshift(t);
  }
  return out;
}
function collectContext(lines, from, max) {
  const out=[];
  for (let i=from;i>=0 && out.length<max;i--) {
    const t = lines[i].trim();
    if (!t) { if (out.length) break; else continue; }
    if (/^>{1,2}( |$)/.test(t) || /(Running|Printing) command:/.test(t) || /\[[A-Za-z0-9 ]+ menu\]/.test(t)) break;
    out.unshift(t);
  }
  return {lines:out};
}

/* ======================= prompt panel ======================= */
function showQuestion(ctx) {
  const L = ctx.lines.length ? ctx.lines : ["The script is asking for a value"];
  // title: a real question line wins ("Please specify/choose...", "...?"),
  // then a "[*]/[!]/Invalid" line, then the last line. The rest is context.
  const find = re => { for (let i=L.length-1;i>=0;i--) if (re.test(L[i])) return i; return -1; };
  let ti = find(/Please (specify|choose|type|provide|enter|select)|Would you|\?\s*\)?\s*$|press Enter/i);
  if (ti < 0) ti = find(/^(\[\*\]|\[!\]|\[-\]|Invalid)/);
  if (ti < 0) ti = L.length-1;
  const title = L[ti].replace(/^\[[*!\-]\]\s*/,"");
  const others = L.filter((_,i)=>i!==ti);
  const context = others.join("\n");
  const full = L.join(" ");

  const spec = {kind:"question", title, context, input:true, choices:[], sig:"q"+PLAIN.length};
  // short single values listed above the question (IPs, names...) = suggestions
  const sugg = others.filter(t => /^[^\s:]{1,60}$/.test(t) && !/^[-=]+$/.test(t)).slice(0,12);
  if (sugg.length) spec.choices = sugg.map(s=>[s,s]);
  // default value
  let d = full.match(/press Enter to (?:choose )?default value:?\s*'?([^')]+?)'?\s*\)/i)
       || full.match(/\(default(?: value)?:?\s*'?([^')]+?)'?\s*\)/i)
       || full.match(/press Enter to ([^)]+)\)/i);
  if (d) spec.def = d[1].trim();
  // yes / no
  if (/\(y\/n\)/i.test(full)) spec.choices = [["y","Yes"],["n","No"]];
  // 'A' or 'B' / between 'A' and 'B'
  const alt = full.match(/'([^']+)' or '([^']+)'/) || full.match(/between '([^']+)' and '([^']+)'/);
  if (alt) spec.choices = [[alt[1],alt[1]],[alt[2],alt[2]]];
  // secret?
  spec.secret = /password|ntlm|hash|aes key|\bkey of\b|secret/i.test(title) && !/file|wordlist|path|list/i.test(title);
  spec.placeholder = spec.def ? `empty = ${spec.def}` : "your answer";
  showPanel(spec);
}

function showChoice(block) {
  const opts=[]; let title="Choose an option"; const ctx=[];
  block.forEach(raw => {
    const t = raw.trim(); if (!t || /^-{5,}$/.test(t)) return;
    const m = t.match(/^([\w.*]{1,6})\)\s*(.+)$/);
    if (m) opts.push([m[1]==="*"?"":m[1], m[2]]);
    else if (/Please (choose|specify|select)|provide/i.test(t)) title = t.replace(/^\[[*i]\]\s*/,"");
    else ctx.push(t);
  });
  showPanel({kind:"choice", title, context:ctx.slice(-3).join("\n"), choices:opts.filter(o=>o[0]!==""),
    input:true, placeholder:"or type a value / custom query", sig:"m"+PLAIN.length});
}

function showPanel(spec) {
  if (PROMPT_SIG === spec.sig) return;
  PROMPT_SIG = spec.sig;
  LAST_SPEC = spec;
  if (CUR_ENTRY && CUR_ENTRY.status === "running") { CUR_ENTRY.status = "waiting"; resMark(CUR_ENTRY); }
  const p = qs("#promptPanel");
  qs("#ppKind").textContent = {question:"question",choice:"choice",continue:"waiting",console:"console"}[spec.kind];
  qs("#ppTitle").textContent = spec.title;
  qs("#ppContext").textContent = spec.context || "";
  const ch = qs("#ppChoices"); ch.innerHTML="";
  (spec.choices||[]).forEach(([key,label]) => {
    const b=document.createElement("button"); b.type="button"; b.className="pp-choice";
    b.innerHTML = key!==label ? `<span class="k">${esc(key)}</span>${esc(label)}` : esc(label);
    b.onclick=()=>answer(key);
    ch.appendChild(b);
  });
  const inp = qs("#ppInput");
  qs("#ppInputRow").classList.toggle("hidden", !spec.input);
  inp.value=""; inp.type = spec.secret ? "password" : "text";
  inp.placeholder = spec.placeholder || "";
  qs("#ppReveal").classList.toggle("hidden", !spec.secret);
  qs("#ppDefault").innerHTML = spec.def ? `Default: <b>${esc(spec.def)}</b>` :
    (spec.kind==="continue" ? "Click when you are ready." : "");
  qs("#ppEnter").textContent = spec.kind==="continue" ? "Continue ⏎" :
    spec.def ? "Use default ⏎" : "Send empty ⏎";
  p.classList.remove("hidden");
  setRunState("input");
  lwpTerm.refit();
  if (!qs('#mainTabs button[data-tab="lwp"]').classList.contains("active"))
    qs('#mainTabs button[data-tab="lwp"]').classList.add("attn");
  setTimeout(()=> spec.input ? inp.focus() : qs("#ppEnter").focus(), 30);
}

function hidePanel() {
  if (qs("#promptPanel").classList.contains("hidden")) return;
  qs("#promptPanel").classList.add("hidden");
  qs('#mainTabs button[data-tab="lwp"]').classList.remove("attn");
  PROMPT_SIG = null;
  lwpTerm.refit();
}

function answer(text) {
  if (LAST_SPEC && LAST_SPEC.kind !== "console") {
    if (!CUR_ENTRY) resNew("session", "Session output", "", "", 0);
    const shown = text === "" ? (LAST_SPEC.def ? `default (${LAST_SPEC.def})` : (LAST_SPEC.kind === "continue" ? "continue" : "empty"))
                : (LAST_SPEC.secret ? "••••••" : text);
    const q = LAST_SPEC.title.replace(/\s*\(.*?\)\s*:?\s*$/, "").replace(/:\s*$/, "");
    CUR_ENTRY.qa.push({q, a: shown});
    // drop the question line itself from the output, it is shown as Q/A
    const frag = LAST_SPEC.title.slice(0, 30);
    for (let i = CUR_ENTRY.lines.length - 1; i >= Math.max(0, CUR_ENTRY.lines.length - 15); i--)
      if (CUR_ENTRY.lines[i].t.includes(frag)) { CUR_ENTRY.lines.splice(i, 1); break; }
  } else if (LAST_SPEC && CUR_ENTRY) {
    CUR_ENTRY.lines.push({t: "› " + text, c: "info"});
  }
  if (CUR_ENTRY && CUR_ENTRY.status === "waiting") { CUR_ENTRY.status = "running"; resMark(CUR_ENTRY); }
  lwpTerm.send(text + "\r");
  hidePanel();
  setRunState("running");
}

function menuReady(menuId) {
  hidePanel();
  if (CUR_ENTRY && CUR_ENTRY.seen >= CUR_ENTRY.need) resClose("done");
  CUR_MENU = menuId;
  const m = MENUS.find(x=>x.id===menuId);
  qs("#lwpCrumb").innerHTML = `menu: <b>${m ? esc(m.title) : "Main menu"}</b>`;
  setRunState("ready");
}

function setRunState(s) {
  if (!SESSION_RUNNING) s = "off";
  if (RUN_STATE === s) return;
  RUN_STATE = s;
  const el = qs("#runState");
  el.className = "state state-" + s;
  el.textContent = {off:"no session", running:"running…", ready:"ready", input:"waiting for your answer"}[s];
  qsa("#actionList .act").forEach(b => b.disabled = (s !== "ready"));
  qs("#lwpHome").disabled = s !== "ready" || CUR_MENU === null;
  qs("#lwpStop").disabled = s === "off";
  qs("#lwpReset").disabled = s === "off";
}

/* ======================= menu tree & actions ======================= */
function renderTree(filter="") {
  const tree = qs("#menuTree"); tree.innerHTML="";
  const f = filter.trim().toLowerCase();
  MENUS.forEach(m => {
    if (f && !(m.title.toLowerCase().includes(f) ||
               m.actions.some(a=>a.label.toLowerCase().includes(f)))) return;
    const el = document.createElement("div");
    el.className = "menu-item" + (CURRENT && CURRENT.id===m.id ? " active":"");
    const n = m.actions.filter(a=>!["A","m","P"].includes(a.key)).length;
    el.innerHTML = `<span class="mi-ico">${ICONS[m.icon]||"▸"}</span>
      <span class="mi-title">${esc(m.title)}</span><span class="mi-count">${n}</span>`;
    el.onclick = () => openMenu(m);
    tree.appendChild(el);
  });
}

function openMenu(m) {
  CURRENT = m;
  renderTree(qs("#menuFilter").value);
  qs("#railTitle").textContent = m.title;
  qs("#railDesc").textContent = m.desc || "";
  renderActions(m);
  switchTab("lwp");
}

function renderActions(m) {
  const list = qs("#actionList"); list.innerHTML="";
  const f = qs("#menuFilter").value.trim().toLowerCase();
  const pick = arr => f ? arr.filter(a=>a.label.toLowerCase().includes(f)||m.title.toLowerCase().includes(f)) : arr;
  const batch = pick(m.actions.filter(a=>a.key==="A"));
  const utils = pick(m.actions.filter(a=>a.key==="m"||a.key==="P"));
  const normal = pick(m.actions.filter(a=>!["A","m","P"].includes(a.key)));
  const sep = t => { const s=document.createElement("div"); s.className="act-sep"; s.textContent=t; list.appendChild(s); };
  const add = a => {
    const btn = document.createElement("button");
    btn.className = "act";
    let badges = "";
    if (a.noisy)   badges += `<span class="badge b-noisy">noisy</span>`;
    if (a.key==="A") badges += `<span class="badge b-batch">batch</span>`;
    if (a.console) badges += `<span class="badge b-console">console</span>`;
    if (a.prompts) badges += `<span class="badge b-prompt">form</span>`;
    btn.innerHTML = `<span class="k">${esc(a.key)}</span><span class="lbl">${esc(a.label)}</span>${badges}`;
    btn.disabled = RUN_STATE !== "ready";
    btn.title = RUN_STATE !== "ready" ? "Wait until the script is back at a menu" : a.label;
    btn.onclick = () => runAction(m, a);
    list.appendChild(btn);
  };
  if (batch.length){ sep("Quick run"); batch.forEach(add); }
  if (normal.length){ sep("Actions"); normal.forEach(add); }
  if (utils.length){ sep("Utilities"); utils.forEach(add); }
}

/* Key sequence from the menu the script is REALLY in (read from its output). */
function keySequence(m, a) {
  const keys = [];
  if (m.direct) {                         // DNS: option of the main menu
    if (CUR_MENU !== null) keys.push("back");
    keys.push(m.enter);
    return keys;
  }
  if (CUR_MENU !== m.id) {
    if (CUR_MENU !== null) keys.push("back");
    keys.push(m.enter);
  }
  keys.push(a.key);
  return keys;
}

async function runAction(m, a) {
  if (RUN_STATE !== "ready") return;
  const keys = keySequence(m, a);
  resNew("action", a.label, m.title, a.key, keys.length);
  // the script will be inside this menu after the keys (confirmed again by its header)
  CUR_MENU = m.direct ? null : m.id;
  qs("#lwpCrumb").innerHTML = `menu: <b>${esc(m.direct ? "Main menu" : m.title)}</b>`;
  setRunState("running");
  const r = await api("/api/action",{method:"POST",body:JSON.stringify({keys})});
  const j = await r.json().catch(()=>({}));
  if (!j.ok) note(`action failed: ${j.error||r.status}`);
}

function note(msg){ lwpTerm.term.write(`\r\n\x1b[33m[web] ${msg}\x1b[0m\r\n`); }


/* ======================= Results view =======================
   Turns the raw output into one card per action: commands run, output
   sorted by type, the answers given in the forms, files produced.
   Fed line by line from the same stream as the terminal. */
let OUTPUT_DIR = "";
let IN_MENU = false;          // inside a menu listing (not results)
let RES = [];                 // entries and separators, oldest first
let CUR_ENTRY = null;
let RES_SEQ = 0;
let RES_FILTER = "", RES_STATUS = "all";
let LAST_SPEC = null;
let AUTO_SECTION = "", PENDING = null, LINE_NO = 0;
const GENERIC_FLAGS = new Set(["port","dns-server","kdcHost","log","dc-ip","dc-host","timeout","no-pass",
  "local-auth","use-kcache","kerberos","aesKey","hashes","target-ip","output","outputfile","debug","dns-tcp"]);
function keyFlag(cmd) {
  const mods = [...cmd.matchAll(/(?:^|\s)-M\s+(\S+)/g)].map(m => m[1]);
  if (mods.length) return "-M " + mods.join(", ");
  for (const m of cmd.matchAll(/(?:^|\s)--([A-Za-z][\w-]+)/g)) if (!GENERIC_FLAGS.has(m[1])) return "--" + m[1];
  return "";
}
let SESSION_ID = null, RES_RESTORED = false;
function resSave() {
  if (!SESSION_ID) return;
  try {
    const data = RES.slice(-150).map(e => {
      const o = Object.assign({}, e); delete o.el;
      if (o.lines) o.lines = o.lines.slice(-800);
      return o;
    });
    sessionStorage.setItem("lwp.res", JSON.stringify({id: SESSION_ID, res: data,
      cur: CUR_ENTRY ? CUR_ENTRY.id : null, seq: RES_SEQ}));
  } catch (e) {}
}
function resRestore(id) {
  /* Always bring back the saved cards (also after the session ended).
     Skip re-reading the replayed output only when it is the same session. */
  try {
    const d = JSON.parse(sessionStorage.getItem("lwp.res") || "null");
    if (!d) return false;
    RES = d.res; RES_SEQ = d.seq || RES.length;
    const same = !!id && d.id === id;
    CUR_ENTRY = same ? (RES.find(e => e.id === d.cur) || null) : null;
    if (!same) RES.forEach(e => { if (e.status === "running" || e.status === "waiting") { e.status = "done"; e.ended = e.ended || Date.now(); } });
    resRenderAll(); RES_RESTORED = same; SESSION_ID = SESSION_ID || d.id; return true;
  } catch (e) { return false; }
}
const resDirty = new Set(); let resTimer = null;

function secretValues() {
  const c = LAST_CFG || {};
  return [c.password, c.hash, c.aeskey, c.certpass].filter(v => v && v.length >= 3);
}
function mask(text) {
  let t = String(text);
  secretValues().forEach(v => { t = t.split(v).join("••••••"); });
  return t;
}
function toolName(cmd) {
  const tok = cmd.trim().split(/\s+/).filter(x => !/^(sudo|timeout|\d+[smh]?|-[a-zA-Z]|env|[A-Z_]+=\S*)$/.test(x));
  const base = (tok[0] || "command").split("/").pop();
  const sub = tok[1] && /^[a-z][a-z0-9_-]{1,14}$/.test(tok[1]) ? " " + tok[1] : "";
  return base + sub;
}
function findFiles(text) {
  if (!OUTPUT_DIR) return [];
  const re = new RegExp(OUTPUT_DIR.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "/[^\\s'\"`;|)]+", "g");
  return (String(text).match(re) || []).map(f => f.slice(OUTPUT_DIR.length + 1).replace(/[.,:]+$/, ""));
}
function classify(t) {
  if (/^\[\+\]/.test(t) || /\b(success|pwn3d!|valid credentials?)\b/i.test(t)) return "ok";
  if (/^\[-\]/.test(t) || /\b(error|failed|failure|denied|not found|timed out|refused|missing)\b/i.test(t)) return "err";
  if (/^\[!\]/.test(t) || /\bwarning\b/i.test(t)) return "warn";
  if (/^\[(i|\*)\]/.test(t)) return "info";
  return "plain";
}
const OL_ICON = {ok:"✓", err:"✕", warn:"!", info:"›", plain:""};

function resNew(kind, label, menu, key, need) {
  if (CUR_ENTRY && (CUR_ENTRY.status === "running" || CUR_ENTRY.status === "waiting"))
    resClose("done");
  RES.forEach(e => { if (e.kind && !e.userToggled) { e.open = false; resMark(e); } });
  const e = {id: ++RES_SEQ, kind, label, menu: menu || "", key: key || "", status: "running",
             started: Date.now(), ended: null, cmds: [], lines: [], qa: [], files: [],
             counts: {ok:0, err:0, warn:0}, need: need || 0, seen: 0,
             open: true, userToggled: false, showAll: false, el: null};
  RES.push(e); CUR_ENTRY = e;
  if (RES.length > 400) RES.splice(0, RES.length - 400).forEach(x => x.el && x.el.remove());
  resMark(e);
  return e;
}
function resClose(status) {
  const e = CUR_ENTRY; if (!e) return;
  if (e.status === "running" || e.status === "waiting") { e.status = status; e.ended = Date.now(); }
  resMark(e);
  CUR_ENTRY = null;
}
function resSep(text) { RES.push({sep: true, text, id: ++RES_SEQ}); resRenderAll(); }

function feedLine(raw) {
  const t = raw.replace(/\s+$/, ""), tr = t.trim();
  if (!tr) return;
  if (/^\[(web|web-ui)\]/.test(tr) || /^\[linWinPwn session not started/.test(tr)) return;
  if (/\[[A-Za-z0-9 ]+ menu\]/.test(tr)) { IN_MENU = true; return; }
  if (/^>{1,2}( |$)/.test(tr)) {                 // echo of a menu choice / answer
    if (/^> \S/.test(tr) && CUR_ENTRY) CUR_ENTRY.seen++;
    IN_MENU = false; return;
  }
  if (IN_MENU) return;
  LINE_NO++;
  if (/^-{5,}$/.test(tr)) return;
  const sec = tr.match(/^\[\+\] Start: (.+)$/);
  if (sec && (!CUR_ENTRY || CUR_ENTRY.kind !== "action")) { AUTO_SECTION = sec[1].trim(); return; }
  const cm = tr.match(/\[i\] (?:Running|Printing) command: (.+)$/);
  if (cm) {
    const cmd = cm[1].trim();
    if (!CUR_ENTRY || CUR_ENTRY.kind === "auto" || CUR_ENTRY.kind === "session") {
      // name the card after the "[*] ..." line announced just before, else tool + key option
      let label = "";
      if (PENDING && LINE_NO - PENDING.no <= 2) {
        label = PENDING.text;
        const pe = PENDING.entry, i = pe ? pe.lines.lastIndexOf(PENDING.line) : -1;
        if (i >= 0) { pe.lines.splice(i, 1); resMark(pe); }
      }
      if (!label) { const kf = keyFlag(cmd); label = toolName(cmd) + (kf ? " · " + kf : ""); }
      PENDING = null;
      resNew("auto", label, AUTO_SECTION, "", 0);
    }
    CUR_ENTRY.cmds.push(cmd);
    findFiles(cmd).forEach(f => CUR_ENTRY.files.includes(f) || CUR_ENTRY.files.push(f));
    resMark(CUR_ENTRY); return;
  }
  if (!CUR_ENTRY) resNew("session", "Session output", "", "", 0);
  const c = classify(tr);
  const line = {t, c};
  CUR_ENTRY.lines.push(line);
  if (/^\[\*\] /.test(tr) && CUR_ENTRY.kind !== "action")
    PENDING = {text: tr.replace(/^\[\*\]\s*/, "").replace(/\.{3}$/, ""), entry: CUR_ENTRY, line, no: LINE_NO};
  if (c in CUR_ENTRY.counts) CUR_ENTRY.counts[c]++;
  findFiles(tr).forEach(f => CUR_ENTRY.files.includes(f) || CUR_ENTRY.files.push(f));
  if (CUR_ENTRY.lines.length > 5000) CUR_ENTRY.lines.splice(0, 1000);
  resMark(CUR_ENTRY);
}

/* ---- rendering ---- */
function resMark(e) { resDirty.add(e); clearTimeout(resTimer); resTimer = setTimeout(resFlush, 90); }
function resFlush() {
  const list = qs("#resList");
  resDirty.forEach(e => {
    if (!RES.includes(e)) return;
    if (!e.el) { e.el = document.createElement("div"); list.appendChild(e.el); }
    resPaint(e);
  });
  resDirty.clear();
  resCountUpdate();
  resSave();
  // keep the newest card in view if the user is near the bottom
  if (list.scrollHeight - list.scrollTop - list.clientHeight < 220) list.scrollTop = list.scrollHeight;
}
function resRenderAll() {
  const list = qs("#resList");
  [...list.querySelectorAll(".rc,.res-sep")].forEach(n => n.remove());
  RES.forEach(e => { e.el = null; });
  RES.forEach(e => {
    e.el = document.createElement("div"); list.appendChild(e.el);
    if (e.sep) { e.el.className = "res-sep"; e.el.textContent = e.text; } else resPaint(e);
  });
  resCountUpdate();
}
function resMatches(e) {
  if (RES_STATUS === "running" && !(e.status === "running" || e.status === "waiting")) return false;
  if (RES_STATUS === "done" && e.status !== "done") return false;
  if (RES_STATUS === "issues" && !(e.counts.err || e.status === "stopped")) return false;
  if (!RES_FILTER) return true;
  const f = RES_FILTER.toLowerCase();
  return (e.label + " " + e.menu + " " + e.cmds.join(" ") + " " + e.lines.map(l => l.t).join(" "))
    .toLowerCase().includes(f);
}
function fmtDur(ms) { const s = Math.round(ms/1000); return s < 60 ? s + "s" : Math.floor(s/60) + "m" + String(s%60).padStart(2,"0"); }
function resPaint(e) {
  const el = e.el;
  if (e.sep) { el.className = "res-sep"; el.textContent = e.text; return; }
  el.className = "rc " + e.status;
  el.style.display = resMatches(e) ? "" : "none";
  const t0 = new Date(e.started).toLocaleTimeString();
  const dur = e.ended ? fmtDur(e.ended - e.started) : (e.status === "waiting" ? "waiting" : "running");
  const pills = [];
  if (e.cmds.length) pills.push(`<span class="pill">${e.cmds.length} cmd</span>`);
  if (e.counts.ok) pills.push(`<span class="pill ok">✓ ${e.counts.ok}</span>`);
  if (e.counts.warn) pills.push(`<span class="pill warn">! ${e.counts.warn}</span>`);
  if (e.counts.err) pills.push(`<span class="pill err">✕ ${e.counts.err}</span>`);
  if (e.status === "stopped") pills.push(`<span class="pill err">stopped</span>`);
  let body = "";
  if (e.open) {
    const sec = [];
    if (e.cmds.length) sec.push(`<div><div class="rc-sec">Commands</div><div class="rc-cmds">` +
      e.cmds.map((c, i) => `<div class="rc-cmd"><code>${esc(mask(c))}</code>` +
        `<button type="button" class="btn btn-ghost sm" data-copy="${i}">copy</button></div>`).join("") + `</div></div>`);
    if (e.qa.length) sec.push(`<div><div class="rc-sec">Your answers</div><div class="rc-qa">` +
      e.qa.map(q => `<span class="qa">${esc(q.q)} → <b>${esc(q.a)}</b></span>`).join("") + `</div></div>`);
    if (e.files.length) sec.push(`<div><div class="rc-sec">Files produced</div><div class="rc-files">` +
      e.files.map(f => `<span class="rc-file" data-file="${esc(f)}" title="${esc(f)}">📄 ${esc(f.split("/").pop())}</span>`).join("") + `</div></div>`);
    const LIM = 300;
    const lines = e.showAll ? e.lines : e.lines.slice(-LIM);
    const hidden = e.lines.length - lines.length;
    sec.push(`<div><div class="rc-sec">Output · ${e.lines.length} lines</div>` +
      (e.lines.length ? `<div class="rc-out">` +
        (hidden ? `<div class="rc-more" data-more="1">show ${hidden} earlier lines</div>` : "") +
        lines.map(l => `<div class="ol ${l.c}"><span class="ic">${OL_ICON[l.c]}</span><span>${esc(mask(l.t))}</span></div>`).join("") +
        `</div>` : `<div class="rc-empty">${e.status === "running" ? "waiting for output…" : "no output"}</div>`) + `</div>`);
    body = `<div class="rc-body">${sec.join("")}</div>`;
  }
  el.innerHTML =
    `<div class="rc-head"><span class="rc-dot"></span>` +
    (e.menu ? `<span class="rc-menu">${esc(e.menu)} ›</span>` : "") +
    `<span class="rc-title">${esc(e.label)}</span>` +
    (e.key ? `<span class="rc-key">${esc(e.key)}</span>` : "") +
    `<span class="rc-pills">${pills.join("")}</span>` +
    `<span class="rc-time">${t0} · ${dur}</span><span class="chev">${e.open ? "▾" : "▸"}</span></div>` + body;
  el.querySelector(".rc-head").onclick = () => { e.open = !e.open; e.userToggled = true; resPaint(e); };
  el.querySelectorAll("[data-copy]").forEach(b => b.onclick = ev => {
    ev.stopPropagation(); navigator.clipboard?.writeText(e.cmds[+b.dataset.copy]);
    b.textContent = "copied"; setTimeout(() => b.textContent = "copy", 1200);
  });
  el.querySelectorAll("[data-file]").forEach(b => b.onclick = () => openLootFile(b.dataset.file));
  const more = el.querySelector("[data-more]"); if (more) more.onclick = () => { e.showAll = true; resPaint(e); };
}
function resCountUpdate() {
  const entries = RES.filter(e => !e.sep);
  const shown = entries.filter(resMatches).length;
  qs("#resCount").textContent = entries.length === shown ? `${entries.length} results` : `${shown} of ${entries.length} results`;
  qs("#resEmpty").style.display = entries.length ? "none" : "";
}
async function openLootFile(rel) {
  switchTab("loot");
  await loadLoot(rel.split("/").slice(0, -1).join("/"));
  previewFile(rel);
}
function resExport() {
  const L = ["# linWinPwn results", "", `Exported ${new Date().toLocaleString()}`, ""];
  RES.forEach(e => {
    if (e.sep) { L.push(`---`, ``, `_${mask(e.text)}_`, ``); return; }
    L.push(`## ${e.menu ? e.menu + " › " : ""}${e.label} (${e.status})`, "");
    L.push(`Started ${new Date(e.started).toLocaleTimeString()}` + (e.ended ? `, took ${fmtDur(e.ended - e.started)}` : ""), "");
    if (e.cmds.length) L.push("```bash", ...e.cmds.map(mask), "```", "");
    if (e.qa.length) L.push(...e.qa.map(q => `- ${q.q} → \`${q.a}\``), "");
    if (e.files.length) L.push("Files:", ...e.files.map(f => `- \`${f}\``), "");
    if (e.lines.length) L.push("```", ...e.lines.map(l => mask(l.t)), "```", "");
  });
  const blob = new Blob([L.join("\n")], {type: "text/markdown"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `linwinpwn-results-${new Date().toISOString().slice(0,16).replace(/[:T]/g,"-")}.md`;
  a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

/* ---- view switch ---- */
function setView(v) {
  qsa("#viewSeg button").forEach(b => b.classList.toggle("active", b.dataset.view === v));
  qs("#termLwp").classList.toggle("hidden", v !== "terminal");
  qs("#resultsView").classList.toggle("hidden", v !== "results");
  qs("#typeableWrap").classList.toggle("hidden", v !== "terminal");
  qs("#lwpClear").classList.toggle("hidden", v !== "terminal");
  try { localStorage.setItem("lwp.view", v); } catch (e) {}
  if (v === "terminal") setTimeout(() => lwpTerm.refit(), 20); else resFlush();
}
function wireResults() {
  qsa("#viewSeg button").forEach(b => b.onclick = () => setView(b.dataset.view));
  let saved = "results"; try { saved = localStorage.getItem("lwp.view") || "results"; } catch (e) {}
  setView(saved);
  qs("#resFilter").oninput = ev => { RES_FILTER = ev.target.value.trim(); RES.forEach(e => !e.sep && e.el && (e.el.style.display = resMatches(e) ? "" : "none")); resCountUpdate(); };
  qsa("#resStatus button").forEach(b => b.onclick = () => {
    qsa("#resStatus button").forEach(x => x.classList.toggle("active", x === b));
    RES_STATUS = b.dataset.st; RES_FILTER = qs("#resFilter").value.trim();
    RES.forEach(e => !e.sep && e.el && (e.el.style.display = resMatches(e) ? "" : "none")); resCountUpdate();
  });
  qs("#resExpand").onclick = () => {
    const ents = RES.filter(e => !e.sep);
    const open = !ents.every(e => e.open);          // expand unless everything is open
    RES.forEach(e => { if (!e.sep) { e.open = open; e.userToggled = true; resMark(e); } });
    qs("#resExpand").textContent = open ? "collapse all" : "expand all";
  };
  qs("#resClear").onclick = () => { RES = []; CUR_ENTRY = null; resRenderAll(); resSave(); };
  qs("#resExport").onclick = resExport;
}

/* ======================= history ======================= */
const HISTORY = [];
function addHistory(cmd) {
  if (HISTORY.length && HISTORY[HISTORY.length-1].cmd === cmd) return;
  HISTORY.push({cmd, ts:new Date().toLocaleTimeString()});
  qs("#histCount").textContent = HISTORY.length;
  const li = document.createElement("li");
  li.innerHTML = `<button class="btn btn-ghost sm">copy</button><span class="ts">${esc(HISTORY[HISTORY.length-1].ts)}</span>${esc(cmd)}`;
  li.querySelector("button").onclick = () => navigator.clipboard?.writeText(cmd);
  qs("#histList").appendChild(li);
}


/* ======================= BloodHound inventory ======================= */
/* Defensive only: inventory + AD hygiene. No attack path analysis here. */
const SEV_LABEL = {high:"high", medium:"medium", low:"low", info:"info"};

async function bhDiscover() {
  const ul = qs("#bhFoundList");
  ul.innerHTML = `<li class="dim">scanning…</li>`;
  const j = await api("/api/bh/discover").then(r=>r.json()).catch(()=>({}));
  ul.innerHTML = "";
  const rows = [];
  (j.folders||[]).forEach(f => rows.push({label:`📁 ${f.path||"/"}`, sub:`${f.count} json`, path:f.path}));
  (j.files||[]).filter(f=>f.name.toLowerCase().endsWith(".zip"))
    .forEach(f => rows.push({label:`${f.uploaded?"⬆":"🗜"} ${f.name}`,
                             sub:(f.uploaded?"uploaded · ":"") + fmtSize(f.size), path:f.path}));
  if (!rows.length) { ul.innerHTML = `<li class="dim">no BloodHound output found yet</li>`; return; }
  rows.slice(0,40).forEach(r => {
    const li = document.createElement("li");
    li.innerHTML = `<span>${esc(r.label)}</span><span class="sz">${esc(r.sub)}</span>`;
    li.onclick = () => bhScan(r.path);
    ul.appendChild(li);
  });
}

function bhBusy(msg) {
  qs("#bhError").classList.add("hidden");
  qs("#bhFoundList").innerHTML = `<li class="dim">${esc(msg)}</li>`;
}
function bhFail(msg) {
  const e = qs("#bhError"); e.textContent = msg; e.classList.remove("hidden");
  bhDiscover();
}

async function bhScan(path) {
  bhBusy("analysing " + path + " …");
  const r = await api("/api/bh/scan",{method:"POST",body:JSON.stringify({path})});
  const j = await r.json().catch(()=>({}));
  if (!j.ok) return bhFail(j.error || ("HTTP " + r.status));
  bhRender(j.report);
}

async function bhUpload(file) {
  if (!file) return;
  bhBusy("uploading " + file.name + " …");
  const fd = new FormData(); fd.append("file", file);
  const r = await fetch(`/api/bh/upload?token=${encodeURIComponent(TOKEN)}`,
    {method:"POST", headers:{"X-Auth-Token":TOKEN}, body:fd});
  const j = await r.json().catch(()=>({}));
  if (!j.ok) return bhFail(j.error || ("HTTP " + r.status));
  bhRender(j.report);
}

let BH = null;                     // current report
const EX = {type: "User", q: "", sort: "name", desc: false, page: 0, size: 50, filter: ""};
const DR_HIST = [];

function bhTab(t) {
  qsa("#bhTabs button").forEach(b => b.classList.toggle("active", b.dataset.bt === t));
  qsa("#bhReport .bh-body").forEach(p => p.classList.toggle("hidden", p.dataset.bp !== t));
  if (t === "explorer") exLoad();
}

function bhBars(rows, nameKey, max, warnFn, clickFn) {
  const top = Math.max(1, ...rows.map(r => r.count));
  return rows.slice(0, max).map((r, i) => {
    const w = Math.round(100 * r.count / top);
    const warn = warnFn && warnFn(r) ? " warn" : "";
    return `<div class="bar-row"><span class="nm${clickFn ? " click" : ""}" data-i="${i}" title="${esc(r[nameKey])}">${esc(r[nameKey])}</span>` +
           `<span class="bar-track"><span class="bar-fill${warn}" style="width:${r.count ? Math.max(w, 2) : 0}%"></span></span>` +
           `<span class="n">${r.count}</span></div>`;
  }).join("") || `<div class="dim">none</div>`;
}

function bhRender(rep) {
  BH = rep;
  qs("#bhSrc").classList.add("hidden");
  qs("#bhReport").classList.remove("hidden");
  qs("#bhDrawer").classList.add("hidden"); qs("#bhReport").classList.remove("dr-open"); DR_HIST.length = 0;
  const st = rep.stats, ov = rep.overview || {};
  qs("#bhLabel").innerHTML = `<b>${esc(st.domains.join(", ") || rep.label)}</b>` +
    (st.collected ? ` · collected ${esc(String(st.collected).slice(0,10))}` : "") + ` · ${esc(rep.label)}`;
  qs("#bhSevChips").innerHTML = ["high","medium","low","info"].filter(k => rep.severity[k])
    .map(k => `<span class="sev-chip sev-${k}">${rep.severity[k]} ${k}</span>`).join("");
  qs("#bhCount").textContent = rep.checks.length;

  /* overview */
  const stat = (v, l, s="", go="") => `<div class="stat${go ? " click" : ""}" ${go}><div class="v">${v}</div><div class="l">${l}</div>` +
    (s ? `<div class="s">${s}</div>` : "") + `</div>`;
  const tc = rep.type_counts || {};
  qs("#bhStats").innerHTML =
    stat(st.users_enabled, "enabled users", `${st.users} total`, `data-ex="User"`) +
    stat(st.computers_enabled, "enabled computers", `${ov.servers ?? "?"} servers · ${ov.workstations ?? "?"} workstations`, `data-ex="Computer"`) +
    stat(st.domain_admins, "domain admins", `${ov.privileged_users ?? "?"} privileged accounts`, `data-ex="User" data-f="privileged"`) +
    stat(st.dcs, "domain controllers") +
    stat(st.groups, "groups", "", `data-ex="Group"`) +
    stat(st.ous, "OUs", "", `data-ex="OU"`) +
    stat(st.gpos, "GPOs", "", `data-ex="GPO"`) +
    stat((tc.CertTemplate || 0) + " / " + (tc.EnterpriseCA || 0), "templates / CAs", "", `data-ex="CertTemplate"`) +
    stat(rep.seconds < 1 ? Math.max(1, Math.round(rep.seconds*1000)) + "ms" : rep.seconds + "s", "parse time", `${st.objects} objects`);
  qsa("#bhStats [data-ex]").forEach(el => el.onclick = () => {
    EX.type = el.dataset.ex; EX.filter = el.dataset.f || ""; EX.page = 0; EX.q = ""; qs("#exSearch").value = "";
    bhTab("explorer");
  });
  const ch = rep.charts || {};
  const oldBucket = r => /1 year|never|180/.test(r.label);
  qs("#chUserLogon").innerHTML = bhBars(ch.user_logon || [], "label", 6, oldBucket);
  qs("#chUserPwd").innerHTML = bhBars(ch.user_pwd || [], "label", 6, r => /1 year/.test(r.label));
  qs("#chCompLogon").innerHTML = bhBars(ch.computer_logon || [], "label", 6, oldBucket);
  qs("#bhPriv").innerHTML = bhBars(rep.privileged_groups.filter(r => r.count > 0), "group", 12,
    r => r.group === "Domain Admins" && r.count > 10);
  const oldOs = /windows (xp|vista|7|8|2000|server 2003|server 2008|server 2012)|2003|2008|2012/i;
  qs("#bhOs").innerHTML = bhBars(rep.os_breakdown, "os", 12, r => oldOs.test(r.os));
  qs("#bhDcs").innerHTML = (ov.dcs || []).map(d =>
    `<div class="kv click" data-id="${esc(d.id)}"><span class="k">${esc(d.name)}</span><span class="v">${esc(d.os || "?")}` +
    (d.last_logon != null ? ` · seen ${d.last_logon}d ago` : "") + `</span></div>`).join("") || `<div class="dim">none found</div>`;
  qs("#bhDoms").innerHTML = (ov.domains || []).map(d =>
    `<div class="kv"><span class="k">${esc(d.name)}</span><span class="v">level ${esc(d.functional_level ?? "?")}` +
    (d.created != null ? ` · created ${Math.round(d.created/365)}y ago` : "") + `</span></div>`).join("") +
    (ov.trusts || []).map(t => `<div class="kv"><span class="k">→ ${esc(t.target)}</span><span class="v">${esc(t.direction)} · ${esc(t.type)} · SID filtering ${esc(t.sidfiltering)}</span></div>`).join("");
  qsa("#bhDcs [data-id]").forEach(el => el.onclick = () => drOpen(el.dataset.id));

  /* findings */
  bhRenderChecks();

  /* explorer type buttons */
  const types = [["User","Users"],["Computer","Computers"],["Group","Groups"],["OU","OUs"],["GPO","GPOs"],
                 ["CertTemplate","Templates"],["EnterpriseCA","CAs"],["Domain","Domains"]].filter(([t]) => (tc[t] || 0) > 0);
  qs("#exType").innerHTML = types.map(([t, l]) =>
    `<button type="button" data-t="${t}" class="${t === EX.type ? "active" : ""}">${l} <span class="dim">${tc[t]}</span></button>`).join("");
  qsa("#exType button").forEach(b => b.onclick = () => { EX.type = b.dataset.t; EX.page = 0; EX.sort = "name"; EX.desc = false; exLoad(); });
  bhTab("overview");
  qs(".bh").scrollTop = 0;
}

let BH_SEV = "all", BH_Q = "";
function bhRenderChecks() {
  const box = qs("#bhChecks"); box.innerHTML = "";
  const q = BH_Q.toLowerCase();
  const list = BH.checks.filter(c => (BH_SEV === "all" || c.severity === BH_SEV) &&
    (!q || (c.title + " " + c.why + " " + c.items.map(i => (i.name || "") + " " + (i.detail || "")).join(" ")).toLowerCase().includes(q)));
  if (!list.length) box.innerHTML = `<div class="ex-empty">no finding matches</div>`;
  list.forEach((c, i) => {
    const el = document.createElement("div");
    el.className = "chk"; el.dataset.cid = c.id;
    const pct = c.pct !== null && c.pct !== undefined ? ` (${c.pct}%)` : "";
    el.innerHTML =
      `<div class="chk-head"><span class="sev-chip sev-${c.severity}">${c.severity}</span>` +
      `<span class="t">${esc(c.title)}</span><span class="c">${c.count}${pct}</span><span class="chev">▸</span></div>` +
      `<div class="chk-body hidden"><p>${esc(c.why)}</p><p class="fix"><b>Fix.</b> ${esc(c.fix)}</p>` +
      (c.items.length ? `<ul class="chk-items">` + c.items.map(it =>
          `<li class="${it.id ? "click" : ""}" ${it.id ? `data-id="${esc(it.id)}"` : ""}><span class="nm">${esc(it.name || "")}</span>` +
          (it.detail ? `<span class="dt">${esc(it.detail)}</span>` : "") + `</li>`).join("") + `</ul>` +
          (c.truncated ? `<div class="chk-more">showing ${c.items.length} of ${c.count} — full list in the .md export</div>` : "") : "") +
      `</div>`;
    const head = el.querySelector(".chk-head"), body = el.querySelector(".chk-body");
    head.onclick = () => { body.classList.toggle("hidden");
      el.querySelector(".chev").textContent = body.classList.contains("hidden") ? "▸" : "▾"; };
    el.querySelectorAll("li[data-id]").forEach(li => li.onclick = () => drOpen(li.dataset.id));
    if (i < 3 && !q && BH_SEV === "all") head.click();
    if (q) head.click();
    box.appendChild(el);
  });
}

/* ---- explorer ---- */
const EX_LABEL = {name:"Name", enabled:"Enabled", privileged:"Privileged", last_logon:"Last logon", pwd_age:"Password age",
  flags:"Flags", ou:"OU", description:"Description", os:"Operating system", role:"Role", members:"Members",
  users_total:"Users (nested)", objects:"Objects", gpos:"GPOs", linked_to:"Linked to", created:"Created", ekus:"EKUs",
  functional_level:"Functional level"};
const BAD_FLAGS = new Set(["no-preauth","pwd-not-required","unconstrained","requester-supplies-subject","SAN-from-request"]);
const WARN_FLAGS = new Set(["SPN","pwd-never-expires","adminCount","constrained"]);
const OK_FLAGS = new Set(["LAPS","sensitive","manager-approval"]);

function exCell(col, v) {
  if (col === "name") return `<td class="nm" title="${esc(v)}">${esc(v)}</td>`;
  if (typeof v === "boolean") return `<td class="${v ? "yes" : "no"}">${v ? "yes" : "no"}</td>`;
  if (col === "last_logon" || col === "pwd_age" || col === "created") {
    if (v === null || v === undefined) return `<td class="vold">never</td>`;
    const cls = col === "created" ? "" : (v > 365 ? "vold" : v > 90 ? "old" : "");
    return `<td class="${cls}">${v} d</td>`;
  }
  if (col === "flags") return `<td>${(v || []).map(f => `<span class="tag ${BAD_FLAGS.has(f) ? "bad" : WARN_FLAGS.has(f) ? "warn" : OK_FLAGS.has(f) ? "ok" : ""}">${esc(f)}</span>`).join("")}</td>`;
  if (col === "role") return `<td><span class="tag ${v === "DC" ? "acc" : ""}">${esc(v)}</span></td>`;
  if (Array.isArray(v)) return `<td title="${esc(v.join(", "))}">${v.length ? esc(v.join(", ")) : `<span class="dim">—</span>`}</td>`;
  return `<td title="${esc(v ?? "")}">${esc(v ?? "")}</td>`;
}

async function exLoad() {
  qsa("#exType button").forEach(b => b.classList.toggle("active", b.dataset.t === EX.type));
  qsa("#exFilter button").forEach(b => b.classList.toggle("active", b.dataset.f === EX.filter));
  const qsx = new URLSearchParams({type: EX.type, q: EX.q, sort: EX.sort, desc: EX.desc ? "1" : "0",
                                   page: EX.page, size: EX.size, filter: EX.filter}).toString();
  const j = await api("/api/bh/objects?" + qsx).then(r => r.json()).catch(() => ({}));
  const thead = qs("#exTable thead"), tbody = qs("#exTable tbody");
  if (!j.ok) { tbody.innerHTML = `<tr><td class="ex-empty">${esc(j.error || "load failed")}</td></tr>`; return; }
  thead.innerHTML = "<tr>" + j.cols.map(c =>
    `<th data-c="${c}" class="${c === EX.sort ? "sorted" : ""}">${EX_LABEL[c] || c}${c === EX.sort ? (EX.desc ? " ↓" : " ↑") : ""}</th>`).join("") + "</tr>";
  qsa("#exTable th").forEach(th => th.onclick = () => {
    if (EX.sort === th.dataset.c) EX.desc = !EX.desc; else { EX.sort = th.dataset.c; EX.desc = ["last_logon","pwd_age","members","users_total","objects","gpos"].includes(th.dataset.c); }
    EX.page = 0; exLoad();
  });
  tbody.innerHTML = j.rows.length ? j.rows.map(r =>
    `<tr data-id="${esc(r.id)}">` + j.cols.map(c => exCell(c, r[c])).join("") + `</tr>`).join("")
    : `<tr><td class="ex-empty" colspan="${j.cols.length}">no object matches</td></tr>`;
  qsa("#exTable tbody tr[data-id]").forEach(tr => tr.onclick = () => {
    qsa("#exTable tbody tr.sel").forEach(x => x.classList.remove("sel")); tr.classList.add("sel"); drOpen(tr.dataset.id); });
  const pages = Math.max(1, Math.ceil(j.total / j.size));
  qs("#exInfo").textContent = `${j.total} ${EX.type.toLowerCase()}${j.total === 1 ? "" : "s"}` + (EX.q || EX.filter ? " match" : "");
  qs("#exPage").textContent = `page ${j.page + 1} / ${pages}`;
  qs("#exPrev").disabled = j.page <= 0;
  qs("#exNext").disabled = j.page + 1 >= pages;
}

/* ---- detail drawer ---- */
async function drOpen(id, fromHistory) {
  const j = await api("/api/bh/object?id=" + encodeURIComponent(id)).then(r => r.json()).catch(() => ({}));
  if (!j.ok) return;
  const o = j.object;
  if (!fromHistory) { const cur = qs("#bhDrawer").dataset.id; if (cur && !qs("#bhDrawer").classList.contains("hidden")) DR_HIST.push(cur); }
  qs("#bhDrawer").dataset.id = o.id;
  qs("#drBack").disabled = !DR_HIST.length;
  qs("#drType").textContent = o.type + (o.row && o.row.privileged ? " · privileged" : "");
  qs("#drTitle").textContent = o.name;
  const link = r => r && BH_has(r) ? `<span class="dr-link" data-id="${esc(r.id)}">${esc(r.name)}</span>` : `<span class="dr-link dim">${esc(r.name)}</span>`;
  const sec = (t, html) => html ? `<div class="dr-sec"><h5>${t}</h5>${html}</div>` : "";
  const row = o.row || {};
  const keyinfo = Object.entries(row).filter(([k]) => !["id","name","type"].includes(k)).map(([k, v]) => {
    let val = v;
    if (typeof v === "boolean") val = v ? "yes" : "no";
    else if (["last_logon","pwd_age","created"].includes(k)) val = v == null ? "never" : `${v} days ago`;
    else if (Array.isArray(v)) val = v.join(", ") || "—";
    return `<tr><td>${esc(EX_LABEL[k] || k)}</td><td>${esc(val)}</td></tr>`;
  }).join("");
  let html = "";
  if (o.findings.length) html += sec("Findings", `<div>` + o.findings.map(f =>
    `<div class="dr-find" data-cid="${esc(f.id)}"><span class="sev-chip sev-${f.severity}">${f.severity}</span><span class="t">${esc(f.title)}</span></div>`).join("") + `</div>`);
  html += sec("Summary", `<table class="dr-props">${keyinfo}</table>`);
  if (o.member_of.length) html += sec(`Member of (${o.member_of.length})`, `<div class="dr-chips">${o.member_of.map(link).join("")}</div>`);
  if (o.member_of_nested.length) html += sec(`Also member through nesting (${o.member_of_nested.length})`, `<div class="dr-chips">${o.member_of_nested.map(link).join("")}</div>`);
  if (o.members) html += sec(`Direct members (${o.members.length}) · ${o.members_total_users} users in total`,
    `<div class="dr-chips">${o.members.slice(0, 300).map(link).join("")}${o.members.length > 300 ? `<span class="dim">… ${o.members.length - 300} more</span>` : ""}</div>`);
  if (o.linked_to) html += sec("Linked to", o.linked_to.length ? `<div class="dr-chips">${o.linked_to.map(n => `<span class="dr-link dim">${esc(n)}</span>`).join("")}</div>` : `<span class="dim">nowhere</span>`);
  html += sec(`All attributes (${Object.keys(o.props).length})`, `<table class="dr-props">` +
    Object.entries(o.props).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(typeof v === "object" ? JSON.stringify(v) : v)}</td></tr>`).join("") + `</table>`);
  qs("#drBody").innerHTML = html;
  qsa("#drBody .dr-link[data-id]").forEach(el => el.onclick = () => drOpen(el.dataset.id));
  qsa("#drBody .dr-find").forEach(el => el.onclick = () => bhGotoFinding(el.dataset.cid));
  qs("#bhDrawer").classList.remove("hidden");
  qs("#bhReport").classList.add("dr-open");
  qs("#drBody").scrollTop = 0;
}
function BH_has(r) { return r && r.id && !/\(not collected\)$/.test(r.name); }
function drClose() { qs("#bhDrawer").classList.add("hidden"); qs("#bhReport").classList.remove("dr-open"); DR_HIST.length = 0; qsa("#exTable tbody tr.sel").forEach(x => x.classList.remove("sel")); }
function bhGotoFinding(cid) {
  BH_SEV = "all"; BH_Q = ""; qs("#bhFindFilter").value = "";
  qsa("#bhSevFilter button").forEach(b => b.classList.toggle("active", b.dataset.sev === "all"));
  bhRenderChecks(); bhTab("findings");
  const el = qs(`#bhChecks .chk[data-cid="${cid}"]`);
  if (!el) return;
  const body = el.querySelector(".chk-body");
  if (body.classList.contains("hidden")) el.querySelector(".chk-head").click();
  el.scrollIntoView({block: "start"}); el.classList.remove("flash"); void el.offsetWidth; el.classList.add("flash");
}

function wireBh() {
  qs("#bhFile").onchange = e => bhUpload(e.target.files[0]);
  const drop = qs("#bhDrop");
  ["dragenter","dragover"].forEach(ev => drop.addEventListener(ev, e => {
    e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave","drop"].forEach(ev => drop.addEventListener(ev, e => {
    e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", e => bhUpload(e.dataTransfer.files[0]));
  qs("#bhRescan").onclick = bhDiscover;
  qs("#bhNew").onclick = () => {
    qs("#bhReport").classList.add("hidden");
    qs("#bhSrc").classList.remove("hidden");
    qs("#bhFile").value = "";
    bhDiscover();
  };
  qs("#bhExport").onclick = () =>
    location.href = `/api/bh/export?token=${encodeURIComponent(TOKEN)}`;
  qsa("#bhTabs button").forEach(b => b.onclick = () => bhTab(b.dataset.bt));
  qsa("#bhSevFilter button").forEach(b => b.onclick = () => {
    qsa("#bhSevFilter button").forEach(x => x.classList.toggle("active", x === b));
    BH_SEV = b.dataset.sev; bhRenderChecks(); });
  let ft = null;
  qs("#bhFindFilter").oninput = e => { clearTimeout(ft); ft = setTimeout(() => { BH_Q = e.target.value.trim(); bhRenderChecks(); }, 150); };
  qs("#bhExpandAll").onclick = () => {
    const bodies = qsa("#bhChecks .chk-body"); const open = bodies.some(b => b.classList.contains("hidden"));
    qsa("#bhChecks .chk").forEach(el => { const b = el.querySelector(".chk-body");
      if (b.classList.contains("hidden") === open) el.querySelector(".chk-head").click(); });
    qs("#bhExpandAll").textContent = open ? "collapse all" : "expand all";
  };
  let st = null;
  qs("#exSearch").oninput = e => { clearTimeout(st); st = setTimeout(() => { EX.q = e.target.value.trim(); EX.page = 0; exLoad(); }, 200); };
  qsa("#exFilter button").forEach(b => b.onclick = () => { EX.filter = b.dataset.f; EX.page = 0; exLoad(); });
  qs("#exPrev").onclick = () => { if (EX.page > 0) { EX.page--; exLoad(); } };
  qs("#exNext").onclick = () => { EX.page++; exLoad(); };
  qs("#exCsv").onclick = () => {
    const qsx = new URLSearchParams({type: EX.type, q: EX.q, sort: EX.sort, desc: EX.desc ? "1" : "0", filter: EX.filter, token: TOKEN});
    location.href = "/api/bh/objects.csv?" + qsx.toString();
  };
  qs("#drClose").onclick = drClose;
  qs("#drBack").onclick = () => { const id = DR_HIST.pop(); if (id) drOpen(id, true); };
  document.addEventListener("keydown", e => {
    if (e.key === "Escape" && !qs("#bhDrawer").classList.contains("hidden")) drClose(); });
}

/* ======================= config / session ======================= */
function readConfig() {
  const v = id => (qs("#"+id)?.value||"").trim();
  const ck = id => qs("#"+id)?.checked||false;
  const activeAuth = qs("#authTabs button.active")?.dataset.auth;
  const cfg = {
    target:v("f_target"), domain:v("f_domain"), user:v("f_user"),
    targets:v("f_targets"), interface:v("f_interface"), attacker_ip:v("f_attacker_ip"),
    dns_ip:v("f_dns_ip"), ldap_port:v("f_ldap_port"), dc_domain:v("f_dc_domain"),
    user_wordlist:v("f_user_wordlist"), pass_wordlist:v("f_pass_wordlist"), output:v("f_output"),
    ldaps:ck("c_ldaps"), ldap_sign:ck("c_ldap_sign"), ldap_bind:ck("c_ldap_bind"),
    force_kerb:ck("c_force_kerb"), use_ip:ck("c_use_ip"), dns_tcp:ck("c_dns_tcp"),
    auto_config:ck("c_auto_config"), verbose:ck("c_verbose"), no_exec:ck("c_no_exec"),
    offline:ck("c_offline"), auto:qs("#modeSeg button.active")?.dataset.mode === "auto",
  };
  if (activeAuth==="password") cfg.password=v("f_password");
  if (activeAuth==="hash")     cfg.hash=v("f_hash");
  if (activeAuth==="kerb")     cfg.kerb=v("f_kerb");
  if (activeAuth==="aeskey")   cfg.aeskey=v("f_aeskey");
  if (activeAuth==="cert")   { cfg.cert=v("f_cert"); cfg.certpass=v("f_certpass"); }
  return cfg;
}

const FORM_SECRETS = new Set(["f_password","f_hash","f_aeskey","f_certpass"]);
function saveForm() {
  try {
    const d = {mode: qs("#modeSeg button.active")?.dataset.mode,
               auth: qs("#authTabs button.active")?.dataset.auth, f: {}, c: {}};
    qsa("#cfgBar input").forEach(i => {
      if (!i.id || FORM_SECRETS.has(i.id)) return;
      if (i.type === "checkbox") d.c[i.id] = i.checked; else d.f[i.id] = i.value;
    });
    localStorage.setItem("lwp.form", JSON.stringify(d));
  } catch (e) {}
}
function loadForm() {
  try {
    const d = JSON.parse(localStorage.getItem("lwp.form") || "null"); if (!d) return;
    Object.entries(d.f || {}).forEach(([k, v]) => { const i = qs("#" + k); if (i) i.value = v; });
    Object.entries(d.c || {}).forEach(([k, v]) => { const i = qs("#" + k); if (i) i.checked = v; });
    if (d.mode) qsa("#modeSeg button").forEach(b => b.classList.toggle("active", b.dataset.mode === d.mode));
    if (d.auth) qs(`#authTabs button[data-auth="${d.auth}"]`)?.click();
  } catch (e) {}
}

async function startSession(cfgOverride) {
  const err = qs("#cfgError"); err.classList.add("hidden");
  const cfg = cfgOverride || readConfig();
  const r = await api("/api/session/start",{method:"POST",body:JSON.stringify(cfg)});
  const j = await r.json().catch(()=>({}));
  if (!j.ok) { err.textContent = j.error||("HTTP "+r.status); err.classList.remove("hidden");
    setTimeout(() => err.classList.add("hidden"), 6000); return; }
  LAST_CFG = cfg;
  afterStart(j);
}
function afterStart(j) {
  RES_RESTORED = false;
  api("/api/session/status").then(r=>r.json()).then(st => { SESSION_ID = st.id; resSave(); }).catch(()=>{});
  SESSION_RUNNING = true; CUR_MENU = null; PLAIN = ""; LINE_ACC = ""; PROMPT_SIG = null;
  hidePanel(); RUN_STATE = "off"; setRunState("running");
  setTopStatus(true);
  lwpTerm.term.clear();
  lwpTerm.reconnect();
  setTimeout(()=>note(`$ ${j.cmdline}`), 300);
  qs("#advPanel").open = false;
  qs("#cfgBar").classList.add("running");
  if (CUR_ENTRY) resClose("done");
  IN_MENU = false; AUTO_SECTION = ""; PENDING = null;
  resSep(`session started ${new Date().toLocaleTimeString()} · ${j.cmdline.replace(/^\/bin\/bash \S+\s*/, "linWinPwn.sh ")}`);
  const auto = (LAST_CFG && LAST_CFG.auto) || /--auto\b/.test(j.cmdline);
  if (auto) { qs("#railDesc").textContent = "Auto mode: linWinPwn runs every default enumeration by itself. Buttons are off; follow the Results."; setView("results"); }
}

async function stopSession() {
  await api("/api/session/stop",{method:"POST"});
  sessionEnded();
}
function sessionEnded() {
  SESSION_RUNNING=false; CUR_MENU=null;
  if (CUR_ENTRY) resClose("done");
  qs("#cfgBar").classList.remove("running");
  hidePanel(); setRunState("off"); setTopStatus(false);
}
function setTopStatus(on){
  qs("#statusText").textContent = on ? "session running" : "session stopped";
  qs("#statusDot").className = "dot " + (on ? "dot-on" : "dot-off");
  qs("#btnStop").disabled = !on;
  qs("#btnStart").textContent = on ? "Restart session ⟳" : "Start session ▸";
}

/* Stop = Ctrl+C for the running command only (server sends SIGINT to the
   processes started by the script, then forces them if they ignore it).
   The script goes back to its menu and the session keeps running. */
async function stopTask() {
  if (!SESSION_RUNNING) return;
  const r = await api("/api/session/stop_task",{method:"POST"});
  const j = await r.json().catch(()=>({}));
  if (!j.ok) { note(`stop failed: ${j.error||r.status}`); return; }
  if (!j.stopped.length) {
    // nothing running: if a question is open, answer it with Ctrl+C semantics = go back
    note(RUN_STATE==="input" ? "nothing is running (answer or leave the form)" : "nothing is running");
    return;
  }
  if (CUR_ENTRY && (CUR_ENTRY.status === "running" || CUR_ENTRY.status === "waiting")) {
    // keep it as the current card: the tool's last lines still belong to it
    CUR_ENTRY.status = "stopped"; CUR_ENTRY.ended = Date.now(); resMark(CUR_ENTRY);
  }
  const names = [...new Set(j.stopped.map(p=>p.cmd.split(" ")[0].split("/").pop()).filter(Boolean))];
  note(`^C stopped: ${names.slice(0,6).join(", ")}`);
}

/* Reset = kill the whole session and start it again with the same config. */
async function resetSession() {
  if (!SESSION_RUNNING) return;
  note("resetting the session…");
  const r = await api("/api/session/restart",{method:"POST"});
  const j = await r.json().catch(()=>({}));
  if (!j.ok) { note(`reset failed: ${j.error||r.status}`); return; }
  afterStart(j);
}

/* ======================= tabs ======================= */
function switchTab(name){
  // leaving the linWinPwn tab with an open prompt: mark the tab so the user
  // sees there is still a question waiting when they look away.
  if (name !== "lwp" && !qs("#promptPanel").classList.contains("hidden"))
    qs('#mainTabs button[data-tab="lwp"]').classList.add("attn");
  qsa("#mainTabs button").forEach(b=>b.classList.toggle("active",b.dataset.tab===name));
  qsa(".tabpane").forEach(p=>p.classList.toggle("hidden",p.dataset.tab!==name));
  if (name==="lwp") { qs('#mainTabs button[data-tab="lwp"]').classList.remove("attn"); lwpTerm.refit(); }
  if (name==="shell"){
    if (!shellTerm){ shellTerm = makeTerm("#termShell","/ws/shell",{autoReconnect:true}); shellTerm.connect(); }
    else shellTerm.refit();
  }
  if (name==="loot") loadLoot(lootPath);
  if (name==="bh" && !BH_LOADED) { BH_LOADED = true; bhDiscover(); }
}

/* ======================= loot browser ======================= */
let lootPath="";
let BH_LOADED=false;
async function loadLoot(path){
  lootPath = path||"";
  qs("#lootPath").textContent = "/"+lootPath;
  const r = await api("/api/files?path="+encodeURIComponent(lootPath));
  const j = await r.json().catch(()=>({}));
  const list = qs("#lootList"); list.innerHTML="";
  if (!j.ok){ list.innerHTML=`<li>· ${esc(j.error||"error")}</li>`; return; }
  if (!j.dir) return;
  if (!j.entries.length) list.innerHTML=`<li>· (empty)</li>`;
  j.entries.forEach(e=>{
    const li=document.createElement("li");
    li.innerHTML=`<span class="ic">${e.dir?"📁":"📄"}</span><span>${esc(e.name)}</span>`+
      (e.dir?"":`<span class="sz">${fmtSize(e.size)}</span>`);
    const rel=(lootPath?lootPath+"/":"")+e.name;
    li.onclick=()=> e.dir ? loadLoot(rel) : previewFile(rel);
    list.appendChild(li);
  });
}
async function previewFile(path){
  const r = await api("/api/files?path="+encodeURIComponent(path));
  const j = await r.json().catch(()=>({}));
  const view = qs("#lootView");
  const dl = `<a href="/api/download?path=${encodeURIComponent(path)}&token=${encodeURIComponent(TOKEN)}">download</a>`;
  if (!j.ok){ view.textContent=j.error||"error"; return; }
  if (j.too_big){ view.innerHTML=`File too large to preview. ${dl}`; return; }
  if (j.binary){ view.innerHTML =
    `<div>${esc(path)}</div><div style="margin-top:8px;color:var(--dim)">` +
    `Binary file, ${fmtSize(j.size)} — no text preview. ${dl}</div>`; return; }
  // linWinPwn writes colour codes into its logs: strip them for reading
  const text = (j.content||"").replace(ANSI_RE, "");
  view.innerHTML = `<div style="margin-bottom:8px">${esc(path)} · ${dl}</div>` + esc(text||"(empty)");
}
function fmtSize(n){ if(n<1024)return n+"B"; if(n<1048576)return (n/1024).toFixed(1)+"K";
  return (n/1048576).toFixed(1)+"M"; }

/* ======================= wiring ======================= */
function wire(){
  qs("#btnStart").onclick = () => startSession();
  qs("#btnStop").onclick  = stopSession;
  qs("#lwpClear").onclick = ()=>lwpTerm.term.clear();
  qs("#lwpHome").onclick  = ()=>{ if (RUN_STATE==="ready" && CUR_MENU!==null){ setRunState("running");
      api("/api/action",{method:"POST",body:JSON.stringify({keys:["back"]})}); } };
  qs("#lwpStop").onclick = stopTask;
  qs("#lwpReset").onclick = resetSession;
  qs("#lwpTypeable").onchange = e => { if (e.target.checked) lwpTerm.term.focus(); };
  qs("#menuFilter").oninput = e=>{ renderTree(e.target.value); if (CURRENT) renderActions(CURRENT); };

  qs("#promptPanel").onsubmit = e => { e.preventDefault(); answer(qs("#ppInput").value); };
  qs("#ppEnter").onclick = () => answer("");
  qs("#ppReveal").onclick = () => { const i=qs("#ppInput"); i.type = i.type==="password"?"text":"password"; i.focus(); };

  qsa("#mainTabs button").forEach(b=>b.onclick=()=>switchTab(b.dataset.tab));
  qsa("#modeSeg button").forEach(b => b.onclick = () =>
    qsa("#modeSeg button").forEach(x => x.classList.toggle("active", x === b)));
  const adv = qs("#advPanel");
  const advCount = () => {
    const n = qsa(".adv-pop input").filter(i => i.type === "checkbox" ? i.checked : i.value.trim()).length;
    const c = qs("#advCount"); c.textContent = n; c.classList.toggle("hidden", !n);
  };
  qsa(".adv-pop input").forEach(i => { i.addEventListener("input", advCount); i.addEventListener("change", advCount); });
  document.addEventListener("click", ev => { if (adv.open && !adv.contains(ev.target)) adv.open = false; });
  document.addEventListener("keydown", ev => { if (ev.key === "Escape") adv.open = false; });
  qsa("#cfgBar input:not([type=checkbox])").forEach(i => i.addEventListener("keydown", ev => {
    if (ev.key === "Enter") { ev.preventDefault(); startSession(); } }));
  wireResults();
  qsa("#cfgBar input").forEach(i => i.addEventListener("change", saveForm));
  qsa("#modeSeg button, #authTabs button").forEach(b => b.addEventListener("click", () => setTimeout(saveForm)));
  qsa("#authTabs button").forEach(b=>b.onclick=()=>{
    qsa("#authTabs button").forEach(x=>x.classList.remove("active"));
    b.classList.add("active");
    qsa(".authpane").forEach(p=>p.classList.toggle("hidden",p.dataset.pane!==b.dataset.auth));
  });
  qs("#lootUp").onclick=()=>{ if(lootPath) loadLoot(lootPath.split("/").slice(0,-1).join("/")); };
  qs("#lootRefresh").onclick=()=>loadLoot(lootPath);
  qs("#histCopyAll").onclick=()=>navigator.clipboard?.writeText(HISTORY.map(h=>h.cmd).join("\n"));
  qs("#histClear").onclick=()=>{ HISTORY.length=0; qs("#histList").innerHTML=""; qs("#histCount").textContent="0"; };
  wireBh();
}

async function init(){
  wire();
  loadForm();
  qsa(".adv-pop input")[0]?.dispatchEvent(new Event("input"));   // refresh advanced badge
  const cfg = await api("/api/config").then(r=>r.json()).catch(()=>({}));
  OUTPUT_DIR = (cfg && cfg.default_output) || "";
  if (cfg && cfg.script_present===false)
    qs("#brandMeta").textContent = "⚠ linWinPwn.sh not found next to web_ui/";
  MENUS = await api("/api/menus").then(r=>r.json()).then(d=>d.menus).catch(()=>[]);
  renderTree();
  if (MENUS.length) openMenu(MENUS.find(m=>m.id==="ad")||MENUS[0]);

  // reattach to a session already running (page reload): scrollback replays the state
  const s = await api("/api/session/status").then(r=>r.json()).catch(()=>null);
  resRestore(s && s.running ? s.id : null);
  if (s && s.running) { SESSION_ID = s.id; SESSION_RUNNING=true; setTopStatus(true); setRunState("running");
    qs("#cfgBar").classList.add("running"); lwpTerm.connect(); }

  setInterval(async()=>{
    const s = await api("/api/session/status").then(r=>r.json()).catch(()=>null);
    if (s && SESSION_RUNNING && !s.running) { sessionEnded(); note("the linWinPwn process exited"); }
  }, 3000);
}

document.addEventListener("DOMContentLoaded", init);
})();
