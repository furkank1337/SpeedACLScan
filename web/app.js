"use strict";
let PROJECT = "";           // the currently OPEN project ("" = none open)
let pwned = [];
let ANALYSIS = null;
let SELECTED = -1;
let pollTimer = null, searchTimer = null, pickedOption = null;

const $ = (id) => document.getElementById(id);
async function api(path, opts) {
  const r = await fetch(path, opts);
  const ct = r.headers.get("content-type") || "";
  const body = ct.includes("json") ? await r.json() : await r.text();
  return { ok: r.ok, status: r.status, body };
}
const qp = (o) => Object.entries(o).map(([k, v]) => k + "=" + encodeURIComponent(v)).join("&");
const esc = (s) => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/* ---------- theme ---------- */
function applyTheme(t) {
  document.documentElement.setAttribute("data-theme", t);
  $("themeBtn").textContent = t === "dark" ? "☀" : "☾";
  localStorage.setItem("speedaclscan.theme", t);
  if (ANALYSIS && $("view-project").classList.contains("active")) drawGraph();
}
function toggleTheme() { applyTheme(document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark"); }

/* ---------- view routing ---------- */
function showView(view) {
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  $("view-" + view).classList.add("active");
  // nav highlight: workspace counts as "projects"
  const navKey = view === "project" ? "projects" : view;
  document.querySelectorAll("#nav button").forEach(b => b.classList.toggle("active", b.dataset.view === navKey));
}
function go(view) {
  clearInterval(pollTimer);           // stop any poller writing into a now-hidden feed
  showView(view);
  if (view === "projects") renderProjects();
  if (view === "logs") loadLogs();
  if (view === "new") { $("npName").value = ""; setTimeout(() => $("npName").focus(), 50); }
}
function resetFeeds() {
  clearInterval(pollTimer);
  ["sc", "im", "an"].forEach(p => {
    const f = $(p + "Feed"); if (f) { f.innerHTML = ""; f.classList.add("hidden"); }
    const pr = $(p + "Progress"); if (pr) pr.classList.add("hidden");
  });
}

/* ---------- projects list ---------- */
async function renderProjects() {
  const { body: list } = await api("/api/projects");
  const box = $("projList");
  $("projEmpty").classList.toggle("hidden", list.length > 0);
  box.classList.toggle("hidden", list.length === 0);
  box.innerHTML = list.map(p => {
    const st = p.status || "created";
    const paths = p.last_paths != null ? `${p.last_paths} paths` : "not analyzed";
    const j = JSON.stringify(p.name);
    return `<div class="proj-row" onclick='enterProject(${j})'>
      <div class="pr-main"><div class="pr-name">${esc(p.name)}</div>
        <div class="pr-sub muted sm">${esc(st)} · ${paths}</div></div>
      <button class="pr-del" title="Delete project" onclick='event.stopPropagation();deleteProject(${j})'>🗑</button>
      <div class="pr-go">open →</div></div>`;
  }).join("");
}
function deleteProject(name) {
  confirmModal("Delete project", `Delete “${name}”? This removes its collection, findings, logs and masking map. This cannot be undone.`, async () => {
    await api("/api/projects/delete", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name }) });
    if (PROJECT === name) PROJECT = "";
    renderProjects();
  }, "Delete");
}

/* ---------- confirm modal ---------- */
function confirmModal(title, msg, onOk, okLabel) {
  $("modalTitle").textContent = title;
  $("modalMsg").textContent = msg;
  const ok = $("modalOk");
  ok.textContent = okLabel || "Confirm";
  ok.onclick = () => { closeModal(); onOk && onOk(); };
  $("modal").classList.remove("hidden");
}
function closeModal() { $("modal").classList.add("hidden"); }
document.addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });

async function createAndEnter() {
  const name = $("npName").value.trim();
  if (!name) { $("npStat").textContent = "Enter a name."; return; }
  await api("/api/projects", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name }) });
  enterProject(name);
}

async function enterProject(name) {
  PROJECT = name;
  localStorage.setItem("speedaclscan.project", name);
  showView("project");
  await renderProject();
}

/* ---------- project workspace ---------- */
async function renderProject() {
  if (!PROJECT) return go("projects");
  $("pTitle").textContent = PROJECT;
  resetFeeds();                       // clear any stale feed/progress from another project
  pickedOption = null;
  $("optScan").classList.remove("sel"); $("optImport").classList.remove("sel");
  $("scanForm").classList.add("hidden"); $("importForm").classList.add("hidden");

  const { body: s } = await api("/api/search?" + qp({ project: PROJECT, q: "" }));
  const hasData = !!s.total;
  $("dataStat").textContent = hasData ? s.total + " objects collected" : "no data yet";
  $("noData").classList.toggle("hidden", hasData);
  $("haveData").classList.toggle("hidden", !hasData);
  // collect section: expanded when empty, collapsed when data exists
  $("collectBody").classList.toggle("hidden", hasData);
  $("collectToggle").textContent = hasData ? "Re-collect" : "Collect";

  await loadPwned();
  await loadScope();
  await loadTargets();
  if (hasData) runSearch();

  const an = await api("/api/analysis?" + qp({ project: PROJECT }));
  ANALYSIS = an.ok ? an.body : null;
  $("pStatus").textContent = ANALYSIS ? "analyzed" : hasData ? "ready to analyze" : "empty";
  $("pSteps").innerHTML =
    `<span class="st ${hasData ? "done" : "on"}">1 · Collect</span>
     <span class="st ${!hasData ? "" : pwned.length ? "done" : "on"}">2 · Pwned</span>
     <span class="st ${ANALYSIS ? "done" : pwned.length ? "on" : ""}">3 · Analyze</span>`;
  $("resultsWrap").classList.toggle("hidden", !ANALYSIS);
  if (ANALYSIS) renderResults();
  updateRunState();

  // if a job is still running for THIS project, re-attach its live feed
  const { body: job } = await api("/api/job?" + qp({ project: PROJECT }));
  if (job.running) {
    const pre = job.kind === "scan" ? "sc" : job.kind === "import" ? "im" : "an";
    if (pre !== "an") toggleCollect(true);
    $(pre + "Feed").classList.remove("hidden"); $(pre + "Progress").classList.remove("hidden");
    pollJob(pre, () => renderProject());
  }
}
function toggleCollect(force) {
  const b = $("collectBody");
  if (force === true) b.classList.remove("hidden");
  else b.classList.toggle("hidden");
}
function updateRunState() {
  $("analyzeBtn").disabled = pwned.length === 0;
  $("runHint").textContent = pwned.length === 0 ? "select at least one compromised principal first" : "";
}

/* ---------- pwned ---------- */
function debouncedSearch() { clearTimeout(searchTimer); searchTimer = setTimeout(runSearch, 150); }
async function runSearch() {
  if (!PROJECT) return;
  const q = $("pwSearch").value.trim();
  const { body: r } = await api("/api/search?" + qp({ project: PROJECT, q }));
  const box = $("pwResults");
  if (r.note) { box.innerHTML = ""; return; }
  box.innerHTML = r.results.map(n => `
    <div class="ri"><span class="badge" style="background:var(--c-${n.type})">${n.type}</span>
      <span class="nm">${esc(n.name)}</span>${n.admincount ? '<span class="tag">adminCount</span>' : ''}
      <button class="btn sec sm" onclick='addPwned(${JSON.stringify(n.name)})'>add</button></div>`).join("")
    || (q ? '<div class="ri"><span class="muted sm">no matches</span></div>' : "");
}
async function loadPwned() {
  const { body } = await api("/api/pwned?" + qp({ project: PROJECT }));
  pwned = body || []; renderPwned();
}
function renderPwned() {
  $("pwnedChips").innerHTML = pwned.map((p, i) =>
    `<span class="chipx">${esc(p)}<button onclick="rmPwned(${i})">×</button></span>`).join("") || '<span class="muted sm">nothing yet</span>';
  $("pwCount").textContent = pwned.length + " marked";
  updateRunState();
}
function addPwned(name) { if (!pwned.some(p => p.toUpperCase() === name.toUpperCase())) { pwned.push(name); renderPwned(); savePwned(); } }
function rmPwned(i) { pwned.splice(i, 1); renderPwned(); savePwned(); }
async function savePwned() {
  await api("/api/pwned", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ project: PROJECT, items: pwned }) });
}

/* ---------- scope + custom targets ---------- */
async function loadScope() {
  const { body: s } = await api("/api/scope?" + qp({ project: PROJECT }));
  $("scEnum").checked = s.enumerate_all !== false;
  $("scStand").checked = s.standalone !== false;
  $("scBroad").checked = s.broaden !== false;
  $("scAdcs").checked = s.detect_adcs !== false;
}
async function saveScope() {
  const scope = { enumerate_all: $("scEnum").checked, standalone: $("scStand").checked,
    broaden: $("scBroad").checked, detect_adcs: $("scAdcs").checked, k: 5 };
  await api("/api/scope", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ project: PROJECT, scope }) });
}
let targets = [];
async function loadTargets() {
  const { body } = await api("/api/custom_targets?" + qp({ project: PROJECT }));
  targets = body || []; renderTargets();
}
function renderTargets() {
  $("tgtChips").innerHTML = targets.map((t, i) =>
    `<span class="chipx tgt">${esc(t)}<button onclick="rmTarget(${i})">×</button></span>`).join("")
    || '<span class="muted sm">none — Domain Admins / DCs are always targets</span>';
}
function addTarget(v) { v = (v || "").trim(); if (v && !targets.some(t => t.toUpperCase() === v.toUpperCase())) { targets.push(v); renderTargets(); saveTargets(); } }
function rmTarget(i) { targets.splice(i, 1); renderTargets(); saveTargets(); }
async function saveTargets() {
  await api("/api/custom_targets", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ project: PROJECT, items: targets }) });
}

/* ---------- analyze ---------- */
async function startAnalyze() {
  if (!PROJECT || pwned.length === 0) return;
  $("analyzeBtn").disabled = true;
  $("anProgress").classList.remove("hidden"); $("anFeed").classList.remove("hidden"); $("anFeed").innerHTML = ""; setBar("an", 0);
  const { body } = await api("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ project: PROJECT, use_ai: $("useAi").checked }) });
  if (body.error) { feed("anFeed", "error", body.error); $("analyzeBtn").disabled = false; return; }
  pollJob("an", async () => { $("analyzeBtn").disabled = false; await renderProject(); });
}

/* ---------- collect: scan / import ---------- */
function pickOption(which) {
  pickedOption = which;
  $("optScan").classList.toggle("sel", which === "scan");
  $("optImport").classList.toggle("sel", which === "import");
  $("scanForm").classList.toggle("hidden", which !== "scan");
  $("importForm").classList.toggle("hidden", which !== "import");
}
async function startScan() {
  if (!PROJECT) return;
  await saveNxcToConfig();
  $("scanBtn").disabled = true; $("scProgress").classList.remove("hidden"); $("scFeed").classList.remove("hidden"); $("scFeed").innerHTML = ""; setBar("sc", 0);
  const body = { project: PROJECT, dc_ip: $("scDc").value.trim(), dc_fqdn: $("scFqdn").value.trim(), domain: $("scDomain").value.trim(), user: $("scUser").value.trim(), password: $("scPass").value };
  const { body: r } = await api("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (r.error) { feed("scFeed", "error", r.error); $("scanBtn").disabled = false; return; }
  pollJob("sc", () => { $("scanBtn").disabled = false; renderProject(); });
}
function uploadZip(file) {
  if (!file || !PROJECT) return;
  $("imProgress").classList.remove("hidden"); $("imFeed").classList.remove("hidden"); $("imFeed").innerHTML = ""; setBar("im", 0);
  $("dropText").textContent = file.name;
  const xhr = new XMLHttpRequest();
  xhr.open("POST", "/api/import?" + qp({ project: PROJECT, name: file.name }));
  xhr.upload.onprogress = (e) => { if (e.lengthComputable) setBar("im", Math.round(e.loaded / e.total * 55)); };
  xhr.onload = () => { feed("imFeed", "phase", "upload complete, ingesting…"); pollJob("im", () => renderProject()); };
  xhr.onerror = () => feed("imFeed", "error", "upload failed");
  xhr.send(file);
}

/* ---------- jobs / progress ---------- */
function setBar(p, pct) { $(p + "Bar").style.width = pct + "%"; $(p + "Pct").textContent = pct + "%"; }
function feed(id, level, msg) { const d = document.createElement("div"); d.className = level; d.textContent = `[${level}] ${msg}`; $(id).appendChild(d); $(id).scrollTop = $(id).scrollHeight; }
function pollJob(prefix, onDone) {
  const proj = PROJECT;                 // bind to the project that started this job
  let seen = 0; clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    if (PROJECT !== proj) { clearInterval(pollTimer); return; }   // user switched projects
    const { body: s } = await api("/api/job?" + qp({ project: proj }));
    for (let i = seen; i < s.events.length; i++) feed(prefix + "Feed", s.events[i].level, s.events[i].msg);
    seen = s.events.length; setBar(prefix, s.pct || 0);
    if (!s.running && seen) { clearInterval(pollTimer); setBar(prefix, 100); onDone && onDone(); }
  }, 600);
}

/* ---------- results ---------- */
function sevColor(l) { return { Critical: "#b4232a", High: "#c75a12", Medium: "#b7950b", Low: "#5b6b7a" }[l] || "#5b6b7a"; }
function renderResults() {
  const a = ANALYSIS;
  $("kpis").innerHTML = `
    <div class="kpi"><b>${a.stats.nodes_total}</b><span>Objects</span></div>
    <div class="kpi"><b>${a.stats.pwned}</b><span>Compromised</span></div>
    <div class="kpi"><b>${a.stats.paths}</b><span>Paths to DA</span></div>
    <div class="kpi crit"><b>${a.stats.critical}</b><span>Critical</span></div>
    <div class="kpi high"><b>${a.stats.high}</b><span>High</span></div>`;
  $("findingList").innerHTML = a.findings.map((f, i) => {
    const c = sevColor(f.label);
    return `<div class="finding ${i === SELECTED ? "sel" : ""}" style="border-left-color:${c}" onclick="selectFinding(${i})">
      <div class="fh"><span class="rank">${f.rank}</span><span class="sev" style="background:${c}">${f.label}</span><span class="score">${f.score}</span></div>
      <div class="ft">${esc(f.start.split("@")[0])} → ${esc(f.target.split("@")[0])}</div>
      <div class="vec">${esc(f.vector)}</div><div class="rat">${esc(f.rationale)}</div></div>`;
  }).join("");
  $("dlHtml").href = "/api/report?" + qp({ project: PROJECT, fmt: "html" });
  $("dlMd").href = "/api/report?" + qp({ project: PROJECT, fmt: "md" });
  $("allBtn").classList.toggle("active", SELECTED === -1);
  drawGraph();
  // standalone dangerous ACEs
  const sa = a.standalone || [];
  $("standaloneWrap").classList.toggle("hidden", sa.length === 0);
  if (sa.length) {
    $("saTable").innerHTML = '<table><thead><tr><th>Severity</th><th>Score</th><th>Principal</th><th>Right</th><th>Over</th><th>Note</th></tr></thead><tbody>'
      + sa.map(s => { const c = sevColor(s.label); const who = s.wide ? ("everyone · " + esc(s.src.split("@")[0])) : esc(s.src.split("@")[0]);
        return `<tr><td><span class="sev" style="background:${c}">${s.label}</span></td><td class="score">${s.score}</td><td>${who}</td><td><code>${esc(s.kind)}</code></td><td>${esc(s.dst.split("@")[0])}</td><td class="muted">${esc(s.tool)}</td></tr>`; }).join("")
      + '</tbody></table>';
  }
  // ADCS line
  const ad = a.adcs || {}; const esc_edges = ad.esc_edges || {};
  const hasAdcs = Object.keys(esc_edges).length > 0;
  $("adcsLine").classList.toggle("hidden", !hasAdcs);
  if (hasAdcs) $("adcsLine").textContent = "AD CS exposure: " + Object.entries(esc_edges).map(e => e[0] + " ×" + e[1]).join(", ") + `  (templates ${ad.templates || 0}, CAs ${ad.cas || 0})`;
  $("legend").innerHTML = ["User", "Group", "Computer", "Domain", "OU", "GPO"]
    .map(t => `<span class="lg"><i style="background:var(--c-${t})"></i>${t}</span>`).join("")
    + '<span class="lg"><i class="ring-crit"></i>pwned</span><span class="lg"><i class="ring-hv"></i>target</span>';
}
function selectFinding(i) {
  SELECTED = i;
  document.querySelectorAll(".finding").forEach((el, idx) => el.classList.toggle("sel", idx === i));
  $("allBtn").classList.toggle("active", i === -1);
  const f = i >= 0 ? ANALYSIS.findings[i] : null;
  $("graphTitle").textContent = f ? `Attack graph — #${f.rank} ${f.label}` : "Attack graph — all paths";
  drawGraph();
}
function currentGraph() { return (SELECTED >= 0 && ANALYSIS.findings[SELECTED]) ? ANALYSIS.findings[SELECTED].graph : ANALYSIS.graph; }

/* ---------- graph (beautified, draggable, zoom/pan, hover-focus) ---------- */
const NS = "http://www.w3.org/2000/svg";
const GLYPH = { User: "U", Group: "G", Computer: "C", Domain: "D", OU: "O", GPO: "P", Base: "•" };
function rOf(t) { return t === "Domain" ? 19 : t === "Computer" ? 17 : t === "Group" ? 15 : 14; }
function shortLabel(label) { const s = (label || "").split("@")[0]; return s.length > 20 ? s.slice(0, 19) + "…" : s; }
let VP = null, VIEW = { k: 1, tx: 0, ty: 0 };   // viewport group + its transform (zoom/pan)
function applyView() { if (VP) VP.setAttribute("transform", `translate(${VIEW.tx},${VIEW.ty}) scale(${VIEW.k})`); }
function rootPt(svg, ev) { const p = svg.createSVGPoint(); p.x = ev.clientX; p.y = ev.clientY; return p.matrixTransform(svg.getScreenCTM().inverse()); }
function zoomAt(cx, cy, factor) {
  const nk = Math.min(4, Math.max(0.3, VIEW.k * factor));
  VIEW.tx = cx - (cx - VIEW.tx) / VIEW.k * nk;
  VIEW.ty = cy - (cy - VIEW.ty) / VIEW.k * nk;
  VIEW.k = nk; applyView();
}
function zoomBy(factor) { zoomAt(700, 300, factor); }        // around canvas centre (buttons)
function zoomReset() { VIEW = { k: 1, tx: 0, ty: 0 }; applyView(); }

function drawGraph() {
  const svg = $("graph"), G = currentGraph();
  if (!G || !G.nodes || !G.nodes.length) {
    svg.innerHTML = '<text x="700" y="300" text-anchor="middle" fill="#8894a3" font-size="16">No attack paths to graph — see Findings / Standalone ACEs</text>';
    return;
  }
  svg.innerHTML = `<defs>
    <marker id="arrow" viewBox="0 0 10 10" refX="23" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z"/></marker>
    <filter id="nsh" x="-40%" y="-40%" width="180%" height="180%"><feDropShadow dx="0" dy="1.5" stdDeviation="2.2" flood-color="#000" flood-opacity="0.28"/></filter>
  </defs>`;
  VP = document.createElementNS(NS, "g"); svg.appendChild(VP);   // everything scales together inside VP
  VIEW = { k: 1, tx: 0, ty: 0 }; applyView();
  const pos = {}; G.nodes.forEach(n => pos[n.id] = { x: n.x, y: n.y });
  const nbr = {}; G.nodes.forEach(n => nbr[n.id] = new Set([n.id]));
  G.edges.forEach(e => { if (nbr[e.src]) nbr[e.src].add(e.dst); if (nbr[e.dst]) nbr[e.dst].add(e.src); });
  // group parallel edges (same unordered pair) so they can fan out instead of overlapping
  const grp = {}; G.edges.forEach(e => { const k = [e.src, e.dst].sort().join("|"); (grp[k] = grp[k] || []).push(e); });
  const edgeOff = new Map(); const SEP = 30;
  Object.values(grp).forEach(list => list.forEach((e, i) => edgeOff.set(e, (i - (list.length - 1) / 2) * SEP)));
  const E = [], L = [], N = [];
  G.edges.forEach(e => {
    const l = document.createElementNS(NS, "path"); l.setAttribute("class", "edgeline"); VP.appendChild(l); E.push([l, e]);
    const t = document.createElementNS(NS, "text"); t.setAttribute("class", "elabel"); t.setAttribute("text-anchor", "middle"); t.textContent = e.kind; VP.appendChild(t); L.push([t, e]);
  });
  G.nodes.forEach(n => {
    const g = document.createElementNS(NS, "g");
    g.setAttribute("class", "node" + (n.pwned ? " pwned" : "") + (n.hv ? " hv" : ""));
    const c = document.createElementNS(NS, "circle"); c.setAttribute("r", rOf(n.type)); c.setAttribute("filter", "url(#nsh)"); c.style.fill = "var(--c-" + n.type + ")"; g.appendChild(c);
    const gl = document.createElementNS(NS, "text"); gl.setAttribute("class", "glyph"); gl.setAttribute("text-anchor", "middle"); gl.setAttribute("dy", ".34em"); gl.textContent = GLYPH[n.type] || "•"; g.appendChild(gl);
    const tx = document.createElementNS(NS, "text"); tx.setAttribute("class", "nlabel"); tx.setAttribute("text-anchor", "middle"); tx.setAttribute("dy", -(rOf(n.type) + 7)); tx.textContent = shortLabel(n.label); g.appendChild(tx);
    VP.appendChild(g); N.push([g, n]);
    g.addEventListener("pointerdown", ev => { cur = n; g.setPointerCapture(ev.pointerId); ev.stopPropagation(); ev.preventDefault(); });
    g.addEventListener("pointerenter", () => { if (!cur && !pan) focus(n.id); });
    g.addEventListener("pointerleave", () => { if (!cur && !pan) focus(null); });
  });
  function focus(id) {
    N.forEach(([g, n]) => g.classList.toggle("dim", id && !nbr[id].has(n.id)));
    E.forEach(([l, e]) => l.classList.toggle("dim", id && !(nbr[id].has(e.src) && nbr[id].has(e.dst))));
    L.forEach(([t, e]) => t.classList.toggle("dim", id && !(nbr[id].has(e.src) && nbr[id].has(e.dst))));
  }
  function ctrl(a, b, off) {   // perpendicular control point for a curved parallel edge
    const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2, dx = b.x - a.x, dy = b.y - a.y;
    const len = Math.hypot(dx, dy) || 1;
    return { x: mx + (-dy / len) * off * 2, y: my + (dx / len) * off * 2 };
  }
  function render() {
    E.forEach(([l, e]) => { const a = pos[e.src], b = pos[e.dst]; if (!a || !b) return;
      const off = edgeOff.get(e) || 0;
      l.setAttribute("d", off ? `M${a.x} ${a.y} Q${ctrl(a, b, off).x} ${ctrl(a, b, off).y} ${b.x} ${b.y}` : `M${a.x} ${a.y} L${b.x} ${b.y}`);
    });
    L.forEach(([t, e]) => { const a = pos[e.src], b = pos[e.dst]; if (!a || !b) return;
      const off = edgeOff.get(e) || 0;
      if (off) { const c = ctrl(a, b, off); t.setAttribute("x", 0.25 * a.x + 0.5 * c.x + 0.25 * b.x); t.setAttribute("y", 0.25 * a.y + 0.5 * c.y + 0.25 * b.y - 2); }
      else { t.setAttribute("x", (a.x + b.x) / 2); t.setAttribute("y", (a.y + b.y) / 2 - 4); }
    });
    N.forEach(([g, n]) => g.setAttribute("transform", `translate(${pos[n.id].x},${pos[n.id].y})`));
  }
  let cur = null, pan = null;
  svg.onpointerdown = ev => { if (cur) return; pan = { x: ev.clientX, y: ev.clientY, tx: VIEW.tx, ty: VIEW.ty, pt: rootPt(svg, ev) }; svg.classList.add("panning"); };
  svg.onpointermove = ev => {
    if (cur) { const q = rootPt(svg, ev); const c = { x: (q.x - VIEW.tx) / VIEW.k, y: (q.y - VIEW.ty) / VIEW.k }; pos[cur.id].x = c.x; pos[cur.id].y = c.y; render(); return; }
    if (pan) { const q = rootPt(svg, ev); VIEW.tx = pan.tx + (q.x - pan.pt.x); VIEW.ty = pan.ty + (q.y - pan.pt.y); applyView(); }
  };
  svg.onpointerup = () => { cur = null; pan = null; svg.classList.remove("panning"); focus(null); };
  svg.onwheel = ev => { ev.preventDefault(); const p = rootPt(svg, ev); zoomAt(p.x, p.y, ev.deltaY < 0 ? 1.12 : 0.89); };
  render();
}

/* ---------- config ---------- */
async function loadConfig() {
  const { body: c } = await api("/api/config");
  $("ocUrl").value = c.opencode.url || ""; $("ocPass").value = c.opencode.password || "";
  $("optIter").value = c.options.max_iterations || 12; $("optPar").value = c.options.parallelism || 1;
  $("nxPath").value = c.nxc.path || "nxc"; $("scDc").value = c.nxc.dc_ip || ""; $("scFqdn").value = c.nxc.dc_fqdn || "";
  $("scDomain").value = c.nxc.domain || ""; $("scDns").value = c.nxc.dns_server || ""; $("scExtra").value = c.nxc.extra_args || "";
  const m = $("ocModel");
  if (c.opencode.model && ![...m.options].some(o => o.value === c.opencode.model)) { const o = document.createElement("option"); o.value = o.textContent = c.opencode.model; m.appendChild(o); }
  if (c.opencode.model) m.value = c.opencode.model;
}
async function saveConfig() {
  const { body: cur } = await api("/api/config");
  cur.opencode = { url: $("ocUrl").value.trim(), model: $("ocModel").value, password: $("ocPass").value };
  cur.options = { max_iterations: +$("optIter").value || 12, parallelism: +$("optPar").value || 1 };
  await api("/api/config", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(cur) });
  const e = $("cfgMsg"); e.className = "msg ok"; e.textContent = "saved"; setTimeout(() => e.textContent = "", 3000);
}
async function saveNxcToConfig() {
  const { body: cur } = await api("/api/config");
  cur.nxc = { path: $("nxPath").value.trim() || "nxc", dc_ip: $("scDc").value.trim(), dc_fqdn: $("scFqdn").value.trim(), domain: $("scDomain").value.trim(), dns_server: $("scDns").value.trim(), extra_args: $("scExtra").value.trim() };
  await api("/api/config", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(cur) });
}
async function testOpenCode() {
  $("ocStat").textContent = "testing…"; await saveConfig();
  const { body: r } = await api("/api/config/test", { method: "POST" });
  if (r.ok) {
    $("ocStat").textContent = "connected · " + r.models.length + " models";
    const m = $("ocModel"), cur = m.value; m.innerHTML = '<option value="">(server default)</option>';
    r.models.forEach(x => { const o = document.createElement("option"); o.value = o.textContent = x; m.appendChild(o); });
    if (cur) m.value = cur;
  } else $("ocStat").textContent = "✗ " + r.error;
}

/* ---------- logs ---------- */
async function loadLogs() {
  $("logsNoProj").classList.toggle("hidden", !!PROJECT);
  $("logsCard").classList.toggle("hidden", !PROJECT);
  if (!PROJECT) return;
  const { body: logs } = await api("/api/logs?" + qp({ project: PROJECT }));
  $("logBody").innerHTML = (logs || []).slice().reverse().map(l => {
    const t = new Date(l.ts * 1000).toLocaleTimeString();
    const txt = l.text.length > 2000 ? l.text.slice(0, 2000) + "\n…(" + l.text.length + " chars)" : l.text;
    return `<tr><td class="muted sm">${t}</td><td class="dir dir-${l.dir}">${l.dir}</td><td class="muted sm">${esc(l.note || "")}</td><td><pre>${esc(txt)}</pre></td></tr>`;
  }).join("") || '<tr><td colspan="4" class="muted sm">no logs</td></tr>';
}

/* ---------- init ---------- */
(async function init() {
  applyTheme(localStorage.getItem("speedaclscan.theme") || "light");
  await loadConfig();
  go("projects");
})();
