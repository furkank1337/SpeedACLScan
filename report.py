"""Report model + Markdown and HTML renderers.

The report is LOCAL and therefore UNMASKED: it is for the operator, so it shows
real names. (The masked view is only what goes to the AI, built elsewhere.)

The HTML report is self-contained (no external assets, no CDN) so it is safe to
hand over on an engagement. It carries a BloodHound-style graph: principals are
draggable bubbles, edges are labelled with the abused right, laid out within a
bounded canvas. Styling is restrained and professional -- a small neutral
palette plus one severity accent, no decorative colour.
"""
from __future__ import annotations

import html
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List

from .analyze import Path, edge_info, path_rationale, severity
from .bloodhound import Graph

SEV_COLOR = {"Critical": "#b4232a", "High": "#c75a12", "Medium": "#b7950b", "Low": "#5b6b7a"}
TYPE_COLOR = {"User": "#2f6fb0", "Group": "#b7791f", "Computer": "#3f7d58",
              "Domain": "#7a3f9d", "OU": "#55606b", "GPO": "#8a5a3b", "Base": "#55606b"}


@dataclass
class Finding:
    rank: int
    label: str
    score: float
    vector: str
    start: str
    target: str
    blast: str
    rationale: str
    steps: List[dict]        # [{src,dst,kind,tool}]
    graph: dict = field(default_factory=dict)   # this scenario's own subgraph


@dataclass
class ReportModel:
    project: str
    generated: str
    findings: List[Finding]
    graph: dict              # {nodes:[{id,label,type,color,pwned,hv,x,y}], edges:[{src,dst,kind}]}
    stats: dict


def _label(g: Graph, sid: str) -> str:
    n = g.nodes.get(sid)
    return n.name if n else sid


def build_report_model(g: Graph, paths: List[Path], masker=None, project: str = "project") -> ReportModel:
    findings: List[Finding] = []
    node_ids: Dict[str, int] = {}
    nodes: List[dict] = []
    edges: List[dict] = []
    seen_edges = set()
    pwned_sids = {p.start for p in paths}
    hv_sids = {p.target for p in paths}

    def ensure(sid: str, layer: int):
        if sid in node_ids:
            nodes[node_ids[sid]]["layer"] = min(nodes[node_ids[sid]]["layer"], layer)
            return
        n = g.nodes.get(sid)
        ntype = n.ntype if n else "Base"
        node_ids[sid] = len(nodes)
        nodes.append({
            "id": sid,
            "label": _label(g, sid),
            "type": ntype,
            "color": TYPE_COLOR.get(ntype, TYPE_COLOR["Base"]),
            "pwned": sid in pwned_sids,
            "hv": sid in hv_sids,
            "layer": layer,
        })

    for i, p in enumerate(sorted(paths, key=lambda pp: severity(g, pp)[0], reverse=True), 1):
        score, label, vector = severity(g, p)
        steps = [{"src": _label(g, h.src), "dst": _label(g, h.dst),
                  "kind": h.kind, "tool": edge_info(h.kind)["tool"]} for h in p.hops]
        subgraph = _subgraph(g, p, pwned_sids, hv_sids)
        findings.append(Finding(i, label, score, vector, _label(g, p.start),
                                _label(g, p.target), p.blast, path_rationale(g, p), steps, subgraph))
        ensure(p.start, 0)
        for depth, h in enumerate(p.hops, 1):
            ensure(h.src, depth - 1)
            ensure(h.dst, depth)
            key = (h.src, h.dst, h.kind)
            if key not in seen_edges:
                seen_edges.add(key)
                edges.append({"src": h.src, "dst": h.dst, "kind": h.kind})

    _layout(nodes)
    stats = {
        "nodes_total": len(g.nodes),
        "edges_total": len(g.edges),
        "pwned": len(pwned_sids),
        "paths": len(paths),
        "critical": sum(1 for f in findings if f.label == "Critical"),
        "high": sum(1 for f in findings if f.label == "High"),
    }
    return ReportModel(project, time.strftime("%Y-%m-%d %H:%M:%S"), findings,
                       {"nodes": nodes, "edges": edges}, stats)


def _subgraph(g: Graph, path: Path, pwned_sids, hv_sids) -> dict:
    """A single scenario's graph: only the nodes/edges on this one path, laid out
    left-to-right along the chain so a clicked finding shows just its own path."""
    order: List[str] = [path.start]
    for h in path.hops:
        if h.src not in order:
            order.append(h.src)
        if h.dst not in order:
            order.append(h.dst)
    nodes = []
    for layer, sid in enumerate(order):
        n = g.nodes.get(sid)
        ntype = n.ntype if n else "Base"
        nodes.append({"id": sid, "label": _label(g, sid), "type": ntype,
                      "color": TYPE_COLOR.get(ntype, TYPE_COLOR["Base"]),
                      "pwned": sid in pwned_sids, "hv": sid in hv_sids, "layer": layer})
    _layout(nodes)
    edges = [{"src": h.src, "dst": h.dst, "kind": h.kind} for h in path.hops]
    return {"nodes": nodes, "edges": edges}


def model_to_dict(m: ReportModel) -> dict:
    """JSON-serialisable analysis model for the in-app dashboard (unmasked, local)."""
    return {
        "project": m.project, "generated": m.generated, "stats": m.stats,
        "findings": [asdict(f) for f in m.findings],
        "graph": m.graph,
    }


def _layout(nodes: List[dict]) -> None:
    """Deterministic layered layout: x by layer (distance from a pwned start),
    y spread within the layer. JS makes them draggable afterwards."""
    by_layer: Dict[int, List[dict]] = {}
    for n in nodes:
        by_layer.setdefault(n["layer"], []).append(n)
    max_layer = max(by_layer) if by_layer else 0
    # Wider horizontal margin keeps edge nodes (and their labels) away from the
    # canvas edges so they are not clipped; the graph box is given more width too.
    W, H, margin = 1400, 560, 160
    for layer, group in sorted(by_layer.items()):
        x = margin + (W - 2 * margin) * (layer / max(1, max_layer))
        k = len(group)
        for j, n in enumerate(group):
            y = margin + (H - 2 * margin) * ((j + 1) / (k + 1))
            n["x"], n["y"] = round(x, 1), round(y, 1)


# --- Markdown --------------------------------------------------------------
def render_md(m: ReportModel, standalone: list | None = None, adcs: dict | None = None) -> str:
    L = [f"# Active Directory Attack-Path Report — {m.project}",
         "", f"*Generated {m.generated}*  ·  "
         f"{m.stats['nodes_total']} objects, {m.stats['paths']} path(s) from "
         f"{m.stats['pwned']} compromised principal(s).", "",
         "## Summary", "",
         "| # | Severity | Score | Vector | Compromised | → Target | Blast radius |",
         "|---|----------|-------|--------|-------------|----------|--------------|"]
    for f in m.findings:
        L.append(f"| {f.rank} | **{f.label}** | {f.score} | `{f.vector}` | "
                 f"{f.start.split('@')[0]} | {f.target.split('@')[0]} | "
                 f"{'everyone ('+f.blast+')' if f.blast!='single' else 'single principal'} |")
    L.append("")
    L.append("## Findings")
    for f in m.findings:
        L += ["", f"### {f.rank}. {f.label} ({f.score}) — {f.start.split('@')[0]} → {f.target.split('@')[0]}",
              "", f"**CVSS:** `{f.vector}`  ", f"**Blast radius:** "
              f"{'every member of '+f.blast if f.blast!='single' else 'single compromised principal'}  ",
              "", f"{f.rationale}", "", "**Path:**", ""]
        L.append("```")
        line = f.start
        for s in f.steps:
            line += f"\n   └─[{s['kind']}: {s['tool']}]→ {s['dst']}"
        L.append(line)
        L.append("```")

    if standalone:
        L += ["", "## Standalone dangerous ACEs",
              "", "*Misconfigurations that are risks in their own right, even without a full path to Domain Admin.*",
              "", "| Severity | Score | Principal | Right | Over | Note |",
              "|----------|-------|-----------|-------|------|------|"]
        for s in standalone:
            who = "everyone (" + s["src"].split("@")[0] + ")" if s["wide"] else s["src"].split("@")[0]
            L.append(f"| **{s['label']}** | {s['score']} | {who} | `{s['kind']}` | "
                     f"{s['dst'].split('@')[0]} | {s['tool']} |")

    if adcs and adcs.get("esc_edges"):
        L += ["", "## AD CS (certificate) exposure",
              "", "Detected ESC edges: " + ", ".join(f"{k} ×{v}" for k, v in adcs["esc_edges"].items()),
              f"  (templates: {adcs.get('templates', 0)}, CAs: {adcs.get('cas', 0)})"]
    L.append("")
    return "\n".join(L)


# --- HTML ------------------------------------------------------------------
def render_html(m: ReportModel) -> str:
    """Self-contained report page matching the app's design language (same palette,
    dark-mode support, beautified interactive graph with zoom/pan, scrollable
    findings, click-a-finding to filter)."""
    return render_html_from_dict(model_to_dict(m))


def render_html_from_dict(model: dict) -> str:
    """Render the report page from a serialised analysis model (analysis.json), so
    the page always reflects the current template — even for older analyses."""
    data = json.dumps(model, ensure_ascii=False).replace("</", "<\\/")
    return (_HTML_TEMPLATE
            .replace("__PROJECT__", html.escape(model.get("project", "")))
            .replace("__GENERATED__", html.escape(model.get("generated", "")))
            .replace('"__MODEL__"', data))


_HTML_TEMPLATE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AD Attack-Path Report — __PROJECT__</title>
<style>
:root{
  --bg:#f3f6f9;--panel:#fff;--panel2:#f7f9fb;--ink:#1b2530;--muted:#5f6f7e;--line:#e2e7ec;
  --accent:#2f6fb0;--accent-soft:#e8f0f8;--shadow:0 1px 2px rgba(20,30,45,.06),0 4px 14px rgba(20,30,45,.05);
  --crit:#b4232a;--high:#c75a12;--med:#b7950b;--low:#5b6b7a;
  --graph-edge:#9aa7b4;--graph-ink:#1b2530;--graph-bg:#fbfcfe;
  --c-User:#2f6fb0;--c-Group:#b7791f;--c-Computer:#3f7d58;--c-Domain:#7a3f9d;--c-OU:#55606b;--c-GPO:#8a5a3b;--c-Base:#55606b;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#0d131b;--panel:#141d28;--panel2:#182230;--ink:#e6edf4;--muted:#8b9bac;--line:#263241;
  --accent:#4b8fd0;--accent-soft:#17283a;--shadow:0 1px 2px rgba(0,0,0,.4),0 6px 18px rgba(0,0,0,.35);
  --graph-edge:#4a5a6c;--graph-ink:#d4dee8;--graph-bg:#0f1824;
  --c-User:#5a9bd8;--c-Group:#d2a04a;--c-Computer:#5aa47a;--c-Domain:#a06cc2;--c-OU:#7c8794;--c-GPO:#b07a54;--c-Base:#7c8794;
}}
:root[data-theme="dark"]{
  --bg:#0d131b;--panel:#141d28;--panel2:#182230;--ink:#e6edf4;--muted:#8b9bac;--line:#263241;
  --accent:#4b8fd0;--accent-soft:#17283a;--shadow:0 1px 2px rgba(0,0,0,.4),0 6px 18px rgba(0,0,0,.35);
  --graph-edge:#4a5a6c;--graph-ink:#d4dee8;--graph-bg:#0f1824;
  --c-User:#5a9bd8;--c-Group:#d2a04a;--c-Computer:#5aa47a;--c-Domain:#a06cc2;--c-OU:#7c8794;--c-GPO:#b07a54;--c-Base:#7c8794;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14.5px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;transition:background .25s,color .25s}
header{background:linear-gradient(100deg,#20364e,#2f5680);color:#fff;padding:20px 32px;display:flex;align-items:center;gap:16px}
:root[data-theme="dark"] header{background:linear-gradient(100deg,#0f1a26,#163049)}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]) header{background:linear-gradient(100deg,#0f1a26,#163049)}}
header h1{margin:0;font-size:19px;font-weight:600}
header .meta{opacity:.78;font-size:12.5px;margin-top:3px}
.theme{margin-left:auto;width:34px;height:34px;border-radius:50%;border:1px solid rgba(255,255,255,.25);background:rgba(255,255,255,.08);color:#fff;cursor:pointer;font-size:15px;transition:transform .35s}
.theme:active{transform:rotate(40deg) scale(.9)}
.wrap{max-width:1120px;margin:0 auto;padding:24px 32px 60px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);border-bottom:1px solid var(--line);padding-bottom:6px;margin:30px 0 14px}
.kpis{display:flex;gap:14px;flex-wrap:wrap;margin:0 0 6px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:13px 20px;min-width:118px;box-shadow:var(--shadow)}
.kpi b{display:block;font-size:25px;font-weight:680;line-height:1.1}
.kpi span{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.kpi.crit b{color:var(--crit)}.kpi.high b{color:var(--high)}
.grid{display:flex;flex-direction:column;gap:18px}
.graph-pane,.findings-pane{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;box-shadow:var(--shadow)}
.pane-h{display:flex;align-items:center;gap:10px;margin:0 0 12px}
.pane-h h3{margin:0;font-size:15px;font-weight:620;margin-right:auto}
.pill{background:var(--accent-soft);color:var(--accent);border:1px solid var(--line);border-radius:999px;padding:4px 13px;font:inherit;font-size:12.5px;font-weight:600;cursor:pointer}
.pill.active{background:var(--accent);color:#fff}
.graphbox{position:relative;height:500px;background:radial-gradient(circle at 50% 0%,color-mix(in srgb,var(--accent) 7%,var(--graph-bg)),var(--graph-bg));border:1px solid var(--line);border-radius:10px;overflow:hidden}
.zoomctl{position:absolute;right:10px;bottom:10px;display:flex;flex-direction:column;gap:5px}
.zoomctl button{width:30px;height:30px;border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:7px;cursor:pointer;font-size:15px;line-height:1;box-shadow:var(--shadow)}
.zoomctl button:hover{border-color:var(--accent);color:var(--accent)}
#findingList{max-height:520px;overflow-y:auto;padding-right:6px;display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px;align-content:start}
#findingList::-webkit-scrollbar{width:9px}#findingList::-webkit-scrollbar-thumb{background:var(--line);border-radius:6px}
svg#graph{width:100%;height:100%;display:block;cursor:grab;touch-action:none}
svg#graph.panning{cursor:grabbing}
#graph .elabel{font:10px ui-monospace,monospace;fill:var(--muted);paint-order:stroke;stroke:var(--graph-bg);stroke-width:3px;stroke-linejoin:round;pointer-events:none;transition:opacity .2s}
#graph .edgeline{fill:none;stroke:var(--graph-edge);stroke-width:2;stroke-linecap:round;marker-end:url(#arrow);transition:opacity .2s}
#graph marker path{fill:var(--graph-edge)}
#graph .node{transition:opacity .2s}
#graph .node .nlabel{font:11.5px sans-serif;font-weight:600;fill:var(--graph-ink);paint-order:stroke;stroke:var(--graph-bg);stroke-width:3.5px;stroke-linejoin:round;pointer-events:none}
#graph .node .glyph{font:11px sans-serif;font-weight:700;fill:#fff;pointer-events:none;opacity:.95}
#graph .node circle{stroke:var(--panel);stroke-width:2.5;cursor:grab}
#graph .node.pwned circle{stroke:var(--crit);stroke-width:3.5}
#graph .node.hv circle{stroke:var(--ink);stroke-width:3.5}
#graph .dim{opacity:.13}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-top:11px}
.lg{display:inline-flex;align-items:center;gap:6px}.lg i{width:11px;height:11px;border-radius:50%;display:inline-block}
.lg i.rc{background:transparent;border:2px solid var(--crit)}.lg i.rh{background:transparent;border:2px solid var(--ink)}
.finding{border:1px solid var(--line);border-left:4px solid;border-radius:9px;padding:11px 13px;margin:0 0 10px;cursor:pointer;transition:transform .12s,box-shadow .15s,background .15s}
.finding:hover{transform:translateX(2px);box-shadow:var(--shadow)}
.finding.sel{box-shadow:0 0 0 2px var(--accent);background:var(--accent-soft)}
.fh{display:flex;align-items:center;gap:8px;margin-bottom:5px}
.sev{color:#fff;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:600}
.rank{background:var(--accent);color:#fff;width:21px;height:21px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:11.5px;flex-shrink:0}
.score{margin-left:auto;font-weight:680;font-variant-numeric:tabular-nums}
.ft{font-size:13.5px;font-weight:600;word-break:break-word}
.vec{font:11px ui-monospace,monospace;color:var(--muted);margin:4px 0 2px;word-break:break-all}
.rat{font-size:12.5px;color:var(--muted);margin:3px 0 7px}
.steps{margin:0;padding-left:18px;font-size:12.5px}
.steps li{margin:2px 0}
.edge{display:inline-block;background:var(--accent);color:#fff;border-radius:4px;padding:0 6px;font-size:11px;font-weight:600}
.tool{color:var(--muted)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:13px;box-shadow:var(--shadow)}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line)}
th{background:var(--panel2);font-weight:600;color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:.03em}
tr:last-child td{border-bottom:none}
code{font:12px ui-monospace,monospace;background:var(--panel2);padding:1px 5px;border-radius:4px}
footer{color:var(--muted);font-size:12px;text-align:center;padding:22px}
@media(max-width:880px){.grid{grid-template-columns:1fr}}
</style></head>
<body>
<header><div><h1>Active Directory Attack-Path Report — __PROJECT__</h1>
<div class="meta">Generated __GENERATED__ · local, unmasked copy · data masked in transit to the model</div></div>
<button class="theme" id="themeBtn" onclick="toggleTheme()">☾</button></header>
<div class="wrap">
  <div class="kpis" id="kpis"></div>
  <h2>Attack graph</h2>
  <div class="grid">
    <div class="graph-pane">
      <div class="pane-h"><h3 id="graphTitle">All paths</h3><button class="pill active" id="allBtn" onclick="select(-1)">All paths</button></div>
      <div class="graphbox"><svg id="graph" viewBox="0 0 1400 600" preserveAspectRatio="xMidYMid meet"></svg><div class="zoomctl"><button onclick="zoomBy(1.25)">+</button><button onclick="zoomBy(0.8)">−</button><button onclick="zoomReset()" title="reset">⟲</button></div></div>
      <div class="legend" id="legend"></div>
    </div>
    <div class="findings-pane">
      <div class="pane-h"><h3>Vulnerabilities</h3></div>
      <div id="findingList"></div>
    </div>
  </div>
  <h2>Summary</h2>
  <table><thead><tr><th>#</th><th>Severity</th><th>Score</th><th>Vector</th><th>Compromised</th><th>Target</th><th>Blast radius</th></tr></thead><tbody id="tbody"></tbody></table>
</div>
<footer>SpeedACLScan · attack paths ranked by blast radius × attack complexity</footer>
<script>
const M="__MODEL__";
let SEL=-1;
const SEVC={Critical:"#b4232a",High:"#c75a12",Medium:"#b7950b",Low:"#5b6b7a"};
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function toggleTheme(){const r=document.documentElement;const d=r.getAttribute("data-theme")==="dark";r.setAttribute("data-theme",d?"light":"dark");document.getElementById("themeBtn").textContent=d?"☾":"☀";draw();}
// kpis
document.getElementById("kpis").innerHTML=
 `<div class="kpi"><b>${M.stats.nodes_total}</b><span>Objects</span></div>`+
 `<div class="kpi"><b>${M.stats.pwned}</b><span>Compromised</span></div>`+
 `<div class="kpi"><b>${M.stats.paths}</b><span>Paths to DA</span></div>`+
 `<div class="kpi crit"><b>${M.stats.critical}</b><span>Critical</span></div>`+
 `<div class="kpi high"><b>${M.stats.high}</b><span>High</span></div>`;
// summary table
document.getElementById("tbody").innerHTML=M.findings.map(f=>{
 const c=SEVC[f.label]||"#555";
 return `<tr><td>${f.rank}</td><td><span class="sev" style="background:${c}">${f.label}</span></td>`+
  `<td class="score">${f.score}</td><td><code>${esc(f.vector)}</code></td>`+
  `<td>${esc(f.start)}</td><td>${esc(f.target)}</td>`+
  `<td>${f.blast!=="single"?"everyone · "+esc(f.blast):"single"}</td></tr>`;
}).join("");
// finding cards
document.getElementById("findingList").innerHTML=M.findings.map((f,i)=>{
 const c=SEVC[f.label]||"#555";
 const steps=`<li><b>${esc(f.start)}</b></li>`+f.steps.map(s=>
   `<li><span class="edge">${esc(s.kind)}</span> <span class="tool">${esc(s.tool)}</span> → <b>${esc(s.dst)}</b></li>`).join("");
 return `<div class="finding" data-i="${i}" style="border-left-color:${c}" onclick="select(${i})">
   <div class="fh"><span class="rank">${f.rank}</span><span class="sev" style="background:${c}">${f.label}</span><span class="score">${f.score}</span></div>
   <div class="ft">${esc(f.start.split("@")[0])} → ${esc(f.target.split("@")[0])}</div>
   <div class="vec">${esc(f.vector)}</div><div class="rat">${esc(f.rationale)}</div>
   <ol class="steps">${steps}</ol></div>`;
}).join("");
document.getElementById("legend").innerHTML=["User","Group","Computer","Domain","OU","GPO"]
 .map(t=>`<span class="lg"><i style="background:var(--c-${t})"></i>${t}</span>`).join("")
 +'<span class="lg"><i class="rc"></i>pwned</span><span class="lg"><i class="rh"></i>target</span>';
function select(i){SEL=i;document.querySelectorAll(".finding").forEach((el,x)=>el.classList.toggle("sel",x===i));
 document.getElementById("allBtn").classList.toggle("active",i===-1);
 const f=i>=0?M.findings[i]:null;
 document.getElementById("graphTitle").textContent=f?`#${f.rank} ${f.label}`:"All paths";draw();}
// graph
const NS="http://www.w3.org/2000/svg";
const GLYPH={User:"U",Group:"G",Computer:"C",Domain:"D",OU:"O",GPO:"P",Base:"•"};
const rOf=t=>t==="Domain"?19:t==="Computer"?17:t==="Group"?15:14;
function curGraph(){return (SEL>=0&&M.findings[SEL])?M.findings[SEL].graph:M.graph;}
let VP=null,VIEW={k:1,tx:0,ty:0};
function applyView(){if(VP)VP.setAttribute("transform",`translate(${VIEW.tx},${VIEW.ty}) scale(${VIEW.k})`);}
function rootPt(svg,ev){const p=svg.createSVGPoint();p.x=ev.clientX;p.y=ev.clientY;return p.matrixTransform(svg.getScreenCTM().inverse());}
function zoomAt(cx,cy,f){const nk=Math.min(4,Math.max(0.3,VIEW.k*f));VIEW.tx=cx-(cx-VIEW.tx)/VIEW.k*nk;VIEW.ty=cy-(cy-VIEW.ty)/VIEW.k*nk;VIEW.k=nk;applyView();}
function zoomBy(f){zoomAt(700,300,f);}
function zoomReset(){VIEW={k:1,tx:0,ty:0};applyView();}
function draw(){
 const svg=document.getElementById("graph"),G=curGraph();
 if(!G.nodes||!G.nodes.length){svg.innerHTML='<text x="700" y="300" text-anchor="middle" fill="#8894a3" font-size="16" font-family="sans-serif">No attack paths to graph — see Findings / Standalone ACEs below</text>';return;}
 svg.innerHTML=`<defs><marker id="arrow" viewBox="0 0 10 10" refX="23" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z"/></marker>`+
  `<filter id="nsh" x="-40%" y="-40%" width="180%" height="180%"><feDropShadow dx="0" dy="1.5" stdDeviation="2.2" flood-color="#000" flood-opacity="0.28"/></filter></defs>`;
 VP=document.createElementNS(NS,"g");svg.appendChild(VP);VIEW={k:1,tx:0,ty:0};applyView();
 const pos={};G.nodes.forEach(n=>pos[n.id]={x:n.x,y:n.y});
 const nbr={};G.nodes.forEach(n=>nbr[n.id]=new Set([n.id]));
 G.edges.forEach(e=>{if(nbr[e.src])nbr[e.src].add(e.dst);if(nbr[e.dst])nbr[e.dst].add(e.src);});
 const grp={};G.edges.forEach(e=>{const k=[e.src,e.dst].sort().join("|");(grp[k]=grp[k]||[]).push(e);});
 const edgeOff=new Map(),SEP=30;Object.values(grp).forEach(list=>list.forEach((e,i)=>edgeOff.set(e,(i-(list.length-1)/2)*SEP)));
 const E=[],L=[],N=[];
 G.edges.forEach(e=>{const l=document.createElementNS(NS,"path");l.setAttribute("class","edgeline");VP.appendChild(l);E.push([l,e]);
  const t=document.createElementNS(NS,"text");t.setAttribute("class","elabel");t.setAttribute("text-anchor","middle");t.textContent=e.kind;VP.appendChild(t);L.push([t,e]);});
 G.nodes.forEach(n=>{const g=document.createElementNS(NS,"g");g.setAttribute("class","node"+(n.pwned?" pwned":"")+(n.hv?" hv":""));
  const c=document.createElementNS(NS,"circle");c.setAttribute("r",rOf(n.type));c.setAttribute("filter","url(#nsh)");c.style.fill="var(--c-"+n.type+")";g.appendChild(c);
  const gl=document.createElementNS(NS,"text");gl.setAttribute("class","glyph");gl.setAttribute("text-anchor","middle");gl.setAttribute("dy",".34em");gl.textContent=GLYPH[n.type]||"•";g.appendChild(gl);
  const tx=document.createElementNS(NS,"text");tx.setAttribute("class","nlabel");tx.setAttribute("text-anchor","middle");tx.setAttribute("dy",-(rOf(n.type)+7));tx.textContent=(()=>{const q=(n.label||"").split("@")[0];return q.length>20?q.slice(0,19)+"\u2026":q;})();g.appendChild(tx);
  VP.appendChild(g);N.push([g,n]);
  g.addEventListener("pointerdown",ev=>{cur=n;g.setPointerCapture(ev.pointerId);ev.stopPropagation();ev.preventDefault();});
  g.addEventListener("pointerenter",()=>{if(!cur&&!pan)focus(n.id);});g.addEventListener("pointerleave",()=>{if(!cur&&!pan)focus(null);});});
 function focus(id){N.forEach(([g,n])=>g.classList.toggle("dim",id&&!nbr[id].has(n.id)));
  E.forEach(([l,e])=>l.classList.toggle("dim",id&&!(nbr[id].has(e.src)&&nbr[id].has(e.dst))));
  L.forEach(([t,e])=>t.classList.toggle("dim",id&&!(nbr[id].has(e.src)&&nbr[id].has(e.dst))));}
 function ctrl(a,b,o){const mx=(a.x+b.x)/2,my=(a.y+b.y)/2,dx=b.x-a.x,dy=b.y-a.y,len=Math.hypot(dx,dy)||1;return {x:mx+(-dy/len)*o*2,y:my+(dx/len)*o*2};}
 function render(){E.forEach(([l,e])=>{const a=pos[e.src],b=pos[e.dst];if(!a||!b)return;const o=edgeOff.get(e)||0;l.setAttribute("d",o?`M${a.x} ${a.y} Q${ctrl(a,b,o).x} ${ctrl(a,b,o).y} ${b.x} ${b.y}`:`M${a.x} ${a.y} L${b.x} ${b.y}`);});
  L.forEach(([t,e])=>{const a=pos[e.src],b=pos[e.dst];if(!a||!b)return;const o=edgeOff.get(e)||0;if(o){const c=ctrl(a,b,o);t.setAttribute("x",0.25*a.x+0.5*c.x+0.25*b.x);t.setAttribute("y",0.25*a.y+0.5*c.y+0.25*b.y-2);}else{t.setAttribute("x",(a.x+b.x)/2);t.setAttribute("y",(a.y+b.y)/2-4);}});
  N.forEach(([g,n])=>g.setAttribute("transform",`translate(${pos[n.id].x},${pos[n.id].y})`));}
 let cur=null,pan=null;
 svg.onpointerdown=ev=>{if(cur)return;pan={tx:VIEW.tx,ty:VIEW.ty,pt:rootPt(svg,ev)};svg.classList.add("panning");};
 svg.onpointermove=ev=>{if(cur){const q=rootPt(svg,ev);pos[cur.id].x=(q.x-VIEW.tx)/VIEW.k;pos[cur.id].y=(q.y-VIEW.ty)/VIEW.k;render();return;}
  if(pan){const q=rootPt(svg,ev);VIEW.tx=pan.tx+(q.x-pan.pt.x);VIEW.ty=pan.ty+(q.y-pan.pt.y);applyView();}};
 svg.onpointerup=()=>{cur=null;pan=null;svg.classList.remove("panning");focus(null);};
 svg.onwheel=ev=>{ev.preventDefault();const p=rootPt(svg,ev);zoomAt(p.x,p.y,ev.deltaY<0?1.12:0.89);};
 render();
}
draw();
try{
// standalone dangerous ACEs
if(M.standalone&&M.standalone.length){document.getElementById("saH").style.display="";
 document.getElementById("saWrap").innerHTML='<table><thead><tr><th>Severity</th><th>Score</th><th>Principal</th><th>Right</th><th>Over</th><th>Note</th></tr></thead><tbody>'+M.standalone.map(s=>{const c=SEVC[s.label]||"#555";const who=s.wide?("everyone · "+esc(s.src.split("@")[0])):esc(s.src.split("@")[0]);
  return `<tr><td><span class="sev" style="background:${c}">${s.label}</span></td><td class="score">${s.score}</td><td>${who}</td><td><code>${esc(s.kind)}</code></td><td>${esc(s.dst.split("@")[0])}</td><td class="muted">${esc(s.tool)}</td></tr>`;}).join("")+'</tbody></table>';}
if(M.adcs&&M.adcs.esc_edges&&Object.keys(M.adcs.esc_edges).length){
 document.getElementById("adcsLine").textContent="AD CS exposure: "+Object.entries(M.adcs.esc_edges).map(e=>e[0]+" ×"+e[1]).join(", ")+"  (templates "+(M.adcs.templates||0)+", CAs "+(M.adcs.cas||0)+")";}
}catch(e){console.error('report tables',e);}
</script>
</body></html>"""
