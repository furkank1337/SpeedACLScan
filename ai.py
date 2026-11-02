"""AI analysis orchestration with masking in transit.

Flow (all local except the one send/receive):

  ingest (raw, local) -> deterministic analysis (offline, always works)
    -> build MASKED graph payload -> OpenCode -> masked reply
    -> UNMASK locally -> verify every AI-claimed edge against the real graph
    -> merge verified AI paths with the offline ones -> report

Two guarantees:
  * Only masked data is sent. A leak-check runs on the exact outgoing text and
    fails closed if any real value survives.
  * The AI cannot inject fictional edges: every hop it returns is verified to
    exist in the real BloodHound graph before it reaches the report.
"""
from __future__ import annotations

import json
from typing import Callable, List, Optional, Tuple

from . import bloodhound
from .analyze import Hop, Path, analyze, edge_info, severity
from .bloodhound import Graph, high_value_targets
from .masking import Masker
from .opencode import OpenCodeClient

SYSTEM = "\n".join([
    "You are assisting an authorized penetration tester. You are given an Active",
    "Directory control graph whose identifiers are ALREADY MASKED (pseudonyms like",
    "U-AB12@DOM1.LOCAL, C-9F.. , S-1-5-21-R..-1104). Keep every pseudonym EXACTLY",
    "as given; never guess, decode or de-anonymize them.",
    "",
    "You get: nodes[], edges[] (src,dst,kind -- controlling src enables acting on",
    "dst via kind), pwned[] (already-compromised node ids) and targets[] (domain",
    "compromise: Domain Admins / DCs / domain root).",
    "",
    "Find attack paths from pwned nodes to any target, using ONLY edges present in",
    "edges[]. Reply with EXACTLY ONE fenced json block:",
    "```json",
    '{"paths":[{"nodes":["<id>","<id>",...],"edges":["<kind>",...],'
    '"note":"short reason"}]}',
    "```",
    "nodes lists the ids in order from a pwned node to a target; edges[i] is the",
    "kind between nodes[i] and nodes[i+1] (so len(edges)==len(nodes)-1). Prefer the",
    "easiest paths. Do not invent edges. No prose outside the block.",
])


def build_masked_payload(g: Graph, pwned_sids: List[str], m: Masker) -> Tuple[dict, dict]:
    """Returns (payload, sid_map) where sid_map maps masked_id -> real_sid."""
    sid_map: dict[str, str] = {}
    nodes = []
    for sid, node in g.nodes.items():
        mid = m.mask_sid(sid)
        sid_map[mid] = sid
        nodes.append({"id": mid, "name": m.mask_name(node.name, node.ntype), "type": node.ntype})
    edges = [{"src": m.mask_sid(e.src), "dst": m.mask_sid(e.dst), "kind": e.kind} for e in g.edges]
    targets = [m.mask_sid(s) for s in high_value_targets(g)]
    pwned_masked = []
    for q in pwned_sids:
        if q in g.nodes:
            pwned_masked.append(m.mask_sid(q))
    payload = {"nodes": nodes, "edges": edges, "pwned": pwned_masked, "targets": targets}
    return payload, sid_map


def _verify_ai_path(g: Graph, real_sids: List[str], kinds: List[str]) -> Optional[Path]:
    """Accept an AI path only if every hop exists in the real graph."""
    if len(real_sids) < 2 or len(kinds) != len(real_sids) - 1:
        return None
    hops: List[Hop] = []
    for i, kind in enumerate(kinds):
        src, dst = real_sids[i], real_sids[i + 1]
        if src not in g.nodes or dst not in g.nodes:
            return None
        if not any(e.dst == dst and e.kind == kind for e in g.out_edges(src)):
            return None
        hops.append(Hop(src, dst, kind))
    from .analyze import _blast_radius
    cost = sum(edge_info(h.kind)["cost"] for h in hops)
    return Path(real_sids[0], real_sids[-1], hops, cost, _blast_radius(g, hops))


def parse_ai_paths(reply: str, g: Graph, m: Masker, sid_map: dict) -> List[Path]:
    import re
    block = re.search(r"```json\s*\n(.*?)```", reply, re.S)
    raw = block.group(1) if block else reply
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    out: List[Path] = []
    for p in data.get("paths", []) if isinstance(data, dict) else []:
        masked_ids = p.get("nodes", [])
        kinds = p.get("edges", [])
        real = [sid_map.get(mid) or g.resolve(m.unmask(mid)) for mid in masked_ids]
        if any(r is None for r in real):
            continue
        vp = _verify_ai_path(g, real, kinds)
        if vp:
            out.append(vp)
    return out


def _merge(offline: List[Path], ai: List[Path]) -> List[Path]:
    seen = set()
    out: List[Path] = []
    for p in offline + ai:
        key = (p.start, p.target, tuple((h.src, h.dst, h.kind) for h in p.hops))
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def run_analysis(store, project: str, use_ai: bool = True,
                 on_status: Callable[..., None] = lambda *a: None) -> dict:
    """Full analysis for a project. on_status(message, pct) reports progress.
    Returns {'paths': n, 'ai_paths': n, 'report': dir}."""
    from .report import build_report_model, model_to_dict, render_html, render_md

    on_status("Ingesting BloodHound data (local)…", 15)
    bh = store.bh_dir(project)
    zips = [f for f in sorted(__import__("glob").glob(bh + "/*")) if f.endswith(".zip")]
    g = bloodhound.ingest_zip(zips[-1]) if zips else bloodhound.ingest_dir(bh)
    if not g.nodes:
        raise RuntimeError("No BloodHound data in project. Run a scan or import first.")

    scope = store.get_scope(project)
    custom_targets = store.get_targets(project)
    pwned_queries = store.get_pwned(project)
    pwned_sids = [sid for sid in (g.resolve(q) for q in pwned_queries) if sid]
    adcs_n = sum(g.adcs.get("esc_edges", {}).values()) if isinstance(g.adcs, dict) else 0
    on_status(f"{len(g.nodes)} objects, {len(pwned_sids)} pwned, {adcs_n} ADCS ESC edge(s).", 25)

    on_status("Computing attack paths (offline, k-shortest)…", 45)
    from .bloodhound import high_value_targets
    from .analyze import standalone_aces
    targets = set(high_value_targets(g, broaden=scope.get("broaden", True), custom=custom_targets))
    offline = analyze(g, pwned_queries, targets=targets,
                      k_per_principal=int(scope.get("k", 5)),
                      enumerate_all=scope.get("enumerate_all", True))
    on_path = {(h.src, h.dst, h.kind) for p in offline for h in p.hops}
    standalone = standalone_aces(g, exclude_edges=on_path) if scope.get("standalone", True) else []

    ai_paths: List[Path] = []
    m = store.masker(project)
    if use_ai:
        cfg = store.load_config()
        payload, sid_map = build_masked_payload(g, pwned_sids, m)
        store.save_masker(project, m)
        text = json.dumps(payload, ensure_ascii=False)

        # fail-closed leak check on the exact outgoing text. Ground-truth reals =
        # every node name + SID, plus every value the masker actually replaced
        # (covers realms and any encoded form).
        reals = {n.name for n in g.nodes.values()} | set(g.nodes) | set(m.mapping().values())
        leaks = m.leak_check(text, reals)
        if leaks:
            store.log(project, "status", f"BLOCKED: masking leak {leaks[:3]}", "fail-closed")
            raise RuntimeError(f"Masking leak detected, nothing sent: {leaks[:3]}")

        on_status("Masking graph and sending to OpenCode…", 60)
        store.log(project, "sent", text, "masked graph payload")
        try:
            oc = cfg["opencode"]
            client = OpenCodeClient(oc["url"], oc.get("model", ""), oc.get("password", ""))
            session = client.create_session("speedaclscan-" + project)
            reply = client.send_message(session, SYSTEM, text)
            store.log(project, "received", reply, "masked AI reply")
            real_reply = m.unmask(reply)
            store.log(project, "reverse", real_reply, "unmasked locally")
            ai_paths = parse_ai_paths(reply, g, m, sid_map)
            on_status(f"AI proposed {len(ai_paths)} verified path(s).", 85)
        except Exception as e:  # AI is best-effort; offline result still stands
            store.log(project, "status", f"AI step failed: {e}", "degraded")
            on_status(f"AI unavailable ({e.__class__.__name__}); using offline analysis.", 85)

    paths = _merge(offline, ai_paths)
    paths.sort(key=lambda p: severity(g, p)[0], reverse=True)

    on_status("Rendering report…", 92)
    model = build_report_model(g, paths, m, project=project)
    adcs_summary = g.adcs if isinstance(g.adcs, dict) else {}
    model_dict = model_to_dict(model)
    model_dict["standalone"] = standalone
    model_dict["adcs"] = adcs_summary
    rd = store.reports_dir(project)
    open(rd + "/report.md", "w", encoding="utf-8").write(render_md(model, standalone, adcs_summary))
    with open(rd + "/analysis.json", "w", encoding="utf-8") as fh:
        json.dump(model_dict, fh, ensure_ascii=False)
    # HTML report is rendered fresh from analysis.json on request (/api/report)
    from .report import render_html_from_dict
    open(rd + "/report.html", "w", encoding="utf-8").write(render_html_from_dict(model_dict))
    store.set_meta(project, status="analyzed", last_paths=len(paths))
    store.save_masker(project, m)
    on_status("Analysis complete.", 100)
    return {"paths": len(paths), "ai_paths": len(ai_paths), "standalone": len(standalone),
            "report": rd, "model": model}
