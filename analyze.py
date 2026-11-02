"""Attack-path analysis: pwned principals -> domain compromise, with severity.

Two things matter for ranking, and they are deliberately separated:

  * blast radius  -- WHO can walk the path. A path whose first hop is a huge
    group (Domain Users / Authenticated Users / Everyone) is far worse than one
    that only a single already-compromised account can use.
  * attack complexity -- HOW hard each edge is to abuse. GenericAll is trivial;
    an OU-write -> GPO -> gPLink chain needs several steps and tooling.

Shortest path uses edge *cost* = complexity, so the surfaced path is the easiest
one, not merely the shortest hop count. Severity is then derived from the
easiest path's total complexity and its blast radius, and expressed both as a
0-10 score and as a CVSS:3.1-style vector so it drops straight into a report.
"""
from __future__ import annotations

import heapq
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .bloodhound import Graph, high_value_targets

# Per-edge abuse model. cost = how hard to traverse (lower = easier).
# "tool" names the standard technique, surfaced in the report narrative.
EDGE_MODEL: Dict[str, dict] = {
    "MemberOf":            {"cost": 0.0, "tool": "group membership", "ac": "low"},
    "GenericAll":          {"cost": 1.0, "tool": "full control (reset pw / add member / RBCD)", "ac": "low"},
    "GenericWrite":        {"cost": 1.5, "tool": "write attrs (targeted Kerberoast / logon script / RBCD)", "ac": "low"},
    "WriteOwner":          {"cost": 2.0, "tool": "set owner then grant rights", "ac": "low"},
    "WriteDacl":           {"cost": 2.0, "tool": "add ACE then abuse it", "ac": "low"},
    "Owns":                {"cost": 1.5, "tool": "owner -> grant rights", "ac": "low"},
    "ForceChangePassword": {"cost": 1.0, "tool": "reset target password", "ac": "low"},
    "AddMember":           {"cost": 0.5, "tool": "add self to group", "ac": "low"},
    "AddSelf":             {"cost": 0.5, "tool": "add self to group", "ac": "low"},
    "AllExtendedRights":   {"cost": 1.0, "tool": "extended rights (DCSync / pw reset)", "ac": "low"},
    "DCSync":              {"cost": 0.5, "tool": "DCSync (DRSUAPI replication)", "ac": "low"},
    "GetChanges":          {"cost": 2.0, "tool": "DCSync precursor", "ac": "low"},
    "GetChangesAll":       {"cost": 2.0, "tool": "DCSync precursor", "ac": "low"},
    "AdminTo":             {"cost": 0.5, "tool": "local admin -> creds in memory", "ac": "low"},
    "HasSession":          {"cost": 2.5, "tool": "token / cred theft from session", "ac": "high"},
    "CanRDP":              {"cost": 2.0, "tool": "interactive logon", "ac": "medium"},
    "CanPSRemote":         {"cost": 1.5, "tool": "remote PowerShell", "ac": "medium"},
    "ExecuteDCOM":         {"cost": 2.5, "tool": "DCOM exec", "ac": "high"},
    "AllowedToDelegate":   {"cost": 2.5, "tool": "constrained delegation (S4U)", "ac": "medium"},
    "AllowedToAct":        {"cost": 2.0, "tool": "RBCD (S4U2self/proxy)", "ac": "medium"},
    "AddAllowedToAct":     {"cost": 2.0, "tool": "configure RBCD", "ac": "medium"},
    "GPLink":              {"cost": 2.5, "tool": "malicious GPO -> affected objects", "ac": "medium"},
    "Contains":            {"cost": 3.0, "tool": "OU control -> child objects", "ac": "medium"},
    "ReadLAPSPassword":    {"cost": 1.0, "tool": "read LAPS local admin pw", "ac": "low"},
    "ReadGMSAPassword":    {"cost": 1.0, "tool": "read gMSA password", "ac": "low"},
    "SyncLAPSPassword":    {"cost": 1.5, "tool": "read LAPS pw", "ac": "low"},
    "AddKeyCredentialLink":{"cost": 1.0, "tool": "shadow credentials (msDS-KeyCredentialLink)", "ac": "low"},
    "WriteSPN":            {"cost": 1.5, "tool": "targeted Kerberoast", "ac": "low"},
    "WriteGPLink":         {"cost": 2.5, "tool": "link a malicious GPO", "ac": "medium"},
    "HasSIDHistory":       {"cost": 0.5, "tool": "SID history", "ac": "low"},
    "SQLAdmin":            {"cost": 2.0, "tool": "MSSQL sysadmin -> xp_cmdshell", "ac": "medium"},
    "DumpSMSAPassword":    {"cost": 1.0, "tool": "read sMSA password", "ac": "low"},
    # --- AD CS (certificate) abuse; each yields a domain-auth certificate ---
    "ADCSESC1":            {"cost": 1.0, "tool": "ESC1: request client-auth cert with chosen SAN", "ac": "low"},
    "ADCSESC2":            {"cost": 1.2, "tool": "ESC2: Any-Purpose cert", "ac": "low"},
    "ADCSESC3":            {"cost": 1.5, "tool": "ESC3: enrollment-agent cert", "ac": "low"},
    "ADCSESC4":            {"cost": 1.3, "tool": "ESC4: rewrite template into ESC1", "ac": "low"},
    "ADCSESC6":            {"cost": 1.2, "tool": "ESC6: CA honours user-supplied SAN", "ac": "low"},
    "ADCSESC7":            {"cost": 1.5, "tool": "ESC7: ManageCA/ManageCertificates", "ac": "low"},
    "ADCSESC8":            {"cost": 2.0, "tool": "ESC8: NTLM relay to web enrollment", "ac": "medium"},
    "ADCSESC9":            {"cost": 1.3, "tool": "ESC9: no-security-extension mapping bypass", "ac": "low"},
    "ADCSESC13":           {"cost": 1.5, "tool": "ESC13: issuance-policy group grant", "ac": "low"},
    "ADCSESC15":           {"cost": 1.3, "tool": "ESC15: schema v1 client-auth (EKUwu)", "ac": "low"},
}
_DEFAULT_EDGE = {"cost": 2.0, "tool": "control relationship", "ac": "medium"}

# Groups whose membership is effectively "everyone"; a path they can use is a
# domain-wide exposure, not a single-principal one.
BLAST_GROUPS = {"DOMAIN USERS", "AUTHENTICATED USERS", "EVERYONE", "DOMAIN COMPUTERS"}


def edge_info(kind: str) -> dict:
    return EDGE_MODEL.get(kind, _DEFAULT_EDGE)


@dataclass
class Hop:
    src: str          # SID
    dst: str          # SID
    kind: str

    def info(self) -> dict:
        return edge_info(self.kind)


@dataclass
class Path:
    start: str                 # pwned SID
    target: str                # high-value SID
    hops: List[Hop]
    cost: float
    blast: str                 # "single" | group name driving the blast radius

    def length(self) -> int:
        return len([h for h in self.hops if h.kind != "MemberOf"])


def shortest_path(g: Graph, start: str, targets: set[str]) -> Optional[Path]:
    """Dijkstra from start to the nearest target, cost = edge complexity."""
    start = start.upper()
    if start not in g.nodes:
        return None
    dist: Dict[str, float] = {start: 0.0}
    prev: Dict[str, Tuple[str, str]] = {}
    pq: List[Tuple[float, str]] = [(0.0, start)]
    reached = None
    while pq:
        d, u = heapq.heappop(pq)
        if d > dist.get(u, float("inf")):
            continue
        if u in targets and u != start:
            reached = u
            break
        for e in g.out_edges(u):
            nd = d + edge_info(e.kind)["cost"]
            if nd < dist.get(e.dst, float("inf")):
                dist[e.dst] = nd
                prev[e.dst] = (u, e.kind)
                heapq.heappush(pq, (nd, e.dst))
    if reached is None:
        return None
    hops: List[Hop] = []
    cur = reached
    while cur in prev:
        p, kind = prev[cur]
        hops.append(Hop(p, cur, kind))
        cur = p
    hops.reverse()
    blast = _blast_radius(g, hops)
    return Path(start, reached, hops, dist[reached], blast)


def _blast_radius(g: Graph, hops: List[Hop]) -> str:
    """If a BLAST_GROUP appears on the path, the whole group can walk it."""
    for h in hops:
        for sid in (h.src, h.dst):
            node = g.nodes.get(sid)
            if node and node.name.upper().split("@", 1)[0] in BLAST_GROUPS:
                return node.name.upper().split("@", 1)[0]
    return "single"


def enumerate_paths(g: Graph, start: str, targets: set[str], k: int = 5,
                    max_len: int = 8, budget: int = 40000) -> List[Path]:
    """Up to k lowest-cost simple paths from start to any target (not just one).
    Bounded DFS with an expansion budget so huge graphs can't explode."""
    start = start.upper()
    if start not in g.nodes:
        return []
    best = shortest_path(g, start, targets)
    if best is None:
        return []
    cap = best.cost * 2.5 + 2.0            # ignore paths far costlier than the best
    found: List[Path] = []
    budget_box = [budget]

    def dfs(node, visited, hops, cost):
        if budget_box[0] <= 0 or cost > cap or len(hops) > max_len or len(found) >= k * 4:
            return
        budget_box[0] -= 1
        if node in targets and hops:
            found.append(Path(start, node, list(hops), cost, _blast_radius(g, hops)))
            return
        for e in g.out_edges(node):
            if e.dst in visited:
                continue
            visited.add(e.dst)
            hops.append(Hop(e.src, e.dst, e.kind))
            dfs(e.dst, visited, hops, cost + edge_info(e.kind)["cost"])
            hops.pop()
            visited.remove(e.dst)

    dfs(start, {start}, [], 0.0)
    found.sort(key=lambda p: p.cost)
    out, seen = [], set()
    for p in found:
        key = tuple((h.src, h.dst, h.kind) for h in p.hops)
        if key not in seen:
            seen.add(key)
            out.append(p)
        if len(out) >= k:
            break
    return out or [best]


def analyze(g: Graph, pwned: List[str], targets: set[str] | None = None,
            k_per_principal: int = 5, enumerate_all: bool = True) -> List[Path]:
    """Attack paths from each pwned principal to any high-value target. With
    enumerate_all, up to k distinct paths per principal are returned (the easiest
    is still ranked first by severity); otherwise only the single easiest path."""
    tg = targets if targets is not None else set(high_value_targets(g))
    paths: List[Path] = []
    seen = set()
    for q in pwned:
        sid = g.resolve(q)
        if not sid:
            continue
        found = enumerate_paths(g, sid, tg, k=k_per_principal) if enumerate_all \
            else [p for p in [shortest_path(g, sid, tg)] if p]
        for p in found:
            key = (p.start, p.target, tuple((h.src, h.dst, h.kind) for h in p.hops))
            if key not in seen:
                seen.add(key)
                paths.append(p)
    paths.sort(key=lambda p: severity(g, p)[0], reverse=True)
    return paths


# Dangerous ACE kinds for the standalone (not-on-a-DA-path) audit.
DANGEROUS_KINDS = {
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "ForceChangePassword",
    "AddKeyCredentialLink", "AddMember", "AddSelf", "AllExtendedRights", "DCSync",
    "WriteSPN", "WriteGPLink", "GPLink", "Contains", "ReadLAPSPassword", "ReadGMSAPassword",
    "AddAllowedToAct", "AllowedToAct", "HasSIDHistory",
    "ADCSESC1", "ADCSESC2", "ADCSESC3", "ADCSESC4", "ADCSESC6", "ADCSESC7", "ADCSESC8",
    "ADCSESC9", "ADCSESC13", "ADCSESC15",
}
WIDE_PRINCIPALS = {"DOMAIN USERS", "AUTHENTICATED USERS", "EVERYONE", "DOMAIN COMPUTERS",
                   "USERS", "GUESTS"}


def standalone_aces(g: Graph, exclude_edges: set | None = None, limit: int = 300) -> List[dict]:
    """Dangerous ACEs that are misconfigurations in their own right, even when they
    do not chain to domain compromise. Prioritises wide principals (Domain Users /
    Authenticated Users / Everyone) and control over privileged objects."""
    exclude = exclude_edges or set()
    hv = set(high_value_targets(g, broaden=True))
    out = []
    for e in g.edges:
        if e.kind not in DANGEROUS_KINDS:
            continue
        if (e.src, e.dst, e.kind) in exclude:
            continue
        src = g.nodes.get(e.src)
        dst = g.nodes.get(e.dst)
        if not src or not dst:
            continue
        src_nm = src.name.upper().split("@", 1)[0]
        wide = src_nm in WIDE_PRINCIPALS
        priv = e.dst in hv or dst.admincount
        if not (wide or priv or e.kind.startswith("ADCSESC")):
            continue
        info = edge_info(e.kind)
        # score: wide-principal control is worst; privileged target raises it
        score = 6.0
        if wide:
            score += 2.5
        if priv:
            score += 1.5
        if e.kind in ("GenericAll", "WriteDacl", "WriteOwner", "DCSync") or e.kind.startswith("ADCSESC"):
            score += 0.5
        score = min(9.5, round(score, 1))
        label = ("Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low")
        out.append({
            "src": src.name, "dst": dst.name, "kind": e.kind, "tool": info["tool"],
            "wide": wide, "priv_target": bool(priv), "score": score, "label": label,
            "detail": f"{'Every member of ' + src_nm if wide else src.name.split('@')[0]} has "
                      f"{e.kind} over {dst.name.split('@')[0]}",
        })
    out.sort(key=lambda d: d["score"], reverse=True)
    return out[:limit]


def severity(g: Graph, path: Path) -> Tuple[float, str, str]:
    """(score 0-10, label, CVSS:3.1 vector). Blast radius dominates; complexity
    (total edge cost + length) lowers the score."""
    # base from blast radius
    if path.blast in BLAST_GROUPS:
        base, ac = 9.6, "L"      # everyone can do it
    else:
        base, ac = 7.6, "L"      # needs the specific compromised principal
    # complexity penalty: longer / costlier chains are harder
    penalty = min(3.0, path.cost * 0.3 + max(0, path.length() - 1) * 0.5)
    # any high-AC edge raises attack complexity in the vector
    if any(h.info()["ac"] == "high" for h in path.hops):
        ac = "H"
        penalty += 0.6
    elif any(h.info()["ac"] == "medium" for h in path.hops):
        ac = "H"
        penalty += 0.3
    score = max(0.0, round(base - penalty, 1))
    label = ("Critical" if score >= 9 else "High" if score >= 7
             else "Medium" if score >= 4 else "Low")
    # PR: a blast-group path needs only any domain user (PR:L); single needs the
    # specific principal (PR:H). Impact is full domain compromise -> C/I/A High.
    pr = "L" if path.blast in BLAST_GROUPS else "H"
    vector = f"CVSS:3.1/AV:N/AC:{ac}/PR:{pr}/UI:N/S:C/C:H/I:H/A:H"
    return score, label, vector


def path_rationale(g: Graph, path: Path) -> str:
    """One-line human explanation of why this ranks where it does."""
    if path.blast in BLAST_GROUPS:
        who = f"every member of {path.blast}"
    else:
        start = g.nodes.get(path.start)
        who = start.name.split("@", 1)[0] if start else "the compromised principal"
    techniques = " -> ".join(h.info()["tool"] for h in path.hops if h.kind != "MemberOf")
    return f"{who} can reach domain compromise via: {techniques or 'direct membership'}."
