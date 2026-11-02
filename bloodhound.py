"""BloodHound ingest -> normalised graph model.

Tolerant parser for SharpHound / BloodHound-CE JSON (and the .zip they ship in).
Builds a directed graph of principals (nodes) and control relationships (edges).
Edge direction is "attacker-usable": an edge A --RIGHT--> B means that
controlling A lets you act on / escalate to B.

Only the subset of fields needed for path analysis is read; everything else is
ignored. Works across minor schema differences by probing several field names.
"""
from __future__ import annotations

import glob
import io
import json
import os
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Kinds of files SharpHound / BloodHound-CE emit; we map each to a node type.
_FILE_TYPES = {
    "users": "User", "groups": "Group", "computers": "Computer",
    "domains": "Domain", "ous": "OU", "gpos": "GPO", "containers": "Container",
    "certtemplates": "CertTemplate", "enterprisecas": "EnterpriseCA",
    "rootcas": "RootCA", "aiacas": "AIACA", "ntauthstores": "NTAuthStore",
    "issuancepolicies": "IssuancePolicy",
}


@dataclass
class Node:
    sid: str
    name: str
    ntype: str
    props: dict = field(default_factory=dict)

    @property
    def enabled(self) -> bool:
        return bool(self.props.get("enabled", True))

    @property
    def admincount(self) -> bool:
        return bool(self.props.get("admincount", False))


@dataclass
class Edge:
    src: str          # source SID (the principal you control)
    dst: str          # target SID (what it grants control over)
    kind: str         # MemberOf, GenericAll, DCSync, AdminTo, ...


class Graph:
    def __init__(self) -> None:
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        self._out: Dict[str, List[Edge]] = {}
        self.name_index: Dict[str, str] = {}  # upper name -> sid
        self.adcs: dict = {}                   # ADCS detection summary

    def add_node(self, node: Node) -> None:
        if not node.sid:
            return
        node.sid = node.sid.upper()
        self.nodes.setdefault(node.sid, node)
        if node.name:
            self.name_index[node.name.upper()] = node.sid

    def add_edge(self, src: str, dst: str, kind: str) -> None:
        if not src or not dst:
            return
        self.edges.append(Edge(src.upper(), dst.upper(), kind))

    def index(self) -> None:
        self._out = {}
        for e in self.edges:
            self._out.setdefault(e.src, []).append(e)

    def out_edges(self, sid: str) -> List[Edge]:
        return self._out.get(sid.upper(), [])

    def resolve(self, query: str) -> Optional[str]:
        """Find a node SID from a user-typed query (name, name@domain, or SID)."""
        q = query.strip().upper()
        if q in self.nodes:
            return q
        if q in self.name_index:
            return self.name_index[q]
        # suffix match on sAMAccountName@DOMAIN or bare label
        for name, sid in self.name_index.items():
            if name.split("@", 1)[0] == q:
                return sid
        return None

    def search(self, term: str, limit: int = 50) -> List[Node]:
        t = term.strip().upper()
        if not t:
            return []
        exact, prefix, sub = [], [], []
        for name, sid in self.name_index.items():
            node = self.nodes[sid]
            if name == t:
                exact.append(node)
            elif name.startswith(t) or name.split("@", 1)[0].startswith(t):
                prefix.append(node)
            elif t in name:
                sub.append(node)
        out = exact + prefix + sub
        return out[:limit]


# --- ingest ---------------------------------------------------------------
def _get(obj: dict, *keys, default=None):
    for k in keys:
        if k in obj and obj[k] is not None:
            return obj[k]
        # case-insensitive fallback
        for ok in obj:
            if ok.lower() == k.lower() and obj[ok] is not None:
                return obj[ok]
    return default


def _node_from(obj: dict, ntype: str) -> Optional[Node]:
    props = _get(obj, "Properties", default={}) or {}
    sid = _get(obj, "ObjectIdentifier", "ObjectId") or _get(props, "objectid", "objectsid")
    name = _get(props, "name", "distinguishedname") or _get(obj, "Name")
    if not sid:
        return None
    return Node(str(sid), str(name or sid), ntype, {k.lower(): v for k, v in props.items()})


def _aces(obj: dict):
    """Yield (principalSID, rightName) from an object's ACE list."""
    for ace in _get(obj, "Aces", default=[]) or []:
        psid = _get(ace, "PrincipalSID", "PrincipalSid")
        right = _get(ace, "RightName", "Right")
        if psid and right:
            yield str(psid), str(right)


def _results(field):
    """BloodHound-CE wraps lists as {"Results":[...],"Collected":bool}; unwrap."""
    if isinstance(field, dict):
        field = field.get("Results", field.get("results", []))
    return field if isinstance(field, list) else []


def _principals(field) -> List[str]:
    """Extract principal SIDs from a Results-or-list field of {ObjectIdentifier}."""
    out = []
    for r in _results(field):
        sid = _get(r, "ObjectIdentifier", "ObjectId", "MemberId") if isinstance(r, dict) else r
        if sid:
            out.append(str(sid))
    return out


def ingest_dir(path: str) -> Graph:
    """Ingest a directory of *.json (BloodHound export, already unzipped)."""
    files = glob.glob(os.path.join(path, "*.json"))
    blobs = {}
    for fp in files:
        with open(fp, "r", encoding="utf-8-sig") as fh:
            try:
                blobs[os.path.basename(fp)] = json.load(fh)
            except json.JSONDecodeError:
                continue
    return _build(blobs)


def ingest_zip(path: str) -> Graph:
    blobs = {}
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if not name.lower().endswith(".json"):
                continue
            with zf.open(name) as fh:
                data = io.TextIOWrapper(fh, encoding="utf-8-sig").read()
            try:
                blobs[os.path.basename(name)] = json.loads(data)
            except json.JSONDecodeError:
                continue
    return _build(blobs)


def ingest_any(path: str) -> Graph:
    if path.lower().endswith(".zip"):
        return ingest_zip(path)
    if os.path.isdir(path):
        return ingest_dir(path)
    raise ValueError("expected a .zip or a directory of BloodHound json")


def _classify(filename: str, blob: dict) -> str:
    meta = _get(blob, "meta", default={}) or {}
    t = str(_get(meta, "type", default="")).lower()
    if t in _FILE_TYPES:
        return _FILE_TYPES[t]
    low = filename.lower()
    for key, ntype in _FILE_TYPES.items():
        if key in low:
            return ntype
    return "Base"


def _build(blobs: Dict[str, dict]) -> Graph:
    g = Graph()
    # pass 1: nodes
    for fname, blob in blobs.items():
        ntype = _classify(fname, blob)
        for obj in _get(blob, "data", default=[]) or []:
            node = _node_from(obj, ntype)
            if node:
                g.add_node(node)

    # pass 2: edges
    for fname, blob in blobs.items():
        ntype = _classify(fname, blob)
        for obj in _get(blob, "data", default=[]) or []:
            sid = (_get(obj, "ObjectIdentifier", "ObjectId")
                   or _get(_get(obj, "Properties", default={}) or {}, "objectid"))
            if not sid:
                continue
            sid = str(sid)

            # ACEs: principal controls this object
            for psid, right in _aces(obj):
                g.add_edge(psid, sid, right)

            if ntype == "Group":
                for m in _get(obj, "Members", default=[]) or []:
                    msid = _get(m, "ObjectIdentifier", "ObjectId", "MemberId")
                    if msid:
                        g.add_edge(str(msid), sid, "MemberOf")

            if ntype == "Computer":
                # local admin / RDP / PSRemote / DCOM rights: principal -> computer
                for field_name, kind in (("LocalAdmins", "AdminTo"), ("RemoteDesktopUsers", "CanRDP"),
                                         ("PSRemoteUsers", "CanPSRemote"), ("DcomUsers", "ExecuteDCOM")):
                    for psid in _principals(_get(obj, field_name, default=[])):
                        g.add_edge(psid, sid, kind)
                # sessions: controlling the computer yields the logged-on user's creds
                for s in _results(_get(obj, "Sessions", default=[])):
                    usid = _get(s, "UserSID", "UserId", "ObjectIdentifier") if isinstance(s, dict) else None
                    csid = _get(s, "ComputerSID", "ComputerId") if isinstance(s, dict) else None
                    if usid:
                        g.add_edge(str(csid or sid), str(usid), "HasSession")
                # constrained delegation (outbound)
                for d in _get(obj, "AllowedToDelegate", default=[]) or []:
                    tsid = _get(d, "ObjectIdentifier", "ObjectId") if isinstance(d, dict) else d
                    if tsid:
                        g.add_edge(sid, str(tsid), "AllowedToDelegate")
                # RBCD: principals allowed to act on behalf of this computer
                for psid in _principals(_get(obj, "AllowedToAct", default=[])):
                    g.add_edge(psid, sid, "AllowedToAct")

            # GPO links on OUs/Domains (controlling the GPO reaches linked objects)
            if ntype in ("OU", "Domain"):
                for link in _get(obj, "Links", "GPLinks", default=[]) or []:
                    gsid = _get(link, "GUID", "ObjectIdentifier", "GPOIdentifier") if isinstance(link, dict) else link
                    if gsid:
                        g.add_edge(str(gsid), sid, "GPLink")

            # Containment: controlling an OU/Container/Domain reaches its children.
            if ntype in ("OU", "Domain", "Container"):
                for child in _get(obj, "ChildObjects", "Contains", default=[]) or []:
                    csid = _get(child, "ObjectIdentifier", "ObjectId") if isinstance(child, dict) else child
                    if csid:
                        g.add_edge(sid, str(csid), "Contains")

    # ADCS ESC edges (certificate abuse) from template/CA properties.
    try:
        from . import adcs
        g.adcs = adcs.detect(blobs, g)
    except Exception as e:  # never let ADCS parsing break core ingest
        g.adcs = {"error": e.__class__.__name__}

    g.index()
    return g


def _dc_sids(g: Graph) -> set[str]:
    """Computers that are domain controllers (member of Domain Controllers / EDC)."""
    dc_groups = set()
    for sid, node in g.nodes.items():
        nm = node.name.upper().split("@", 1)[0]
        rid = sid.rsplit("-", 1)[-1] if sid.startswith("S-1-5-21") else ""
        if nm in ("DOMAIN CONTROLLERS", "ENTERPRISE DOMAIN CONTROLLERS") or rid == "516":
            dc_groups.add(sid)
    dcs = set()
    for e in g.edges:
        if e.kind == "MemberOf" and e.dst in dc_groups:
            dcs.add(e.src)
    return dcs


def high_value_targets(g: Graph, broaden: bool = False, custom: List[str] | None = None) -> List[str]:
    """SIDs that represent 'domain compromise': DA/EA/Administrators groups, the
    domain root (DCSync), and every domain controller.

    broaden=True also treats adminCount=1 objects (protected / Tier-0), enterprise
    CAs and the NTAuth store as targets. custom is a list of user-supplied target
    queries (names or SIDs), resolved and added (e.g. Tier-0 service accounts)."""
    hv = []
    for sid, node in g.nodes.items():
        nm = node.name.upper().split("@", 1)[0]
        rid = sid.rsplit("-", 1)[-1] if sid.startswith("S-1-5-21") else ""
        if nm in ("DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS"):
            hv.append(sid)
        elif rid in ("512", "519", "544"):
            hv.append(sid)
        elif node.ntype == "Domain":
            hv.append(sid)  # DCSync target
    hv.extend(_dc_sids(g))
    if broaden:
        for sid, node in g.nodes.items():
            if node.admincount and node.ntype in ("User", "Group"):
                hv.append(sid)
            elif node.ntype in ("EnterpriseCA", "NTAuthStore"):
                hv.append(sid)
    for q in custom or []:
        s = g.resolve(q)
        if s:
            hv.append(s)
    return list(dict.fromkeys(hv))
