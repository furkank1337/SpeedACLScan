# SpeedACLScan

**Masked, AI-assisted Active Directory attack-path analysis.**

SpeedACLScan ingests a BloodHound collection, builds the full AD graph **locally**,
and asks an LLM (via OpenCode) to draw attack paths from your compromised principals
to Domain Admin / Tier-0 — but **every FQDN, username, group and computer name is
masked before it ever leaves your machine**. The AI reasons over pseudonyms; the
unmasked graph, the findings and the final report stay local. Same masking
philosophy as [Cloak](https://github.com/furkank1337/BurpCloak), applied to AD.

It runs as a single local web app (stdlib `http.server`, no web framework) with a
project-based workflow: collect → mark compromised → scope → analyze → interactive
graph + HTML/Markdown report.

---

## Why masking

AD object names leak the customer: domain, hostnames, naming conventions, service
accounts, admin handles. Sending a raw BloodHound graph to a hosted model exfiltrates
all of that. SpeedACLScan replaces every name/SID with a deterministic pseudonym
(HMAC-based, reversible only via the local map), sends the pseudonymized graph to the
AI, then **reverses the AI's answer locally**. Well-known SIDs/RIDs (Domain Admins,
Authenticated Users, KRBTGT, built-in accounts, …) are kept so the model can still
reason about them.

A **fail-closed leak check** runs on every outbound payload: if any real token
survives masking (word-boundary matched, well-known names stripped first), the request
is **blocked**, not sent.

---

## Install & run

Requires Python 3.10+. No third-party Python dependencies for the core app.
For live collection you need [NetExec](https://github.com/Pennyw0rth/NetExec) (`nxc`)
on `PATH`; for AI analysis you need an [OpenCode](https://opencode.ai) server.

```bash
git clone https://github.com/furkank1337/SpeedACLScan
cd SpeedACLScan
python -m speedaclscan            # serves on http://127.0.0.1:8777
python -m speedaclscan --host 127.0.0.1 --port 8777
```

Then open the printed URL. AI is **optional** — without OpenCode the offline engine
(k-shortest enumeration + standalone ACE detection) still produces the full graph and
report; the `use AI` toggle just adds the model's path proposals on top.

---

## Workflow

1. **Projects** — each engagement is its own project (own collection, pwned list,
   masking map, findings). Listed newest-first; deletable.
2. **Collect** — per project, either:
   - **New BloodHound scan** — runs `nxc ldap <dc> -u <user> -p <pass> --bloodhound
     --collection All`. DC FQDN is preferred as the target; `--dns-server` defaults to
     the DC IP when left blank. Creds go to the `nxc` subprocess only.
   - **Import collection zip** — load any existing SharpHound / BloodHound-CE export.
3. **Compromised principals** — fast search over the collected objects; add owned
   `domain\user` / groups / computers / machine accounts to the pwned list.
4. **Scope** (chosen *before* analysis — broadens what gets found):
   - Enumerate all paths (k-shortest, easiest still ranked first)
   - Report standalone dangerous ACEs (risks even without a full path to DA)
   - Broaden targets (adminCount / DCs / Enterprise CAs / NTAuth)
   - Detect AD CS (ESC) exposure
   - **Extra Tier-0 targets** — type any principal/SID to add it as a target.
5. **Run analysis** — offline engine always runs; if `use AI` is on, the masked graph
   goes to OpenCode, paths come back, and each is **verified against the real graph**
   before being accepted (see below).
6. **Results** — BloodHound-style draggable/zoomable SVG graph (full-width, parallel
   edges for e.g. ESC1+ESC15 on the same pair don't overlap), ranked vulnerability
   list, standalone-ACE table, and **Open full report** (same app CSS, zoom + scroll).
   Report is emitted as both HTML and Markdown.
7. **Logs** — the OpenCode session for the project: what was **sent** (masked), what
   was **received** (masked), and how it was **reversed** locally.

Dark/light toggle top-right.

---

## Severity

Findings are scored CVSS:3.1-style by **blast radius × attack complexity**, not by
edge type alone. Domain Users holding DCSync on a DC ranks far above a single user
with a GenericWrite on one OU. Each path's cost is the sum of its edge costs; the
easiest path to each target is ranked first, and the rest are still enumerated.

---

## Detection coverage

Built from the BloodHound collection — detection is **bounded by what SharpHound/nxc
actually collects**, not by what the model knows (see *Extending detection* below).

- **ACL abuse** — every ACE is ingested generically: GenericAll, GenericWrite,
  WriteDacl, WriteOwner, Owns, ForceChangePassword, AddKeyCredentialLink (shadow
  creds), AddMember, DCSync / GetChanges / GetChangesAll, …
- **RBCD** — `AllowedToAct` (msDS-AllowedToActOnBehalfOfOtherIdentity).
- **Delegation** — `AllowedToDelegate` (constrained).
- **Group membership** — `Members` → `MemberOf`, transitively.
- **Local rights** — LocalAdmins → `AdminTo`, RemoteDesktopUsers → `CanRDP`,
  PSRemoteUsers → `CanPSRemote`, DcomUsers → `ExecuteDCOM`.
- **Sessions** — `HasSession`.
- **GPO / OU abuse** — `GPLink` (GPO → linked OU/Domain) and `Contains`
  (OU/Domain/Container → children). A write over a GPO chains
  `GenericWrite → GPLink → Contains` down to every affected object (e.g. a DC);
  a write over an OU chains `GenericWrite → Contains` to the objects inside it.
- **AD CS (ESC)** — property/template-detectable escalations are emitted from the
  cert-template and CA blobs (ESC1, ESC2, ESC3, ESC4, ESC6, ESC7, ESC8, ESC9, ESC13,
  ESC15). ESCs that require live host/registry state (e.g. ESC5/10/11/12/14/16/17) are
  **intentionally not fabricated** — they can't be proven from an offline graph.

**Standalone dangerous ACEs** — dangerous rights held by wide principals
(Domain Users, Authenticated Users, Everyone, Domain Computers, …) are reported *even
when they don't chain all the way to Domain Admin*.

### A note on wide principals

Marking **Domain Users** does **not** automatically pull in **Authenticated Users** or
**Everyone** — these are computed well-known SIDs with no `MemberOf` edge between them.
If an ACL is granted to Authenticated Users / Everyone and you want it traversed from a
standard foothold, mark those principals as pwned too (a real user + Domain Users +
Authenticated Users + Everyone covers the typical "any domain account" position).

---

## The AI contract (and why it can't hallucinate)

The model receives **only** a masked graph:

```
nodes[]   : {id, name (masked), type}
edges[]   : {src, dst, kind}      # controlling src enables acting on dst via kind
pwned[]   : already-compromised node ids
targets[] : domain / Tier-0 node ids
```

It must reply with paths built **only from edges present in `edges[]`**. Every path it
returns is then re-checked against the real local graph:

```python
# every hop must exist in the real graph, or the path is dropped
if not any(e.dst == dst and e.kind == kind for e in g.out_edges(src)):
    return None
```

So the AI **cannot invent an edge**. If it proposes a relationship that isn't in the
collection, the path is rejected. This is deliberate: the model's value is finding
*non-obvious chains* through real edges, not asserting attacks that aren't backed by
collected data.

---

## Extending detection — the "new ACL" question

**What the model's misconfig list controls vs. what the collection controls** is worth
being precise about:

- **If a new/exotic ACL is present in the collection as an ACE** (SharpHound collected
  it) but SpeedACLScan's edge model doesn't know that right name — **it still surfaces
  in attack paths.** Ingest is generic (`add_edge(principal, object, RightName)` with
  no whitelist), the masked payload sends **all** edges, unknown kinds fall back to a
  default cost, and path verification is existence-based (it checks the edge is real,
  not that the kind is known). It will appear in AI and offline paths that reach a
  target.
  - *Caveats:* an unknown kind is **not** listed in the **Standalone dangerous ACEs**
    table (that table is whitelisted to known-dangerous kinds), and its CVSS is
    default-weighted (`ac: medium`, cost 2.0) rather than finely tuned.
- **If the ACL isn't in the collection at all** (SharpHound/nxc never collected that
  relationship) — **it will not appear**, and the AI cannot add it, because
  verification rejects any edge absent from the real graph. The bottleneck here is
  collection, not the model.

**To fully promote a newly-published technique** (correct CVSS + standalone reporting +
offline detection), add its kind to `EDGE_MODEL` (and `DANGEROUS_KINDS` if it's a
standalone risk) in `speedaclscan/analyze.py`. You do **not** need to touch ingest —
the edge is already in the graph the moment it's in the collection.

---

## Data & privacy

- All project data lives under `~/.speedaclscan` (override with `SPEEDACLSCAN_HOME`):
  raw collection, masking map, pwned list, scope, `analysis.json`, and the rendered
  `report.html` / `report.md`.
- The masking map (pseudonym ↔ real) **never** leaves the machine.
- Only masked payloads are sent to OpenCode, and only after the fail-closed leak check
  passes.
- Credentials entered for a scan are passed to the `nxc` subprocess and not persisted.

---

## Project layout

```
speedaclscan/
  __main__.py     # python -m speedaclscan  → boots the server
  server.py       # local web app: projects, jobs, routes, fresh report render
  store.py        # ~/.speedaclscan persistence, per-project state
  scan.py         # nxc bloodhound command builder + runner
  bloodhound.py   # collection ingest → graph (ACEs, memberships, GPO/OU, sessions, RBCD)
  adcs.py         # AD CS ESC detection from cert-template / CA properties
  analyze.py      # edge model, k-shortest enumeration, severity, standalone ACEs
  masking.py      # deterministic pseudonyms + fail-closed leak check
  ai.py           # masked payload, OpenCode orchestration, path verification
  opencode.py     # OpenCode REST client
  report.py       # HTML + Markdown report, SVG graph layout
  web/            # SPA: index.html, app.js, style.css
```

---

## Legal

For **authorized** security assessments only. You are responsible for having
permission to collect against and analyze any environment you point this at.
