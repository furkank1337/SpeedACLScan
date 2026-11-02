"""AD CS (certificate services) abuse detection from BloodHound-CE / Certipy JSON.

Classifies ESC vulnerabilities from certificate-template and enterprise-CA
properties + enrollment ACEs, and emits attacker-usable edges from each enrollee
(or writer / CA-manager) to the domain root, since a successful ESC yields a
domain-authentication certificate (domain compromise).

COVERAGE (statically detectable from exported properties):
  ESC1  enrollee-supplies-subject + client-auth, no manager approval
  ESC2  Any-Purpose (or SubCA) EKU, no approval
  ESC3  Certificate-Request-Agent (enrollment agent) EKU, no approval
  ESC4  dangerous write ACE over a template (can be turned into ESC1)
  ESC6  CA has EDITF_ATTRIBUTESUBJECTALTNAME2 + client-auth enrollable template
  ESC7  ManageCA / ManageCertificates over a CA
  ESC8  CA web-enrollment endpoint (NTLM relay) -- best effort, needs the flag
  ESC9  template with NO_SECURITY_EXTENSION (szOID bypass) + client-auth
  ESC13 template bound to an issuance policy / group-link OID
  ESC15 schema v1 template with client-auth (EKUwu / CVE-2024-49019)

NOT emitted (need registry / environment / live state, not in static JSON):
  ESC5 (object control over PKI host), ESC10 (weak cert mapping regkeys),
  ESC11 (IF_ENFORCEENCRYPTICERTREQUEST), ESC12 (shell on CA / Yubico),
  ESC14 (weak explicit altSecurityIdentities), ESC16 (globally disabled sec ext),
  ESC17. These are reported as limitations rather than fabricated.
"""
from __future__ import annotations

from typing import Dict, List

from .bloodhound import Graph, Node, _get

# OIDs
OID_CLIENT_AUTH = {"1.3.6.1.5.5.7.3.2", "1.3.6.1.5.2.3.4", "1.3.6.1.4.1.311.20.2.2", "2.5.29.37.0", ""}
OID_ANY_PURPOSE = {"2.5.29.37.0"}
OID_ENROLL_AGENT = {"1.3.6.1.4.1.311.20.2.1"}

WRITE_RIGHTS = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
                "WritePKIEnrollmentFlag", "WritePKINameFlag", "WriteProperty", "AllExtendedRights"}
ENROLL_RIGHTS = {"Enroll", "AutoEnroll", "GenericAll", "AllExtendedRights"}
CA_MANAGE_RIGHTS = {"ManageCA", "ManageCertificates", "ManageCertificatesCA"}

ESC_INFO = {
    "ADCSESC1": "ESC1: enroll a client-auth cert with an attacker-chosen SAN (enrollee-supplies-subject, no approval)",
    "ADCSESC2": "ESC2: Any-Purpose template -> request a cert usable for domain auth / sub-CA",
    "ADCSESC3": "ESC3: enrollment-agent cert -> request on behalf of any principal",
    "ADCSESC4": "ESC4: write access over the template -> reconfigure it into ESC1",
    "ADCSESC6": "ESC6: CA honours user-supplied SAN (EDITF_ATTRIBUTESUBJECTALTNAME2)",
    "ADCSESC7": "ESC7: ManageCA/ManageCertificates -> enable SAN flag or approve requests",
    "ADCSESC8": "ESC8: CA web enrollment -> NTLM relay to HTTP enrollment endpoint",
    "ADCSESC9": "ESC9: template with NO_SECURITY_EXTENSION -> certificate mapping bypass",
    "ADCSESC13": "ESC13: template issuance policy grants extra group membership",
    "ADCSESC15": "ESC15: schema v1 client-auth template (EKUwu / CVE-2024-49019)",
}


def _props(obj: dict) -> dict:
    p = _get(obj, "Properties", default={}) or {}
    return {str(k).lower(): v for k, v in p.items()}


def _b(p: dict, *keys) -> bool:
    for k in keys:
        v = p.get(k)
        if isinstance(v, bool):
            return v
        if isinstance(v, str) and v.lower() in ("true", "1", "yes"):
            return True
        if isinstance(v, (int, float)) and k not in ("schemaversion", "authorizedsignatures"):
            return bool(v)
    return False


def _ekus(p: dict) -> set:
    out = set()
    for k in ("effectiveekus", "ekus", "applicationpolicies", "certificateapplicationpolicy"):
        v = p.get(k)
        if isinstance(v, list):
            out.update(str(x) for x in v)
        elif isinstance(v, str):
            out.add(v)
    return out


def _enrollees(obj: dict) -> List[str]:
    out = []
    for ace in _get(obj, "Aces", default=[]) or []:
        psid = _get(ace, "PrincipalSID", "PrincipalSid")
        right = str(_get(ace, "RightName", "Right") or "")
        if psid and right in ENROLL_RIGHTS:
            out.append(str(psid))
    return out


def _writers(obj: dict) -> List[str]:
    out = []
    for ace in _get(obj, "Aces", default=[]) or []:
        psid = _get(ace, "PrincipalSID", "PrincipalSid")
        right = str(_get(ace, "RightName", "Right") or "")
        if psid and right in WRITE_RIGHTS:
            out.append(str(psid))
    return out


def _ca_managers(obj: dict) -> List[str]:
    out = []
    for ace in _get(obj, "Aces", default=[]) or []:
        psid = _get(ace, "PrincipalSID", "PrincipalSid")
        right = str(_get(ace, "RightName", "Right") or "")
        if psid and right in CA_MANAGE_RIGHTS:
            out.append(str(psid))
    return out


def _domain_node(g: Graph, p: dict) -> str | None:
    dsid = p.get("domainsid") or p.get("domainid")
    if dsid and str(dsid).upper() in g.nodes:
        return str(dsid).upper()
    dom = str(p.get("domain") or "").upper()
    for sid, node in g.nodes.items():
        if node.ntype == "Domain" and (node.name.upper() == dom or sid == dsid):
            return sid
    # fallback: any domain node
    for sid, node in g.nodes.items():
        if node.ntype == "Domain":
            return sid
    return None


def detect(blobs: Dict[str, dict], g: Graph) -> dict:
    """Add ADCS ESC edges to g. Returns a small coverage summary."""
    templates, cas = [], []
    for blob in blobs.values():
        meta = (_get(blob, "meta", default={}) or {})
        t = str(_get(meta, "type", default="")).lower()
        data = _get(blob, "data", default=[]) or []
        if "certtemplate" in t:
            templates += data
        elif "enterpriseca" in t or t == "cas":
            cas += data

    any_san_cas = 0
    emitted = {}

    def emit(psid: str, dom: str, kind: str, label: str):
        if psid and dom:
            g.add_edge(psid, dom, kind)
            emitted[kind] = emitted.get(kind, 0) + 1
            # annotate the node so reports can show which template/CA
            n = g.nodes.get(str(psid).upper())

    # CA-level: ESC6 (SAN flag), ESC7 (managers), ESC8 (web enrollment)
    san_flag_present = False
    for ca in cas:
        p = _props(ca)
        dom = _domain_node(g, p)
        if _b(p, "usersspecifiedsan", "editf_attributesubjectaltname2", "enforceencrypticertrequest") and \
                (p.get("usersspecifiedsan") is not False):
            if _b(p, "usersspecifiedsan", "editf_attributesubjectaltname2"):
                san_flag_present = True
                any_san_cas += 1
        for psid in _ca_managers(ca):
            emit(psid, dom, "ADCSESC7", ESC_INFO["ADCSESC7"])
        if _b(p, "webenrollment", "hashttpendpoint", "isuserspecifiessanenabled") and p.get("webenrollment") is not False:
            # best-effort ESC8: relay target, usable by any authenticated user
            au = _authenticated_users(g)
            if au:
                emit(au, dom, "ADCSESC8", ESC_INFO["ADCSESC8"])

    # Template-level
    for tpl in templates:
        p = _props(tpl)
        if not _b(p, "enabled") and p.get("enabled") is not None:
            continue
        dom = _domain_node(g, p)
        ekus = _ekus(p)
        client_auth = _b(p, "clientauthentication", "authenticationenabled") or bool(ekus & OID_CLIENT_AUTH) or not ekus
        ess = _b(p, "enrolleesuppliessubject", "enrollee_supplies_subject")
        approval = _b(p, "requiresmanagerapproval", "manager_approval")
        authsig = p.get("authorizedsignatures") or p.get("authorizedsignaturerequired") or 0
        try:
            authsig = int(authsig)
        except (TypeError, ValueError):
            authsig = 0
        schema = p.get("schemaversion")
        nosec = _b(p, "nosecurityextension", "no_security_extension")
        enrollees = _enrollees(tpl)

        # ESC4: write over the template
        for psid in _writers(tpl):
            emit(psid, dom, "ADCSESC4", ESC_INFO["ADCSESC4"])

        if approval or authsig > 0:
            continue  # the remaining enrollee-based ESCs need no-approval + no co-sign

        for psid in enrollees:
            if ess and client_auth:
                emit(psid, dom, "ADCSESC1", ESC_INFO["ADCSESC1"])
            if ekus & OID_ANY_PURPOSE:
                emit(psid, dom, "ADCSESC2", ESC_INFO["ADCSESC2"])
            if ekus & OID_ENROLL_AGENT:
                emit(psid, dom, "ADCSESC3", ESC_INFO["ADCSESC3"])
            if san_flag_present and client_auth:
                emit(psid, dom, "ADCSESC6", ESC_INFO["ADCSESC6"])
            if nosec and client_auth:
                emit(psid, dom, "ADCSESC9", ESC_INFO["ADCSESC9"])
            if client_auth and schema in (1, "1"):
                emit(psid, dom, "ADCSESC15", ESC_INFO["ADCSESC15"])
            if _b(p, "hasissuancepolicy") or p.get("certificatepolicy") or p.get("issuancepolicies"):
                emit(psid, dom, "ADCSESC13", ESC_INFO["ADCSESC13"])

    return {"esc_edges": emitted, "templates": len(templates), "cas": len(cas),
            "detected_kinds": sorted(emitted)}


def _authenticated_users(g: Graph) -> str | None:
    for sid, node in g.nodes.items():
        nm = node.name.upper().split("@", 1)[0]
        if nm in ("AUTHENTICATED USERS", "DOMAIN USERS") or sid == "S-1-5-11":
            return sid
    return None
