"""Reversible local masking for AD objects.

Design: we control the whole pipeline (we build the masked graph, send it to the
AI, get back paths referencing pseudonyms, and unmap locally). So no in-band
encryption is needed -- the AI never reverses anything. Pseudonyms are
deterministic (stable across a project via HMAC) and the real<->pseudonym map
lives ONLY on disk in the project dir. Raw data stays unmasked locally; only the
masked view ever leaves the machine.

Masked forms keep *structure* (type + realm) because that is not sensitive and
the AI needs it to reason about attack paths:

    FURKAN@EXAMPLE.LOCAL              -> U-5F3A9C@DOM1.LOCAL
    DOMAIN ADMINS@EXAMPLE.LOCAL       -> DOMAIN ADMINS@DOM1.LOCAL   (well-known, kept)
    DC01.EXAMPLE.LOCAL                -> C-1B77E2.DOM1.LOCAL
    S-1-5-21-111-222-333-1104         -> S-1-5-21-R1-1104           (RID kept, domain masked)

Well-known group names (Domain Admins, Enterprise Admins, ...) and well-known
RIDs/SIDs are NOT masked: they carry no customer identity and are the semantic
anchors of every attack path. Everything else (sAMAccountNames, host labels,
custom OU/GPO names, domain/realm) is masked.
"""
from __future__ import annotations

import hmac
import json
import os
import re
from hashlib import sha256
from typing import Dict, Iterable

# Group names whose identity is universal AD, not customer data. Kept verbatim so
# the AI (and the report) can anchor paths on them.
WELL_KNOWN_NAMES = {
    "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS", "ADMINISTRATORS",
    "DOMAIN CONTROLLERS", "ENTERPRISE DOMAIN CONTROLLERS", "DOMAIN USERS",
    "DOMAIN COMPUTERS", "AUTHENTICATED USERS", "EVERYONE", "ACCOUNT OPERATORS",
    "BACKUP OPERATORS", "SERVER OPERATORS", "PRINT OPERATORS", "DNSADMINS",
    "GROUP POLICY CREATOR OWNERS", "CERT PUBLISHERS", "READ-ONLY DOMAIN CONTROLLERS",
    "KEY ADMINS", "ENTERPRISE KEY ADMINS", "PROTECTED USERS", "GUESTS",
    "REMOTE DESKTOP USERS", "DISTRIBUTED COM USERS",
    # Built-in universal accounts (same RID in every domain, no customer identity).
    "ADMINISTRATOR", "GUEST", "KRBTGT", "DEFAULTACCOUNT", "WDAGUTILITYACCOUNT",
}
# Well-known RIDs (>= -512 etc.) are stable across every domain.
WELL_KNOWN_RIDS = {
    "500", "501", "502", "512", "513", "514", "515", "516", "517", "518",
    "519", "520", "521", "522", "525", "526", "527", "498", "9",
}
# Well-known full SIDs (built-in, not domain-specific).
WELL_KNOWN_SIDS = {
    "S-1-1-0", "S-1-5-11", "S-1-5-9", "S-1-5-18", "S-1-5-32-544", "S-1-5-32-545",
    "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551", "S-1-5-32-555",
    "S-1-5-32-562",
}

_SID_RE = re.compile(r"S-1-5-21-\d+-\d+-\d+-(\d+)")


def new_key() -> str:
    return os.urandom(32).hex()


class Masker:
    """Deterministic, reversible masker backed by a persisted map.

    The map is additive: once a value gets a pseudonym it never changes within a
    project, so masked graphs correlate across scans.
    """

    def __init__(self, key_hex: str, mapping: Dict[str, str] | None = None):
        self._key = bytes.fromhex(key_hex)
        # pseudonym -> real  (reverse map, the only thing we need to unmask)
        self._rev: Dict[str, str] = dict(mapping or {})
        # real -> pseudonym  (forward cache, rebuilt from rev)
        self._fwd: Dict[str, str] = {v: k for k, v in self._rev.items()}
        self._domains: Dict[str, str] = {}  # real realm -> DOMn
        self._reload_domains()

    # --- persistence -------------------------------------------------------
    @classmethod
    def load(cls, path: str, key_hex: str) -> "Masker":
        mapping = {}
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                mapping = json.load(fh)
        return cls(key_hex, mapping)

    def save(self, path: str) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._rev, fh, ensure_ascii=False, indent=0)
        os.replace(tmp, path)

    def mapping(self) -> Dict[str, str]:
        return dict(self._rev)

    # --- helpers -----------------------------------------------------------
    def _short(self, kind: str, value: str) -> str:
        mac = hmac.new(self._key, (kind + "\0" + value.lower()).encode("utf-8"), sha256)
        return mac.hexdigest()[:6].upper()

    def _reload_domains(self) -> None:
        for pseudo, real in self._rev.items():
            if pseudo.startswith("@DOMAIN:"):
                self._domains[real] = pseudo.split(":", 1)[1]

    def _domain_pseudo(self, realm: str) -> str:
        realm_u = realm.upper()
        if realm_u in self._domains:
            return self._domains[realm_u]
        # keep the TLD label so the AI sees realm shape (e.g. .LOCAL / .CORP)
        tld = realm_u.rsplit(".", 1)[-1] if "." in realm_u else "LOCAL"
        pseudo = "DOM%d.%s" % (len(self._domains) + 1, tld)
        self._domains[realm_u] = pseudo
        self._rev["@DOMAIN:" + pseudo] = realm_u  # bookkeeping entry
        return pseudo

    def _remember(self, pseudo: str, real: str) -> str:
        self._rev[pseudo] = real
        self._fwd[real] = pseudo
        return pseudo

    # --- masking -----------------------------------------------------------
    def mask_name(self, name: str, node_type: str = "") -> str:
        """Mask an AD principal name like NAME@REALM, HOST.REALM or a bare label."""
        if not name:
            return name
        if name in self._fwd:
            return self._fwd[name]
        upper = name.upper()

        # NAME@REALM form (users, groups).
        if "@" in upper:
            local, realm = upper.rsplit("@", 1)
            dpseudo = self._domain_pseudo(realm)
            if local in WELL_KNOWN_NAMES:
                return "%s@%s" % (local, dpseudo)  # not stored; fully derivable
            tag = "G" if node_type.lower() == "group" else "U"
            pseudo = "%s-%s@%s" % (tag, self._short(node_type or "name", name), dpseudo)
            return self._remember(pseudo, name)

        # HOST.REALM form (computers / FQDNs).
        if "." in upper and node_type.lower() in ("computer", "", "ou", "gpo", "domain", "container"):
            host, realm = upper.split(".", 1)
            if node_type.lower() == "domain" or host in ("", None):
                return self._domain_pseudo(upper)
            dpseudo = self._domain_pseudo(realm)
            tag = {"computer": "C", "ou": "OU", "gpo": "GPO", "container": "CN"}.get(node_type.lower(), "C")
            pseudo = "%s-%s.%s" % (tag, self._short(node_type or "host", name), dpseudo)
            return self._remember(pseudo, name)

        # Bare label.
        if upper in WELL_KNOWN_NAMES:
            return upper
        pseudo = "N-%s" % self._short(node_type or "label", name)
        return self._remember(pseudo, name)

    def mask_sid(self, sid: str) -> str:
        if not sid:
            return sid
        s = sid.upper()
        if s in WELL_KNOWN_SIDS or s.startswith("S-1-5-32-"):
            return s
        m = _SID_RE.match(s)
        if m:
            rid = m.group(1)
            if rid in WELL_KNOWN_RIDS:
                # keep well-known RID, mask only the domain identifier portion
                return "S-1-5-21-R%s-%s" % (self._short("siddom", s.rsplit("-", 1)[0]), rid)
            return self._remember(
                "S-1-5-21-R%s-%s" % (self._short("siddom", s.rsplit("-", 1)[0]), rid), sid
            )
        # non domain SID we do not recognise: mask wholesale, fail-safe
        return self._remember("S-OPAQUE-%s" % self._short("sid", s), sid)

    # --- unmasking ---------------------------------------------------------
    def unmask(self, text: str) -> str:
        """Replace every pseudonym in text with its real value (longest first)."""
        if not text:
            return text
        for pseudo in sorted((p for p in self._rev if not p.startswith("@DOMAIN:")),
                             key=len, reverse=True):
            if pseudo in text:
                text = text.replace(pseudo, self._rev[pseudo])
        # realms last (shorter tokens, could be substrings of the above)
        for real, pseudo in sorted(self._domains.items(), key=lambda kv: len(kv[1]), reverse=True):
            if pseudo in text:
                text = text.replace(pseudo, real)
        return text

    def unmask_obj(self, obj):
        """Deep-unmask a JSON-like structure (dict/list/str)."""
        if isinstance(obj, str):
            return self.unmask(obj)
        if isinstance(obj, list):
            return [self.unmask_obj(x) for x in obj]
        if isinstance(obj, dict):
            return {self.unmask(k): self.unmask_obj(v) for k, v in obj.items()}
        return obj

    def leak_check(self, text: str, reals: Iterable[str]) -> list[str]:
        """Independent second defence: confirm no real value survives in the text.

        Two things make this precise rather than a naive substring scan:
          * Kept well-known names (DOMAIN ADMINS, ADMINISTRATORS, ...) are blanked
            out first, so a real value that is a *substring* of one of them — e.g.
            ADMINISTRATOR inside the kept group ADMINISTRATORS — is not a false hit.
          * Matching is on identifier boundaries, so ADMINISTRATOR does not match
            inside ADMINISTRATORS and WEB does not match inside WEB01.

        Returns the real values still present (empty == clean); caller fails closed.
        """
        scan = text
        for wk in WELL_KNOWN_NAMES:
            scan = re.sub(r"(?i)(?<![A-Za-z0-9])" + re.escape(wk) + r"(?![A-Za-z0-9])", " ", scan)
        low = scan.lower()
        hits: list[str] = []
        seen: set[str] = set()
        for real in reals:
            if not real:
                continue
            r = real.lower()
            if len(r) < 4 or r in seen:
                continue
            seen.add(r)
            if r not in low:                       # fast reject (C-level substring)
                continue
            if re.search(r"(?<![a-z0-9])" + re.escape(r) + r"(?![a-z0-9])", low):
                hits.append(real)
        return hits
