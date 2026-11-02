"""On-disk project store. Everything is local; raw (unmasked) BloodHound and the
masking map live only here, under the operator's own directory.

Layout:
  <base>/config.json                 global config (opencode, nxc, options)
  <base>/projects/<proj>/
       meta.json                     project metadata + masking key
       bh/                           raw BloodHound json (UNMASKED, never leaves)
       pwned.json                    list of pwned principal queries
       map.json                      masking reverse-map (pseudonym -> real)
       logs.jsonl                    opencode session log (what went / came / reverse)
       reports/report.html|.md
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List

from . import masking

DEFAULT_CONFIG = {
    "opencode": {"url": "http://127.0.0.1:4096", "model": "", "password": ""},
    "nxc": {"path": "nxc", "dc_ip": "", "dc_fqdn": "", "domain": "", "dns_server": "", "extra_args": ""},
    "options": {"max_iterations": 12, "parallelism": 1},
}

_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def _slug(name: str) -> str:
    s = _SAFE.sub("_", name.strip()).strip("_")
    return s or "project"


class Store:
    def __init__(self, base: str | None = None):
        self.base = base or os.environ.get("SPEEDACLSCAN_HOME") or os.path.expanduser("~/.speedaclscan")
        self.projects_dir = os.path.join(self.base, "projects")
        os.makedirs(self.projects_dir, exist_ok=True)
        self.config_path = os.path.join(self.base, "config.json")
        if not os.path.exists(self.config_path):
            self.save_config(DEFAULT_CONFIG)

    # --- config ------------------------------------------------------------
    def load_config(self) -> dict:
        try:
            with open(self.config_path, "r", encoding="utf-8") as fh:
                cfg = json.load(fh)
        except (OSError, json.JSONDecodeError):
            cfg = {}
        # deep-merge defaults so new keys appear
        out = json.loads(json.dumps(DEFAULT_CONFIG))
        for k, v in cfg.items():
            if isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k].update(v)
            else:
                out[k] = v
        return out

    def save_config(self, cfg: dict) -> None:
        _atomic_json(self.config_path, cfg)

    # --- projects ----------------------------------------------------------
    def project_dir(self, name: str) -> str:
        return os.path.join(self.projects_dir, _slug(name))

    def list_projects(self) -> List[dict]:
        out = []
        for d in os.listdir(self.projects_dir):
            meta = os.path.join(self.projects_dir, d, "meta.json")
            if os.path.exists(meta):
                try:
                    out.append(json.load(open(meta, encoding="utf-8")))
                except json.JSONDecodeError:
                    pass
        # most recently created first
        out.sort(key=lambda m: m.get("created", 0), reverse=True)
        return out

    def create_project(self, name: str) -> dict:
        pdir = self.project_dir(name)
        os.makedirs(os.path.join(pdir, "bh"), exist_ok=True)
        os.makedirs(os.path.join(pdir, "reports"), exist_ok=True)
        meta_path = os.path.join(pdir, "meta.json")
        if os.path.exists(meta_path):
            return json.load(open(meta_path, encoding="utf-8"))
        meta = {"name": name, "slug": _slug(name), "created": time.time(),
                "key": masking.new_key(), "status": "created"}
        _atomic_json(meta_path, meta)
        _atomic_json(os.path.join(pdir, "pwned.json"), [])
        return meta

    def delete_project(self, name: str) -> bool:
        import shutil
        d = self.project_dir(name)
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)
            return True
        return False

    def get_meta(self, name: str) -> dict:
        return json.load(open(os.path.join(self.project_dir(name), "meta.json"), encoding="utf-8"))

    def set_meta(self, name: str, **fields) -> dict:
        meta = self.get_meta(name)
        meta.update(fields)
        _atomic_json(os.path.join(self.project_dir(name), "meta.json"), meta)
        return meta

    def masker(self, name: str) -> masking.Masker:
        meta = self.get_meta(name)
        return masking.Masker.load(os.path.join(self.project_dir(name), "map.json"), meta["key"])

    def save_masker(self, name: str, m: masking.Masker) -> None:
        m.save(os.path.join(self.project_dir(name), "map.json"))

    # --- pwned list --------------------------------------------------------
    def get_pwned(self, name: str) -> List[str]:
        p = os.path.join(self.project_dir(name), "pwned.json")
        return json.load(open(p, encoding="utf-8")) if os.path.exists(p) else []

    def set_pwned(self, name: str, items: List[str]) -> None:
        seen, out = set(), []
        for it in items:
            k = it.strip()
            if k and k.upper() not in seen:
                seen.add(k.upper())
                out.append(k)
        _atomic_json(os.path.join(self.project_dir(name), "pwned.json"), out)

    # --- custom targets (Tier-0 etc.) -------------------------------------
    def get_targets(self, name: str) -> List[str]:
        p = os.path.join(self.project_dir(name), "targets.json")
        return json.load(open(p, encoding="utf-8")) if os.path.exists(p) else []

    def set_targets(self, name: str, items: List[str]) -> None:
        seen, out = set(), []
        for it in items:
            k = it.strip()
            if k and k.upper() not in seen:
                seen.add(k.upper()); out.append(k)
        _atomic_json(os.path.join(self.project_dir(name), "targets.json"), out)

    def get_scope(self, name: str) -> dict:
        p = os.path.join(self.project_dir(name), "scope.json")
        base = {"enumerate_all": True, "standalone": True, "broaden": True, "detect_adcs": True, "k": 5}
        if os.path.exists(p):
            try:
                base.update(json.load(open(p, encoding="utf-8")))
            except json.JSONDecodeError:
                pass
        return base

    def set_scope(self, name: str, scope: dict) -> None:
        _atomic_json(os.path.join(self.project_dir(name), "scope.json"), scope)

    # --- logs --------------------------------------------------------------
    def log(self, name: str, direction: str, text: str, note: str = "") -> None:
        """direction: sent | received | reverse | status"""
        rec = {"ts": time.time(), "dir": direction, "note": note, "text": text}
        with open(os.path.join(self.project_dir(name), "logs.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def get_logs(self, name: str, limit: int = 500) -> List[dict]:
        p = os.path.join(self.project_dir(name), "logs.jsonl")
        if not os.path.exists(p):
            return []
        lines = open(p, encoding="utf-8").read().splitlines()[-limit:]
        out = []
        for ln in lines:
            try:
                out.append(json.loads(ln))
            except json.JSONDecodeError:
                pass
        return out

    def clear_logs(self, name: str) -> None:
        open(os.path.join(self.project_dir(name), "logs.jsonl"), "w").close()

    def bh_dir(self, name: str) -> str:
        return os.path.join(self.project_dir(name), "bh")

    def reports_dir(self, name: str) -> str:
        return os.path.join(self.project_dir(name), "reports")


def _atomic_json(path: str, obj: Any) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
