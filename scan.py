"""BloodHound collection via NetExec (nxc) and its output handling.

Runs `nxc ldap <dc> -u <user> -p <pass> --bloodhound --collection All`, streams
progress to a callback for the Scan tab, locates the emitted .zip and copies it
into the project's bh/ directory. Credentials are passed to the subprocess only;
they are never logged or sent anywhere.
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import threading
import time
from typing import Callable, List

_ZIP_RE = re.compile(r"(\S+\.zip)")
# Rough phase markers nxc/bloodhound.py prints while collecting.
_PHASES = [
    ("Resolving collection methods", "Planning collection"),
    ("Done in", "Collection finished"),
    ("Compressing", "Compressing output"),
    ("Users", "Collecting users"),
    ("Groups", "Collecting groups"),
    ("Computers", "Collecting computers"),
    ("Trusts", "Collecting trusts"),
]


def build_command(cfg: dict, dc_ip: str, user: str, password: str,
                  dc_fqdn: str = "", domain: str = "") -> List[str]:
    nxc = cfg.get("nxc", {})
    path = nxc.get("path") or "nxc"
    fqdn = (dc_fqdn or nxc.get("dc_fqdn") or "").strip()
    ip = (dc_ip or nxc.get("dc_ip") or "").strip()
    dom = (domain or nxc.get("domain") or "").strip()
    # BloodHound collection resolves better against the DC FQDN; fall back to IP.
    target = fqdn or ip
    cmd = [path, "ldap", target, "-u", user, "-p", password]
    if dom:
        cmd += ["-d", dom]
    cmd += ["--bloodhound", "--collection", "All"]
    # DNS is needed so the BloodHound ingestor can locate the DC / resolve domain
    # objects (otherwise: "Could not find a domain controller"). Default to the DC
    # IP whenever no DNS is configured -- the DC is almost always the domain's DNS
    # server. This holds even when the target is an IP (the common case).
    dns = (nxc.get("dns_server") or "").strip() or ip
    if dns:
        cmd += ["--dns-server", dns]
    extra = nxc.get("extra_args")
    if extra:
        cmd += shlex.split(extra)
    return cmd


def run_collection(cfg: dict, dc_ip: str, user: str, password: str, bh_dir: str,
                   on_phase: Callable[[str, str], None],
                   dc_fqdn: str = "", domain: str = "") -> str:
    """Blocking. Streams phases via on_phase(level, message). Returns the path of
    the collected zip copied into bh_dir. Raises on failure."""
    cmd = build_command(cfg, dc_ip, user, password, dc_fqdn, domain)
    # redacted command for the log (no password)
    shown = list(cmd)
    if "-p" in shown:
        shown[shown.index("-p") + 1] = "********"
    on_phase("status", "Running: " + " ".join(shlex.quote(c) for c in shown))

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
    except FileNotFoundError:
        raise RuntimeError(f"nxc not found at '{cmd[0]}'. Set the nxc path in Config.")

    found_zip = None
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip("\n")
        if not line:
            continue
        on_phase("nxc", line)
        for needle, label in _PHASES:
            if needle.lower() in line.lower():
                on_phase("phase", label)
        m = _ZIP_RE.search(line)
        if m and "bloodhound" in line.lower():
            found_zip = m.group(1)
    code = proc.wait()
    if code != 0:
        raise RuntimeError(f"nxc exited with code {code}. Check the Scan log for details.")

    if not found_zip or not os.path.exists(found_zip):
        found_zip = _newest_zip()
    if not found_zip or not os.path.exists(found_zip):
        raise RuntimeError("Collection finished but no BloodHound zip was found. "
                           "Check nxc output path.")
    os.makedirs(bh_dir, exist_ok=True)
    dest = os.path.join(bh_dir, f"bloodhound_{int(time.time())}.zip")
    shutil.copy2(found_zip, dest)
    on_phase("phase", "Imported collection into project")
    return dest


def _newest_zip() -> str | None:
    """Fallback: newest *.zip under the usual nxc output locations."""
    candidates: List[str] = []
    roots = [os.getcwd(), os.path.expanduser("~/.nxc"), os.path.expanduser("~/.nxc/logs"),
             os.path.expanduser("~/.nxc/modules/bloodhound")]
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for f in files:
                if f.lower().endswith(".zip"):
                    candidates.append(os.path.join(dirpath, f))
    if not candidates:
        return None
    return max(candidates, key=lambda p: os.path.getmtime(p))
