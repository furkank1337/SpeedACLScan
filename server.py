"""Local web server (stdlib only) exposing the four tabs:

  config | scan | pwned | logs   (+ the report view)

Everything runs on 127.0.0.1. Long operations (nxc collection, AI analysis) run
on background threads; the UI polls a per-project job buffer for progress.
"""
from __future__ import annotations

import json
import os
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import ai, bloodhound, scan
from .opencode import OpenCodeClient, OpenCodeError
from .store import Store

WEB = os.path.join(os.path.dirname(__file__), "web")


class Jobs:
    """Per-project progress buffers for background scan/analyze/import runs."""
    def __init__(self):
        self._buf: dict[str, list] = {}
        self._running: dict[str, bool] = {}
        self._pct: dict[str, int] = {}
        self._kind: dict[str, str] = {}
        self._lock = threading.Lock()

    def start(self, project: str, kind: str = "job") -> bool:
        with self._lock:
            if self._running.get(project):
                return False
            self._running[project] = True
            self._buf[project] = []
            self._pct[project] = 0
            self._kind[project] = kind
            return True

    def push(self, project: str, level: str, msg: str, pct: int | None = None):
        with self._lock:
            if pct is not None:
                self._pct[project] = pct
            self._buf.setdefault(project, []).append(
                {"level": level, "msg": msg, "pct": self._pct.get(project, 0)})

    def finish(self, project: str, msg: str = "done"):
        self.push(project, "done", msg, 100)
        with self._lock:
            self._running[project] = False

    def snapshot(self, project: str):
        with self._lock:
            return {"running": self._running.get(project, False),
                    "pct": self._pct.get(project, 0),
                    "kind": self._kind.get(project, ""),
                    "events": list(self._buf.get(project, []))}


class GraphCache:
    """Caches an ingested graph per project, invalidated by bh/ mtime."""
    def __init__(self, store: Store):
        self.store = store
        self._cache: dict[str, tuple[float, bloodhound.Graph]] = {}
        self._lock = threading.Lock()

    def get(self, project: str):
        bh = self.store.bh_dir(project)
        if not os.path.isdir(bh):
            return None
        mtime = max([os.path.getmtime(bh)] +
                    [os.path.getmtime(os.path.join(bh, f)) for f in os.listdir(bh)] or [0])
        with self._lock:
            hit = self._cache.get(project)
            if hit and hit[0] == mtime:
                return hit[1]
        zips = sorted([os.path.join(bh, f) for f in os.listdir(bh) if f.endswith(".zip")])
        g = bloodhound.ingest_zip(zips[-1]) if zips else bloodhound.ingest_dir(bh)
        with self._lock:
            self._cache[project] = (mtime, g)
        return g

    def invalidate(self, project: str):
        with self._lock:
            self._cache.pop(project, None)


STORE = Store()
JOBS = Jobs()
GRAPHS = GraphCache(STORE)


class Handler(BaseHTTPRequestHandler):
    server_version = "speedaclscan"

    def log_message(self, *a):  # quiet
        pass

    # --- helpers -----------------------------------------------------------
    def _send(self, code, body=b"", ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_raw": raw}

    def _q(self):
        return {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}

    # --- routing -----------------------------------------------------------
    def do_GET(self):
        try:
            self._route_get()
        except Exception as e:
            self._send(500, {"error": str(e), "trace": traceback.format_exc()})

    def do_POST(self):
        try:
            self._route_post()
        except Exception as e:
            self._send(500, {"error": str(e), "trace": traceback.format_exc()})

    def _route_get(self):
        path = urlparse(self.path).path
        q = self._q()
        if path in ("/", "/index.html"):
            return self._static("index.html")
        if path.startswith("/web/"):
            return self._static(path[len("/web/"):])

        if path == "/api/projects":
            return self._send(200, STORE.list_projects())
        if path == "/api/config":
            return self._send(200, STORE.load_config())
        if path == "/api/pwned":
            return self._send(200, STORE.get_pwned(q["project"]))
        if path == "/api/custom_targets":
            return self._send(200, STORE.get_targets(q["project"]))
        if path == "/api/scope":
            return self._send(200, STORE.get_scope(q["project"]))
        if path == "/api/logs":
            return self._send(200, STORE.get_logs(q["project"]))
        if path == "/api/job":
            return self._send(200, JOBS.snapshot(q.get("project", "")))
        if path == "/api/search":
            return self._search(q)
        if path == "/api/report":
            return self._report(q)
        if path == "/api/analysis":
            return self._analysis_json(q)
        if path == "/api/targets":
            return self._targets(q)
        return self._send(404, {"error": "not found"})

    def _route_post(self):
        path = urlparse(self.path).path
        q = self._q()
        if path == "/api/projects":
            body = self._json_body()
            return self._send(200, STORE.create_project(body["name"]))
        if path == "/api/projects/delete":
            name = self._json_body().get("name", "")
            GRAPHS.invalidate(name)
            ok = STORE.delete_project(name)
            return self._send(200, {"ok": ok})
        if path == "/api/config":
            STORE.save_config(self._json_body())
            return self._send(200, {"ok": True})
        if path == "/api/config/test":
            return self._test_opencode()
        if path == "/api/pwned":
            body = self._json_body()
            STORE.set_pwned(body["project"], body.get("items", []))
            return self._send(200, {"ok": True, "count": len(STORE.get_pwned(body["project"]))})
        if path == "/api/custom_targets":
            body = self._json_body()
            STORE.set_targets(body["project"], body.get("items", []))
            return self._send(200, {"ok": True})
        if path == "/api/scope":
            body = self._json_body()
            STORE.set_scope(body["project"], body.get("scope", {}))
            return self._send(200, {"ok": True})
        if path == "/api/import":
            return self._import(q)
        if path == "/api/scan":
            return self._scan(self._json_body())
        if path == "/api/analyze":
            return self._analyze(self._json_body())
        return self._send(404, {"error": "not found"})

    # --- static ------------------------------------------------------------
    def _static(self, rel):
        rel = rel.lstrip("/").replace("..", "")
        fp = os.path.join(WEB, rel)
        if not os.path.isfile(fp):
            return self._send(404, b"not found", "text/plain")
        ctype = {"html": "text/html", "js": "application/javascript", "css": "text/css"}.get(
            rel.rsplit(".", 1)[-1], "application/octet-stream")
        with open(fp, "rb") as fh:
            self._send(200, fh.read(), ctype)

    # --- endpoints ---------------------------------------------------------
    def _test_opencode(self):
        cfg = STORE.load_config()["opencode"]
        client = OpenCodeClient(cfg["url"], cfg.get("model", ""), cfg.get("password", ""))
        try:
            client.ping()
            models = client.list_models()
            return self._send(200, {"ok": True, "models": models})
        except OpenCodeError as e:
            return self._send(200, {"ok": False, "error": str(e)})

    def _search(self, q):
        project, term = q.get("project", ""), q.get("q", "")
        g = GRAPHS.get(project)
        if g is None:
            return self._send(200, {"results": [], "note": "no data yet — run a scan or import"})
        res = [{"name": n.name, "type": n.ntype, "sid": n.sid, "enabled": n.enabled,
                "admincount": n.admincount} for n in g.search(term, limit=40)]
        return self._send(200, {"results": res, "total": len(g.nodes)})

    def _targets(self, q):
        g = GRAPHS.get(q.get("project", ""))
        if g is None:
            return self._send(200, {"targets": []})
        hv = bloodhound.high_value_targets(g)
        return self._send(200, {"targets": [g.nodes[s].name for s in hv if s in g.nodes]})

    def _report(self, q):
        project, fmt = q["project"], q.get("fmt", "html")
        rd = STORE.reports_dir(project)
        if fmt == "md":
            fp = os.path.join(rd, "report.md")
            if not os.path.isfile(fp):
                return self._send(404, {"error": "no report yet — run analysis"})
            with open(fp, "rb") as fh:
                return self._send(200, fh.read(), "text/markdown; charset=utf-8")
        # HTML: render fresh from the saved model so the page always uses the
        # current template (zoom/pan, scroll, theme) regardless of when it ran.
        aj = os.path.join(rd, "analysis.json")
        if os.path.isfile(aj):
            import json as _json
            from . import report as _report
            with open(aj, encoding="utf-8") as fh:
                model = _json.load(fh)
            return self._send(200, _report.render_html_from_dict(model), "text/html; charset=utf-8")
        fp = os.path.join(rd, "report.html")   # fallback: pre-model saved page
        if not os.path.isfile(fp):
            return self._send(404, {"error": "no report yet — run analysis"})
        with open(fp, "rb") as fh:
            self._send(200, fh.read(), "text/html; charset=utf-8")

    def _analysis_json(self, q):
        fp = os.path.join(STORE.reports_dir(q["project"]), "analysis.json")
        if not os.path.isfile(fp):
            return self._send(404, {"error": "no analysis yet"})
        with open(fp, "rb") as fh:
            self._send(200, fh.read())

    def _import(self, q):
        """Save the uploaded zip, then ingest it on a background job with progress."""
        project = q["project"]
        STORE.create_project(project)
        n = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(n)
        if not JOBS.start(project, "import"):
            return self._send(409, {"error": "a job is already running for this project"})
        dest = os.path.join(STORE.bh_dir(project), q.get("name", "import.zip"))
        with open(dest, "wb") as fh:
            fh.write(data)
        threading.Thread(target=self._import_worker, args=(project, len(data)), daemon=True).start()
        return self._send(200, {"ok": True, "started": True})

    def _import_worker(self, project, nbytes):
        try:
            JOBS.push(project, "phase", f"Received {nbytes} bytes; ingesting…", 60)
            GRAPHS.invalidate(project)
            g = GRAPHS.get(project)
            JOBS.push(project, "phase", f"Parsed {len(g.nodes)} objects, {len(g.edges)} relationships", 95)
            STORE.set_meta(project, status="collected")
            JOBS.finish(project, f"import complete: {len(g.nodes)} objects")
        except Exception as e:
            JOBS.push(project, "error", str(e))
            JOBS.finish(project, "failed")

    def _scan(self, body):
        project = body["project"]
        STORE.create_project(project)
        if not JOBS.start(project, "scan"):
            return self._send(409, {"error": "a job is already running for this project"})
        cfg = STORE.load_config()
        args = (project, cfg, body.get("dc_ip", ""), body.get("user", ""), body.get("password", ""),
                body.get("dc_fqdn", ""), body.get("domain", ""))
        threading.Thread(target=self._scan_worker, args=args, daemon=True).start()
        return self._send(200, {"ok": True, "started": True})

    # nxc collection has no clean % -- estimate from the phase it is printing.
    _SCAN_PCT = [
        ("via nxc", 5), ("Planning collection", 12), ("Collecting users", 25),
        ("Collecting groups", 42), ("Collecting computers", 62), ("Collecting trusts", 75),
        ("Compressing output", 85), ("Imported collection", 94), ("Ingested", 98),
    ]

    def _scan_worker(self, project, cfg, dc_ip, user, password, dc_fqdn="", domain=""):
        def phase(level, msg):
            pct = None
            for needle, p in self._SCAN_PCT:
                if needle.lower() in msg.lower():
                    pct = p
            JOBS.push(project, level, msg, pct)
            STORE.log(project, "status", msg, "scan:" + level)
        try:
            phase("phase", "Starting BloodHound collection via nxc")
            scan.run_collection(cfg, dc_ip, user, password, STORE.bh_dir(project), phase,
                                dc_fqdn=dc_fqdn, domain=domain)
            GRAPHS.invalidate(project)
            g = GRAPHS.get(project)
            phase("phase", f"Ingested {len(g.nodes)} objects, {len(g.edges)} relationships")
            STORE.set_meta(project, status="collected")
            JOBS.finish(project, "collection complete")
        except Exception as e:
            phase("error", str(e))
            JOBS.finish(project, "failed")

    def _analyze(self, body):
        project = body["project"]
        use_ai = bool(body.get("use_ai", True))
        if not JOBS.start(project, "analyze"):
            return self._send(409, {"error": "a job is already running for this project"})
        threading.Thread(target=self._analyze_worker, args=(project, use_ai), daemon=True).start()
        return self._send(200, {"ok": True, "started": True})

    def _analyze_worker(self, project, use_ai):
        try:
            res = ai.run_analysis(STORE, project, use_ai=use_ai,
                                  on_status=lambda s, pct=None: JOBS.push(project, "phase", s, pct))
            JOBS.push(project, "result", f"{res['paths']} path(s), {res['ai_paths']} AI-verified", 100)
            JOBS.finish(project, "analysis complete")
        except Exception as e:
            JOBS.push(project, "error", str(e))
            JOBS.finish(project, "failed")


def serve(host="127.0.0.1", port=8777):
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"speedaclscan -> http://{host}:{port}   (store: {STORE.base})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
