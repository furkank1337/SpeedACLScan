"""Minimal OpenCode v2 client (stdlib only), mirroring the Cloak/Burp client.

Burp is the orchestrator: create a session (pinned to a model), POST a prompt,
then poll the message list for the assistant reply. HTTP basic auth
(opencode:<password>). These calls go directly to `opencode serve`, not through
any proxy.
"""
from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional


class OpenCodeError(RuntimeError):
    pass


class OpenCodeClient:
    REPLY_TIMEOUT = 300
    POLL = 0.8

    def __init__(self, url: str, model: str = "", password: str = ""):
        self.url = url.rstrip("/")
        self.model = model
        self.password = password

    # --- public ------------------------------------------------------------
    def ping(self) -> dict:
        return self._get("/api/info")

    def list_models(self) -> List[str]:
        data = self._unwrap(self._get("/api/model"))
        out: set[str] = set()
        self._collect_models(data, out)
        return sorted(out)

    def create_session(self, title: str) -> str:
        body: dict = {"title": title}
        if "/" in self.model:
            prov, mid = self.model.split("/", 1)
            if prov and mid:
                body["model"] = {"providerID": prov, "id": mid}
        data = self._unwrap(self._post("/api/session", body))
        sid = self._find_str(data, "id")
        if not sid:
            raise OpenCodeError("OpenCode session response had no id.")
        return sid

    def send_message(self, session_id: str, system_text: Optional[str], user_text: str) -> str:
        text = user_text if not system_text else system_text + "\n\n----- TASK -----\n\n" + user_text
        before = self._assistant_ids(session_id)
        self._post(f"/api/session/{urllib.parse.quote(session_id)}/prompt", {"text": text})
        deadline = time.time() + self.REPLY_TIMEOUT
        while time.time() < deadline:
            reply = self._new_completed(session_id, before)
            if reply is not None:
                out = self._collect_text(reply).strip()
                if not out:
                    raise OpenCodeError("OpenCode returned an empty reply.")
                return out
            time.sleep(self.POLL)
        raise OpenCodeError("Timed out waiting for the OpenCode reply.")

    # --- polling -----------------------------------------------------------
    def _messages(self, session_id: str) -> list:
        data = self._unwrap(self._get(f"/api/session/{urllib.parse.quote(session_id)}/message"))
        return data if isinstance(data, list) else []

    def _assistant_ids(self, session_id: str) -> set:
        ids = set()
        for m in self._messages(session_id):
            if isinstance(m, dict) and m.get("type") == "assistant" and m.get("id"):
                ids.add(str(m["id"]))
        return ids

    def _new_completed(self, session_id: str, exclude: set):
        latest = None
        for m in self._messages(session_id):
            if not isinstance(m, dict) or m.get("type") != "assistant":
                continue
            mid = m.get("id")
            if mid and str(mid) not in exclude and self._completed(m):
                latest = m
        return latest

    @staticmethod
    def _completed(m: dict) -> bool:
        if m.get("finish") is not None:
            return True
        t = m.get("time")
        return isinstance(t, dict) and t.get("completed") is not None

    # --- http --------------------------------------------------------------
    def _get(self, path: str):
        return self._send(urllib.request.Request(self.url + path, method="GET",
                                                  headers=self._headers()))

    def _post(self, path: str, body: dict):
        data = json.dumps(body).encode("utf-8")
        return self._send(urllib.request.Request(self.url + path, data=data, method="POST",
                                                  headers=self._headers(True)))

    def _headers(self, post: bool = False) -> dict:
        h = {"Accept": "application/json"}
        if post:
            h["Content-Type"] = "application/json"
        if self.password:
            tok = base64.b64encode(("opencode:" + self.password).encode()).decode()
            h["Authorization"] = "Basic " + tok
        return h

    def _send(self, req: urllib.request.Request):
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise OpenCodeError("OpenCode rejected the credentials (401). Check the server password.")
            raise OpenCodeError(f"OpenCode returned HTTP {e.code} for {req.selector}. "
                                f"Is this an OpenCode v2 URL (not a proxy)?")
        except urllib.error.URLError as e:
            raise OpenCodeError(f"Cannot reach OpenCode at {self.url} ({e.reason}). "
                                f"Is 'opencode serve' running and the URL correct?")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise OpenCodeError("OpenCode returned an unreadable response.")

    # --- json helpers ------------------------------------------------------
    @staticmethod
    def _unwrap(parsed):
        if isinstance(parsed, dict) and "data" in parsed:
            return parsed["data"]
        return parsed

    @classmethod
    def _collect_models(cls, node, out: set):
        if isinstance(node, dict):
            p, m = node.get("providerID"), node.get("modelID")
            if isinstance(p, str) and isinstance(m, str) and p and m:
                out.add(p + "/" + m)
            for v in node.values():
                if isinstance(v, (dict, list)):
                    cls._collect_models(v, out)
        elif isinstance(node, list):
            for v in node:
                cls._collect_models(v, out)

    @classmethod
    def _find_str(cls, node, key) -> Optional[str]:
        if isinstance(node, dict):
            if isinstance(node.get(key), str):
                return node[key]
            for v in node.values():
                r = cls._find_str(v, key)
                if r:
                    return r
        elif isinstance(node, list):
            for v in node:
                r = cls._find_str(v, key)
                if r:
                    return r
        return None

    @classmethod
    def _collect_text(cls, node) -> str:
        parts: List[str] = []
        cls._walk_text(node, parts)
        return "\n".join(parts)

    @classmethod
    def _walk_text(cls, node, parts: List[str]):
        if isinstance(node, dict):
            if node.get("type") == "text" and isinstance(node.get("text"), str):
                parts.append(node["text"])
            for v in node.values():
                if isinstance(v, (dict, list)):
                    cls._walk_text(v, parts)
        elif isinstance(node, list):
            for v in node:
                cls._walk_text(v, parts)
