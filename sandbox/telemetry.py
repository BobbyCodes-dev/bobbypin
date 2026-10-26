"""Opt-in run telemetry.

Default OFF. When off, nothing here touches the network - not even a DNS lookup.
When on, it reports aggregate facts about a sandbox run to the operator's own
dashboard: which backend ran, how long it took, whether the target crashed, how
many honeypot artifacts were touched. Never the binary, never its bytes, never a
full path.

Identity: the host is identified by sha256(salt + /etc/machine-id)[:16], where the
salt is a random 32-byte value generated locally and never transmitted. So the id
is stable on this machine and useless anywhere else.

Failures never break a run: anything that cannot be delivered is spooled to
~/.bobbypin/telemetry-queue.jsonl (oldest dropped past the cap) and retried by
flush().
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional

SCHEMA_VERSION = 1
EVENT_NAME = "sandbox_run"


def _state_dir(config: Optional[dict]) -> str:
    raw = ((config or {}).get("state_dir") or "~/.bobbypin")
    env = os.environ.get("BOBBYPIN_STATE_DIR")
    if env:
        raw = env
    return os.path.abspath(os.path.expanduser(raw))


def _tool_version(repo_root: Optional[str] = None) -> str:
    """bobbypin's version, without importing it (import pulls in capstone)."""
    root = repo_root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [os.path.join(root, "bobbypin.py"), os.path.join(root, "bobbypin_ai.py")]
    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                head = fh.read(200_000)
        except OSError:
            continue
        match = re.search(r"^VERSION\s*=\s*[\"']([^\"']+)[\"']", head, re.MULTILINE)
        if match:
            return match.group(1)
    return "unknown"


class Telemetry:
    def __init__(self, config: Optional[dict] = None, config_path: Optional[str] = None,
                 repo_root: Optional[str] = None):
        self.config = config or {}
        self.tcfg = dict(self.config.get("telemetry") or {})
        self.config_path = config_path or self.config.get("_path")
        self.state_dir = _state_dir(self.config)
        self.repo_root = repo_root
        self._host_id: Optional[str] = None

    # -- state ------------------------------------------------------------
    @property
    def endpoint(self) -> str:
        return (self.tcfg.get("endpoint") or "").strip()

    @property
    def enabled(self) -> bool:
        return bool(self.tcfg.get("enabled")) and bool(self.endpoint)

    def _salt_path(self) -> str:
        return os.path.join(self.state_dir, "host_salt")

    def host_id(self) -> str:
        if self._host_id:
            return self._host_id
        try:
            os.makedirs(self.state_dir, exist_ok=True)
            if not os.path.exists(self._salt_path()):
                fd = os.open(self._salt_path(), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(secrets.token_bytes(32))
            with open(self._salt_path(), "rb") as fh:
                salt = fh.read()
        except OSError:
            salt = b"bobbypin-ephemeral"
        ident = b""
        for src in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                with open(src, "rb") as fh:
                    ident = fh.read().strip()
                if ident:
                    break
            except OSError:
                continue
        if not ident:
            ident = os.uname().nodename.encode()
        self._host_id = hashlib.sha256(salt + ident).hexdigest()[:16]
        return self._host_id

    def _queue_path(self) -> str:
        return os.path.join(self.state_dir, "telemetry-queue.jsonl")

    def _last_path(self) -> str:
        return os.path.join(self.state_dir, "telemetry-last.json")

    # -- event ------------------------------------------------------------
    @staticmethod
    def hash_path(path: str) -> str:
        return hashlib.sha256(("bobbypin-path:" + os.path.abspath(path)).encode()).hexdigest()[:16]

    def event_from(self, record, extra: Optional[dict] = None) -> dict:
        extra = extra or {}
        hp = extra.get("honeypots") or {}
        summary = (hp.get("summary") or {}) if isinstance(hp, dict) else {}
        kinds = sorted({h.get("kind") for h in (hp.get("hits") or []) if h.get("kind")}) if isinstance(hp, dict) else []
        target_path = getattr(record, "target", None)
        event = {
            "schema": SCHEMA_VERSION,
            "event": EVENT_NAME,
            "run_id": getattr(record, "run_id", None),
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tool": {"name": "bobbypin", "version": _tool_version(self.repo_root)},
            "backend": getattr(record, "backend", None),
            "host_id": self.host_id(),
            "target": {
                "basename": os.path.basename(target_path) if target_path else None,
                "sha256": getattr(record, "target_sha256", None),
                "size": getattr(record, "target_size", None),
                "kind": extra.get("kind"),
                "path_hashed": self.hash_path(target_path) if target_path else None,
            },
            "result": {
                "exit_code": getattr(record, "exit_code", None),
                "signal": getattr(record, "signal", None),
                "timed_out": bool(getattr(record, "timed_out", False)),
                "crashed": bool(getattr(record, "crashed", False)),
                "bsod_suspected": bool(getattr(record, "bsod_suspected", False)),
                "oom_killed": bool(getattr(record, "oom_killed", False)),
                "duration_s": getattr(record, "duration_s", None),
            },
            "honeypots": {
                "total": summary.get("total", 0),
                "modified": summary.get("modified", 0),
                "deleted": summary.get("deleted", 0),
                "leaked": summary.get("leaked", 0),
                "clean": summary.get("clean", True),
                "kinds": kinds,
            },
            "containment": getattr(record, "containment", {}) or {},
        }
        return event

    # -- transport --------------------------------------------------------
    def send(self, event: dict) -> dict:
        if not self.enabled:
            reason = "disabled" if not self.tcfg.get("enabled") else "no endpoint configured"
            return {"sent": False, "queued": False, "http": None, "status": reason, "url": None}
        payload = json.dumps(event).encode("utf-8")
        req = urllib.request.Request(self.endpoint, data=payload, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "bobbypin-telemetry/1"})
        try:
            with urllib.request.urlopen(req, timeout=float(self.tcfg.get("timeout_s", 10))) as resp:
                code = getattr(resp, "status", 200)
                body = resp.read(512).decode("utf-8", "replace")
            result = {"sent": True, "queued": False, "http": code, "status": "sent",
                      "url": self.endpoint, "body": body[:200]}
            self._write_last(result)
            return result
        except urllib.error.HTTPError as exc:
            result = {"sent": False, "queued": True, "http": exc.code,
                      "status": "http_error", "url": self.endpoint}
        except (urllib.error.URLError, OSError, ValueError) as exc:
            result = {"sent": False, "queued": True, "http": None,
                      "status": "network_error", "url": self.endpoint,
                      "detail": str(exc)[:200]}
        self._spool(event)
        self._write_last(result)
        return result

    def _spool(self, event: dict) -> None:
        try:
            os.makedirs(self.state_dir, exist_ok=True)
            lines = []
            if os.path.exists(self._queue_path()):
                with open(self._queue_path(), "r", encoding="utf-8") as fh:
                    lines = [ln for ln in fh.read().splitlines() if ln.strip()]
            lines.append(json.dumps(event))
            cap = int(self.tcfg.get("queue_max", 200) or 200)
            if len(lines) > cap:
                lines = lines[-cap:]
            with open(self._queue_path(), "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            os.chmod(self._queue_path(), 0o600)
        except OSError:
            pass

    def _write_last(self, result: dict) -> None:
        try:
            os.makedirs(self.state_dir, exist_ok=True)
            with open(self._last_path(), "w", encoding="utf-8") as fh:
                json.dump({"at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                           **result}, fh, indent=2)
            os.chmod(self._last_path(), 0o600)
        except OSError:
            pass

    def flush(self) -> dict:
        if not self.enabled:
            return {"flushed": 0, "remaining": self.queued(), "status": "disabled"}
        path = self._queue_path()
        if not os.path.exists(path):
            return {"flushed": 0, "remaining": 0, "status": "empty"}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                pending = [ln for ln in fh.read().splitlines() if ln.strip()]
        except OSError:
            return {"flushed": 0, "remaining": 0, "status": "unreadable"}
        flushed, keep = 0, []
        for line in pending:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            res = self.send(event)
            if res.get("sent"):
                flushed += 1
            else:
                keep.append(line)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(("\n".join(keep) + "\n") if keep else "")
        except OSError:
            pass
        return {"flushed": flushed, "remaining": len(keep), "status": "ok"}

    def queued(self) -> int:
        try:
            with open(self._queue_path(), "r", encoding="utf-8") as fh:
                return len([ln for ln in fh.read().splitlines() if ln.strip()])
        except OSError:
            return 0

    def status(self) -> dict:
        last = None
        try:
            with open(self._last_path(), "r", encoding="utf-8") as fh:
                last = json.load(fh)
        except (OSError, ValueError):
            last = None
        return {"enabled": self.enabled,
                "configured": bool(self.tcfg.get("enabled")),
                "endpoint": self.endpoint or None,
                "queued": self.queued(),
                "host_id": self.host_id(),
                "schema": SCHEMA_VERSION,
                "last": last}
