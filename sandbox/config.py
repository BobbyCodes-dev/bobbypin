"""Sandbox configuration: ~/.bobbypin/sandbox.json (0600)."""

from __future__ import annotations

import copy
import json
import os
import tempfile
from typing import Any, Optional

DEFAULTS: dict = {
    "backend": "auto",
    "image": "bobbypin/sandbox:latest",
    "timeout_s": 300,
    "memory": "2g",
    "memory_mb": 2048,
    "cpus": 2.0,
    "telemetry": {"enabled": False, "endpoint": "", "timeout_s": 10, "queue_max": 200},
    "honeypots": {"enabled": True, "profile": "windows"},
    "kvm": {"base_image": "", "memory_mb": 4096, "cpus": 2, "no_egress": True, "no_reboot": True},
    "state_dir": "~/.bobbypin",
}


def state_dir() -> str:
    raw = os.environ.get("BOBBYPIN_STATE_DIR") or DEFAULTS["state_dir"]
    return os.path.abspath(os.path.expanduser(raw))


def config_path(path: Optional[str] = None) -> str:
    if path:
        return os.path.abspath(os.path.expanduser(path))
    env = os.environ.get("BOBBYPIN_SANDBOX_CONFIG")
    if env:
        return os.path.abspath(os.path.expanduser(env))
    return os.path.join(state_dir(), "sandbox.json")


def _deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def load_config(path: Optional[str] = None) -> dict:
    """DEFAULTS deep-merged with whatever is on disk. Never raises."""
    p = config_path(path)
    disk: dict = {}
    try:
        with open(p, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        if isinstance(loaded, dict):
            disk = loaded
    except (OSError, ValueError):
        disk = {}
    cfg = _deep_merge(DEFAULTS, disk)
    cfg["_path"] = p
    return cfg


def save_config(cfg: dict, path: Optional[str] = None) -> str:
    p = config_path(path or cfg.get("_path"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    payload = {k: v for k, v in cfg.items() if not k.startswith("_")}
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(p), prefix=".sandbox-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return p


def set_value(dotted_key: str, value: Any, path: Optional[str] = None) -> dict:
    """set_value("telemetry.enabled", True) -> persisted config."""
    cfg = load_config(path)
    parts = [p for p in dotted_key.split(".") if p]
    if not parts:
        raise ValueError("empty key")
    node = cfg
    for part in parts[:-1]:
        nxt = node.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            node[part] = nxt
        node = nxt
    node[parts[-1]] = value
    cfg["_path"] = config_path(path or cfg.get("_path"))
    save_config(cfg)
    return load_config(cfg["_path"])


def get_value(cfg: dict, dotted_key: str, default: Any = None) -> Any:
    node: Any = cfg
    for part in dotted_key.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node
