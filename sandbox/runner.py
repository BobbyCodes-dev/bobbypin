"""Orchestrator: probe -> plant honeypots -> run in a boundary -> audit -> report.

One call does the whole safe-run sequence and always returns a dict. A target
that crashes does not raise - it comes back as ``crashed: true`` in the record.
Only an unusable *boundary* fails the call, and then it fails with an
``install`` hint rather than quietly running the target on the host.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Optional

from . import capabilities
from .base import RunRequest, SandboxError, SandboxUnavailable
from .backends import get_backend
from .config import load_config, state_dir
from .honeypots import HoneypotSet, merge_guest_audit
from .telemetry import Telemetry

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def preflight(config: Optional[dict] = None) -> dict:
    """What isolation is available on this host, and what it would take to get more."""
    cfg = config or load_config()
    rep = capabilities.probe()
    tel = Telemetry(cfg)
    return {
        "ok": bool(rep["recommended"]),
        "recommended": rep["recommended"],
        "backends": rep["backends"],
        "notes": rep["notes"],
        "host": rep["host"],
        "config_path": cfg.get("_path"),
        "configured_backend": cfg.get("backend"),
        "image": cfg.get("image"),
        "honeypots": cfg.get("honeypots"),
        "telemetry": tel.status(),
    }


def _default_workdir(cfg: dict, target: Optional[str]) -> str:
    label = "probe"
    if target:
        label = os.path.splitext(os.path.basename(target))[0] or "target"
    label = _SAFE.sub("_", label)[:40].strip("_") or "run"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return os.path.join(state_dir(), "runs", f"{stamp}-{label}")


def run_sandbox(target: Optional[str] = None, backend: str = "auto",
                workdir: Optional[str] = None, argv: Optional[list] = None,
                timeout_s: Optional[int] = None, honeypots: bool = True,
                config: Optional[dict] = None, scan_roots: Optional[list] = None,
                kind: Optional[str] = None, helpers: Optional[list] = None,
                trip_debug: bool = False, trip_helper: Optional[str] = None) -> dict:
    """Run one target (or a containment probe) inside an isolation boundary."""
    cfg = config or load_config()
    cfg = dict(cfg)
    backend_name = backend if backend and backend != "auto" else cfg.get("backend", "auto")
    workdir = os.path.abspath(os.path.expanduser(workdir or _default_workdir(cfg, target)))
    os.makedirs(os.path.join(workdir, "out"), exist_ok=True)

    hp_cfg = cfg.get("honeypots") or {}
    deploy_honeypots = bool(honeypots and hp_cfg.get("enabled", True))
    hp_root = os.path.join(workdir, "honeypots")

    result = {"ok": False, "backend": backend_name, "workdir": workdir,
              "record": None, "honeypots": None, "telemetry": None,
              "error": None, "install": None, "capabilities": None}

    try:
        chosen = get_backend(backend_name, cfg)
    except SandboxUnavailable as exc:
        result["error"] = str(exc)
        result["install"] = exc.install
        result["capabilities"] = capabilities.probe()
        return result
    except SandboxError as exc:
        result["error"] = str(exc)
        return result

    result["backend"] = chosen.name

    if deploy_honeypots:
        try:
            HoneypotSet.deploy(hp_root, hp_cfg.get("profile", "windows"))
        except (OSError, ValueError) as exc:
            result["error"] = f"could not plant honeypots: {exc}"
            deploy_honeypots = False

    req = RunRequest(
        target=os.path.abspath(os.path.expanduser(target)) if target else None,
        workdir=workdir,
        argv=argv,
        timeout_s=int(timeout_s or cfg.get("timeout_s", 300)),
        memory=str(cfg.get("memory", "2g")),
        memory_mb=int((cfg.get("kvm") or {}).get("memory_mb") or cfg.get("memory_mb") or 2048),
        cpus=float(cfg.get("cpus", 2.0)),
        honeypot_root=hp_root if deploy_honeypots else None,
        helpers=list(helpers or []),
        trip_debug=bool(trip_debug),
        trip_helper=trip_helper,
        image=cfg.get("image"),
        no_egress=True,
    )

    try:
        record = chosen.run(req)
    except SandboxUnavailable as exc:
        result["error"] = str(exc)
        result["install"] = exc.install
        return result
    except SandboxError as exc:
        result["error"] = str(exc)
        return result

    audit = None
    if deploy_honeypots and os.path.exists(os.path.join(hp_root, "_honeypot_manifest.json")):
        try:
            hs = HoneypotSet.load(hp_root)
            audit = hs.audit(scan_roots or [workdir],
                             exclude=[record.guest_audit_dir] if record.guest_audit_dir else None)
            if getattr(record, "guest_audit", None):
                # VM: the bait lived on the guest's throwaway disk, so the guest's
                # own account of what happened is the one that counts.
                audit = merge_guest_audit(audit, hs.artifacts, record.guest_audit)
        except (OSError, ValueError) as exc:
            record.warnings.append(f"honeypot audit failed: {exc}")

    tel = Telemetry(cfg)
    send_result = tel.send(tel.event_from(record, {"honeypots": audit, "kind": kind}))

    result.update({
        "ok": True,
        "record": record.to_dict(),
        "honeypots": audit,
        "telemetry": send_result,
        "capabilities": {"recommended": capabilities.probe()["recommended"]},
    })
    if audit and not audit["summary"]["clean"]:
        result["honeypot_hits"] = audit["hits"]
    return result


def main(argv=None):
    import json
    import sys
    args = list(argv if argv is not None else sys.argv[1:])
    if not args or args[0] in {"-h", "--help", "preflight"}:
        print(json.dumps(preflight(), indent=2))
        return 0
    target = args[0] if args[0] not in {"probe", "-"} else None
    payload = run_sandbox(target=target)
    print(json.dumps(payload, indent=2))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
