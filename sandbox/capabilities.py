"""Backend capability probing. Side-effect free, import-safe everywhere."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess

DOCKER_INSTALL = "apt-get install -y docker.io   # or: curl -fsSL https://get.docker.com | sh"
KVM_INSTALL = "sudo apt-get install -y qemu-system-x86 qemu-utils"


def _run(argv, timeout=15):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


_PROBE_CODE = """
import json, os, shutil
out = {}
out["docker_cli"] = bool(shutil.which("docker"))
out["server_version"] = None
try:
    import subprocess
    r = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                       capture_output=True, text=True, timeout=10)
    if r.returncode == 0 and r.stdout.strip():
        out["server_version"] = r.stdout.strip()
    else:
        out["error"] = (r.stderr or "").strip()[:300]
except Exception as exc:
    out["error"] = str(exc)[:300]
print(json.dumps(out))
"""


def docker_available() -> dict:
    """Is a working docker daemon reachable?"""
    if not shutil.which("docker"):
        return {"available": False, "reason": "docker CLI not found on PATH",
                "install": DOCKER_INSTALL,
                "detail": {"docker_cli": False, "server_version": None}}
    res = _run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=15)
    if res is None:
        return {"available": False, "reason": "docker version probe failed to execute",
                "install": DOCKER_INSTALL,
                "detail": {"docker_cli": True, "server_version": None}}
    if res.returncode != 0 or not res.stdout.strip():
        return {"available": False,
                "reason": "docker daemon unreachable: " + (res.stderr or res.stdout or "").strip()[:200],
                "install": "systemctl start docker   # and ensure $USER is in the docker group",
                "detail": {"docker_cli": True, "server_version": None}}
    version = res.stdout.strip()
    return {"available": True, "reason": "docker " + version, "install": None,
            "detail": {"docker_cli": True, "server_version": version}}


def kvm_available() -> dict:
    """Is a KVM/QEMU guest boundary buildable?"""
    detail = {}
    detail["qemu_binary"] = shutil.which("qemu-system-x86_64")
    detail["qemu_img"] = shutil.which("qemu-img")
    detail["kvm_device"] = os.path.exists("/dev/kvm")
    detail["kvm_readable"] = os.access("/dev/kvm", os.R_OK | os.W_OK) if detail["kvm_device"] else False
    missing = []
    if not detail["qemu_binary"]:
        missing.append("qemu-system-x86_64")
    if not detail["qemu_img"]:
        missing.append("qemu-img")
    if not detail["kvm_readable"]:
        missing.append("/dev/kvm (read/write)")
    if missing:
        return {"available": False,
                "reason": "missing prerequisite(s): " + ", ".join(missing),
                "install": KVM_INSTALL, "detail": detail}
    return {"available": True, "reason": "qemu + /dev/kvm ready", "install": None, "detail": detail}


def host_info() -> dict:
    info = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "machine": platform.machine(),
    }
    try:
        with open("/etc/machine-id", "r", encoding="utf-8") as fh:
            info["machine_id_present"] = bool(fh.read().strip())
    except OSError:
        info["machine_id_present"] = False
    return info


def probe() -> dict:
    """Full capability report + a recommended backend."""
    docker = docker_available()
    kvm = kvm_available()
    notes = []
    if kvm["available"] and docker["available"]:
        recommended = "kvm"
        notes.append("kvm available: strongest isolation (separate kernel) - preferred")
    elif docker["available"]:
        recommended = "docker"
        notes.append("kvm unavailable: falling back to hardened-container isolation "
                     "(shared kernel - a kernel-level exploit is not contained)")
    elif kvm["available"]:
        recommended = "kvm"
    else:
        recommended = None
        notes.append("no isolation backend available - sandboxed runs are refused, "
                     "nothing will be executed on the host")
    if not kvm["available"]:
        notes.append("enable kvm isolation with: " + (kvm.get("install") or "install qemu"))
    return {"backends": {"docker": docker, "kvm": kvm},
            "recommended": recommended,
            "host": host_info(),
            "notes": notes}


def main(argv=None):
    print(json.dumps(probe(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
