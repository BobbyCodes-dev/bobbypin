#!/usr/bin/env python3
"""bobbypin one-command setup.

Installs what bobbypin needs and provisions the isolation backend, so you do not
have to assemble the pieces by hand:

    python3 setup.py                 # detect, install, provision, verify
    python3 setup.py --check         # report only, change nothing
    python3 setup.py --yes           # never prompt (CI / unattended)
    python3 setup.py --no-vm         # skip the guest image (docker backend only)
    python3 setup.py --with-frida    # also install frida-tools for live monitors
    python3 setup.py --install-system-packages
                                     # run the apt commands for missing system deps

What it does, in order:

  1. checks the Python version
  2. installs `capstone` (needed for verified patch candidates) - into a repo-local
     `.venv` when the system interpreter refuses pip installs (PEP 668)
  3. reports missing system packages (docker, qemu, genisoimage) with the exact
     command for your distro
  4. builds the container analysis image `bobbypin/sandbox:latest` if docker is up
  5. provisions the KVM guest (downloads a Debian cloud image, ~330 MB, and runs a
     one-time unattended install) - this is the strongest isolation boundary
  6. writes `~/.bobbypin/sandbox.json` and points `kvm.base_image` at the guest
  7. runs a containment probe so you know the boundary actually works

Nothing here touches the network except the package installs, the docker build and
the guest image download. Re-running it is safe: every step is skipped when it is
already satisfied.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.path.join(REPO, ".venv")
DOCKER_IMAGE = "bobbypin/sandbox:latest"
DEFAULT_VM_DIR = os.path.join(os.path.expanduser("~"), "bobbypin-vm")

# ANSI only when a human is watching
_TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


def step(msg: str) -> None:
    print("\n" + _c("1;36", "==> ") + _c("1", msg))


def ok(msg: str) -> None:
    print("    " + _c("32", "ok") + "   " + msg)


def warn(msg: str) -> None:
    print("    " + _c("33", "warn") + " " + msg)


def bad(msg: str) -> None:
    print("    " + _c("31", "fail") + " " + msg)


def info(msg: str) -> None:
    print("          " + msg)


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def in_virtualenv() -> bool:
    """True when the running interpreter is a venv - `pip --user` is illegal there."""
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)


def run(argv, timeout=600, capture=True):
    """Run a command. Returns (returncode, combined output)."""
    try:
        p = subprocess.run(
            argv,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
            text=True,
            timeout=timeout,
        )
        return p.returncode, (p.stdout or "") if capture else ""
    except FileNotFoundError:
        return 127, f"{argv[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"


def ask(question: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    try:
        reply = input(f"    {question} [Y/n] ").strip().lower()
    except EOFError:
        return False
    return reply in ("", "y", "yes")


# --------------------------------------------------------------------------- #
# 1. Python
# --------------------------------------------------------------------------- #

def check_python() -> bool:
    step("Python")
    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 7):
        bad(f"Python {major}.{minor} - bobbypin needs 3.7 or newer")
        return False
    ok(f"Python {major}.{minor}.{sys.version_info[2]} at {sys.executable}")
    if (major, minor) < (3, 9):
        warn("3.9+ recommended; older interpreters are fine for the core but slow on large scans")
    return True


# --------------------------------------------------------------------------- #
# 2. capstone (+ optional frida)
# --------------------------------------------------------------------------- #

def capstone_importable(python: str) -> bool:
    code, _ = run([python, "-c", "import capstone"], timeout=30)
    return code == 0


def pip_install(python: str, packages, user: bool, break_system: bool):
    argv = [python, "-m", "pip", "install", "--disable-pip-version-check", "--quiet"]
    if user:
        argv.append("--user")
    if break_system:
        argv.append("--break-system-packages")
    argv.extend(packages)
    return run(argv, timeout=900)


def ensure_capstone(args, want_frida: bool):
    """Return the interpreter that can import capstone, or None."""
    step("Python packages")

    if capstone_importable(sys.executable):
        ok(f"capstone already available in {sys.executable}")
        if want_frida:
            code, _ = run([sys.executable, "-c", "import frida"], timeout=30)
            if code != 0:
                info("frida-tools not installed (only needed for live monitors)")
        return sys.executable

    if args.check:
        bad("capstone not importable - run `python3 setup.py` to install it")
        return None

    packages = ["capstone"] + (["frida-tools"] if want_frida else [])
    info("installing " + ", ".join(packages) + " ...")
    code, out = pip_install(sys.executable, packages, user=not in_virtualenv(),
                             break_system=False)

    if code != 0 and "externally-managed-environment" in out:
        # PEP 668: the distro python refuses installs. Own virtualenv instead of
        # fighting the system package manager.
        info("system interpreter is externally managed (PEP 668) - using a repo-local venv")
        venv_python = os.path.join(VENV_DIR, "bin", "python")
        if not os.path.exists(venv_python):
            code, out = run([sys.executable, "-m", "venv", VENV_DIR], timeout=300)
            if code != 0:
                bad("could not create " + VENV_DIR)
                info(out.strip().splitlines()[-1] if out.strip() else "no output")
                return None
        code, out = pip_install(venv_python, packages, user=False, break_system=False)
        if code == 0 and capstone_importable(venv_python):
            ok("installed into " + VENV_DIR)
            info("run bobbypin with: " + os.path.join(VENV_DIR, "bin", "python"))
            return venv_python
        bad("capstone install failed in the venv")
        info((out.strip().splitlines() or ["no output"])[-1])
        return None

    if code != 0:
        bad("capstone install failed")
        info((out.strip().splitlines() or ["no output"])[-1])
        return None

    if capstone_importable(sys.executable):
        ok("capstone installed")
        return sys.executable

    bad("capstone installed but still not importable")
    return None


# --------------------------------------------------------------------------- #
# 3. system packages
# --------------------------------------------------------------------------- #

APT_DEPS = {
    "qemu-system-x86_64": "qemu-system-x86",
    "qemu-img": "qemu-utils",
    "genisoimage": "genisoimage",
}

SUDO_APT = "sudo apt-get update && sudo apt-get install -y qemu-system-x86 qemu-utils genisoimage"


def check_system(args) -> dict:
    step("System packages")
    state = {"docker": have("docker"), "kvm_tools": True, "kvm_device": os.path.exists("/dev/kvm")}

    missing = [pkg for binary, pkg in APT_DEPS.items() if not have(binary)]
    if missing:
        state["kvm_tools"] = False
        bad("missing: " + ", ".join(missing))
        info("install with: " + SUDO_APT)
        if args.install_system_packages and not args.check:
            info("running it for you (sudo may prompt) ...")
            code, out = run(
                ["sudo", "apt-get", "install", "-y", *sorted(set(missing))],
                timeout=1800, capture=False,
            )
            if code == 0:
                ok("system packages installed")
                state["kvm_tools"] = all(have(b) for b in APT_DEPS)
    else:
        ok("qemu, qemu-img and genisoimage present")

    if not state["kvm_device"]:
        warn("/dev/kvm is missing - hardware virtualisation is off in firmware, or "
             "the kvm module is not loaded (try: sudo modprobe kvm_intel)")
    else:
        ok("/dev/kvm present")

    if state["docker"]:
        code, out = run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=30)
        if code == 0:
            ok("docker " + out.strip())
        else:
            state["docker"] = False
            bad("docker CLI present but the daemon is not reachable")
            info("start it with: sudo systemctl enable --now docker")
    else:
        warn("docker not installed - the container backend will be unavailable")
        info("install with: curl -fsSL https://get.docker.com | sh")

    return state


# --------------------------------------------------------------------------- #
# 4. container image
# --------------------------------------------------------------------------- #

def docker_image_present() -> bool:
    if not have("docker"):
        return False
    code, _ = run(["docker", "image", "inspect", DOCKER_IMAGE], timeout=30)
    return code == 0


def build_docker_image(args, system) -> bool:
    step("Container analysis image")
    if docker_image_present():
        ok(f"{DOCKER_IMAGE} already built")
        return True
    if not system.get("docker"):
        warn("skipped - docker is not available")
        return False
    if args.no_docker:
        warn("skipped (--no-docker)")
        return False
    if args.check:
        bad(f"{DOCKER_IMAGE} not built yet")
        info("build with: docker build -f sandbox/docker/Dockerfile.sandbox -t " + DOCKER_IMAGE + " .")
        return False
    if not ask(f"Build {DOCKER_IMAGE}? (pulls a Debian base, a few minutes)", args.yes):
        warn("skipped")
        return False

    info("building ...")
    code, out = run(
        ["docker", "build", "-f", os.path.join("sandbox", "docker", "Dockerfile.sandbox"),
         "-t", DOCKER_IMAGE, "."],
        timeout=3600,
    )
    if code == 0 and docker_image_present():
        ok(f"{DOCKER_IMAGE} built")
        return True
    bad("docker build failed")
    info((out.strip().splitlines() or ["no output"])[-1])
    return False


# --------------------------------------------------------------------------- #
# 5. KVM guest
# --------------------------------------------------------------------------- #

def configure_guest(vm_dir: str) -> None:
    """Point kvm.base_image at the provisioned guest. Uses the tool's own config layer.

    An existing, working base_image is never overwritten - a Windows guest or a
    hand-built image already in use would otherwise be silently swapped for the
    Debian one this script provisions.
    """
    sys.path.insert(0, REPO)
    try:
        from sandbox.config import set_value, get_value, load_config, config_path  # noqa: WPS433
    except Exception as exc:  # pragma: no cover - config layer is in-repo
        warn(f"could not import sandbox.config ({exc}); set kvm.base_image by hand")
        return

    cfg = load_config()
    current = get_value(cfg, "kvm.base_image", "") or ""
    base = os.path.join(vm_dir, "base.qcow2")

    if current and os.path.isfile(os.path.expanduser(current)):
        if os.path.abspath(os.path.expanduser(current)) == os.path.abspath(base):
            ok(f"kvm.base_image -> {base} (already configured)")
        else:
            ok(f"kvm.base_image left as configured -> {current}")
            info(f"this script provisioned {base}; point the backend at it by hand if that")
            info("is the guest you want: python3 -c \"from sandbox.config import "
                 "set_value; set_value('kvm.base_image', '" + base + "')\"")
        return

    set_value("kvm.base_image", base)
    set_value("backend", "auto")
    ok(f"kvm.base_image -> {base}")
    info("config: " + config_path())


def provision_guest(args, system) -> bool:
    step("KVM guest (strongest isolation)")
    vm_dir = os.path.abspath(os.path.expanduser(args.vm_dir))
    base = os.path.join(vm_dir, "base.qcow2")

    if os.path.isfile(base):
        size = os.path.getsize(base) / (1024 ** 3)
        ok(f"guest already provisioned: {base} ({size:.1f} GiB on disk)")
        if not args.check:
            configure_guest(vm_dir)
        return True

    if args.no_vm:
        warn("skipped (--no-vm)")
        return False
    if not system.get("kvm_tools") or not system.get("kvm_device"):
        warn("skipped - qemu, genisoimage and /dev/kvm are required")
        info("the docker backend still works; re-run setup after installing them")
        return False
    if args.check:
        bad("guest not provisioned")
        info(f"provision with: ./sandbox/kvm/provision-guest.sh {vm_dir}")
        return False

    script = os.path.join(REPO, "sandbox", "kvm", "provision-guest.sh")
    if not os.path.isfile(script):
        bad("sandbox/kvm/provision-guest.sh is missing")
        return False
    if not ask("Download the Debian cloud image (~330 MB) and build the guest? "
               "It boots once and installs wine; about 5 minutes", args.yes):
        warn("skipped")
        return False

    free_gb = shutil.disk_usage(os.path.dirname(vm_dir) or ".").free / (1024 ** 3)
    if free_gb < 8:
        bad(f"only {free_gb:.1f} GiB free - the guest needs ~5 GiB")
        return False

    info("provisioning (this boots a VM once, unattended) ...")
    code, out = run(["/bin/bash", script, vm_dir], timeout=3600)
    if code != 0 or not os.path.isfile(base):
        bad("provisioning failed")
        for line in out.strip().splitlines()[-5:]:
            info(line)
        info(f"log: {os.path.join(vm_dir, 'provision.log')}")
        return False

    ok("guest built: " + base)
    configure_guest(vm_dir)
    return True


# --------------------------------------------------------------------------- #
# 6. verify
# --------------------------------------------------------------------------- #

def verify(args, python: str) -> bool:
    step("Verification")
    if not python:
        bad("no interpreter with capstone - skipping the probe")
        return False
    if args.check:
        info("(report-only mode, no probe run)")
        return True

    code, out = run([python, os.path.join(REPO, "bobbypin_ai.py"), "sandbox_preflight"], timeout=120)
    try:
        data = json.loads(out)["data"]
    except Exception:
        bad("sandbox_preflight did not return JSON")
        info((out.strip().splitlines() or ["no output"])[-1])
        return False

    for name, backend in (data.get("backends") or {}).items():
        if backend.get("available"):
            ok(f"backend {name}: {backend.get('reason')}")
        else:
            warn(f"backend {name}: {backend.get('reason')}")

    backend = "docker" if data.get("backends", {}).get("docker", {}).get("available") else "auto"
    info(f"running a containment probe on the {backend} backend ...")
    code, out = run(
        [python, os.path.join(REPO, "bobbypin_ai.py"), "sandbox_run",
         json.dumps({"backend": backend})],
        timeout=600,
    )
    try:
        verdict = json.loads(out)["data"]
    except Exception:
        bad("the containment probe did not return JSON")
        info((out.strip().splitlines() or ["no output"])[-1])
        return False

    if not (verdict.get("run_id") or verdict.get("backend")):
        bad("containment probe failed: " + str(verdict.get("error") or verdict))
        return False

    box = verdict.get("containment") or {}
    ok(f"containment probe ran on {verdict.get('backend')} "
       f"in {verdict.get('duration_s')}s, exit={verdict.get('exit_code')}")
    info("network=" + str(box.get("network")) + " (verified: "
         + str(box.get("network_verified")) + "), rootfs=" + str(box.get("rootfs"))
         + " (verified: " + str(box.get("rootfs_verified")) + ")")
    info("uid=" + str(box.get("uid")) + ", cap_drop=" + str(box.get("cap_drop"))
         + ", no_new_privileges=" + str(box.get("no_new_privileges")))
    if not (box.get("network_verified") and box.get("rootfs_verified")):
        bad("the boundary did not verify: see containment above")
        return False
    return True


# --------------------------------------------------------------------------- #

def banner() -> None:
    print(_c("1", "\nbobbypin setup"))
    print("  reverse-engineering suite for Windows binaries and Electron apps")
    print("  this installer prepares the analysis toolchain and the isolation backend\n")


def summary(python, system, docker_ok, guest_ok) -> None:
    step("Summary")
    info(f"interpreter   : {python or 'MISSING (capstone)'}")
    info(f"docker image  : {'ready' if docker_ok else 'not built'}")
    info(f"kvm guest     : {'ready' if guest_ok else 'not provisioned'}")
    if not python:
        info("")
        info("Next: install capstone, then re-run this script.")
    elif not (docker_ok or guest_ok):
        info("")
        info("Next: no isolation backend is ready. Static analysis (triage, strings,")
        info("      candidates, disasm, patch) works now; sandbox_run needs docker or KVM.")
    else:
        info("")
        info("Next:")
        info("  python3 bobbypin_gui.py          # browser GUI on 127.0.0.1:8877")
        info("  python3 bobbypin.py target.exe   # CLI triage")
        info("  python3 bobbypin_ai.py plan target.exe   # JSON for agents")
    print()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Install bobbypin's prerequisites and provision its isolation backend.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--check", action="store_true", help="report what is missing, change nothing")
    ap.add_argument("--yes", "-y", action="store_true", help="never prompt")
    ap.add_argument("--no-vm", action="store_true", help="skip the KVM guest build")
    ap.add_argument("--no-docker", action="store_true", help="skip the container image build")
    ap.add_argument("--with-frida", action="store_true", help="also install frida-tools")
    ap.add_argument("--install-system-packages", action="store_true",
                    help="run the apt commands for missing system packages")
    ap.add_argument("--vm-dir", default=DEFAULT_VM_DIR, help="where the guest image lives")
    args = ap.parse_args(argv)

    banner()
    if not check_python():
        return 2

    python = ensure_capstone(args, args.with_frida)
    system = check_system(args)
    docker_ok = build_docker_image(args, system)
    guest_ok = provision_guest(args, system)
    verified = verify(args, python)
    summary(python, system, docker_ok, guest_ok)

    healthy = bool(python) and (docker_ok or guest_ok)
    if args.check:
        return 0 if healthy else 1
    return 0 if (healthy and verified) else 1


if __name__ == "__main__":
    sys.exit(main())
