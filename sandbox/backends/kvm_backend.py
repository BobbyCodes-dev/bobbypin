"""KVM/QEMU isolation backend - a real virtual machine boundary.

Why this exists: a container shares the host kernel, so a shared-kernel boundary
is only good enough for crashing applications. A target that bugchecks Windows -
or that a driver in the target's installer takes down on boot - needs a real
guest kernel of its own. That is what this backend provides:

  * separate guest kernel   - a guest bugcheck/panic cannot touch the host
  * ephemeral disk, always  - a qcow2 overlay on the base image (plus -snapshot
                              as belt-and-braces); every write is discarded, so
                              an infection or a corrupted boot volume does not
                              survive the run
  * -no-reboot              - a bugcheck halts the VM instead of restarting into
                              an endless crash loop
  * no egress               - user-mode networking with restrict=on and no port
                              forwards: the guest cannot reach the host or the
                              internet
  * captured console        - serial + QEMU stderr are scanned by sandbox.bsod so
                              a guest crash is reported, not silently hung

Requires qemu-system-x86_64, qemu-img and a guest image. Nothing is installed
automatically and the host is never used as a fallback.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from datetime import datetime, timezone

from ..base import RunRecord, RunRequest, SandboxBackend, SandboxUnavailable, new_run_id
from .. import bsod as bsod_mod
from .. import capabilities
from ..honeypots import MANIFEST_NAME, HoneypotArtifact

QEMU_BIN = "qemu-system-x86_64"
QEMU_IMG = "qemu-img"
GUEST_INSTALL_HINT = capabilities.KVM_INSTALL


class KVMBackend(SandboxBackend):
    name = "kvm"

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        kvm_cfg = self.config.get("kvm") or {}
        self.base_image = (kvm_cfg.get("base_image") or os.environ.get("BOBBYPIN_KVM_BASE") or "")
        self.memory_mb = int(kvm_cfg.get("memory_mb") or self.config.get("memory_mb") or 4096)
        self.cpus = int(kvm_cfg.get("cpus") or self.config.get("cpus") or 2)
        self.no_reboot = bool(kvm_cfg.get("no_reboot", True))
        # A Windows guest needs to be ALLOWED to restart after a bugcheck: that is how it
        # writes the crash dump we read the bugcheck code out of. -no-reboot would kill the
        # VM at the moment of the crash instead. The run timeout is the bound.
        self.want_crash_dump = bool(kvm_cfg.get("want_crash_dump", True))
        self.keep_overlay = bool(kvm_cfg.get("keep_overlay", False))
        self.shutdown_grace_s = int(kvm_cfg.get("shutdown_grace_s", 20) or 20)
        # Guest hardware profile. Windows guests installed by dockurr are UEFI (OVMF) with
        # the disk on virtio-scsi and a raw image; the Debian guest is BIOS with virtio-blk.
        # Booting a disk under hardware it was not installed on simply fails, so this is
        # detected from what sits next to the base image rather than guessed.
        self.force_firmware = (kvm_cfg.get("firmware") or "").lower() or None
        self.force_disk_bus = (kvm_cfg.get("disk_bus") or "").lower() or None
        self.firmware_code = kvm_cfg.get("firmware_code") or ""
        # How long to wait for the guest agent after power-on. 120 s is generous for the
        # Debian guest (~10 s) but tight for Windows with kernel debug enabled, which waits
        # for a debugger before finishing its boot.
        self.agent_timeout_s = int(kvm_cfg.get("agent_timeout_s", 180) or 180)
        # how long to wait for a rebooted guest's agent to come back after a crash
        self.revive_timeout_s = int(kvm_cfg.get("revive_timeout_s", 150) or 150)
        self.timeout_s = int(self.config.get("timeout_s", 300) or 300)

    # -- capability -------------------------------------------------------
    def available(self) -> dict:
        info = capabilities.kvm_available()
        detail = dict(info.get("detail") or {})
        detail["base_image"] = self.base_image or None
        detail["base_image_present"] = bool(self.base_image) and os.path.isfile(
            os.path.expanduser(self.base_image))
        if not info.get("available"):
            info["detail"] = detail
            return info
        if not detail["base_image_present"]:
            info = dict(info)
            info["available"] = False
            info["reason"] = ("no guest base image configured (set kvm.base_image in "
                              "~/.bobbypin/sandbox.json or $BOBBYPIN_KVM_BASE)")
            info["install"] = ("create a guest disk: see sandbox/kvm/README.md, then "
                               "set kvm.base_image to the .qcow2 path")
            info["detail"] = detail
            return info
        info["detail"] = detail
        return info

    # -- qemu command line -------------------------------------------------
    def _build_qemu_argv(self, req: RunRequest, plan: dict) -> list:
        """Deterministic QEMU argv. Exposed for unit testing without qemu installed."""
        argv = [plan["qemu_bin"]]
        if plan.get("kvm"):
            argv += ["-enable-kvm", "-cpu", "host"]
        else:
            argv += ["-accel", "tcg"]

        fw = plan.get("firmware") or {}
        if fw.get("mode") == "uefi":
            # OVMF needs q35; Windows guests installed by dockurr are UEFI and will not
            # boot on the legacy BIOS path at all.
            argv += ["-machine", "q35"]
        argv += ["-m", str(plan["memory_mb"]), "-smp", str(plan["cpus"])]
        argv += ["-uuid", plan["uuid"]]
        argv += ["-rtc", "base=localtime" if fw.get("mode") == "uefi" else "base=utc"]
        argv += ["-display", "none", "-monitor", "none"]
        argv += ["-serial", "file:" + plan["serial_log"]]

        if fw.get("mode") == "uefi":
            argv += ["-drive", "if=pflash,format=raw,readonly=on,file=" + str(fw["code"])]
            argv += ["-drive", "if=pflash,format=raw,file=" + plan["uefi_vars"]]
            # no sleep states: a suspended guest looks identical to a hung one
            argv += ["-global", "ICH9-LPC.disable_s3=1", "-global", "ICH9-LPC.disable_s4=1"]

        # ephemeral disk: overlay on the base image, never the base image itself
        if plan.get("overlay"):
            if fw.get("disk_bus") == "virtio-scsi":
                # match what the guest was installed on - Windows has no virtio-blk driver
                # unless it was installed with one
                argv += ["-drive", "file=" + plan["overlay"] + ",if=none,format=qcow2,id=bpdisk"]
                argv += ["-device", "virtio-scsi-pci,id=bpscsi"]
                argv += ["-device", "scsi-hd,drive=bpdisk,bus=bpscsi.0"]
            else:
                argv += ["-drive", "file=" + plan["overlay"] + ",if=virtio,format=qcow2,cache=unsafe"]
        if plan.get("snapshot"):
            argv += ["-snapshot"]

        # a bugcheck halts instead of looping forever
        if plan.get("no_reboot", True):
            argv += ["-no-reboot"]

        # no egress: user-mode net with restrict=on and zero port forwards
        if plan.get("no_egress", True):
            argv += ["-netdev", "user,id=n0,restrict=on"]
            argv += ["-device", "virtio-net-pci,netdev=n0"]
        else:
            argv += ["-netdev", "user,id=n0"]
            argv += ["-device", "virtio-net-pci,netdev=n0"]

        # No -virtfs shares on purpose: the Debian cloud kernel has no 9p support,
        # and a shared filesystem is another host<->guest surface. Files move over
        # the guest agent (guest-file-read/write) instead. See sandbox/kvm/README.md.

        # guest agent, so the payload can be launched and results pulled back
        argv += ["-chardev", "socket,path=" + plan["qga_sock"] + ",server=on,wait=off,id=qga0"]
        argv += ["-device", "virtio-serial"]
        argv += ["-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0"]
        return argv

    def plan_paths(self, req: RunRequest, workdir: str, run_id: str) -> dict:
        base = os.path.expanduser(self.base_image) if self.base_image else ""
        return {
            "qemu_bin": shutil.which(QEMU_BIN) or QEMU_BIN,
            "qemu_img": shutil.which(QEMU_IMG) or QEMU_IMG,
            "base_image": base,
            "overlay": os.path.join(workdir, "disk.qcow2"),
            "serial_log": os.path.join(workdir, "serial.log"),
            "qemu_stderr": os.path.join(workdir, "qemu.stderr.log"),
            "qga_sock": os.path.join(workdir, "qga.sock"),
            "uuid": run_id if len(run_id) == 36 else
                    "%s-%s-%s-%s-%s" % (run_id[0:8], run_id[8:12], run_id[12:16], run_id[16:20], run_id[20:32]),
            "memory_mb": self.memory_mb,
            "cpus": self.cpus,
            "no_reboot": self.no_reboot,
            "no_egress": bool(req.no_egress),
            "snapshot": True,
            "kvm": os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK),
            "firmware": self.firmware_profile(),
            # per-run NVRAM: the template's vars file holds the UEFI boot entries, so it is
            # copied rather than written to. The template stays untouched, every run starts
            # from the same boot state.
            "uefi_vars": os.path.join(workdir, "uefi.vars"),
        }

    # -- guest agent -------------------------------------------------------
    @staticmethod
    def _qga(sock_path: str, command: dict, timeout: float = 5.0) -> dict:
        """One QGA request over the unix socket. Never raises; returns {'error': ...}."""
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect(sock_path)
                sock.sendall((json.dumps(command) + "\n").encode("utf-8"))
                sock.settimeout(timeout * 2)
                raw = b""
                # file transfer rides this channel, so the cap has to accommodate a
                # chunked base64 payload rather than a small status reply.
                while b"\n" not in raw and len(raw) < 64 * 1024 * 1024:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    raw += chunk
            return json.loads(raw.decode("utf-8", "replace").strip() or "{}")
        except (OSError, ValueError) as exc:
            return {"error": {"class": "Transport", "desc": str(exc)[:200]}}

    @staticmethod
    def base_image_format(path: str) -> str:
        """raw or qcow2, straight from qemu-img. The overlay needs the right -F."""
        img = shutil.which(QEMU_IMG) or QEMU_IMG
        try:
            res = subprocess.run([img, "info", "--output=json", path],
                                 capture_output=True, text=True, timeout=60)
            if res.returncode == 0:
                return (json.loads(res.stdout) or {}).get("format") or "qcow2"
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        return "qcow2"

    def firmware_profile(self) -> dict:
        """What hardware this base image expects: firmware and disk bus.

        dockurr-installed Windows leaves `windows.rom` / `windows.vars` (OVMF) next to the
        disk and lives on virtio-scsi. A disk booted with the wrong firmware or bus is not
        merely slow, it does not start.
        """
        base = os.path.expanduser(self.base_image) if self.base_image else ""
        folder = os.path.dirname(base)
        if self.force_firmware:
            mode = self.force_firmware
        else:
            mode = "uefi" if os.path.isfile(os.path.join(folder, "windows.vars")) else "bios"
        prof = {"mode": mode, "code": None, "vars": None}
        if mode == "uefi":
            code = self.firmware_code or os.path.join(folder, "windows.rom")
            if not os.path.isfile(code):
                code = self._system_ovmf_code()
            prof["code"] = code
            prof["vars"] = os.path.join(folder, "windows.vars")
        if self.force_disk_bus:
            prof["disk_bus"] = self.force_disk_bus
        else:
            prof["disk_bus"] = "virtio-scsi" if mode == "uefi" else "virtio-blk"
        prof["base_format"] = self.base_image_format(base) if base else "qcow2"
        return prof

    @staticmethod
    def _system_ovmf_code() -> str:
        for cand in ("/usr/share/OVMF/OVMF_CODE_4M.fd",
                     "/usr/share/OVMF/OVMF_CODE.fd",
                     "/usr/share/OVMF/OVMF_CODE.ms.fd",
                     "/usr/share/qemu/OVMF.fd"):
            if os.path.isfile(cand):
                return cand
        return "/usr/share/OVMF/OVMF_CODE_4M.fd"

    def _qga_exec(self, sock: str, argv: list, poll_timeout: float = 120.0) -> dict:
        """Run argv in the guest and collect its output.

        Returns {"ok", "exit_code", "stdout", "stderr", "pid", "error"}. Never
        raises: a guest that stops answering comes back as ok=False with an error,
        because an unresponsive target is a normal outcome, not a crash of ours.
        """
        rep = self._qga(sock, {"execute": "guest-exec",
                               "arguments": {"path": argv[0], "arg": [str(a) for a in argv[1:]],
                                             "capture-output": True}}, timeout=30.0)
        ret = rep.get("return")
        if not isinstance(ret, dict):
            return {"ok": False, "exit_code": None, "stdout": "", "stderr": "",
                    "pid": None, "error": json.dumps(rep)[:200]}
        pid = ret.get("pid")
        deadline = time.time() + poll_timeout
        transport_failures = 0
        while time.time() < deadline:
            st = self._qga(sock, {"execute": "guest-exec-status", "arguments": {"pid": pid}},
                           timeout=10.0)
            if "error" in st and not isinstance(st.get("return"), dict):
                # the agent stopped answering - the guest is gone, do not wait it out
                transport_failures += 1
                if transport_failures >= 2:
                    return {"ok": False, "exit_code": None, "stdout": "", "stderr": "",
                            "pid": pid, "error": "guest agent stopped responding"}
                time.sleep(1.0)
                continue
            status = st.get("return") or {}
            if status.get("exited"):
                def _decode(key):
                    raw = status.get(key)
                    if not raw:
                        return ""
                    try:
                        return base64.b64decode(raw).decode("utf-8", "replace")
                    except (ValueError, TypeError):
                        return ""
                return {"ok": True, "exit_code": status.get("exitcode"),
                        "stdout": _decode("out-data"), "stderr": _decode("err-data"),
                        "pid": pid, "error": None}
            time.sleep(0.5)
        return {"ok": False, "exit_code": None, "stdout": "", "stderr": "", "pid": pid,
                "error": f"guest-exec pid {pid} still running after {poll_timeout}s"}

    # -- channel: file transfer over the guest agent ------------------------
    # Deliberately NOT virtfs/9p. The Debian cloud kernel ships no 9p support at
    # all (mount fails with "unknown filesystem type '9p'"), and a shared
    # filesystem is another host<->guest surface to reason about. The guest agent
    # is already the control channel, so it carries the files too:
    #   host -> guest : guest-file-write   (target, bait tarball)
    #   guest -> host : guest-file-read    (anything the target produced)
    CHUNK = 256 * 1024

    # A Windows guest is not a Linux guest with a different accent: paths, shells and
    # available tooling all differ. Detect it once per run and use the right ones rather
    # than assuming a POSIX guest.
    def _guest_os(self, sock: str) -> str:
        rep = self._qga(sock, {"execute": "guest-get-osinfo"}, timeout=15.0)
        info = rep.get("return") if isinstance(rep.get("return"), dict) else None
        if info:
            ident = str(info.get("id") or info.get("pretty-name") or "").lower()
            if "windows" in ident or "msdos" in ident:
                return "windows"
            if ident:
                return "linux"
        return "linux"

    @staticmethod
    def _shell_argv(guest_os: str, script: str) -> list:
        if guest_os == "windows":
            return ["C:\\Windows\\System32\\cmd.exe", "/c", script]
        return ["/bin/sh", "-c", script]

    @staticmethod
    def _mkdir_snippet(guest_os: str, path: str) -> str:
        """Create a directory, idempotently.

        Deliberately unquoted on Windows: `cmd /c if not exist "C:\in" mkdir "C:\in"` sends
        cmd.exe down its quote-stripping path and it silently does nothing. The paths used
        here (C:\in, C:\out, C:\bp) contain no spaces, so no quoting is needed.
        """
        if guest_os == "windows":
            return "mkdir " + path
        return "mkdir -p '" + path + "'"

    @staticmethod
    def _guest_path(guest_os: str, *parts: str) -> str:
        if guest_os == "windows":
            return "\\".join(parts)
        return "/".join(parts)

    @staticmethod
    def _guest_alive(sock: str, timeout: float = 3.0) -> bool:
        return "return" in KVMBackend._qga(sock, {"execute": "guest-ping"}, timeout=timeout)

    def _guest_exec_simple(self, sock: str, script: str, timeout: float = 60.0,
                           guest_os: str = "linux") -> dict:
        return self._qga_exec(sock, self._shell_argv(guest_os, script), poll_timeout=timeout)

    def _guest_put(self, sock: str, host_path: str, guest_path: str,
                   guest_os: str = "linux") -> dict:
        """Copy a host file into the guest via the agent."""
        parent = guest_path.rsplit("\\", 1)[0] if guest_os == "windows" else os.path.dirname(guest_path)
        self._guest_exec_simple(sock, self._mkdir_snippet(guest_os, parent),
                                timeout=30.0, guest_os=guest_os)
        opened = self._qga(sock, {"execute": "guest-file-open",
                                  "arguments": {"path": guest_path, "mode": "wb"}}, timeout=30.0)
        handle = (opened.get("return") or {}).get("handle") if isinstance(opened.get("return"), dict) else None
        if handle is None:
            # some agents return a bare integer handle
            handle = opened.get("return") if isinstance(opened.get("return"), int) else None
        if handle is None:
            return {"ok": False, "error": "guest-file-open failed: " + json.dumps(opened)[:160]}
        written = 0
        try:
            with open(host_path, "rb") as fh:
                while True:
                    chunk = fh.read(self.CHUNK)
                    if not chunk:
                        break
                    rep = self._qga(sock, {"execute": "guest-file-write",
                                           "arguments": {"handle": handle,
                                                         "buf-b64": base64.b64encode(chunk).decode()}},
                                    timeout=60.0)
                    ret = rep.get("return")
                    if isinstance(ret, dict):
                        written += int(ret.get("count", 0))
                    elif isinstance(ret, int):
                        written += ret
                    else:
                        return {"ok": False, "error": "guest-file-write failed: " + json.dumps(rep)[:160]}
        finally:
            self._qga(sock, {"execute": "guest-file-close", "arguments": {"handle": handle}}, timeout=30.0)
        size = os.path.getsize(host_path)
        return {"ok": written == size, "bytes": written, "size": size,
                "error": None if written == size else f"short write ({written}/{size})"}

    def _guest_get(self, sock: str, guest_path: str, host_path: str) -> dict:
        """Copy a file out of the guest via the agent."""
        opened = self._qga(sock, {"execute": "guest-file-open",
                                  "arguments": {"path": guest_path, "mode": "rb"}}, timeout=30.0)
        handle = (opened.get("return") or {}).get("handle") if isinstance(opened.get("return"), dict) else None
        if handle is None:
            handle = opened.get("return") if isinstance(opened.get("return"), int) else None
        if handle is None:
            return {"ok": False, "error": "guest-file-open failed: " + json.dumps(opened)[:160]}
        os.makedirs(os.path.dirname(host_path), exist_ok=True)
        total = 0
        try:
            with open(host_path, "wb") as fh:
                while True:
                    rep = self._qga(sock, {"execute": "guest-file-read",
                                           "arguments": {"handle": handle, "count": self.CHUNK}},
                                    timeout=120.0)
                    ret = rep.get("return") or {}
                    buf = ret.get("buf-b64")
                    if buf:
                        data = base64.b64decode(buf)
                        fh.write(data)
                        total += len(data)
                    if not buf or int(ret.get("count", 0)) == 0:
                        break
        finally:
            self._qga(sock, {"execute": "guest-file-close", "arguments": {"handle": handle}}, timeout=30.0)
        return {"ok": True, "bytes": total}

    # Where a planted decoy tree should live so the target meets it naturally.
    #   Windows guest  -> C:\              (the windows profile's own Users\... layout)
    #   Linux + wine   -> the wine prefix, because that is what C:\Users resolves to
    #   Linux          -> /root
    WINE_PREFIX = "/root/.wine"
    WINE_DRIVE_C = "/root/.wine/drive_c"

    def _staged_base(self, guest_os: str, profile: str) -> str:
        if guest_os == "windows":
            return "C:\\"
        return self.WINE_DRIVE_C if profile in ("windows", "both") else "/root"

    def _stage_bait(self, sock: str, channel_dir: str, hp_root: str,
                    guest_os: str = "linux") -> dict:
        """Ship the decoys into the guest and verify they landed.

        Nothing of ours is written into the bait tree (no manifest, no script): the state
        is read back out afterwards instead, which also works on a guest with no Python.
        """
        import tarfile

        try:
            with open(os.path.join(hp_root, MANIFEST_NAME), "r", encoding="utf-8") as fh:
                manifest = json.load(fh)
        except (OSError, ValueError):
            manifest = {"artifacts": [], "profile": "windows"}
        profile = manifest.get("profile", "windows")
        artifacts = [HoneypotArtifact(**a) for a in manifest.get("artifacts", [])]
        staged_base = self._staged_base(guest_os, profile)

        tar_path = os.path.join(channel_dir, "bait.tar")
        with tarfile.open(tar_path, "w") as tar:
            for name in os.listdir(hp_root):
                if name == MANIFEST_NAME:
                    continue
                tar.add(os.path.join(hp_root, name), arcname=name)
        tar_guest = self._guest_path(guest_os, "C:\\bp" if guest_os == "windows" else "/bp",
                                     "bait.tar")

        if guest_os == "windows":
            prep = "mkdir C:\\\\bp"
        else:
            prep = "mkdir -p /bp %s" % staged_base
            if staged_base == self.WINE_DRIVE_C:
                prep = ("WINEPREFIX=%s wineboot -u >/dev/null 2>&1 || true; " % self.WINE_PREFIX) + prep
        self._guest_exec_simple(sock, prep, timeout=180.0, guest_os=guest_os)

        put = self._guest_put(sock, tar_path, tar_guest, guest_os=guest_os)
        if not put.get("ok"):
            return {"ok": False, "error": "bait transfer failed: " + str(put.get("error")),
                    "files": 0, "base": staged_base}

        # Windows 10+ ships tar.exe; Linux guests have tar. Either way, verify by sentinel.
        first = artifacts[0].relpath.replace("/", "\\\\") if guest_os == "windows" else artifacts[0].relpath
        sep = " & " if guest_os == "windows" else " && "
        if guest_os == "windows":
            # tar -C avoids a `cd` (and its drive-switching quirks); unquoted, as above
            sentinel = (staged_base.rstrip("\\\\") + "\\\\" + first) if staged_base else first
            unpack = ("tar xf %s -C %s%sif exist %s echo LANDED"
                      % (tar_guest, staged_base, sep, sentinel))
        else:
            unpack = ("cd '%s'%star xf '%s'%sif [ -f '%s' ]; then echo LANDED; else echo MISSING; fi"
                      % (staged_base, sep, tar_guest, sep, first))
        res = self._guest_exec_simple(sock, unpack, timeout=180.0, guest_os=guest_os)
        landed = "LANDED" in (res.get("stdout") or "")
        return {"ok": landed, "files": len(artifacts) if landed else 0, "base": staged_base,
                "artifacts": artifacts,
                "error": None if landed else "bait did not land at " + staged_base}

    def _pull_bait_state(self, sock: str, guest_os: str, staged_base: str,
                         artifacts: list, host_dir: str) -> dict:
        """Read each decoy back out of the guest and hash it on the host.

        This is the OS-agnostic replacement for running an audit script inside the guest:
        it needs nothing installed there, returns the tampered files as evidence, and works
        the same on Windows and Linux.
        """
        state = {}
        for art in artifacts:
            rel = art.relpath
            guest_path = self._guest_path(guest_os, staged_base.rstrip("\\/"), rel)
            host_path = os.path.join(host_dir, rel.replace("\\", "/"))
            got = self._guest_get(sock, guest_path, host_path)
            if not got.get("ok"):
                state[rel] = None          # gone by the time we looked
                continue
            try:
                with open(host_path, "rb") as fh:
                    blob = fh.read()
                state[rel] = {"sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob)}
            except OSError:
                state[rel] = None
        return state

    def _collect_crash_dump(self, sock: str, workdir: str) -> Optional[dict]:
        """Pull the newest Windows minidump and read its bugcheck code.

        The dump is the only honest source for the code: the human-readable "*** STOP:"
        banner is produced by a debugger, not by the crashed machine.
        """
        listing = self._guest_exec_simple(
            sock, "dir /b /o-d C:\\Windows\\Minidump", timeout=60.0, guest_os="windows")
        names = [n.strip() for n in (listing.get("stdout") or "").splitlines()
                 if n.strip().lower().endswith(".dmp")]
        if not names:
            listing = self._guest_exec_simple(sock, "dir /b C:\\Windows\\Minidump",
                                              timeout=60.0, guest_os="windows")
            names = [n.strip() for n in (listing.get("stdout") or "").splitlines()
                     if n.strip().lower().endswith(".dmp")]
        if not names:
            return None
        guest_dump = "C:\\Windows\\Minidump\\" + names[0]
        host_dump = os.path.join(workdir, "crash", names[0])
        got = self._guest_get(sock, guest_dump, host_dump)
        if not got.get("ok"):
            return {"path": None, "error": "could not pull " + guest_dump}
        parsed = bsod_mod.parse_minidump(host_dump)
        parsed["dump_file"] = host_dump
        return parsed

    def _collect_out(self, sock: str, out_dir: str, guest_os: str = "linux") -> list:
        """Pull anything the target wrote to the scratch output directory back to the host."""
        if guest_os == "windows":
            res = self._guest_exec_simple(sock, "dir /b /s C:\\out", timeout=90.0,
                                          guest_os="windows")
            lines = [l.strip() for l in (res.get("stdout") or "").splitlines()]
            prefix, cut = "C:\\out\\", len("C:\\out\\")
            rels = [(l, l[cut:]) for l in lines if l.lower().startswith(prefix.lower())]
        else:
            res = self._guest_exec_simple(sock, "find /out -type f 2>/dev/null | head -200",
                                           timeout=60.0)
            rels = [(l.strip(), l.strip()[len("/out/"):]) for l in (res.get("stdout") or "").splitlines()
                    if l.strip().startswith("/out/")]
        pulled = []
        for guest_path, rel in rels:
            if not rel or rel.endswith("\\"):
                continue
            host_path = os.path.join(out_dir, rel.replace("\\", "/"))
            if self._guest_get(sock, guest_path, host_path).get("ok"):
                pulled.append(host_path)
        return sorted(pulled)

    # -- execution ---------------------------------------------------------
    def run(self, req: RunRequest) -> RunRecord:
        self._ensure_ready()
        rec = RunRecord(run_id=new_run_id(), backend=self.name)
        started = time.time()
        rec.started_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if req.target:
            if not os.path.isfile(req.target):
                raise SandboxUnavailable(f"target not found: {req.target}", backend=self.name)
            rec.target = os.path.abspath(req.target)
            rec.target_size = os.path.getsize(rec.target)
            sha = hashlib.sha256()
            with open(rec.target, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    sha.update(chunk)
            rec.target_sha256 = sha.hexdigest()

        workdir = os.path.abspath(os.path.expanduser(req.workdir or "/tmp/bobbypin-vm"))
        os.makedirs(os.path.join(workdir, "out"), exist_ok=True)
        plan = self.plan_paths(req, workdir, rec.run_id)

        # ephemeral disk: overlay on the base image. The base image is opened
        # read-only by qemu and is never the drive qemu is given.
        overlay_ok = False
        img_bin = plan["qemu_img"]
        fw = plan.get("firmware") or {}
        if fw.get("mode") == "uefi" and os.path.isfile(fw.get("vars") or ""):
            # fresh NVRAM per run, seeded with the template's boot entries
            try:
                shutil.copyfile(fw["vars"], plan["uefi_vars"])
            except OSError as exc:
                raise SandboxUnavailable(f"could not prepare UEFI vars: {exc}",
                                         backend=self.name)
        elif fw.get("mode") == "uefi":
            raise SandboxUnavailable(
                "UEFI guest but no vars image found (expected windows.vars next to the "
                "base image)", install="re-provision the guest: sandbox/kvm/provision-guest.sh",
                backend=self.name)

        if os.path.isfile(plan["base_image"]) and shutil.which(QEMU_IMG):
            res = subprocess.run([img_bin, "create", "-f", "qcow2", "-b", plan["base_image"],
                                  "-F", fw.get("base_format", "qcow2"), plan["overlay"]],
                                 capture_output=True, text=True, timeout=120)
            overlay_ok = res.returncode == 0
            if not overlay_ok:
                rec.warnings.append("overlay create failed (" + (res.stderr or "").strip()[:200] +
                                    "); relying on -snapshot for ephemerality")
        if not overlay_ok:
            plan["overlay"] = ""
            plan["snapshot"] = True
            if not plan.get("snapshot"):
                raise SandboxUnavailable(
                    "refusing to run: no ephemeral disk could be arranged (overlay failed and "
                    "-snapshot disabled)", backend=self.name)

        argv = self._build_qemu_argv(req, plan)
        timeout_s = int(req.timeout_s or self.timeout_s)

        stdout_fh = open(os.path.join(workdir, "qemu.stdout.log"), "wb")
        stderr_fh = open(plan["qemu_stderr"], "wb")
        proc = None
        agent_up = False
        try:
            try:
                proc = subprocess.Popen(argv, stdout=stdout_fh, stderr=stderr_fh,
                                        stdin=subprocess.DEVNULL, start_new_session=True)
            except OSError as exc:
                raise SandboxUnavailable(f"could not launch qemu: {exc}",
                                         install=GUEST_INSTALL_HINT, backend=self.name)

            # wait for the guest agent to answer, up to a slice of the budget
            boot_deadline = time.time() + min(self.agent_timeout_s,
                                              max(20, int(timeout_s // 2)))
            while time.time() < boot_deadline and proc.poll() is None:
                if os.path.exists(plan["qga_sock"]):
                    rep = self._qga(plan["qga_sock"], {"execute": "guest-ping"}, timeout=2.0)
                    if "return" in rep:
                        agent_up = True
                        break
                time.sleep(1.0)
            if not agent_up:
                rec.warnings.append("guest agent never answered; falling back to boot-only run "
                                    "(no in-guest execution, no in-guest result collection)")

            if agent_up:
                sock = plan["qga_sock"]
                guest_os = self._guest_os(sock)
                plan["guest_os"] = guest_os
                rec.containment["guest_os"] = guest_os
                if guest_os == "windows":
                    # Windows guests here are installed by dockurr for this purpose and
                    # should have the agent; if not, nothing downstream can work and the
                    # operator needs to know why, not a traceback.
                    rec.warnings.append("Windows guest detected: payloads run natively (no wine)")
                # The transport artifacts (bait tarball, audit script) are ours, not
                # the target's, so they live OUTSIDE the workdir: otherwise the leak
                # scan finds every decoy token inside our own tarball and reports 13
                # bogus exfiltration hits.
                channel_dir = tempfile.mkdtemp(prefix="bp-channel-")
                plan["channel_dir"] = channel_dir

                # Where things live on THIS guest. Computed before anything is delivered,
                # because the scratch setup, the target and the helpers all need it.
                in_dir = self._guest_path(guest_os, "C:\\in" if guest_os == "windows" else "/in")
                out_guest = self._guest_path(guest_os, "C:\\out" if guest_os == "windows" else "/out")
                plan["in_dir"] = in_dir
                plan["out_dir_guest"] = out_guest

                # scratch the payload is told it may use. Run each separately and check the
                # result: a silent failure here surfaces later as "cannot find the path",
                # which is a much worse error message than this one.
                if guest_os == "windows":
                    for path in (in_dir, out_guest):
                        res = self._guest_exec_simple(sock, self._mkdir_snippet(guest_os, path),
                                                      timeout=60.0, guest_os=guest_os)
                        if res.get("exit_code") not in (0, None):
                            rec.warnings.append("could not create %s: %s" % (
                                path, (res.get("stderr") or res.get("error") or "")[:120]))
                else:
                    self._guest_exec_simple(sock, "mkdir -p /in /out && chmod 1777 /out",
                                            timeout=30.0, guest_os=guest_os)

                # Deliver the target through the agent, not a shared filesystem.
                if req.target:
                    guest_target = self._guest_path(guest_os, in_dir, os.path.basename(rec.target))
                    put = self._guest_put(sock, rec.target, guest_target)
                    if guest_os != "windows":
                        self._guest_exec_simple(sock, "chmod 0755 '%s'" % guest_target, timeout=30.0)
                    rec.containment["target_delivered"] = bool(put.get("ok"))
                    if not put.get("ok"):
                        rec.warnings.append("target transfer into the guest failed: "
                                            + str(put.get("error")))

                # Helper binaries (e.g. the debugger-state simulator) travel the same way.
                for helper in (req.helpers or []):
                    if not os.path.isfile(helper):
                        rec.warnings.append("helper not found: " + helper)
                        continue
                    guest_helper = self._guest_path(guest_os, in_dir, os.path.basename(helper))
                    put = self._guest_put(sock, helper, guest_helper)
                    if guest_os != "windows":
                        self._guest_exec_simple(sock, "chmod 0755 '%s'" % guest_helper, timeout=30.0)
                    if not put.get("ok"):
                        rec.warnings.append("helper transfer failed: " + str(put.get("error")))

                # Plant the decoys inside the guest's throwaway disk.
                bait = None
                if req.honeypot_root and os.path.isdir(req.honeypot_root):
                    bait = self._stage_bait(sock, channel_dir, req.honeypot_root,
                                            guest_os=guest_os)
                    rec.containment["bait_files_staged"] = bait.get("files")
                    rec.containment["bait_inside_guest"] = bool(bait.get("ok"))
                    if not bait.get("ok"):
                        rec.warnings.append("bait staging failed: " + str(bait.get("error")))

                # A trip_debug run launches the simulator, which launches the target, so
                # the command line is built here where the guest OS and paths are known.
                if req.trip_debug and req.target:
                    self.trip_helper = req.trip_helper or (
                        req.helpers[0] if req.helpers else None)
                    req.argv = self.trip_argv(guest_os, in_dir, os.path.basename(rec.target))
                    rec.containment["trip_debug"] = True

                # Run it.
                transport_lost = False
                if req.argv:
                    guest = self._qga_exec(sock, [str(a) for a in req.argv],
                                           poll_timeout=min(max(timeout_s, 5), 3600))
                    if guest["ok"]:
                        rec.exit_code = guest["exit_code"]
                        rec.stdout_tail = self._tail(guest["stdout"])
                        rec.stderr_tail = self._tail(guest["stderr"])
                        rec.containment["guest_pid"] = guest["pid"]
                    else:
                        rec.timed_out = "still running" in (guest["error"] or "")
                        # "stopped responding" is the interesting failure: it means the guest
                        # itself went away mid-payload, not that the payload is slow.
                        transport_lost = "stopped responding" in (guest["error"] or "")
                        if transport_lost:
                            # the guest went away while we were waiting for a result
                            rec.crashed = True
                            rec.abnormal_exit = True
                        rec.warnings.append("guest execution: " + str(guest["error"]))

                # If the transport died mid-payload the guest may have bugchecked and
                # restarted. Wait a bounded time to see whether the agent comes back: if it
                # does, the guest restarted, which is a crash, and its dump is waiting.
                if req.argv and transport_lost and not self._guest_alive(sock, timeout=3.0):
                    revive_deadline = time.time() + self.revive_timeout_s
                    while time.time() < revive_deadline:
                        if self._guest_alive(sock, timeout=3.0):
                            rec.containment["guest_restarted"] = True
                            rec.crashed = True
                            rec.abnormal_exit = True
                            rec.warnings.append(
                                "the guest stopped answering mid-run and then came back: it "
                                "RESTARTED, i.e. the target took it down and Windows rebooted "
                                "(a bugcheck, unless the target asked for a restart)")
                            break
                        time.sleep(3.0)

                # Collect while the guest is still alive: results first, then the
                # bait's state. If the target took the kernel down there is nothing
                # to collect, and we must not sit on a dead agent waiting for it.
                if self._guest_alive(sock, timeout=3.0):
                    try:
                        rec.artifacts = self._collect_out(sock, os.path.join(workdir, "out"),
                                                           guest_os=guest_os)
                        if (rec.containment.get("guest_restarted") or transport_lost) \
                                and guest_os == "windows":
                            rec.minidump = self._collect_crash_dump(sock, workdir)
                            if rec.minidump and rec.minidump.get("bugcheck_code"):
                                rec.bsod_suspected = True
                                rec.warnings.append(
                                    "bugcheck %s (%s) read from the crash dump" % (
                                        hex(rec.minidump["bugcheck_code"]),
                                        rec.minidump.get("bugcheck_name") or "unnamed code"))
                        if bait and bait.get("ok"):
                            rec.guest_audit_dir = os.path.join(workdir, "bait_after")
                            rec.guest_audit = self._pull_bait_state(
                                sock, guest_os, bait["base"], bait.get("artifacts", []),
                                rec.guest_audit_dir)
                    except (OSError, ValueError) as exc:
                        rec.warnings.append("guest collection failed: " + str(exc))
                else:
                    rec.warnings.append("guest stopped answering before results could be "
                                        "collected - consistent with the target taking the "
                                        "guest down (see the crash signatures below)")

                # Polite shutdown; the ephemeral disk goes with it. NOTE: this is a
                # guest-agent command, not the QMP `system_powerdown` - qemu-ga only
                # speaks its own command set, and a QMP name gets CommandNotFound
                # silently, which leaves the VM running until the grace period expires.
                self._qga(sock, {"execute": "guest-shutdown",
                                 "arguments": {"mode": "powerdown"}}, timeout=10.0)

            # Teardown. The payload budget (timeout_s) is spent by the time we get
            # here, so this is just the shutdown handshake - a guest that ignores
            # ACPI powerdown does not get to hold the run open.
            if proc.poll() is None:
                try:
                    proc.wait(timeout=self.shutdown_grace_s)
                except subprocess.TimeoutExpired:
                    rec.warnings.append(
                        f"guest did not power off within {self.shutdown_grace_s}s; "
                        "the vm was terminated (the disk is ephemeral, so nothing is lost)")
                    self._terminate(proc)
            qemu_returncode = proc.poll()
        finally:
            if proc is not None and proc.poll() is None:
                self._terminate(proc)
            stdout_fh.close()
            stderr_fh.close()
            channel_dir = plan.get("channel_dir")
            if channel_dir:
                shutil.rmtree(channel_dir, ignore_errors=True)

        # post-mortem: did the guest restart under us? The boot record is the reliable
        # witness - it is there whether or not the agent ever comes back.
        cycles = bsod_mod.scan_boot_cycles(plan["serial_log"])
        if cycles.get("restarted"):
            rec.containment["guest_restarted"] = True
            rec.containment["boot_cycles"] = cycles.get("cycles")
            rec.crashed = True
            rec.abnormal_exit = True
            rec.warnings.append(
                "the guest RESTARTED mid-run (%d boots recorded): the target took the "
                "machine down and the firmware went through its boot path again"
                % cycles.get("cycles", 0))

        serial = bsod_mod.scan_file(plan["serial_log"])
        qerr = bsod_mod.scan_file(plan["qemu_stderr"])
        hits = list(serial.get("matches") or []) + list(qerr.get("matches") or [])
        # OR, not overwrite: the crash dump already established this, and a plain
        # assignment here silently undid it (the record said "no bugcheck" while carrying
        # a minidump with the bugcheck code in it).
        rec.bsod_suspected = bool(rec.bsod_suspected
                                  or serial.get("bsod_suspected")
                                  or qerr.get("bsod_suspected"))
        for hit in hits[:20]:
            rec.warnings.append("guest-crash signature: " + hit.get("pattern", "") +
                                " :: " + (hit.get("line") or "")[:160])

        rec.serial_log = plan["serial_log"]
        rec.containment = dict(rec.containment or {})
        rec.containment.update({
            "engine": "qemu-kvm" if plan.get("kvm") else "qemu-tcg",
            "network": "restrict" if plan.get("no_egress", True) else "user",
            "disk": "qcow2-overlay-ephemeral" if overlay_ok else "snapshot-ephemeral",
            "base_image_touched": False,
            "kvm": bool(plan.get("kvm")),
            "firmware": fw.get("mode", "bios"),
            "disk_bus": fw.get("disk_bus", "virtio-blk"),
            "base_format": fw.get("base_format", "qcow2"),
            "no_reboot": bool(plan.get("no_reboot", True)),
            "guest_agent": agent_up,
            "qemu_returncode": locals().get("qemu_returncode"),
            "serial_log": plan["serial_log"],
            "channel": "qemu-guest-agent (no shared filesystem)",
            "ephemeral": True,
        })
        if not overlay_ok:
            rec.containment["disk"] = "snapshot-ephemeral"
        if not plan.get("kvm"):
            rec.warnings.append("KVM acceleration unavailable; running under TCG emulation (slow)")

        rec.ended_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rec.duration_s = round(time.time() - started, 3)
        # OR in what the crash evidence already established: a guest that restarted or went
        # silent mid-payload did NOT "exit cleanly", and an overwrite here would hide that.
        rec.crashed = bool(rec.crashed or rec.timed_out or rec.bsod_suspected or
                           rec.exit_code not in (0, None))
        rec.abnormal_exit = bool(rec.abnormal_exit or rec.timed_out or rec.bsod_suspected)
        out_dir = os.path.join(workdir, "out")
        rec.artifacts = sorted(os.path.join(out_dir, f) for f in os.listdir(out_dir)) \
            if os.path.isdir(out_dir) else []

        if not self.keep_overlay and overlay_ok and os.path.exists(plan["overlay"]):
            try:
                os.unlink(plan["overlay"])
                rec.warnings.append("ephemeral disk overlay discarded")
            except OSError as exc:
                rec.warnings.append(f"could not discard overlay: {exc}")
        return rec

    @staticmethod
    def _terminate(proc, grace: float = 5.0) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except OSError:
            try:
                proc.terminate()
            except OSError:
                return
        try:
            proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:
                pass
