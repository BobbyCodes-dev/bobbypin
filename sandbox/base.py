"""Frozen interfaces for the sandbox safety layer. See sandbox/CONTRACT.md."""

from __future__ import annotations

import os
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Optional


def new_run_id() -> str:
    return uuid.uuid4().hex


@dataclass
class RunRequest:
    """What to run, and inside what limits."""

    target: Optional[str] = None          # abs path to target file (None -> containment probe)
    workdir: str = ""                     # abs host dir for outputs; created if missing
    argv: Optional[list] = None          # command to execute INSIDE the boundary
    timeout_s: int = 300
    memory: str = "2g"                    # docker-style limit
    memory_mb: int = 2048                 # kvm-style limit
    cpus: float = 2.0
    honeypot_root: Optional[str] = None   # abs host dir of deployed honeypots
    env: dict = field(default_factory=dict)
    image: Optional[str] = None
    # extra host files to place alongside the target at /in/<basename> - used by
    # `trip_debug`, which needs ad_trip.exe in the guest to simulate a debugger
    helpers: list = field(default_factory=list)
    trip_debug: bool = False              # run the target under the debugger simulator
    trip_helper: Optional[str] = None     # host path of that simulator (ad_trip.exe)
    no_egress: bool = True               # MUST default True

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RunRecord:
    """What actually happened. Strict-JSON serialisable."""

    run_id: str = field(default_factory=new_run_id)
    backend: str = ""
    target: Optional[str] = None
    target_sha256: Optional[str] = None
    target_size: Optional[int] = None
    started_iso: str = ""
    ended_iso: str = ""
    duration_s: float = 0.0
    exit_code: Optional[int] = None
    signal: Optional[int] = None
    timed_out: bool = False
    crashed: bool = False          # nonzero exit OR signal OR crash OR oom (see contract)
    abnormal_exit: bool = False    # the boundary killed it / it died: signal, timeout, oom, crash
    bsod_suspected: bool = False
    oom_killed: bool = False
    containment: dict = field(default_factory=dict)
    artifacts: list = field(default_factory=list)
    stdout_tail: str = ""
    stderr_tail: str = ""
    serial_log: Optional[str] = None
    # For a VM, tampering happens on the guest's ephemeral disk and can only be
    # observed from inside it. The backend reports what it found there; the
    # host-side honeypot root stays pristine, so the runner merges these two.
    guest_audit: dict = field(default_factory=dict)
    guest_audit_dir: Optional[str] = None   # VM only: where the decoys were pulled back to,
                                            # so the leak scan does not flag our own copies
    minidump: Optional[dict] = None         # Windows crash dump parsed for the bugcheck code
    warnings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class SandboxError(RuntimeError):
    """Base class for sandbox failures."""


class SandboxUnavailable(SandboxError):
    """The boundary could not be built.

    Raised instead of ever falling back to host execution. The message
    carries the operator-fixable reason plus an ``install`` hint when one
    exists (``self.install``).
    """

    def __init__(self, message: str, install: Optional[str] = None,
                 backend: Optional[str] = None):
        super().__init__(message)
        self.install = install
        self.backend = backend


class SandboxBackend:
    """Abstract execution boundary."""

    name: str = "base"

    def available(self) -> dict:
        """Return {"available": bool, "reason": str, "install": Optional[str], "detail": {...}}."""
        raise NotImplementedError

    def run(self, req: RunRequest) -> RunRecord:
        """Create the boundary, run inside it, tear it down.

        Raises SandboxUnavailable when the boundary cannot be created.
        Never executes req.argv on the host.
        """
        raise NotImplementedError

    # -- helpers shared by backends -----------------------------------------
    def trip_argv(self, guest_os: str, in_dir: str, target_basename: str) -> list:
        """How to launch the target under the debugger simulator on this guest.

        Lives here rather than in the caller because only the backend knows what it woke
        up: a Windows guest runs the .exe directly, a Linux guest needs wine, and the paths
        are different in each case.
        """
        join = (lambda *p: "\\".join(p)) if guest_os == "windows" else (lambda *p: "/".join(p))
        helper = join(in_dir, os.path.basename(self.trip_helper or "ad_trip.exe"))
        target = join(in_dir, target_basename)
        if guest_os == "windows":
            # Launched through cmd.exe rather than directly. qemu-ga's Windows guest-exec
            # rejects (path=helper, arg=[target]) with "Failed to execute child process
            # (Invalid argument)" even for files it can clearly run, while going through a
            # shell works every time - and it keeps the child's stdout on our pipe, which is
            # where the "debugger detected" line shows up.
            return ["C:\\Windows\\System32\\cmd.exe", "/c", helper + " " + target]
        return ["wine", helper, target]

    @staticmethod
    def _tail(text: Optional[str], limit: int = 4000) -> str:
        if not text:
            return ""
        return text if len(text) <= limit else text[-limit:]

    def _ensure_ready(self) -> dict:
        info = self.available()
        if not info.get("available"):
            raise SandboxUnavailable(
                info.get("reason") or f"backend {self.name} unavailable",
                install=info.get("install"),
                backend=self.name,
            )
        return info
