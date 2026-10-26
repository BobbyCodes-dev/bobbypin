# sandbox/ — internal interface contract (v1)

Frozen interfaces for the safety layer. Every module below **must** match these
signatures exactly — other modules are being written against this contract in
parallel. Do not rename, do not change field names, do not add required args.

Repo root: the bobbypin working clone.
Python: 3.11, **stdlib only** unless noted (no pytest — tests use `unittest`).
Everything the sandbox emits is strict JSON-serialisable (`to_dict()`).

---

## Purpose

Three safety features, all in service of the same goal: analysis of untrusted
targets must not be able to damage the machine it runs on.

1. **VM isolation** — execute/contain a target in a throwaway boundary
   (hardened container or KVM/QEMU guest) so a buggy or hostile binary can
   crash *its* boundary, never the operator's host. No host BSOD, no
   host BSOD-loop, no persistence.
2. **Honeypots** — decoy artifacts deployed into the boundary so any attempt
   to read/exfiltrate credentials, license keys or wallets is detected and
   reported after the run.
3. **Telemetry** — opt-in (default OFF) run reporting to the operator's
   dashboard. Aggregate run facts only, never binary contents or full paths.

---

## `sandbox/base.py`

```python
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

@dataclass
class RunRequest:
    target: Optional[str] = None      # abs path to target file (None for a containment probe)
    workdir: str = ""                 # abs host dir for outputs; created if missing
    argv: Optional[list] = None       # command to execute INSIDE the sandbox (None -> backend probe)
    timeout_s: int = 300
    memory: str = "2g"                # backend hint (docker); kvm maps to memory_mb
    memory_mb: int = 2048
    cpus: float = 2.0
    honeypot_root: Optional[str] = None   # abs host dir of deployed honeypots (copied/mounted in)
    env: dict = field(default_factory=dict)
    image: Optional[str] = None       # backend-specific override
    no_egress: bool = True            # MUST default True

@dataclass
class RunRecord:
    run_id: str                       # uuid4 hex
    backend: str                      # "docker" | "kvm"
    target: Optional[str]
    target_sha256: Optional[str]
    target_size: Optional[int]
    started_iso: str
    ended_iso: str
    duration_s: float
    exit_code: Optional[int]
    signal: Optional[int]
    timed_out: bool
    crashed: bool                     # nonzero exit OR signal OR bsod_suspected
    bsod_suspected: bool = False
    oom_killed: bool = False
    containment: dict = field(default_factory=dict)   # {"network":"none","rootfs":"read-only","writable":[...],"ephemeral":True,...}
    artifacts: list = field(default_factory=list)     # host abs paths produced by the run
    stdout_tail: str = ""
    stderr_tail: str = ""
    serial_log: Optional[str] = None                  # abs path when the backend captures one
    guest_audit: dict = field(default_factory=dict)    # VM only: in-guest bait state,
                                                       # relpath -> {"sha256","size"} | None
    warnings: list = field(default_factory=list)

    def to_dict(self) -> dict: ...    # asdict(self)

class SandboxError(RuntimeError): ...
class SandboxUnavailable(SandboxError): ...   # boundary cannot be created - never fall back to host execution

class SandboxBackend:
    name: str = "base"
    def available(self) -> dict:
        """{"available": bool, "reason": str, "install": Optional[str], "detail": {...}}"""
    def run(self, req: RunRequest) -> RunRecord:
        """Create boundary, run inside it, tear it down. Raise SandboxUnavailable
        if the boundary cannot be created. NEVER execute req.argv on the host."""
```

## `sandbox/capabilities.py`

```python
def probe() -> dict:
    """{"backends": {"docker": <available() dict>, "kvm": <available() dict>},
        "recommended": "docker"|"kvm"|None, "host": {...}, "notes": [str]}"""
def docker_available() -> dict
def kvm_available() -> dict
```

## `sandbox/backends/__init__.py`

```python
def get_backend(name: str, config: dict | None = None) -> SandboxBackend
    # name in {"docker","kvm"}; "auto" -> capabilities.probe()["recommended"]
    # unknown/unavailable -> raise SandboxUnavailable (with .install hint in the message)
def list_backends() -> list   # ["docker","kvm"]
```

## `sandbox/bsod.py`

```python
BSOD_PATTERNS: list   # regex strings
def detect(text: str) -> dict
    """{"bsod_suspected": bool, "matches": [{"pattern":str,"line":str}], "severity": "none"|"warn"|"hit"}"""
def scan_file(path: str, max_bytes: int = 400_000) -> dict   # same shape
```

## `sandbox/honeypots.py`

```python
CANARY_PREFIX = "BP-CANARY-"

@dataclass
class HoneypotArtifact:
    relpath: str      # POSIX-relative path inside the honeypot root
    kind: str         # "credential"|"license"|"wallet"|"key"|"document"|"config"
    sha256: str
    size: int
    mtime: float
    token: str        # f"{CANARY_PREFIX}{8 hex}" - unique, embedded in the content

class HoneypotSet:
    root: str
    artifacts: list
    manifest_path: str
    @classmethod
    def deploy(cls, root: str, profile: str = "windows") -> "HoneypotSet"
        # profile in {"windows","linux","both"}; creates files, writes
        # <root>/_honeypot_manifest.json (0600), returns loaded set
    @classmethod
    def load(cls, root: str) -> "HoneypotSet"
    def to_dict(self) -> dict
    def audit(self, scan_roots: Optional[list] = None, max_scan_bytes: int = 8_000_000) -> dict
        """{"summary": {"total":int,"modified":int,"deleted":int,"leaked":int,"clean":bool},
            "hits": [{"relpath":str,"kind":str,"change":"modified"|"deleted"|"token_leaked",
                      "token":str,"found_in":Optional[str],"severity":"low"|"medium"|"high"}],
            "scanned_roots":[...], "duration_ms": int}"""
```

## `sandbox/telemetry.py`

```python
SCHEMA_VERSION = 1

class Telemetry:
    def __init__(self, config: dict, config_path: Optional[str] = None): ...
    @property
    def enabled(self) -> bool: ...          # False unless configured on
    def host_id(self) -> str: ...           # sha256(salt + /etc/machine-id)[:16], salt file 0600
    def event_from(self, record, extra: Optional[dict] = None) -> dict
    def send(self, event: dict) -> dict
        """{"sent":bool,"queued":bool,"http":Optional[int],"status":str,"url":Optional[str]}"""
    def flush(self) -> dict   # {"flushed":int,"remaining":int}
    def status(self) -> dict  # {"enabled":bool,"endpoint":Optional[str],"queued":int,"host_id":str,"last":Optional[dict]}
```

Event payload (exact keys):

```json
{"schema": 1, "event": "sandbox_run", "run_id": "...", "ts": "ISO8601Z",
 "tool": {"name": "bobbypin", "version": "<from bobbypin.py VERSION or 'unknown'>"},
 "backend": "docker", "host_id": "abc123",
 "target": {"basename": "app.exe", "sha256": "..", "size": 123, "kind": "pe32", "path_hashed": ".."},
 "result": {"exit_code": 1, "signal": null, "timed_out": false, "crashed": true,
            "bsod_suspected": false, "oom_killed": false, "duration_s": 1.23},
 "honeypots": {"total": 9, "modified": 1, "deleted": 0, "leaked": 1, "clean": false,
               "kinds": ["license"]},
 "containment": {"network": "none", "rootfs": "read-only", "ephemeral": true}}
```

Rules: `enabled=False` -> `send()` returns `{"sent": False, "queued": False, "status": "disabled"}` and **never touches the network**. Network failure -> spool to `~/.bobbypin/telemetry-queue.jsonl` (cap 200, drop oldest) and never raise.

## `sandbox/config.py`

```python
DEFAULTS: dict   # see below
def config_path() -> str            # ~/.bobbypin/sandbox.json
def load_config(path: Optional[str] = None) -> dict   # deep-merged over DEFAULTS
def save_config(cfg: dict, path: Optional[str] = None) -> str   # 0600
def set_value(dotted_key: str, value, path: Optional[str] = None) -> dict
```

```python
DEFAULTS = {
  "backend": "auto",
  "image": "bobbypin/sandbox:latest",
  "timeout_s": 300,
  "memory": "2g", "memory_mb": 2048, "cpus": 2.0,
  "telemetry": {"enabled": False, "endpoint": "", "timeout_s": 10, "queue_max": 200},
  "honeypots": {"enabled": True, "profile": "windows"},
  "kvm": {"base_image": "", "memory_mb": 4096, "cpus": 2, "no_egress": True, "no_reboot": True},
  "state_dir": "~/.bobbypin",
}
```

## `sandbox/runner.py`

```python
def preflight(config: Optional[dict] = None) -> dict
def run_sandbox(target=None, backend="auto", workdir=None, argv=None, timeout_s=None,
                honeypots=True, config=None, scan_roots=None) -> dict
    """Returns:
    {"ok": bool, "backend": str, "record": {...RunRecord...},
     "honeypots": {...audit...} | None, "telemetry": {...send result...},
     "error": Optional[str], "install": Optional[str]}"""
```

A VM cannot show tampering on the host honeypot root: the decoys live on the
guest's ephemeral disk, so the guest reports their state in `guest_audit` and the
runner folds it in with `honeypots.merge_guest_audit()` (the host report still
supplies leak detection, because a leak is what made it out of the guest).

`run_sandbox` contract:
1. resolve config, probe capabilities, pick backend (`auto` -> recommended).
2. deploy honeypots into `<workdir>/honeypots` (if enabled) **before** the run.
3. build a `RunRequest`, call `backend.run(req)`.
4. `HoneypotSet.load(...).audit(scan_roots)` after the run, merged with
   `record.guest_audit` when the backend is a VM.
5. hand the record + audit to telemetry; never let telemetry failure fail the run.
6. always return a dict, never raise for a *target-caused* failure (`crashed=True`);
   raise/return `ok=false` + `install` hint only when the *backend* is unavailable.

---

## Non-negotiables

- **Never fall back to host execution.** If a boundary can't be built, fail loudly.
- No new third-party dependencies. `capstone`/`frida` are only needed by `bobbypin.py`.
- No `sudo`, no downloads at import or test time.
- All writes land under `workdir`, `~/.bobbypin/`, or the honeypot root.
- Tests: `sandbox/tests/test_*.py`, stdlib `unittest`, runnable with
  `python3 -m unittest discover -s sandbox/tests -t .`
- Every module must import cleanly on a machine with no docker and no qemu.
