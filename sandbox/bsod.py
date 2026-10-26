"""Detect a guest kernel crash (bugcheck / panic) from captured console output.

A target that bugchecks a guest kernel looks like a hung run unless you look.
This module turns serial output, QEMU stderr and Windows event text into a
plain verdict, so the operator is told "the target crashed the guest" instead
of waiting on a dead boundary.
"""

from __future__ import annotations

import os
import re

# (regex, severity, label)
BSOD_PATTERNS: list = [
    (r"\*\*\*\s*STOP\s*:", "hit", "windows_bugcheck_stop"),
    (r"A problem has been detected and Windows has been shut down", "hit", "windows_bsod_banner"),
    (r"\bBUGCHECK\b", "hit", "windows_bugcheck"),
    (r"KMODE_EXCEPTION_NOT_HANDLED", "hit", "windows_bugcheck_kmode"),
    (r"PAGE_FAULT_IN_NONPAGED_AREA", "hit", "windows_bugcheck_page_fault"),
    (r"IRQL_NOT_LESS_OR_EQUAL", "hit", "windows_bugcheck_irql"),
    (r"DRIVER_IRQL_NOT_LESS_OR_EQUAL", "hit", "windows_bugcheck_driver_irql"),
    (r"SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "hit", "windows_bugcheck_system_thread"),
    (r"CRITICAL_PROCESS_DIED", "hit", "windows_bugcheck_critical_process"),
    (r"BAD_POOL_CALLER", "hit", "windows_bugcheck_bad_pool"),
    (r"BAD_POOL_HEADER", "hit", "windows_bugcheck_bad_pool_header"),
    (r"UNEXPECTED_KERNEL_MODE_TRAP", "hit", "windows_bugcheck_kernel_trap"),
    (r"ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY", "hit", "windows_bugcheck_nx"),
    (r"SYSTEM_SERVICE_EXCEPTION", "hit", "windows_bugcheck_service_exception"),
    (r"REFERENCE_BY_POINTER", "hit", "windows_bugcheck_reference_by_pointer"),
    (r"0x0000000A\b", "hit", "bugcheck_code_0x0A_irql"),
    (r"0x0000001E\b", "hit", "bugcheck_code_0x1E_kmode"),
    (r"0x0000003B\b", "hit", "bugcheck_code_0x3B_service_exception"),
    (r"0x00000050\b", "hit", "bugcheck_code_0x50_page_fault"),
    (r"0x0000007E\b", "hit", "bugcheck_code_0x7E_system_thread"),
    (r"0x000000D1\b", "hit", "bugcheck_code_0xD1_driver_irql"),
    (r"0xC0000005\b.*(access|violation)", "warn", "access_violation"),
    (r"Kernel panic - not syncing", "hit", "linux_kernel_panic"),
    (r"BUG: unable to handle kernel", "hit", "linux_kernel_oops"),
    (r"\bOops:\s", "warn", "linux_oops"),
    (r"triple fault", "hit", "qemu_triple_fault"),
    (r"Guest has not initialized the display", "hit", "qemu_guest_no_display"),
    (r"KVM: entry failed", "hit", "kvm_entry_failed"),
    (r"KVM: emulation failure", "warn", "kvm_emulation_failure"),
    (r"qemu: terminating on signal (?:11|6|7|8|4)\b", "hit", "qemu_died_from_fatal_signal"),
    (r"qemu: terminating on signal", "warn", "qemu_terminated_by_signal"),
    (r"kvm_run: failed", "warn", "kvm_run_failed"),
    (r"guest reset", "warn", "guest_reset"),
    (r"reboot: Restarting system", "warn", "guest_reboot_loop"),
    (r"halted by -no-reboot|QEMU: Terminated due to no-reboot", "hit", "no_reboot_halt"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), sev, label) for p, sev, label in BSOD_PATTERNS]
_SEVERITY_ORDER = {"none": 0, "warn": 1, "hit": 2}


# Firmware boot banners. Two of these in one run means the guest restarted itself
# mid-run - which, for a guest with no operator, means it went down.
BOOT_MARKERS = [
    b"BdsDxe: starting Boot",          # OVMF/UEFI handing over to a boot target
    b"BdsDxe: loading Boot",
    b"SeaBIOS",                        # legacy BIOS
    b"iPXE",
]


def count_boot_cycles(data: bytes) -> int:
    """How many times did this guest boot during the run? >1 means it restarted."""
    if not data:
        return 0
    return max(data.count(marker) for marker in BOOT_MARKERS) if any(
        marker in data for marker in BOOT_MARKERS) else 0


def scan_boot_cycles(path: str, max_bytes: int = 4_000_000) -> dict:
    """count_boot_cycles() over a serial log. Missing file -> 0 cycles, never raises."""
    if not path or not os.path.isfile(path):
        return {"cycles": 0, "restarted": False, "path": path}
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes)
    except OSError:
        return {"cycles": 0, "restarted": False, "path": path}
    cycles = count_boot_cycles(data)
    return {"cycles": cycles, "restarted": cycles > 1, "path": path}


# Windows bugcheck codes -> the name a human recognises. Only the ones worth naming.
BUGCHECK_NAMES = {
    0x0000000A: "IRQL_NOT_LESS_OR_EQUAL",
    0x00000019: "BAD_POOL_HEADER",
    0x0000001A: "MEMORY_MANAGEMENT",
    0x0000001E: "KMODE_EXCEPTION_NOT_HANDLED",
    0x00000024: "NTFS_FILE_SYSTEM",
    0x0000003B: "SYSTEM_SERVICE_EXCEPTION",
    0x0000003D: "INTERRUPT_EXCEPTION_NOT_HANDLED",
    0x0000004E: "PFN_LIST_CORRUPT",
    0x00000050: "PAGE_FAULT_IN_NONPAGED_AREA",
    0x0000007E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
    0x0000007F: "UNEXPECTED_KERNEL_MODE_TRAP",
    0x0000008E: "KERNEL_MODE_EXCEPTION_NOT_HANDLED",
    0x0000009F: "DRIVER_POWER_STATE_FAILURE",
    0x000000BE: "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
    0x000000C2: "BAD_POOL_CALLER",
    0x000000C4: "DRIVER_VERIFIER_DETECTED_VIOLATION",
    0x000000C5: "DRIVER_CORRUPTED_EXPOOL",
    0x000000D1: "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
    0x000000EF: "CRITICAL_PROCESS_DIED",
    0x000000F4: "CRITICAL_OBJECT_TERMINATION",
    0x000000FC: "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY",
    0x00000133: "DPC_WATCHDOG_VIOLATION",
    0x00000139: "KERNEL_SECURITY_CHECK_FAILURE",
    0xC0000218: "STATUS_CANNOT_LOAD_REGISTRY_FILE",
    0xC0000221: "STATUS_IMAGE_CHECKSUM_MISMATCH",
}


def parse_minidump(path: str) -> dict:
    """Read the bugcheck out of a Windows crash dump header.

    A bugcheck banner is written by the *debugger*, not the target, so kernel debug on a
    serial port gives you kd protocol bytes and nothing readable. The dump is the honest
    source: DUMP_HEADER64 carries the code at 0x38 and four parameters from 0x40.

    Works for a small memory dump (C:\Windows\Minidump\*.dmp) or a kernel dump - the
    header layout is the same.
    """
    out = {"path": path, "bugcheck_code": None, "bugcheck_name": None, "parameters": [],
           "signature": None, "error": None}
    try:
        with open(path, "rb") as fh:
            head = fh.read(0x2000)
    except OSError as exc:
        out["error"] = str(exc)
        return out
    if len(head) < 0x60:
        out["error"] = "dump too small to hold a header"
        return out
    import struct
    try:
        out["signature"] = head[0:8].decode("latin-1", "replace").rstrip("\x00")
        code = struct.unpack_from("<I", head, 0x38)[0]
        params = list(struct.unpack_from("<4Q", head, 0x40))
    except struct.error as exc:
        out["error"] = str(exc)
        return out
    out["bugcheck_code"] = code
    out["bugcheck_name"] = BUGCHECK_NAMES.get(code)
    out["parameters"] = [hex(p) for p in params if p]
    out["bsod_suspected"] = code not in (0, None)
    return out


def detect(text: str) -> dict:
    """Scan text for guest-crash signatures."""
    matches = []
    if text:
        for line in text.splitlines():
            for rx, sev, label in _COMPILED:
                if rx.search(line):
                    matches.append({"pattern": label, "severity": sev, "line": line.strip()[:300]})
    severity = "none"
    for m in matches:
        if _SEVERITY_ORDER[m["severity"]] > _SEVERITY_ORDER[severity]:
            severity = m["severity"]
    # dedupe by (pattern, line)
    seen = set()
    uniq = []
    for m in matches:
        key = (m["pattern"], m["line"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(m)
    return {"bsod_suspected": severity == "hit", "matches": uniq, "severity": severity}


def scan_file(path: str, max_bytes: int = 400_000) -> dict:
    """detect() over a file. Missing/unreadable file -> clean result, never raises."""
    if not path or not os.path.isfile(path):
        return {"bsod_suspected": False, "matches": [], "severity": "none",
                "path": path, "error": "not found"}
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            if size > max_bytes:
                fh.seek(max(0, size - max_bytes))
            raw = fh.read(max_bytes)
        text = raw.decode("utf-8", "replace")
    except OSError as exc:
        return {"bsod_suspected": False, "matches": [], "severity": "none",
                "path": path, "error": str(exc)}
    out = detect(text)
    out["path"] = path
    out["bytes_scanned"] = min(size, max_bytes)
    return out


def main(argv=None):
    import json
    import sys
    args = list(argv if argv is not None else sys.argv[1:])
    if not args:
        print("usage: python3 -m sandbox.bsod <file> [...]")
        return 2
    for p in args:
        print(json.dumps(scan_file(p), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
