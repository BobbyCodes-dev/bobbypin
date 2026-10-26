"""Anti-analysis detection: is there debug protection, and what does it do?

Two questions, one report:

  1. **Is there debug / analysis protection?** Import names, byte patterns and
     strings that only show up when a program is checking whether it is being
     watched - IsDebuggerPresent, the PEB checks, `NtQueryInformationProcess` with
     ProcessDebugPort, exception-based tricks, RDTSC timing, hypervisor and VM
     artefacts, self-integrity hashing.

  2. **What does it do when it trips?** This is the part that matters operationally.
     A licence check that exits is an inconvenience; one that forces a bugcheck
     takes the machine with it. The response is inferred from the APIs and strings
     that are present, and cross-checked against the observed outcome when the
     binary is run in the sandbox (see `sandbox.bsod` for the guest-side detection).

Static inference is inference: a program can carry a bugcheck path it never takes.
That is why `report["response"]["inferred"]` and the sandbox's observed outcome are
reported separately rather than collapsed into one claim.

Everything here is stdlib and operates on bytes plus an optional parsed PE dict from
`bobbypin.parse_pe`.
"""

from __future__ import annotations

import re

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Checks the target performs on its environment
# ---------------------------------------------------------------------------
# `apis` match import names, `bytes` are hex patterns in the file image,
# `strings` match ASCII substrings. `where` is filled in when reported.

CHECKS = [
    # -- directly asks the OS whether a debugger is attached ------------------
    {"id": "is_debugger_present", "family": "debugger_detect", "severity": "high",
     "apis": ["IsDebuggerPresent"],
     "why": "reads PEB.BeingDebugged - the single most common check"},
    {"id": "check_remote_debugger", "family": "debugger_detect", "severity": "high",
     "apis": ["CheckRemoteDebuggerPresent"],
     "why": "DebugPort check on any process handle"},
    {"id": "nt_query_information_process", "family": "debugger_detect", "severity": "high",
     "apis": ["NtQueryInformationProcess", "ZwQueryInformationProcess"],
     "why": "ProcessDebugPort (7) / ProcessDebugObjectHandle (0x1e) / ProcessDebugFlags (0x1f)"},
    {"id": "nt_set_information_thread", "family": "debugger_detect", "severity": "high",
     "apis": ["NtSetInformationThread", "ZwSetInformationThread"],
     "why": "ThreadHideFromDebugger (0x11) detaches the thread from any debugger"},
    {"id": "nt_query_object", "family": "debugger_detect", "severity": "medium",
     "apis": ["NtQueryObject"],
     "why": "queries handle types looking for an open debug object"},
    {"id": "nt_create_thread_ex", "family": "debugger_detect", "severity": "medium",
     "apis": ["NtCreateThreadEx"],
     "why": "spawns threads with hide-from-debugger flags set"},
    {"id": "output_debug_string", "family": "debugger_detect", "severity": "medium",
     "apis": ["OutputDebugStringA", "OutputDebugStringW"],
     "why": "the classic no-real-debugger trick: GetLastError differs under a debugger"},
    {"id": "debug_event_api", "family": "debugger_detect", "severity": "medium",
     "apis": ["WaitForDebugEvent", "ContinueDebugEvent", "DebugActiveProcess",
              "DebugActiveProcessStop"],
     "why": "debugger lifecycle APIs present in a non-debugger binary"},
    {"id": "peb_being_debugged_bytes", "family": "debugger_detect", "severity": "high",
     "bytes": ["64a130000000", "648b0d30000000", "648b3d30000000"],
     "why": "direct PEB access via fs:[0x30] instead of going through the API"},
    {"id": "nt_global_flag", "family": "debugger_detect", "severity": "medium", "weak": True,
     "bytes": ["648b0d30000000648b813c0000000000", "418b80bc00000000"],
     "why": "reads PEB->NtGlobalFlag (0x68 on WOW64, 0xBC on x64)"},
    {"id": "heap_flags", "family": "debugger_detect", "severity": "medium", "weak": True,
     "bytes": ["8b4118", "8b4170"],
     "why": "heap Flags / ForceFlags at PEB->ProcessHeap (noisy on its own)"},

    # -- debug register / hardware breakpoint checks --------------------------
    {"id": "thread_context", "family": "hardware_breakpoint", "severity": "high",
     "apis": ["GetThreadContext", "SetThreadContext"],
     "why": "reads CONTEXT_DEBUG_REGISTERS looking for hardware breakpoints"},
    {"id": "unhandled_exception_filter", "family": "exception_based", "severity": "high", "weak": True,
     "apis": ["SetUnhandledExceptionFilter", "UnhandledExceptionFilter"],
     "why": "the classic exception-based anti-debug: no debugger means the filter runs"},
    {"id": "vectored_exception_handler", "family": "exception_based", "severity": "medium", "weak": True,
     "apis": ["RtlAddVectoredExceptionHandler", "AddVectoredExceptionHandler"],
     "why": "VEH used to catch the deliberately raised exception"},
    {"id": "raise_exception", "family": "exception_based", "severity": "medium", "weak": True,
     "apis": ["RaiseException"],
     "why": "raises an exception and notices whether a debugger eats it"},
    {"id": "closehandle_trick", "family": "debugger_detect", "severity": "medium", "weak": True,
     "apis": ["CloseHandle", "GetLastError"],
     "why": "invalid-handle trick (0xDEADC0DE) - only fails without a debugger present (noisy)"},

    # -- timing checks -------------------------------------------------------
    {"id": "timing_apis", "family": "timing", "severity": "medium", "weak": True,
     "apis": ["QueryPerformanceCounter", "GetTickCount", "GetTickCount64",
              "timeGetTime", "NtQuerySystemTime", "QueryPerformanceFrequency"],
     "why": "measures elapsed time to spot debugger/single-step slowdown"},
    {"id": "rdtsc", "family": "timing", "severity": "medium",
     "bytes": ["0f31"],
     "why": "raw timestamp counter - the lowest-level timing check"},
    {"id": "sleep_timing", "family": "timing", "severity": "low", "weak": True,
     "apis": ["Sleep", "SleepEx"],
     "why": "sleep-and-compare loops (very common, low signal on its own)"},

    # -- environment / VM / sandbox artefacts ---------------------------------
    {"id": "vm_artifacts", "family": "anti_vm", "severity": "medium",
     "strings": ["vmware", "vbox", "virtualbox", "vboxservice", "vboxguest",
                 "vmtoolsd", "vmmouse", "vmci", "qemu", "qemuwmi", "xen",
                 "hyper-v", "virtual hd", "vmware tools"],
     "why": "looks for virtualisation artefacts in devices, registry or driver names"},
    {"id": "sandbox_artifacts", "family": "anti_vm", "severity": "high",
     "strings": ["sbiedll", "sandboxie", "cuckoo", "sandbox", "wireshark",
                 "procmon", "procexp", "x64dbg", "ollydbg", "windbg",
                 "scylla", "idaq", "ghidra", "frida"],
     "why": "looks for analysis tooling by name - strong signal in a shipped product"},
    {"id": "wine_detection", "family": "anti_vm", "severity": "high",
     "strings": ["wine_get_version", "wine_get_unix_file_name", "wineserver",
                 "winelib", "wine_ntdll"],
     "why": "detects wine specifically - relevant because the sandbox runs PE targets "
            "under wine, so this check will fire there"},
    {"id": "cpuid_hypervisor", "family": "anti_vm", "severity": "medium", "weak": True,
     "bytes": ["0fa2"],
     "why": "CPUID with leaf 0x40000000 exposes the hypervisor vendor (approx: any cpuid)"},

    # -- self-integrity / tamper detection -----------------------------------
    {"id": "self_map", "family": "integrity", "severity": "medium", "weak": True,
     "apis": ["CreateFileMappingA", "CreateFileMappingW", "MapViewOfFile",
              "NtQueryVirtualMemory", "VirtualQuery"],
     "why": "maps or inspects its own image, typically to hash it"},
    {"id": "self_modify", "family": "integrity", "severity": "medium", "weak": True,
     "apis": ["VirtualProtect", "VirtualProtectEx", "WriteProcessMemory",
              "FlushInstructionCache"],
     "why": "changes its own or another process's memory - packing, unpacking or patching"},
    {"id": "crc_table", "family": "integrity", "severity": "medium", "weak": True,
     "bytes": ["2083b8ed", "edb88320"],
     "why": "CRC-32 polynomial constant - a checksum routine is present"},
    {"id": "integrity_strings", "family": "integrity", "severity": "medium", "weak": True,
     "strings": ["integrity", "checksum", "tamper", "self-check", "modified",
                 "corrupted", "reinstall"],
     "why": "error text that reads like a tamper response"},
    {"id": "self_path_lookup", "family": "integrity", "severity": "low", "weak": True,
     "apis": ["GetModuleFileNameA", "GetModuleFileNameW", "GetModuleHandleA"],
     "why": "opens or inspects its own file path (noisy on its own)"},
]

# ---------------------------------------------------------------------------
# What it does when it trips
# ---------------------------------------------------------------------------
# severity ordering decides the headline response when several are present.

RESPONSES = [
    {"id": "deliberate_bsod", "severity": "critical",
     "label": "deliberate BSOD (bugcheck)",
     "apis": ["NtRaiseHardError", "ZwRaiseHardError", "KeBugCheckEx",
              "RtlSetProcessIsCritical", "NtSetSystemInformation"],
     "strings": ["shutdownsystem", "bugcheck", "0x000000ce", "0xc0000218",
                 "\\device\\physicalmemory", "\\\\.\\physicalmemory", "ntoskrnl"],
     "explain": "NtRaiseHardError with ResponseOption 6 (ShutdownSystem) forces an "
                "immediate bugcheck; RtlSetProcessIsCritical(TRUE) then exiting does the "
                "same by killing a critical process. The machine goes down, not just the "
                "process."},
    {"id": "wipe_or_encrypt", "severity": "critical",
     "label": "destroys or encrypts data",
     "apis": ["CryptEncrypt", "CryptGenKey", "CryptAcquireContextA", "CryptAcquireContextW",
              "FindFirstFileA", "FindFirstFileW", "MoveFileExA", "MoveFileExW"],
     "strings": ["decrypt", "encrypted", "ransom", "your files"],
     "explain": "file enumeration plus crypto or delayed-delete primitives - the shape of "
                "a destructive or ransom response. Treat the target as hostile."},
    {"id": "reboot_or_shutdown", "severity": "high",
     "label": "reboots or powers off the machine",
     "apis": ["ExitWindowsEx", "InitiateSystemShutdownA", "InitiateSystemShutdownW",
              "InitiateSystemShutdownExA", "InitiateSystemShutdownExW", "NtShutdownSystem",
              "NtSetSystemPowerState"],
     "strings": ["shutdown /r", "shutdown -r", "shutdown.exe"],
     "explain": "needs SeShutdownPrivilege, which most installs grant, so this usually "
                "works. A clean reboot rather than a bugcheck."},
    {"id": "self_delete", "severity": "high",
     "label": "deletes itself or its install",
     "apis": ["DeleteFileA", "DeleteFileW", "MoveFileExA", "MoveFileExW"],
     "strings": ["cmd /c del", "cmd.exe /c del", "ping -n", "del /f", "selfdestruct"],
     "explain": "removes its own binary (often via a delayed delete) so the evidence does "
                "not survive. Re-running the analysis then fails for a different reason."},
    {"id": "corrupt_state", "severity": "high",
     "label": "corrupts files or registry state",
     "apis": ["RegSetValueExA", "RegSetValueExW", "RegDeleteKeyA", "RegDeleteKeyW",
              "RegDeleteValueA", "RegDeleteValueW", "WriteFile", "SetFileAttributesA"],
     "strings": ["tamper", "corrupt", "invalid licence", "licence destroyed"],
     "explain": "writes a broken state so the product stops working, rather than refusing "
                "to start."},
    {"id": "process_exit", "severity": "medium",
     "label": "exits the process",
     "apis": ["ExitProcess", "TerminateProcess", "RtlExitUserProcess", "ExitThread"],
     "explain": "the polite version: the target just quits. Also the most common response "
                "to a licence check failing."},
    {"id": "hang_or_sleep", "severity": "medium",
     "label": "hangs or stalls",
     "apis": ["SuspendThread", "NtSuspendThread"],
     "strings": ["please wait", "initialising", "initializing"],
     "explain": "stops responding so nothing looks like an error - reads as a hang in the "
                "sandbox (the run reports timed_out)."},
    {"id": "nag_dialog", "severity": "low",
     "label": "shows a nag / refusal dialog",
     "apis": ["MessageBoxA", "MessageBoxW", "MessageBoxExA", "MessageBoxExW"],
     "strings": ["debugger", "not allowed", "purchase", "buy now", "please close",
                 "unsupported", "contact support"],
     "explain": "tells the user off and carries on. The least destructive response, and the "
                "most common in shareware."},
]

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Packer / obfuscator section names and strings (extends detect_packers, which
# only knows about PyInstaller/AutoIt/NSIS/Inno/Go/UPX).
OBFUSCATOR_SECTIONS = {
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".themida": "Themida", ".winlice": "Themida/WinLicense",
    ".enigma1": "Enigma", ".enigma2": "Enigma",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".petite": "Petite", ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".pklstb": "PKLite", ".packed": "generic packer", ".upx0": "UPX", ".upx1": "UPX",
}
OBFUSCATOR_STRINGS = {
    "confuserex": ".NET: ConfuserEx",
    "confuser": ".NET: Confuser",
    "eazfuscator": ".NET: Eazfuscator",
    "smartassembly": ".NET: SmartAssembly",
    ".net reactor": ".NET: .NET Reactor", "netreactor": ".NET: .NET Reactor",
    "dotfuscator": ".NET: Dotfuscator",
    "themida": "Themida", "winlicense": "Themida/WinLicense",
    "vmprotect": "VMProtect", "enigma protector": "Enigma", "obsidium": "Obsidium",
    "molebox": "MoleBox", "ilprotector": ".NET: ILProtector",
    "agile.net": ".NET: Agile.NET",
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _hexbytes(pattern: str) -> bytes:
    return bytes.fromhex(pattern)


def _import_index(pe: dict) -> dict:
    """lowercase function name -> dll, so evidence can name where it was seen."""
    index = {}
    for entry in (pe or {}).get("imports", []):
        dll = entry.get("dll", "")
        for fn in entry.get("functions", []):
            index.setdefault(fn.lower(), dll)
    return index


def _find_all(haystack: bytes, needle: bytes, limit: int = 8) -> list:
    out, start = [], 0
    while len(out) < limit:
        i = haystack.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def _strings_blob(data: bytes, min_len: int = 5, limit: int = 200000) -> str:
    """Printable strings, lowercased, for substring matching.

    Only used for matching, never echoed back wholesale - a target's own strings can
    be long and noisy, and dumping them adds nothing to the finding.
    """
    chunks = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data[:limit])
    return b"\n".join(chunks).decode("latin-1").lower()


# ---------------------------------------------------------------------------
# the analysis
# ---------------------------------------------------------------------------

def analyse(data: bytes, pe: dict | None = None) -> dict:
    """Static anti-analysis report. Never raises on odd input."""
    imports = _import_index(pe or {})
    strings = _strings_blob(data)

    indicators = []
    families = set()
    for check in CHECKS:
        evidence = None
        where = None
        for api in check.get("apis", []):
            if api.lower() in imports:
                evidence = "%s (imported from %s)" % (api, imports[api.lower()] or "?")
                where = "import"
                break
            if api.lower() in strings:
                # resolved at runtime via GetProcAddress, so it is in the strings only
                evidence = "%s (resolved at runtime - name is a string, not an import)" % api
                where = "string"
                break
        if evidence is None:
            for pattern in check.get("bytes", []):
                hits = _find_all(data, _hexbytes(pattern), limit=1)
                if hits:
                    evidence = "byte pattern %s @ file offset %#x" % (pattern, hits[0])
                    where = "bytes"
                    break
        if evidence is None:
            for needle in check.get("strings", []):
                if needle in strings:
                    evidence = "string %r" % needle
                    where = "string"
                    break
        if evidence is None:
            continue
        families.add(check["family"])
        indicators.append({
            "id": check["id"],
            "family": check["family"],
            "severity": check["severity"],
            "weak": bool(check.get("weak")),
            "where": where,
            "evidence": evidence,
            "why": check.get("why", ""),
        })

    indicators.sort(key=lambda i: -SEVERITY_ORDER[i["severity"]])

    debug_families = {"debugger_detect", "hardware_breakpoint", "exception_based",
                      "timing", "integrity"}
    debug_indicators = [i for i in indicators if i["family"] in debug_families]
    vm_indicators = [i for i in indicators if i["family"] == "anti_vm"]

    # Noisy checks (Sleep, GetModuleFileName, CloseHandle+GetLastError, heap flags) are
    # present in almost every normal program. They may corroborate, but a lone noisy hit
    # must not make the report cry "debug protection detected".
    strong = [i for i in debug_indicators if not i.get("weak")]
    noisy = [i for i in debug_indicators if i.get("weak")]

    score = sum(SEVERITY_ORDER[i["severity"]] for i in strong)
    has_primitive = any(i["severity"] in ("high", "critical") for i in strong)
    if score >= 8 or (has_primitive and len(strong) >= 2):
        confidence = "high"
    elif score >= 3:
        confidence = "medium"
    elif strong:
        confidence = "low"
    else:
        confidence = "none"

    report = {
        "debug_protection": {
            "detected": bool(strong),
            "confidence": confidence,
            "score": score,
            "families": sorted({i["family"] for i in strong}),
            "indicators": strong,
            "corroborating": noisy,
        },
        "anti_vm": {
            "detected": bool(vm_indicators),
            "indicators": vm_indicators,
        },
        "obfuscation": _obfuscation(pe, strings),
        # only the unambiguous indicators can create a trigger; a weak/noisy signal
        # (a CRT-imported SetUnhandledExceptionFilter, say) is not a check
        "response": _response(data, pe, imports, strings, strong + vm_indicators),
        "notes": [],
    }

    if not indicators:
        report["notes"].append("no anti-analysis indicators found")
    elif not strong and noisy:
        report["notes"].append(
            "only noisy signals (%s) - common in normal programs, not counted as debug "
            "protection" % ", ".join(i["id"] for i in noisy))
    elif not debug_indicators:
        report["notes"].append("no debug protection found; only environment checks")
    if report["anti_vm"]["detected"] and any(
            i["id"] == "wine_detection" for i in vm_indicators):
        report["notes"].append(
            "target detects wine: it will notice the sandbox and its behaviour there may "
            "differ from real Windows - treat an in-sandbox result as a lower bound")
    return report


def _obfuscation(pe: dict | None, strings: str) -> dict:
    sections = []
    for sec in (pe or {}).get("sections", []):
        name = (sec.get("name") or "").lower()
        if name in OBFUSCATOR_SECTIONS:
            sections.append({"section": sec.get("name"), "product": OBFUSCATOR_SECTIONS[name]})
    found = []
    for needle, product in OBFUSCATOR_STRINGS.items():
        if needle in strings and product not in [f["product"] for f in found]:
            found.append({"string": needle, "product": product})
    return {"detected": bool(sections or found), "sections": sections, "matches": found}


def _response(data: bytes, pe: dict | None, imports: dict, strings: str,
              debug_indicators: list) -> dict:
    """Infer what the protection does when it fires.

    Deliberately explicit that this is inference: presence of a bugcheck path is not
    proof the target takes it. The sandbox reports what actually happened.
    """
    candidates = []
    for resp in RESPONSES:
        evidence = []
        for api in resp.get("apis", []):
            if api.lower() in imports:
                evidence.append("%s (import)" % api)
            elif api.lower() in strings:
                evidence.append("%s (resolved at runtime)" % api)
        for needle in resp.get("strings", []):
            if needle in strings:
                evidence.append("string %r" % needle)
        if evidence:
            candidates.append({
                "id": resp["id"],
                "label": resp["label"],
                "severity": resp["severity"],
                "explain": resp.get("explain", ""),
                "evidence": evidence,
            })
    candidates.sort(key=lambda c: -SEVERITY_ORDER[c["severity"]])

    # A bugcheck path in a program with no protection has no trigger, so reporting it as
    # "on trigger: BSOD" would be a lie. Only headline the response when something is
    # actually checking the environment.
    trigger_exists = bool(debug_indicators) or any(
        i["id"] in ("vm_artifacts", "sandbox_artifacts", "wine_detection")
        for i in debug_indicators) or bool((pe or {}).get("_anti_vm"))
    primary = None
    if candidates and trigger_exists:
        primary = candidates[0]
        if primary["id"] == "deliberate_bsod" and debug_indicators:
            primary = dict(primary)
            primary["explain"] = (
                "debug protection is present AND a bugcheck path is present: if the "
                "debugger/integrity check fires, the machine goes down rather than the "
                "process. " + primary["explain"])

    return {
        "inferred": primary["id"] if primary else None,
        "label": primary["label"] if primary else None,
        "severity": primary["severity"] if primary else "none",
        "evidence": primary["evidence"] if primary else [],
        "explain": primary["explain"] if primary else "",
        "alternatives": candidates[1:],
        "capabilities": candidates,
        "trigger_present": bool(trigger_exists),
        "confidence": "medium" if primary else "none",
        "basis": "static inference - the sandbox reports the observed outcome separately",
        "note": ("" if primary else
                 "no analysis check or tamper check found, so there is nothing for a "
                 "refusal path to fire from; any crash would be a plain bug, not protection"),
    }


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def summarize(report: dict) -> list:
    """Human lines for the CLI and the AI layer's `verdict`."""
    lines = []
    dp = report.get("debug_protection", {})
    if dp.get("detected"):
        lines.append("debug protection: DETECTED (%s confidence, %d indicator%s)" % (
            dp.get("confidence"), len(dp.get("indicators", [])),
            "" if len(dp.get("indicators", [])) == 1 else "s"))
        for ind in dp.get("indicators", [])[:6]:
            lines.append("  - %s [%s] - %s" % (ind["id"], ind["where"], ind["why"]))
        if len(dp.get("indicators", [])) > 6:
            lines.append("  ... and %d more" % (len(dp["indicators"]) - 6))
    else:
        lines.append("debug protection: none detected")

    corr = dp.get("corroborating") or []
    if corr and not dp.get("detected"):
        lines.append("noisy-only signals ignored: %s" % ", ".join(i["id"] for i in corr))
    elif corr:
        lines.append("corroborating (noisy) signals: %s" % ", ".join(i["id"] for i in corr))

    resp = report.get("response", {})
    if resp.get("inferred"):
        lines.append("on trigger: %s%s - %s" % (
            resp["label"].upper(), "" if resp["severity"] == "low" else " [%s]" % resp["severity"],
            resp["explain"]))
        for alt in resp.get("alternatives", [])[:3]:
            lines.append("  also possible: %s" % alt["label"])
    elif resp.get("capabilities"):
        lines.append("on trigger: nothing to fire - no analysis check found, so the "
                     "refusal paths present (%s) have no trigger; a crash would be a "
                     "plain bug" % ", ".join(c["label"] for c in resp["capabilities"][:2]))
    else:
        lines.append("on trigger: no refusal or crash path identified")

    vm = report.get("anti_vm", {})
    if vm.get("detected"):
        lines.append("anti-VM/sandbox: %d indicator%s (%s)" % (
            len(vm["indicators"]), "" if len(vm["indicators"]) == 1 else "s",
            ", ".join(i["id"] for i in vm["indicators"][:4])))

    ob = report.get("obfuscation", {})
    if ob.get("detected"):
        products = sorted({s["product"] for s in ob.get("sections", [])} |
                          {m["product"] for m in ob.get("matches", [])})
        lines.append("obfuscation: %s" % ", ".join(products))
    return lines


def main(argv=None):
    import json
    import sys
    args = list(argv if argv is not None else sys.argv[1:])
    if not args:
        print("usage: python3 -m antianalysis <target.exe> [--json]")
        return 2
    path = args[0]
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        import bobbypin as bp
        pe = bp.parse_pe(data)
    except Exception:
        pe = None
    report = analyse(data, pe)
    if "--json" in args:
        print(json.dumps(report, indent=2))
    else:
        for line in summarize(report):
            print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
