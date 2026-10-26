#!/usr/bin/env python3
"""antidebug_patch.py - detect a target's debug protection, then patch it out of the way.

antianalysis.py answers "what does this binary check, and what does it do when the check
fires?". This answers the next question: "can that be neutralised - and did it work?".

The classes below are different problems, so they are not treated identically. Only the
one whose semantics are unambiguous is patched automatically; the rest are reported.

  A. A detection API reached through the import table (IsDebuggerPresent,
     CheckRemoteDebuggerPresent). The *call* produces the verdict, and the verdict is a
     BOOLEAN in EAX where 0 == "nothing found". Replacing the call with `xor eax, eax`
     makes the check report clean whatever the environment says, and it does not matter
     how the caller tests the result or which branch it takes. AUTOMATIC.

  A2. NtQueryInformationProcess, where the return value is NOT the answer. It returns
     NTSTATUS (0 == the query SUCCEEDED) and puts the verdict in the out buffer, so zeroing
     EAX alone would tell the caller "the query worked" and it would then read whatever the
     buffer already held. The InfoClass decides whether anything can be forced at all:
     ProcessDebugPort (7) and ProcessDebugObjectHandle (0x1e) answer 0 for "nothing found",
     and the six-byte call slot can be rewritten as `xor eax,eax` + `and qword ptr [r8], 0`
     - STATUS_SUCCESS plus a zeroed out buffer. AUTOMATIC, but only when the class can be
     read from the instruction stream in front of the call (capstone, x64, immediate class).

     ProcessDebugFlags (0x1f) is a debug check and is still refused: it reports the INVERSE
     of BeingDebugged, so its clean value is 1, and 1 plus a success status does not fit in
     six bytes without relocating code. Any other InfoClass is refused too - the out buffer
     of a non-debug query is a PEB pointer, a size or a struct the caller goes on to use.

  B. A detection API resolved at runtime through GetProcAddress. The name is a string, the
     call site is indirect (`call rax`), and there is no import slot to rewrite. Reported,
     not patched - a patch here would be a guess about which indirect call is the check.

  C. A direct PEB read (`mov eax, fs:[0x30]`). Zeroing EAX is NOT the fix: the following
     instructions dereference it (`[eax+2]` is BeingDebugged), so a nulled base pointer
     turns a false positive into an access violation. Reported, not patched.

  D. Timing checks (rdtsc, QueryPerformanceCounter), integrity self-checks and anti-VM
     probes. Neutralising those means rewriting arithmetic or hiding the environment,
     not replacing a call. Reported, not patched.

  E. The rest of the verdict APIs that are not BOOLEAN-returning: NtQueryObject (NTSTATUS,
     answer in the object information), OutputDebugString and the CloseHandle trick (the tell
     is GetLastError, not the return value), GetThreadContext (writes a whole CONTEXT).
     Reported, not patched.

Every automatic patch preserves instruction length (`xor eax,eax` + NOP padding, or `xor
eax,eax` + `and qword ptr [r8], 0`), so no offset in the file moves and no other patch has to
be relocated.

Never in place: `out` must be a different file. The original is the evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# what can be patched automatically, and what each patch means
# ---------------------------------------------------------------------------
# antianalysis indicator id -> how it is neutralised.
#
# kind: how the 6-byte call slot is rewritten.
#   "boolean_zero" - the API's BOOLEAN return is the verdict, and 0 means "nothing found".
#                    `xor eax,eax` padded with NOPs. The caller's own test or branch does
#                    not have to be touched, because the answer itself becomes truthful.
#   "ntqip_clean_zero" - NtQueryInformationProcess writes its verdict into the out buffer
#                    and returns NTSTATUS. The InfoClass has to be read first; only the
#                    classes whose clean answer is 0 can be forced.
AUTO = {
    "is_debugger_present": {
        "apis": ("isdebuggerpresent",),
        "kind": "boolean_zero",
        "why": "returns BOOL from PEB.BeingDebugged; 0 is a truthful 'no debugger' answer, so "
               "the caller's own test/branch decides correctly without being touched",
    },
    "check_remote_debugger": {
        "apis": ("checkremotedebuggerpresent",),
        "kind": "boolean_zero",
        "why": "returns BOOL and writes BOOL*; the out-parameter keeps the value the caller "
               "initialised it with (that is how the idiom is written), and the return value "
               "goes to 0",
    },
    "nt_query_information_process": {
        "apis": ("ntqueryinformationprocess", "zwqueryinformationprocess"),
        "kind": "ntqip_clean_zero",
        "why": "returns NTSTATUS with the verdict in the out buffer, so the InfoClass decides "
               "whether this is patchable at all - see CLEAN_ZERO_CLASSES",
    },
}

# InfoClasses whose answer means "nothing found" when it is 0. These are the only ones the
# out buffer can be zeroed for: NtQueryInformationProcess is used for a lot that has nothing
# to do with debuggers, and zeroing a struct the caller reads as a pointer or a length would
# turn a patch into a bug.
CLEAN_ZERO_CLASSES = {
    7: ("ProcessDebugPort", "the out slot is a ULONG_PTR where 0 means no debug port"),
    0x1E: ("ProcessDebugObjectHandle", "the out slot is a handle where 0 means no debug object"),
}

# Classes that ARE debug checks but cannot be forced length-preservingly, with the reason.
INVERTED_CLASSES = {
    0x1F: ("ProcessDebugFlags", "the answer is the INVERSE of PEB.BeingDebugged, so the clean "
                                "value is 1, not 0. Writing 1 plus a success status does not "
                                "fit in the 6 bytes of the call slot, and stretching it would "
                                "mean relocating code - so it is reported, not forced"),
}

# indicator id -> why this one is deliberately NOT auto-patched
MANUAL = {
    "nt_query_object":
        "NTSTATUS in EAX, verdict in the object information written by the call",
    "nt_set_information_thread":
        "ThreadHideFromDebugger is a side effect, not a return value - there is no verdict "
        "to force",
    "nt_create_thread_ex": "the hide-from-debugger flag is an argument, not a result",
    "output_debug_string":
        "the tell is GetLastError, not the return value - zeroing EAX does nothing",
    "closehandle_trick":
        "the tell is GetLastError (0xDEADC0DE), not the return value",
    "debug_event_api":
        "presence of the debugger lifecycle APIs is the signal; there is no BOOL to force",
    "thread_context":
        "GetThreadContext / SetThreadContext move a CONTEXT struct, and the debug-register "
        "check reads DR0-DR7 out of that struct",
    "unhandled_exception_filter":
        "exception-based: the filter firing IS the flow. Skipping the raise changes which "
        "path runs instead of forcing a verdict",
    "vectored_exception_handler": "exception-based, same as the filter",
    "raise_exception": "exception-based: the deliberate raise must happen for the check to work",
    "peb_being_debugged_bytes":
        "direct PEB read. The load must be neutralised AFTER the base pointer is "
        "established (the next instructions dereference it), so the instruction sequence "
        "has to be decoded, not the call replaced",
    "nt_global_flag":
        "PEB->NtGlobalFlag is read as data; needs the same treatment as a direct PEB read",
    "heap_flags":
        "heap Flags/ForceFlags read as data; noisy on its own and needs the same treatment",
    "timing_apis": "needs the elapsed-time arithmetic rewritten, not a call replaced",
    "rdtsc": "needs the timestamp delta rewritten, not a call replaced",
    "sleep_timing": "needs the sleep-and-compare rewritten",
    "cpuid_hypervisor": "anti-VM: needs the hypervisor bit masked after CPUID, not a call replaced",
    "self_map": "integrity: it hashes its own image; suppressing the call changes nothing",
    "self_modify": "integrity: self-patching primitives are how it checks itself",
    "crc_table": "integrity: a checksum routine exists, but the comparison is the check",
    "integrity_strings": "tamper-response text only - no code to patch",
    "self_path_lookup": "reads its own path; noisy on its own and not a debugger check",
    "vm_artifacts": "anti-VM: the environment has to be hidden, not the call replaced",
    "sandbox_artifacts": "anti-VM: the environment has to be hidden, not the call replaced",
    "wine_detection": "anti-VM: the environment has to be hidden, not the call replaced",
}


# ---------------------------------------------------------------------------
# small PE helpers (kept local so this module stands on its own and is testable)
# ---------------------------------------------------------------------------

def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def u64(d, o):
    return struct.unpack_from("<Q", d, o)[0]


def read_cstr(d, o, limit=256):
    end = d.find(b"\x00", o, o + limit)
    if end < 0:
        end = min(len(d), o + limit)
    return d[o:end].decode("latin-1", "replace")


def rva2off(sections, rva):
    for sec in sections:
        span = max(sec["vsize"], sec["rawsize"])
        if sec["va"] <= rva < sec["va"] + span:
            return sec["raw"] + (rva - sec["va"])
    return None


def off2rva(sections, off):
    for sec in sections:
        if sec["raw"] <= off < sec["raw"] + sec["rawsize"]:
            return sec["va"] + (off - sec["raw"])
    return None


def exec_ranges(pe):
    """(start, end) file offsets of sections that carry code."""
    out = []
    for sec in pe["sections"]:
        if sec["chars"] & 0x20000000 and sec["rawsize"]:
            out.append((sec["raw"], sec["raw"] + sec["rawsize"]))
    return out


# ---------------------------------------------------------------------------
# the import table, resolved to slot addresses
# ---------------------------------------------------------------------------

def iat_slots(data, pe):
    """API name (lowercase) -> list of IAT slot VAs, plus the IAT's VA span.

    The span matters: it is what turns a raw `FF 15` hit into a real call site, because
    a random pair of bytes almost never computes an address inside the import table.
    """
    pe_off = u32(data, 0x3C)
    opt = pe_off + 24
    plus = pe["pe32plus"]
    dirs_off = opt + (112 if plus else 96)
    num_dirs = u32(data, opt + (108 if plus else 92))
    if num_dirs < 2:
        return {}, None
    imp_rva = u32(data, dirs_off + 8)
    if not imp_rva:
        return {}, None

    sections = pe["sections"]
    imagebase = pe["imagebase"]
    step = 8 if plus else 4
    high = 1 << (63 if plus else 31)
    mask = (1 << 64) - 1 if plus else (1 << 32) - 1

    slots = {}
    lows, highs = [], []
    off = rva2off(sections, imp_rva)
    seen = 0
    while off is not None and off + 20 <= len(data) and seen < 4096:
        oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, off)
        if oft == 0 and name_rva == 0 and ft == 0:
            break
        seen += 1
        names_off = rva2off(sections, oft or ft)
        i = 0
        while names_off is not None and i < 65536:
            p = names_off + i * step
            if p + step > len(data):
                break
            val = u64(data, p) & mask if plus else u32(data, p)
            if val == 0:
                break
            slot_va = imagebase + ft + i * step
            if not (val & high):
                h = rva2off(sections, val)
                if h is not None:
                    name = read_cstr(data, h + 2).lower()
                    if name:
                        slots.setdefault(name, []).append(slot_va)
            lows.append(slot_va)
            highs.append(slot_va + step)
            i += 1
        off += 20

    if not lows:
        return {}, None
    return slots, (min(lows), max(highs))


# ---------------------------------------------------------------------------
# call sites
# ---------------------------------------------------------------------------

def _decode_available():
    try:
        import capstone  # noqa: F401
    except ImportError:
        return False
    return True


def find_call_sites(data, pe, slots, span):
    """Every `call [<IAT slot>]` in the code, with the API it lands on.

    capstone when it is installed, so the instruction boundary and length are decoded
    rather than assumed. Without it a structural scan of `FF 15` is used with the same
    strict filter (the computed address must land in the import table), and the method is
    reported so the caller knows which one produced the answer.
    """
    if not slots or not span:
        return [], "none"
    va_to_api = {}
    for api, vas in slots.items():
        for va in vas:
            va_to_api[va] = api

    sections = pe["sections"]
    imagebase = pe["imagebase"]
    plus = pe["pe32plus"]
    sites = []

    if _decode_available():
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86,
                         capstone.CS_MODE_64 if plus else capstone.CS_MODE_32)
        md.detail = True
        for start, end in exec_ranges(pe):
            for insn in md.disasm(data[start:end], imagebase + (off2rva(sections, start) or 0)):
                if insn.mnemonic != "call" or len(insn.operands) != 1:
                    continue
                op = insn.operands[0]
                if op.type != capstone.x86.X86_OP_MEM:
                    continue
                m = op.mem
                if plus:
                    if m.base != capstone.x86.X86_REG_RIP:
                        continue
                    target = insn.address + insn.size + m.disp
                else:
                    if m.base != 0 or m.index != 0:
                        continue
                    target = m.disp & 0xFFFFFFFF
                api = va_to_api.get(target)
                if api:
                    off = (insn.address - imagebase) - (off2rva(sections, start) or 0) + start
                    sites.append({"api": api, "va": insn.address, "offset": off,
                                  "size": insn.size, "bytes": data[off:off + insn.size].hex()})
        return _dedupe(sites), "capstone"

    for start, end in exec_ranges(pe):
        blob = data[start:end]
        i = 0
        while True:
            i = blob.find(b"\xff\x15", i)
            if i < 0 or i + 6 > len(blob):
                break
            off = start + i
            disp = u32(data, off + 2)
            if plus:
                insn_va = imagebase + (off2rva(sections, off) or 0)
                target = (insn_va + 6 + struct.unpack("<i", struct.pack("<I", disp))[0]) & ((1 << 64) - 1)
            else:
                target = disp
            api = va_to_api.get(target)
            if api:
                sites.append({"api": api, "va": imagebase + (off2rva(sections, off) or 0),
                              "offset": off, "size": 6, "bytes": data[off:off + 6].hex()})
            i += 2
    return _dedupe(sites), "structural"


def _dedupe(sites):
    out, seen = [], set()
    for s in sorted(sites, key=lambda s: s["offset"]):
        if s["offset"] in seen:
            continue
        seen.add(s["offset"])
        out.append(s)
    return out


# ---------------------------------------------------------------------------
# plan / apply
# ---------------------------------------------------------------------------

def _forced_clean_call(size):
    """`xor eax,eax` padded with NOPs to the original instruction length.

    Length-preserving on purpose: nothing after it has to move, so a patch can never
    desynchronise the rest of the file or another patch site.
    """
    if size < 2:
        raise ValueError("cannot force a return value in %d byte(s)" % size)
    return b"\x31\xc0" + b"\x90" * (size - 2)


# `xor eax,eax` + `and qword ptr [r8], 0`. Six bytes, the exact length of a `call [rip+disp]`.
# EAX becomes STATUS_SUCCESS and the out buffer the third argument points at (R8, fixed for
# every NtQueryInformationProcess call by the x64 calling convention) is zeroed, so the caller
# reads "nothing found" whether it tests the status or the buffer.
CLEAN_ZERO_CALL = b"\x31\xc0\x49\x83\x20\x00"


def _decode_ending_at(data, pe, call_off, keep=16):
    """The instructions immediately before `call_off`, or None if the call is not decodable.

    x86 is variable-length, so the bytes in front of an instruction cannot be walked
    backwards, and guessing a start offset does not work either - padding bytes decode into
    plausible one-byte instructions, so plenty of wrong alignments happen to land on the call.
    The one alignment that is not a guess is the section's own instruction stream, so the
    section is decoded forward from its start and the call has to be an instruction in it.
    If it is not (the offset is data, or the section start is not code), the answer is None and
    the caller refuses rather than guessing.
    """
    if not _decode_available() or pe is None:
        return None
    import capstone
    sections = pe["sections"]
    imagebase = pe["imagebase"]
    plus = pe["pe32plus"]
    section = None
    for sec in sections:
        if sec["raw"] <= call_off < sec["raw"] + sec["rawsize"]:
            section = sec
            break
    if section is None or not (section["chars"] & 0x20000000):
        return None
    want_off = call_off
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if plus else capstone.CS_MODE_32)
    md.detail = True
    start = section["raw"]
    va = imagebase + section["va"]
    window = []
    for insn in md.disasm(data[start:start + section["rawsize"]], va):
        off = start + (insn.address - va)
        if off == want_off:
            return window[-keep:]
        if off > want_off:
            return None          # the call sits inside another instruction: wrong alignment
        window.append(insn)
        if len(window) > keep:
            window.pop(0)
    return None


def _info_class(data, pe, call_off):
    """(class value, explanation) for an NtQueryInformationProcess call, or (None, why not).

    The InfoClass is the second argument. On x64 that is EDX, and compilers set it with an
    immediate a few instructions before the call. Anything else - a register that is computed
    at runtime, an undecodable window, a 32-bit target where the argument is on the stack -
    means the class is unknown, and an unknown class must NOT be patched: the out buffer of a
    non-debug query (a PEB pointer, a size, a struct) is data the caller goes on to use.
    """
    if pe is None or not pe["pe32plus"]:
        return None, ("not a 64-bit target, so the InfoClass argument travels on the stack and "
                      "cannot be read without tracking the stack pointer")
    if not _decode_available():
        return None, ("reading the InfoClass needs the instruction decode, and capstone is not "
                      "installed: `pip install capstone` (or run under a venv that has it)")
    insns = _decode_ending_at(data, pe, call_off)
    if insns is None:
        return None, ("could not decode the argument setup in front of the call, so the "
                      "InfoClass is unknown")
    import capstone
    writes_edx = None
    for insn in insns:
        if not insn.operands:
            continue
        dst = insn.operands[0]
        if dst.type != capstone.x86.X86_OP_REG:
            continue
        if dst.reg not in (capstone.x86.X86_REG_EDX, capstone.x86.X86_REG_RDX):
            continue
        if len(insn.operands) < 2:
            writes_edx = (None, insn)
            continue
        src = insn.operands[1]
        if insn.mnemonic.startswith("mov") and src.type == capstone.x86.X86_OP_IMM:
            writes_edx = (src.imm & 0xFFFFFFFF, insn)
        else:
            writes_edx = (None, insn)
    if writes_edx is None:
        return None, "no write to EDX found before the call, so the InfoClass is unknown"
    value, insn = writes_edx
    if value is None:
        return None, ("InfoClass is set by `%s %s`, which is not an immediate - it cannot be "
                      "known statically" % (insn.mnemonic, insn.op_str))
    return value, "InfoClass %#x set by `%s %s` at %#x" % (value, insn.mnemonic, insn.op_str,
                                                           insn.address)


def _ntqip_sites(data, pe, sites):
    """Split NtQueryInformationProcess call sites into patchable and refused, with reasons."""
    patchable, refused = [], []
    for site in sites:
        cls, note = _info_class(data, pe, site["offset"])
        base = {"id": "nt_query_information_process", "api": site["api"], "va": site["va"],
                "offset": site["offset"], "size": site["size"], "before": site["bytes"],
                "class": "E"}
        if cls is None:
            refused.append(dict(base, why="InfoClass could not be read: %s" % note))
            continue
        if site["size"] != len(CLEAN_ZERO_CALL):
            refused.append(dict(base, why="the call is %d bytes, not %d, so the status and the "
                                          "out buffer cannot both be forced without moving "
                                          "code" % (site["size"], len(CLEAN_ZERO_CALL))))
            continue
        if cls in CLEAN_ZERO_CLASSES:
            name, why = CLEAN_ZERO_CLASSES[cls]
            patchable.append({**base, "class": "A", "after": CLEAN_ZERO_CALL.hex(),
                              "why": "%s (%#x): %s. EAX is forced to STATUS_SUCCESS and the "
                                     "out buffer the call would have written is zeroed, so "
                                     "the caller reads 'nothing found' whether it tests the "
                                     "status or the buffer. %s"
                                     % (name, cls, why, note)})
        elif cls in INVERTED_CLASSES:
            name, why = INVERTED_CLASSES[cls]
            refused.append(dict(base, why="%s (%#x): %s" % (name, cls, why)))
        else:
            refused.append(dict(base, why="InfoClass %#x is not a debug check. Zeroing the out "
                                          "buffer of an unrelated query would corrupt data the "
                                          "caller goes on to use, so this call is left alone. "
                                          "(%s)" % (cls, note)))
    return patchable, refused


def plan(data, pe, report=None, api_filter=None):
    """Turn the detection report into a patch plan.

    `report` is an antianalysis report. Without one every detection API present in the
    import table is considered, which is the "just patch what you found" path.
    """
    slots, span = iat_slots(data, pe)
    sites, method = find_call_sites(data, pe, slots, span)

    detected = {}
    if report:
        block = report.get("debug_protection") or {}
        for ind in (block.get("indicators") or []):
            detected[ind.get("id")] = ind
        for ind in (block.get("corroborating") or []):
            detected.setdefault(ind.get("id"), ind)

    patchable, manual, absent = [], [], []
    # No report means "patch whatever you find"; a report that found nothing means patch
    # nothing. Collapsing those two into one fallback would let a clean target be patched
    # for a check it does not have.
    considered = {k: {} for k in AUTO} if report is None else detected

    for ind_id, ind in considered.items():
        if api_filter and ind_id not in api_filter:
            continue
        if ind_id in AUTO:
            spec = AUTO[ind_id]
            apis = spec["apis"]
            why = spec["why"]
            hits = [s for s in sites if s["api"] in apis]
            if not hits:
                absent.append({
                    "id": ind_id, "apis": list(apis),
                    "why": "detected statically but no direct call site found - it is "
                           "resolved at runtime (GetProcAddress) or inlined, so the "
                           "indirect call cannot be identified with confidence",
                })
                continue
            if spec["kind"] == "ntqip_clean_zero":
                # This one is not a BOOLEAN verdict, so the return value is not the answer:
                # the InfoClass has to be read and the out buffer forced instead.
                ok, refused = _ntqip_sites(data, pe, hits)
                patchable.extend(ok)
                for r in refused:
                    manual.append({"id": r["id"], "api": r["api"], "va": r["va"],
                                   "offset": r["offset"], "class": r["class"],
                                   "why": r["why"]})
                continue
            for s in hits:
                patchable.append({
                    "id": ind_id, "api": s["api"], "va": s["va"], "offset": s["offset"],
                    "size": s["size"], "before": s["bytes"],
                    "after": _forced_clean_call(s["size"]).hex(),
                    "why": why, "class": "A",
                })
        elif ind_id in MANUAL:
            manual.append({"id": ind_id, "class": _class_of(ind_id), "why": MANUAL[ind_id]})

    notes = []
    if method == "structural":
        notes.append("capstone is not installed, so call sites came from a structural "
                     "scan of FF 15 filtered by the import table span; install capstone "
                     "to have them decoded instead")
    if absent:
        notes.append("%d detected check(s) have no direct call site; see the skipped list"
                     % len(absent))
    if span is None:
        notes.append("no import table found - nothing to patch through it")
    return {
        "patchable": patchable,
        "skipped": manual + [{"id": a["id"], "apis": a["apis"], "class": "B",
                              "why": a["why"]} for a in absent],
        "notes": notes,
        "method": method,
        "iat_span": list(span) if span else None,
        "sites_found": len(sites),
    }


def _class_of(ind_id):
    if ind_id in ("peb_being_debugged_bytes", "nt_global_flag", "heap_flags"):
        return "C"
    if ind_id in ("nt_query_information_process", "nt_query_object", "output_debug_string",
                  "closehandle_trick", "thread_context", "nt_set_information_thread",
                  "nt_create_thread_ex", "debug_event_api"):
        return "E"
    return "D"


def apply(data, patches):
    """Write the patches into a copy. Returns (new_data, results)."""
    out = bytearray(data)
    results = []
    for p in patches:
        before = bytes(data[p["offset"]:p["offset"] + p["size"]])
        after = bytes.fromhex(p["after"])
        if len(after) != p["size"]:
            results.append({**p, "status": "error",
                            "detail": "replacement is not the same length"})
            continue
        if before.hex() != p["before"]:
            results.append({**p, "status": "error",
                            "detail": "file changed under the patch (expected %s, found %s)"
                                      % (p["before"], before.hex())})
            continue
        out[p["offset"]:p["offset"] + p["size"]] = after
        results.append({**p, "status": "applied", "detail": "call replaced with xor eax,eax"})
    return bytes(out), results


def verify(orig, new):
    """Byte-diff regions, so the change can be inspected rather than trusted."""
    regions = []
    i = 0
    n = min(len(orig), len(new))
    while i < n:
        if orig[i] == new[i]:
            i += 1
            continue
        j = i
        while j < n and (orig[j] != new[j] or (j - i) < 2):
            j += 1
            if j - i > 64:
                break
        regions.append({"offset": i, "before": orig[i:j].hex(), "after": new[i:j].hex()})
        i = j
    if len(orig) != len(new):
        regions.append({"offset": n, "before": "len %d" % len(orig),
                        "after": "len %d" % len(new)})
    return regions


def run(path, out_path, api_filter=None):
    """Detect, patch, verify. The whole pipeline, used by the CLI and the agent command."""
    import antianalysis  # same directory; imported late so this module stays testable alone

    with open(path, "rb") as fh:
        data = fh.read()
    pe = None
    try:
        import bobbypin
        pe = bobbypin.parse_pe(data)
    except Exception:
        pe = None
    if pe is None:
        return {"ok": False, "error": "not a parsed PE file - the patch engine needs one"}

    report = antianalysis.analyse(data, pe)
    pl = plan(data, pe, report, api_filter)

    result = {
        "ok": True,
        "path": os.path.abspath(path),
        "detected": (report.get("debug_protection") or {}).get("detected", False),
        "confidence": (report.get("debug_protection") or {}).get("confidence", "none"),
        "response": (report.get("response") or {}).get("label"),
        "plan": pl,
    }
    if not pl["patchable"]:
        result["status"] = "nothing_patchable"
        result["message"] = ("no automatically patchable check found - see plan.skipped "
                             "for what is there and why it needs a manual patch")
        return result

    if os.path.abspath(out_path) == os.path.abspath(path):
        result["ok"] = False
        result["error"] = "refusing to patch in place; the original is the evidence"
        return result

    new, applied = apply(data, pl["patchable"])
    with open(out_path, "wb") as fh:
        fh.write(new)
    os.chmod(out_path, 0o644)

    result["out"] = os.path.abspath(out_path)
    result["applied"] = applied
    result["applied_count"] = sum(1 for a in applied if a["status"] == "applied")
    result["diff"] = verify(data, new)
    result["hashes"] = {"before": _sha(data), "after": _sha(new)}
    result["status"] = "patched" if result["applied_count"] else "failed"
    return result


def _sha(blob):
    import hashlib
    return hashlib.sha256(blob).hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(description="detect a target's debug protection and patch "
                                             "out the checks whose verdict can be forced")
    ap.add_argument("target")
    ap.add_argument("-o", "--out", required=True, help="patched copy (never the original)")
    ap.add_argument("--api", action="append", default=None,
                    help="restrict to one indicator id (repeatable)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    res = run(args.target, args.out, set(args.api) if args.api else None)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        if not res.get("ok"):
            print("error: %s" % res.get("error"))
            return 1
        dp = "detected" if res["detected"] else "not detected"
        print("debug protection: %s (confidence %s)" % (dp, res["confidence"]))
        if res.get("response"):
            print("response on trigger: %s" % res["response"])
        print("\npatchable (%d):" % len(res["plan"]["patchable"]))
        for p in res["plan"]["patchable"]:
            print("  %#010x  %-28s %s -> %s" % (p["offset"], p["api"], p["before"], p["after"]))
        if res["plan"]["skipped"]:
            print("\nnot auto-patched (%d):" % len(res["plan"]["skipped"]))
            for s in res["plan"]["skipped"]:
                print("  [%s] %-28s %s" % (s.get("class", "?"), s["id"], s["why"]))
        if res.get("status") == "patched":
            print("\nwrote %s (%d patch(es) applied)" % (res["out"], res["applied_count"]))
        else:
            print("\n%s" % res.get("message", res.get("status")))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
