"""pinpoint — deep analysis for the target classes bobbypin cannot see into.

bobbypin patches what it can decode. It cannot see inside .NET CIL, Android APKs,
firmware, Go/Rust build metadata, WASM, IL2CPP or Godot packs, and today it answers
those with a one-line "go use another tool" note. pinpoint turns those dead ends
into real evidence, using an optional analysis CLI that this module drives.

Three rules, and they are the whole design:

1. **The analysis pack is never required.** Missing means {"installed": false},
   not an exception, and every existing bobbypin command keeps working untouched.
2. **Only read-only probes are reachable.** The allowlist lives here, not in the
   CLI, because that CLI also ships subcommands that execute the target
   (capture-process, debug-with-gdb). bobbypin's contract is that an untrusted
   binary only ever runs inside `sandbox_run`, so a handoff that quietly executed
   the target on the operator's machine would be the worst possible feature.
3. **Analysis output is evidence, not instructions.** Nothing here feeds a patch
   offset. A report can tell a human where to look; it never tells bobbypin where
   to flip a byte.

Wire-up: `bobbypin_ai.py pinpoint_status`, `bobbypin_ai.py pinpoint_analyze`,
and the `pinpoint` block that `triage` / `plan` attach for unsupported kinds.

Implementation note for maintainers: "the analysis pack" is the `pinpoint-agents`
CLI. It stays a single constant below (`PACK_INSTALL`) so the dependency is
declared in exactly one place; bobbypin's own surface never speaks in its terms.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess

VERSION_TIMEOUT_S = 20
DEFAULT_TIMEOUT_S = 180          # native analysis on a large binary is not fast

# The one place the underlying analysis pack is named. Everything user-facing is
# bobbypin's own vocabulary; this string only exists so a missing pack can be
# installed. A user cannot install a tool they are not told the name of.
#
# Installed from our own release asset rather than the npm registry: the package
# name `pinpoint-agents` is reserved for a registry publish, but a registry
# account could not be created from this network (www.npmjs.com answers 403 to
# every path, including /signup and /login). The tarball is byte-identical to
# what would be published, and `npm i -g <tarball-url>` needs no account.
PACK_INSTALL = (
    "npm i -g https://github.com/BobbyCodes-dev/bobbypin/releases/download/"
    "pinpoint-v1.0.0/pinpoint-agents-1.0.0.tgz"
)
PACK_BINARIES = ("pinpoint",)

# Read-only by construction. Anything that runs, writes or serves is absent on
# purpose: see rule 2 in the module docstring.
READ_ONLY_COMMANDS = frozenset({
    "analyze",
    "inspect",
    "capabilities",
    "doctor",
    "function",
    "decompile",
    "decompile-all",
    "compare",
    "compare-managed-members",
    "inspect-pe-imports",
    "inspect-artifact",
    "inspect-binary-layout",
    "inspect-byte-entropy",
    "inspect-android-package",
    "inspect-android-class",
    "inspect-android-method",
    "inspect-managed-artifact",
    "inspect-managed-members",
    "inspect-managed-native-boundaries",
    "inspect-apk-signature",
    "identify-flutter-build",
    "decode-android-resources",
    "decode-android-manifest",
    "analyze-javascript-application",
    "demangle-swift",
})

# Profiles are bobbypin's vocabulary. Each one maps to the read-only probe that
# works without any native disassembler installed, because requiring Ghidra to
# answer "what is this file" would make the feature unusable on a fresh box.
PROFILES = {
    "managed": "inspect-managed-members",
    "apk": "inspect-apk-signature",
    "binary": "inspect-artifact",
    "auto": "inspect-artifact",
}

# What bobbypin's own triage kinds mean for pinpoint. `profile` is what the caller
# passes to pinpoint_analyze; `also_try` is text for a human, never executed here.
HANDOFF = {
    "apk": {
        "profile": "apk",
        "reason": ("bobbypin reads an APK as a zip and stops. pinpoint verifies declared "
                   "signing schemes and content digests without executing anything."),
        "also_try": ["inspect-android-package", "identify-flutter-build"],
    },
    "dotnet": {
        "profile": "managed",
        "reason": (".NET CIL is outside bobbypin's native patch loop. pinpoint reads "
                   "managed metadata, member signatures and CIL anchors directly, with "
                   "no disassembler installed."),
        "also_try": ["inspect-managed-native-boundaries", "compare-managed-members"],
    },
    "elf": {
        "profile": "binary",
        "reason": ("ELF string triage is all bobbypin offers. pinpoint reports format, "
                   "digests, sections and next probes without a disassembler."),
        "also_try": ["inspect-byte-entropy", "analyze"],
    },
    "macho": {
        "profile": "binary",
        "reason": ("Mach-O patching is manual in bobbypin. pinpoint inventories the "
                   "artifact before anyone edits bytes."),
        "also_try": ["demangle-swift", "analyze"],
    },
    "unknown": {
        "profile": "binary",
        "reason": ("bobbypin could not identify the container. pinpoint identifies more "
                   "formats and reports what it can prove about the file."),
        "also_try": ["inspect-byte-entropy"],
    },
}

# Kinds bobbypin already owns end to end. A handoff here would duplicate work and
# risk two different answers for the same artifact.
OWNED = {"pe32", "pe32+", "asar", "jar", "pyinstaller"}


class PinpointError(Exception):
    """Raised only for a caller mistake, never for the pack being absent."""


def _candidates():
    # PINPOINT_BIN wins outright, including the empty string: PINPOINT_BIN="" is the
    # supported way to disable pinpoint on a box that has the pack installed,
    # without uninstalling it or making every triage fall through to a search.
    if "PINPOINT_BIN" in os.environ:
        yield os.environ["PINPOINT_BIN"]
        return
    for name in PACK_BINARIES:
        found = shutil.which(name)
        if found:
            yield found
    # The pack is usually installed under nvm here, and service units do not source
    # nvm.sh, so look where nvm would have put it before giving up. Built from
    # PACK_BINARIES so the name appears once in this file.
    for name in PACK_BINARIES:
        for pattern in ("~/.nvm/versions/node/*/bin/" + name,
                        "/usr/local/bin/" + name,
                        "/usr/bin/" + name):
            for path in sorted(glob.glob(os.path.expanduser(pattern)), reverse=True):
                yield path
    return


def find_cli() -> str | None:
    """Absolute path to the analysis CLI, or None."""
    for path in _candidates():
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def available() -> dict:
    """Cheap, side-effect-free probe. Safe to call from every triage."""
    binary = find_cli()
    if not binary:
        return {
            "installed": False,
            "why": ("the analysis pack is not installed. It is optional: bobbypin "
                    "works without it. To enable deep analysis run: %s (Node 22.23.4+)"
                    % PACK_INSTALL),
        }
    return {"installed": True, "binary": binary}


def version(timeout: int = VERSION_TIMEOUT_S) -> str | None:
    binary = find_cli()
    if not binary:
        return None
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True,
                             timeout=timeout, check=False, env=_child_env(binary))
    except (OSError, subprocess.SubprocessError):
        return None
    text = (out.stdout or "").strip().splitlines()
    return text[-1].strip() if text else None


def _child_env(binary: str) -> dict:
    """The CLI is a Node script, so a bare exec fails with "env: 'node': No such
    file" anywhere nvm is not sourced (service units, cron, test runners). The
    binary lives in the same bin directory as the node that installed it, so put
    that directory on the child's PATH instead of assuming the caller's shell."""
    env = dict(os.environ)
    bin_dir = os.path.dirname(binary)
    if bin_dir:
        env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
    return env


def providers(timeout: int = 60) -> dict:
    """Which deep providers the pack can actually reach on this host.

    Native decompilation needs Ghidra, Hopper, IDA or Kuna. The provider-free
    probes (artifact inventory, entropy, signatures, managed inventories) work
    without any of them, which is why the default profiles use those.
    Returns {} when capabilities cannot be read; callers treat that as unknown.
    """
    binary = find_cli()
    if not binary:
        return {}
    try:
        proc = subprocess.run([binary, "capabilities", "--format", "json"],
                              capture_output=True, text=True, timeout=timeout,
                              check=False, env=_child_env(binary))
        data = json.loads((proc.stdout or "").strip() or "{}")
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}
    available_set, missing = set(), set()
    for entry in data.get("capabilities") or []:
        pid = _provider_label(((entry.get("provider") or {}).get("id")) or "?")
        for group in entry.get("groups") or []:
            if group.get("available"):
                available_set.add(pid)
            else:
                missing.add(pid)
    return {"available": sorted(available_set), "unavailable": sorted(missing - available_set)}


def _provider_label(pid: str) -> str:
    """Readable capability label.

    The pack names its providers with its own prefix. bobbypin reports what a
    provider can do, not who shipped it, so the prefix is stripped and the known
    ones get a plain-language name.
    """
    known = {
        "artifact-graph": "artifact-graph",
        "dotnet-static": "managed-static",
    }
    base = pid[9:] if pid.startswith("pinpoint-") else pid
    return known.get(base, base)


def run(command: str, path: str | None = None, extra: list[str] | None = None,
        timeout: int = DEFAULT_TIMEOUT_S) -> dict:
    """Run one read-only probe and return bobbypin's JSON envelope.

    Returns {"ok": True, "cmd": "pinpoint_<profile>", "data": ...} or
    {"ok": False, "cmd": ..., "error": ...}. A missing pack is an error here
    because the caller asked for work; `available()` is the cheap probe.
    """
    if command not in READ_ONLY_COMMANDS:
        raise PinpointError(
            "refusing to run the analysis pack with %r: not on the read-only "
            "allowlist (bobbypin only executes targets inside sandbox_run)" % command)
    binary = find_cli()
    if not binary:
        return {"ok": False, "cmd": "pinpoint", "error": available()["why"]}

    argv = [binary, command]
    if path:
        argv.append(os.path.abspath(os.path.expanduser(path)))
    if extra:
        argv.extend(extra)
    # No token window with structured output: the pack refuses that combination.
    # Trimming context is the caller's job, not ours.
    argv.extend(["--format", "json"])

    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              check=False, env=_child_env(binary))
    except subprocess.TimeoutExpired:
        return {"ok": False, "cmd": "pinpoint", "error": "analysis timed out after %ss" % timeout}
    except OSError as ex:
        return {"ok": False, "cmd": "pinpoint", "error": "could not run the analysis pack: %s" % ex}

    raw = (proc.stdout or "").strip()
    if proc.returncode != 0:
        return {"ok": False, "cmd": "pinpoint",
                "error": "analysis exited %s: %s" % (proc.returncode,
                                                     (proc.stderr or raw or "no output")[:400])}
    try:
        data = json.loads(raw)
    except ValueError:
        parsed = None
        for line in reversed(raw.splitlines()):
            try:
                parsed = json.loads(line)
                break
            except ValueError:
                continue
        if parsed is None:
            return {"ok": False, "cmd": "pinpoint",
                    "error": "analysis output was not JSON: %s" % raw[:300]}
        data = parsed
    return {"ok": True, "cmd": "pinpoint", "data": data}


def analyze(path: str, profile: str = "auto", timeout: int = DEFAULT_TIMEOUT_S) -> dict:
    """Public entry point: one profile, one file, bobbypin's envelope out."""
    command = PROFILES.get(profile)
    if not command:
        raise PinpointError("unknown profile %r (choose from %s)"
                            % (profile, ", ".join(sorted(PROFILES))))
    out = run(command, path, timeout=timeout)
    out["profile"] = profile
    return out


def handoff(kind: str, path: str | None = None) -> dict | None:
    """What to tell an agent that hit a target kind bobbypin cannot work.

    Returns None when bobbypin owns the kind, so callers can drop the block in
    without a special case. Never raises and never runs the pack, so it is safe
    to call from inside triage where a crash would break every consumer.
    """
    if not kind or kind in OWNED:
        return None
    spec = HANDOFF.get(kind)
    if not spec:
        return None
    probe = available()
    prov = providers() if probe.get("installed") else {}
    block = {
        "kind": kind,
        "profile": spec["profile"],
        "reason": spec["reason"],
        "bobbypin_can_patch": False,
        "installed": bool(probe.get("installed")),
        "call": 'pinpoint_analyze {"path": %s, "profile": "%s"}'
                % (json.dumps(path or "<path>"), spec["profile"]),
        "also_try": list(spec.get("also_try") or []),
    }
    if prov:
        block["deep_providers"] = prov.get("available") or []
        if "analyze" in (spec.get("also_try") or []) and not prov.get("available"):
            block["provider_note"] = (
                "decompiling or analysing native code needs Ghidra, Hopper, IDA or "
                "Kuna; none is configured on this host, so the profile above is the "
                "one that answers without one")
    if not probe.get("installed"):
        block["why_not_now"] = probe.get("why")
        block["suggested_next"] = (
            "bobbypin cannot patch this target class. Install the optional analysis "
            "pack to analyse it: %s" % PACK_INSTALL)
    else:
        block["suggested_next"] = (
            "call pinpoint_analyze with this path and profile for evidence about how "
            "the target works; bobbypin's patch loop does not apply to this format")
    return block
