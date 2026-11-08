#!/usr/bin/env python3
"""Recover source from a shipped artifact. Patch nothing.

bobbypin's patch loop answers "how do I change this program". This module
answers the other question: "what is this program made of". Point it at a
binary, an APK, a .NET assembly, an Electron app or a PyInstaller bundle and it
writes a readable source tree next to the target.

    from recover import recover_source
    recover_source("app.exe")              -> ./app_src/         (C pseudocode, Ghidra)
    recover_source("app.apk", out="src")   -> ./src/             (Java + resources, jadx)
    recover_source("App.dll")              -> ./App_src/         (C# project, ilspycmd)
    recover_source("app.asar")             -> ./app_src/         (the shipped JS)

Rules this module keeps:

  * the target is read-only. Nothing is written to it, ever. There is no patch
    code path in here at all.
  * an engine that is not installed is reported with the exact line that
    installs it, plus whatever evidence can still be produced without it.
    Nothing is faked and nothing is silently skipped.
  * every artefact lands under one output directory so a run can be deleted.

CLI:
    python3 recover.py target.apk [--out DIR] [--engine NAME] [--json]
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import zipfile

try:
    import bobbypin as bp
except ImportError:  # running from a different cwd
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import bobbypin as bp

try:
    import pinpoint as pp
except ImportError:
    pp = None

DEFAULT_TIMEOUT = 1800

MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
}

LANGUAGE_BY_EXT = {
    ".cs": "C#", ".java": "Java", ".kt": "Kotlin", ".js": "JavaScript",
    ".ts": "TypeScript", ".py": "Python", ".c": "C pseudocode", ".h": "C header",
    ".go": "Go", ".rs": "Rust", ".xaml": "XAML", ".smali": "Smali",
    ".xml": "XML", ".json": "JSON", ".txt": "text",
}


def _which(name: str, extra_paths=()) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for directory in extra_paths:
        candidate = os.path.join(os.path.expanduser(directory), name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _dotnet_paths():
    root = os.environ.get("DOTNET_ROOT") or os.path.expanduser("~/.dotnet")
    return (os.path.join(root, "tools"), root)


def detect_kind(path: str) -> dict:
    """What is this file? Cheap, read-only, never raises for a real file."""
    with open(path, "rb") as fh:
        head = fh.read(4096)
    out = {"kind": "unknown", "dotnet": False, "container": None}

    if head[:2] == b"MZ":
        out["kind"] = "pe"
        try:
            with open(path, "rb") as fh:
                pe = bp.parse_pe(fh.read())
            out["dotnet"] = bool(pe.get("dotnet"))
            out["machine"] = pe.get("machine")
        except (ValueError, OSError):
            pass
        return out

    if head[:4] == b"\x7fELF":
        out["kind"] = "elf"
        return out

    if head[:4] in MACHO_MAGICS:
        out["kind"] = "macho"
        return out

    if head[:4] == b"\x04\x00\x00\x00":
        try:
            with open(path, "rb") as fh:
                if bp.parse_asar(fh.read()):
                    out["kind"] = "asar"
                    out["container"] = "asar"
                    return out
        except (OSError, ValueError, IndexError):
            pass

    if head[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
        except (zipfile.BadZipFile, OSError):
            names = []
        if any(n == "AndroidManifest.xml" for n in names):
            out["kind"] = "apk"
        elif any(n.startswith("META-INF/") for n in names) or any(n.endswith(".class") for n in names):
            out["kind"] = "jar"
        else:
            out["kind"] = "zip"
        out["container"] = "zip"
        out["entries"] = len(names)
        return out

    try:
        with open(path, "rb") as fh:
            if bp.pyinstaller_files(fh.read()):
                out["kind"] = "pyinstaller"
                return out
    except (OSError, ValueError):
        pass
    return out


def _count_tree(root: str):
    by_ext, files = {}, []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            ext = os.path.splitext(name)[1].lower()
            by_ext[ext or "<none>"] = by_ext.get(ext or "<none>", 0) + 1
            files.append(os.path.relpath(full, root))
    languages = sorted({LANGUAGE_BY_EXT[e] for e in by_ext if e in LANGUAGE_BY_EXT})
    return {"files": len(files), "by_extension": dict(sorted(by_ext.items(), key=lambda kv: -kv[1])),
            "languages": languages, "sample": sorted(files)[:25]}


def _run(argv, timeout, cwd=None, env=None):
    started = time.time()
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              cwd=cwd, env=env)
        return {"code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr,
                "duration_s": round(time.time() - started, 2)}
    except FileNotFoundError:
        return {"code": 127, "stdout": "", "stderr": f"{argv[0]} not found",
                "duration_s": round(time.time() - started, 2)}
    except subprocess.TimeoutExpired:
        return {"code": 124, "stdout": "", "stderr": f"timed out after {timeout}s",
                "duration_s": round(time.time() - started, 2)}


def _result(path, out, kind_info, engine, **extra):
    payload = {
        "target": os.path.abspath(path),
        "kind": kind_info["kind"],
        "dotnet": kind_info.get("dotnet", False),
        "engine": engine,
        "output_dir": os.path.abspath(out) if out else None,
        "patched": False,
        "target_written": False,
        "read_only": True,
    }
    payload.update(extra)
    return payload


def recover_source(path, out=None, engine=None, force=False, timeout=DEFAULT_TIMEOUT) -> dict:
    """Recover a source tree from `path`. Returns a manifest, never raises for
    the expected failure modes (missing file, missing engine, bad output path)."""
    if not path:
        return {"ok": False, "error": "no target given"}
    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(path):
        return {"ok": False, "error": f"no such file: {path}"}

    kind_info = detect_kind(path)
    kind = kind_info["kind"]
    if engine and kind == "pe" and engine in ("ilspycmd", "dotnet"):
        kind_info["dotnet"] = True
        kind = kind_info["kind"] = "dotnet"
    elif kind == "pe" and kind_info.get("dotnet"):
        kind = kind_info["kind"] = "dotnet"

    stem = os.path.splitext(os.path.basename(path))[0]
    out = os.path.abspath(os.path.expanduser(out)) if out else os.path.join(
        os.path.dirname(path), f"{stem}_src")

    if os.path.abspath(out) == path or out.startswith(path + os.sep):
        return {"ok": False, "error": "output directory cannot be the target itself"}

    try:
        already = os.listdir(out)
    except FileNotFoundError:
        already = []
    if already and not force:
        return {"ok": False, "kind": kind, "output_dir": out,
                "error": "output directory is not empty; pass force=true (or --force) to write into it",
                "hint": "recover_source writes next to the target by default: "
                        f"{os.path.join(os.path.dirname(path), stem + '_src')}"}
    os.makedirs(out, exist_ok=True)

    if kind == "dotnet":
        return _recover_dotnet(path, out, kind_info, timeout)
    if kind in ("jar", "apk"):
        return _recover_with_jadx(path, out, kind_info, timeout)
    if kind == "asar":
        return _recover_asar(path, out, kind_info, timeout)
    if kind == "pyinstaller":
        return _recover_pyinstaller(path, out, kind_info, timeout)
    if kind in ("pe", "elf", "macho"):
        return _recover_native(path, out, kind_info, timeout)
    return _result(path, out, kind_info, None, ok=False,
                   error=f"no source-recovery engine for kind '{kind}'",
                   hint="pinpoint can still inventory it: pinpoint inspect-artifact",
                   files=0)


def _recover_dotnet(path, out, kind_info, timeout) -> dict:
    ilspy = _which("ilspycmd", _dotnet_paths())
    if not ilspy:
        return _result(path, out, kind_info, "ilspycmd", ok=False,
                       error="ilspycmd is not installed",
                       remediation="dotnet tool install -g ilspycmd  (needs the .NET SDK 8+)",
                       files=0,
                       hint="without it, pinpoint can still read managed metadata: "
                            "pinpoint inspect-managed-members <path>")
    env = dict(os.environ)
    extra = [p for p in _dotnet_paths() if os.path.isdir(p)]
    if extra:
        env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])
    env.setdefault("DOTNET_ROOT", os.path.expanduser("~/.dotnet"))
    run = _run([ilspy, "-p", "-o", out, path], timeout, env=env)
    combined = (run["stderr"] or "") + (run["stdout"] or "")
    if "You must install .NET" in combined or ".NET location: Not found" in combined:
        return _result(path, out, kind_info, "ilspycmd", ok=False,
                       error="ilspycmd is installed but cannot find the .NET runtime",
                       remediation="point DOTNET_ROOT at your .NET install "
                                   "(export DOTNET_ROOT=$HOME/.dotnet) and re-run; "
                                   "./install.sh writes this into the env file",
                       files=0)
    tree = _count_tree(out)
    ok = run["code"] == 0 and tree["files"] > 0
    return _result(path, out, kind_info, "ilspycmd", ok=ok,
                   files=tree["files"], by_extension=tree["by_extension"],
                   languages=tree["languages"], sample=tree["sample"],
                   duration_s=run["duration_s"],
                   error=None if ok else (run["stderr"] or run["stdout"]).strip()[-1500:],
                   notes=["decompiled C# project; open the .csproj in an IDE or read the .cs files",
                          "obfuscated assemblies come back with meaningless identifiers but keep their structure"])


def _recover_with_jadx(path, out, kind_info, timeout) -> dict:
    jadx = _which("jadx")
    if not jadx:
        return _result(path, out, kind_info, "jadx", ok=False,
                       error="jadx is not installed",
                       remediation="download jadx from github.com/skylot/jadx/releases and put "
                                   "jadx on PATH (or apt install jadx)",
                       files=0,
                       hint="the classes are still readable as bytecode: unzip the archive and "
                            "use javap -c on the entries you care about")
    run = _run([jadx, "-d", out, "--no-debug-info", path], timeout)
    tree = _count_tree(out)
    ok = tree["files"] > 0
    return _result(path, out, kind_info, "jadx", ok=ok,
                   files=tree["files"], by_extension=tree["by_extension"],
                   languages=tree["languages"], sample=tree["sample"],
                   duration_s=run["duration_s"],
                   error=None if ok else (run["stderr"] or run["stdout"]).strip()[-1500:],
                   notes=["Java sources are recovered from the DEX/class bytecode; names may be "
                          "obfuscated but control flow is intact",
                          "resources are not exported by this run, only code"])


def _recover_asar(path, out, kind_info, timeout) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()
    parsed = bp.parse_asar(data)
    if not parsed:
        return _result(path, out, kind_info, "asar", ok=False,
                       error="could not parse the ASAR index", files=0)
    files = parsed if isinstance(parsed, list) else (parsed.get("files") or [])
    bp.unpack_asar(data, files, out)
    tree = _count_tree(out)
    ok = tree["files"] > 0
    return _result(path, out, kind_info, "asar", ok=ok,
                   files=tree["files"], by_extension=tree["by_extension"],
                   languages=tree["languages"], sample=tree["sample"], duration_s=0,
                   error=None if ok else "the archive listed no files",
                   notes=["Electron ships readable JavaScript, so this is the real source, not a "
                          "decompilation",
                          "minified bundles can be prettified with any formatter; source maps, when "
                          "present, are kept as-is"])


def _recover_pyinstaller(path, out, kind_info, timeout) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()
    bp.unpack_pyinstaller(data, out)
    tree = _count_tree(out)
    decompiler = _which("pycdc")
    decompiled = 0
    notes = ["PyInstaller ships compiled .pyc bytecode, not source"]
    if decompiler:
        for dirpath, _dirs, names in os.walk(out):
            for name in names:
                if name.endswith(".pyc"):
                    dst = os.path.join(dirpath, name[:-4] + ".py")
                    run = _run([decompiler, os.path.join(dirpath, name)], timeout=300)
                    if run["code"] == 0 and run["stdout"].strip():
                        with open(dst, "w", encoding="utf-8") as fh:
                            fh.write(run["stdout"])
                        decompiled += 1
        notes.append(f"{decompiled} .pyc file(s) turned back into .py with pycdc")
        tree = _count_tree(out)
    else:
        notes.append("install pycdc (Decompyle++) to turn the .pyc bytecode back into .py")
    ok = tree["files"] > 0
    return _result(path, out, kind_info, "pyinstaller" + ("+pycdc" if decompiler else ""),
                   ok=ok, files=tree["files"], by_extension=tree["by_extension"],
                   languages=tree["languages"], sample=tree["sample"], duration_s=0,
                   decompiled_files=decompiled,
                   error=None if ok else "nothing was extracted", notes=notes)


def _recover_native(path, out, kind_info, timeout) -> dict:
    if pp is None:
        return _result(path, out, kind_info, None, ok=False,
                       error="the analysis layer is not importable", files=0,
                       remediation="run ./install.sh, or set PINPOINT_BIN to the pinpoint CLI")
    binary = pp.find_cli()
    if not binary:
        return _result(path, out, kind_info, "pinpoint", ok=False,
                       error="pinpoint CLI not found", files=0,
                       remediation="run ./install.sh (installs it) or set PINPOINT_BIN")
    providers = pp.providers() if hasattr(pp, "providers") else {}
    live = providers.get("available") or []
    if "ghidra" not in live:
        return _result(path, out, kind_info, "ghidra", ok=False,
                       error="no decompiler engine is configured, so C pseudocode cannot be produced",
                       remediation="install Ghidra 12.1.x and set GHIDRA_INSTALL_DIR "
                                   "(./install.sh wires this up when it finds one)",
                       providers=providers, files=0,
                       hint="disassembly without an engine still works: bobbypin_ai.py disasm")
    # decompile-all insists on creating the output directory itself; an existing
    # (even empty) one makes it ask for --resume instead.
    if os.path.isdir(out) and not os.listdir(out):
        os.rmdir(out)
    run = _run([binary, "decompile-all", path, "--output", out], timeout)
    tree = _count_tree(out)
    detail = {}
    try:
        detail = json.loads(run["stdout"] or "{}")
    except ValueError:
        detail = {}
    ok = tree["files"] > 0
    return _result(path, out, kind_info, "ghidra", ok=ok,
                   files=tree["files"], by_extension=tree["by_extension"],
                   languages=tree["languages"], sample=tree["sample"],
                   duration_s=run["duration_s"], providers=providers,
                   functions=detail.get("functions_written") or detail.get("written"),
                   error=None if ok else (run["stderr"] or run["stdout"]).strip()[-1500:],
                   notes=["C pseudocode from the Ghidra decompiler: control flow and call structure "
                          "are faithful, original variable names are gone",
                          "this is a reconstruction for reading, not compilable source"])


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="Recover source from an artifact without patching it.",
        epilog="examples:\n"
               "  python3 recover.py app.apk\n"
               "  python3 recover.py App.dll --out src\n"
               "  python3 recover.py app.exe --engine ghidra --json\n")
    ap.add_argument("file")
    ap.add_argument("--out", metavar="DIR", help="output directory (default: <name>_src next to the target)")
    ap.add_argument("--engine", help="force an engine: ilspycmd, jadx, asar, pycdc, ghidra")
    ap.add_argument("--force", action="store_true", help="write into a non-empty output directory")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--json", action="store_true", help="machine-readable manifest")
    args = ap.parse_args(argv)

    result = recover_source(args.file, out=args.out, engine=args.engine,
                            force=args.force, timeout=args.timeout)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if not result.get("ok"):
            print(f"recover: {result.get('error')}")
            if result.get("remediation"):
                print(f"  fix: {result['remediation']}")
            if result.get("hint"):
                print(f"  or:  {result['hint']}")
        else:
            print(f"recovered {result['files']} file(s) into {result['output_dir']}")
            print(f"  engine   : {result['engine']} ({result['kind']})")
            if result.get("languages"):
                print(f"  languages: {', '.join(result['languages'])}")
            for note in result.get("notes") or []:
                print(f"  note     : {note}")
            print("  the target was not modified and nothing was patched")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
