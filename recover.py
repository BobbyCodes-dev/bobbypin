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
import marshal
import os
import shutil
import struct
import subprocess
import sys
import time
import zipfile

try:  # POSIX advisory locks
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows
    _fcntl = None
try:  # Windows advisory locks
    import msvcrt as _msvcrt
except ImportError:  # pragma: no cover - POSIX
    _msvcrt = None

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

# Which engines can actually read which detected kind. A forced engine that is
# not in the list is refused by name instead of being silently ignored.
ENGINES_BY_KIND = {
    "dotnet": ("ilspycmd",),
    "jar": ("jadx",),
    "apk": ("jadx",),
    "asar": ("asar",),
    "pyinstaller": ("pyinstaller", "pycdc"),
    "pe": ("ghidra",),
    "elf": ("ghidra",),
    "macho": ("ghidra",),
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


PYINST_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"

# Section names that mean "what you are about to decompile is an unpacker stub,
# not the program". Read from the PE section table; cheap and read-only.
PACKER_SECTIONS = {
    "upx0", "upx1", "upx2", "upx!", ".aspack", ".adata", ".packed", ".petite",
    ".themida", ".vmp0", ".vmp1", ".mpress1", ".mpress2", ".enigma1", ".enigma2",
    "pec1", "pec2", ".nsp0", ".nsp1",
}


# Python bytecode magic per version, needed because PyInstaller stores a bare
# marshal blob: no .pyc header, so every decompiler rejects it as-is. A wrong
# magic here makes the decompiler fail silently, so the version is resolved from
# the bundle itself rather than from the cookie field alone.
_PYC_MAGIC = {
    (3, 6): 3379, (3, 7): 3394, (3, 8): 3413, (3, 9): 3425, (3, 10): 3439,
    (3, 11): 3495, (3, 12): 3531, (3, 13): 3571, (3, 14): 3611,
}


def _python_version(data, cookie_pyver):
    """(major, minor) for the bundle.

    PyInstaller writes `pyver` either as a bare minor (3.7 -> 7 in 3.x-era
    builds) or as major*100+minor (3.7 -> 307 in current builds). Neither is
    authoritative on its own: the interpreter DLL name in the stub is.
    """
    import re
    found = re.search(rb"python(\d)\.?(\d{1,2})\.dll", data, re.I)
    if found:
        try:
            return int(found.group(1)), int(found.group(2))
        except ValueError:
            pass
    if cookie_pyver:
        if cookie_pyver >= 100:
            return cookie_pyver // 100, cookie_pyver % 100
        if 4 <= cookie_pyver <= 20:
            return 3, cookie_pyver
    return None


def _pyc_header(version) -> bytes:
    magic = _PYC_MAGIC.get(version, 3495)
    # magic, flags(0), timestamp/hash (zeroed): enough for pycdc and friends
    return magic.to_bytes(2, "little") + b"\r\n" + b"\x00" * 12


def _pyinstaller_index(data):
    """Return (pkg_start, entries, pyver) for a PyInstaller bundle.

    Layout: [stub][package][cookie]. bobbypin's own parser reads the cookie as
    little-endian u32 and stops there, so a current bundle comes back empty.
    PyInstaller writes the fields big-endian, and the cookie grew a fixed
    64-byte python-library name in 6.x, which moves the package start. The cookie
    size is resolved by testing which candidate makes the first compressed entry
    actually inflate, rather than guessing a version constant.
    """
    import zlib
    idx = data.rfind(PYINST_MAGIC)
    if idx == -1 or idx + 24 > len(data):
        return None, [], None
    try:
        pkg_len, _toc_off, toc_len, pyver = struct.unpack_from("!IIII", data, idx + 8)
    except struct.error:
        return None, [], None
    toc_start = idx - toc_len
    if toc_start < 0:
        return None, [], None

    entries = []
    pos = toc_start
    while pos + 18 <= idx:
        try:
            entry_len, entry_pos, csize, usize = struct.unpack_from("!IIII", data, pos)
        except struct.error:
            break
        if entry_len < 18 or pos + entry_len > len(data):
            break
        flag = data[pos + 16]
        etype = chr(data[pos + 17])
        name = data[pos + 18:pos + entry_len].rstrip(b"\x00").decode("latin-1")
        entries.append([name, etype, flag, entry_pos, csize, usize])
        pos += entry_len
    if not entries:
        return None, [], None

    pkg_start = None
    for cookie_size in (88, 24, 32, 40):
        candidate = idx + cookie_size - pkg_len
        if candidate < 0:
            continue
        probe = next((e for e in entries if e[2] and e[4] > 0), None)
        if probe is None:
            pkg_start = candidate
            break
        blob = data[candidate + probe[3]:candidate + probe[3] + probe[4]]
        try:
            if len(zlib.decompress(blob)) == probe[5]:
                pkg_start = candidate
                break
        except zlib.error:
            continue
    if pkg_start is None:
        pkg_start = idx + 24 - pkg_len
    resolved = [(n, t, f, pkg_start + pos, cs, us) for n, t, f, pos, cs, us in entries]
    return pkg_start, resolved, pyver


def _pyz_modules(blob):
    """[(name, typecode, pos, length)] from a PyInstaller PYZ archive.

    The PYZ bundle holds every pure-Python module the app imports, which is
    where the application's own code lives: the archive TOC only lists the
    entry script. Layout: 'PYZ\\0', 4-byte pyc magic, big-endian TOC offset,
    zlib-compressed marshal blobs, then a marshalled dict at the TOC offset.
    """
    if len(blob) < 12 or blob[:4] != b"PYZ\0":
        return []
    try:
        toc_offset = struct.unpack("!I", blob[8:12])[0]
        toc = marshal.loads(blob[toc_offset:])
    except (struct.error, ValueError, EOFError, TypeError):
        return []
    if isinstance(toc, list):  # older builds marshal a list of (name, meta) pairs
        toc = dict(toc)
    if not isinstance(toc, dict):
        return []
    out = []
    for name, meta in toc.items():
        try:
            typecode, pos, length = meta[0], int(meta[1]), int(meta[2])
        except (IndexError, TypeError, ValueError):
            continue
        out.append((str(name), typecode, pos, length))
    return out


def _unpack_pyinstaller(data, out_dir):
    """Extract the payload; code entries get a .pyc header so decompile works.

    Returns (written, (major, minor), cookie_pyver, pyz_modules_written).
    """
    _start, entries, pyver = _pyinstaller_index(data)
    if not entries:
        return [], None, None, 0
    import zlib
    version = _python_version(data, pyver)
    written = []
    header = _pyc_header(version)
    pyz_written = 0

    def write_code(rel_path, code_blob):
        nonlocal pyz_written
        if not code_blob.startswith(header[:2]):
            code_blob = header + code_blob
        dest = os.path.join(out_dir, rel_path)
        os.makedirs(os.path.dirname(dest) or out_dir, exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(code_blob)
        pyz_written += 1

    for name, etype, flag, off, csize, _usize in entries:
        if etype == "o":
            continue
        blob = data[off:off + csize]
        if flag:
            try:
                blob = zlib.decompress(blob)
            except zlib.error:
                pass
        safe = name.replace("\\", "/").lstrip("/")
        if etype == "z":
            # PYZ archive: unpack every module it carries, keeping the dotted
            # name as a path so package structure survives.
            for mod, _tc, pos, length in _pyz_modules(blob):
                try:
                    code = zlib.decompress(blob[pos:pos + length])
                except zlib.error:
                    continue
                rel = "_pyz/" + mod.replace(".", "/") + ".pyc"
                write_code(rel, code)
            # base_library.zip and other plain zips are data, not modules
            if blob[:4] == b"PK\x03\x04":
                dest = os.path.join(out_dir, "_pyz", os.path.basename(safe) or "archive.zip")
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as fh:
                    fh.write(blob)
            continue
        if etype in ("s", "m", "M"):
            if not safe.endswith((".pyc", ".py")):
                safe += ".pyc"
            write_code(safe, blob)
            continue
        dest = os.path.join(out_dir, safe)
        os.makedirs(os.path.dirname(dest) or out_dir, exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(blob)
        written.append((safe, len(blob)))
    return written, version, pyver, pyz_written


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
            names = {str(s.get("name", "")).strip("\x00").lower()
                     for s in (pe.get("sections") or [])}
            packed = sorted(names & PACKER_SECTIONS)
            if packed:
                out["packed"] = packed
        except (ValueError, OSError):
            pass

    elif head[:4] == b"\x7fELF":
        out["kind"] = "elf"

    elif head[:4] in MACHO_MAGICS:
        out["kind"] = "macho"

    elif head[:4] == b"\x04\x00\x00\x00":
        try:
            with open(path, "rb") as fh:
                if bp.parse_asar(fh.read()):
                    out["kind"] = "asar"
                    out["container"] = "asar"
                    return out
        except (OSError, ValueError, IndexError):
            pass

    elif head[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
        except (zipfile.BadZipFile, OSError):
            names = []
        if any(n == "AndroidManifest.xml" for n in names):
            out["kind"] = "apk"
            # Flutter apps carry their logic as Dart AOT in libapp.so: there is
            # no Java worth reading, and saying "2 .java files recovered" without
            # saying why would be a lie of omission.
            if any(os.path.basename(n) in ("libflutter.so", "libapp.so") for n in names):
                out["dart_aot"] = True
        elif any(n.startswith("META-INF/") for n in names) or any(n.endswith(".class") for n in names):
            out["kind"] = "jar"
        else:
            out["kind"] = "zip"
        out["container"] = "zip"
        out["entries"] = len(names)
        return out

    # PyInstaller wraps a native stub, so it has to be checked after the format
    # is known but before a native engine gets the file: the stub is a valid ELF
    # or PE on its own, and decompiling it instead of unpacking the payload is a
    # wrong answer, not a slow one.
    if out["kind"] in ("pe", "elf", "macho", "unknown"):
        try:
            with open(path, "rb") as fh:
                _start, entries, _pyver = _pyinstaller_index(fh.read())
            if entries:
                out["stub"] = out["kind"]
                out["kind"] = "pyinstaller"
                out["entries"] = len(entries)
        except (OSError, ValueError, struct.error):
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


# Extensions that hold recovered source, as opposed to the engine's own index
# and journal files. "ok" is decided on these: a run that writes an index and no
# code has recovered nothing, whatever its exit status said.
SOURCE_EXTS = {".c", ".h", ".cs", ".java", ".kt", ".js", ".mjs", ".ts", ".py", ".go", ".rs"}


def _source_files(tree, exts=SOURCE_EXTS):
    return sum(tree["by_extension"].get(e, 0) for e in exts)


def _run(argv, timeout, cwd=None, env=None):
    """Run one engine. Always returns a dict; never raises, never hangs."""
    # Windows cannot CreateProcess a .cmd/.bat shim directly, and jadx and npm
    # both install as one. Everything else gets the plain argv.
    if os.name == "nt" and argv and str(argv[0]).lower().endswith((".cmd", ".bat")):
        argv = ["cmd", "/c", *argv]
    started = time.time()

    def done(code, stdout="", stderr=""):
        return {"code": code, "stdout": stdout, "stderr": stderr,
                "duration_s": round(time.time() - started, 2)}

    try:
        # A process group of its own, so a timeout can take the whole tree down:
        # a .bat wrapper that spawns an interpreter will not die with its parent
        # on Windows, and the pipes stay open until the grandchild exits.
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, cwd=cwd, env=env,
                                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                                if os.name == "nt" else 0)
    except FileNotFoundError:
        return done(127, stderr=f"{argv[0]} not found")
    except OSError as exc:
        # Not executable, wrong architecture, no execute permission: an engine
        # that cannot be launched is a reported error, never a traceback.
        return done(126, stderr=f"cannot execute {argv[0]}: {exc.strerror or exc}")

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, check=False)
        else:
            proc.kill()
        try:
            proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            pass
        return done(124, stderr=f"timed out after {timeout}s")
    return done(proc.returncode, stdout, stderr)


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
    if kind_info.get("packed"):
        payload["packed"] = kind_info["packed"]
    payload.update(extra)
    return payload


def recover_source(path, out=None, engine=None, force=False, timeout=DEFAULT_TIMEOUT,
                   pyc_decompiler=None) -> dict:
    """Recover a source tree from `path`. Returns a manifest, never raises for
    the expected failure modes (missing file, missing engine, bad output path)."""
    if not path:
        return {"ok": False, "error": "no target given"}
    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(path):
        return {"ok": False, "error": f"no such file: {path}"}

    try:
        kind_info = detect_kind(path)
    except OSError as exc:
        return {"ok": False, "target": path,
                "error": f"cannot read the target: {exc.strerror or exc}",
                "remediation": "check the file permissions, or copy the artifact somewhere "
                               "readable and re-run"}
    kind = kind_info["kind"]
    if engine and kind == "pe" and engine in ("ilspycmd", "dotnet"):
        kind_info["dotnet"] = True
        kind = kind_info["kind"] = "dotnet"
    elif kind == "pe" and kind_info.get("dotnet"):
        kind = kind_info["kind"] = "dotnet"

    if engine:
        allowed = ENGINES_BY_KIND.get(kind, ())
        if engine not in allowed:
            return {"ok": False, "kind": kind, "target": path, "engine": engine,
                    "error": f"engine '{engine}' cannot read a '{kind}' target",
                    "remediation": ("engines for this kind: " + ", ".join(allowed))
                    if allowed else "this kind has no source-recovery engine",
                    "hint": "drop --engine to let the target type pick its engine"}

    stem = os.path.splitext(os.path.basename(path))[0]
    out = os.path.abspath(os.path.expanduser(out)) if out else os.path.join(
        os.path.dirname(path), f"{stem}_src")

    if os.path.abspath(out) == path or out.startswith(path + os.sep):
        return {"ok": False, "error": "output directory cannot be the target itself"}

    if os.path.exists(out) and not os.path.isdir(out):
        return {"ok": False, "kind": kind, "output_dir": out,
                "error": "the output path exists and is not a directory",
                "remediation": "pick a different --out (or delete that file first)",
                "hint": "the target was not touched; nothing was written"}
    try:
        already = os.listdir(out)
    except FileNotFoundError:
        already = []
    except OSError as exc:
        return {"ok": False, "kind": kind, "output_dir": out,
                "error": f"cannot use the output directory: {exc.strerror or exc}",
                "remediation": "point --out at a writable directory",
                "hint": "the target was not touched; nothing was written"}
    if already and not force:
        return {"ok": False, "kind": kind, "output_dir": out,
                "error": "output directory is not empty; pass force=true (or --force) to write into it",
                "hint": "recover_source writes next to the target by default: "
                        f"{os.path.join(os.path.dirname(path), stem + '_src')}"}
    try:
        os.makedirs(out, exist_ok=True)
    except OSError as exc:
        # unwritable path, a parent that is a file, a read-only mount next to the
        # target: the caller passed an output location this process cannot use.
        return {"ok": False, "kind": kind, "output_dir": out,
                "error": f"cannot create the output directory: {exc.strerror or exc}",
                "remediation": "point --out at a writable directory, for example "
                               f"--out {os.path.expanduser('~/' + stem + '_src')}",
                "hint": "the target was not touched; nothing was written"}
    if not os.access(out, os.W_OK):
        return {"ok": False, "kind": kind, "output_dir": out,
                "error": f"output directory is not writable: {out}",
                "remediation": "pick a writable --out directory or fix its permissions",
                "hint": "the target was not touched; nothing was written"}

    if kind == "dotnet":
        recover = lambda: _recover_dotnet(path, out, kind_info, timeout)
    elif kind in ("jar", "apk"):
        recover = lambda: _recover_with_jadx(path, out, kind_info, timeout)
    elif kind == "asar":
        recover = lambda: _recover_asar(path, out, kind_info, timeout)
    elif kind == "pyinstaller":
        recover = lambda: _recover_pyinstaller(path, out, kind_info, timeout, pyc_decompiler)
    elif kind in ("pe", "elf", "macho"):
        recover = lambda: _recover_native(path, out, kind_info, timeout)
    else:
        return _result(path, out, kind_info, None, ok=False,
                       error=f"no source-recovery engine for kind '{kind}'",
                       hint="pinpoint can still inventory it: pinpoint inspect-artifact",
                       files=0)

    # An advisory lock serialises two concurrent runs that write the same output
    # tree: both would otherwise pass the empty-directory check and then
    # interleave. It is taken on a lock file in the temp directory, keyed by the
    # output path, never on the target: ilspycmd and friends open the artifact
    # with sharing rules that a second handle on it breaks. The kernel drops the
    # lock when the process dies, so there is no stale state to clean up.
    handle = None
    if _fcntl is not None or _msvcrt is not None:
        import hashlib
        import tempfile
        key = hashlib.sha1(out.encode("utf-8", "surrogateescape")).hexdigest()[:16]
        lock_path = os.path.join(tempfile.gettempdir(), f"bobbypin-recover-{key}.lock")
        try:
            handle = open(lock_path, "a+b")
            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b"\0")      # msvcrt needs a byte to lock
                handle.flush()
            if _fcntl is not None:
                _fcntl.flock(handle.fileno(), _fcntl.LOCK_EX | _fcntl.LOCK_NB)
            else:
                handle.seek(0)
                _msvcrt.locking(handle.fileno(), _msvcrt.LK_NBLCK, 1)
        except OSError:
            if handle:
                handle.close()
            return {"ok": False, "kind": kind, "target": path, "output_dir": out,
                    "error": "another recovery run is already writing to this output directory",
                    "hint": "wait for it to finish, or point --out somewhere else and run again"}
    try:
        return recover()
    finally:
        if handle is not None:
            try:
                if _fcntl is not None:
                    _fcntl.flock(handle.fileno(), _fcntl.LOCK_UN)
                else:
                    handle.seek(0)
                    _msvcrt.locking(handle.fileno(), _msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
            finally:
                handle.close()


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
    source_files = _source_files(tree, {".cs"})
    return _result(path, out, kind_info, "ilspycmd", ok=ok and source_files > 0,
                   files=tree["files"], source_files=source_files,
                   by_extension=tree["by_extension"],
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
    by_ext = tree["by_extension"]
    source_files = _source_files(tree, {".java", ".kt"})
    ok = source_files > 0
    failed = 0
    for dirpath, _dirs, names in os.walk(out):
        for name in names:
            if name.endswith(".java"):
                try:
                    with open(os.path.join(dirpath, name), errors="ignore") as fh:
                        body = fh.read()
                except OSError:
                    continue
                if "Method not decompiled" in body or "failed to decompile" in body:
                    failed += 1
    notes = ["Java sources are recovered from the DEX/class bytecode; names may be "
             "obfuscated but control flow is intact",
             "XML/manifest/assets from the archive are written alongside the code "
             "(decoded where jadx can decode them)"]
    if kind_info.get("dart_aot"):
        notes.insert(0, "this APK is a Flutter app: the app's own logic is Dart AOT "
                        "compiled into libapp.so, not Java. What came back is the thin "
                        "Java wrapper (activity, plugins, manifest) around it. Recovering "
                        "the Dart code needs a Dart snapshot extractor, not a Java "
                        "decompiler; the .so is in resources/ if you want to take it further")
    if failed:
        notes.append(f"{failed} of {by_ext.get('.java', 0)} .java file(s) could not be fully "
                     "decompiled by jadx; they keep a stub with the original signatures")
    return _result(path, out, kind_info, "jadx", ok=ok,
                   files=tree["files"], source_files=source_files, by_extension=by_ext,
                   languages=tree["languages"], sample=tree["sample"],
                   duration_s=run["duration_s"], decompile_failures=failed,
                   dart_aot=bool(kind_info.get("dart_aot")),
                   error=None if ok else (run["stderr"] or run["stdout"]).strip()[-1500:],
                   notes=notes)


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
    source_files = _source_files(tree, {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".json", ".html"})
    ok = source_files > 0
    return _result(path, out, kind_info, "asar", ok=ok,
                   files=tree["files"], source_files=source_files, by_extension=tree["by_extension"],
                   languages=tree["languages"], sample=tree["sample"], duration_s=0,
                   error=None if ok else "the archive listed no files",
                   notes=["Electron ships readable JavaScript, so this is the real source, not a "
                          "decompilation",
                          "minified bundles can be prettified with any formatter; source maps, when "
                          "present, are kept as-is"])


def _module_name(pyc_path, root):
    """'pkg/sub.pyc' under <root>/_pyz -> 'pkg.sub'."""
    rel = os.path.relpath(pyc_path, root).replace(os.sep, "/")
    if rel.startswith("_pyz/"):
        rel = rel[len("_pyz/"):]
    return rel[:-4].replace("/", ".") if rel.endswith(".pyc") else rel


def _pyc_decompiler(explicit=None):
    """A decompiler command for .pyc files, or None.

    pycdc's bytecode range is narrower than the versions PyInstaller ships, and
    no single decompiler covers every Python release. The command can be
    overridden with `pyc_decompiler=` or BOBBYPIN_PYC_DECOMPILER, using `{pyc}`
    as the placeholder for the file (`{py}`, `{out}` are accepted too).
    """
    candidates = [explicit, os.environ.get("BOBBYPIN_PYC_DECOMPILER")]
    for cmd in candidates:
        if cmd:
            return cmd
    for name in ("pycdc", "decompyle3", "uncompyle6"):
        found = _which(name)
        if found:
            return found
    return None


def _run_pyc_decompiler(command, pyc_path, out_path, timeout=300):
    """Run one decompiler over one .pyc. Returns (source, error)."""
    import shlex
    if "{pyc}" in command or "{out}" in command or "{py}" in command:
        argv = shlex.split(command.format(pyc=pyc_path, out=out_path, py=sys.executable))
        run = _run(argv, timeout)
        if run["code"] == 0 and run["stdout"].strip():
            return run["stdout"], None
        if os.path.exists(out_path):
            body = open(out_path, encoding="utf-8", errors="replace").read()
            if body.strip():
                return body, None
        return None, (run["stderr"] or run["stdout"]).strip()[-400:] or "no output"
    run = _run(shlex.split(command) + [pyc_path], timeout)
    if run["code"] == 0 and run["stdout"].strip():
        return run["stdout"], None
    return None, (run["stderr"] or run["stdout"]).strip()[-400:] or "no output"


def _recover_pyinstaller(path, out, kind_info, timeout, pyc_decompiler=None) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()
    written, version, _cookie_pyver, pyz_count = _unpack_pyinstaller(data, out)
    decompiler = _pyc_decompiler(pyc_decompiler)
    decompiled = skipped_stdlib = failed = 0
    first_failure = None
    py_label = f"{version[0]}.{version[1]}" if version else None
    notes = [f"PyInstaller bundle: {len(written)} payload file(s) extracted"
             + (f", {pyz_count} module(s) unpacked from the PYZ archive" if pyz_count else "")
             + (f", bytecode for Python {py_label}" if py_label else ""),
             "every code entry is marshalled bytecode with no file header: a .pyc header "
             "is synthesised so a decompiler will open it"]
    pycs = [os.path.join(dp, n) for dp, _d, ns in os.walk(out) for n in ns if n.endswith(".pyc")]
    stdlib = set(getattr(sys, "stdlib_module_names", ()))
    if decompiler:
        for src in pycs:
            mod = _module_name(src, out)
            # Stdlib modules are the same everywhere; decompiling them costs
            # minutes and tells the reader nothing about this app.
            if stdlib and mod.split(".")[0] in stdlib and mod != "__main__":
                skipped_stdlib += 1
                continue
            dst = src[:-4] + ".py"
            source, why = _run_pyc_decompiler(decompiler, src, dst)
            if source:
                with open(dst, "w", encoding="utf-8") as fh:
                    fh.write(source)
                decompiled += 1
            else:
                failed += 1
                if failed == 1 and why:
                    first_failure = why
        notes.append(f"{decompiled} .pyc file(s) turned back into .py with "
                     + os.path.basename(str(decompiler).split()[0])
                     + (f" ({skipped_stdlib} stdlib module(s) left as .pyc)" if skipped_stdlib else "")
                     + (f", {failed} failed" if failed else ""))
        if failed and first_failure:
            notes.append("first decompiler error: " + " ".join(first_failure.split())[:200])
        if pycs and decompiled == 0:
            notes.append("the decompiler could not read these code objects"
                         + (f" (built by Python {py_label})" if py_label else "")
                         + ": its supported bytecode range is narrower than the bundle's. "
                           "The .pyc files are intact and complete, so point the tool at one "
                           "that matches: BOBBYPIN_PYC_DECOMPILER='decompyle3' or "
                           "recover.py --pyc-decompiler <command> (use {pyc} as the placeholder).")
    else:
        notes.append("install pycdc (Decompyle++) to turn the .pyc bytecode back into .py, or "
                     "set BOBBYPIN_PYC_DECOMPILER / --pyc-decompiler to any command that "
                     "prints source for a .pyc")
    tree = _count_tree(out)
    ok = tree["files"] > 0
    engine_name = "pyinstaller" + ("+" + os.path.basename(str(decompiler).split()[0])
                                   if decompiler else "")
    return _result(path, out, kind_info, engine_name,
                   ok=ok, files=tree["files"], source_files=_source_files(tree, {".py"}),
                   by_extension=tree["by_extension"],
                   languages=tree["languages"], sample=tree["sample"], duration_s=0,
                   python_version=py_label, code_entries=len(pycs),
                   decompiled_files=decompiled, decompile_failures=failed,
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
    source_files = _source_files(tree, {".c", ".h"})
    ok = source_files > 0
    notes = ["C pseudocode from the Ghidra decompiler: control flow and call structure "
             "are faithful, original variable names are gone",
             "this is a reconstruction for reading, not compilable source"]
    if kind_info.get("packed"):
        notes.insert(0, f"target looks packed ({', '.join(kind_info['packed'])}): what was "
                        "decompiled is the unpacker stub, not the real code. Unpack the "
                        "artifact first (run it in the sandbox, or pinpoint's unpack step) "
                        "and recover from the unpacked image")
    return _result(path, out, kind_info, "ghidra", ok=ok,
                   files=tree["files"], source_files=source_files, by_extension=tree["by_extension"],
                   languages=tree["languages"], sample=tree["sample"],
                   duration_s=run["duration_s"], providers=providers,
                   functions=detail.get("functions_written") or detail.get("written"),
                   error=None if ok else (run["stderr"] or run["stdout"]).strip()[-1500:],
                   notes=notes)


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
    ap.add_argument("--engine",
                    help="force an engine; must be able to read the detected kind: "
                         "ilspycmd (.NET), jadx (.apk/.jar), asar (Electron), "
                         "pyinstaller/pycdc (PyInstaller), ghidra (PE/ELF/Mach-O)")
    ap.add_argument("--force", action="store_true", help="write into a non-empty output directory")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--pyc-decompiler", metavar="CMD",
                    help="PyInstaller only: command that prints source for a .pyc "
                         "(default: pycdc, then decompyle3, then uncompyle6). "
                         "Use {pyc} as the placeholder for the file")
    ap.add_argument("--json", action="store_true", help="machine-readable manifest")
    args = ap.parse_args(argv)

    result = recover_source(args.file, out=args.out, engine=args.engine,
                            force=args.force, timeout=args.timeout,
                            pyc_decompiler=args.pyc_decompiler)
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
            if result.get("source_files") is not None:
                print(f"  source   : {result['source_files']} code file(s)")
            if result.get("languages"):
                print(f"  languages: {', '.join(result['languages'])}")
            for note in result.get("notes") or []:
                print(f"  note     : {note}")
            print("  the target was not modified and nothing was patched")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
