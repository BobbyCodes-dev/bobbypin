#!/usr/bin/env python3
"""Recover editable XAML from the BAML streams embedded in a .NET/WPF assembly.

When a WPF project builds, every .xaml page is compiled to binary BAML and
stored inside a ``<AssemblyName>.g.resources`` container embedded in the
assembly. ILSpy understands that format and can turn each stream back into
readable XAML. This module drives ILSpy's ``ilspycmd`` for every BAML stream in
an assembly, so it works on any WPF app, not just one target.

Usage:
    python3 baml_to_xaml.py <assembly.dll> [-o out] [--list] [--json]
    python3 baml_to_xaml.py <assembly.dll> --resource "App.g.resources/mainwindow.baml"

Requires:
    dotnet tool install -g ilspycmd

Rules this module keeps:

  * the assembly is only ever read. Nothing is written next to it.
  * ``ok`` is true only when at least one .xaml file was produced. An assembly
    with no BAML streams is reported as a failure with the reason, never as a
    silent success with zero files.
  * a missing engine, a timeout and a non-zero exit are all reported by name,
    with the command that fixes them.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

TOOL = "ilspycmd"
DEFAULT_TIMEOUT = 300


def find_ilspycmd() -> str | None:
    """Resolve ilspycmd the way every entry point here has to.

    A login shell usually has ``~/.dotnet/tools`` on PATH; a cron job, a systemd
    unit and an agent tool call usually do not. Both are checked, and on Windows
    the tool is a ``.exe`` so that name is tried too.
    """
    exe = shutil.which(TOOL)
    if exe:
        return exe
    roots = [os.environ.get("DOTNET_ROOT"), os.path.expanduser("~/.dotnet")]
    for root in roots:
        if not root:
            continue
        for name in (TOOL, TOOL + ".exe", TOOL + ".cmd", TOOL + ".bat"):
            cand = os.path.join(root, "tools", name)
            if os.path.isfile(cand):
                return cand
    return None


def _run(args: list[str], timeout: int):
    """Run ilspycmd. Returns (code, stdout, stderr, error-or-None).

    Text is decoded as UTF-8 with replacement: XAML carries non-ASCII text and
    the default locale codec on Windows is cp1252, which raises mid-decode.
    """
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "", "", f"{Path(args[0]).name} did not finish within {timeout}s"
    except OSError as exc:
        return None, "", "", f"could not run {Path(args[0]).name}: {exc}"
    return proc.returncode, proc.stdout or "", proc.stderr or "", None


def list_resources(assembly, exe: str | None = None, timeout: int = DEFAULT_TIMEOUT) -> list[str]:
    """Every embedded resource name, as ``<container>/<entry>``."""
    exe = exe or find_ilspycmd()
    if not exe:
        raise RuntimeError(_missing_engine())
    code, out, err, error = _run([exe, "--list-resources", str(assembly)], timeout)
    if error:
        raise RuntimeError(error)
    if code != 0:
        raise RuntimeError((err or out).strip() or f"{TOOL} failed ({code})")
    return [line.strip() for line in out.splitlines() if line.strip()]


def decompile_resource(assembly, resource: str, exe: str | None = None,
                       timeout: int = DEFAULT_TIMEOUT) -> str:
    """The XAML text for one resource name. Use a name from ``list_resources``
    verbatim: it is relative to the container listing, so no leading slash."""
    exe = exe or find_ilspycmd()
    if not exe:
        raise RuntimeError(_missing_engine())
    code, out, err, error = _run([exe, "--resource", resource, str(assembly)], timeout)
    if error:
        raise RuntimeError(error)
    if code != 0:
        raise RuntimeError((err or out).strip() or f"{TOOL} failed ({code})")
    return out


def baml_name_to_xaml(resource: str) -> str:
    """``<container>/sub/page.baml`` -> ``sub/page.xaml`` (the container is dropped)."""
    rel = resource.split("/", 1)[1] if "/" in resource else resource
    return re.sub(r"\.baml$", ".xaml", rel, flags=re.IGNORECASE)


def _missing_engine() -> str:
    return (f"{TOOL} is not installed. Install it with:\n"
            f"    dotnet tool install -g {TOOL}\n"
            f"  (needs the .NET SDK 8+, and ~/.dotnet/tools on PATH)")


def extract(assembly, out, timeout: int = DEFAULT_TIMEOUT, exe: str | None = None) -> dict:
    """Decompile every BAML stream into ``out``. Returns the report; never prints.

    The report is the same shape whether called from the CLI or from
    ``recover.py``: ``ok``, ``count``, ``files``, ``errors``, ``reason``.
    """
    assembly_path = Path(str(assembly)).expanduser()
    if not assembly_path.is_file():
        return {"ok": False, "count": 0, "files": [], "errors": [],
                "reason": f"no such file: {assembly_path}"}
    assembly_path = assembly_path.resolve()
    out_dir = Path(str(out)).expanduser()

    try:
        resources = list_resources(assembly_path, exe=exe, timeout=timeout)
    except RuntimeError as exc:
        return {"ok": False, "count": 0, "files": [], "errors": [],
                "reason": str(exc)}

    bamls = [r for r in resources if r.lower().endswith(".baml")]
    if not bamls:
        return {"ok": False, "count": 0, "files": [], "errors": [],
                "reason": (f"no .baml streams in {assembly_path.name}: nothing in the "
                           f"assembly is a compiled WPF page. A console/WinForms "
                           f"assembly recovers C# only; a single-file .NET bundle "
                           f"has no managed resources at the top level, so point "
                           f"this at the contained .dll instead"),
                "resources": resources}

    written, errors = [], []
    for resource in bamls:
        rel = baml_name_to_xaml(resource)
        dest = out_dir / Path(rel)
        try:
            xaml = decompile_resource(assembly_path, resource, exe=exe, timeout=timeout)
        except RuntimeError as exc:
            errors.append({"resource": resource, "error": str(exc)})
            continue
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(xaml, encoding="utf-8")
        except OSError as exc:
            errors.append({"resource": resource, "error": f"could not write {dest}: {exc}"})
            continue
        written.append({"resource": resource, "path": str(dest),
                        "bytes": len(xaml.encode("utf-8"))})

    report = {"ok": bool(written) and not errors, "count": len(written),
              "files": written, "errors": errors,
              "out": str(out_dir), "baml_streams": len(bamls)}
    if not written:
        report["reason"] = ("every BAML stream failed to decompile: "
                            + (errors[0]["error"] if errors else "no output produced"))
    elif errors:
        report["reason"] = f"{len(errors)} of {len(bamls)} BAML stream(s) failed"
    return report


def _emit(payload: dict, as_json: bool, text_lines: list[str]) -> None:
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        for line in text_lines:
            print(line)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="baml_to_xaml",
        description="Decompile BAML streams from a .NET/WPF assembly into XAML.",
    )
    ap.add_argument("assembly", help="path to a managed assembly (.dll)")
    ap.add_argument("-o", "--out", default="xaml",
                    help="output directory for .xaml files (default: xaml)")
    ap.add_argument("--list", action="store_true",
                    help="only list embedded resources, extract nothing")
    ap.add_argument("--resource", metavar="NAME",
                    help="decompile a single resource (as printed by --list) "
                         "to stdout instead of writing files")
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable JSON")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                    help=f"seconds before an ilspycmd call is abandoned (default: {DEFAULT_TIMEOUT})")
    args = ap.parse_args(argv)

    assembly = Path(args.assembly).expanduser()
    if not assembly.is_file():
        _emit({"ok": False, "cmd": "baml_to_xaml", "error": f"no such file: {assembly}"},
              args.json, [f"error: no such file: {assembly}"])
        return 2
    assembly = assembly.resolve()

    if args.resource:
        try:
            text = decompile_resource(assembly, args.resource, timeout=args.timeout)
        except RuntimeError as exc:
            _emit({"ok": False, "cmd": "baml_to_xaml", "error": str(exc)},
                  args.json, [f"error: {exc}"])
            return 2
        _emit({"ok": True, "cmd": "baml_to_xaml",
               "data": {"assembly": str(assembly), "resource": args.resource, "text": text}},
              args.json, [text])
        return 0

    if args.list:
        try:
            resources = list_resources(assembly, timeout=args.timeout)
        except RuntimeError as exc:
            _emit({"ok": False, "cmd": "baml_to_xaml", "error": str(exc)},
                  args.json, [f"error: {exc}"])
            return 2
        bamls = [r for r in resources if r.lower().endswith(".baml")]
        _emit({"ok": True, "cmd": "baml_to_xaml",
               "data": {"assembly": str(assembly), "resources": resources, "baml": bamls}},
              args.json, resources)
        return 0

    report = extract(assembly, args.out, timeout=args.timeout)
    payload = {"ok": report["ok"], "cmd": "baml_to_xaml",
               "data": {"assembly": str(assembly), **report}}
    if not report["ok"]:
        payload["error"] = report.get("reason")
    lines = [f"wrote {f['path']}" for f in report["files"]]
    lines += [f"error: {e['resource']}: {e['error']}" for e in report["errors"]]
    if report["ok"]:
        lines.append(f"\n{report['count']} BAML stream(s) -> {report.get('out', args.out)}")
    else:
        lines.append(f"\n{report.get('reason')}")
    _emit(payload, args.json, lines)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
