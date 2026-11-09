#!/usr/bin/env python3
"""Test suite for recover.py — source recovery, no patching.

Runs with the standard library only, builds its own fixtures, and skips engine
tests whose tool is not installed instead of failing on a machine that never
had it. Two tiers:

    python3 tests/test_recover.py              # fixtures + contract (no big targets)
    BOBBYPIN_REAL_TARGETS=/path/to/targets.json python3 tests/test_recover.py
                                               # adds real artifacts, see README

A real-targets file is JSON: {"label": "/absolute/path/to/artifact", ...}.
Every run re-hashes each target and asserts it was never written to.
"""

import hashlib
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import recover  # noqa: E402


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def walk(root):
    for dirpath, _dirs, names in os.walk(root):
        for name in names:
            yield os.path.join(dirpath, name)


def which(name):
    return shutil.which(name)


# --------------------------------------------------------------------------
# fixtures: built here so the suite does not depend on files outside the repo
# --------------------------------------------------------------------------
def pyinstaller_skip_reason():
    if Fixtures.paths.get("pyi"):
        return None
    if not shutil.which("pyinstaller"):
        return "pyinstaller not installed"
    return "pyinstaller could not build the fixture: " + Fixtures.paths.get("pyi_error", "unknown")


def native_engine_ready():
    """The tool's own resolution order, not just PATH: install.sh writes an env file."""
    return recover.pp is not None and recover.pp.find_cli() is not None


def make_elf(directory):
    """A real ELF: /bin/true if present, otherwise skipped by the caller."""
    for candidate in ("/bin/true", "/bin/echo"):
        if os.path.exists(candidate):
            return candidate
    return None


def make_pe(directory, name="fixture.exe"):
    """A PE built with mingw when available: real headers, real code."""
    gcc = which("x86_64-w64-mingw32-gcc") or which("i686-w64-mingw32-gcc")
    if not gcc:
        return None
    src = os.path.join(directory, "pe_fixture.c")
    with open(src, "w") as fh:
        fh.write('#include <stdio.h>\n'
                 'int license_check(const char *k){ return k[0] == 66; }\n'
                 'int main(void){ printf("%d\\n", license_check("BP")); return 0; }\n')
    exe = os.path.join(directory, name)
    run = subprocess.run([gcc, "-O1", src, "-o", exe], capture_output=True, text=True)
    return exe if run.returncode == 0 and os.path.exists(exe) else None


def make_zip(directory, name, entries):
    path = os.path.join(directory, name)
    with zipfile.ZipFile(path, "w") as zf:
        for entry, body in entries.items():
            zf.writestr(entry, body)
    return path


def make_apk(directory, name="fixture.apk", flutter=False):
    entries = {
        "AndroidManifest.xml": b"<manifest/>",
        "classes.dex": b"dex\n035\0",
        "resources.arsc": b"",
        "res/values/strings.xml": b"<resources/>",
    }
    if flutter:
        entries["lib/arm64-v8a/libflutter.so"] = b"\x7fELF"
        entries["lib/arm64-v8a/libapp.so"] = b"\x7fELF"
    return make_zip(directory, name, entries)


def make_jar(directory, name="fixture.jar"):
    """A real JAR when javac is available, otherwise a header-only archive.

    A `.class` full of placeholder bytes is not a class: jadx rejects it and the
    run correctly reports that no source came back. That case is kept on purpose
    as a fixture for the "engine produced nothing" contract test.
    """
    entries = {"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n",
               "com/example/App.class": b"\xca\xfe\xba\xbe"}
    javac = which("javac")
    if javac:
        src_dir = os.path.join(directory, "javasrc", "com", "example")
        os.makedirs(src_dir, exist_ok=True)
        src = os.path.join(src_dir, "App.java")
        with open(src, "w") as fh:
            fh.write("package com.example;\n"
                     "public class App {\n"
                     '  public static final String KEY = "SENTINEL-jar-1";\n'
                     "  public boolean licensed(String k) { return KEY.equals(k); }\n"
                     "}\n")
        run = subprocess.run([javac, "-d", os.path.join(directory, "javacls"), src],
                             capture_output=True, text=True, timeout=300)
        compiled = os.path.join(directory, "javacls", "com", "example", "App.class")
        if run.returncode == 0 and os.path.exists(compiled):
            with open(compiled, "rb") as fh:
                entries["com/example/App.class"] = fh.read()
    return make_zip(directory, name, entries)


def make_asar(directory, name="fixture.asar"):
    """A real Electron asar, written with the same layout the packer uses."""
    files = {
        "package.json": b'{"name":"fixture","main":"main.js"}',
        "main.js": b'const KEY="SENTINEL-asar-1";\nmodule.exports=()=>KEY;\n',
        "ui/index.html": b"<!doctype html><title>fixture</title>",
    }
    header = {"files": {}}
    blobs, offset = [], 0
    for rel, body in files.items():
        node = header["files"]
        parts = rel.split("/")
        for part in parts[:-1]:
            node = node.setdefault(part, {"files": {}})["files"]
        node[parts[-1]] = {"size": len(body), "offset": str(offset)}
        blobs.append(body)
        offset += len(body)
    payload = json.dumps(header, separators=(",", ":")).encode()
    pad = (4 - len(payload) % 4) % 4
    payload += b"\0" * pad
    # <u32 4><u32 header size><u32 json length><json><data>
    size_field = 8 + len(payload)
    head = struct.pack("<II", 4, size_field)
    body = struct.pack("<I", len(payload)) + payload + b"".join(blobs)
    path = os.path.join(directory, name)
    with open(path, "wb") as fh:
        fh.write(head + body)
    return path


class Fixtures:
    """Built once per run."""

    root = None
    paths = {}

    @classmethod
    def build(cls):
        cls.root = tempfile.mkdtemp(prefix="bobbypin-recover-tests-")
        p = cls.paths
        p["elf"] = make_elf(cls.root)
        p["pe"] = make_pe(cls.root)
        p["apk"] = make_apk(cls.root)
        p["apk_flutter"] = make_apk(cls.root, "flutter.apk", flutter=True)
        p["jar"] = make_jar(cls.root)
        p["zip"] = make_zip(cls.root, "plain.zip", {"readme.txt": "hi"})
        p["asar"] = make_asar(cls.root)
        p["text"] = os.path.join(cls.root, "notes.txt")
        with open(p["text"], "w") as fh:
            fh.write("not a binary\n")
        p["empty"] = os.path.join(cls.root, "empty.bin")
        open(p["empty"], "wb").close()
        p["pyi"] = None
        if shutil.which("pyinstaller"):
            src = os.path.join(cls.root, "pyi_src")
            os.makedirs(src, exist_ok=True)
            with open(os.path.join(src, "app.py"), "w") as fh:
                fh.write('SENTINEL = "pyi-fixture-1"\n\n\ndef main():\n'
                         '    print(SENTINEL)\n\n\nif __name__ == "__main__":\n    main()\n')
            out = os.path.join(cls.root, "pyi_dist")
            run = subprocess.run(
                ["pyinstaller", "--onefile", "--noconfirm", "--log-level=ERROR",
                 "--distpath", out, "--workpath", os.path.join(cls.root, "pyi_build"),
                 os.path.join(src, "app.py")],
                capture_output=True, text=True, timeout=900, cwd=cls.root)
            candidate = os.path.join(out, "app.exe" if os.name == "nt" else "app")
            if run.returncode == 0 and os.path.exists(candidate):
                p["pyi"] = candidate
            else:
                # A broken pyinstaller (wrong HOME, missing module) is not the same
                # as "not installed": the skip reason has to say what happened.
                p["pyi_error"] = ((run.stderr or run.stdout or "").strip().splitlines()
                                  or ["pyinstaller produced no output"])[-1][:200]

    @classmethod
    def cleanup(cls):
        shutil.rmtree(cls.root, ignore_errors=True)


class DetectionTests(unittest.TestCase):
    def test_formats_are_named_correctly(self):
        expect = {"elf": "elf", "pe": "pe", "apk": "apk", "apk_flutter": "apk",
                  "jar": "jar", "zip": "zip", "asar": "asar", "text": "unknown",
                  "empty": "unknown", "pyi": "pyinstaller"}
        for key, want in expect.items():
            path = Fixtures.paths.get(key)
            if not path:
                continue
            with self.subTest(key=key):
                self.assertEqual(recover.detect_kind(path)["kind"], want)

    def test_pyinstaller_is_not_reported_as_its_stub(self):
        path = Fixtures.paths.get("pyi")
        if not path:
            self.skipTest("pyinstaller not installed")
        info = recover.detect_kind(path)
        self.assertEqual(info["kind"], "pyinstaller")
        self.assertIn(info.get("stub"), ("elf", "pe"))
        self.assertGreater(info.get("entries", 0), 0)

    def test_flutter_apk_is_flagged_as_dart(self):
        info = recover.detect_kind(Fixtures.paths["apk_flutter"])
        self.assertTrue(info.get("dart_aot"))
        plain = recover.detect_kind(Fixtures.paths["apk"])
        self.assertFalse(plain.get("dart_aot"))

    def test_packed_sections_are_reported(self):
        info = recover.detect_kind(Fixtures.paths["pe"]) if Fixtures.paths.get("pe") else None
        if info is None:
            self.skipTest("no mingw to build a PE fixture")
        self.assertIn("packed", info) if info.get("packed") else None
        # a normal build must not be accused of being packed
        self.assertNotIn("packed", info)


class ContractTests(unittest.TestCase):
    def out(self, name):
        path = os.path.join(Fixtures.root, "out", name)
        shutil.rmtree(path, ignore_errors=True)
        return path

    def test_missing_file(self):
        r = recover.recover_source(os.path.join(Fixtures.root, "nope.bin"))
        self.assertFalse(r["ok"])
        self.assertIn("no such file", r["error"])

    def test_directory_input(self):
        r = recover.recover_source(Fixtures.root)
        self.assertFalse(r["ok"])
        self.assertIn("no such file", r["error"])

    def test_unreadable_target(self):
        path = os.path.join(Fixtures.root, "locked.asar")
        shutil.copy(Fixtures.paths["asar"], path)
        os.chmod(path, 0)
        try:
            if os.access(path, os.R_OK):
                self.skipTest("running as a user that ignores file modes")
            r = recover.recover_source(path, out=self.out("unreadable"))
        finally:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        self.assertFalse(r["ok"])
        self.assertIn("cannot read the target", r["error"])

    def test_empty_and_text_files_have_no_engine(self):
        for key in ("empty", "text"):
            with self.subTest(key=key):
                r = recover.recover_source(Fixtures.paths[key], out=self.out(key))
                self.assertFalse(r["ok"])
                self.assertIn("no source-recovery engine", r["error"])

    def test_plain_zip_has_no_engine(self):
        r = recover.recover_source(Fixtures.paths["zip"], out=self.out("zip"))
        self.assertFalse(r["ok"])
        self.assertIn("no source-recovery engine for kind 'zip'", r["error"])

    def test_output_cannot_be_the_target(self):
        r = recover.recover_source(Fixtures.paths["asar"], out=Fixtures.paths["asar"])
        self.assertFalse(r["ok"])
        self.assertIn("cannot be the target", r["error"])

    def test_non_empty_output_needs_force(self):
        out = self.out("nonempty")
        os.makedirs(out)
        keep = os.path.join(out, "keep.txt")
        open(keep, "w").write("x")
        r = recover.recover_source(Fixtures.paths["asar"], out=out)
        self.assertFalse(r["ok"])
        self.assertIn("not empty", r["error"])
        self.assertTrue(os.path.exists(keep), "the existing file was deleted anyway")

    def test_force_writes_into_existing_output(self):
        out = self.out("force")
        os.makedirs(out)
        open(os.path.join(out, "stale.txt"), "w").write("x")
        r = recover.recover_source(Fixtures.paths["asar"], out=out, force=True)
        self.assertTrue(r["ok"], r.get("error"))
        self.assertGreaterEqual(r["source_files"], 3)

    def test_output_path_that_is_a_file(self):
        out = os.path.join(Fixtures.root, "out", "file")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        open(out, "w").write("x")
        r = recover.recover_source(Fixtures.paths["asar"], out=out)
        self.assertFalse(r["ok"])
        self.assertIn("not a directory", r["error"])

    def test_unwritable_output_reports_and_does_not_raise(self):
        # A path under a regular file cannot be created on any platform, which is
        # what makes this portable: no /proc, no assumptions about permissions.
        blocker = os.path.join(Fixtures.root, "blocker.bin")
        open(blocker, "wb").close()
        r = recover.recover_source(Fixtures.paths["asar"],
                                   out=os.path.join(blocker, "child"))
        self.assertFalse(r["ok"])
        self.assertIn("output directory", r["error"])
        self.assertIn("remediation", r)

    def test_readonly_parent_directory(self):
        parent = os.path.join(Fixtures.root, "readonly")
        shutil.rmtree(parent, ignore_errors=True)
        os.makedirs(parent)
        target = os.path.join(parent, "app.asar")
        shutil.copy(Fixtures.paths["asar"], target)
        os.chmod(parent, 0o555)
        try:
            if os.access(parent, os.W_OK):
                self.skipTest("permissions not enforced for this user")
            r = recover.recover_source(target)
        finally:
            os.chmod(parent, 0o755)
        self.assertFalse(r["ok"])
        self.assertIn("output", r["error"])

    def test_engine_that_cannot_read_the_kind_is_refused(self):
        r = recover.recover_source(Fixtures.paths["asar"], out=self.out("mismatch"),
                                   engine="ilspycmd")
        self.assertFalse(r["ok"])
        self.assertIn("cannot read", r["error"])
        self.assertIn("asar", r["remediation"])

    def test_two_runs_one_output_tree_do_not_interleave(self):
        target = os.path.join(Fixtures.root, "concurrent.asar")
        shutil.copy(Fixtures.paths["asar"], target)
        out = os.path.join(Fixtures.root, "out", "concurrent")
        shutil.rmtree(out, ignore_errors=True)
        results = {}

        def run(i):
            results[i] = recover.recover_source(target, out=out)

        threads = [threading.Thread(target=run, args=(i,)) for i in range(2)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        oks = [r for r in results.values() if r.get("ok")]
        self.assertEqual(len(oks), 1, [r.get("error") for r in results.values()])

    def test_manifest_shape(self):
        r = recover.recover_source(Fixtures.paths["asar"], out=self.out("manifest"))
        for key in ("ok", "target", "kind", "engine", "output_dir", "files",
                    "source_files", "patched", "target_written", "read_only"):
            self.assertIn(key, r)
        self.assertFalse(r["patched"])
        self.assertFalse(r["target_written"])
        self.assertTrue(r["read_only"])


class AsarTests(unittest.TestCase):
    def test_files_come_out_byte_identical(self):
        out = os.path.join(Fixtures.root, "out", "asar")
        shutil.rmtree(out, ignore_errors=True)
        r = recover.recover_source(Fixtures.paths["asar"], out=out)
        self.assertTrue(r["ok"], r.get("error"))
        with open(os.path.join(out, "main.js"), "rb") as fh:
            body = fh.read()
        self.assertIn(b"SENTINEL-asar-1", body)
        self.assertTrue(os.path.exists(os.path.join(out, "ui", "index.html")))
        self.assertGreaterEqual(r["source_files"], 3)

    def test_asar_target_is_untouched(self):
        before = sha(Fixtures.paths["asar"])
        out = os.path.join(Fixtures.root, "out", "asar_ro")
        shutil.rmtree(out, ignore_errors=True)
        recover.recover_source(Fixtures.paths["asar"], out=out)
        self.assertEqual(before, sha(Fixtures.paths["asar"]))


class JarApkTests(unittest.TestCase):
    def test_jar_recovery(self):
        if not which("jadx"):
            self.skipTest("jadx not installed")
        if not which("javac"):
            self.skipTest("javac not installed, so the fixture jar has no real class")
        out = os.path.join(Fixtures.root, "out", "jar")
        shutil.rmtree(out, ignore_errors=True)
        r = recover.recover_source(Fixtures.paths["jar"], out=out)
        self.assertTrue(r["ok"], r.get("error"))
        self.assertGreaterEqual(r["source_files"], 1)
        self.assertIn("decompile_failures", r)
        java = [p for p in walk(out) if p.endswith(".java")]
        body = "".join(open(p, errors="ignore").read() for p in java)
        self.assertIn("SENTINEL-jar-1", body)

    def test_jar_with_no_readable_classes_is_a_failure_not_a_success(self):
        if not which("jadx"):
            self.skipTest("jadx not installed")
        fake = make_zip(Fixtures.root, "empty.jar",
                        {"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n",
                         "com/example/App.class": b"\xca\xfe\xba\xbe"})
        out = os.path.join(Fixtures.root, "out", "jar_empty")
        shutil.rmtree(out, ignore_errors=True)
        r = recover.recover_source(fake, out=out)
        self.assertFalse(r["ok"])
        self.assertEqual(r["source_files"], 0)

    def test_flutter_apk_says_why_there_is_no_java(self):
        if not which("jadx"):
            self.skipTest("jadx not installed")
        out = os.path.join(Fixtures.root, "out", "flutter")
        shutil.rmtree(out, ignore_errors=True)
        r = recover.recover_source(Fixtures.paths["apk_flutter"], out=out)
        self.assertTrue(r.get("dart_aot"))
        self.assertTrue(any("Flutter" in n or "Dart" in n for n in r.get("notes", [])))

    def test_missing_engine_is_named_with_its_install_line(self):
        saved_path = os.environ.get("PATH", "")
        out = os.path.join(Fixtures.root, "out", "nojadx")
        shutil.rmtree(out, ignore_errors=True)
        os.environ["PATH"] = os.path.join(Fixtures.root, "empty-bin")
        os.makedirs(os.environ["PATH"], exist_ok=True)
        try:
            r = recover.recover_source(Fixtures.paths["jar"], out=out)
        finally:
            os.environ["PATH"] = saved_path
        self.assertFalse(r["ok"])
        self.assertIn("jadx", r["error"])
        self.assertIn("jadx", r["remediation"])


class PyInstallerTests(unittest.TestCase):
    def test_bundle_is_unpacked_with_pyz_modules(self):
        path = Fixtures.paths.get("pyi")
        if not path:
            self.skipTest(pyinstaller_skip_reason())
        out = os.path.join(Fixtures.root, "out", "pyi")
        shutil.rmtree(out, ignore_errors=True)
        r = recover.recover_source(path, out=out)
        self.assertTrue(r["ok"], r.get("error"))
        self.assertEqual(r["python_version"],
                         f"{sys.version_info[0]}.{sys.version_info[1]}")
        self.assertGreaterEqual(r["code_entries"], 1)
        self.assertTrue(any(p.endswith(".pyc") for p in walk(out)))

    def test_decompiler_override_is_honoured(self):
        path = Fixtures.paths.get("pyi")
        if not path:
            self.skipTest(pyinstaller_skip_reason())
        fake = os.path.join(Fixtures.root, "fake-decompiler.sh")
        with open(fake, "w") as fh:
            fh.write('#!/bin/sh\necho "# recovered by the override"\necho "SENTINEL = 1"\n')
        os.chmod(fake, 0o755)
        out = os.path.join(Fixtures.root, "out", "pyi_override")
        shutil.rmtree(out, ignore_errors=True)
        r = recover.recover_source(path, out=out, pyc_decompiler=fake)
        self.assertTrue(r["ok"], r.get("error"))
        self.assertIn("fake-decompiler", r["engine"])
        pys = [p for p in walk(out) if p.endswith(".py")]
        self.assertTrue(pys)
        with open(pys[0], errors="ignore") as fh:
            self.assertIn("recovered by the override", fh.read())


class NativeTests(unittest.TestCase):
    def test_binary_decompiles_to_c_and_reports_provenance(self):
        if not native_engine_ready():
            self.skipTest("pinpoint CLI not installed")
        elf = Fixtures.paths.get("elf")
        if not elf:
            self.skipTest("no ELF to test with")
        env_note = os.environ.get("GHIDRA_INSTALL_DIR")
        out = os.path.join(Fixtures.root, "out", "elf")
        shutil.rmtree(out, ignore_errors=True)
        r = recover.recover_source(elf, out=out, timeout=900)
        if not r.get("ok") and "decompiler" in (r.get("error") or ""):
            self.skipTest("no decompiler engine configured")
        self.assertTrue(r["ok"], r.get("error"))
        cs = [p for p in walk(out) if p.endswith(".c")]
        self.assertGreater(len(cs), 10)
        with open(cs[0], errors="ignore") as fh:
            head = fh.read(600)
        self.assertIn("// name:", head)
        self.assertIn("// address:", head)

    def test_pe_symbols_survive(self):
        pe = Fixtures.paths.get("pe")
        if not pe or not native_engine_ready():
            self.skipTest("no mingw PE fixture or no pinpoint")
        out = os.path.join(Fixtures.root, "out", "pe")
        shutil.rmtree(out, ignore_errors=True)
        r = recover.recover_source(pe, out=out, timeout=900)
        if not r.get("ok") and "decompiler" in (r.get("error") or ""):
            self.skipTest("no decompiler engine configured")
        self.assertTrue(r["ok"], r.get("error"))
        names = []
        for path in walk(out):
            if path.endswith(".c"):
                with open(path, errors="ignore") as fh:
                    for line in fh.read(400).splitlines():
                        if line.startswith("// name:"):
                            names.append(line.split(":", 1)[1].strip())
        self.assertIn("license_check", names)


class EdgeCaseTests(unittest.TestCase):
    def out(self, name):
        path = os.path.join(Fixtures.root, "out", name)
        shutil.rmtree(path, ignore_errors=True)
        return path

    def test_paths_with_spaces_and_unicode(self):
        src = os.path.join(Fixtures.root, "space and ünïcode target.asar")
        shutil.copy(Fixtures.paths["asar"], src)
        out = self.out("weird name out")
        r = recover.recover_source(src, out=out)
        self.assertTrue(r["ok"], r.get("error"))
        self.assertTrue(os.path.exists(os.path.join(out, "main.js")))

    def test_symlink_to_target(self):
        link = os.path.join(Fixtures.root, "link.asar")
        if os.path.lexists(link):
            os.remove(link)
        os.symlink(Fixtures.paths["asar"], link)
        r = recover.recover_source(link, out=self.out("symlink"))
        self.assertTrue(r["ok"], r.get("error"))

    def test_source_files_excludes_resources(self):
        apk = make_zip(Fixtures.root, "withres.apk", {
            "AndroidManifest.xml": b"<manifest/>",
            "classes.dex": b"dex\n035\0",
            "res/drawable/icon.png": b"\x89PNG",
        })
        if not which("jadx"):
            self.skipTest("jadx not installed")
        out = self.out("withres")
        r = recover.recover_source(apk, out=out)
        self.assertEqual(r["source_files"],
                         sum(r["by_extension"].get(e, 0)
                             for e in (".java", ".kt")))
        self.assertGreater(r["files"], r["source_files"])

    def native_target(self):
        for key in ("elf", "pe"):
            if Fixtures.paths.get(key):
                return Fixtures.paths[key]
        return None

    def test_engine_timeout_is_reported_not_hung(self):
        if recover.pp is None or not self.native_target():
            self.skipTest("analysis layer or a native target is not available")
        stub = os.path.join(Fixtures.root, "slow-engine.sh")
        with open(stub, "w") as fh:
            fh.write("#!/bin/sh\nsleep 30\necho '{\"functions\": []}'\n")
        os.chmod(stub, 0o755)
        saved = recover.pp.find_cli, getattr(recover.pp, "providers", None)
        recover.pp.find_cli = lambda: stub
        if saved[1] is not None:
            recover.pp.providers = lambda: {"available": ["ghidra"]}
        try:
            started = time.time()
            r = recover.recover_source(self.native_target(), out=self.out("timeout"),
                                       timeout=1)
            elapsed = time.time() - started
        finally:
            recover.pp.find_cli = saved[0]
            if saved[1] is not None:
                recover.pp.providers = saved[1]
        self.assertFalse(r["ok"])
        self.assertIn("timed out", (r.get("error") or "").lower())
        self.assertLess(elapsed, 25, "timeout was not enforced")

    def test_two_processes_cannot_share_one_output_tree(self):
        if recover.pp is None or not self.native_target():
            self.skipTest("analysis layer or a native target is not available")
        stub = os.path.join(Fixtures.root, "slow-engine2.sh")
        with open(stub, "w") as fh:
            fh.write("#!/bin/sh\nsleep 4\necho '{\"functions\": []}'\n")
        os.chmod(stub, 0o755)
        out = self.out("crossproc")
        env = dict(os.environ, PINPOINT_BIN=stub)
        procs = [subprocess.Popen([sys.executable, os.path.join(REPO, "recover.py"),
                                   self.native_target(), "--out", out, "--json"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, env=env) for _ in range(2)]
        results = []
        for proc in procs:
            stdout, stderr = proc.communicate(timeout=120)
            try:
                results.append(json.loads(stdout))
            except ValueError:
                results.append({"ok": False, "error": stderr[:200]})
        errors = [r.get("error", "") for r in results]
        locked = [e for e in errors if "another recovery run" in e]
        # Exactly one process may hold the output tree. The other one is refused,
        # whatever the winner goes on to do with its engine.
        self.assertEqual(len(locked), 1, errors)
        self.assertEqual(sum(1 for e in errors if "another recovery run" not in e), 1, errors)


class PortabilityTests(unittest.TestCase):
    """The parts that could differ on Windows, tested here instead of hoped for."""

    def out(self, name):
        path = os.path.join(Fixtures.root, "out", name)
        shutil.rmtree(path, ignore_errors=True)
        return path

    def test_recovery_works_without_fcntl(self):
        # Windows has no fcntl; the lock is an optimisation, never a requirement.
        saved = recover._fcntl
        recover._fcntl = None
        try:
            r = recover.recover_source(Fixtures.paths["asar"], out=self.out("no_fcntl"))
        finally:
            recover._fcntl = saved
        self.assertTrue(r["ok"], r.get("error"))
        self.assertGreaterEqual(r["source_files"], 3)

    def test_pyc_magic_follows_the_python_version(self):
        # 3.7 bytecode with a 3.11 header is what silently broke pycdc before:
        # the magic has to track the version, not a constant.
        self.assertEqual(recover._pyc_header((3, 7))[:2], (3394).to_bytes(2, "little"))
        self.assertEqual(recover._pyc_header((3, 11))[:2], (3495).to_bytes(2, "little"))
        self.assertEqual(recover._pyc_header((3, 13))[:2], (3571).to_bytes(2, "little"))
        # an unknown future version still yields a syntactically valid header
        self.assertEqual(recover._pyc_header((3, 99))[2:4], b"\r\n")

    def test_python_version_reads_the_stub_not_just_the_cookie(self):
        self.assertEqual(recover._python_version(b"...python37.dll...", 37), (3, 7))
        self.assertEqual(recover._python_version(b"...python311.dll...", 311), (3, 11))
        self.assertEqual(recover._python_version(b"nothing here", 307), (3, 7))
        self.assertIsNone(recover._python_version(b"nothing here", 0))

    def test_nested_pyz_module_names_use_dots(self):
        root = tempfile.mkdtemp(dir=Fixtures.root)
        nested = os.path.join(root, "_pyz", "pkg", "sub")
        os.makedirs(nested)
        path = os.path.join(nested, "mod.pyc")
        open(path, "wb").close()
        self.assertEqual(recover._module_name(path, root), "pkg.sub.mod")


class CliTests(unittest.TestCase):
    def test_json_success(self):
        out = os.path.join(Fixtures.root, "out", "cli_json")
        shutil.rmtree(out, ignore_errors=True)
        run = subprocess.run([sys.executable, os.path.join(REPO, "recover.py"),
                              Fixtures.paths["asar"], "--out", out, "--json"],
                             capture_output=True, text=True, timeout=300)
        self.assertEqual(run.returncode, 0, run.stderr)
        parsed = json.loads(run.stdout)
        self.assertTrue(parsed["ok"])
        self.assertGreaterEqual(parsed["source_files"], 3)

    def test_json_failure_shape_and_exit_code(self):
        run = subprocess.run([sys.executable, os.path.join(REPO, "recover.py"),
                              os.path.join(Fixtures.root, "nope.bin"), "--json"],
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(run.returncode, 1)
        parsed = json.loads(run.stdout)
        self.assertFalse(parsed["ok"])
        self.assertIn("no such file", parsed["error"])

    def test_human_output_states_nothing_was_patched(self):
        out = os.path.join(Fixtures.root, "out", "cli_human")
        shutil.rmtree(out, ignore_errors=True)
        run = subprocess.run([sys.executable, os.path.join(REPO, "recover.py"),
                              Fixtures.paths["asar"], "--out", out],
                             capture_output=True, text=True, timeout=300)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("recovered", run.stdout)
        self.assertIn("was not modified", run.stdout)

    def test_ai_bridge_contract(self):
        out = os.path.join(Fixtures.root, "out", "bridge")
        shutil.rmtree(out, ignore_errors=True)
        request = json.dumps({"cmd": "recover_source", "path": Fixtures.paths["asar"],
                              "out": out})
        run = subprocess.run([sys.executable, os.path.join(REPO, "bobbypin_ai.py"),
                              "recover_source", request],
                             capture_output=True, text=True, timeout=300)
        parsed = json.loads(run.stdout.strip().splitlines()[-1])
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["cmd"], "recover_source")
        self.assertTrue(parsed["data"]["ok"])


class RealTargetTests(unittest.TestCase):
    """Opt-in: BOBBYPIN_REAL_TARGETS=/path/to/targets.json

    {"label": "/abs/path"} — every entry gets recovered, checked for source
    files, and re-hashed afterwards to prove the artifact was not written.
    """

    @classmethod
    def setUpClass(cls):
        cls.targets = {}
        spec = os.environ.get("BOBBYPIN_REAL_TARGETS")
        if spec:
            with open(os.path.expanduser(spec)) as fh:
                cls.targets = json.load(fh)
        cls.before = {k: sha(v) for k, v in cls.targets.items() if os.path.exists(v)}

    def test_every_real_target(self):
        if not self.targets:
            self.skipTest("set BOBBYPIN_REAL_TARGETS to a targets JSON to run these")
        failures = []
        for label, path in self.targets.items():
            if not os.path.exists(path):
                failures.append(f"{label}: missing {path}")
                continue
            out = os.path.join(Fixtures.root, "out", "real_" + label.replace("/", "_"))
            shutil.rmtree(out, ignore_errors=True)
            r = recover.recover_source(path, out=out, timeout=3600)
            reasons = []
            if not r.get("ok"):
                reasons.append(f"ok=False ({(r.get('error') or '')[:160]})")
            if not r.get("source_files"):
                reasons.append("no source files")
            if r.get("target_written"):
                reasons.append("target was written")
            if reasons:
                failures.append(f"{label}: " + "; ".join(reasons))
            print(f"  {label}: ok={r.get('ok')} files={r.get('files')} "
                  f"source={r.get('source_files')} engine={r.get('engine')}", flush=True)
        self.assertEqual(failures, [], "\n".join(failures))

    def test_real_targets_untouched(self):
        if not self.before:
            self.skipTest("no real targets configured")
        changed = [k for k, h in self.before.items() if sha(self.targets[k]) != h]
        self.assertEqual(changed, [], f"targets changed on disk: {changed}")


def setUpModule():
    """Also lets `python -m unittest tests.test_recover` and pytest discovery work."""
    Fixtures.build()


def tearDownModule():
    Fixtures.cleanup()


def main():
    Fixtures.build()
    try:
        loader = unittest.TestLoader()
        suite = unittest.TestSuite()
        for case in (DetectionTests, ContractTests, AsarTests, JarApkTests,
                     PyInstallerTests, NativeTests, EdgeCaseTests,
                     PortabilityTests, CliTests, RealTargetTests):
            suite.addTests(loader.loadTestsFromTestCase(case))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    finally:
        Fixtures.cleanup()
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
