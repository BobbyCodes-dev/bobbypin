#!/usr/bin/env python3
"""Tests for baml_to_xaml, and for the pass recover.py makes with it.

No .NET SDK on the machine is required and none is assumed: the engine is a stub
written at run time that answers exactly the two calls this module makes
(``--list-resources`` and ``--resource``) plus the project export recover.py uses.
What that proves is everything except ILSpy's own BAML decoding, which is ILSpy's
job and cannot be faked honestly.

Run it three ways, all supported:
    python3 tests/test_baml_to_xaml.py
    python3 -m unittest tests.test_baml_to_xaml
    pytest tests/test_baml_to_xaml.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import baml_to_xaml  # noqa: E402
import recover  # noqa: E402

RESOURCES = {
    "wpf.dll": [
        "App.g.resources/app.baml",
        "App.g.resources/views/mainwindow.baml",
        "App.g.resources/Views/MAIN.BAML",
        "App.g.resources/logo.png",
    ],
    "partial.dll": [
        "App.g.resources/ok.baml",
        "App.g.resources/broken.baml",
    ],
    "nowpf.dll": ["App.g.resources/strings.txt"],
    "slow.dll": ["App.g.resources/slow.baml"],
}

STUB = r'''
import os, sys, time

args = sys.argv[1:]
asm = os.path.basename(args[-1]).lower()
RESOURCES = %(resources)r

if "-p" in args:
    out = args[args.index("-o") + 1]
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "App.cs"), "w") as fh:
        fh.write("namespace App { public class MainWindow { } }\n")
    sys.exit(0)

if "--list-resources" in args:
    for name in RESOURCES.get(asm, []):
        print(name)
    sys.exit(0)

if "--resource" in args:
    name = args[args.index("--resource") + 1]
    if asm == "slow.dll":
        time.sleep(10)
    if "broken" in name:
        sys.stderr.write("Cannot decompile stream: unsupported BAML version\n")
        sys.exit(1)
    if asm not in RESOURCES or name not in RESOURCES[asm]:
        sys.stderr.write("no such resource: %%s\n" %% name)
        sys.exit(1)
    print('<Resource Name="%%s"><Grid /></Resource>' %% name)
    sys.exit(0)

sys.stderr.write("unexpected arguments: %%r\n" %% (args,))
sys.exit(2)
''' % {"resources": RESOURCES}


class Fixtures:
    root = None
    stub = None

    @classmethod
    def build(cls):
        cls.root = tempfile.mkdtemp(prefix="bx-")
        script = os.path.join(cls.root, "fake_ilspy.py")
        with open(script, "w") as fh:
            fh.write(STUB)
        bindir = os.path.join(cls.root, "bin")
        os.makedirs(bindir, exist_ok=True)
        if os.name == "nt":
            cls.stub = os.path.join(bindir, "ilspycmd.bat")
            with open(cls.stub, "w") as fh:
                fh.write('@echo off\r\n"%s" "%s" %%*\r\n' % (sys.executable, script))
        else:
            cls.stub = os.path.join(bindir, "ilspycmd")
            with open(cls.stub, "w") as fh:
                fh.write('#!/bin/sh\nexec "%s" "%s" "$@"\n' % (sys.executable, script))
            os.chmod(cls.stub, 0o755)
        cls.bindir = bindir
        for name in RESOURCES:
            with open(cls.assembly(name), "wb") as fh:
                fh.write(b"MZ" + b"\0" * 64)
        return cls

    @classmethod
    def assembly(cls, name):
        return os.path.join(cls.root, name)

    @classmethod
    def cleanup(cls):
        if cls.root and os.path.isdir(cls.root):
            shutil.rmtree(cls.root, ignore_errors=True)


def setUpModule():
    Fixtures.build()


def tearDownModule():
    Fixtures.cleanup()


class NameMappingTests(unittest.TestCase):
    def test_container_is_dropped_and_extension_lowercased_by_case(self):
        self.assertEqual(baml_to_xaml.baml_name_to_xaml("App.g.resources/views/mainwindow.baml"),
                         "views/mainwindow.xaml")

    def test_uppercase_baml_still_becomes_xaml(self):
        self.assertEqual(baml_to_xaml.baml_name_to_xaml("App.g.resources/Views/MAIN.BAML"),
                         "Views/MAIN.xaml")

    def test_a_name_without_a_container_maps_directly(self):
        self.assertEqual(baml_to_xaml.baml_name_to_xaml("page.baml"), "page.xaml")


class ExtractTests(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="bx-out-", dir=Fixtures.root)

    def test_every_baml_stream_becomes_a_xaml_file(self):
        r = baml_to_xaml.extract(Fixtures.assembly("wpf.dll"), self.out, exe=Fixtures.stub)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["count"], 3)
        for rel in ("app.xaml", os.path.join("views", "mainwindow.xaml"),
                    os.path.join("Views", "MAIN.xaml")):
            path = os.path.join(self.out, rel)
            self.assertTrue(os.path.isfile(path), path)
            with open(path) as fh:
                self.assertIn("<Resource", fh.read())

    def test_non_baml_resources_are_not_written_out(self):
        baml_to_xaml.extract(Fixtures.assembly("wpf.dll"), self.out, exe=Fixtures.stub)
        self.assertFalse(os.path.exists(os.path.join(self.out, "logo.png")))

    def test_the_assembly_is_only_read(self):
        path = Fixtures.assembly("wpf.dll")
        before = open(path, "rb").read()
        baml_to_xaml.extract(path, self.out, exe=Fixtures.stub)
        self.assertEqual(open(path, "rb").read(), before)

    def test_an_assembly_with_no_baml_is_a_failure_not_an_empty_success(self):
        r = baml_to_xaml.extract(Fixtures.assembly("nowpf.dll"), self.out, exe=Fixtures.stub)
        self.assertFalse(r["ok"])
        self.assertEqual(r["count"], 0)
        self.assertIn("no .baml streams", r["reason"])
        self.assertIn("WinForms", r["reason"])

    def test_one_broken_stream_is_reported_and_the_rest_still_land(self):
        r = baml_to_xaml.extract(Fixtures.assembly("partial.dll"), self.out, exe=Fixtures.stub)
        self.assertEqual(r["count"], 1)
        self.assertEqual(len(r["errors"]), 1)
        self.assertIn("unsupported BAML", r["errors"][0]["error"])
        self.assertFalse(r["ok"])
        self.assertIn("1 of 2", r["reason"])

    def test_a_hanging_engine_times_out_instead_of_blocking(self):
        r = baml_to_xaml.extract(Fixtures.assembly("slow.dll"), self.out,
                                 exe=Fixtures.stub, timeout=1)
        self.assertFalse(r["ok"])
        self.assertEqual(r["count"], 0)
        self.assertIn("did not finish within 1s", r["reason"])

    def test_a_missing_engine_says_how_to_install_it(self):
        r = baml_to_xaml.extract(Fixtures.assembly("wpf.dll"), self.out,
                                 exe="/nonexistent/ilspycmd")
        self.assertFalse(r["ok"])
        self.assertIn("could not run ilspycmd", r["reason"])
        self.assertEqual(baml_to_xaml._missing_engine().count("dotnet tool install -g ilspycmd"), 1)

    def test_a_missing_assembly_is_named(self):
        r = baml_to_xaml.extract(os.path.join(Fixtures.root, "nope.dll"), self.out,
                                 exe=Fixtures.stub)
        self.assertFalse(r["ok"])
        self.assertIn("no such file", r["reason"])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="bx-cli-", dir=Fixtures.root)
        self.env = dict(os.environ)
        self.env["PATH"] = Fixtures.bindir + os.pathsep + self.env.get("PATH", "")

    def run_cli(self, *args):
        return subprocess.run([sys.executable, os.path.join(ROOT, "baml_to_xaml.py"), *args],
                              capture_output=True, text=True, env=self.env)

    def test_json_success_envelope(self):
        proc = self.run_cli(Fixtures.assembly("wpf.dll"), "-o", self.out, "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["cmd"], "baml_to_xaml")
        self.assertEqual(payload["data"]["count"], 3)

    def test_json_failure_names_the_reason_and_exits_non_zero(self):
        proc = self.run_cli(Fixtures.assembly("nowpf.dll"), "-o", self.out, "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertFalse(payload["ok"])
        self.assertIn("no .baml streams", payload["error"])

    def test_list_shows_the_container_contents(self):
        proc = self.run_cli(Fixtures.assembly("wpf.dll"), "--list")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("App.g.resources/logo.png", proc.stdout)

    def test_single_resource_json_carries_the_text(self):
        proc = self.run_cli(Fixtures.assembly("wpf.dll"),
                            "--resource", "App.g.resources/app.baml", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertIn("<Resource", payload["data"]["text"])

    def test_missing_file_is_exit_2(self):
        proc = self.run_cli(os.path.join(Fixtures.root, "nope.dll"))
        self.assertEqual(proc.returncode, 2)


class DocumentedCommandTests(unittest.TestCase):
    """The README tells people to run `bobbypin.py App.dll --baml`. That has to work."""

    def setUp(self):
        self.env = dict(os.environ)
        self.env["PATH"] = Fixtures.bindir + os.pathsep + self.env.get("PATH", "")

    def test_the_documented_flag_runs_and_writes_beside_the_assembly(self):
        proc = subprocess.run([sys.executable, os.path.join(ROOT, "bobbypin.py"),
                               Fixtures.assembly("wpf.dll"), "--baml", "--json", "--skip-deps"],
                              capture_output=True, text=True, env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["ok"])
        target = os.path.splitext(Fixtures.assembly("wpf.dll"))[0] + "_xaml"
        self.assertTrue(os.path.isfile(os.path.join(target, "app.xaml")))

    def test_baml_out_overrides_the_default_folder(self):
        out = tempfile.mkdtemp(prefix="bx-doc-", dir=Fixtures.root)
        proc = subprocess.run([sys.executable, os.path.join(ROOT, "bobbypin.py"),
                               Fixtures.assembly("wpf.dll"), "--baml", "--baml-out", out,
                               "--skip-deps"],
                              capture_output=True, text=True, env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.isfile(os.path.join(out, "app.xaml")))


class RecoverIntegrationTests(unittest.TestCase):
    """recover.py runs this pass itself, so one command returns code and screens."""
    def test_dotnet_recovery_reports_the_pages_it_recovered(self):
        out = tempfile.mkdtemp(prefix="bx-rec-", dir=Fixtures.root)
        info = recover._recover_wpf(Fixtures.assembly("wpf.dll"), out,
                                    Fixtures.stub, 30, dict(os.environ))
        self.assertEqual(info["count"], 3)
        self.assertIn("xaml", info["note"])
        self.assertTrue(os.path.isdir(os.path.join(out, "xaml")))

    def test_a_non_wpf_assembly_adds_no_note_and_no_directory(self):
        out = tempfile.mkdtemp(prefix="bx-rec2-", dir=Fixtures.root)
        info = recover._recover_wpf(Fixtures.assembly("nowpf.dll"), out,
                                    Fixtures.stub, 30, dict(os.environ))
        self.assertEqual(info["count"], 0)
        self.assertIsNone(info["note"])
        self.assertFalse(os.path.isdir(os.path.join(out, "xaml")))


def main():
    Fixtures.build()
    try:
        loader = unittest.TestLoader()
        suite = unittest.TestSuite()
        for case in (NameMappingTests, ExtractTests, CliTests, DocumentedCommandTests,
                     RecoverIntegrationTests):
            suite.addTests(loader.loadTestsFromTestCase(case))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    finally:
        Fixtures.cleanup()
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
