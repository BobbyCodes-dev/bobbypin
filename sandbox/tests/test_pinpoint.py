"""Tests for the optional pinpoint analysis layer.

Two rules drive every case here:

1. **bobbypin works without the analysis pack.** The unit tests run against a fake
   CLI or none at all, so they pass on a machine that has never installed it. That
   is the contract the import layer promises and it needs a test, not a comment.
2. **Only read-only probes are reachable.** The pack ships subcommands that launch
   the target (capture-process, debug-with-gdb). A handoff that could run an
   untrusted binary outside `sandbox_run` would be worse than no handoff, so the
   allowlist gets exercised against a name it must refuse.

Run: python3 -m unittest sandbox.tests.test_pinpoint -v
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

import pinpoint  # noqa: E402


def write_fake_cli(directory: Path, payload: dict, exit_code: int = 0) -> Path:
    """A stand-in analysis CLI that records its argv and prints one JSON object."""
    path = directory / "analysis-cli"   # any name: PINPOINT_BIN pins the path
    body = (
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "open(%r, 'w').write(json.dumps(sys.argv[1:]))\n"
        "print(json.dumps(%r))\n"
        "sys.exit(%d)\n" % (str(directory / "argv.json"), payload, exit_code)
    )
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class FakeCliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self._saved = os.environ.get("PINPOINT_BIN")

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("PINPOINT_BIN", None)
        else:
            os.environ["PINPOINT_BIN"] = self._saved
        self.tmp.cleanup()

    def test_missing_pack_is_not_an_exception(self):
        """The whole point of the optional import: no pack, no crash."""
        os.environ["PINPOINT_BIN"] = ""
        probe = pinpoint.available()
        self.assertFalse(probe["installed"])
        self.assertIn("optional", probe["why"])

    def test_run_refuses_a_probe_that_could_execute_the_target(self):
        fake = write_fake_cli(self.dir, {"ok": True})
        os.environ["PINPOINT_BIN"] = str(fake)
        with self.assertRaises(pinpoint.PinpointError) as ctx:
            pinpoint.run("capture-process", "/bin/true")
        self.assertIn("read-only", str(ctx.exception))

    def test_run_parses_json_and_asks_for_structured_output(self):
        fake = write_fake_cli(self.dir, {"evidence_id": "ev_1", "subject": {"format": "pe"}})
        os.environ["PINPOINT_BIN"] = str(fake)
        out = pinpoint.run("inspect-artifact", "/bin/true")
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["cmd"], "pinpoint")
        self.assertEqual(out["data"]["evidence_id"], "ev_1")
        argv = json.loads((self.dir / "argv.json").read_text())
        self.assertIn("--format", argv)
        self.assertIn("json", argv)
        # A token window cannot be combined with structured output on this CLI.
        self.assertNotIn("--token-limit", argv)

    def test_run_reports_a_nonzero_exit_as_an_error_not_a_traceback(self):
        fake = write_fake_cli(self.dir, {"error": "provider_unavailable"}, exit_code=1)
        os.environ["PINPOINT_BIN"] = str(fake)
        out = pinpoint.run("analyze", "/bin/true")
        self.assertFalse(out["ok"])
        self.assertIn("provider_unavailable", out["error"])

    def test_profiles_map_only_to_read_only_probes(self):
        provider_backed = {"analyze", "inspect", "decompile", "decompile-all", "function"}
        for profile, command in pinpoint.PROFILES.items():
            self.assertIn(command, pinpoint.READ_ONLY_COMMANDS,
                          "%s maps to a command outside the allowlist" % profile)
            self.assertNotIn(command, provider_backed,
                             "%s needs a disassembler; a fresh box cannot answer it" % profile)

    def test_unknown_profile_is_a_caller_error(self):
        os.environ["PINPOINT_BIN"] = str(write_fake_cli(self.dir, {"ok": True}))
        with self.assertRaises(pinpoint.PinpointError):
            pinpoint.analyze("/bin/true", "nonsense")

    def test_handoff_is_none_for_kinds_bobbypin_owns(self):
        for kind in ("pe32", "pe32+", "asar", "jar", "pyinstaller"):
            self.assertIsNone(pinpoint.HANDOFF.get(kind),
                              "%s must not get a handoff" % kind)

    def test_handoff_block_shape(self):
        os.environ["PINPOINT_BIN"] = str(write_fake_cli(self.dir, {"evidence_id": "ev"}))
        block = pinpoint.handoff("dotnet", "/tmp/x.dll")
        self.assertIsNotNone(block)
        for key in ("kind", "profile", "reason", "bobbypin_can_patch", "installed",
                    "call", "also_try", "suggested_next"):
            self.assertIn(key, block)
        self.assertFalse(block["bobbypin_can_patch"])
        self.assertIn("pinpoint_analyze", block["call"])
        self.assertEqual(block["profile"], "managed")


class RealPackTest(unittest.TestCase):
    """Skipped unless the optional analysis pack is installed."""

    @classmethod
    def setUpClass(cls):
        if not pinpoint.available().get("installed"):
            raise unittest.SkipTest("analysis pack not installed")

    def test_version_reads(self):
        self.assertTrue(pinpoint.version())

    def test_providers_never_raises(self):
        self.assertIsInstance(pinpoint.providers(), dict)

    def test_binary_profile_on_a_local_elf(self):
        out = pinpoint.analyze("/bin/ls", "binary", timeout=180)
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["profile"], "binary")
        self.assertIn("evidence_id", out["data"])


if __name__ == "__main__":
    unittest.main()
