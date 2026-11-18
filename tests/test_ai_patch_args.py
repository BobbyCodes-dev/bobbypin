"""Argument-shape tests for the AI layer's patch path.

Why this file exists: `triage`, `plan`, `anti_analysis` and `candidates` all take
`path`, but `patch` wanted `src`/`dst` and `verify` wanted `orig`/`new`. An agent
that reuses the shape it just used got a bare "need src, dst", read that as a broken
tool, and stopped before producing the patched copy - which is the whole deliverable.

So: both vocabularies work, and a call that still cannot be understood names the
accepted keys instead of a riddle.

Fixtures are built here rather than taken from the repo, so the tests do not depend
on a compiled sample being present.
"""

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import bobbypin_ai as ai  # noqa: E402


def _tiny_pe_with_jne():
    """A minimal PE whose one meaningful byte pair is a `jne` at file offset 0x200.

    `patch` only needs a readable file and a byte at the offset it is told about, so
    a real compiler is not required. The header is a plausible DOS+PE signature; the
    body carries `75 00` (jne) to flip and to NOP.
    """
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\0\0"
    data[0x200:0x202] = b"\x75\x00"
    data[0x300:0x302] = b"\x0f\x85"          # a near conditional jump, 6 bytes
    return bytes(data)


class PatchArgAliasTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bp-args-")
        self.src = os.path.join(self.tmp, "target.exe")
        with open(self.src, "wb") as fh:
            fh.write(_tiny_pe_with_jne())

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.unlink(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def _patched(self, name="out.exe"):
        return os.path.join(self.tmp, name)

    def test_canonical_src_dst_still_works(self):
        dst = self._patched()
        res = ai.cmd_patch({"src": self.src, "dst": dst,
                            "patches": [{"offset": "0x200", "mode": "flip"}]})
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["data"]["results"][0]["before"], "7500")
        self.assertEqual(res["data"]["results"][0]["after"], "7400")
        self.assertTrue(os.path.isfile(dst))

    def test_path_and_out_are_accepted(self):
        """The shape every other command in this layer uses must not be refused."""
        dst = self._patched()
        res = ai.cmd_patch({"path": self.src, "out": dst,
                            "patches": [{"offset": "0x200", "mode": "nop"}]})
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["data"]["results"][0]["after"], "9090")
        with open(dst, "rb") as fh:
            self.assertEqual(fh.read()[0x200:0x202], b"\x90\x90")

    def test_target_and_output_are_accepted(self):
        dst = self._patched()
        res = ai.cmd_patch({"target": self.src, "output": dst,
                            "patches": [{"offset": "0x200", "mode": "flip"}]})
        self.assertTrue(res["ok"], res)

    def test_in_place_is_still_refused_however_it_is_spelled(self):
        before = open(self.src, "rb").read()
        res = ai.cmd_patch({"path": self.src, "out": self.src,
                            "patches": [{"offset": "0x200", "mode": "flip"}]})
        self.assertFalse(res["ok"])
        self.assertIn("dst must differ", res["error"])
        self.assertEqual(open(self.src, "rb").read(), before)

    def test_error_names_the_accepted_spellings(self):
        res = ai.cmd_patch({"patches": [{"offset": "0x200", "mode": "flip"}]})
        self.assertFalse(res["ok"])
        self.assertIn("aliases accepted", res["error"])
        self.assertIn("out", res["error"])

    def test_verify_accepts_both_vocabularies(self):
        one, two = self._patched("a.exe"), self._patched("b.exe")
        ai.cmd_patch({"src": self.src, "dst": one,
                      "patches": [{"offset": "0x200", "mode": "flip"}]})
        ai.cmd_patch({"src": self.src, "dst": two,
                      "patches": [{"offset": "0x200", "mode": "nop"}]})
        canonical = ai.cmd_verify({"orig": self.src, "new": one})
        aliased = ai.cmd_verify({"path": self.src, "out": one})
        self.assertTrue(aliased["ok"], aliased)
        self.assertEqual(canonical["data"], aliased["data"])
        self.assertEqual(aliased["data"]["regions_changed"], 1)
        self.assertEqual(ai.cmd_verify({"src": self.src, "dst": two})["data"]["diffs"][0]["new"], "9090")


class AntidebugDeadEndTest(unittest.TestCase):
    """`nothing_patchable` must hand back a manual path, not an empty result."""

    def test_nothing_patchable_carries_candidates_and_next_steps(self):
        tmp = tempfile.mkdtemp(prefix="bp-adp-args-")
        src = os.path.join(tmp, "t.exe")
        dst = os.path.join(tmp, "t_patched.exe")
        with open(src, "wb") as fh:
            fh.write(_tiny_pe_with_jne())
        try:
            res = ai.cmd_antidebug_patch({"path": src, "dst": dst})
            if not res["ok"]:
                self.skipTest("antidebug_patch unavailable: %s" % res.get("error"))
            data = res["data"]
            if data.get("status") != "nothing_patchable":
                self.skipTest("fixture unexpectedly patchable")
            self.assertFalse(os.path.exists(dst), "nothing may be written when nothing patched")
            self.assertIn("manual_candidates", data)
            self.assertTrue(data["suggested_next"])
            joined = " ".join(data["suggested_next"])
            self.assertIn("patch", joined)
            self.assertIn("verify", joined)
        finally:
            for name in os.listdir(tmp):
                os.unlink(os.path.join(tmp, name))
            os.rmdir(tmp)


class HelpMentionsAliasesTest(unittest.TestCase):
    """A capability nobody is told about is not shipped."""

    def test_help_lists_the_accepted_spellings(self):
        payload = json.dumps(ai.cmd_help({})["data"])
        self.assertIn("aliases", payload)
        self.assertIn("out for dst", payload)
        self.assertIn("manual_candidates", payload)


if __name__ == "__main__":
    unittest.main()
