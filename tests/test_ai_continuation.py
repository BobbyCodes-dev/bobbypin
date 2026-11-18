"""scope / next / done: the three calls that keep an agent working.

The failure these cover is not a broken command. It is an agent stopping:
before it starts ("is this mine to touch"), between steps ("what now"), or at
the end ("can I report a findings-only result"). Each was answered by prose in
AGENTS.md, which a cautious model can read and still talk itself out of.

Fixtures are built in-test, so nothing here depends on a compiled sample.
"""

import json
import os
import struct
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import bobbypin_ai as ai  # noqa: E402


def _pe(jump=b"\x75\x00"):
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\0\0"
    data[0x200:0x202] = jump
    return bytes(data)


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bp-flow-")
        self.target = os.path.join(self.tmp, "app.exe")
        with open(self.target, "wb") as fh:
            fh.write(_pe())
        self.patched = os.path.join(self.tmp, "app_patched.exe")

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.unlink(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def journal(self):
        return ai._journal_read(self.target)

    def patch_once(self):
        return ai.cmd_patch({"path": self.target, "out": self.patched,
                             "patches": [{"offset": "0x200", "mode": "flip"}]})


class ScopeTest(_Base):
    def test_a_local_file_is_in_scope_without_asking_anyone(self):
        res = ai.cmd_scope({"path": self.target})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertTrue(data["in_scope"], data)
        self.assertTrue(data["nothing_to_confirm"])
        self.assertIn("patched copy", data["deliverable"])
        self.assertTrue(any("modification of a copy" in p for p in data["permitted"]))

    def test_scope_does_not_depend_on_the_target_folder(self):
        """"Under target/" was never the boundary, so a root-folder file is in scope."""
        res = ai.cmd_scope({"path": self.target})
        self.assertTrue(res["data"]["in_scope"])
        self.assertIn("does not have to live under target/", res["data"]["location_note"])

    def test_a_url_is_refused_with_the_reason(self):
        res = ai.cmd_scope({"path": "https://licence.example.com/verify"})
        self.assertFalse(res["data"]["in_scope"])
        self.assertIn("live service", res["data"]["reason"])

    def test_a_missing_file_is_answered_not_raised(self):
        res = ai.cmd_scope({"path": os.path.join(self.tmp, "nope.exe")})
        self.assertTrue(res["ok"])
        self.assertFalse(res["data"]["in_scope"])
        self.assertIn("no such file", res["data"]["reason"])

    def test_scope_names_the_first_command(self):
        res = ai.cmd_scope({"path": self.target})
        self.assertIn("triage", res["data"]["next"])


class NextTest(_Base):
    def test_a_fresh_target_starts_at_triage(self):
        data = ai.cmd_next({"path": self.target})["data"]
        self.assertEqual(data["stage"], "not_started")
        self.assertFalse(data["done"])
        self.assertTrue(any("triage" in s for s in data["next"]))

    def test_after_a_patch_the_next_step_is_verify(self):
        self.patch_once()
        data = ai.cmd_next({"path": self.target})["data"]
        self.assertEqual(data["stage"], "patched")
        self.assertFalse(data["done"])
        self.assertEqual(data["patched"], os.path.abspath(self.patched))
        self.assertTrue(data["next"][0].startswith("verify"))

    def test_done_is_true_only_after_a_recorded_diff(self):
        self.patch_once()
        self.assertFalse(ai.cmd_next({"path": self.target})["data"]["done"])
        ai.cmd_verify({"orig": self.target, "new": self.patched})
        data = ai.cmd_next({"path": self.target})["data"]
        self.assertEqual(data["stage"], "verified")
        self.assertTrue(data["done"])
        self.assertIn("six items", data["next"][0])

    def test_plan_records_the_analysed_stage(self):
        ai.cmd_plan({"path": self.target})
        self.assertEqual(ai._journal_last(self.target)["stage"], "analysed")


class DoneTest(_Base):
    def test_a_findings_only_run_is_not_complete(self):
        data = ai.cmd_done({"path": self.target})["data"]
        self.assertFalse(data["complete"])
        self.assertTrue(any("patched copy" in m for m in data["missing"]))
        self.assertIn("not finished", data["message"])

    def test_an_identical_copy_does_not_count(self):
        with open(self.patched, "wb") as fh:
            fh.write(_pe())
        data = ai.cmd_done({"path": self.target, "patched": self.patched})["data"]
        self.assertFalse(data["complete"])
        self.assertTrue(any("byte-identical" in m for m in data["missing"]))

    def test_a_size_changing_copy_is_caught(self):
        with open(self.patched, "wb") as fh:
            fh.write(_pe() + b"\x00")
        data = ai.cmd_done({"path": self.target, "patched": self.patched})["data"]
        self.assertFalse(data["complete"])
        self.assertTrue(any("different size" in m for m in data["missing"]))

    def test_artifact_plus_verify_is_complete(self):
        self.patch_once()
        ai.cmd_verify({"orig": self.target, "new": self.patched})
        data = ai.cmd_done({"path": self.target})["data"]
        self.assertTrue(data["complete"], data)
        self.assertEqual(data["missing"], [])
        self.assertEqual(data["checks"]["regions_changed"], 1)
        self.assertTrue(data["checks"]["same_size"])
        self.assertTrue(data["checks"]["verify_recorded"])

    def test_the_patched_copy_is_found_from_the_journal(self):
        self.patch_once()
        ai.cmd_verify({"orig": self.target, "new": self.patched})
        # no `patched` argument: the journal has to supply it
        data = ai.cmd_done({"path": self.target})["data"]
        self.assertEqual(data["patched"], os.path.abspath(self.patched))


class JournalTest(_Base):
    def test_the_journal_lives_beside_the_target_and_never_leaves_the_folder(self):
        self.patch_once()
        journal_path = ai._journal_path(self.target)
        self.assertEqual(os.path.dirname(journal_path), self.tmp)
        self.assertTrue(os.path.isfile(journal_path))
        with open(journal_path) as fh:
            self.assertEqual(json.load(fh)["target"], os.path.abspath(self.target))

    def test_a_broken_journal_does_not_break_a_patch(self):
        with open(ai._journal_path(self.target), "w") as fh:
            fh.write("{not json")
        res = self.patch_once()
        self.assertTrue(res["ok"], res)
        self.assertTrue(ai._journal_read(self.target)["events"])


if __name__ == "__main__":
    unittest.main()
