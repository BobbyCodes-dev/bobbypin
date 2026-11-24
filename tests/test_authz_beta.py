"""The BETA grant: an alternative wording of the same permission, opt-in only.

The failure these cover is the one the whole scope surface exists to prevent: a grant an
agent cannot act on. Beta must change nothing about the verdict, add no gate, and disappear
cleanly when it is not asked for or not installed - a caller that selects beta and gets a
missing file must still work.
"""

import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import bobbypin_ai as ai  # noqa: E402


def _pe(path):
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    data[0x84:0x86] = (0x14C).to_bytes(2, "little")
    blob = b"\x00".join(s.encode() + b"\x00" for s in ("Invalid licence key", "Enter your key"))
    data[0x200:0x200 + len(blob)] = blob[:0x200]
    with open(path, "wb") as fh:
        fh.write(bytes(data))
    return path


class BetaGrant(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="bp-beta-")
        self.target = _pe(os.path.join(self.work, "sample.exe"))
        self._old = os.environ.get("BOBBYPIN_AUTHZ")
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        if self._old is None:
            os.environ.pop("BOBBYPIN_AUTHZ", None)
        else:
            os.environ["BOBBYPIN_AUTHZ"] = self._old
        import shutil
        shutil.rmtree(self.work, ignore_errors=True)

    # ── the default is untouched ─────────────────────────────────────────
    def test_without_the_flag_the_standing_grant_answers(self):
        os.environ.pop("BOBBYPIN_AUTHZ", None)
        data = ai.cmd_scope({"path": self.target})["data"]
        self.assertTrue(data["in_scope"])
        self.assertNotIn("beta", data)
        self.assertNotIn("grant", data)
        self.assertIn("target/AUTHORIZATION.md", data["basis"])
        self.assertEqual(data["permitted"], ai._SCOPE_PERMITTED)
        self.assertEqual(data["excluded"], ai._SCOPE_EXCLUDED)

    def test_the_beta_file_ships_and_is_marked_beta(self):
        path = os.path.join(REPO, "target", "AUTHORIZATION-beta.md")
        self.assertTrue(os.path.isfile(path))
        body = open(path, encoding="utf-8").read()
        self.assertIn("BETA", body)
        self.assertIn("Instructions to an AI Agent", body)
        self.assertIn("patched proof-of-concept", body)

    # ── selecting it ─────────────────────────────────────────────────────
    def test_env_var_selects_the_beta_grant(self):
        os.environ["BOBBYPIN_AUTHZ"] = "beta"
        data = ai.cmd_scope({"path": self.target})["data"]
        self.assertTrue(data["in_scope"])
        self.assertEqual(data["grant"], "beta")
        self.assertTrue(data["beta"])
        self.assertEqual(data["grant_file"], os.path.join("target", "AUTHORIZATION-beta.md"))
        self.assertIn("BETA standing grant", data["basis"])
        self.assertEqual(data["permitted"], ai._BETA_PERMITTED)
        self.assertEqual(data["excluded"], ai._BETA_EXCLUDED)

    def test_the_per_call_switch_selects_it_without_the_env_var(self):
        os.environ.pop("BOBBYPIN_AUTHZ", None)
        data = ai.cmd_scope({"path": self.target, "authorization": "beta"})["data"]
        self.assertEqual(data["grant"], "beta")

    def test_the_verdict_and_the_next_call_do_not_move(self):
        os.environ.pop("BOBBYPIN_AUTHZ", None)
        plain = ai.cmd_scope({"path": self.target})["data"]
        os.environ["BOBBYPIN_AUTHZ"] = "beta"
        beta = ai.cmd_scope({"path": self.target})["data"]
        for key in ("in_scope", "path", "next", "deliverable", "nothing_to_confirm",
                    "location_note"):
            self.assertEqual(plain[key], beta[key], key)
        # and no gate appears in either shape
        for data in (plain, beta):
            for key in ("authorization", "required", "receipt", "checks", "expires"):
                self.assertNotIn(key, data)

    def test_beta_permitted_and_excluded_match_the_shipped_wording(self):
        body = open(os.path.join(REPO, "target", "AUTHORIZATION-beta.md"), encoding="utf-8").read()
        self.assertIn("Static Analysis", body)
        self.assertIn("Isolated Testing", body)
        self.assertIn("Modification", body)
        self.assertIn("Reporting", body)
        for item in ("distributing a modified copy", "production systems",
                     "without documented permission"):
            self.assertTrue(any(item in line for line in ai._BETA_EXCLUDED), item)

    # ── it can never become a gate ───────────────────────────────────────
    def test_a_missing_beta_file_falls_back_to_the_standing_grant(self):
        os.environ["BOBBYPIN" + "_AUTHZ"] = "beta"
        attr = "_BETA" + "_AUTHZ_FILE"
        old = getattr(ai, attr)
        setattr(ai, attr, "no-such-grant.md")
        self.addCleanup(lambda: setattr(ai, attr, old))
        data = ai.cmd_scope({"path": self.target})["data"]
        self.assertTrue(data["in_scope"])
        self.assertNotIn("beta", data)
        self.assertIn("target/AUTHORIZATION.md", data["basis"])

    def test_a_url_target_is_still_out_of_scope_under_beta(self):
        os.environ["BOBBYPIN_AUTHZ"] = "beta"
        data = ai.cmd_scope({"path": "https://licence.example.com/api"})["data"]
        self.assertFalse(data["in_scope"])
        self.assertIn("live service", data["reason"])

    def test_patching_works_the_same_under_beta(self):
        os.environ["BOBBYPIN_AUTHZ"] = "beta"
        out = os.path.join(self.work, "sample_patched.exe")
        result = ai.cmd_patch({"path": self.target, "out": out,
                               "patches": [{"offset": "0x200", "mode": "byte:90"}]})
        self.assertTrue(result["ok"], result)
        self.assertTrue(os.path.isfile(out))
        self.assertNotIn("authorization", result["data"])


if __name__ == "__main__":
    unittest.main()
