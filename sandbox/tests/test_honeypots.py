"""Honeypot deploy + detection tests."""

import json
import os
import shutil
import tempfile
import unittest

from sandbox.honeypots import CANARY_PREFIX, MANIFEST_NAME, HoneypotSet


class HoneypotTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bp-hp-")
        self.root = os.path.join(self.tmp, "honeypots")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _deploy(self, profile="windows"):
        return HoneypotSet.deploy(self.root, profile)

    # -- deploy ----------------------------------------------------------
    def test_deploy_is_clean_and_manifest_is_private(self):
        hs = self._deploy()
        self.assertGreaterEqual(len(hs.artifacts), 10)
        rep = hs.audit([self.tmp])
        self.assertTrue(rep["summary"]["clean"], rep)
        self.assertEqual(rep["summary"]["total"], len(hs.artifacts))
        mode = os.stat(os.path.join(self.root, MANIFEST_NAME)).st_mode & 0o777
        self.assertEqual(mode, 0o600)
        self.assertTrue(os.path.isfile(os.path.join(self.root, MANIFEST_NAME)))

    def test_every_artifact_has_its_own_token(self):
        hs = self._deploy()
        tokens = [a.token for a in hs.artifacts]
        self.assertEqual(len(tokens), len(set(tokens)), "tokens must be unique per artifact")
        for tok in tokens:
            self.assertTrue(tok.startswith(CANARY_PREFIX))
            self.assertEqual(len(tok), len(CANARY_PREFIX) + 8)

    def test_expected_kinds_present(self):
        hs = self._deploy()
        kinds = {a.kind for a in hs.artifacts}
        for wanted in ("credential", "license", "wallet", "key", "document", "config"):
            self.assertIn(wanted, kinds)
        self.assertTrue(any("license" in a.relpath.lower() or a.kind == "license"
                            for a in hs.artifacts))

    def test_unknown_profile_rejected(self):
        with self.assertRaises(ValueError):
            HoneypotSet.deploy(self.root, "solaris")

    # -- detection -------------------------------------------------------
    def test_modified_artifact_detected(self):
        hs = self._deploy()
        victim = next(a for a in hs.artifacts if a.kind == "credential")
        with open(os.path.join(self.root, victim.relpath), "ab") as fh:
            fh.write(b"\ntampered\n")
        rep = hs.audit([self.tmp])
        hits = [h for h in rep["hits"] if h["change"] == "modified"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["relpath"], victim.relpath)
        self.assertIn(hits[0]["severity"], {"medium", "high"})
        self.assertFalse(rep["summary"]["clean"])

    def test_deleted_artifact_detected(self):
        hs = self._deploy()
        victim = next(a for a in hs.artifacts if a.kind == "wallet")
        os.unlink(os.path.join(self.root, victim.relpath))
        rep = hs.audit([self.tmp])
        hits = [h for h in rep["hits"] if h["change"] == "deleted"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["relpath"], victim.relpath)
        self.assertEqual(hits[0]["severity"], "high")

    def test_copied_artifact_is_caught_by_token(self):
        hs = self._deploy()
        victim = next(a for a in hs.artifacts if a.kind == "license")
        exfil = os.path.join(self.tmp, "exfil.txt")
        shutil.copyfile(os.path.join(self.root, victim.relpath), exfil)
        rep = hs.audit([self.tmp])
        hits = [h for h in rep["hits"] if h["change"] == "token_leaked"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(os.path.abspath(hits[0]["found_in"]), os.path.abspath(exfil))
        self.assertEqual(hits[0]["severity"], "high")
        self.assertFalse(rep["summary"]["clean"])

    def test_token_in_an_unrelated_log_is_still_caught(self):
        """A binary that logs the value it read is caught, not just a raw copy."""
        hs = self._deploy()
        victim = next(a for a in hs.artifacts if a.kind == "key")
        log = os.path.join(self.tmp, "run.log")
        with open(log, "w") as fh:
            fh.write("2026-01-01 loading config\n")
            fh.write("found value %s in profile\n" % victim.token)
        rep = hs.audit([self.tmp])
        self.assertIn(victim.token, [h["token"] for h in rep["hits"]])
        self.assertTrue(any(os.path.abspath(h["found_in"]) == os.path.abspath(log)
                            for h in rep["hits"] if h["found_in"]))

    def test_planted_files_do_not_self_match(self):
        hs = self._deploy()
        rep = hs.audit([self.tmp])
        self.assertEqual(rep["summary"]["leaked"], 0)

    def test_load_round_trips_manifest(self):
        hs = self._deploy()
        again = HoneypotSet.load(self.root)
        self.assertEqual([a.relpath for a in again.artifacts],
                         [a.relpath for a in hs.artifacts])
        self.assertEqual([a.token for a in again.artifacts], [a.token for a in hs.artifacts])
        payload = json.loads(json.dumps(again.to_dict()))
        self.assertEqual(payload["profile"], "windows")

    def test_other_profiles_deploy(self):
        for profile in ("linux", "both"):
            root = os.path.join(self.tmp, profile)
            hs = HoneypotSet.deploy(root, profile)
            self.assertGreaterEqual(len(hs.artifacts), 10)
            self.assertTrue(hs.audit([self.tmp])["summary"]["clean"], profile)

    def test_survives_broken_symlink_and_missing_dirs(self):
        hs = self._deploy()
        os.symlink("/nonexistent/target", os.path.join(self.tmp, "dangling"))
        os.symlink("/etc", os.path.join(self.tmp, "dirlink"))
        rep = hs.audit([self.tmp, "/nonexistent/root"])
        self.assertTrue(rep["summary"]["clean"], rep)
        self.assertIsInstance(rep["files_scanned"], int)

    def test_audit_does_not_mutate_the_root(self):
        hs = self._deploy()
        before = {a.relpath: a.sha256 for a in hs.artifacts}
        hs.audit([self.tmp])
        after = {a.relpath: a.sha256 for a in HoneypotSet.load(self.root).artifacts}
        self.assertEqual(before, after)


    def test_exclude_keeps_our_own_copies_out_of_the_leak_scan(self):
        """A VM run pulls the decoys back for comparison. Those copies are OURS, and they
        contain every token - without an exclusion the scan reports a dozen fake
        exfiltrations against itself."""
        hs = self._deploy()
        ours = os.path.join(self.tmp, "bait-after")
        os.makedirs(ours, exist_ok=True)
        victim = next(a for a in hs.artifacts if a.kind == "license")
        shutil.copyfile(os.path.join(self.root, victim.relpath),
                        os.path.join(ours, "license.key"))
        noisy = hs.audit([self.tmp])
        self.assertGreaterEqual(noisy["summary"]["leaked"], 1, "sanity: the copy is otherwise found")
        quiet = hs.audit([self.tmp], exclude=[ours])
        self.assertEqual(quiet["summary"]["leaked"], 0)
        self.assertTrue(quiet["summary"]["clean"])


if __name__ == "__main__":
    unittest.main()
