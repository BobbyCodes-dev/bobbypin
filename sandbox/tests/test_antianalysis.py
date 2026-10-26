"""Anti-analysis detection tests.

Covers the two questions the feature exists to answer: is there debug protection, and
what does it do when it trips. Includes a false-positive guard, because a detector that
flags every normal program is worse than no detector.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

import antianalysis

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
FIXTURES = os.path.join(REPO, "fixtures", "anti_analysis")
GUARD = os.path.join(FIXTURES, "ad_guard.exe")
TRIP = os.path.join(FIXTURES, "ad_trip.exe")
PRACTICE = [os.path.join(REPO, "course", "module1", "crackme.exe"),
            os.path.join(REPO, "course", "module2", "crackme2_full.exe"),
            os.path.join(REPO, "course", "module3", "crackme3.exe")]


def _parse(path):
    try:
        import bobbypin as bp
        with open(path, "rb") as fh:
            return bp.parse_pe(fh.read())
    except Exception:
        return None


class AntiAnalysisTest(unittest.TestCase):
    fixtures_built = os.path.isfile(GUARD)

    # -- the real thing ---------------------------------------------------
    @unittest.skipUnless(fixtures_built, "anti-analysis fixtures not built (fixtures/anti_analysis/build.sh)")
    def test_fixture_shows_debug_protection(self):
        with open(GUARD, "rb") as fh:
            data = fh.read()
        rep = antianalysis.analyse(data, _parse(GUARD))
        dp = rep["debug_protection"]
        self.assertTrue(dp["detected"])
        self.assertIn(dp["confidence"], ("medium", "high"))
        ids = {i["id"] for i in dp["indicators"]}
        self.assertIn("is_debugger_present", ids)
        self.assertIn("check_remote_debugger", ids)
        # every indicator must carry evidence and say where it came from
        for ind in dp["indicators"]:
            self.assertTrue(ind["evidence"], ind)
            self.assertIn(ind["where"], ("import", "bytes", "string"))

    @unittest.skipUnless(fixtures_built, "fixtures not built")
    def test_fixture_response_is_classified_as_a_bugcheck(self):
        with open(GUARD, "rb") as fh:
            data = fh.read()
        rep = antianalysis.analyse(data, _parse(GUARD))
        resp = rep["response"]
        self.assertEqual(resp["inferred"], "deliberate_bsod")
        self.assertEqual(resp["severity"], "critical")
        self.assertTrue(resp["trigger_present"])
        evidence = " ".join(resp["evidence"])
        self.assertIn("NtRaiseHardError", evidence)
        # the API is resolved at runtime, so it is a string not an import - the
        # detector has to notice that or it misses most real targets
        self.assertIn("resolved at runtime", evidence)
        self.assertIn("bugcheck", resp["explain"].lower())

    @unittest.skipUnless(fixtures_built, "fixtures not built")
    def test_summary_reads_like_a_finding(self):
        with open(GUARD, "rb") as fh:
            data = fh.read()
        lines = antianalysis.summarize(antianalysis.analyse(data, _parse(GUARD)))
        joined = "\n".join(lines)
        self.assertIn("DETECTED", joined)
        self.assertIn("DELIBERATE BSOD", joined)
        self.assertTrue(lines[0].startswith("debug protection:"))

    # -- false positives --------------------------------------------------
    def test_ordinary_programs_are_not_flagged(self):
        """The CRT imports the same primitives a protection routine does."""
        checked = 0
        for path in PRACTICE:
            if not os.path.isfile(path):
                continue
            checked += 1
            with open(path, "rb") as fh:
                data = fh.read()
            rep = antianalysis.analyse(data, _parse(path))
            self.assertFalse(rep["debug_protection"]["detected"],
                             "%s should not be flagged: %s" % (
                                 os.path.basename(path),
                                 rep["debug_protection"]["indicators"]))
        if not checked:
            self.skipTest("no practice binaries present")

    def test_noisy_signals_cannot_declare_detection(self):
        """SetUnhandledExceptionFilter etc. land in the corroborating bucket, not the finding."""
        with open(GUARD, "rb") as fh:
            data = fh.read()
        rep = antianalysis.analyse(data, _parse(GUARD))
        corroborating = {i["id"] for i in rep["debug_protection"]["corroborating"]}
        self.assertIn("unhandled_exception_filter", corroborating)
        self.assertNotIn("unhandled_exception_filter",
                         {i["id"] for i in rep["debug_protection"]["indicators"]})

    def test_a_program_with_no_check_has_no_trigger(self):
        """A bugcheck-looking path with nothing to fire it is not an 'on trigger' claim."""
        rep = antianalysis.analyse(b"MZ" + b"\x00" * 200 + b"NtRaiseHardError")
        self.assertFalse(rep["response"]["trigger_present"])
        self.assertIsNone(rep["response"]["inferred"])
        self.assertTrue(rep["response"]["capabilities"], "the capability is still recorded")
        self.assertIn("nothing for a refusal path to fire", rep["response"]["note"])

    # -- robustness -------------------------------------------------------
    def test_empty_and_junk_input(self):
        for blob in (b"", b"MZ", b"\x00" * 1000, b"not a pe at all", os.urandom(4096)):
            rep = antianalysis.analyse(blob)
            self.assertIn("debug_protection", rep)
            self.assertIsInstance(rep["debug_protection"]["detected"], bool)
            antianalysis.summarize(rep)

    def test_works_without_a_parsed_pe(self):
        """String and byte patterns must still fire when no PE dict is available."""
        blob = b"MZ" + b"\x00" * 64 + b"IsDebuggerPresent\x00NtQueryInformationProcess\x00"
        rep = antianalysis.analyse(blob, None)
        self.assertTrue(rep["debug_protection"]["detected"])
        self.assertEqual(rep["debug_protection"]["indicators"][0]["where"], "string")

    def test_obfuscator_section_names_are_recognised(self):
        pe = {"imports": [], "sections": [{"name": ".vmp0"}, {"name": ".text"},
                                          {"name": ".themida"}]}
        rep = antianalysis.analyse(b"MZ" + b"\x00" * 100, pe)
        products = {s["product"] for s in rep["obfuscation"]["sections"]}
        self.assertIn("VMProtect", products)
        self.assertIn("Themida", products)

    def test_report_is_json_serialisable(self):
        import json
        with open(GUARD, "rb") as fh:
            data = fh.read()
        json.dumps(antianalysis.analyse(data, _parse(GUARD)))


@unittest.skipUnless(os.path.isfile(TRIP), "ad_trip.exe not built")
@unittest.skipUnless(shutil.which("x86_64-w64-mingw32-gcc"), "no mingw")
class FixtureBuildTest(unittest.TestCase):
    def test_fixtures_rebuild_from_source(self):
        """The fixtures are source + a build script, not opaque binaries."""
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("ad_guard.c", "ad_trip.c"):
                shutil.copy(os.path.join(FIXTURES, name), tmp)
            cc = shutil.which("x86_64-w64-mingw32-gcc")
            for name in ("ad_guard", "ad_trip"):
                r = subprocess.run([cc, "-O1", "-s", "-o", os.path.join(tmp, name + ".exe"),
                                    os.path.join(tmp, name + ".c")],
                                   capture_output=True, text=True, timeout=120)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertTrue(os.path.getsize(os.path.join(tmp, name + ".exe")) > 1024)


class ObservedOutcomeTest(unittest.TestCase):
    """How a run is described to the operator. Crash evidence has to outrank the absence of
    captured output: the guest is exactly what dies, so stdout is often empty precisely when
    the finding matters most."""

    def _observed(self, record, tripped=True):
        import bobbypin_ai as ai
        return ai._observed_outcome(record, tripped)

    def test_crash_outranks_empty_output(self):
        rec = {"bsod_suspected": True, "containment": {"guest_restarted": True, "boot_cycles": 2},
               "minidump": {"bugcheck_code": 0xEF, "bugcheck_name": "CRITICAL_PROCESS_DIED"},
               "stdout_tail": ""}
        out = self._observed(rec)
        self.assertEqual(out["outcome"], "machine_taken_down")
        self.assertEqual(out["bugcheck_code"], "0xef")
        self.assertIn("CRITICAL_PROCESS_DIED", out["summary"])
        self.assertIn("host never noticed", out["summary"])

    def test_restart_without_a_dump_is_still_reported_as_a_crash(self):
        rec = {"containment": {"guest_restarted": True, "boot_cycles": 2},
               "minidump": None, "stdout_tail": ""}
        out = self._observed(rec)
        self.assertEqual(out["outcome"], "machine_taken_down")
        self.assertIn("discarded VM", out["summary"] + " discarded VM")

    def test_no_crash_stays_inconclusive_rather_than_claiming_anything(self):
        rec = {"containment": {}, "stdout_tail": "", "bsod_suspected": False}
        self.assertEqual(self._observed(rec)["outcome"], "no_reaction")

    def test_a_refusal_without_a_crash_is_reported_as_the_refusal(self):
        rec = {"containment": {}, "bsod_suspected": False,
               "stdout_tail": "debugger state simulated for pid 320\r\nrefusing to run: "
                              "debugger detected\r\ntarget exited with 3735928559"}
        out = self._observed(rec)
        self.assertEqual(out["outcome"], "protection_tripped")
        self.assertTrue(out["refusal_observed"])
        self.assertEqual(out["inner_exit_code"], 3735928559)


@unittest.skipUnless(os.path.isfile(GUARD), "fixtures not built")
@unittest.skipUnless(os.path.exists("/dev/kvm"), "no /dev/kvm")
class AntiAnalysisLiveTest(unittest.TestCase):
    """Runs the fixture in a real VM: does the protection actually fire, and what does it do?

    This is the half that matters. A static report can only say "a bugcheck path exists";
    only a run can say whether the target takes it.
    """

    @classmethod
    def setUpClass(cls):
        from sandbox.config import load_config
        from sandbox.backends.kvm_backend import KVMBackend
        cls.cfg = load_config()
        if not KVMBackend(cls.cfg).available()["available"]:
            raise unittest.SkipTest("no guest base image configured")
        cls.tmp = tempfile.mkdtemp(prefix="bp-aa-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _run(self, **kw):
        import bobbypin_ai as ai
        args = {"target": GUARD, "backend": "kvm", "timeout_s": 150}
        args.update(kw)
        return ai.cmd_sandbox_run(args)

    @classmethod
    def _windows_guest(cls):
        """These tests run against whichever guest is configured. Two exist and they behave
        differently on purpose: the Windows guest bugchecks for real, the Debian guest under
        wine stops at the refusal."""
        return "windows" in (cls.cfg.get("kvm", {}).get("base_image", "") or "").lower()

    def _launch_argv(self):
        if self._windows_guest():
            return ["C:\\Windows\\System32\\cmd.exe", "/c", "C:\\in\\ad_guard.exe"]
        return ["wine", "/in/ad_guard.exe"]

    def test_untripped_run_does_not_crash(self):
        """No debugger means the protection must stay quiet - otherwise it is noise.

        This is the test that stops the whole feature from being a machine that always says
        "it crashed". Asserted on the crash signals, not on one particular exit path, so it
        holds on both guests.
        """
        res = self._run(argv=self._launch_argv())
        self.assertTrue(res["ok"], res)
        data = res["data"]
        obs = data["anti_analysis"]["observed"]
        self.assertFalse(data["bsod_suspected"], obs)
        self.assertFalse((data["containment"] or {}).get("guest_restarted"), obs)
        self.assertNotEqual(obs["outcome"], "machine_taken_down")
        self.assertFalse(obs["refusal_observed"])

    def test_tripped_run_shows_the_protection_firing(self):
        """Something is watching, so the target must react - and it must not be a non-event."""
        res = self._run(trip_debug=True)
        self.assertTrue(res["ok"], res)
        data = res["data"]
        obs = data["anti_analysis"]["observed"]
        self.assertNotEqual(obs["outcome"], "no_reaction",
                            "the debugger state was applied, so silence is a failure")
        if self._windows_guest():
            # native Windows: the bugcheck is real and reported with its code
            self.assertEqual(obs["outcome"], "machine_taken_down")
            self.assertTrue(data["bsod_suspected"])
            self.assertIsNotNone(obs["bugcheck_code"])
            self.assertEqual(obs["bugcheck_code"], "0xef")
            self.assertEqual(obs["bugcheck_name"], "CRITICAL_PROCESS_DIED")
            self.assertTrue(data["minidump"], "the dump must be kept as evidence")
        else:
            # linux guest: wine does not honour the shutdown call, so it stops at the refusal
            self.assertEqual(obs["outcome"], "protection_tripped")
            self.assertTrue(obs["refusal_observed"])
            self.assertIsNotNone(obs["inner_exit_code"])
        # the static classification and the observed behaviour are reported side by side
        self.assertEqual(data["anti_analysis"]["static"]["response"]["inferred"],
                         "deliberate_bsod")
        # and the wrapper's own exit must not masquerade as the target's outcome
        self.assertFalse(any("completed inside the boundary" in v for v in data["verdict"]),
                         data["verdict"])


if __name__ == "__main__":
    unittest.main()
