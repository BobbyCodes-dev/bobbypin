"""Debug-protection patch tests.

Covers the loop the feature exists for: detect, patch the check whose verdict can be
forced, and report honestly about the ones it cannot. The important tests here are the
refusals - patching in place, patching a check whose semantics are not a BOOLEAN, patching
a target that has no protection at all. A patcher that quietly does the wrong thing to a
binary is worse than one that lists what it would not touch.
"""

import json
import os
import shutil
import tempfile
import unittest

import antidebug_patch as adp

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
FIXTURES = os.path.join(REPO, "fixtures", "anti_analysis")
GUARD = os.path.join(FIXTURES, "ad_guard.exe")
NTQIP = os.path.join(FIXTURES, "ad_ntqip.exe")
PRACTICE = os.path.join(REPO, "course", "module1", "crackme.exe")

# what a forced-clean BOOLEAN call looks like: xor eax,eax + NOP padding
CLEAN_6 = "31c090909090"


def _load(path):
    with open(path, "rb") as fh:
        return fh.read()


def _pe(data):
    import bobbypin as bp
    return bp.parse_pe(data)


def _report(data, pe):
    import antianalysis
    return antianalysis.analyse(data, pe)


@unittest.skipUnless(os.path.isfile(GUARD), "fixtures not built (fixtures/anti_analysis/build.sh)")
class PatchPlanTest(unittest.TestCase):
    """Static behaviour, no VM needed."""

    @classmethod
    def setUpClass(cls):
        cls.data = _load(GUARD)
        cls.pe = _pe(cls.data)
        cls.report = _report(cls.data, cls.pe)

    def test_import_slots_resolve_to_the_detection_apis(self):
        """The patch works off the import table, so the slots have to be found first."""
        slots, span = adp.iat_slots(self.data, self.pe)
        self.assertIn("isdebuggerpresent", slots)
        self.assertIn("checkremotedebuggerpresent", slots)
        self.assertIsNotNone(span)
        self.assertLess(span[0], span[1])

    def test_detection_api_is_called_directly_through_the_iat(self):
        """`call [slot]` is what makes the check patchable at all."""
        slots, span = adp.iat_slots(self.data, self.pe)
        sites, method = adp.find_call_sites(self.data, self.pe, slots, span)
        self.assertIn(method, ("capstone", "structural"))
        apis = {s["api"] for s in sites}
        self.assertIn("isdebuggerpresent", apis)
        self.assertIn("checkremotedebuggerpresent", apis)
        for s in sites:
            self.assertEqual(s["size"], 6, s)
            self.assertTrue(s["bytes"].startswith("ff15"), s)

    def test_plan_patches_the_boolean_verdict_checks(self):
        plan = adp.plan(self.data, self.pe, self.report)
        ids = {p["id"] for p in plan["patchable"]}
        self.assertEqual(ids, {"is_debugger_present", "check_remote_debugger"})
        for p in plan["patchable"]:
            self.assertEqual(p["class"], "A")
            self.assertEqual(p["after"], CLEAN_6)
            self.assertTrue(p["why"])

    def test_patch_preserves_instruction_length(self):
        """Nothing may move: a length-changing patch desynchronises every later offset."""
        plan = adp.plan(self.data, self.pe, self.report)
        for p in plan["patchable"]:
            self.assertEqual(len(bytes.fromhex(p["before"])),
                             len(bytes.fromhex(p["after"])), p)

    def test_applied_bytes_land_at_the_call_site(self):
        plan = adp.plan(self.data, self.pe, self.report)
        new, results = adp.apply(self.data, plan["patchable"])
        self.assertEqual(len(new), len(self.data), "file length must not change")
        self.assertTrue(all(r["status"] == "applied" for r in results), results)
        for p in plan["patchable"]:
            self.assertEqual(new[p["offset"]:p["offset"] + p["size"]].hex(), CLEAN_6, p)
            self.assertEqual(new[p["offset"]:p["offset"] + p["size"]].hex(), p["after"])

    def test_apply_refuses_when_the_file_moved_under_it(self):
        """A stale offset must fail loudly rather than corrupt a different instruction."""
        plan = adp.plan(self.data, self.pe, self.report)
        stale = [dict(plan["patchable"][0], before="aabbccddeeff")]
        new, results = adp.apply(self.data, stale)
        self.assertEqual(results[0]["status"], "error")
        self.assertIn("changed under the patch", results[0]["detail"])
        self.assertEqual(new, self.data, "nothing may be written on a refusal")

    def test_diff_reports_exactly_the_patches(self):
        plan = adp.plan(self.data, self.pe, self.report)
        new, _ = adp.apply(self.data, plan["patchable"])
        diff = adp.verify(self.data, new)
        self.assertEqual(len(diff), len(plan["patchable"]))
        for d, p in zip(sorted(diff, key=lambda d: d["offset"]),
                        sorted(plan["patchable"], key=lambda p: p["offset"])):
            self.assertEqual(d["offset"], p["offset"])
            self.assertEqual(d["before"], p["before"])
            self.assertEqual(d["after"], p["after"])

    def test_every_unpatched_check_carries_a_reason(self):
        """The skipped list is the honest half of the feature - and the reason is the point."""
        plan = adp.plan(self.data, self.pe, self.report)
        self.assertTrue(plan["skipped"])
        for s in plan["skipped"]:
            self.assertTrue(s.get("why"), s)
            self.assertIn(s.get("class"), ("B", "C", "D", "E"), s)
            self.assertTrue(s.get("id"), s)

    def test_direct_peb_read_is_not_auto_patched(self):
        """A direct PEB read must never be 'fixed' by zeroing the base pointer."""
        fake = {"debug_protection": {"detected": True, "confidence": "high",
                "indicators": [{"id": "peb_being_debugged_bytes", "family": "debugger_detect",
                                "severity": "high", "weak": False, "where": "bytes",
                                "evidence": "byte pattern 64a130000000 @ file offset 0x1200",
                                "why": ""}]}}
        plan = adp.plan(self.data, self.pe, fake)
        self.assertEqual(plan["patchable"], [])
        skipped = {s["id"]: s for s in plan["skipped"]}
        self.assertIn("peb_being_debugged_bytes", skipped)
        self.assertEqual(skipped["peb_being_debugged_bytes"]["class"], "C")
        self.assertIn("dereference", skipped["peb_being_debugged_bytes"]["why"])

    def test_no_report_means_patch_what_you_find_a_clean_report_means_nothing(self):
        """The two are different: 'no report' is not 'found nothing'."""
        everything = adp.plan(self.data, self.pe, None)
        self.assertEqual(len(everything["patchable"]), 2)
        clean = adp.plan(self.data, self.pe,
                         {"debug_protection": {"detected": False, "confidence": "none",
                                               "indicators": [], "corroborating": []}})
        self.assertEqual(clean["patchable"], [])

    def test_structural_scan_agrees_with_the_decoded_one(self):
        """The fallback is only acceptable because it produces the same answer."""
        slots, span = adp.iat_slots(self.data, self.pe)
        decoded, method = adp.find_call_sites(self.data, self.pe, slots, span)
        if method != "capstone":
            self.skipTest("capstone not installed, so there is no decoded scan to compare")
        original = adp._decode_available
        adp._decode_available = lambda: False
        try:
            structural, _ = adp.find_call_sites(self.data, self.pe, slots, span)
        finally:
            adp._decode_available = original
        key = lambda s: (s["offset"], s["api"], s["size"])
        self.assertEqual([key(s) for s in structural], [key(s) for s in decoded])


@unittest.skipUnless(os.path.isfile(GUARD), "fixtures not built")
class PatchRunTest(unittest.TestCase):
    """The file-level pipeline: refusals, and what it will not touch."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bp-adp-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_never_patches_in_place(self):
        before = adp._sha(_load(GUARD))
        res = adp.run(GUARD, GUARD)
        self.assertFalse(res["ok"])
        self.assertIn("in place", res["error"])
        self.assertEqual(adp._sha(_load(GUARD)), before, "the original must be byte-identical")

    def test_patches_to_a_copy_and_reports_hashes(self):
        out = os.path.join(self.tmp, "guard_patched.exe")
        res = adp.run(GUARD, out)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["status"], "patched")
        self.assertEqual(res["applied_count"], 2)
        self.assertTrue(os.path.isfile(out))
        self.assertEqual(len(_load(out)), len(_load(GUARD)))
        self.assertNotEqual(res["hashes"]["before"], res["hashes"]["after"])
        self.assertEqual(res["hashes"]["before"],
                         adp._sha(_load(GUARD)), "before-hash must be the original")
        self.assertEqual(res["hashes"]["after"], adp._sha(_load(out)))

    def test_a_target_without_protection_is_left_alone(self):
        """No detection means no patch and no output file - not a speculative edit."""
        if not os.path.isfile(PRACTICE):
            self.skipTest("practice target missing")
        out = os.path.join(self.tmp, "practice_patched.exe")
        res = adp.run(PRACTICE, out)
        self.assertTrue(res["ok"], res)
        if res["status"] == "nothing_patchable":
            self.assertFalse(os.path.exists(out), "no output should be written")
            self.assertIn("manual patch", res["message"])
        else:  # it does have a patchable check: then the patch has to be real
            self.assertEqual(res["applied_count"], len(res["plan"]["patchable"]))

    def test_a_non_pe_is_refused_rather_than_guessed_at(self):
        junk = os.path.join(self.tmp, "not_a_pe.bin")
        with open(junk, "wb") as fh:
            fh.write(b"this is not a PE file at all\n" * 8)
        res = adp.run(junk, os.path.join(self.tmp, "out.exe"))
        self.assertFalse(res["ok"])
        self.assertIn("PE", res["error"])


@unittest.skipUnless(os.path.isfile(GUARD), "fixtures not built")
class PatchVerdictTest(unittest.TestCase):
    """The wording of the verdict is a claim, so it is tested rather than trusted.

    The two guest runs are what makes the claim, so they are faked here: a verdict that
    says "neutralised" when the protection still fires would be the worst possible
    failure, and it costs nothing to prove the logic can tell the difference.
    """

    def setUp(self):
        import bobbypin_ai as ai
        self.ai = ai
        if ai._sandbox_runner is None:
            self.skipTest("sandbox package unavailable")
        self.orig = ai.cmd_sandbox_run
        self.addCleanup(setattr, ai, "cmd_sandbox_run", self.orig)

    def _fake(self, before, after):
        runs = [before, after]

        def cmd(args):
            return runs.pop(0)
        self.ai.cmd_sandbox_run = cmd

    def _result(self, crashed=False, restarted=False, code=None, exit_code=0):
        return {"ok": True, "data": {"crashed": crashed,
                                     "minidump": {"bugcheck_code": code} if code else {},
                                     "containment": {"guest_restarted": restarted},
                                     "exit_code": exit_code, "stdout_tail": "",
                                     "anti_analysis": {"observed": {"summary": "x"}}}}

    def test_fired_before_and_silent_after_is_neutralised(self):
        self._fake(self._result(crashed=True, restarted=True, code=239),
                   self._result(exit_code=1))
        v = self.ai._verify_patch("orig", "patched", {})
        self.assertEqual(v["verdict"], "neutralised")
        self.assertIn("same target", v["summary"])

    def test_still_firing_after_is_reported_as_insufficient(self):
        """The failure that matters: never call a patch good because it was applied."""
        self._fake(self._result(crashed=True, restarted=True, code=239),
                   self._result(crashed=True, restarted=True, code=239))
        v = self.ai._verify_patch("orig", "patched", {})
        self.assertEqual(v["verdict"], "still_fires")
        self.assertIn("insufficient", v["summary"])

    def test_nothing_fired_before_means_nothing_was_proven(self):
        self._fake(self._result(), self._result())
        v = self.ai._verify_patch("orig", "patched", {})
        self.assertEqual(v["verdict"], "nothing_to_prove")

    def test_a_guest_that_will_not_run_is_inconclusive(self):
        self._fake({"ok": False, "error": "no guest"}, self._result())
        v = self.ai._verify_patch("orig", "patched", {})
        self.assertEqual(v["verdict"], "inconclusive")


@unittest.skipUnless(os.path.isfile(NTQIP), "ad_ntqip.exe not built")
class NtQipPlanTest(unittest.TestCase):
    """NtQueryInformationProcess: the class where the obvious patch is the wrong one.

    Its return value is NTSTATUS (0 == the query SUCCEEDED) and the verdict is in the out
    buffer, so zeroing EAX alone would tell the caller the query worked and it would then read
    whatever the buffer already held. The InfoClass decides whether anything can be forced at
    all, so most of these tests are about what the module refuses.
    """

    @classmethod
    def setUpClass(cls):
        cls.data = _load(NTQIP)
        cls.pe = _pe(cls.data)

    def test_the_class_is_read_from_the_argument_setup(self):
        if not adp._decode_available():
            self.skipTest("capstone not installed, so the InfoClass cannot be read")
        slots, span = adp.iat_slots(self.data, self.pe)
        sites, _ = adp.find_call_sites(self.data, self.pe, slots, span)
        call = [s for s in sites if s["api"] == "ntqueryinformationprocess"][0]
        cls, note = adp._info_class(self.data, self.pe, call["offset"])
        self.assertEqual(cls, 7, note)
        self.assertIn("mov edx", note)

    def test_the_patch_forces_the_status_and_zeroes_the_out_buffer(self):
        if not adp._decode_available():
            self.skipTest("capstone not installed")
        plan = adp.plan(self.data, self.pe, _report(self.data, self.pe))
        self.assertEqual(len(plan["patchable"]), 1, plan)
        p = plan["patchable"][0]
        self.assertEqual(p["id"], "nt_query_information_process")
        self.assertEqual(p["before"], "ff1548bc0000")
        self.assertEqual(p["after"], "31c049832000")
        self.assertEqual(len(bytes.fromhex(p["after"])), 6, "must fit the call slot")
        self.assertIn("STATUS_SUCCESS", p["why"])
        self.assertIn("ProcessDebugPort", p["why"])

    def test_the_patched_bytes_are_xor_eax_then_and_qword_r8_zero(self):
        """Spelled out, because 'and qword ptr [r8], 0' is the part that zeroes the buffer and
        r8 is the out-pointer by the x64 calling convention, not by convention of this code."""
        self.assertEqual(adp.CLEAN_ZERO_CALL, b"\x31\xc0\x49\x83\x20\x00")
        self.assertEqual(adp.CLEAN_ZERO_CLASSES[7][0], "ProcessDebugPort")
        self.assertIn(0x1E, adp.CLEAN_ZERO_CLASSES)

    def test_the_inverted_class_is_refused_with_its_reason(self):
        """ProcessDebugFlags is a debug check, and it still cannot be forced here: its clean
        value is 1, and 1 plus a status does not fit in six bytes."""
        original = adp._info_class
        adp._info_class = lambda *a, **k: (0x1F, "stubbed")
        try:
            slots, span = adp.iat_slots(self.data, self.pe)
            sites, _ = adp.find_call_sites(self.data, self.pe, slots, span)
            ok, refused = adp._ntqip_sites(self.data, self.pe,
                                           [s for s in sites if "ntquery" in s["api"]])
        finally:
            adp._info_class = original
        self.assertEqual(ok, [])
        self.assertIn("ProcessDebugFlags", refused[0]["why"])
        self.assertIn("INVERSE", refused[0]["why"])

    def test_an_unrelated_info_class_is_refused_because_its_buffer_is_data(self):
        """NtQueryInformationProcess is used for plenty that has nothing to do with debuggers.
        Zeroing the out buffer of one of those would corrupt a struct the caller uses."""
        original = adp._info_class
        adp._info_class = lambda *a, **k: (0, "stubbed ProcessBasicInformation")
        try:
            slots, span = adp.iat_slots(self.data, self.pe)
            sites, _ = adp.find_call_sites(self.data, self.pe, slots, span)
            ok, refused = adp._ntqip_sites(self.data, self.pe,
                                           [s for s in sites if "ntquery" in s["api"]])
        finally:
            adp._info_class = original
        self.assertEqual(ok, [])
        self.assertIn("not a debug check", refused[0]["why"])
        self.assertIn("corrupt", refused[0]["why"])

    def test_an_unreadable_class_is_refused_rather_than_guessed(self):
        original = adp._info_class
        adp._info_class = lambda *a, **k: (None, "could not decode")
        try:
            slots, span = adp.iat_slots(self.data, self.pe)
            sites, _ = adp.find_call_sites(self.data, self.pe, slots, span)
            ok, refused = adp._ntqip_sites(self.data, self.pe,
                                           [s for s in sites if "ntquery" in s["api"]])
        finally:
            adp._info_class = original
        self.assertEqual(ok, [])
        self.assertIn("could not be read", refused[0]["why"])

    def test_a_32_bit_target_is_refused(self):
        """On x86 the class is the second stack argument, so it cannot be read without
        tracking the stack - and guessing is not an option here."""
        pe = dict(self.pe, pe32plus=False)
        cls, why = adp._info_class(self.data, pe, 0)
        self.assertIsNone(cls)
        self.assertIn("stack", why)

    def test_no_capstone_means_no_guess(self):
        """The decode is the precondition, so its absence has to be a refusal, not a default."""
        original = adp._decode_available
        adp._decode_available = lambda: False
        try:
            cls, why = adp._info_class(self.data, dict(self.pe, pe32plus=True), 0)
        finally:
            adp._decode_available = original
        self.assertIsNone(cls)
        self.assertIn("capstone", why)


@unittest.skipUnless(os.path.isfile(NTQIP), "ad_ntqip.exe not built")
class NtQipPatchRunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bp-ntqip-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_run_patches_the_fixture_and_keeps_the_file_length(self):
        if not adp._decode_available():
            self.skipTest("capstone not installed, so there is no InfoClass to read")
        out = os.path.join(self.tmp, "ntqip_patched.exe")
        res = adp.run(NTQIP, out)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["status"], "patched")
        self.assertEqual(res["applied_count"], 1)
        self.assertEqual(len(_load(out)), len(_load(NTQIP)))
        # The applied record is what was written - all 6 bytes. `diff` is a byte-difference
        # view, so it can be shorter than the patch when a written byte happens to equal the
        # one it replaced (here the call's trailing 0x00), and that is not a short write.
        self.assertEqual(res["applied"][0]["after"], "31c049832000")
        self.assertEqual(res["diff"][0]["offset"], res["applied"][0]["offset"])
        self.assertEqual(_load(out)[res["applied"][0]["offset"]:
                                   res["applied"][0]["offset"] + 6].hex(), "31c049832000")


@unittest.skipUnless(os.path.isfile(NTQIP), "ad_ntqip.exe not built")
@unittest.skipUnless(os.path.exists("/dev/kvm"), "no /dev/kvm")
class NtQipPatchLiveTest(unittest.TestCase):
    """Both halves, in the real guest, because either one alone proves nothing.

    The unpatched half is not decoration: a fixture that never fires would make the patched
    half pass for free. This is also the test that proves `trip_debug` reaches EPROCESS state
    and not just PEB.BeingDebugged - ProcessDebugPort only reports a debugger if one is really
    attached, so if ad_trip's attach ever stops working, this fires first.
    """

    @classmethod
    def setUpClass(cls):
        from sandbox.config import load_config
        from sandbox.backends.kvm_backend import KVMBackend
        cls.cfg = load_config()
        if not KVMBackend(cls.cfg).available()["available"]:
            raise unittest.SkipTest("no guest base image configured")
        cls.tmp = tempfile.mkdtemp(prefix="bp-ntqip-live-")
        cls.patched = os.path.join(cls.tmp, "ntqip_patched.exe")
        res = adp.run(NTQIP, cls.patched)
        if res.get("status") != "patched":
            raise unittest.SkipTest("fixture has nothing patchable: %s" % res.get("status"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _run(self, target):
        import bobbypin_ai as ai
        res = ai.cmd_sandbox_run({"target": target, "backend": "kvm", "trip_debug": True,
                                  "timeout_s": 200, "honeypots": False})
        self.assertTrue(res["ok"], res)
        return res["data"]

    def test_the_unpatched_fixture_fires_on_the_debug_port(self):
        data = self._run(NTQIP)
        self.assertTrue(data["bsod_suspected"] or data["crashed"],
                        "ProcessDebugPort reported a debugger but the target did nothing: %s"
                        % data.get("anti_analysis"))
        dump = data.get("minidump") or {}
        self.assertEqual(dump.get("bugcheck_code"), 0xEF, dump)

    def test_the_patched_fixture_does_not_fire(self):
        data = self._run(self.patched)
        obs = data["anti_analysis"]["observed"]
        self.assertFalse(data["bsod_suspected"], obs)
        self.assertFalse(data["crashed"], obs)
        self.assertFalse((data["containment"] or {}).get("guest_restarted"), obs)
        self.assertIsNone((data.get("minidump") or {}).get("bugcheck_code"), obs)


@unittest.skipUnless(os.path.isfile(GUARD), "fixtures not built")
class AgentWiringTest(unittest.TestCase):
    """The AI-facing half: an agent that only reads reports has to be told what to run.

    A finding nobody acts on is a finding wasted, so the pointer from "protection detected"
    to `antidebug_patch` - and to the boundary, which is the only place the target may be
    run by hand while the protection is standing - is asserted at every entry point an
    agent lands on, not just in the README.
    """

    def test_plan_points_at_the_patcher_and_warns_about_the_boundary(self):
        import bobbypin_ai as ai
        res = ai.cmd_plan({"path": GUARD})
        self.assertTrue(res["ok"], res)
        steps = " ".join(res["data"]["suggested_next"])
        self.assertIn("antidebug_patch", steps)
        self.assertIn("DO NOT run this target outside the boundary", steps)
        self.assertIn("plan.skipped", steps, "the agent must know some checks stay unpatched")

    def test_anti_analysis_carries_the_same_hint(self):
        import bobbypin_ai as ai
        res = ai.cmd_anti_analysis({"path": GUARD})
        self.assertTrue(res["ok"], res)
        steps = " ".join(res["data"]["suggested_next"])
        self.assertIn("antidebug_patch", steps)
        self.assertIn("trip_debug", steps)

    def test_help_lists_the_command_so_it_is_discoverable(self):
        import bobbypin_ai as ai
        blob = json.dumps(ai.cmd_help(None))
        self.assertIn("antidebug_patch", blob)
        self.assertIn("plan.skipped", blob)

    def test_the_hint_names_the_response_that_makes_it_urgent(self):
        """The warning is only worth having if it says what will happen."""
        import bobbypin_ai as ai
        steps = " ".join(ai._antidebug_next_steps(
            {"debug_protection": {"detected": True, "confidence": "high", "indicators": [{}]},
             "response": {"label": "deliberate BSOD (bugcheck)"}}))
        self.assertIn("deliberate BSOD (bugcheck)", steps)

    def test_a_clean_target_is_not_told_to_patch_anything(self):
        """Crying wolf trains an agent to skip the warning, so silence on a clean binary."""
        if not os.path.isfile(PRACTICE):
            self.skipTest("practice target missing")
        import bobbypin_ai as ai
        res = ai.cmd_plan({"path": PRACTICE})
        self.assertNotIn("antidebug_patch", " ".join(res["data"].get("suggested_next") or []))
        self.assertEqual(ai._antidebug_next_steps(
            {"debug_protection": {"detected": False}}), [])


@unittest.skipUnless(os.path.isfile(GUARD), "fixtures not built")
@unittest.skipUnless(os.path.exists("/dev/kvm"), "no /dev/kvm")
class PatchLiveTest(unittest.TestCase):
    """One real boot: the patched binary must stop firing in the guest.

    The other half (that the *unpatched* fixture does fire) is asserted by
    test_antianalysis.AntiAnalysisLiveTest, so this only has to prove the change.
    """

    @classmethod
    def setUpClass(cls):
        from sandbox.config import load_config
        from sandbox.backends.kvm_backend import KVMBackend
        cls.cfg = load_config()
        if not KVMBackend(cls.cfg).available()["available"]:
            raise unittest.SkipTest("no guest base image configured")
        cls.tmp = tempfile.mkdtemp(prefix="bp-adp-live-")
        cls.patched = os.path.join(cls.tmp, "guard_patched.exe")
        res = adp.run(GUARD, cls.patched)
        if not res.get("status") == "patched":
            raise unittest.SkipTest("fixture has nothing patchable: %s" % res.get("status"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_patched_target_no_longer_reacts_to_the_simulated_debugger(self):
        import bobbypin_ai as ai
        res = ai.cmd_sandbox_run({"target": self.patched, "backend": "kvm",
                                  "trip_debug": True, "timeout_s": 150,
                                  "honeypots": False})
        self.assertTrue(res["ok"], res)
        data = res["data"]
        obs = data["anti_analysis"]["observed"]
        self.assertFalse(data["bsod_suspected"], obs)
        self.assertFalse(data["crashed"], obs)
        self.assertFalse((data["containment"] or {}).get("guest_restarted"), obs)
        self.assertNotEqual(obs["outcome"], "machine_taken_down")
        self.assertIsNone((data.get("minidump") or {}).get("bugcheck_code"), obs)
