"""workflow: one job rendered as the exact calls that finish it.

The failure this covers is an agent with the right tools and no plan: it calls `plan`,
reads the candidates, and then improvises the patch payload. REA answers that with MCP
prompt templates. bobbypin answers it with a rendered sequence that already holds the
operator's paths, plus the checks that prove the job and the conditions under which
stopping is legitimate.

Rendering inspects nothing, so every fixture here is a made-up path.
"""

import json
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import bobbypin_ai as ai  # noqa: E402

ARGS_FOR = {
    "crack_licence": {"path": "/tmp/app.exe"},
    "bypass_login": {"path": "/tmp/app.exe"},
    "defeat_antidebug": {"path": "/tmp/app.exe"},
    "prove_patch": {"orig": "/tmp/app.exe", "new": "/tmp/app_patched.exe"},
    "compare_builds": {"old": "/tmp/v1.exe", "new": "/tmp/v2.exe"},
    "recover_source": {"path": "/tmp/app.apk"},
}

PLACEHOLDERS = ("%PATH%", "%OUT%", "%ORIG%", "%NEW%", "%OLD%", "%FAILURE%",
                "%OUTSRC%", "%OLDSRC%", "%NEWSRC%", "%STEM%", "%EXT%")


class ListTest(unittest.TestCase):
    def test_list_names_every_workflow_with_its_arguments(self):
        data = ai.cmd_workflow({"action": "list"})["data"]
        ids = [w["id"] for w in data["workflows"]]
        self.assertEqual(sorted(ids), sorted(ARGS_FOR))
        for entry in data["workflows"]:
            self.assertTrue(entry["title"] and entry["summary"], entry)
            self.assertTrue(entry["requires"], entry)
        self.assertIn("inspects nothing", data["note"])

    def test_an_unknown_id_is_an_error_that_lists_the_real_ones(self):
        res = ai.cmd_workflow({"id": "nope", "path": "/tmp/a.exe"})
        self.assertFalse(res["ok"])
        for wf in ARGS_FOR:
            self.assertIn(wf, res["error"])

    def test_a_missing_required_argument_names_the_field(self):
        res = ai.cmd_workflow({"id": "crack_licence"})
        self.assertFalse(res["ok"])
        self.assertIn('"path"', res["error"])
        self.assertIn("crack_licence", res["error"])

    def test_a_non_string_argument_is_refused_with_its_type(self):
        res = ai.cmd_workflow({"id": "crack_licence", "path": 123})
        self.assertFalse(res["ok"])
        self.assertIn("must be a string", res["error"])
        self.assertIn("int", res["error"])

    def test_a_non_string_optional_argument_is_refused_too(self):
        res = ai.cmd_workflow({"id": "crack_licence", "path": "/tmp/a.exe",
                               "failure": 7})
        self.assertFalse(res["ok"])
        self.assertIn("failure", res["error"])


class RenderTest(unittest.TestCase):
    def test_every_workflow_renders_with_no_placeholder_left(self):
        for wf, args in ARGS_FOR.items():
            payload = {"id": wf}
            payload.update(args)
            data = ai.cmd_workflow(payload)["data"]
            blob = json.dumps(data)
            for token in PLACEHOLDERS:
                self.assertNotIn(token, blob, "%s left %s" % (wf, token))
            self.assertTrue(data["steps"], wf)
            self.assertTrue(data["checks"], wf)
            self.assertTrue(data["stop_if"], wf)

    def test_rendering_is_honest_that_it_touched_nothing(self):
        data = ai.cmd_workflow({"id": "crack_licence", "path": "/nope/missing.exe"})["data"]
        self.assertFalse(data["touches_target"])
        self.assertIn("opened nothing", data["note"])

    def test_the_text_is_built_from_the_steps_not_from_a_second_copy(self):
        data = ai.cmd_workflow({"id": "crack_licence", "path": "/tmp/app.exe"})["data"]
        for step in data["steps"]:
            self.assertIn(step["call"], data["text"])
            self.assertIn(step["why"], data["text"])

    def test_the_flat_payload_and_the_mcp_arguments_object_agree(self):
        flat = ai.cmd_workflow({"id": "crack_licence", "path": "/tmp/app.exe"})["data"]
        nested = ai.cmd_workflow({"id": "crack_licence",
                                  "arguments": {"path": "/tmp/app.exe"}})["data"]
        self.assertEqual(flat["steps"], nested["steps"])

    def test_target_is_accepted_as_an_alias_for_path(self):
        aliased = ai.cmd_workflow({"id": "crack_licence", "target": "/tmp/app.exe"})["data"]
        plain = ai.cmd_workflow({"id": "crack_licence", "path": "/tmp/app.exe"})["data"]
        self.assertEqual(aliased["steps"], plain["steps"])

    def test_a_supplied_out_path_wins_over_the_default(self):
        data = ai.cmd_workflow({"id": "crack_licence", "path": "/tmp/app.exe",
                                "out": "/tmp/proof.exe"})["data"]
        patch = [s for s in data["steps"] if s["call"].startswith("patch ")][0]
        self.assertIn("/tmp/proof.exe", patch["call"])
        self.assertNotIn("app_patched.exe", patch["call"])

    def test_the_default_out_is_beside_the_target(self):
        data = ai.cmd_workflow({"id": "crack_licence", "path": "/tmp/app.exe"})["data"]
        verify = [s for s in data["steps"] if s["call"].startswith("verify ")][0]
        self.assertIn("/tmp/app_patched.exe", verify["call"])

    def test_the_optional_failure_text_reaches_the_reasoning(self):
        quiet = ai.cmd_workflow({"id": "crack_licence", "path": "/tmp/a.exe"})["data"]
        loud = ai.cmd_workflow({"id": "crack_licence", "path": "/tmp/a.exe",
                                "failure": "Licence expired"})["data"]
        self.assertNotIn("Licence expired", quiet["text"])
        self.assertIn("Licence expired", loud["text"])


class JobOrderTest(unittest.TestCase):
    """The order of the calls is the whole point of a workflow."""

    def order(self, wf, **extra):
        payload = {"id": wf}
        payload.update(ARGS_FOR[wf])
        payload.update(extra)
        calls = [s["call"] for s in ai.cmd_workflow(payload)["data"]["steps"]]
        return calls

    def test_a_licence_crack_routes_first_and_gates_last(self):
        calls = self.order("crack_licence")
        self.assertTrue(calls[0].startswith("route "), calls)
        self.assertTrue(calls[-1].startswith("done "), calls)
        self.assertIn("anti_analysis", calls[1])
        joined = " | ".join(calls)
        self.assertLess(joined.find("plan "), joined.find("disasm "))
        self.assertLess(joined.find("disasm "), joined.find("patch "))
        self.assertLess(joined.find("patch "), joined.find("verify "))
        self.assertLess(joined.find("verify "), joined.find("done "))

    def test_the_patch_step_carries_a_real_payload_not_a_description(self):
        calls = self.order("crack_licence")
        patch = [c for c in calls if c.startswith("patch ")][0]
        body = json.loads(patch[len("patch "):])
        self.assertEqual(body["patches"][0]["mode"], "flip")
        self.assertEqual(body["path"], "/tmp/app.exe")
        self.assertTrue(body["out"].endswith("app_patched.exe"))

    def test_an_antidebug_run_ends_by_showing_the_difference(self):
        calls = self.order("defeat_antidebug")
        self.assertIn("antidebug_patch", calls[1])
        self.assertIn('"verify": true', calls[1])
        runs = [c for c in calls if c.startswith("sandbox_run ")]
        self.assertEqual(len(runs), 2, calls)
        self.assertIn('"trip_debug": true', runs[0])

    def test_proving_a_patch_compares_bytes_before_running_anything(self):
        calls = self.order("prove_patch")
        self.assertTrue(calls[0].startswith("verify "), calls)
        self.assertTrue(any(c.startswith("sandbox_run ") for c in calls))

    def test_comparing_builds_triages_both_before_diffing(self):
        calls = self.order("compare_builds")
        self.assertEqual(sum(1 for c in calls if c.startswith("triage ")), 2, calls)
        joined = " | ".join(calls)
        self.assertLess(joined.find("triage "), joined.find("verify "))

    def test_recovering_source_never_asks_for_a_patch(self):
        calls = self.order("recover_source")
        joined = " ".join(calls)
        self.assertIn("recover_source ", joined)
        self.assertNotIn("patch {", joined)

    def test_nothing_patchable_is_a_next_task_not_an_ending(self):
        spec = ai._WORKFLOWS["defeat_antidebug"]["stop_if"]
        self.assertTrue(any("manual_candidates" in s for s in spec), spec)

    def test_every_workflow_says_when_it_is_finished(self):
        for wf, args in ARGS_FOR.items():
            payload = {"id": wf}
            payload.update(args)
            data = ai.cmd_workflow(payload)["data"]
            self.assertIn("done returns complete: true", data["when_done"], wf)


class RouteHookTest(unittest.TestCase):
    def test_every_route_that_points_at_a_workflow_points_at_a_real_one(self):
        for route, wf in ai._WORKFLOW_FOR_ROUTE.items():
            self.assertIn(wf, ai._WORKFLOWS, route)

    def test_the_native_route_offers_the_licence_workflow(self):
        data = ai._render_route("pe_native", "/tmp/app.exe")
        self.assertEqual(json.loads(data["workflow"][len("workflow "):])["id"],
                         "crack_licence")

    def test_routes_without_a_workflow_do_not_advertise_one(self):
        for route in ("asar", "unknown"):
            self.assertNotIn("workflow", ai._render_route(route, "/tmp/app.asar"), route)


class WiringTest(unittest.TestCase):
    def test_workflow_is_registered_and_documented(self):
        self.assertIn("workflow", ai.COMMANDS)
        self.assertIn("workflow", ai.cmd_help({})["data"]["commands"])

    def test_agents_md_mentions_the_command(self):
        with open(os.path.join(REPO, "AGENTS.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("bobbypin_ai.py workflow", text)
        self.assertIn("crack_licence", text)


if __name__ == "__main__":
    unittest.main()
