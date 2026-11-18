"""route / guidance: the two calls that stop an agent guessing.

`route` answers "what is this file and what do I call first", so the playbook is
picked from the artifact instead of from the file extension or the agent's mood.
`guidance` answers "which paragraph of the manual covers this", so an agent does
not page through 35 KB of markdown to find one rule and still miss it.

Both are pure reads over the repository, so the fixtures are built here.
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
        self.tmp = tempfile.mkdtemp(prefix="bp-route-")
        self.target = os.path.join(self.tmp, "app.exe")
        with open(self.target, "wb") as fh:
            fh.write(_pe())

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.unlink(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)


class RouteClassTest(unittest.TestCase):
    """The playbook is keyed off triage output, never off the filename."""

    def test_native_pe_gets_the_patch_loop(self):
        self.assertEqual(ai._route_class({"kind": "pe32"}), "pe_native")
        self.assertEqual(ai._route_class({"kind": "pe32+"}), "pe_native")

    def test_a_managed_assembly_never_gets_the_patch_loop(self):
        self.assertEqual(ai._route_class({"kind": "pe32+", "dotnet": True}), "dotnet")

    def test_managed_wins_over_packers(self):
        rep = {"kind": "pe32", "dotnet": True, "packers": ["UPX"]}
        self.assertEqual(ai._route_class(rep), "dotnet")

    def test_a_upx_target_is_routed_to_unpack_first(self):
        self.assertEqual(ai._route_class({"kind": "pe32", "packers": ["upx"]}),
                         "pe_packed")

    def test_every_container_kind_maps_to_its_own_route(self):
        for kind, route in (("asar", "asar"), ("apk", "apk"), ("jar", "jar"),
                            ("pyinstaller", "pyinstaller"), ("elf", "native_posix"),
                            ("macho", "native_posix")):
            self.assertEqual(ai._route_class({"kind": kind}), route, kind)

    def test_an_unrecognised_file_is_routed_to_identification(self):
        self.assertEqual(ai._route_class({"kind": "unknown"}), "unknown")
        self.assertEqual(ai._route_class({}), "unknown")


class RoutePayloadTest(unittest.TestCase):
    """Every template has to render to copy-pasteable calls with no placeholders left."""

    def test_every_route_renders_without_a_leftover_placeholder(self):
        for cls in ai._ROUTE_TEMPLATES:
            data = ai._render_route(cls, "/tmp/sample.bin")
            blob = json.dumps(data)
            for token in ("%PATH%", "%OUT%", "%STEM%", "%EXT%"):
                self.assertNotIn(token, blob, "%s left %s" % (cls, token))
            self.assertTrue(data["steps"], cls)
            self.assertEqual(data["first_command"], data["steps"][0]["call"])
            self.assertTrue(data["job"] and data["why"], cls)
            self.assertTrue(data["stop_if"], cls)
            self.assertTrue(data["do_not"], cls)

    def test_the_universal_rules_are_on_every_route(self):
        for cls in ai._ROUTE_TEMPLATES:
            data = ai._render_route(cls, "/tmp/sample.bin")
            self.assertTrue(data["in_scope"])
            self.assertTrue(data["nothing_to_confirm"])
            self.assertIn("done", data["finish_with"])
            self.assertTrue(any("walk" in r or "repeat" in r
                                for r in data["do_not"]), cls)

    def test_only_routes_that_end_in_an_artifact_advertise_one(self):
        native = ai._render_route("pe_native", "/tmp/app.exe")
        self.assertEqual(native["patched_copy_would_be"], "/tmp/app_patched.exe")
        for cls in ("dotnet", "apk", "jar", "pyinstaller", "native_posix", "unknown",
                    "pe_packed"):
            self.assertNotIn("patched_copy_would_be",
                             ai._render_route(cls, "/tmp/app.bin"), cls)

    def test_the_asar_route_repacks_in_place_and_says_why(self):
        data = ai._render_route("asar", "/opt/app/resources/app.asar")
        bypass = [s for s in data["steps"] if "electron_bypass" in s["call"]]
        self.assertEqual(len(bypass), 1)
        self.assertIn('"out": "/opt/app/resources/app.asar"', bypass[0]["call"])
        self.assertEqual(data["patched_copy_would_be"], "/opt/app/resources/app.asar")

    def test_the_managed_route_has_no_patch_step(self):
        data = ai._render_route("dotnet", "/tmp/App.dll")
        calls = " ".join(s["call"] for s in data["steps"])
        self.assertNotIn("patch {", calls)
        self.assertIn("recover_source", calls)
        self.assertTrue(any("server" in r for r in data["stop_if"]))

    def test_the_native_route_reads_the_branch_before_flipping_it(self):
        steps = [s["call"] for s in ai._render_route("pe_native", "/tmp/a.exe")["steps"]]
        self.assertLess(" ".join(steps).find("disasm"),
                        " ".join(steps).find("patch {"))


class RouteCommandTest(_Base):
    def test_a_pe_target_gets_a_route_and_the_first_call_is_anti_analysis(self):
        res = ai.cmd_route({"path": self.target})
        self.assertTrue(res["ok"], res)
        data = res["data"]
        self.assertEqual(data["route"], "pe_native")
        self.assertTrue(data["first_command"].startswith("anti_analysis"), data)
        self.assertEqual(data["path"], os.path.abspath(self.target))
        self.assertTrue(data["in_scope"])

    def test_route_accepts_the_same_key_spellings_as_its_neighbours(self):
        for key in ("path", "target", "src", "file"):
            res = ai.cmd_route({key: self.target})
            self.assertTrue(res["ok"], key)
            self.assertEqual(res["data"]["route"], "pe_native")

    def test_a_missing_file_is_an_error_not_a_guess(self):
        res = ai.cmd_route({"path": os.path.join(self.tmp, "nope.exe")})
        self.assertFalse(res["ok"])
        self.assertIn("no such file", res["error"])

    def test_a_url_is_out_of_scope_and_says_so(self):
        res = ai.cmd_route({"path": "https://licences.example.com/verify"})
        self.assertTrue(res["ok"])
        self.assertFalse(res["data"]["in_scope"])
        self.assertIsNone(res["data"]["route"])
        self.assertIn("live service", res["data"]["reason"])

    def test_no_path_is_an_error(self):
        self.assertFalse(ai.cmd_route({})["ok"])


class MdSectionTest(unittest.TestCase):
    """Section splitting is what makes a search result fussy enough to be useful."""

    TEXT = ("# Title\n\nintro\n\n## Alpha\n\nown alpha\n\n### Alpha child\n\nchild text\n\n"
            "## Beta\n\nown beta\n\n```bash\n# this is a shell comment, not a heading\n```\n"
            "\ntail beta\n")

    def test_sections_are_split_on_headings(self):
        titles = [s["title"] for s in ai._md_sections(self.TEXT)]
        self.assertEqual(titles, ["Title", "Alpha", "Alpha child", "Beta"])

    def test_a_hash_inside_a_fence_is_not_a_heading(self):
        titles = [s["title"] for s in ai._md_sections(self.TEXT)]
        self.assertNotIn("this is a shell comment, not a heading", titles)

    def test_own_text_stops_at_the_first_subsection(self):
        alpha = [s for s in ai._md_sections(self.TEXT) if s["title"] == "Alpha"][0]
        self.assertIn("own alpha", alpha["own"])
        self.assertNotIn("child text", alpha["own"])
        self.assertIn("child text", alpha["body"])

    def test_a_leaf_section_owns_all_of_its_text(self):
        beta = [s for s in ai._md_sections(self.TEXT) if s["title"] == "Beta"][0]
        self.assertIn("own beta", beta["own"])
        self.assertIn("tail beta", beta["own"])
        self.assertNotIn("own alpha", beta["own"])


class GuidanceTest(unittest.TestCase):
    def test_list_returns_the_installed_manual(self):
        data = ai.cmd_guidance({"action": "list"})["data"]
        locators = [s["locator"] for s in data["sections"]]
        self.assertTrue(any(l.startswith("AGENTS.md#") for l in locators), locators[:5])
        self.assertTrue(any(l.startswith("POLICY.md#") for l in locators), locators[:5])

    def test_search_returns_the_section_that_holds_every_term(self):
        data = ai.cmd_guidance({"query": "electron backup"})["data"]
        self.assertGreater(data["total"], 0)
        self.assertEqual(data["terms"], ["electron", "backup"])
        top = data["matches"][0]
        self.assertEqual(top["match_scope"], "section")
        self.assertIn("backup", top["excerpt"].lower() + top["locator"])

    def test_a_section_match_outranks_a_subsection_only_match(self):
        data = ai.cmd_guidance({"query": "hard rules"})["data"]
        scopes = [m["match_scope"] for m in data["matches"]]
        self.assertEqual(scopes, sorted(scopes, key=lambda s: 0 if s == "section" else 1))

    def test_read_returns_the_whole_section(self):
        found = ai.cmd_guidance({"query": "asar backup"})["data"]["matches"]
        locator = [m for m in found if m["locator"].endswith("backup-behavior")][0]["locator"]
        data = ai.cmd_guidance({"locator": locator})["data"]
        self.assertTrue(data["found"])
        self.assertIn("app.asar.bak", data["text"])
        self.assertIn("Backup behavior", data["text"])

    def test_every_search_result_can_be_read_back(self):
        for match in ai.cmd_guidance({"query": "patch"})["data"]["matches"]:
            data = ai.cmd_guidance({"locator": match["locator"]})["data"]
            self.assertTrue(data["found"], match["locator"])
            self.assertTrue(data["text"].strip())

    def test_an_unknown_locator_is_reported_not_faked(self):
        data = ai.cmd_guidance({"locator": "AGENTS.md#no-such-section"})["data"]
        self.assertFalse(data["found"])
        self.assertIn("action", data["reason"])

    def test_a_nonsense_query_returns_no_matches(self):
        data = ai.cmd_guidance({"query": "zzzznothing"})["data"]
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["matches"], [])

    def test_a_stopword_only_query_is_an_error_with_the_fix(self):
        res = ai.cmd_guidance({"query": "how do i"})
        self.assertFalse(res["ok"])
        self.assertIn("specific word", res["error"])

    def test_limit_is_clamped_and_reported(self):
        data = ai.cmd_guidance({"query": "patch", "limit": 2})["data"]
        self.assertLessEqual(len(data["matches"]), 2)
        self.assertTrue(data["truncated"])


class WiringTest(unittest.TestCase):
    """A command that is not in `help` or on the routing cards does not exist."""

    def test_both_commands_are_registered(self):
        self.assertIn("route", ai.COMMANDS)
        self.assertIn("guidance", ai.COMMANDS)

    def test_help_documents_both_commands(self):
        commands = ai.cmd_help({})["data"]["commands"]
        self.assertIn("route", commands)
        self.assertIn("guidance", commands)
        self.assertIn("playbook", commands["route"])
        self.assertIn("locator", commands["guidance"])

    def test_agents_md_puts_route_before_plan(self):
        with open(os.path.join(REPO, "AGENTS.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("route", text)
        self.assertLess(text.find("bobbypin_ai.py route"), text.find("## Commands"))


if __name__ == "__main__":
    unittest.main()
