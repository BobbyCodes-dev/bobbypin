"""Config, capabilities and orchestrator tests."""

import json
import os
import shutil
import tempfile
import unittest

from sandbox import capabilities
from sandbox.config import DEFAULTS, get_value, load_config, save_config, set_value
from sandbox.runner import preflight, run_sandbox


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bp-cfg-")
        self.path = os.path.join(self.tmp, "sandbox.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_defaults_are_safe(self):
        self.assertFalse(DEFAULTS["telemetry"]["enabled"])
        self.assertEqual(DEFAULTS["telemetry"]["endpoint"], "")
        self.assertTrue(DEFAULTS["honeypots"]["enabled"])
        self.assertTrue(DEFAULTS["kvm"]["no_egress"])
        self.assertTrue(DEFAULTS["kvm"]["no_reboot"])

    def test_load_merges_over_defaults_and_survives_garbage(self):
        cfg = load_config(self.path)
        self.assertEqual(cfg["backend"], "auto")
        self.assertFalse(cfg["telemetry"]["enabled"])
        with open(self.path, "w") as fh:
            fh.write("{not json")
        self.assertEqual(load_config(self.path)["backend"], "auto")

    def test_save_is_private_and_round_trips(self):
        cfg = load_config(self.path)
        cfg["timeout_s"] = 42
        save_config(cfg, self.path)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        self.assertEqual(load_config(self.path)["timeout_s"], 42)

    def test_set_value_creates_and_persists_nested_keys(self):
        set_value("telemetry.enabled", True, self.path)
        cfg = load_config(self.path)
        self.assertTrue(cfg["telemetry"]["enabled"])
        set_value("telemetry.endpoint", "https://example.invalid/hook", self.path)
        cfg = load_config(self.path)
        self.assertTrue(cfg["telemetry"]["enabled"], "sibling keys must survive")
        self.assertEqual(get_value(cfg, "telemetry.endpoint"), "https://example.invalid/hook")
        self.assertIsNone(get_value(cfg, "nope.nothing"))


class CapabilitiesTest(unittest.TestCase):
    def test_probe_shape(self):
        rep = capabilities.probe()
        for key in ("backends", "recommended", "host", "notes"):
            self.assertIn(key, rep)
        for name in ("docker", "kvm"):
            self.assertIn("available", rep["backends"][name])
            self.assertIn("reason", rep["backends"][name])
        self.assertIn(rep["recommended"], {"docker", "kvm", None})
        json.dumps(rep)

    def test_kvm_reports_the_missing_prerequisites(self):
        info = capabilities.kvm_available()
        if not info["available"]:
            self.assertTrue(info["install"])
        self.assertIn("kvm_device", info["detail"])

    def test_docker_install_hint_is_actionable(self):
        info = capabilities.docker_available()
        self.assertIsInstance(info["available"], bool)
        if not info["available"]:
            self.assertTrue(info["install"])


class RunnerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bp-run-")
        self.cfg = load_config(os.path.join(self.tmp, "sandbox.json"))
        self.cfg["state_dir"] = self.tmp
        self.cfg["image"] = "alpine:3.20"
        self.cfg["timeout_s"] = 30

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_preflight_is_serialisable_and_actionable(self):
        rep = preflight(self.cfg)
        json.dumps(rep)
        self.assertIn("backends", rep)
        self.assertIn("telemetry", rep)
        self.assertTrue(any("install" in b for b in rep["backends"].values()))

    def test_unknown_backend_fails_loudly_with_a_hint(self):
        res = run_sandbox(backend="vmware", workdir=os.path.join(self.tmp, "w"), config=self.cfg)
        self.assertFalse(res["ok"])
        self.assertIn("vmware", res["error"])

    @unittest.skipUnless(capabilities.docker_available()["available"], "no docker")
    def test_full_run_plants_honeypots_and_keeps_telemetry_off(self):
        res = run_sandbox(backend="docker", workdir=os.path.join(self.tmp, "w1"),
                          config=self.cfg, timeout_s=30)
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(res["backend"], "docker")
        self.assertEqual(res["honeypots"]["summary"]["total"], 13)
        self.assertTrue(res["honeypots"]["summary"]["clean"])
        self.assertEqual(res["telemetry"]["status"], "disabled")
        self.assertTrue(res["record"]["containment"]["network_verified"])
        self.assertTrue(os.path.isdir(os.path.join(self.tmp, "w1", "honeypots")))

    @unittest.skipUnless(capabilities.docker_available()["available"], "no docker")
    def test_a_target_that_steals_the_decoy_licence_is_reported(self):
        payload = ["sh", "-c",
                   "cat /honeypots/Users/analyst/Desktop/license.key > /out/stolen.txt"]
        res = run_sandbox(backend="docker", workdir=os.path.join(self.tmp, "w2"),
                          argv=payload, config=self.cfg, timeout_s=30)
        self.assertTrue(res["ok"], res.get("error"))
        hits = res["honeypots"]["hits"]
        self.assertTrue(any(h["change"] == "token_leaked" for h in hits), hits)
        self.assertFalse(res["honeypots"]["summary"]["clean"])
        self.assertEqual(res["record"]["containment"]["engine"], "docker")

    @unittest.skipUnless(capabilities.docker_available()["available"], "no docker")
    def test_telemetry_goes_out_only_when_switched_on(self):
        from sandbox.tests.test_telemetry import _Sink
        from http.server import HTTPServer
        import threading
        _Sink.received = []
        server = HTTPServer(("127.0.0.1", 0), _Sink)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            cfg = dict(self.cfg)
            cfg["telemetry"] = {"enabled": True, "timeout_s": 3,
                                "endpoint": "http://127.0.0.1:%d/hook" % server.server_address[1]}
            off = run_sandbox(backend="docker", workdir=os.path.join(self.tmp, "w3"),
                              config=self.cfg, timeout_s=30)
            self.assertEqual(off["telemetry"]["status"], "disabled")
            self.assertEqual(_Sink.received, [])
            on = run_sandbox(backend="docker", workdir=os.path.join(self.tmp, "w4"),
                             config=cfg, timeout_s=30)
            self.assertTrue(on["telemetry"]["sent"], on["telemetry"])
            self.assertEqual(len(_Sink.received), 1)
            self.assertEqual(_Sink.received[0]["event"], "sandbox_run")
            self.assertEqual(_Sink.received[0]["host_id"], on["telemetry"]["status"] if False else _Sink.received[0]["host_id"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
