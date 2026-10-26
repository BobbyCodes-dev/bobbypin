"""Telemetry tests: default off, opt-in works, failures never raise."""

import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from sandbox.base import RunRecord
from sandbox import telemetry as tel_mod
from sandbox.telemetry import Telemetry


class _Sink(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _Sink.received.append(json.loads(body.decode()))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def _record(**kw):
    base = dict(run_id="deadbeef", backend="docker", target="/tmp/app.exe",
                target_sha256="a" * 64, target_size=1234, exit_code=0, duration_s=1.5)
    base.update(kw)
    return RunRecord(**base)


class TelemetryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bp-tel-")
        self.cfg = {"state_dir": self.tmp,
                    "telemetry": {"enabled": False, "endpoint": "", "timeout_s": 2, "queue_max": 3}}
        _Sink.received = []

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_disabled_by_default_and_touches_no_network(self):
        called = {"n": 0}

        def _boom(*a, **k):
            called["n"] += 1
            raise AssertionError("network must not be touched when telemetry is off")

        original = tel_mod.urllib.request.urlopen
        tel_mod.urllib.request.urlopen = _boom
        try:
            tel = Telemetry(self.cfg)
            self.assertFalse(tel.enabled)
            res = tel.send(tel.event_from(_record()))
        finally:
            tel_mod.urllib.request.urlopen = original
        self.assertEqual(called["n"], 0)
        self.assertFalse(res["sent"])
        self.assertEqual(res["status"], "disabled")

    def test_enabled_requires_an_endpoint(self):
        cfg = {"state_dir": self.tmp,
               "telemetry": {"enabled": True, "endpoint": "", "timeout_s": 2}}
        self.assertFalse(Telemetry(cfg).enabled)
        res = Telemetry(cfg).send({})
        self.assertEqual(res["status"], "no endpoint configured")

    def test_event_shape(self):
        tel = Telemetry(self.cfg)
        event = tel.event_from(_record(crashed=True, signal=11, bsod_suspected=True),
                               {"kind": "pe32",
                                "honeypots": {"summary": {"total": 13, "modified": 0,
                                                          "deleted": 0, "leaked": 1,
                                                          "clean": False},
                                              "hits": [{"kind": "license"}]}})
        self.assertEqual(event["schema"], tel_mod.SCHEMA_VERSION)
        self.assertEqual(event["event"], "sandbox_run")
        self.assertEqual(event["target"]["basename"], "app.exe")
        self.assertNotIn("/tmp", json.dumps(event), "full paths must never be transmitted")
        self.assertEqual(event["honeypots"]["kinds"], ["license"])
        self.assertTrue(event["result"]["bsod_suspected"])
        self.assertEqual(len(event["host_id"]), 16)

    def test_host_id_is_stable_and_salted(self):
        a = Telemetry(self.cfg).host_id()
        b = Telemetry(self.cfg).host_id()
        self.assertEqual(a, b)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "host_salt")))
        self.assertEqual(os.stat(os.path.join(self.tmp, "host_salt")).st_mode & 0o777, 0o600)
        # a different salt must produce a different id
        other = tempfile.mkdtemp(prefix="bp-tel2-")
        try:
            self.assertNotEqual(a, Telemetry({"state_dir": other, "telemetry": {}}).host_id())
        finally:
            shutil.rmtree(other, ignore_errors=True)

    def test_delivery_to_a_live_endpoint(self):
        server = HTTPServer(("127.0.0.1", 0), _Sink)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            cfg = {"state_dir": self.tmp,
                   "telemetry": {"enabled": True,
                                 "endpoint": f"http://127.0.0.1:{port}/bobbypin-telemetry",
                                 "timeout_s": 3}}
            tel = Telemetry(cfg)
            self.assertTrue(tel.enabled)
            res = tel.send(tel.event_from(_record()))
            self.assertTrue(res["sent"], res)
            self.assertEqual(res["http"], 200)
            self.assertEqual(len(_Sink.received), 1)
            self.assertEqual(_Sink.received[0]["backend"], "docker")
            self.assertFalse(res["queued"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_network_failure_spools_then_flushes(self):
        cfg = {"state_dir": self.tmp,
               "telemetry": {"enabled": True, "endpoint": "http://127.0.0.1:1/nope",
                             "timeout_s": 1, "queue_max": 3}}
        tel = Telemetry(cfg)
        res = tel.send(tel.event_from(_record()))
        self.assertFalse(res["sent"])
        self.assertTrue(res["queued"])
        self.assertEqual(res["status"], "network_error")
        self.assertEqual(tel.queued(), 1)

        # queue cap drops the oldest
        for _ in range(5):
            tel.send(tel.event_from(_record()))
        self.assertEqual(tel.queued(), 3)

        server = HTTPServer(("127.0.0.1", 0), _Sink)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            cfg2 = {"state_dir": self.tmp,
                    "telemetry": {"enabled": True,
                                  "endpoint": f"http://127.0.0.1:{port}/x",
                                  "timeout_s": 3, "queue_max": 10}}
            out = Telemetry(cfg2).flush()
            self.assertEqual(out["flushed"], 3)
            self.assertEqual(out["remaining"], 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_status_reports_schema_and_last(self):
        st = Telemetry(self.cfg).status()
        self.assertFalse(st["enabled"])
        self.assertEqual(st["schema"], tel_mod.SCHEMA_VERSION)
        self.assertEqual(st["queued"], 0)


if __name__ == "__main__":
    unittest.main()
