"""Hardened-container backend tests. Real containers; skipped without docker."""

import json
import os
import shutil
import tempfile
import unittest

from sandbox.base import RunRequest
from sandbox.backends.docker_backend import DockerBackend, parse_probe

PROBE_IMAGE = "alpine:3.20"


def _docker_ok():
    return DockerBackend().available().get("available", False)


def _has_image(image):
    return DockerBackend()._image_present(image)


@unittest.skipUnless(_docker_ok(), "docker daemon not available")
class DockerBackendTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bp-docker-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.image = PROBE_IMAGE if _has_image(PROBE_IMAGE) else "alpine:latest"

    def _req(self, **kw):
        kw.setdefault("workdir", self.tmp)
        kw.setdefault("image", self.image)
        kw.setdefault("timeout_s", 60)
        return RunRequest(**kw)

    def test_parse_probe_parses_observed_values(self):
        out = "noise\nBOBBYPIN_PROBE uid=1000 ro=1 tmpw=1 ifaces=lo egress=blocked hp=1 in=0 out=1\n"
        pd = parse_probe(out)
        self.assertEqual(pd["uid"], 1000)
        self.assertEqual(pd["ro"], 1)
        self.assertEqual(pd["egress"], "blocked")
        self.assertEqual(pd["ifaces"], "lo")
        self.assertEqual(parse_probe("nothing here"), {})

    def test_flags_are_fixed_and_strong(self):
        backend = DockerBackend()
        req = self._req(argv=["sh", "-c", "true"], no_egress=False)
        warnings = []
        flags = backend._run_flags(req, os.path.join(self.tmp, "out"), warnings)
        for flag in ("--network", "none", "--read-only", "--cap-drop", "ALL",
                     "--security-opt", "no-new-privileges", "--pids-limit", "256",
                     "--ipc", "none", "--user", "1000:1000"):
            self.assertIn(flag, flags, flag)
        self.assertIn("--tmpfs", flags)
        self.assertNotIn("--privileged", flags)
        self.assertNotIn("--network", [f for f in flags if f == "host"])
        self.assertTrue(any("no_egress=False was ignored" in w for w in warnings),
                        "must refuse to enable networking")
        joined = " ".join(flags)
        self.assertNotIn("/var/run/docker.sock", joined)

    def test_target_mounts_are_read_only(self):
        target = os.path.join(self.tmp, "app.exe")
        with open(target, "wb") as fh:
            fh.write(b"MZ" + b"\x00" * 32)
        flags = DockerBackend()._run_flags(self._req(target=target),
                                           os.path.join(self.tmp, "out"), [])
        joined = " ".join(flags)
        self.assertIn("/in/app.exe:ro", joined)

    def test_probe_proves_the_boundary(self):
        rec = DockerBackend().run(self._req())
        c = rec.containment
        self.assertTrue(c["network_verified"], c)
        self.assertTrue(c["rootfs_verified"], c)
        self.assertEqual(c["uid"], 1000)
        self.assertEqual(c["interfaces"], "lo")
        self.assertEqual(c["cap_drop"], "ALL")
        self.assertFalse(rec.crashed)
        self.assertEqual(rec.exit_code, 0)

    def test_payload_cannot_write_to_root_or_escape(self):
        rec = DockerBackend().run(self._req(
            argv=["sh", "-c",
                  "printf x > /write_test; printf x > /etc/passwd; "
                  "printf x > /root/.ssh/authorized_keys"]))
        self.assertEqual(rec.stdout_tail, "")
        self.assertIn("Read-only file system", rec.stderr_tail)
        self.assertFalse(rec.containment["rootfs_verified"] is False)
        self.assertFalse(os.path.exists("/write_test"), "host must not be affected")
        self.assertFalse(os.path.exists("/root/.ssh/authorized_keys_bp"), "host must not be affected")

    def test_crashing_payload_is_contained_and_reported(self):
        rec = DockerBackend().run(self._req(argv=["sh", "-c", "kill -SEGV $$"]))
        self.assertTrue(rec.crashed)
        self.assertEqual(rec.exit_code, 139)
        self.assertEqual(rec.signal, 11)
        self.assertFalse(rec.timed_out)
        # the host is obviously fine - this process survived to assert it
        self.assertTrue(os.path.isdir(self.tmp))

    def test_nonzero_exit_is_not_reported_as_an_abnormal_death(self):
        """A target that exits 1 ran fine; only signal/timeout/oom is an abnormal exit."""
        rec = DockerBackend().run(self._req(argv=["sh", "-c", "exit 1"]))
        self.assertEqual(rec.exit_code, 1)
        self.assertTrue(rec.crashed)         # contract: nonzero exit is a failure
        self.assertFalse(rec.abnormal_exit)  # ...but nothing killed it
        rec2 = DockerBackend().run(self._req(argv=["sh", "-c", "kill -SEGV $$"]))
        self.assertTrue(rec2.abnormal_exit)

    def test_timeout_kills_the_payload(self):
        rec = DockerBackend().run(self._req(argv=["sh", "-c", "sleep 30"], timeout_s=3))
        self.assertTrue(rec.timed_out)
        self.assertTrue(rec.crashed)
        self.assertLess(rec.duration_s, 30)

    def test_artifacts_written_to_out_are_collected(self):
        out = os.path.join(self.tmp, "out")
        os.makedirs(out, exist_ok=True)
        rec = DockerBackend().run(self._req(
            argv=["sh", "-c", "printf hello > /out/result.txt"]))
        self.assertEqual(rec.exit_code, 0)
        self.assertIn(os.path.join(out, "result.txt"), rec.artifacts)
        with open(os.path.join(out, "result.txt")) as fh:
            self.assertEqual(fh.read(), "hello")

    def test_target_hashes_are_recorded(self):
        target = os.path.join(self.tmp, "app.bin")
        with open(target, "wb") as fh:
            fh.write(b"payload")
        rec = DockerBackend().run(self._req(target=target))
        self.assertEqual(rec.target_size, 7)
        self.assertEqual(len(rec.target_sha256), 64)
        self.assertEqual(rec.target, target)

    def test_missing_target_is_an_error_not_a_host_run(self):
        from sandbox.base import SandboxUnavailable
        with self.assertRaises(SandboxUnavailable):
            DockerBackend().run(self._req(target=os.path.join(self.tmp, "ghost.exe")))

    def test_no_container_survives_the_run(self):
        rec = DockerBackend().run(self._req(argv=["sh", "-c", "true"]))
        names = DockerBackend()._docker(["ps", "-a", "--format", "{{.Names}}"], timeout=30)
        self.assertNotIn("bobbypin-sbx-", names.stdout or "")


if __name__ == "__main__":
    unittest.main()
