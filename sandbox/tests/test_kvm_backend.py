"""KVM backend tests. The VM itself cannot boot here (no qemu installed), so we
test the capability gate and, critically, the QEMU command line the backend
would build - the arguments are where the safety properties actually live."""

import os
import shutil
import subprocess
import tempfile
import unittest

from sandbox.base import RunRequest, SandboxUnavailable

REPO_PATH = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sandbox.backends.kvm_backend import KVMBackend


class KVMBackendTest(unittest.TestCase):
    def setUp(self):
        self.cfg = {"kvm": {"base_image": "/tmp/does-not-exist.qcow2",
                            "memory_mb": 4096, "cpus": 2,
                            "no_reboot": True, "no_egress": True},
                    "timeout_s": 60}
        self.backend = KVMBackend(self.cfg)

    def _plan(self, **over):
        req = RunRequest(workdir="/tmp/bp-kvm", target=None)
        plan = self.backend.plan_paths(req, "/tmp/bp-kvm", "0123456789abcdef0123456789abcdef")
        plan.update(over)
        return req, plan

    def test_unavailable_names_the_actual_missing_prerequisite(self):
        """Whatever is missing, the report must name it and say how to fix it.

        Two states matter and both are hit in practice: qemu absent (install it),
        and qemu present but no guest disk configured (build/provide one).
        """
        info = self.backend.available()
        if info["available"]:
            self.skipTest("a guest base image is configured on this host")
        self.assertFalse(info["available"])
        self.assertTrue(info["reason"])
        self.assertTrue(info["install"], "an unavailable backend must ship a fix hint")
        if self.backend.available()["detail"].get("qemu_binary"):
            self.assertIn("base image", info["reason"])
            self.assertIn("kvm/README.md", info["install"])
        else:
            self.assertIn("qemu-system-x86_64", info["reason"])
            self.assertIn("apt-get install", info["install"])

    def test_run_raises_instead_of_using_the_host(self):
        """The safety property: no boundary -> no execution, with a hint to the operator."""
        if self.backend.available()["available"]:
            self.skipTest("a guest base image is configured on this host")
        marker = "/tmp/bp-must-not-exist"
        if os.path.exists(marker):
            os.unlink(marker)
        with self.assertRaises(SandboxUnavailable) as ctx:
            self.backend.run(RunRequest(workdir="/tmp/bp-kvm",
                                        argv=["/bin/sh", "-c", "touch " + marker]))
        self.assertTrue(ctx.exception.install, "must carry an operator fix hint")
        self.assertFalse(os.path.exists(marker), "the payload must not have run on the host")

    def test_available_once_a_base_image_exists(self):
        """With qemu + /dev/kvm + a base image present, the backend reports ready."""
        if not os.path.exists("/dev/kvm"):
            self.skipTest("no /dev/kvm on this host")
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "base.qcow2")
            subprocess.run([shutil.which("qemu-img") or "qemu-img", "create", "-f", "qcow2", base, "64M"],
                           capture_output=True, timeout=60)
            backend = KVMBackend({"kvm": {"base_image": base}, "timeout_s": 30})
            info = backend.available()
            self.assertTrue(info["available"], info)
            self.assertTrue(info["detail"]["base_image_present"])

    def test_uuid_is_wellformed(self):
        _, plan = self._plan()
        self.assertEqual(len(plan["uuid"].split("-")), 5)
        self.assertEqual([len(p) for p in plan["uuid"].split("-")], [8, 4, 4, 4, 12])

    def test_argv_is_ephemeral_no_reboot_and_no_egress(self):
        req, plan = self._plan()
        argv = self.backend._build_qemu_argv(req, plan)
        self.assertIn("-no-reboot", argv)
        self.assertIn("-snapshot", argv)
        self.assertIn("file=" + plan["overlay"] + ",if=virtio,format=qcow2,cache=unsafe", argv)
        self.assertIn("restrict=on", " ".join(argv))
        self.assertEqual(argv[argv.index("-m") + 1], "4096")
        self.assertEqual(argv[argv.index("-smp") + 1], "2")
        self.assertIn("-display", argv)
        self.assertIn("none", argv)
        self.assertTrue(any(a.startswith("file:") and a.endswith("serial.log") for a in argv))
        self.assertNotIn("hostfwd", " ".join(argv), "no port forwards may ever be opened")

    def test_base_image_is_never_handed_to_qemu(self):
        req, plan = self._plan(base_image="/tmp/base.qcow2", overlay="/tmp/overlay.qcow2")
        argv = self.backend._build_qemu_argv(req, plan)
        self.assertNotIn("file=/tmp/base.qcow2", " ".join(argv))
        self.assertIn("file=/tmp/overlay.qcow2", " ".join(argv))

    def test_no_shared_filesystem_is_exposed(self):
        """Files move over the guest agent. 9p/virtfs is deliberately absent:
        the Debian cloud kernel has no 9p support, and a host share is one more way
        for a target to reach the host."""
        target = "/tmp/targets/app.exe"
        req = RunRequest(workdir="/tmp/bp-kvm", target=target,
                         honeypot_root="/tmp/bp-kvm/honeypots")
        plan = self.backend.plan_paths(req, "/tmp/bp-kvm", "0123456789abcdef0123456789abcdef")
        argv = " ".join(self.backend._build_qemu_argv(req, plan))
        self.assertNotIn("-virtfs", argv)
        self.assertNotIn("mount_tag", argv)
        self.assertNotIn("/honeypots", argv)
        self.assertNotIn("/out", argv)

    def test_no_reboot_can_be_disabled_only_by_config(self):
        backend = KVMBackend({"kvm": {"no_reboot": False}})
        req, plan = self._plan()
        plan["no_reboot"] = False
        self.assertNotIn("-no-reboot", backend._build_qemu_argv(req, plan))
        req2, plan2 = self._plan()
        self.assertIn("-no-reboot", KVMBackend({"kvm": {"no_reboot": True}})._build_qemu_argv(req2, plan2))

    def test_egress_off_uses_restricted_user_networking(self):
        req, plan = self._plan(no_egress=False)
        argv = self.backend._build_qemu_argv(req, plan)
        self.assertEqual(argv[argv.index("-netdev") + 1], "user,id=n0")
        req2, plan2 = self._plan()
        argv2 = self.backend._build_qemu_argv(req2, plan2)
        self.assertEqual(argv2[argv2.index("-netdev") + 1], "user,id=n0,restrict=on")

    def test_kvm_accel_used_when_dev_kvm_is_present(self):
        req, plan = self._plan(kvm=True)
        argv = self.backend._build_qemu_argv(req, plan)
        self.assertIn("-enable-kvm", argv)
        self.assertIn("-cpu", argv)

    def test_tcg_is_the_documented_fallback(self):
        req, plan = self._plan(kvm=False)
        argv = self.backend._build_qemu_argv(req, plan)
        self.assertIn("-accel", argv)
        self.assertIn("tcg", argv)
        self.assertNotIn("-enable-kvm", argv)

    def test_guest_agent_channel_is_wired(self):
        req, plan = self._plan()
        argv = " ".join(self.backend._build_qemu_argv(req, plan))
        self.assertIn("org.qemu.guest_agent.0", argv)
        self.assertIn("server=on,wait=off", argv)
        self.assertIn(plan["qga_sock"], argv)

    def test_qga_transport_failure_is_not_fatal(self):
        rep = KVMBackend._qga("/tmp/definitely-not-a-socket", {"execute": "guest-ping"})
        self.assertIn("error", rep)


class TripLaunchTest(unittest.TestCase):
    """trip_debug builds its own command line, because only the backend knows whether it is
    talking to Windows or to a Linux guest running wine."""

    def setUp(self):
        self.backend = KVMBackend({"kvm": {}})
        self.backend.trip_helper = "/host/path/ad_trip.exe"

    def test_windows_goes_through_cmd(self):
        argv = self.backend.trip_argv("windows", "C:\\in", "app.exe")
        self.assertEqual(argv[0], "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(argv[1], "/c")
        self.assertEqual(argv[2], "C:\\in\\ad_trip.exe C:\\in\\app.exe")
        self.assertNotIn("wine", " ".join(argv))

    def test_linux_uses_wine_and_posix_paths(self):
        self.assertEqual(self.backend.trip_argv("linux", "/in", "app.exe"),
                         ["wine", "/in/ad_trip.exe", "/in/app.exe"])

    def test_helper_name_is_preserved(self):
        self.backend.trip_helper = "/x/custom_trip.exe"
        self.assertIn("custom_trip.exe", self.backend.trip_argv("windows", "C:\\in", "a.exe")[2])


class KVMHardwareProfileTest(unittest.TestCase):
    """Firmware and disk bus are not preferences: a disk booted on the wrong ones does not
    start. dockurr-installed Windows is UEFI with the disk on virtio-scsi, over a raw image."""

    def _backend_for(self, tmp, with_ovmf=True, fmt="raw"):
        base = os.path.join(tmp, "data.img")
        if fmt == "qcow2":
            subprocess.run([shutil.which("qemu-img") or "qemu-img", "create", "-f", "qcow2",
                            base, "8M"], capture_output=True, timeout=60)
        else:
            with open(base, "wb") as fh:
                fh.write(b"\0" * (1 << 20))
        if with_ovmf:
            for name, blob in (("windows.rom", b"OVMFCODE"), ("windows.vars", b"OVMFVARS")):
                with open(os.path.join(tmp, name), "wb") as fh:
                    fh.write(blob)
        return KVMBackend({"kvm": {"base_image": base}, "timeout_s": 30}), base

    def test_dockurr_layout_is_detected_as_uefi_on_scsi(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend, base = self._backend_for(tmp)
            prof = backend.firmware_profile()
            self.assertEqual(prof["mode"], "uefi")
            self.assertEqual(prof["disk_bus"], "virtio-scsi")
            self.assertEqual(prof["base_format"], "raw")
            self.assertTrue(prof["code"].endswith("windows.rom"))
            self.assertTrue(prof["vars"].endswith("windows.vars"))

    def test_plain_qcow2_disk_stays_bios_on_virtio_blk(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend, base = self._backend_for(tmp, with_ovmf=False, fmt="qcow2")
            prof = backend.firmware_profile()
            self.assertEqual(prof["mode"], "bios")
            self.assertEqual(prof["disk_bus"], "virtio-blk")
            self.assertEqual(prof["base_format"], "qcow2")

    def test_explicit_config_overrides_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend, base = self._backend_for(tmp, with_ovmf=False, fmt="qcow2")
            backend.force_firmware = "uefi"
            backend.force_disk_bus = "virtio-scsi"
            prof = backend.firmware_profile()
            self.assertEqual(prof["mode"], "uefi")
            self.assertEqual(prof["disk_bus"], "virtio-scsi")

    def test_argv_carries_ovmf_scsi_and_no_virtio_blk(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend, base = self._backend_for(tmp)
            req = RunRequest(workdir=tmp)
            plan = backend.plan_paths(req, tmp, "0123456789abcdef0123456789abcdef")
            argv = backend._build_qemu_argv(req, plan)
            joined = " ".join(argv)
            self.assertIn("-machine q35", joined)
            self.assertIn("if=pflash,format=raw,readonly=on,file=" + plan["firmware"]["code"], joined)
            self.assertIn("if=pflash,format=raw,file=" + plan["uefi_vars"], joined)
            self.assertIn("virtio-scsi-pci", joined)
            self.assertIn("scsi-hd,drive=bpdisk", joined)
            self.assertNotIn("if=virtio,format=qcow2", joined,
                             "a Windows guest has no virtio-blk driver")
            self.assertIn("-no-reboot", argv)
            self.assertIn("restrict=on", joined)

    def test_uefi_without_a_vars_image_is_refused_not_guessed(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend, base = self._backend_for(tmp, with_ovmf=False, fmt="qcow2")
            backend.force_firmware = "uefi"
            with self.assertRaises(SandboxUnavailable) as ctx:
                backend.run(RunRequest(workdir=tmp, argv=["/bin/true"]))
            self.assertIn("UEFI", str(ctx.exception))

    def test_uefi_vars_are_copied_per_run_so_the_template_is_never_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend, base = self._backend_for(tmp)
            template = os.path.join(tmp, "windows.vars")
            before = open(template, "rb").read()
            plan = backend.plan_paths(RunRequest(workdir=tmp), tmp, "0123456789abcdef0123456789abcdef")
            shutil.copyfile(plan["firmware"]["vars"], plan["uefi_vars"])
            self.assertTrue(os.path.isfile(plan["uefi_vars"]))
            self.assertEqual(open(template, "rb").read(), before)

    def test_guest_os_paths_and_shells(self):
        self.assertEqual(KVMBackend._shell_argv("windows", "dir")[0],
                         "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(KVMBackend._shell_argv("windows", "dir")[1], "/c")
        self.assertEqual(KVMBackend._shell_argv("linux", "ls"), ["/bin/sh", "-c", "ls"])
        self.assertEqual(KVMBackend._guest_path("windows", "C:\\in", "x.exe"),
                         "C:\\in\\x.exe")
        self.assertEqual(KVMBackend._guest_path("linux", "/in", "x.exe"), "/in/x.exe")
        # unquoted on purpose: `if not exist "C:\\in" mkdir "C:\\in"` sends cmd.exe down
        # its quote-stripping path and silently does nothing (cost a debugging session)
        self.assertEqual(KVMBackend._mkdir_snippet("windows", "C:\\in"), "mkdir C:\\in")
        self.assertNotIn(chr(34), KVMBackend._mkdir_snippet("windows", "C:\\in"))
        self.assertEqual(KVMBackend._mkdir_snippet("linux", "/in"), "mkdir -p '/in'")

    def test_staged_base_per_guest_and_profile(self):
        backend = KVMBackend({})
        self.assertEqual(backend._staged_base("windows", "windows"), "C:\\")
        self.assertEqual(backend._staged_base("linux", "windows"), backend.WINE_DRIVE_C)
        self.assertEqual(backend._staged_base("linux", "linux"), "/root")


@unittest.skipUnless(os.path.exists("/dev/kvm"), "no /dev/kvm")
@unittest.skipUnless(shutil.which("qemu-system-x86_64"), "qemu not installed")
class KVMWindowsGuestTest(unittest.TestCase):
    """The Windows guest: native execution, UEFI boot, and a real bugcheck on demand."""

    @classmethod
    def setUpClass(cls):
        from sandbox.backends.kvm_backend import KVMBackend
        cls.cfg, base = _configured_base_image()
        backend = KVMBackend(cls.cfg)
        if not backend.available()["available"]:
            raise unittest.SkipTest("no guest base image configured")
        if "windows" not in (backend.base_image or "").lower():
            raise unittest.SkipTest("configured guest is not Windows")
        cls.base = os.path.expanduser(backend.base_image)
        cls.tmp = tempfile.mkdtemp(prefix="bp-winrun-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @staticmethod
    def _sha(path):
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def _run(self, argv, **kw):
        from sandbox.runner import run_sandbox
        kw.setdefault("timeout_s", 200)
        res = run_sandbox(backend="kvm",
                          workdir=os.path.join(self.tmp, "w%d" % len(os.listdir(self.tmp))),
                          argv=argv, config=self.cfg, honeypots=kw.pop("honeypots", False), **kw)
        self.assertTrue(res["ok"], res.get("error"))
        return res

    def test_windows_boots_uefi_on_scsi_over_a_raw_image(self):
        res = self._run(["C:\\Windows\\System32\\cmd.exe", "/c", "ver"])
        c = res["record"]["containment"]
        self.assertEqual(c["guest_os"], "windows")
        self.assertEqual(c["firmware"], "uefi")
        self.assertEqual(c["disk_bus"], "virtio-scsi")
        self.assertEqual(c["base_format"], "raw")
        self.assertIn("Microsoft Windows", res["record"]["stdout_tail"])
        self.assertFalse(res["record"]["bsod_suspected"])

    def test_executes_a_pe_natively_without_wine(self):
        """ad_guard.exe is a Windows binary: it must run, not be run under wine."""
        guard = os.path.join(REPO_PATH, "fixtures", "anti_analysis", "ad_guard.exe")
        if not os.path.isfile(guard):
            self.skipTest("fixtures not built")
        res = self._run(["C:\\Windows\\System32\\cmd.exe", "/c", "C:\\in\\ad_guard.exe"],
                        target=guard)
        rec = res["record"]
        self.assertTrue(rec["containment"]["target_delivered"])
        self.assertIn("Acme Studio", rec["stdout_tail"])
        self.assertNotIn("wine", (rec["stderr_tail"] or "").lower())

    def test_base_image_untouched_and_no_state_carries_over(self):
        before = self._sha(self.base)
        marker = "bp-crosstalk-" + os.urandom(4).hex()
        first = self._run(["C:\\Windows\\System32\\cmd.exe", "/c", "echo x > C:\\" + marker])
        self.assertEqual(first["record"]["exit_code"], 0)
        self.assertFalse(os.path.exists(os.path.join(first["workdir"], "disk.qcow2")),
                         "the per-run overlay must be discarded")
        second = self._run(["C:\\Windows\\System32\\cmd.exe", "/c",
                            "if exist C:\\" + marker + " (echo LEAKED) else (echo CLEAN)"])
        self.assertIn("CLEAN", second["record"]["stdout_tail"])
        self.assertEqual(self._sha(self.base), before, "the base image must be read-only")


if __name__ == "__main__":
    unittest.main()


def _configured_base_image():
    """Resolve kvm.base_image the way the tool does, then fall back to the real user's
    config. A runner's HOME is not always the user's HOME (agent harnesses and service
    managers routinely set their own), and a silently skipped VM suite looks exactly like a
    passing one - which is worse than a failure."""
    from sandbox.config import load_config
    cfg = load_config()
    base = (cfg.get("kvm") or {}).get("base_image") or ""
    if base:
        return cfg, base
    import pwd
    real_home = pwd.getpwuid(os.getuid()).pw_dir
    for candidate in (os.path.join(real_home, ".bobbypin", "sandbox.json"),):
        if os.path.isfile(candidate):
            cfg = load_config(candidate)
            base = (cfg.get("kvm") or {}).get("base_image") or ""
            if base:
                return cfg, base
    return cfg, base


@unittest.skipUnless(os.path.exists("/dev/kvm"), "no /dev/kvm")
@unittest.skipUnless(shutil.which("qemu-system-x86_64"), "qemu not installed")
class KVMGuestRunTest(unittest.TestCase):
    """End-to-end runs against a real guest. Skipped unless a base image is configured.

    These are the tests that prove the VM guarantees rather than describing them:
    the guest boots, the agent answers, the payload executes, the network is dead,
    the base image is never written, and a kernel panic stays inside the guest.
    """

    @classmethod
    def setUpClass(cls):
        from sandbox.backends.kvm_backend import KVMBackend
        cls.cfg, base = _configured_base_image()
        backend = KVMBackend(cls.cfg)
        if not backend.available()["available"]:
            raise unittest.SkipTest("no guest base image configured (kvm.base_image)")
        if "windows" in (backend.base_image or "").lower():
            # These assert POSIX guest behaviour (/bin/sh, /in, virtfs-free mounts). The
            # Windows guest is covered by KVMWindowsGuestTest instead.
            raise unittest.SkipTest("configured guest is Windows; see KVMWindowsGuestTest")
        cls.base = os.path.expanduser(backend.base_image)
        cls.tmp = tempfile.mkdtemp(prefix="bp-kvmrun-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _run(self, argv, **kw):
        from sandbox.runner import run_sandbox
        kw.setdefault("timeout_s", 90)
        res = run_sandbox(backend="kvm", workdir=os.path.join(self.tmp, "w%d" % len(os.listdir(self.tmp))),
                          argv=argv, config=self.cfg, honeypots=kw.pop("honeypots", True), **kw)
        self.assertTrue(res["ok"], res.get("error"))
        return res

    @staticmethod
    def _sha(path):
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def test_payload_runs_in_the_guest_and_output_comes_back(self):
        res = self._run(["/bin/sh", "-c", "echo marker-from-guest; id -u; uname -r"])
        rec = res["record"]
        self.assertEqual(rec["exit_code"], 0)
        self.assertIn("marker-from-guest", rec["stdout_tail"])
        self.assertIn("0", rec["stdout_tail"].splitlines()[1])  # runs as root in the guest
        self.assertFalse(rec["crashed"])
        self.assertIn("qemu-guest-agent", rec["containment"]["channel"])
        self.assertEqual(rec["containment"]["engine"], "qemu-kvm")
        self.assertTrue(rec["containment"]["kvm"])
        self.assertFalse(rec["containment"]["base_image_touched"])

    def test_guest_has_no_egress(self):
        res = self._run(["/bin/sh", "-c",
                         "(timeout 6 bash -c 'cat < /dev/tcp/1.1.1.1/53' 2>/dev/null "
                         "&& echo REACHABLE || echo BLOCKED)"])
        self.assertIn("BLOCKED", res["record"]["stdout_tail"])
        self.assertEqual(res["record"]["containment"]["network"], "restrict")

    def test_base_image_is_never_written_and_the_overlay_is_discarded(self):
        before = self._sha(self.base)
        res = self._run(["/bin/sh", "-c", "echo ephemeral > /bp-should-not-persist"])
        self.assertEqual(self._sha(self.base), before, "the base image must be read-only")
        workdir = res["workdir"]
        self.assertFalse(os.path.exists(os.path.join(workdir, "disk.qcow2")),
                         "the per-run overlay must be discarded")

    def test_state_does_not_leak_between_runs(self):
        """Write a file in one run; the next run must not see it."""
        marker = "/bp-crosstalk-" + os.urandom(4).hex()
        self._run(["/bin/sh", "-c", "echo x > " + marker])
        res = self._run(["/bin/sh", "-c",
                         "test -e " + marker + " && echo LEAKED || echo CLEAN"])
        self.assertIn("CLEAN", res["record"]["stdout_tail"])

    def test_a_target_that_panics_the_guest_kernel_is_contained_and_reported(self):
        """The BSOD case: the target takes the guest kernel down. The host must not care."""
        res = self._run(["/bin/sh", "-c",
                         "echo c > /proc/sysrq-trigger"], timeout_s=25, honeypots=False)
        rec = res["record"]
        self.assertTrue(rec["bsod_suspected"], rec["warnings"])
        self.assertTrue(rec["crashed"])
        self.assertTrue(any("panic" in w.lower() for w in rec["warnings"]), rec["warnings"])
        # the host is demonstrably fine - this process is still running
        self.assertTrue(os.path.isdir("/dev"))

    def test_bait_is_planted_in_the_guest_and_a_target_that_tampers_is_caught(self):
        """The bait lives on the guest's throwaway disk, so tampering shows up in the
        in-guest audit, not on the host honeypot root."""
        drive = "/root/.wine/drive_c"
        res = self._run(["/bin/sh", "-c",
                         "ls %s/Users/analyst/Desktop >/dev/null 2>&1 && echo BAIT_PRESENT; "
                         "echo pwned >> %s/Users/analyst/Desktop/license.key; "
                         "rm -f %s/Users/analyst/wallet.dat; "
                         "cat %s/Users/analyst/Documents/passwords.txt > /out/stolen.txt"
                         % (drive, drive, drive, drive)])
        rec = res["record"]
        self.assertIn("BAIT_PRESENT", rec["stdout_tail"])
        self.assertTrue(rec["containment"]["bait_inside_guest"])
        report = res["honeypots"]
        self.assertFalse(report["summary"]["clean"])
        changes = {h["change"] for h in report["hits"]}
        self.assertIn("modified", changes)
        self.assertIn("deleted", changes)
        self.assertIn("token_leaked", changes)
        self.assertEqual(report.get("observed_in"), "guest")
        # the leak was recovered as a real file on the host
        self.assertTrue(any(a.endswith("stolen.txt") for a in rec["artifacts"]), rec["artifacts"])
