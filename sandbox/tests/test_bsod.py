"""Guest-crash detection tests."""

import os
import tempfile
import unittest

from sandbox import bsod

REPO_PATH = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class BsodTest(unittest.TestCase):
    POSITIVE = [
        "*** STOP: 0x0000007E (0xC0000005, 0xFFFFF880, 0x0, 0x0)",
        "KMODE_EXCEPTION_NOT_HANDLED",
        "PAGE_FAULT_IN_NONPAGED_AREA",
        "IRQL_NOT_LESS_OR_EQUAL",
        "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        "CRITICAL_PROCESS_DIED",
        "BAD_POOL_CALLER",
        "UNEXPECTED_KERNEL_MODE_TRAP",
        "A problem has been detected and Windows has been shut down to prevent damage",
        "bugcheck 0x00000050",
        "Kernel panic - not syncing: Attempted to kill init!",
        "BUG: unable to handle kernel NULL pointer dereference",
        "qemu: terminating on signal 11 from pid 4242",
        "KVM: entry failed, hardware error 0x0",
        "triple fault - resetting",
        "Guest has not initialized the display (yet)",
    ]
    WARN_ONLY = [
        # our own timeout kill: noteworthy, but not evidence of a guest crash
        "qemu: terminating on signal 15 from pid 4242",
        "guest reset",
    ]
    NEGATIVE = [
        "",
        "booting linux kernel 6.1.0",
        "systemd[1]: Reached target Multi-User System.",
        "License check failed: invalid key",
        "wine: created the configuration directory",
        "exit code 0",
        "the quick brown fox jumps over the lazy dog",
    ]

    def test_positives_are_flagged(self):
        for text in self.POSITIVE:
            rep = bsod.detect(text)
            self.assertEqual(rep["severity"], "hit", f"missed: {text!r}")
            self.assertTrue(rep["bsod_suspected"], text)

    def test_negatives_are_clean(self):
        for text in self.NEGATIVE:
            rep = bsod.detect(text)
            self.assertFalse(rep["bsod_suspected"], f"false positive: {text!r}")
            self.assertEqual(rep["severity"], "none")

    def test_matches_carry_the_offending_line(self):
        rep = bsod.detect("noise\n*** STOP: 0x0000000A\nnoise")
        self.assertTrue(rep["matches"])
        self.assertIn("STOP", rep["matches"][0]["line"])

    def test_expected_termination_is_only_a_warning(self):
        for text in self.WARN_ONLY:
            rep = bsod.detect(text)
            self.assertEqual(rep["severity"], "warn", text)
            self.assertFalse(rep["bsod_suspected"], text)

    def test_warn_level_alone_is_not_a_bugcheck(self):
        rep = bsod.detect("qemu: terminating on signal 9")
        self.assertEqual(rep["severity"], "warn")
        self.assertFalse(rep["bsod_suspected"])

    def test_scan_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "serial.log")
            with open(path, "w") as fh:
                fh.write("SeaBIOS booting...\n*** STOP: 0x0000003B\n")
            rep = bsod.scan_file(path)
            self.assertTrue(rep["bsod_suspected"])
            self.assertEqual(rep["path"], path)
            missing = bsod.scan_file(os.path.join(tmp, "nope.log"))
            self.assertFalse(missing["bsod_suspected"])
            self.assertEqual(missing["error"], "not found")

    def test_scan_file_tolerates_binary_noise(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "serial.log")
            with open(path, "wb") as fh:
                fh.write(bytes(range(256)) * 8)
            self.assertIn("bsod_suspected", bsod.scan_file(path))


class BootCycleTest(unittest.TestCase):
    """Two boot banners in one run == the guest went down and came back. This is the
    witness that survives a crashed guest, because the guest agent does not."""

    OVMF = (b"BdsDxe: loading Boot0005 \"Windows Boot Manager\" from HD(1,GPT,...)\r\n"
            b"BdsDxe: starting Boot0005 \"Windows Boot Manager\" from HD(1,GPT,...)\r\n")
    SEABIOS = b"SeaBIOS (version 1.16.2-debian-1.16.2-1)\r\n"

    def test_one_boot_is_not_a_restart(self):
        self.assertEqual(bsod.count_boot_cycles(self.OVMF), 1)
        self.assertFalse(bsod.count_boot_cycles(self.OVMF) > 1)
        self.assertEqual(bsod.count_boot_cycles(self.SEABIOS), 1)

    def test_two_boots_is_a_restart(self):
        self.assertEqual(bsod.count_boot_cycles(self.OVMF * 2), 2)

    def test_banner_variants_do_not_double_count_one_boot(self):
        """loading+starting are two lines for the SAME boot, so take the max, not the sum."""
        one_boot = (b"BdsDxe: loading Boot0005 x\r\nBdsDxe: starting Boot0005 x\r\n")
        self.assertEqual(bsod.count_boot_cycles(one_boot), 1)
        self.assertEqual(bsod.count_boot_cycles(one_boot * 2), 2)

    def test_empty_and_junk(self):
        self.assertEqual(bsod.count_boot_cycles(b""), 0)
        self.assertEqual(bsod.count_boot_cycles(b"nothing to see"), 0)

    def test_scan_boot_cycles_over_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "serial.log")
            with open(path, "wb") as fh:
                fh.write(self.OVMF * 2)
            rep = bsod.scan_boot_cycles(path)
            self.assertEqual(rep["cycles"], 2)
            self.assertTrue(rep["restarted"])
            missing = bsod.scan_boot_cycles(os.path.join(tmp, "nope.log"))
            self.assertFalse(missing["restarted"])


class MiniDumpTest(unittest.TestCase):
    """The bugcheck code lives in the dump header. There is no readable banner anywhere:
    the "*** STOP:" line is printed by a debugger, not by the crashed machine."""

    FIXTURE = os.path.join(REPO_PATH, "fixtures", "anti_analysis", "bugcheck-0xef.dmp")

    def _synthetic(self, tmp, code, signature=b"PAGEDU64"):
        import struct
        blob = bytearray(0x2000)
        blob[0:8] = signature.ljust(8, b"\x00")
        struct.pack_into("<I", blob, 0x38, code)
        struct.pack_into("<4Q", blob, 0x40, 0xffffb009ab711080, 0xffffb009ab711080, 0, 0)
        path = os.path.join(tmp, "synthetic.dmp")
        with open(path, "wb") as fh:
            fh.write(bytes(blob))
        return path

    def test_real_capture_from_the_windows_guest(self):
        if not os.path.isfile(self.FIXTURE):
            self.skipTest("no captured dump fixture")
        rep = bsod.parse_minidump(self.FIXTURE)
        self.assertIsNone(rep["error"])
        self.assertEqual(rep["bugcheck_code"], 0xEF)
        self.assertEqual(rep["bugcheck_name"], "CRITICAL_PROCESS_DIED")
        self.assertTrue(rep["bsod_suspected"])
        self.assertTrue(rep["parameters"])

    def test_synthetic_header(self):
        import tempfile as tf
        with tf.TemporaryDirectory() as tmp:
            rep = bsod.parse_minidump(self._synthetic(tmp, 0x0000007E))
            self.assertEqual(rep["bugcheck_code"], 0x7E)
            self.assertEqual(rep["bugcheck_name"], "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED")
            self.assertIn("0x", rep["parameters"][0])

    def test_unnamed_code_still_reports_the_number(self):
        import tempfile as tf
        with tf.TemporaryDirectory() as tmp:
            rep = bsod.parse_minidump(self._synthetic(tmp, 0x0000ABCD))
            self.assertEqual(rep["bugcheck_code"], 0xABCD)
            self.assertIsNone(rep["bugcheck_name"], "unknown codes must not be invented")
            self.assertTrue(rep["bsod_suspected"])

    def test_missing_and_truncated_dumps(self):
        import tempfile as tf
        rep = bsod.parse_minidump("/nonexistent/x.dmp")
        self.assertIsNotNone(rep["error"])
        self.assertFalse(rep.get("bsod_suspected"))
        with tf.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "tiny.dmp")
            with open(path, "wb") as fh:
                fh.write(b"PAGE")
            self.assertIsNotNone(bsod.parse_minidump(path)["error"])


if __name__ == "__main__":
    unittest.main()
