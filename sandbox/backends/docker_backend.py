"""Hardened-container isolation backend.

The boundary is a single throwaway container created with a fixed, non-negotiable
flag set. A target cannot reach the network, cannot write to the root filesystem,
cannot gain capabilities, cannot see the host, and cannot survive the run: the
container is destroyed afterwards.

Trade-off, stated plainly: containers share the host kernel. A kernel-level
exploit (rare, and not what a crashing or badly-written application does) could
escape. For crash containment - "don't take my workstation down" - this is
sufficient; for hostile binaries, use the KVM backend.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from datetime import datetime, timezone

from ..base import RunRecord, RunRequest, SandboxBackend, SandboxUnavailable, new_run_id
from .. import capabilities

SANDBOX_IMAGE = "bobbypin/sandbox:latest"
FALLBACK_IMAGE = "alpine:3.20"

# POSIX-sh containment probe. Prints exactly one BOBBYPIN_PROBE line of key=value
# pairs (no embedded quotes, so there is nothing to escape between Python and sh).
PROBE_SCRIPT = r"""
uid=$(id -u 2>/dev/null || echo -1)
ro=0
if (printf x > /.bp_write_test) 2>/dev/null; then rm -f /.bp_write_test; else ro=1; fi
tmpw=0
if (printf x > /tmp/.bp_write_test) 2>/dev/null; then tmpw=1; rm -f /tmp/.bp_write_test; else tmpw=0; fi
ifaces=$(ls /sys/class/net 2>/dev/null | tr "\n" ",")
ifaces=${ifaces%,}
egress=unknown
if command -v nc >/dev/null 2>&1; then
  if nc -w 2 1.1.1.1 53 </dev/null >/dev/null 2>&1; then egress=reachable; else egress=blocked; fi
elif command -v wget >/dev/null 2>&1; then
  if wget -q -T 2 -O /dev/null http://1.1.1.1/ >/dev/null 2>&1; then egress=reachable; else egress=blocked; fi
fi
hp=0; [ -d /honeypots ] && hp=1
inp=0; [ -d /in ] && inp=1
outp=0; [ -d /out ] && outp=1
echo "BOBBYPIN_PROBE uid=$uid ro=$ro tmpw=$tmpw ifaces=${ifaces} egress=${egress} hp=$hp in=$inp out=$outp"
"""

KEEPALIVE = "trap 'exit 0' TERM INT; while :; do sleep 1; done"


def parse_probe(stdout: str) -> dict:
    """BOBBYPIN_PROBE key=value ... -> dict with ints coerced."""
    data: dict = {}
    for line in (stdout or "").splitlines():
        if not line.startswith("BOBBYPIN_PROBE "):
            continue
        for token in line[len("BOBBYPIN_PROBE "):].split():
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            if key in {"uid", "ro", "tmpw", "hp", "in", "outp"}:
                try:
                    data[key] = int(value)
                except ValueError:
                    data[key] = value
            else:
                data[key] = value
    return data


class DockerBackend(SandboxBackend):
    name = "docker"

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self.timeout_s = int(self.config.get("timeout_s", 300) or 300)
        self.image = self.config.get("image") or SANDBOX_IMAGE

    # -- capability -------------------------------------------------------
    def available(self) -> dict:
        return capabilities.docker_available()

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _docker(args, timeout=60):
        try:
            return subprocess.run(["docker", *args], capture_output=True,
                                  text=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            return subprocess.CompletedProcess(["docker", *args], 127, "", str(exc))

    def _image_present(self, image: str) -> bool:
        return self._docker(["image", "inspect", image], timeout=30).returncode == 0

    def _resolve_image(self, req: RunRequest, probe: bool):
        """Pick an image. Returns (image, warnings).

        A containment probe only needs a shell, so it may fall back to a tiny
        public image. A payload run does not: the configured image is where the
        analysis tooling (wine, python) lives, so a missing one is an error.
        """
        warnings: list = []
        wanted = req.image or self.image
        build_hint = ("build it: docker build -f sandbox/docker/Dockerfile.sandbox "
                      "-t " + SANDBOX_IMAGE + " .")
        if self._image_present(wanted):
            return wanted, warnings
        if probe:
            if self._image_present(FALLBACK_IMAGE):
                warnings.append(f"sandbox image {wanted!r} not built; probe used {FALLBACK_IMAGE}")
                return FALLBACK_IMAGE, warnings
            warnings.append(f"sandbox image {wanted!r} not built; pulled {FALLBACK_IMAGE} for the probe")
            res = self._docker(["pull", FALLBACK_IMAGE], timeout=180)
            if res.returncode != 0:
                raise SandboxUnavailable(
                    f"no usable sandbox image: {wanted!r} missing and {FALLBACK_IMAGE!r} "
                    f"could not be pulled ({(res.stderr or '').strip()[:200]})",
                    install=build_hint, backend=self.name)
            return FALLBACK_IMAGE, warnings
        warnings.append(f"image {wanted!r} not present locally; pulling")
        res = self._docker(["pull", wanted], timeout=900)
        if res.returncode != 0:
            raise SandboxUnavailable(
                f"image {wanted!r} unavailable: {(res.stderr or '').strip()[:200]}",
                install=build_hint, backend=self.name)
        return wanted, warnings

    def _run_flags(self, req: RunRequest, out_dir: str, warnings: list) -> list:
        """The fixed containment flag set. Not configurable into something weaker."""
        if not req.no_egress:
            warnings.append("no_egress=False was ignored: sandbox networking is always disabled")
        scratch_dir = os.path.join(os.path.dirname(out_dir), "scratch")
        os.makedirs(scratch_dir, exist_ok=True)
        flags = [
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "256",
            "--ipc", "none",
            "--user", "1000:1000",
            "--tmpfs", "/tmp:rw,size=64m,mode=1777",
            "--memory", str(req.memory or "2g"),
            "--memory-swap", str(req.memory or "2g"),
            "--cpus", str(req.cpus),
            "--stop-timeout", "5",
            "-v", f"{out_dir}:/out",
            "-v", f"{scratch_dir}:/scratch",
            "--env", "HOME=/scratch",
            "--env", "WINEPREFIX=/scratch/.wine",
        ]
        if req.target:
            flags += ["-v", f"{os.path.abspath(req.target)}:/in/{os.path.basename(req.target)}:ro"]
        if req.honeypot_root:
            flags += ["-v", f"{os.path.abspath(req.honeypot_root)}:/honeypots:ro"]
        for helper in (req.helpers or []):
            if os.path.isfile(helper):
                flags += ["-v", f"{os.path.abspath(helper)}:/in/{os.path.basename(helper)}:ro"]
            else:
                warnings.append(f"helper not found: {helper}")
        for key, value in (req.env or {}).items():
            if not key.replace("_", "").isalnum():
                warnings.append(f"ignored env var with unsafe name: {key!r}")
                continue
            flags += ["--env", f"{key}={value}"]
        return flags

    # -- execution --------------------------------------------------------
    def run(self, req: RunRequest) -> RunRecord:
        self._ensure_ready()
        rec = RunRecord(run_id=new_run_id(), backend=self.name)
        rec.target = os.path.abspath(req.target) if req.target else None
        started = time.time()
        rec.started_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if rec.target:
            if not os.path.isfile(rec.target):
                raise SandboxUnavailable(f"target not found: {rec.target}", backend=self.name)
            rec.target_size = os.path.getsize(rec.target)
            sha = hashlib.sha256()
            with open(rec.target, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    sha.update(chunk)
            rec.target_sha256 = sha.hexdigest()

        workdir = os.path.abspath(os.path.expanduser(req.workdir or "/tmp/bobbypin-sbx"))
        os.makedirs(workdir, exist_ok=True)
        out_dir = os.path.join(workdir, "out")
        os.makedirs(out_dir, exist_ok=True)

        probe_mode = not req.argv
        image, warnings = self._resolve_image(req, probe_mode)
        rec.warnings.extend(warnings)
        flags = self._run_flags(req, out_dir, rec.warnings)
        timeout_s = int(req.timeout_s or self.timeout_s)
        name = f"bobbypin-sbx-{rec.run_id[:12]}"

        create = self._docker(["create", "--name", name, *flags, image, "sh", "-c", KEEPALIVE],
                              timeout=120)
        if create.returncode != 0:
            raise SandboxUnavailable(
                "could not create sandbox container: " + (create.stderr or create.stdout).strip()[:300],
                backend=self.name)

        stdout_chunks: list = []
        stderr_chunks: list = []
        state: dict = {}
        try:
            start = self._docker(["start", name], timeout=60)
            if start.returncode != 0:
                raise SandboxUnavailable(
                    "could not start sandbox container: " + (start.stderr or "").strip()[:300],
                    backend=self.name)

            # phase 1 - prove the boundary actually holds
            probe = self._docker(["exec", name, "sh", "-c", PROBE_SCRIPT], timeout=45)
            pd = parse_probe(probe.stdout or "")
            egress = pd.get("egress", "unknown")
            rec.containment = {
                "engine": "docker",
                "network": "none",
                "network_verified": egress == "blocked",
                "rootfs": "read-only",
                "rootfs_verified": pd.get("ro") == 1,
                "tmp_writable": pd.get("tmpw") == 1,
                "ephemeral": True,
                "uid": pd.get("uid"),
                "cap_drop": "ALL",
                "no_new_privileges": True,
                "pids_limit": 256,
                "memory_limit": str(req.memory or "2g"),
                "cpus": req.cpus,
                "interfaces": pd.get("ifaces", ""),
                "writable_paths": ["/tmp (tmpfs, 64m)", "/out (workdir bind)",
                                   "/scratch (workdir bind, wine prefix)"],
                "honeypots_mounted_read_only": bool(pd.get("hp")),
                "input_mounted_read_only": bool(pd.get("in")),
            }
            if not rec.containment["network_verified"]:
                rec.warnings.append(f"containment probe could not confirm egress is blocked (egress={egress!r})")
            if not rec.containment["rootfs_verified"]:
                rec.warnings.append("containment probe could not confirm the root filesystem is read-only")

            # phase 2 - the payload
            if not probe_mode:
                if req.trip_debug and req.target:
                    self.trip_helper = req.trip_helper or (req.helpers[0] if req.helpers else None)
                    req.argv = self.trip_argv("linux", "/in", os.path.basename(req.target))
                    rec.containment["trip_debug"] = True
                argv = [str(a) for a in req.argv]
                try:
                    done = subprocess.run(["docker", "exec", name, *argv],
                                          capture_output=True, text=True, timeout=timeout_s)
                    rec.exit_code = done.returncode
                    stdout_chunks.append(done.stdout or "")
                    stderr_chunks.append(done.stderr or "")
                except subprocess.TimeoutExpired as exc:
                    rec.timed_out = True
                    rec.warnings.append(f"payload exceeded timeout_s={timeout_s}; container killed")
                    for stream, sink in ((exc.stdout, stdout_chunks), (exc.stderr, stderr_chunks)):
                        if stream is None:
                            continue
                        sink.append(stream.decode("utf-8", "replace") if isinstance(stream, bytes) else stream)
                    self._docker(["kill", name], timeout=30)
                except OSError as exc:
                    raise SandboxUnavailable(f"docker exec failed: {exc}", backend=self.name)

            insp = self._docker(["inspect", "--format", "{{json .State}}", name], timeout=30)
            if insp.returncode == 0 and insp.stdout.strip():
                try:
                    state = json.loads(insp.stdout.strip())
                except ValueError:
                    state = {}
        finally:
            self._docker(["rm", "-f", name], timeout=60)

        rec.stdout_tail = self._tail("".join(stdout_chunks))
        rec.stderr_tail = self._tail("".join(stderr_chunks))
        rec.ended_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rec.duration_s = round(time.time() - started, 3)

        if state:
            if rec.exit_code is None and isinstance(state.get("ExitCode"), int):
                rec.exit_code = state["ExitCode"]
            rec.oom_killed = bool(state.get("OOMKilled"))
        if rec.exit_code is not None and rec.exit_code > 128:
            rec.signal = rec.exit_code - 128
        if rec.exit_code == 137:
            rec.oom_killed = True
            rec.warnings.append("exit 137: process killed by SIGKILL (cgroup memory limit or OOM)")
        rec.crashed = bool(rec.timed_out or rec.exit_code not in (0, None) or rec.signal)
        rec.abnormal_exit = bool(rec.timed_out or rec.signal or rec.oom_killed)

        rec.artifacts = sorted(os.path.join(out_dir, f) for f in os.listdir(out_dir)) \
            if os.path.isdir(out_dir) else []
        return rec
