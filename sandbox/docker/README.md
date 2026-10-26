# Container isolation backend

Hardened, throwaway container. The fixed flag set (see
`backends/docker_backend.py::_run_flags`) is not configurable into something
weaker:

- `--network none` - no interfaces except loopback, verified per run
- `--read-only` root filesystem, verified per run by attempting a write to `/`
- `--cap-drop ALL --security-opt no-new-privileges`
- `--pids-limit 256 --ipc none --memory <limit> --cpus <n>`
- `--user 1000:1000` - unprivileged, never root
- writable paths only: `/tmp` (64m tmpfs), `/out` (workdir bind), `/scratch` (wine prefix)
- target mounted read-only at `/in/<name>`, honeypots read-only at `/honeypots`
- the container is created per run and `docker rm -f`'d afterwards

## Build the analysis image

```bash
cd <repo root>
docker build -f sandbox/docker/Dockerfile.sandbox -t bobbypin/sandbox:latest .
```

Until it is built, containment probes fall back to `alpine:3.20` (they only need
a shell) and payload runs fail loudly with the build hint above. Payload runs are
never silently substituted - the configured image is where the tooling lives.

## Run

```bash
# containment probe - proves the boundary, executes nothing
python3 -c "from sandbox.runner import run_sandbox; import json; \
  print(json.dumps(run_sandbox(workdir='/tmp/bp-probe'), indent=2))"

# a target, inside the boundary (wine, from the image)
python3 -c "from sandbox.runner import run_sandbox; \
  print(run_sandbox(target='/abs/app.exe', argv=['wine','/in/app.exe']))"
```

The record's `containment` block carries the *observed* values, not the intended
ones - if the probe could not confirm egress is blocked or the rootfs read-only,
`network_verified` / `rootfs_verified` are false and a warning is appended.

## Not a kernel boundary

Containers share the host kernel. Crash containment - the thing that stops a bad
target from taking your workstation down - is solid. A deliberate kernel exploit
is not contained; for hostiles, use the KVM backend.
