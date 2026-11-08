# START HERE

bobbypin is a reverse-engineering suite: it finds the branch that decides
"licensed / not licensed", "password correct / wrong", "debugger detected /
not", and patches a copy of the binary so you can prove the outcome. Everything
runs against software you own or are authorised to test.

Three surfaces over one engine — a browser GUI, a CLI, and an AI layer. Deep
analysis (Ghidra, jadx, apktool) is the packaged `pinpoint` component, installed
for you by the same command.

---

## 1. Install — one command

```bash
./install.sh
```

That is `python3 setup.py` with the repo as the working directory. It:

1. checks Python, installs `capstone` (repo-local `.venv` if the system
   interpreter is PEP 668 managed)
2. reports any missing system packages with the exact apt line
3. builds the container analysis image, if docker is up
4. provisions the KVM guest (~330 MB, one unattended install) — the strongest
   isolation boundary
5. writes `~/.bobbypin/sandbox.json`
6. installs the **pinpoint** analysis layer from the bundled tarball (or the
   release asset when the bundle is not present), writes
   `~/.config/pinpoint-env.sh`, and prints which deep providers are live
7. runs a containment probe so the boundary is proven before you trust it

Nothing is mandatory. No docker? Static analysis still works. No Node? Patch
loop still works, only deep decompilation is missing. Re-running is always safe.

```bash
./install.sh --check     # report only, change nothing
./install.sh --yes       # never prompt
./install.sh --no-vm     # docker backend only
```

Full flag list: `python3 setup.py --help`.

---

## 2. First five minutes

```bash
# what is this file, and what does it do when it sees a debugger?
python3 bobbypin.py target/myapp/app.exe
python3 bobbypin_ai.py anti_analysis '{"path":"target/myapp/app.exe"}'

# triage + verified candidates + suggested_next in one JSON answer
python3 bobbypin_ai.py plan '{"path":"target/myapp/app.exe"}'
```

Drop targets in `target/` — that is the convention the playbooks assume. There
is no per-target paperwork: [`target/AUTHORIZATION.md`](target/AUTHORIZATION.md)
is a standing grant covering everything under `target/`.

Prefer clicking? `python3 bobbypin_gui.py` then open http://127.0.0.1:8877

---

## 3. Drive it with an AI agent

| read | why |
|---|---|
| [`AGENTS.md`](AGENTS.md) | the complete operating manual: every command, argument, JSON shape, decision rules |
| `target/AUTHORIZATION.md` | standing scope — read once, then work; nothing to fill in |
| `pinpoint/skills/pinpoint/SKILL.md` | the deep-analysis skill, shipped with the pinpoint package |

The `pinpoint` CLI also runs as an MCP server (229 tools) so an agent can call
the analysis layer directly:

```bash
pinpoint mcp --help            # or register it: pinpoint setup --client codex
pinpoint capabilities          # which providers are actually reachable on this host
```

Every answer is evidence, not prose: a `ev_sha256…` bundle with coverage and
limitations attached, so a claim can be re-checked instead of trusted.

---

## 4. What is in the box

```
bobbypin.py              CLI engine — triage, strings, candidates, disasm, patch, verify
bobbypin_ai.py           JSON layer for agents — same engine, strict output, one-shot or serve
bobbypin_gui.py          browser GUI on 127.0.0.1:8877
antianalysis.py          debug/analysis protection detection with evidence
antidebug_patch.py       patch the checks out, then prove it in the sandbox
sandbox/                 isolation backends (kvm, docker, fake-debugger harness)
pinpoint.py              bridge from bobbypin to the pinpoint analysis layer
pinpoint/                the deep-analysis component (Ghidra / jadx / apktool / pwntools)
setup.py                 one-command installer
install.sh               ./install.sh wrapper around setup.py
AGENTS.md                AI operating manual
target/AUTHORIZATION.md  standing scope
start-here               this file
```

---

## 5. When something is missing

```bash
./install.sh --check       # what is missing, changes nothing
pinpoint doctor            # why the analysis layer is unhappy
pinpoint capabilities      # which engines are live right now
```

Engines are opt-in and never auto-downloaded: Ghidra, IDA, Hopper, Kuna, jadx,
apktool. Set the matching `PINPOINT_*` variable (or `GHIDRA_INSTALL_DIR`) and the
operation unlocks; leave it unset and the answer is `provider_unavailable`
instead of a guess.

---

## 6. The rules that do not bend

- Analysis, patching and repacking happen on **copies**. The original is never the
  write target.
- Anything that **executes** a target goes through `sandbox_run` — a real VM with
  its own kernel, no network, fresh disk. Never on the host.
- Credentials or user data found inside a target are reported, never used.
- Local file access is not permission to touch the live service that file talks
  to. Say no to that, in one sentence.

Read [`README.md`](README.md) for the long version, per-format workflows and the
legal section.
