<p align="center">
  <img src="bobbypin_logo.svg" alt="bobbypin" width="132">
</p>

<h1 align="center">bobbypin</h1>

<p align="center"><b>Recover the source, or find the branch that decides "licensed" and flip it.</b><br>
A reverse-engineering suite for binaries you have no source for.</p>

<p align="center">
  <a href="https://bobbypin.bobbycodes.dev/count.json" title="every clone and every download, live"><img src="https://bobbypin.bobbycodes.dev/badge.svg" alt="downloads"></a>
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT">
  <img src="https://img.shields.io/badge/python-3.7%2B-3776AB?logo=python&logoColor=white" alt="python 3.7+">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey" alt="platforms">
  <img src="https://img.shields.io/badge/targets-PE%20%C2%B7%20Electron%20%C2%B7%20.NET%20%C2%B7%20APK%20%C2%B7%20ELF-informational" alt="targets">
</p>

bobbypin takes a compiled app you have no source for and gets you inside it. It
finds the string that says *you are not licensed*, follows it backwards to the
exact conditional jump that decides your fate, and flips that jump in a copy.
Then it proves the result by running both builds in a VM and reporting what
actually happened.

The name is the hair pin: a thin piece of spring steel that goes where nothing
else fits and holds one thing in place.

```bash
git clone https://github.com/BobbyCodes-dev/bobbypin.git
cd bobbypin && ./install.sh          # toolchain, sandbox, VM, analysis layer, probe
python3 recover.py target/myapp/app.apk        # source tree, nothing patched
python3 bobbypin_ai.py plan '{"path":"target/myapp/app.exe"}'
```

Two jobs, one tool: **read the program** or **change it**.

Five minutes of context, one page: **[START-HERE.md](START-HERE.md)**. Driving it
with an AI: **[AGENTS.md](AGENTS.md)**.

---

## What it does

| | Job | What you get |
|---|---|---|
| 📖 | **Recover source** | a readable tree with no patch step at all: C# from .NET, Java from APK/JAR, the shipped JS from Electron, C pseudocode from native |
| 🔓 | **Crack licence checks** | the exact conditional jump guarding the check, verified by a real disassembler, patched length-preserving in a copy |
| 🔑 | **Bypass password and login gates** | same loop against activation and auth branches, in PE and in Electron apps |
| 🛡 | **Defeat anti-debug protection** | the checks found with evidence, the response classified (exit, nag, wipe, bugcheck), the forceable ones neutralised |
| ✅ | **Prove every patch** | original and patched both run in an isolated VM; the verdict is `neutralised` or `still_fires`, never "patch applied" |

<br>

## See it work

Real output, trimmed. Managed code, decompiled without loading the assembly:

```console
$ pinpoint --version
1.0.0

$ python3 bobbypin_ai.py pinpoint_status
{"ok": true, "installed": true, "version": "1.0.0",
 "deep_providers": {"available": ["artifact-graph", "managed-static"],
                    "unavailable": ["ghidra", "hopper", "ida", "kuna"]}}

$ pinpoint decompile /bin/true 0x23d0
evidence_id: ev_faedbe58f9a2f6e1a385bd772f2d461704a6a4747d3baa99c7614032d83f1bec
provider:    ghidra 12.1.4
raw_result:
  value: "void processEntry entry(undefined8 param_1, undefined8 param_2)
          {
            __libc_start_main(FUN_00102310, param_2, &stack0x00000008, 0, 0, param_1, auStack_8);
            do { } while (true);
          }"
```

Every answer is an evidence record with coverage and limitations attached, not a
paragraph of prose. Anything that cannot be done on this host says
`provider_unavailable` with the exact setting to fix, instead of guessing.

<br>

## Get the source, not the patch

Reading a program and changing it are separate jobs, so they are separate
commands. `recover_source` writes a source tree and states which engine produced
it. It never writes to the target and there is no patch code on that path.

```bash
python3 recover.py app.apk                  # Java sources + resources, via jadx
python3 recover.py App.dll --out src        # a C# project, via ilspycmd
python3 recover.py app.asar                 # the shipped JavaScript, as shipped
python3 recover.py app.exe                  # C pseudocode, one file per function
python3 recover.py app.exe --json           # manifest: engine, files, languages
```

| Target | Engine | What lands in the output directory |
|---|---|---|
| .NET assembly | ilspycmd | one `.cs` per type, plus a `.csproj` you can open in an IDE, and every compiled WPF page as editable `.xaml` |
| Android `.apk`, Java `.jar` | jadx | Java sources under `sources/`, resources and manifest beside them |
| Electron `.asar` | built in | the real JavaScript tree, not a decompilation |
| PyInstaller bundle | built in, `pycdc` optional | the payload plus every module in the `PYZ` archive, non-stdlib `.pyc` turned back into `.py` |
| native PE / ELF / Mach-O | Ghidra through pinpoint | one `.c` per function, with provider and address in a header comment |

Real runs, on real artifacts:

- A 6.5 MB Android package: **4,707 files, 2,584 `.java`, 1,503 `.xml`, 16 s**
- A 13 MB PyInstaller GUI app: **851 files, 554 modules out of the `PYZ`, 230 `.py` recovered, 2 s**
- An 11 MB native Windows binary: **one `.c` per function**, 20 to 140 s depending on size
- A .NET assembly: **95 `.cs` and a `.csproj` in 2 s**

The recovery layer has 34 tests that build their own fixtures and skip engines
that are not installed: `python3 tests/test_recover.py`. Point it at real
artifacts with `BOBBYPIN_REAL_TARGETS=targets.json` and every one is recovered
and re-hashed to prove it was not written to.

### WPF screens come back as markup, not as guesses

A WPF app's `.xaml` pages are compiled to binary **BAML** and stored inside the
assembly's `<AssemblyName>.g.resources` container, where a C# decompile cannot see
them. `baml_to_xaml.py` drives `ilspycmd` once per stream and writes the pages back
as editable XAML, mirroring the resource paths:

```bash
python3 bobbypin.py App.dll --baml              # -> App_xaml/, one .xaml per page
python3 baml_to_xaml.py App.dll --list          # what is embedded, extract nothing
python3 baml_to_xaml.py App.dll --resource "App.g.resources/mainwindow.baml"
```

`recover.py App.dll` runs this pass itself (`wpf_xaml` in the manifest), so one
command returns the code and the screens. `App.g.resources/views/mainwindow.baml`
becomes `views/mainwindow.xaml`; only `.baml` entries are decompiled. ILSpy emits
synthetic namespaces in the output, so recompiling it against the real assembly may
need those normalised. Point it at a managed `.dll`: a single-file .NET bundle has
no managed resources at the top level. Needs `dotnet tool install -g ilspycmd`, and
`python3 tests/test_baml_to_xaml.py` covers it with a stub engine, so it runs
without the .NET SDK.

`ok` means source files came back, not that a subprocess exited 0. A run that
writes only its engine's index reports failure. Packed targets (`upx0`, `.vmp0`,
`.themida`) say so instead of presenting the unpacker stub as the program, and a
forced `--engine` that cannot read the detected kind is refused by name.

Missing engine means a named error with the line that fixes it, never a silent
no-op:

```console
$ python3 recover.py App.dll
recover: ilspycmd is not installed
  fix: dotnet tool install -g ilspycmd  (needs the .NET SDK 8+)
  or:  without it, pinpoint can still read managed metadata: pinpoint inspect-managed-members <path>
```

Native recovery needs Ghidra (or Hopper, IDA, Kuna). Without one the answer says
so, and `disasm` still reads the instructions.

<br>

## How a patch happens

```
  triage      ──▶  what is this? format, strings, packers, protections
                   │
                   ▼
  candidates  ──▶  which conditional jumps actually guard the strings that matter
                   │
                   ▼
  disasm      ──▶  30 instructions of context: is this the right check?
                   │
                   ▼
  patch       ──▶  NOP or branch flip, length-preserving, written to a copy
                   │
                   ▼
  verify      ──▶  byte diff, then both builds run in the VM against a debugger
                   │
                   ▼
  verdict     ──▶  neutralised / still_fires / nothing_to_prove
```

`plan` runs the first three steps in one call and hands you `suggested_next`.

<br>

## Three ways in

| Surface | Start with | Built for |
|---|---|---|
| **GUI** | `python3 bobbypin_gui.py` | clicking through: drop a binary, hit **Workflow**, go baseline → strings → candidates → byte verify → patch |
| **CLI** | `python3 bobbypin.py target.exe` | repeat runs and scripting (`--json`, `--apply N`, `--flip`) |
| **AI layer** | `python3 bobbypin_ai.py` | strict JSON in and out, one-shot or a persistent `serve` session; every command returns a verdict |

All three call the same engine, so a GUI result and an AI-layer result are the
same finding. Served on `127.0.0.1:8877`.

<br>

## What it handles

| Format | Support |
|---|---|
| **PE32 / PE32+** `.exe` `.dll` | the full loop: verified patching, Frida monitors, UPX auto-unpack |
| **Electron** `.asar` | `electron_plan` + `electron_bypass`, string triage, integrity-correct repacking |
| **.NET** assemblies | detection, BAML to XAML UI recovery, decompile-first playbook |
| **Android** `.apk` | package, class and signature evidence; apktool / jadx playbook |
| **PyInstaller** bundles | unpacking, string triage, SSL monitor |
| **Java** `.jar` | extraction, string scanning |
| **ELF / Mach-O** | triage, strings, layout, deep decompilation through Ghidra |
| **NSIS / Inno** installers | payload extraction guidance |

<details>
<summary><b>Per-format workflows</b></summary>

- **PE32 / PE32+**: triage → candidate cards → disassembly → NOP or flip → verify.
  The only format the byte-patch engine touches.
- **Java `.jar`**: `python3 bobbypin.py target.jar` extracts to `<name>_unpacked/`
  and scans class and config strings. Change behaviour in Java source, not bytes.
- **Electron `.asar`**: edit plain `.js` directly, repack with `asar_repack` or
  `npx @electron/asar pack`. Bytenode `.jsc` builds cannot be branch-patched; use
  the generated `<name>_hook.js` Frida monitor instead.
- **PyInstaller**: unpacks to `<name>_unpacked/`, decompile the `.pyc` with pycdc
  or uncompyle6, rebuild, confirm live with a Frida monitor.
- **.NET / WPF**: `python3 bobbypin.py App.dll --baml` recovers editable XAML from
  the compiled BAML streams, so you read the real licence screen instead of
  guessing from strings.

</details>

<details>
<summary><b>Why the candidates can be trusted</b></summary>

Strings that matter are decoded from executable sections, then walked forward
over real instruction boundaries to the next conditional jump, never crossing a
function edge. A second pass matches jumps whose target lands on a later guard's
message, so chained checks get their own cards. Dense library string tables
(libcurl, zlib, `SEC_E_*`) are detected and excluded, so you see the app's logic
rather than its dependencies'. Nothing is pattern-guessed.

</details>

<br>

## Deep analysis: pinpoint

Some formats bobbypin can read but cannot reason about, like .NET CIL, APK
internals, ELF and Mach-O. `pinpoint` ships inside this repo and turns those dead
ends into evidence. `./install.sh` installs it; the CLI also runs as an MCP server
with **229 tools** for agents.

| Target kind | Profile | What you get |
|---|---|---|
| `.NET` assembly | `managed` | member signatures, CIL anchors, `ldstr` strings, native boundaries |
| `.apk` | `apk` | package, classes, methods, signing schemes and content digests |
| ELF / Mach-O / unknown | `binary` | format, architecture, digests, sections, imports, entropy |

```bash
pinpoint capabilities          # which engines are reachable on this host
pinpoint doctor                # why one is not
pinpoint analyze /bin/ls       # evidence bundle
```

Engines are bring-your-own and never auto-downloaded: Ghidra, Hopper, IDA, Kuna,
plus jadx and apktool for Android. Set the matching `PINPOINT_*` variable and the
operation unlocks; leave it unset and you get `provider_unavailable` with the
setting to fix, never a fabricated answer.

<details>
<summary><b>Rules the analysis layer holds itself to</b></summary>

- **Read-only.** Only allowlisted probes are reachable from bobbypin. Anything
  that launches a target is refused outside `sandbox_run`.
- **Evidence, not instructions.** No analysis report can choose a patch offset.
  It tells you where to look; bobbypin still decides what to flip.
- **Optional.** No analysis pack means `{"installed": false}` and one install
  hint. Every other command behaves exactly as before.

</details>

<br>

## Isolation, because you are running someone else's binary

Nothing executes on the host. A real QEMU/KVM guest is the default backend, a
hardened container is the fallback, and each run gets a fresh overlay so a crash
never accumulates. Containment is **verified per run**, not assumed: a probe
inside the boundary tries to write to `/` and reach the network, and the results
land in the record.

```
  target ──▶ ┌───────────────────────────┐ ──▶ outcome + containment evidence
             │  VM (own kernel) or       │     network=none (verified)
             │  container (read-only,    │     rootfs=read-only (verified)
             │  caps dropped, non-root)  │     honeypot tokens untouched
             └───────────────────────────┘     bugcheck captured, not hidden
```

`{"trip_debug": true}` runs the target with debugger state simulated, so the
protection fires for real inside the boundary and you see what it actually does.

<details>
<summary><b>Backends, honeypots, telemetry, and the anti-debug detail</b></summary>

**Backends.** `kvm` boots a lean Debian guest or a Windows 11 LTSC guest, picked
by what sits next to the disk image, on the right firmware and bus. Every run
uses a fresh qcow2 overlay, `-no-reboot`, and `-netdev user,restrict=on` with no
port forwards. Files move over the guest agent, so there is no host share to
reach. 8 to 35 seconds per run. `docker` is the zero-dependency fallback:
`--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`,
`--pids-limit 256`, non-root. `auto` picks the strongest available and fails
loudly when none is.

**Anti-debug.** `anti_analysis` answers two questions: is the target checking
whether it is watched, and what happens if it decides it is. It matches imports,
runtime-resolved API names from `GetProcAddress`, byte patterns (PEB access,
RDTSC, CRC tables), and strings. The response is classified because "exits" and
"takes the machine with it" are different findings:

`deliberate BSOD` · `wipes or encrypts data` · `reboots or powers off` ·
`deletes itself` · `corrupts files or registry` · `exits the process` · `hangs` ·
`shows a nag`

`antidebug_patch` then neutralises the checks whose verdict can be forced. A
boolean detection call becomes `xor eax, eax` padded to the same length. For
`NtQueryInformationProcess` the return value is NTSTATUS, not the answer, so the
slot becomes `xor eax,eax` + `and qword ptr [r8], 0`: success status *and* a
zeroed out buffer. Everything it will not guess at is listed in `plan.skipped`
with the reason, because a wrong patch that silently breaks a binary is worse
than a listed one that needs a human.

**Honeypots.** Before a run, a believable user profile is planted inside the
boundary: credentials, licence files, wallets, SSH and AWS keys, documents, 13
files on the Windows profile, each carrying a canary token. After the run,
`audit()` reports what was modified, deleted, or copied out, catching truncated
or re-encoded copies by token.

**Telemetry.** Opt-in, off by default. Aggregate run facts to your own endpoint:
backend, duration, exit or signal, crash flags, honeypot hit counts. Never the
binary, never a full path. Off means no network call at all.

Real command output for all of the above is in [sandbox/SMOKE.md](sandbox/SMOKE.md).

</details>

<br>

## Install

| Way | Command |
|---|---|
| **Bundle** (everything inside, no registry lookup) | `tar -xzf bobbypin-bundle-v1.0.0.tar.gz && cd bobbypin && ./install.sh` |
| **Git** | `git clone https://github.com/BobbyCodes-dev/bobbypin.git && cd bobbypin && ./install.sh` |
| **Windows** | `Expand-Archive bobbypin-bundle-v1.0.0.zip .; cd bobbypin; .\install.ps1` |

Linux, macOS and Windows are all supported and tested on all three in CI. The
KVM guest backend is Linux-only by nature; everywhere else the container backend
is used, and on a machine with neither, analysis, patching and source recovery
still install and work. Only running an untrusted target needs a backend.
| **Zip** | [bobbypin.bobbycodes.dev/dl/bcd](https://bobbypin.bobbycodes.dev/dl/bcd), then `./install.sh` |

`./install.sh` checks Python, installs `capstone` (into a repo-local `.venv` when
the system interpreter refuses pip), reports missing system packages with the
exact apt line, builds the container image, provisions the guest, installs
pinpoint, writes the env file every entry point reads, and finishes with a
containment probe.

| Flag | Effect |
|---|---|
| `--check` | report what is missing, change nothing |
| `--yes` | never prompt |
| `--no-vm` | container backend only, skip the guest build |
| `--no-pinpoint` | skip the analysis layer |
| `--with-frida` | also install frida-tools |
| `--install-system-packages` | run the apt commands for missing system deps |

Nothing is mandatory. No docker still gives you static analysis, no Node still
gives you the patch loop. Re-running is always safe.

<details>
<summary><b>Requirements, by hand</b></summary>

- Python 3.7+ (3.9+ recommended for large scans)
- `capstone` for verified candidates: `pip install capstone`
- `frida-tools`, optional, only for live monitors
- docker for the container backend, plus `qemu-system-x86`, `qemu-utils`,
  `genisoimage` for the VM backend
- `GHIDRA_INSTALL_DIR` and JDK 21 if you want native decompilation

</details>

<br>

## Learn on targets that ship with it

[`course/`](course/) contains three compiled crackmes with their C source and a
correct `*_patched.exe` to diff against:

| Target | Lesson | Failure behaviour |
|---|---|---|
| `course/module1/crackme.exe` | single guard, the basic loop | prints `License invalid.` |
| `course/module2/crackme2.exe` | chained guards, hash then account state | second lock prints `Account suspended.` |
| `course/module3/crackme3.exe` | silent guard, no failure string at all | exits quietly with code 3 |

```bash
python3 bobbypin_ai.py plan '{"path":"course/module1/crackme.exe"}'
```

Module 2 is where most real licences live: the first candidate you find is rarely
the only gate. Module 3 removes the training wheels.

<br>

## Docs

| File | What it is |
|---|---|
| [START-HERE.md](START-HERE.md) | the one-page tour |
| [recover.py](recover.py) | source recovery, all engines, with `--help` |
| [baml_to_xaml.py](baml_to_xaml.py) | compiled WPF pages back to editable XAML, via `ilspycmd` |
| [AGENTS.md](AGENTS.md) | complete operating manual for an AI agent: every command, argument, JSON shape and decision rule |
| [target/AUTHORIZATION.md](target/AUTHORIZATION.md) | standing scope, already granted |
| [pinpoint/skills/pinpoint/SKILL.md](pinpoint/skills/pinpoint/SKILL.md) | the deep-analysis skill |
| [sandbox/SMOKE.md](sandbox/SMOKE.md) | recorded evidence for the safety layer |

**bobbycodes.dev** : [site](https://bobbycodes.dev) · [GitHub](https://github.com/BobbyCodes-dev)

<br>

## Legal

For analysing software you own or are explicitly authorised to test. Every run
writes patches to a copy, never to the original, and never executes a target
outside the isolation boundary. Do not be the reason this needs a takedown
notice.
