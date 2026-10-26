# Smoke evidence

Real output from the machine, kept so nobody has to take any of this on trust.
Re-run with the commands shown.

## 1. Backend preflight (no docker install needed to read this)

```
$ python3 -m sandbox.capabilities
recommended: docker
docker: available  (docker 29.7.2)
kvm:    NOT available - "missing prerequisite(s): qemu-system-x86_64, qemu-img"
        install: sudo apt-get install -y qemu-system-x86 qemu-utils
```

`kvm_device: true, kvm_readable: true` - `/dev/kvm` is there, only QEMU is
missing. Until it is installed, KVM runs refuse with that hint instead of
executing anything on the host.

## 2. Containment probe - the boundary proves itself

```
$ python3 -c "from sandbox.runner import run_sandbox; ...  run_sandbox(workdir='/tmp/bp-probe')"
ok: True   backend: docker   duration: 0.727   crashed: False
containment: {
  "network": "none",          "network_verified": true,
  "rootfs": "read-only",      "rootfs_verified": true,
  "tmp_writable": true,       "uid": 1000,
  "cap_drop": "ALL",          "no_new_privileges": true,
  "pids_limit": 256,          "interfaces": "lo",
  "honeypots_mounted_read_only": true,
  "writable_paths": ["/tmp (tmpfs, 64m)", "/out (workdir bind)", "/scratch (workdir bind, wine prefix)"]
}
```

These are observed values from inside the container, not the flags we intended
to pass. `interfaces: "lo"` is loopback only; the egress test could not reach
1.1.1.1:53.

## 3. A target that steals the decoy licence, then segfaults

```
$ python3 -c "run_sandbox(argv=['sh','-c','cat /honeypots/.../license.key > /out/stolen.txt; ...; kill -SEGV \$\$'])"
exit: 139   signal: 11   crashed: True   timed_out: False
stderr: sh: can't create /rootfs_write_test: Read-only file system
        sh: can't create /honeypots/.../tamper.txt: Read-only file system
artifacts: ['/tmp/bp-run-payload/out/stolen.txt']
honeypots: {'total': 13, 'modified': 0, 'deleted': 0, 'leaked': 1, 'clean': False}
  HIT token_leaked license Users/analyst/Desktop/license.key
      -> /tmp/bp-run-payload/out/stolen.txt  severity: high
host /rootfs_write_test exists: False
```

Four things at once: the target could not write to `/`, could not tamper with the
bait, could not delete the evidence, and the run kept going after it segfaulted -
the host was never in the blast radius.

## 4. A real Windows PE executed inside the boundary

```
$ python3 -c "run_sandbox(target='course/module1/crackme.exe', argv=['wine','/in/crackme.exe'])"
exit: 1   signal: None   abnormal_exit: False   duration: 7.4s
stdout: BobbinSoft Pro - license check | Enter license key: License invalid. Please purchase a key.
stderr: wine: created the configuration directory '/scratch/.wine'
```

The PE ran, printed its licence check, and exited 1 - inside a container with no
network, a read-only rootfs, no capabilities and a throwaway filesystem. `exit 1`
is recorded as `crashed: true` (the contract treats a nonzero exit as a failed
run) but `abnormal_exit: false`, because nothing killed it.

## 5. A real Windows PE, executed inside the VM

```
$ python3 -c "run_sandbox(target='course/module1/crackme.exe', backend='kvm',
    argv=['/bin/sh','-c','sha256sum /in/crackme.exe; file /in/crackme.exe; wine /in/crackme.exe; \
      cp /root/.wine/drive_c/Users/analyst/Desktop/license.key /out/grabbed.txt'])"
wall: 35.2s | exit: 0 | target delivered: True | target_sha256: 6f2822eb53854c5b...
-- delivered target (sha256 computed INSIDE the guest) --
6f2822eb53854c5ba6d9572025582ba09aac115a43e50de2e6491a85f6472fce  /in/crackme.exe
/in/crackme.exe: PE32+ executable (console) x86-64, for MS Windows, 18 sections
-- executed under wine, inside the boundary --
BobbinSoft Pro - license check
Enter license key: License invalid. Please purchase a key.
summary: {'total': 13, 'modified': 0, 'deleted': 0, 'leaked': 1, 'clean': False}
  HIT token_leaked license -> /tmp/bp-vm-pe/out/grabbed.txt  high
```

The target travelled host -> guest over the guest agent; the guest's own sha256 matches
the host's record byte for byte. It then ran under wine inside a VM with no network, and
the decoy licence it stole was caught and recovered as a real file on the host. The disk
it did all of that on no longer exists.

Note: the practice target is x86-64, so `wine64` was enough. `wine32` is installed anyway
because most commercial licence-guarded Windows apps are still 32-bit - it needs
`dpkg --add-architecture i386` first, which is why that step is in `runcmd` rather than
the `packages:` list (see `sandbox/kvm/cloud-init-user-data.yaml`).

## 6. A real VM: the guest kernel dies, the host does not care

```
$ python3 -c "run_sandbox(backend='kvm', argv=['/bin/sh','-c',
    'echo c > /proc/sysrq-trigger'], timeout_s=25)"
wall: 86.4s | exit: None | timed_out: True | crashed: True | bsod_suspected: True
warnings:
  - guest execution: guest-exec pid 414 still running after 25s
  - guest did not power off within 20s; the vm was terminated (... nothing is lost)
  - guest-crash signature: linux_kernel_panic :: Kernel panic - not syncing: sysrq triggered crash
  - ephemeral disk overlay discarded

$ sha256sum base.qcow2   # before and after, identical
$ uptime                 # host: up 47 days
```

The target took the guest kernel down. The host did not notice, the base image was
never written, and the run reads as a crash rather than a hang.

## 7. A normal VM run is ~8-14 s, and nothing survives it

```
$ python3 -c "run_sandbox(backend='kvm', honeypots=True, argv=[...])"
wall: 14.2s | exit: 0 | bait files staged: 17
stdout: BAIT_OK | done
summary: {'total': 13, 'modified': 1, 'deleted': 1, 'leaked': 1, 'clean': False}
         observed_in: guest
  HIT modified     license    Users/analyst/Desktop/license.key            medium
  HIT deleted      wallet     Users/analyst/wallet.dat                     high
  HIT token_leaked credential Users/analyst/Documents/passwords.txt
      -> /tmp/bp-vm-bait2/out/stolen.txt                                   high
leaked content: "# personal password notes (keep offline)"
```

A payload that edits the decoy licence, deletes the decoy wallet and copies the
decoy password file out is caught three ways, and the copy is recovered as a real
file on the host. `ls /tmp/bp-vm-*/disk.qcow2` afterwards: nothing - the disk it
did all that on no longer exists.

## 8. Bugs the live runs found (each would have shipped as false confidence)

- **No 9p in the cloud kernel.** The first design passed files over `-virtfs`
  shares. `mount -t 9p` in the guest fails with `unknown filesystem type '9p'`
  because the Debian *cloud* kernel ships no 9p support at all - and the
  "shares mounted" check echoed a success string even when every mount had failed,
  so it reported `shares_mounted: true` while the bait was landing nowhere. The
  channel now rides the guest agent (`guest-file-read`/`guest-file-write`), which
  needs no kernel support and adds no host share.
- **`system_powerdown` is not a guest-agent command.** It is a QMP monitor command;
  qemu-ga answers `CommandNotFound` and the VM keeps running until the grace period
  expires. That cost 45 s per run. `guest-shutdown` is the agent's own command.
- **The transport tarball sat inside the scanned workdir**, so the leak scan found
  every decoy token inside our own bait tarball and reported 13 bogus exfiltration
  hits. It now lives in a temp dir outside the workdir.
- **A "did the shares mount" check that echoed a success string.** It reported
  `shares_mounted: true` while every mount had failed. Checks that can only report
  success are worse than no check; it now verifies a planted sentinel file.

## 9. Debug protection: detected, classified, and made to fire on purpose

A fixture stands in for a commercial anti-tamper target: it checks for a debugger and, if
it finds one, deliberately bugchecks the machine (`NtRaiseHardError` with ResponseOption 6
= ShutdownSystem). Source and build script in `fixtures/anti_analysis/`.

**Static — what it says about itself:**

```
$ python3 -m antianalysis fixtures/anti_analysis/ad_guard.exe
debug protection: DETECTED (high confidence, 2 indicators)
  - is_debugger_present [import] - reads PEB.BeingDebugged - the single most common check
  - check_remote_debugger [import] - DebugPort check on any process handle
corroborating (noisy) signals: unhandled_exception_filter, closehandle_trick, self_map,
  self_modify, sleep_timing, self_path_lookup
on trigger: DELIBERATE BSOD (BUGCHECK) [critical] - debug protection is present AND a
  bugcheck path is present: if the debugger/integrity check fires, the machine goes down
  rather than the process. NtRaiseHardError with ResponseOption 6 (ShutdownSystem) forces
  an immediate bugcheck...

$ python3 -m antianalysis course/module1/crackme.exe
debug protection: none detected
noisy-only signals ignored: unhandled_exception_filter, closehandle_trick, self_map,
  self_modify, integrity_strings, sleep_timing
```

The bugcheck call is resolved at runtime via `GetProcAddress`, so it never appears in the
import table. Matching only imports would have missed it - the detector falls back to the
API name as a string, and says so in the evidence.

**Dynamic — what it actually does.** `trip_debug` simulates a debugger (sets
`PEB->BeingDebugged` in a suspended child, which is what `IsDebuggerPresent` reads) and
runs the target:

```
$ python3 bobbypin_ai.py sandbox_run '{"target":".../ad_guard.exe","trip_debug":true}'
stdout: debugger state simulated for pid 308
        Acme Studio - license check
        refusing to run: debugger detected
        target exited with 3735928559
observed: protection_tripped - the protection TRIPPED - the target saw the debugger state
          and refused to run (exit 3735928559). Note: on Windows the follow-on call in this
          path is a machine-wide bugcheck; wine does not honour it, so here the run stops at
          the refusal. The boundary contained it either way.
static predicted: deliberate_bsod [critical]
```

Run *without* `trip_debug`, the same target prints `License invalid` and exits 1 - the
protection stays quiet, which is what keeps the finding meaningful.

**Honest caveat.** wine does not honour the shutdown call, so the bugcheck itself is not
reproducible under wine; the run stops at the refusal. The classification still says
bugcheck, the two are reported side by side, and the boundary's ability to contain a guest
kernel death is proven separately in section 6.

## 10. Native Windows: the protection trips and the machine goes down

The fixture from section 9, run in the **Windows 11 LTSC guest** — no wine, the real thing.
`ad_trip.exe` sets `PEB->BeingDebugged`, `ad_guard.exe` sees it and takes the machine down:

```
$ python3 bobbypin_ai.py sandbox_run '{"target":".../ad_guard.exe","trip_debug":true,"backend":"kvm"}'
wall: 78.1s
crashed: True | bsod_suspected: True | abnormal_exit: True
boot_cycles: 2 | guest_restarted: True
BUGCHECK: 0xef CRITICAL_PROCESS_DIED
dump file: ~/.bobbypin/runs/<run>/crash/101726-2859-01.dmp
OBSERVED: machine_taken_down
  the protection TRIPPED and the response was a bugcheck - the guest crashed and restarted
  itself mid-run; the host never noticed. Bugcheck 0xef (CRITICAL_PROCESS_DIED) read from
  its crash dump.
VERDICT:
  - the target took the guest down with bugcheck 0xef (CRITICAL_PROCESS_DIED) - contained;
    on a workstation that is a dead machine, here it is one discarded VM
  - debug protection: DETECTED (high confidence, 2 indicators)
  - observed: the protection TRIPPED and the response was a bugcheck ...
```

The same target run **without** `trip_debug`, in the same guest, executes natively and
reports honestly:

```
exit: 1 | crashed: True | bsod: False | boot_cycles: None
stdout: Acme Studio - license check
        Enter license key: License invalid. Please purchase a key.
observed: exited_nonzero
```

Same binary, same guest, two very different outcomes depending on whether anything is
watching — which is the whole point of the feature.

**How the evidence is obtained, since it is not obvious.** Kernel debug over a serial port
is the natural way to catch a bugcheck and it does not work here: with no debugger attached,
Windows waits for one forever, so the guest goes silent and writes nothing reachable. The
guest is configured instead to write a small memory dump and restart. The restart is read
from the boot record (`BsdDxe: starting Boot` twice in one run), which works even though the
guest agent is exactly what dies; the bugcheck code is read out of the dump header
(`PAGEDU64`, code at 0x38) after the agent comes back. Both paths are exercised by the tests.

## 11. Debug protection: detected, then removed, and proven removed

The loop this section is about: find the check, patch the check, then show the difference in
the guest. The fixture is `fixtures/anti_analysis/ad_guard.exe`, which prints
`Acme Studio - license check`, checks for a debugger, and **bugchecks the machine** if it
finds one.

```
$ python3 bobbypin_ai.py antidebug_patch '{"path":"fixtures/anti_analysis/ad_guard.exe",
                                           "out":"/tmp/ad_guard_safe.exe","verify":true}'
```

Detection and patch plan:

```
detected: True | confidence: high | response: deliberate BSOD (bugcheck)
status: patched | applied: 2

  0x00000a5d  isdebuggerpresent            ff1515bc0000 -> 31c090909090
  0x00000a81  checkremotedebuggerpresent   ff1599bb0000 -> 31c090909090

not auto-patched (6):
  [D] unhandled_exception_filter   exception-based: the filter firing IS the flow...
  [E] closehandle_trick            the tell is GetLastError (0xDEADC0DE)...
  [D] self_map / self_modify       integrity: suppressing the call changes nothing
  [D] sleep_timing                 needs the sleep-and-compare rewritten
  [D] self_path_lookup             noisy on its own, not a debugger check

hashes: before abf3a3c8...482d  ->  after 4277d38c...085b
diff:   [{"offset": 2653, "before": "ff1515bc0000", "after": "31c090909090"},
         {"offset": 2689, "before": "ff1599bb0000", "after": "31c090909090"}]
size:   41472 bytes before and after (length-preserving: nothing moved)
```

Both files then ran in the **same Windows 11 guest**, with the **same simulated debugger
state** (`trip_debug`), back to back:

```
BEFORE (original): crashed=True  bugcheck_code=239 (0xef CRITICAL_PROCESS_DIED)
                   guest_restarted=True   exit=None
  observed: the protection TRIPPED and the response was a bugcheck - the guest crashed and
            restarted itself mid-run; the host never noticed.

AFTER  (patched):  crashed=False bugcheck_code=None  guest_restarted=False  exit=0
  stdout:  debugger state simulated for pid 6912
           Acme Studio - license check
           Enter license key: License invalid. Please purchase a key.
           target exited with 1
  observed: the debugger state was simulated but the target showed no reaction to it.

VERDICT: neutralised - the protection fired before the patch and does not fire after it:
         same target, same guest, same simulated debugger state
```

The unpatched side of that pair is not decoration. `still_fires` and `nothing_to_prove` are
real outcomes: a patch that was merely applied is not evidence, and if the protection still
fires after it, the report says the patch is insufficient rather than reporting success.

**What it would not touch, and why that matters.** The six listed checks are reported, not
patched. The dangerous one is `NtQueryInformationProcess`: it returns NTSTATUS, where **0
means the query succeeded**, and the verdict is in the out buffer — so `xor eax,eax` there
would tell the caller "the query worked" and it would then read whatever the buffer already
held. A direct PEB read (`mov eax, fs:[0x30]`) is the other trap: zeroing that base pointer
turns the next `[eax+2]` (BeingDebugged) into an access violation - a false positive traded
for a crash. Both are listed for a human instead of guessed at, and the classes are named
(`A` forced here, `B` runtime-resolved, `C` PEB/integrity data read, `D` timing/anti-VM,
`E` non-BOOLEAN verdict API).

**Two fallbacks, cross-checked.** Site detection uses capstone when it is installed and a
structural `FF 15` scan filtered by the import table's address span when it is not; the two
produce identical results on this fixture (28 call sites, the same two detection calls at the
same offsets), which is the only reason the fallback is acceptable.

**The reports say so, so an agent does not have to know.** A command nobody reaches for is a
command that does not exist, so every entry point an agent lands on carries the instruction.
`plan` on the fixture now leads with:

```
suggested_next:
  1. DO NOT run this target outside the boundary: the response is "deliberate BSOD
     (bugcheck)". Use sandbox_run {"trip_debug": true} to make it fire in the VM instead.
  2. debug protection detected (high confidence, 2 indicator(s)): run antidebug_patch
     {"path": ..., "out": ..., "verify": true} to force the patchable checks
     (IsDebuggerPresent / CheckRemoteDebuggerPresent become xor eax,eax) and prove it in the
     boundary. Read data.plan.skipped first: every check it will NOT touch is listed there
     with its class and reason.
  3. for each FAIL candidate near auth strings: disasm its jcc_off +/- 40 insns
  ...
```

Both new steps come **ahead of** the licence-guard steps on purpose: patching a guard is
wasted work on a binary that bugchecks the machine when it sees the debugger the patch run
implies. `anti_analysis` and `sandbox_run` carry the same hint. A target with no protection
gets nothing added — a warning that fires on everything is a warning an agent learns to skip.

## 12. NtQueryInformationProcess: the class where the obvious patch is the wrong one

`IsDebuggerPresent` returns BOOL, so forcing it to 0 is the whole job. `NtQueryInformationProcess`
does not work that way: it returns **NTSTATUS** (0 means the *query succeeded*) and puts the
verdict in the out buffer. Zeroing EAX there says "the query worked" and the caller then reads
whatever the buffer already held — a patch that looks applied and changes nothing, or worse,
one that leaves the answer pointing at stale memory.

The `InfoClass` decides whether anything can be forced. `ProcessDebugPort` (7) and
`ProcessDebugObjectHandle` (0x1e) answer 0 for "nothing found", so for those the six-byte call
slot becomes `xor eax,eax` + `and qword ptr [r8], 0` — a success status *and* a zeroed out
buffer (`r8` is the out-pointer by the x64 calling convention).

**Reading the class is the precondition, and it is done by decoding, not guessing.** x86 is
variable-length, so the bytes in front of the call cannot be walked backwards, and trying
arbitrary start offsets does not work either: the padding before the function decodes into
plausible one-byte instructions, and several wrong alignments happen to land exactly on the
call. The section is decoded forward from its start instead, and the call has to be an
instruction in that stream. On the fixture that yields:

```
0x1400015d5  4c8d842488000000   lea r8, [rsp + 0x88]     ; out buffer
0x1400015dd  ba07000000         mov edx, 7               ; InfoClass = ProcessDebugPort
0x1400015e2  ff1548bc0000       call [rip + 0xbc48]      <== the check
```

```
$ .venv/bin/python antidebug_patch.py fixtures/anti_analysis/ad_ntqip.exe -o /tmp/patched.exe
debug protection: detected (confidence medium)
response on trigger: deliberate BSOD (bugcheck)

patchable (1):
  0x000009e2  ntqueryinformationprocess    ff1548bc0000 -> 31c049832000

not auto-patched (5):
  [D] unhandled_exception_filter   exception-based: the filter firing IS the flow...
  ...
wrote /tmp/patched.exe (1 patch(es) applied)
```

Both halves in the Windows guest, `trip_debug` on, back to back:

```
BEFORE (unpatched): crashed=True  bsod_suspected=True  guest_restarted=True
                    bugcheck 0xef CRITICAL_PROCESS_DIED
AFTER  (patched):   crashed=False bsod_suspected=False exit=0
  stdout:  debugger state applied for pid 4684 (attached as a debugger)
           Acme Studio - license check
           ProcessDebugPort query: status=0x00000000 port=0
           Enter license key: License invalid. Please purchase a key.
```

That stdout line is the proof in one place: the debugger state **was** applied — really applied,
the process had a debug port — and the patched call still answers `STATUS_SUCCESS` with
`port=0`. Same binary, same guest, same trip; only the 6 bytes changed. File length identical
(41472 bytes).

### The trip helper had to get stronger to prove this at all

`ad_trip.exe` v1 wrote `PEB->BeingDebugged` from outside the process. That byte is exactly what
`IsDebuggerPresent` reads, so `ad_guard.exe` fired — but `ProcessDebugPort` reads
**EPROCESS** state that a PEB write cannot reach, so a `ProcessDebugPort` fixture answered
`port=0` under the trip and could not be made to fire. Measured, not assumed:

```
BEFORE the trip upgrade:  ProcessDebugPort query: status=0x00000000 port=0
                          → the target showed no reaction to it
```

v2 attaches as a **real debugger** (`DebugActiveProcess`) and pumps the debug events, passing
every exception back to the target. The kernel then sets both `DebugPort` and `BeingDebugged`,
so the whole family fires — `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` (never exercised
before), `ProcessDebugPort`, `ProcessDebugFlags`. If the attach is refused it falls back to the
PEB byte and says so, so a run is never described as more than it was.

**What is still refused, and why it stays refused.** `ProcessDebugFlags` (0x1f) is a debug check
whose answer is the *inverse* of `BeingDebugged`: its clean value is 1, and 1 plus a success
status does not fit in six bytes without relocating code. Any other InfoClass is refused because
its out buffer is a PEB pointer, a size or a struct the caller goes on to use — zeroing one of
those turns a patch into a bug. `plan.skipped` lists each site with the class it found and the
reason, so a caller can see exactly what was and was not done.

## 13. Test suite

```
$ .venv/bin/python -m unittest discover -s sandbox/tests -t . -v
Ran 141 tests in 647.018s

OK (skipped=1)
```

141 tests. Eight boot the **real Windows guest** and assert the guarantees rather than
describing them: the guest boots UEFI on virtio-scsi over the raw base, a PE executes natively
and its output comes back, the base image hash is unchanged and the per-run overlay is gone,
no state carries between runs, a target's debug protection **stays quiet when nothing is
watching**, **fires when something is** (bugcheck `0xef` read from its dump), and a **patched**
target no longer fires — asserted for both the BOOLEAN API fixture and the
`NtQueryInformationProcess` one, each with its own before-and-after pair. A protection that
never fires would fail these, so "it didn't fire" can never pass for a working patch.

The single skip is expected: `KVMGuestRunTest.setUpClass` defers to `KVMWindowsGuestTest`
because `kvm.base_image` is the Windows guest.

**Two interpreters, on purpose.** The `NtQueryInformationProcess` tests need the instruction
decode to read the `InfoClass`, so they need capstone. With the repo venv
(`uv venv .venv && uv pip install --python .venv/bin/python capstone`) everything runs — the
line above. Under the system interpreter, which has no capstone, those tests skip themselves
and the patcher reports the class as unread rather than guessing:

```
$ python3 -m unittest sandbox.tests.test_antidebug_patch.NtQipPlanTest \
    sandbox.tests.test_antidebug_patch.NtQipPatchRunTest
Ran 9 tests in 0.006s

OK (skipped=3)
```

Read the skip count, never just "OK".

**The suite resolves `~/.bobbypin/sandbox.json` from the real account's home directory**, not
from `$HOME`. A runner whose `$HOME` is something else (an agent harness sandbox, a service
unit) would otherwise make every live-VM test **silently skip** while the suite still prints
"OK" — the exact failure mode that looks like success. That cost a full run before
`_configured_base_image()` (which resolves the config the way the tool does, then falls back to
the passwd entry for the uid) was added.

The anti-analysis tests include a false-positive guard: three ordinary practice binaries must
come back `none detected`, since the CRT imports the same primitives a protection routine
does. The container tests skip when no daemon is present, and the KVM tests skip when
`/dev/kvm` or QEMU is absent (they assert the *unavailable* path otherwise). The QEMU command
line is unit-tested directly, which is how most of the VM guarantees are verified without
booting anything.
