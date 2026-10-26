# Anti-analysis fixtures

Three small Windows programs used to test `antianalysis.py`, `antidebug_patch.py` and the
sandbox, end to end. They exist because the feature's whole claim - "this target has debug
protection, and when it trips it takes the machine down rather than the process" - needs to be
provable, not asserted.

| file | what it is |
|---|---|
| `ad_guard.exe` | stands in for a commercial target: `IsDebuggerPresent` + `CheckRemoteDebuggerPresent`, and if it sees either, deliberately bugchecks the machine |
| `ad_ntqip.exe` | the same idea through `ntdll` directly: `NtQueryInformationProcess(ProcessDebugPort)`, statically imported so the call reaches ntdll through the import table |
| `ad_trip.exe` | stands in for "a debugger is attached": launches a target suspended, attaches as a **real** debugger, pumps its debug events |
| `build.sh` | builds all three with mingw-w64 |
| `ntdll.def` | import list for `dlltool` - mingw's `libntdll.a` does not export the ntdll functions for import |

## Building

```bash
sudo apt-get install -y mingw-w64
./build.sh
```

## What `ad_guard.exe` does

```
no debugger        Acme Studio - license check
                   Enter license key: License invalid. Please purchase a key.   (exit 1)

debugger present   Acme Studio - license check
                   refusing to run: debugger detected                          (bugcheck)
```

The bugcheck is the real thing, not a simulation: `NtRaiseHardError` with `ResponseOption`
6 (`ShutdownSystem`) is the documented way to force an immediate BSOD on Windows, with
`RtlSetProcessIsCritical(TRUE)` + exit as the fallback. That is what commercial
anti-tamper code does when it decides you are debugging it - and it is why you do not run
untested targets on the machine you work on.

## What `ad_ntqip.exe` does

```
ProcessDebugPort query: status=0x00000000 port=0      -> no debugger, carries on
ProcessDebugPort query: status=0x00000000 port=<n>    -> refusing to run: debug port present
```

It calls `NtQueryInformationProcess(GetCurrentProcess(), 7, &port, sizeof(port), &returned)`
and treats a non-zero `port` as detection. Two details are deliberate:

- **statically imported** (`__declspec(dllimport)` + a dlltool-made import library), because an
  import-table entry is what makes the call reachable as `call [rip+disp]` - i.e. patchable at
  the call site. Resolved through `GetProcAddress` it would be an indirect call and
  `antidebug_patch` would (correctly) refuse to guess which one is the check.
- **`ProcessDebugPort` (7), not `ProcessDebugFlags` (0x1f)**, because 7 is the class whose
  clean answer is 0 and so can be forced length-preservingly. 0x1f reports the *inverse* of
  `BeingDebugged`, so its clean answer is 1, which does not fit in the bytes of the call -
  `antidebug_patch` refuses that class rather than relocating code.

## What `ad_trip.exe` does

```c
CreateProcess(..., CREATE_SUSPENDED, ...)
DebugActiveProcess(pid)                    // a real debugger: kernel sets DebugPort + BeingDebugged
ResumeThread(pid)
WaitForDebugEvent / ContinueDebugEvent     // pass every exception back to the target
```

Attaching is what makes the **whole family** of presence checks fire, not just one:

| check | v1 (PEB byte only) | v2 (real attach) |
|---|---|---|
| `IsDebuggerPresent` | fires | fires |
| `CheckRemoteDebuggerPresent` | **no** - reads `EPROCESS.DebugPort`, which a PEB write cannot reach | fires |
| `NtQueryInformationProcess(ProcessDebugPort, 7)` | **no** - same reason | fires |
| `NtQueryInformationProcess(ProcessDebugFlags, 0x1f)` | fires | fires |

That difference is not academic: a `ProcessDebugPort` fixture could not be made to fire at all
under v1, which meant the class-A2 patch could not be verified. If the attach is refused
(it needs `SeDebugPrivilege`, fine for a child of your own) the helper falls back to the PEB
byte and says so in its output - `debugger state applied for pid N (PEB byte only ...)` - so a
run is never described as more than it was.

The event loop passes exceptions to the target (`DBG_EXCEPTION_NOT_HANDLED`) except the
debugger's own initial breakpoint: the point is to look debugged, not to change what the target
does about it.

## Caveat worth knowing

Under **wine** the protection fires (the target prints `refusing to run: debugger
detected`) but wine does not honour the shutdown call, so the run stops at the refusal
instead of bugchecking. The static scan still classifies the response as a bugcheck, and
the sandbox reports the two side by side rather than pretending. On a real Windows guest
the same code bugchecks, and `sandbox.bsod` picks it out of the minidump.

The boundary itself is proven separately: a payload that panics the guest kernel is
contained and reported (`sandbox/SMOKE.md`, section 6).
