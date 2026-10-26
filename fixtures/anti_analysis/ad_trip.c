/* ad_trip.exe - make the target's debug protection see a debugger.
 *
 * v2 attaches as a REAL debugger (DebugActiveProcess). The kernel then sets the target's
 * DebugPort and PEB->BeingDebugged itself, which is what makes the whole family of presence
 * checks fire:
 *
 *   IsDebuggerPresent                       reads PEB.BeingDebugged      -> fires
 *   CheckRemoteDebuggerPresent               reads EPROCESS.DebugPort     -> fires
 *   NtQueryInformationProcess(ProcessDebugPort, 7)                       -> fires
 *   NtQueryInformationProcess(ProcessDebugFlags, 0x1f)                   -> fires (inverted)
 *
 * v1 only wrote the PEB byte from outside the process. That is enough for IsDebuggerPresent
 * (which reads that exact byte) but it cannot reach EPROCESS state, so every DebugPort-based
 * check still answered "no debugger" - a fixture built on ProcessDebugPort could not be made
 * to fire at all. Attaching fixes the class, not just the one check.
 *
 * The debug loop passes every exception back to the target (DBG_EXCEPTION_NOT_HANDLED) except
 * the debugger's own initial breakpoint: the point is to look debugged, not to interfere with
 * what the target does about it. If the attach is refused it falls back to writing the PEB
 * byte and says which one it did, so a run is never described as more than it was.
 *
 *   ad_trip.exe <target.exe> [args...]
 *
 * Build: ./build.sh. See README.md.
 */
#include <windows.h>
#include <stdio.h>

typedef LONG NTSTATUS;
typedef struct {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
typedef NTSTATUS (WINAPI *NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

/* Printed once the state is in place. bobbypin_ai._observed_outcome looks for this marker to
 * tell "the target saw the debugger and did nothing" from "the trip never applied"; keep it. */
#define TRIP_MARKER "debugger state applied"

static void pump_debug_events(PROCESS_INFORMATION *pi)
{
    DEBUG_EVENT ev;
    while (WaitForDebugEvent(&ev, INFINITE)) {
        DWORD cont = DBG_CONTINUE;
        BOOL done = FALSE;

        switch (ev.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:
            /* Every exception belongs to the target - including the ones its own anti-debug
             * code raises on purpose. The initial breakpoint is the debugger's, not the
             * app's, and continuing it past the app is the only correct answer. */
            if (ev.u.Exception.ExceptionRecord.ExceptionCode == (DWORD)EXCEPTION_BREAKPOINT) {
                cont = DBG_CONTINUE;
            } else {
                cont = DBG_EXCEPTION_NOT_HANDLED;
            }
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            done = TRUE;
            break;
        default:
            break;
        }

        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
        if (done) {
            break;
        }
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: ad_trip.exe <target.exe>\n");
        return 2;
    }

    char cmdline[2048];
    int n = snprintf(cmdline, sizeof(cmdline), "\"%s\"", argv[1]);
    for (int i = 2; i < argc; i++) {
        n += snprintf(cmdline + n, sizeof(cmdline) - n, " %s", argv[i]);
        if (n >= (int)sizeof(cmdline)) break;
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed (%lu)\n", (unsigned long)GetLastError());
        return 3;
    }

    /* Attach for real. The kernel sets DebugPort and BeingDebugged for us. */
    if (DebugActiveProcess(pi.dwProcessId)) {
        printf("%s for pid %lu (attached as a debugger)\n",
               TRIP_MARKER, (unsigned long)pi.dwProcessId);
        fflush(stdout);

        ResumeThread(pi.hThread);
        pump_debug_events(&pi);

        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD code = 0;
        GetExitCodeProcess(pi.hProcess, &code);
        printf("target exited with %lu\n", (unsigned long)code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 0;
    }

    /* Refused (SeDebugPrivilege, or an existing debugger). Fall back to the PEB byte, which
     * still covers IsDebuggerPresent, and say that is what happened. */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    NtQueryInformationProcess_t qip =
        (NtQueryInformationProcess_t)GetProcAddress(ntdll, "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION pbi;
    ULONG len = 0;
    BOOL wrote = FALSE;
    if (qip && qip(pi.hProcess, 0, &pbi, sizeof(pbi), &len) == 0 && pbi.PebBaseAddress) {
        BYTE being_debugged = 1;
        SIZE_T written = 0;
        if (WriteProcessMemory(pi.hProcess, (BYTE *)pbi.PebBaseAddress + 2,
                               &being_debugged, 1, &written) && written == 1) {
            wrote = TRUE;
        }
    }

    if (wrote) {
        printf("%s for pid %lu (PEB byte only - DebugActiveProcess failed with %lu)\n",
               TRIP_MARKER, (unsigned long)pi.dwProcessId,
               (unsigned long)GetLastError());
    } else {
        printf("could not apply the debugger state (DebugActiveProcess failed with %lu)\n",
               (unsigned long)GetLastError());
    }
    fflush(stdout);

    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    printf("target exited with %lu\n", (unsigned long)code);
    return 0;
}
