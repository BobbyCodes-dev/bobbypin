/* ad_guard.exe - anti-analysis test fixture.
 *
 * Stands in for the commercial targets bobbypin exists for: it checks whether it is
 * being watched and, if it is, deliberately bugchecks the machine rather than the
 * process. The response is real, not simulated - NtRaiseHardError with ResponseOption
 * 6 (ShutdownSystem) is the documented way to force an immediate BSOD on Windows, and
 * the "mark yourself critical then exit" trick lands in the same place.
 *
 *   no debugger  ->  prints "licensed OK", exit 0
 *   debugger     ->  prints "debugger detected", then bugchecks the machine
 *
 * Build: ./build.sh (needs mingw-w64). See README.md.
 */
#include <windows.h>
#include <stdio.h>

typedef LONG NTSTATUS;
typedef NTSTATUS (WINAPI *NtRaiseHardError_t)(NTSTATUS, ULONG, PULONG_PTR, PVOID, ULONG, PULONG);
typedef NTSTATUS (WINAPI *RtlSetProcessIsCritical_t)(BOOLEAN, PBOOLEAN, BOOLEAN);

#define RESPONSE_SHUTDOWN_SYSTEM 6

static void deliberate_bsod(const char *reason)
{
    printf("refusing to run: %s\n", reason);
    fflush(stdout);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    NtRaiseHardError_t raise_hard_error =
        (NtRaiseHardError_t)GetProcAddress(ntdll, "NtRaiseHardError");
    ULONG response = 0;
    if (raise_hard_error) {
        /* ResponseOption 6 == ShutdownSystem: an immediate bugcheck */
        raise_hard_error(0xC0000005UL, 0, NULL, NULL, RESPONSE_SHUTDOWN_SYSTEM, &response);
    }

    /* fallback: mark ourselves critical, then exit - also bugchecks the machine */
    RtlSetProcessIsCritical_t set_critical =
        (RtlSetProcessIsCritical_t)GetProcAddress(ntdll, "RtlSetProcessIsCritical");
    if (set_critical) {
        BOOLEAN was = FALSE;
        set_critical(TRUE, &was, FALSE);
        ExitProcess(0xDEADBEEF);
    }
    ExitProcess(0xDEADBEEF);
}

int main(void)
{
    printf("Acme Studio - license check\n");
    fflush(stdout);

    if (IsDebuggerPresent()) {
        deliberate_bsod("debugger detected");
    }

    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    if (remote) {
        deliberate_bsod("remote debugger detected");
    }

    /* A plausible-looking licence check so the fixture behaves like the real thing. */
    char key[64] = {0};
    printf("Enter license key: ");
    fflush(stdout);
    if (!fgets(key, sizeof(key), stdin)) {
        key[0] = 0;
    }
    if (strstr(key, "ACME-") == NULL) {
        printf("License invalid. Please purchase a key.\n");
        return 1;
    }

    printf("licensed OK\n");
    return 0;
}
