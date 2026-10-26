/* ad_ntqip.exe - anti-analysis fixture for the NtQueryInformationProcess family.
 *
 * The check IsDebuggerPresent cannot stand in for: this one goes through ntdll directly
 * and asks about the *debug port*, which is a different piece of state than the
 * PEB.BeingDebugged byte. It is imported statically (not resolved with GetProcAddress) so
 * the call reaches ntdll through the import table, which is what makes it patchable at the
 * call site rather than guessed at.
 *
 *   no debug port  ->  prints "licensed OK", exit 0
 *   debug port     ->  prints "debugger detected", then bugchecks the machine
 *
 * ProcessDebugPort (7) is the class whose "clean" answer is 0, so it is the one the patcher
 * can force with a length-preserving patch. ProcessDebugFlags (0x1f) is deliberately NOT
 * the one used here: its clean answer is 1 (it reports the inverse of BeingDebugged), which
 * does not fit in the bytes of the call, so the patcher refuses it by design.
 *
 * Build: ./build.sh (needs mingw-w64). See README.md.
 */
#include <windows.h>
#include <stdio.h>

typedef LONG NTSTATUS;
#define STATUS_SUCCESS 0

__declspec(dllimport) NTSTATUS WINAPI NtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);
__declspec(dllimport) NTSTATUS WINAPI NtRaiseHardError(NTSTATUS, ULONG, PULONG_PTR, PVOID, ULONG, PULONG);
__declspec(dllimport) NTSTATUS WINAPI RtlSetProcessIsCritical(BOOLEAN, PBOOLEAN, BOOLEAN);

#define PROCESS_DEBUG_PORT 7
#define RESPONSE_SHUTDOWN_SYSTEM 6

static void deliberate_bsod(const char *reason)
{
    printf("refusing to run: %s\n", reason);
    fflush(stdout);

    ULONG response = 0;
    NtRaiseHardError(0xC0000005UL, 0, NULL, NULL, RESPONSE_SHUTDOWN_SYSTEM, &response);

    /* fallback: mark ourselves critical, then exit - also bugchecks the machine */
    BOOLEAN was = FALSE;
    RtlSetProcessIsCritical(TRUE, &was, FALSE);
    ExitProcess(0xDEADBEEF);
}

int main(void)
{
    printf("Acme Studio - license check\n");
    fflush(stdout);

    /* The real check: ask ntdll for this process's debug port. */
    ULONG_PTR port = 0;
    ULONG returned = 0;
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), PROCESS_DEBUG_PORT,
                                                &port, sizeof(port), &returned);
    printf("ProcessDebugPort query: status=0x%08lx port=%llu\n",
           (unsigned long)status, (unsigned long long)port);
    fflush(stdout);

    if (status == STATUS_SUCCESS && port != 0) {
        deliberate_bsod("debug port present");
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
