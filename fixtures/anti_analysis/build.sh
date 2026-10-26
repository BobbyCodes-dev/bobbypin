#!/bin/bash
# Build the anti-analysis fixtures (needs mingw-w64).
#
#   ad_guard.exe  - IsDebuggerPresent / CheckRemoteDebuggerPresent, bugchecks when tripped
#   ad_ntqip.exe  - NtQueryInformationProcess(ProcessDebugPort), bugchecks when tripped
#   ad_trip.exe   - applies a debugger state to a target so the protections fire on purpose
#
# ad_ntqip links against ntdll directly (that is the point - a static import is what makes the
# call reachable through the import table, and therefore patchable). mingw's own libntdll.a
# does not export NtQueryInformationProcess for import, so a small import library is generated
# with dlltool from ntdll.def. Without the import table entry, the call would have to go
# through GetProcAddress and this fixture would not exercise the code path the patcher handles.
set -euo pipefail
cd "$(dirname "$0")"
CC="${CC:-x86_64-w64-mingw32-gcc}"
command -v "$CC" >/dev/null || { echo "$CC not found - apt-get install -y mingw-w64"; exit 1; }

"$CC" -O1 -s -o ad_guard.exe ad_guard.c
"$CC" -O1 -s -o ad_trip.exe ad_trip.c

if command -v x86_64-w64-mingw32-dlltool >/dev/null; then
    _imp="$(mktemp -d)"
    x86_64-w64-mingw32-dlltool -d ntdll.def -l "$_imp/libntdll_imp.a" -k
    "$CC" -O1 -s -o ad_ntqip.exe ad_ntqip.c "$_imp/libntdll_imp.a"
    rm -rf "$_imp"
else
    echo "x86_64-w64-mingw32-dlltool not found - skipping ad_ntqip.exe"
fi

ls -l ./*.exe
