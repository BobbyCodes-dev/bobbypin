# bobbypin installer for Windows - the same single command the POSIX installer is.
#
#   .\install.ps1              # install everything, verify what this machine supports
#   .\install.ps1 --check      # report what is missing, change nothing
#   .\install.ps1 --yes        # unattended
#
# This is a thin wrapper: all logic lives in setup.py, so there is one install
# path to maintain and read, on every platform.

$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

# Prefer the py launcher (it knows about every installed CPython), fall back to
# python on PATH, then fail with something that says what to do.
$python = $null
foreach ($candidate in @("py", "python", "python3")) {
    $found = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($found) {
        if ($candidate -eq "py") {
            $probe = & py -3 -c "import sys; print(sys.version_info >= (3, 9))" 2>$null
            if ($probe -eq "True") { $python = @("py", "-3"); break }
        } else {
            $probe = & $candidate -c "import sys; print(sys.version_info >= (3, 9))" 2>$null
            if ($probe -eq "True") { $python = @($candidate); break }
        }
    }
}

if (-not $python) {
    Write-Host "install.ps1: Python 3.9+ is required." -ForegroundColor Red
    Write-Host "  install it with: winget install -e --id Python.Python.3.12"
    Write-Host "  then open a new terminal and run this again."
    exit 1
}

& $python[0] @($python[1..($python.Count - 1)] | Where-Object { $_ }) setup.py @args
exit $LASTEXITCODE
