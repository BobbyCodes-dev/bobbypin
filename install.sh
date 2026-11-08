#!/usr/bin/env bash
# bobbypin installer - one command, then you are done.
#
#   ./install.sh              # install everything, verify the boundary
#   ./install.sh --check      # report what is missing, change nothing
#   ./install.sh --yes        # unattended
#
# This is a thin wrapper: all logic lives in setup.py so there is exactly one
# install path to maintain and to read.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

if ! command -v python3 >/dev/null 2>&1; then
  echo "install.sh: python3 is required" >&2
  exit 1
fi

exec python3 setup.py "$@"
