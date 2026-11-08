#!/usr/bin/env bash
# pinpoint installer - thin wrapper over npm so there is exactly one install path.
set -euo pipefail

PACKAGE="pinpoint-agents"
VERSION="latest"

usage() {
  cat <<'USAGE'
Usage: install.sh [--version VERSION]

Installs the pinpoint CLI globally with npm.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

fail() { printf 'install.sh: %s\n' "$1" >&2; exit 1; }

command -v node >/dev/null 2>&1 || fail "Node.js is required. Install it from https://nodejs.org and rerun."
command -v npm  >/dev/null 2>&1 || fail "npm is required. It ships with Node.js."

node_major="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$node_major" -lt 22 ]; then
  fail "Node.js 22 or newer is required; found $(node -v)."
fi

spec="$PACKAGE"
[ "$VERSION" = "latest" ] || spec="$PACKAGE@$VERSION"

printf 'Installing %s...\n' "$spec" >&2
npm install -g --no-audit --no-fund "$spec" || fail "npm install failed."

if command -v pinpoint >/dev/null 2>&1; then
  printf 'Installed: pinpoint %s\n' "$(pinpoint --version 2>/dev/null || echo '?')" >&2
else
  printf 'Installed, but the pinpoint binary is not on PATH. Add your npm global bin directory to PATH.\n' >&2
fi
