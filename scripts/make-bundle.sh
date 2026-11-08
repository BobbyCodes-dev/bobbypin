#!/usr/bin/env bash
# Build the downloadable bundle: everything needed for an offline install, in one
# tarball. The result goes to dist/ and is what gets attached to a GitHub release.
#
#   scripts/make-bundle.sh              # -> dist/bobbypin-bundle-<date>.tar.gz
#   scripts/make-bundle.sh v1.0.0       # -> dist/bobbypin-bundle-v1.0.0.tar.gz
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

label="${1:-$(date +%Y%m%d)}"
out="dist/bobbypin-bundle-${label}.tar.gz"
vendor="vendor/bobbypin-pinpoint-1.0.0.tgz"

if [ ! -f "$vendor" ]; then
  echo "make-bundle: $vendor is missing." >&2
  echo "  fetch it from the bobbypin-pinpoint-v1.0.0 release and drop it in vendor/." >&2
  exit 1
fi
if [ ! -f setup.py ] || [ ! -f bobbypin.py ] || [ ! -f START-HERE.md ]; then
  echo "make-bundle: run this from a complete checkout" >&2
  exit 1
fi

mkdir -p dist
# Ship the source, the vendored analysis layer, and every instruction file.
# Leave out what the installer regenerates or what is machine-specific.
tar --create --gzip --file "$out" \
  --exclude='.git' \
  --exclude='.venv' \
  --exclude='venv' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='node_modules' \
  --exclude='dist' \
  --exclude='target/*/AUTHORIZATION.md.tmp' \
  --transform 's,^\.,bobbypin,' \
  .

printf 'built %s (%s)\n' "$out" "$(du -h "$out" | cut -f1)"
printf 'contents:\n'
tar --list --file "$out" | grep -E 'START-HERE|install\.sh|setup\.py|AGENTS\.md|AUTHORIZATION|vendor/' | sed 's/^/  /'
