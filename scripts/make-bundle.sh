#!/usr/bin/env bash
# Build the downloadable bundle: everything needed for an offline install, in one
# tarball. The result goes to dist/ and is what gets attached to a GitHub release.
#
#   scripts/make-bundle.sh              # -> dist/bobbypin-bundle-<date>.tar.gz
#   scripts/make-bundle.sh v1.0.0       # -> dist/bobbypin-bundle-v1.0.0.tar.gz
#
# The tarball is built from the commit, not from the directory: `git archive`
# ships exactly the tracked files at HEAD, so local scratch can never leak into
# a download and the bundle always matches a SHA you can point at.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

label="${1:-$(date +%Y%m%d)}"
out="dist/bobbypin-bundle-${label}.tar.gz"
vendor="vendor/bobbypin-pinpoint-1.0.0.tgz"
ref="${BOBBYPIN_BUNDLE_REF:-HEAD}"

for f in setup.py bobbypin.py START-HERE.md AGENTS.md "$vendor"; do
  if [ ! -f "$f" ]; then
    echo "make-bundle: $f is missing." >&2
    case "$f" in
      "$vendor") echo "  fetch it from the bobbypin-pinpoint-v1.0.0 release and drop it in vendor/." >&2 ;;
    esac
    exit 1
  fi
done
# Both entry points ship or the download is not ready for all three platforms.
if ! git cat-file -e "${ref}:install.sh" 2>/dev/null || ! git cat-file -e "${ref}:install.ps1" 2>/dev/null; then
  echo "make-bundle: ${ref} must contain install.sh and install.ps1." >&2
  echo "  without install.ps1 the bundle installs on Linux and macOS only." >&2
  exit 1
fi
# A dirty tree would build a bundle that does not match the commit it claims.
if [ "$ref" = "HEAD" ] && [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "make-bundle: tracked files are modified; commit them or set BOBBYPIN_BUNDLE_REF." >&2
  git status --short --untracked-files=no >&2
  exit 1
fi

mkdir -p dist
git archive --format=tar.gz --prefix=bobbypin/ --output="$out" "$ref"

sha="$(git rev-parse --short "$ref")"
printf 'built %s (%s) from %s\n' "$out" "$(du -h "$out" | cut -f1)" "$sha"
printf 'contents:\n'
tar --list --file "$out" | grep -E 'START-HERE|install\.sh|install\.ps1|setup\.py|AGENTS\.md|AUTHORIZATION|vendor/' | sed 's/^/  /'
