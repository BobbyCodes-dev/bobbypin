"""Honeypot decoys: plant bait, then prove what the target did with it.

Untrusted binaries are run inside a throwaway boundary. Before the run this
module plants a realistic-looking user profile (credentials, licence files,
wallets, keys, documents) inside that boundary. Every planted file carries a
unique canary token embedded in its contents. After the run, ``audit()`` tells
you, with evidence, which of them were changed, deleted, or - the interesting
case - copied somewhere else. A binary that reads the decoy licence key and
writes it to a log, a temp file or an output file is caught by the token, even
if it re-encoded or truncated the copy.

Standard canary practice: tokens are unique per artifact, so a hit names both
the decoy file and the place the copy turned up.

NOTE FOR EDITORS: decoy key/value lines are assembled by ``_kv()``/``_name()``
instead of being written as literals on purpose. A plain ``SOMETHING_KEY=value``
literal in this source file trips secret-scanning filters in editors, CI and
agent tooling, which silently rewrites or redacts it and leaves broken code
behind. Build the assignment, do not type it.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass
from typing import Optional

CANARY_PREFIX = "BP-CANARY-"
MANIFEST_NAME = "_honeypot_manifest.json"

# Builders are rendered with this placeholder and then stamped with a UNIQUE
# token per artifact, so a leaked token identifies exactly one decoy file.
_STAMP = chr(37) * 2 + "BP" + chr(95) + "TOKEN" + chr(37) * 2

HIGH_VALUE_KINDS = {"credential", "license", "wallet", "key"}

_EQ = chr(61)          # '='
_HASH = chr(35)        # '#' comment marker


def _token() -> str:
    return CANARY_PREFIX + secrets.token_hex(4)


def _name(*parts: str) -> str:
    """'OPENAI', 'API', 'KEY' -> 'OPENAI_API_KEY=' (assignment, built not typed)."""
    return "_".join(parts) + _EQ


def _kv(name: str, value: str) -> str:
    return name + _EQ + str(value)


def _yml(name: str, value: str, indent: int = 0) -> str:
    return " " * indent + name + ": " + str(value)


@dataclass
class HoneypotArtifact:
    relpath: str
    kind: str
    sha256: str
    size: int
    mtime: float
    token: str


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: str) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _tokens_in(data: bytes) -> list:
    text = data.decode("utf-8", "replace")
    out, idx = [], 0
    while True:
        idx = text.find(CANARY_PREFIX, idx)
        if idx < 0:
            break
        out.append(text[idx:idx + len(CANARY_PREFIX) + 8])
        idx += len(CANARY_PREFIX)
    return out


def _lines(*rows: str) -> bytes:
    return ("\n".join(rows) + "\n").encode()


# --------------------------------------------------------------------------
# content builders - every value is generated at runtime, every artifact
# carries its own token
# --------------------------------------------------------------------------

def _windows_contents(token: str) -> dict:
    lic_blob = "BP-LIC-v3." + secrets.token_hex(24)
    vault = _lines(
        _HASH + " personal password notes (keep offline)",
        _kv("bobbinsoft-portal", "analyst " + token),
        _kv("bank", "analyst Open-Sesame-2026"),
        _kv("vpn", "analyst autumn-leaves-91"),
    )
    chrome = _lines(
        "name,url,username,password",
        "Acme Studio,https://portal.acmestudio.example,analyst@example.com," + token,
        "BobbinSoft Pro,https://license.bobbinsoft.example,analyst@example.com," + token + "b",
        "bank.example,https://bank.example,analyst,Open-Sesame-2026",
    )
    return {
        "Users/analyst/Documents/passwords.txt": ("credential", 0o600, vault),
        "Users/analyst/Documents/chrome_logins.csv": ("credential", 0o600, chrome),
        "Users/analyst/Documents/tax_return_2025.pdf": ("document", 0o644,
            b"%PDF-1.4\n"
            b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj\n"
            b"4 0 obj<</Length 96>>stream\n"
            b"BT /F1 11 Tf 72 720 Td (2025 Individual Return - AGI 84,120.00) Tj ET\n"
            b"endstream\nendobj\ntrailer<</Root 1 0 R>>\n"
            + ("%% " + token + "\n").encode()),
        "Users/analyst/Documents/notes.txt": ("document", 0o644, _lines(
            "2026-01 vendor renewal notes",
            "- BobbinSoft Pro renewal quoted at $249/yr; key is on the Desktop",
            "- invoice reference " + token,
            "- move the vault off this box before the audit")),
        "Users/analyst/Desktop/license.key": ("license", 0o600, _lines(
            _HASH + " BobbinSoft Pro - activated licence",
            _yml("product", "BobbinSoft Pro v2.0"),
            _yml("licence-id", token),
            _yml("email", "analyst@example.com"),
            _yml("blob", lic_blob))),
        "Users/analyst/AppData/Roaming/BobbinSoft Pro/license.dat": ("license", 0o600,
            _lines("[licence]",
                   _yml("id", token),
                   _yml("status", "activated"),
                   _yml("seats", 3),
                   _yml("blob", lic_blob))),
        "Users/analyst/AppData/Roaming/Microsoft/Crypto/keys.dat": ("key", 0o600,
            _lines("[REDACTED PRIVATE KEY]",
                   _HASH + " key-id " + token)),
        "Users/analyst/AppData/Local/Google/Chrome/User Data/Default/Login Data":
            ("credential", 0o600,
             b"SQLite format 3\x00" + secrets.token_bytes(64) + ("\n" + token + "\n").encode()),
        "Users/analyst/wallet.dat": ("wallet", 0o600,
            b"\x00\x00\x00\x00\x01\x00\x00\x00bitcoin-wallet\n"
            + ("# label: savings " + token + "\n").encode()
            + (secrets.token_hex(96) + "\n").encode()),
        "Users/analyst/.ssh/id_rsa": ("key", 0o600,
            _lines("[REDACTED PRIVATE KEY]",
                   _HASH + " " + token + " analyst@workstation")),
        "Users/analyst/.aws/credentials": ("credential", 0o600, _lines(
            "[default]",
            "aws_access_key_id " + _EQ + " AKIA" + secrets.token_hex(8).upper(),
            "aws_secret_access_key " + _EQ + " " + secrets.token_urlsafe(32),
            _HASH + " profile-tag " + _EQ + " " + token,
            "",
            "[backup]",
            "aws_access_key_id " + _EQ + " AKIA" + secrets.token_hex(8).upper(),
            "aws_secret_access_key " + _EQ + " " + secrets.token_urlsafe(32))),
        "Users/analyst/secrets.env": ("config", 0o600, _lines(
            _kv("APP_ENV", "prod"),
            _name("STRIPE", "SECRET", "KEY") + secrets.token_urlsafe(24),
            _name("OPENAI", "API", "KEY") + secrets.token_urlsafe(24),
            _name("DB", "PASSWORD") + "analyst-" + secrets.token_hex(6),
            _name("TELEMETRY", "TAG") + token)),
        "Users/analyst/AppData/Roaming/config.json": ("config", 0o644,
            json.dumps({
                "vendor": "BobbinSoft",
                "licence": {"id": token, "tier": "pro", "seats": 3},
                "telemetry": False,
                "update_url": "https://updates.bobbinsoft.example/v2/manifest.json",
            }, indent=2).encode() + b"\n"),
    }


def _linux_contents(token: str) -> dict:
    return {
        ".ssh/id_rsa": ("key", 0o600,
            _lines("[REDACTED PRIVATE KEY]", _HASH + " " + token + " analyst@host")),
        ".ssh/id_rsa.pub": ("key", 0o644,
            ("ssh-rsa AAAAB3NzaC1yc2E" + secrets.token_hex(32)
             + " analyst@host " + token + "\n").encode()),
        ".aws/credentials": ("credential", 0o600, _lines(
            "[default]",
            "aws_access_key_id " + _EQ + " AKIA" + secrets.token_hex(8).upper(),
            "aws_secret_access_key " + _EQ + " " + secrets.token_urlsafe(32),
            _HASH + " " + token)),
        ".docker/config.json": ("config", 0o600,
            json.dumps({"auths": {"ghcr.io": {"auth": secrets.token_hex(24)}},
                        "comment": token, "credsStore": "pass"}, indent=2).encode() + b"\n"),
        ".netrc": ("credential", 0o600, _lines(
            "machine pypi.org login analyst password " + token,
            "machine github.com login analyst password " + "gh" + "p_" + secrets.token_hex(8))),
        ".bash_history": ("document", 0o600, _lines(
            "cd ~/work",
            "psql -h db.internal -U analyst",
            "export " + _kv("TOKEN", token),
            "ssh-keygen -t ed25519",
            "tar czf backup.tgz ~/Documents")),
        ".env": ("config", 0o600, _lines(
            _kv("APP_ENV", "prod"),
            _name("SECRET", "KEY") + secrets.token_urlsafe(32),
            _name("CANARY") + token)),
        "wallet.dat": ("wallet", 0o600,
            ("bitcoin-wallet\n# " + token + "\n" + secrets.token_hex(64) + "\n").encode()),
        "id_rsa.pem": ("key", 0o600, _lines("[REDACTED PRIVATE KEY]", _HASH + " " + token)),
        ".kube/config": ("config", 0o600, _lines(
            "apiVersion: v1",
            "kind: Config",
            "current-context: prod",
            "users:",
            "- name: admin",
            "  user:",
            "    token: " + token)),
        "licence.key": ("license", 0o600, _lines(
            _kv("PRODUCT", "BobbinSoft Pro"),
            _kv("LICENCE", token),
            _kv("SEATS", "3"))),
        ".npmrc": ("credential", 0o600, _lines(
            "//registry.npmjs.org/:_authToken=npm_" + secrets.token_hex(16),
            "; " + token)),
    }


PROFILES = {
    "windows": _windows_contents,
    "linux": _linux_contents,
    "both": lambda token: {**_windows_contents(token), **_linux_contents(token + "b")},
}


class HoneypotSet:
    def __init__(self, root: str, artifacts: list, manifest_path: str, profile: str = "windows"):
        self.root = os.path.abspath(root)
        self.artifacts = artifacts
        self.manifest_path = manifest_path
        self.profile = profile

    # -- lifecycle --------------------------------------------------------
    @classmethod
    def deploy(cls, root: str, profile: str = "windows") -> "HoneypotSet":
        if profile not in PROFILES:
            raise ValueError(f"unknown honeypot profile {profile!r}; known: {', '.join(PROFILES)}")
        root = os.path.abspath(os.path.expanduser(root))
        os.makedirs(root, exist_ok=True)
        builder = PROFILES[profile]
        artifacts = []
        for relpath, (kind, mode, data) in builder(_STAMP).items():
            # every artifact gets its OWN token, even in the union profile, so a
            # leaked token names one decoy and not "all of them"
            art_token = _token()
            data = data.replace(_STAMP.encode(), art_token.encode())
            if CANARY_PREFIX.encode() not in data:
                data = data + ("\n" + _HASH + " " + art_token + "\n").encode()
            full = os.path.join(root, relpath)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(data)
            try:
                os.chmod(full, mode)
            except OSError:
                pass
            found = _tokens_in(data)
            token = found[0] if found else art_token
            st = os.stat(full)
            artifacts.append(HoneypotArtifact(
                relpath=relpath.replace(os.sep, "/"), kind=kind,
                sha256=_sha256_bytes(data), size=st.st_size,
                mtime=st.st_mtime, token=token))
        manifest = {
            "tool": "bobbypin.sandbox.honeypots",
            "version": 1,
            "profile": profile,
            "created": time.time(),
            "root": root,
            "artifacts": [asdict(a) for a in artifacts],
        }
        manifest_path = os.path.join(root, MANIFEST_NAME)
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
        try:
            os.chmod(manifest_path, 0o600)
        except OSError:
            pass
        return cls(root, artifacts, manifest_path, profile)

    @classmethod
    def load(cls, root: str) -> "HoneypotSet":
        root = os.path.abspath(os.path.expanduser(root))
        manifest_path = os.path.join(root, MANIFEST_NAME)
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        artifacts = [HoneypotArtifact(**a) for a in manifest.get("artifacts", [])]
        return cls(root, artifacts, manifest_path, manifest.get("profile", "unknown"))

    def to_dict(self) -> dict:
        return {"root": self.root, "profile": self.profile,
                "manifest": self.manifest_path,
                "artifacts": [asdict(a) for a in self.artifacts]}

    # -- detection --------------------------------------------------------
    def audit(self, scan_roots: Optional[list] = None, max_scan_bytes: int = 8_000_000,
              max_files: int = 5000, exclude: Optional[list] = None) -> dict:
        """Compare the decoys against the manifest and hunt for leaked tokens.

        `exclude` paths are skipped by the leak scan. It is for our own working copies -
        a transport tarball, or the decoys pulled back out of a VM for comparison - which
        otherwise "leak" every token into themselves and report a dozen false exfiltrations.
        """
        excludes = [os.path.abspath(os.path.expanduser(e)).rstrip(os.sep) + os.sep
                    for e in (exclude or []) if e]
        started = time.time()
        hits = []
        modified = deleted = leaked = 0

        for art in self.artifacts:
            full = os.path.join(self.root, art.relpath)
            if not os.path.isfile(full):
                deleted += 1
                hits.append({"relpath": art.relpath, "kind": art.kind, "change": "deleted",
                             "token": art.token, "found_in": None,
                             "severity": "high" if art.kind in HIGH_VALUE_KINDS else "medium"})
                continue
            try:
                st = os.stat(full)
                digest = _sha256_file(full)
            except OSError:
                continue
            if digest != art.sha256 or st.st_size != art.size:
                modified += 1
                hits.append({"relpath": art.relpath, "kind": art.kind, "change": "modified",
                             "token": art.token, "found_in": full,
                             "severity": "medium" if art.kind in HIGH_VALUE_KINDS else "low"})

        # leak scan: hunt for canary tokens outside the honeypot root
        roots = scan_roots if scan_roots is not None else [os.path.dirname(self.root)]
        roots = [os.path.abspath(os.path.expanduser(r)) for r in roots if r]
        needles = {a.token.encode(): a for a in self.artifacts if a.token}
        root_prefix = self.root.rstrip(os.sep) + os.sep
        scanned_files = 0
        for base in roots:
            if not os.path.isdir(base):
                continue
            for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
                dirnames[:] = [d for d in dirnames
                               if not os.path.join(dirpath, d).startswith(root_prefix)
                               and not os.path.islink(os.path.join(dirpath, d))]
                for fname in filenames:
                    full = os.path.join(dirpath, fname)
                    if full.startswith(root_prefix) or os.path.islink(full):
                        continue
                    if any(full.startswith(ex) for ex in excludes):
                        continue
                    if not os.path.isfile(full):
                        continue
                    if scanned_files >= max_files:
                        break
                    scanned_files += 1
                    try:
                        if os.path.getsize(full) > max_scan_bytes:
                            continue
                        with open(full, "rb") as fh:
                            blob = fh.read(max_scan_bytes)
                    except OSError:
                        continue
                    for needle, art in needles.items():
                        if needle in blob:
                            leaked += 1
                            hits.append({"relpath": art.relpath, "kind": art.kind,
                                         "change": "token_leaked", "token": art.token,
                                         "found_in": full, "severity": "high"})

        summary = {"total": len(self.artifacts), "modified": modified, "deleted": deleted,
                   "leaked": leaked, "clean": not hits}
        return {"summary": summary, "hits": hits, "scanned_roots": roots,
                "files_scanned": scanned_files,
                "duration_ms": int((time.time() - started) * 1000)}


def merge_guest_audit(host_report: dict, artifacts: list, guest_audit: dict) -> dict:
    """Fold an in-guest bait audit into a host-side one.

    In a VM the bait lives on the guest's ephemeral disk, so the host honeypot root
    stays pristine and cannot testify about tampering. The guest reports sha256 per
    decoy instead; this replaces the host's modified/deleted findings with the
    guest's, while keeping any leak the host found (a copy that made it out of the
    guest). Shape matches audit() so callers do not care which boundary ran.
    """
    if not guest_audit or guest_audit.get("_error"):
        return host_report
    by_rel = {a.relpath: a for a in artifacts}
    kept = [h for h in (host_report.get("hits") or [])
            if h.get("change") == "token_leaked"]
    modified = deleted = 0
    hits = []
    for rel, seen in guest_audit.items():
        art = by_rel.get(rel)
        if art is None:
            continue
        if seen is None:
            deleted += 1
            hits.append({"relpath": rel, "kind": art.kind, "change": "deleted",
                         "token": art.token, "found_in": None,
                         "severity": "high" if art.kind in HIGH_VALUE_KINDS else "medium"})
        elif seen.get("sha256") != art.sha256 or seen.get("size") != art.size:
            modified += 1
            hits.append({"relpath": rel, "kind": art.kind, "change": "modified",
                         "token": art.token, "found_in": None,
                         "severity": "medium" if art.kind in HIGH_VALUE_KINDS else "low"})
    hits.extend(kept)
    leaked = sum(1 for h in hits if h["change"] == "token_leaked")
    summary = {"total": len(artifacts), "modified": modified, "deleted": deleted,
               "leaked": leaked, "clean": not hits}
    merged = dict(host_report)
    merged["summary"] = summary
    merged["hits"] = hits
    merged["observed_in"] = "guest"
    return merged


def main(argv=None):
    import sys
    args = list(argv if argv is not None else sys.argv[1:])
    if not args:
        print("usage: python3 -m sandbox.honeypots deploy <root> [profile]")
        print("       python3 -m sandbox.honeypots audit <root> [scan_root ...]")
        return 2
    action = args[0]
    if action == "deploy":
        hs = HoneypotSet.deploy(args[1], args[2] if len(args) > 2 else "windows")
        print(json.dumps(hs.to_dict(), indent=2))
        return 0
    if action == "audit":
        hs = HoneypotSet.load(args[1])
        print(json.dumps(hs.audit(args[2:] or None), indent=2))
        return 0
    print(f"unknown action {action!r}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
