# Honeypots

Decoys planted inside the isolation boundary before a target runs. Afterwards,
`audit()` reports which of them the target touched. This is how a run answers
"what did this binary go looking for?" with evidence instead of a guess.

## What gets planted

Profile `windows` (13 artifacts) - a believable analyst profile:

| where | artifact | kind |
|---|---|---|
| `Documents/passwords.txt` | password notes | credential |
| `Documents/chrome_logins.csv` | saved browser logins | credential |
| `Documents/tax_return_2025.pdf` | PDF with a real header + trailer | document |
| `Documents/notes.txt` | vendor renewal notes | document |
| `Desktop/license.key` | activated product licence | license |
| `AppData/Roaming/BobbinSoft Pro/license.dat` | product licence + blob | license |
| `AppData/Roaming/Microsoft/Crypto/keys.dat` | key material | key |
| `AppData/Local/.../Login Data` | SQLite-shaped browser store | credential |
| `wallet.dat` | bitcoin-wallet shaped | wallet |
| `.ssh/id_rsa` | private key | key |
| `.aws/credentials` | two AWS profiles | credential |
| `secrets.env` | service keys | config |
| `AppData/Roaming/config.json` | app config with licence block | config |

Profile `linux` plants `.ssh/id_rsa`, `.aws/credentials`, `.docker/config.json`,
`.netrc`, `.bash_history`, `.env`, `wallet.dat`, `id_rsa.pem`, `.kube/config`,
`licence.key`, `.npmrc`. Profile `both` plants the union.

Credentials and keys are `0600`; documents are `0644`.

## How detection works

Every artifact carries **its own** canary token (`BP-CANARY-` + 8 hex), embedded
in its contents where a searching binary will find it and a human will barely
notice. Three checks run in `audit()`:

- **modified** - size or sha256 differs from the manifest
- **deleted** - the artifact is gone (a target tidying up after itself)
- **token_leaked** - the artifact's token appears anywhere under the scan roots
  outside the honeypot root

The leak check matches on the *token*, not on a file hash, so it still fires when
the copy was truncated, re-encoded, base64'd into a log, or written to a temp file
- and `found_in` tells you exactly where it turned up.

Severity: a leak, or a deleted wallet/key/credential/licence file, is `high`; a
modified high-value file is `medium`; everything else is `low`/`medium`.

## Reading a report

```json
{"summary": {"total": 13, "modified": 0, "deleted": 0, "leaked": 1, "clean": false},
 "hits": [{"relpath": "Users/analyst/Desktop/license.key", "kind": "license",
           "change": "token_leaked", "token": "BP-CANARY-1a2b3c4d",
           "found_in": "/run/out/leak.txt", "severity": "high"}]}
```

Read `found_in` as: *this binary read the decoy licence key and wrote it here.*
`clean: false` on any run means the target went after data it had no business
touching.

## Use

```bash
python3 -m sandbox.honeypots deploy /tmp/hp windows
python3 -m sandbox.honeypots audit  /tmp/hp /tmp/scan-here
```

Or through the tool: `honeypot_deploy` / `honeypot_check`. In a sandboxed run the
honeypot root is bind-mounted **read-only** at `/honeypots`, so the target can read
the bait but cannot alter or delete the evidence.

## Caveats

- These are fakes. Nothing here is a real credential and the values are
  regenerated on every deploy.
- The tokens are unique per artifact, so a hit names one decoy. The manifests are
  `0600`; treat a honeypot root as sensitive anyway.
- Absence of hits is not proof of good behaviour - only of not having touched the
  bait in this run.
