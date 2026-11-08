# pinpoint

Deep static analysis for the targets ordinary patchers cannot read: .NET managed
code, Android packages, ELF and Mach-O internals, WASM, Go/Rust build metadata,
IL2CPP, Electron and JavaScript applications.

One CLI and one MCP server. Everything returns structured JSON, so an agent can
consume it without screen-scraping.

```bash
npm i -g https://github.com/BobbyCodes-dev/bobbypin/releases/download/bobbypin-pinpoint-v1.0.0/bobbypin-pinpoint-1.0.0.tgz
pinpoint --version   # 1.0.0
```

## What it answers

- **What is this file?** format, architecture, digests, sections, entropy, packers
- **What is inside it without running it?** managed metadata and member
  signatures, APK signing schemes and content digests, native imports and layout
- **What did it look like before?** compare two builds member by member, artifact
  to artifact, capture to capture
- **What does this function do?** decompile and function analysis through a
  provider you already own

Analysis is evidence. It reports what it can prove and says so when it cannot.

## Commands

```
pinpoint inspect-artifact <path>            # everything provable about one file
pinpoint inspect-managed-members <path>     # .NET metadata, signatures, CIL anchors
pinpoint inspect-apk-signature <path>       # declared signing schemes, digests
pinpoint inspect-byte-entropy <path>        # byte-level entropy profile
pinpoint decompile <path> --procedure <name>
pinpoint function <path> --procedure <name>
pinpoint compare <a> <b>                    # two evidence bundles
pinpoint capabilities                       # which providers this host can reach
pinpoint doctor                             # is this install ready
```

Every command accepts `--format json`.

## Agent use

```bash
pinpoint setup          # configure agent integrations
pinpoint mcp add        # register the MCP server
pinpoint mcp doctor
```

The MCP server exposes the same operations as the CLI, with input schemas, so an
agent gets typed tool calls instead of shell strings. `pinpoint mcp` with no
subcommand serves the catalog over stdio; add `--http` for streamable HTTP.

## Providers

The provider-free probes work on a fresh machine with nothing installed:
artifact inventory, entropy, APK signature reading, managed member inventories,
JavaScript application graphs.

Decompiling native code needs one of Ghidra, Hopper, IDA, Kuna or Cutter on the
host. `pinpoint doctor` says what is reachable and what is missing, and
`pinpoint capabilities` lists every provider with its availability and side
effects, so nothing runs that you did not ask for.

## Safety

Targets are read, not executed, by every probe documented above. Anything that
launches a process is a separate, explicit command with its own side-effect
declaration in `capabilities`. Only analyse software you own or are authorised
to test.

## Requirements

Node.js `^22.23.4 || ^24.22.1 || >=26.12.1`. Linux, macOS and Windows.

## License

MIT. See [LICENSE](LICENSE); it records the upstream MIT notice this build is
derived from, as that license requires.
