# skills-checker

A CLI security scanner for local Agent/SKILL configuration files, written in Rust.

Recursively scans global and user-specified directories for four categories of security risks:

| Category | Description | Example rules |
|---|---|---|
| 🔴 Remote data upload | Sending local data to a remote server by default | `requests.post`, `curl -X POST`, `upload()`, `multipart/form-data`, `webhook:` |
| 🔑 Hardcoded secrets | Plaintext API keys / tokens / passwords | `sk-*`, `AKIA*`, `ghp_*`, `xox*`, `AIza*`, `password = "..."` |
| 🌐 Suspicious URLs | Data collectors / tunneling services / raw IPs / telemetry | `webhook.site`, `requestbin`, `ngrok`, raw IP, `telemetry/collect` |
| ⚡ Dangerous execution | Download-and-run, shell injection, destructive commands | `curl \| sh`, `base64 -d \| sh`, `shell=True`, `os.system`, `rm -rf /`, encoded PowerShell |

## Quick start

```bash
cargo build --release
./target/release/skills-checker                 # scan common global agent config dirs
./target/release/skills-checker -d ~/.claude    # scan a specific dir (repeatable -d)
./target/release/skills-checker -d ./skills --json   # JSON to stdout
./target/release/skills-checker -d ./skills -o report.json   # export (format inferred from extension)
./target/release/skills-checker -d ./skills -o report.html   # readable HTML report
./target/release/skills-checker -d ./skills -o report.txt --format text
./target/release/skills-checker -d ./skills --fail-on high -q   # CI integration
```

## CLI options

```
-d, --path <DIR>    Scan a specific directory (repeatable); default scans common global agent dirs
    --json          Output JSON to stdout
-o, --output <FILE> Export report to a file
    --format <FMT>  Export format auto|json|html|text (default: auto, inferred from file extension)
    --no-cache      Disable incremental cache
-q, --quiet         Quiet mode (single summary line)
-v, --verbose       Show matched source lines
    --fail-on <LVL> Minimum severity that triggers a failing exit code: critical|high|medium|low (default: low)
```

Default global scan dirs: `~/.claude`, `~/.coze`, `~/.cursor`, `~/.gemini`, `~/.codex`,
`~/.aider`, `~/.continue`, `~/.copilot`, `~/.config/{claude,coze,cursor,...}`, etc.
Additional dirs can be appended via the `SKILLS_CHECKER_PATHS` environment variable
(OS path-separator separated).

## Exit codes (CI friendly)

| Code | Meaning |
|---|---|
| 0 | No findings at or above the `--fail-on` threshold |
| 1 | Findings at or above the threshold |
| 2 | Runtime error (invalid args / directory) |

## Project layout

```
src/
├── main.rs      # Entry: clap arg parsing, scan orchestration, exit codes
├── models.rs    # Data structures (Severity/RiskType/Finding/ScanResult/cache)
├── rules.rs     # 20+ detection rules (regex + severity + description + fix)
├── scanner.rs   # Dir discovery, file filtering, parallel scan, incremental cache
└── report.rs    # Colored terminal output, JSON/text export
```

## Performance design

- **Parallel scan**: `rayon` parallelizes file reads and matching across CPU cores; the
  rule set is compiled once and shared globally.
- **Incremental cache**: `~/.cache/skills-checker/cache.json` stores a `(size, mtime)`
  fingerprint per file; unchanged files reuse previous results (near-instant rescan).
  A built-in **rules fingerprint** invalidates stale cache automatically when rules change.
- **File filtering**: only text files whose name contains skill/agent/mcp or that live
  under a skill directory are scanned; skips `.git`/`node_modules`/`target` and files
  larger than 10MB.

## Noise reduction

- Placeholder/example values (`your-*`, `example`, `<token>`, `xxx`, `******` etc.) are ignored.
- URL allowlist: docs/official domains (github.com, docs.rs, pypi.org, etc.) do not raise
  low-severity warnings.
- `--fail-on` tunes CI sensitivity; `-q` is for scripts.

## Development

```bash
cargo test        # unit tests
cargo clippy      # lint (zero warnings)
cargo fmt         # formatting
```

## Distribute as an npm package

The CLI can be published to the npm registry for easy install/distribution, using
the same pattern as esbuild / oxlint: an npm package that bundles the native
Rust binary and a zero-dependency Node shim.

```
bin/skills-checker.js              # cross-platform shim: locates & spawns the native binary
bin/<platform>-<arch>/skills-checker(.exe)   # prebuilt native binary
scripts/copy-bin.js                # copy target/release output into the npm layout
scripts/install.js                 # postinstall: verify or optionally download the binary
scripts/merge-artifacts.js         # CI: merge per-platform build artifacts
.github/workflows/release.yml      # 5-platform build matrix + auto npm publish
```

Supported platforms: `win32-x64`, `linux-x64`, `linux-arm64`, `darwin-x64`, `darwin-arm64`.

### Build and test locally

```bash
npm run build:bin                  # cargo build --release + copy into bin/
npm run test:bin                   # node bin/skills-checker.js --version
npm pack --dry-run                 # inspect tarball contents
```

### Publish

Option A — manual (current platform only):

```bash
npm login
npm run build:bin
npm publish --access public
```

Option B — CI (recommended, all 5 platforms):

1. Push a tag: `git tag v0.1.0 && git push --tags`
2. `.github/workflows/release.yml` builds all platform binaries, merges them and
   publishes to npm automatically (`secrets.NPM_TOKEN` required in repo settings)
3. Package version is synced from the git tag

### Install and use

```bash
npm install -g skills-checker
skills-checker -d ./skills --json        # machine-readable JSON
skills-checker -d ./skills -o report.html # self-contained readable HTML report
```

The HTML report is a single self-contained file (inline CSS/JS, no external
dependencies) with severity badges, per-file grouping, clickable severity
filters and dark-mode support — ideal for sharing with non-CLI users.

If no prebuilt binary matches the platform, `postinstall` prints instructions:
`npm run build:bin` (build locally) or set `SKILLS_CHECKER_BIN_URL` to download
a binary from a GitHub Release asset.

## Languages

[English](README.md) · [简体中文](README.zh-CN.md)
