# CLAUDE.md

> **Maintenance rule**: When you add, remove, rename, or change the public API of any script or library module, you **must** update this file and the relevant sections of `README.md`. Keep both concise and accurate.

## Overview

Revelio is a standalone host dependency audit CLI for macOS and Linux. It inventories installed packages across every major package manager (Homebrew, npm, pip/pipx/uv, cargo, gem, go, dotnet on macOS; the same plus dpkg/apt, rpm/dnf, pacman, snap, flatpak on Linux), checks for outdated versions, and cross-references findings against multiple vulnerability databases — all in a Bash 4+ script with runtime dependencies on `jq` and `curl`.

## Repository Map

```text
.
├── README.md
├── CLAUDE.md
├── revelio.sh              # CLI entrypoint
├── revelio.config.json     # Default runtime configuration
├── ci-smoke.sh             # Smoke tests (run before committing)
├── lib/
│   ├── core.sh             # Logging, require_param, check_dependencies, trim, to_lowercase
│   ├── file.sh             # write_file_content, path_normalize, ensure_dir, is_absolute_path
│   ├── platform.sh         # OS/arch detection, platform-specific default paths, scheduler chooser
│   ├── diff.sh             # `revelio diff`: compare two reports (text/json/markdown)
│   ├── schedule.sh         # `revelio schedule install/uninstall/status` (launchd | systemd-user | cron)
│   ├── publish.sh          # `revelio publish`: push a run to the configured git repo
│   └── security.sh         # All inventory, scanning, enrichment, and reporting logic (~3000 lines)
└── .github/
    └── instructions/
        └── shell-scripts.instructions.md  # Bash conventions for this repo
```

## Architecture

- `revelio.sh` is the CLI entrypoint. It parses commands and delegates to functions in `lib/security.sh`.
- `revelio.sh` fails fast on unsupported Bash versions and tells users to install modern Bash with Homebrew.
- `lib/security.sh` is the core library. Public API starts with `security_`; private helpers start with `_security_`.
- `lib/core.sh` and `lib/file.sh` are lightweight standalone helpers with no external dependencies. `security.sh` self-sources them if not already loaded.
- Config is resolved via `security_build_effective_config`: bundled `revelio.config.json` → optional user config file → CLI flag overrides.
- Each scan run writes artifacts to a timestamped directory under `~/.revelio/<run-id>/`.

### Key internal patterns

- **`_config_bool $json $path $default`** — extract a boolean from a JSON config string; use this instead of inline `jq -r 'if (...|type)=="boolean"...'` everywhere.
- **NDJSON streaming** — collectors and scanners append NDJSON to `.ndjson` files; a final `jq -s` consolidates each into JSON. Never append directly to a shared JSON array from concurrent processes.
- **Parallel collectors** — `_security_collect_inventory` runs all 9 collectors in background subshells with per-collector temp files; `wait` then concatenates. Follow this pattern when adding new collectors.
- **Subshell isolation** — `security_run` wraps the full execution in `if ! (...); then` so failures abort cleanly and partial artifacts are preserved for debugging.

## Code Style

- **Shell**: Bash (`#!/usr/bin/env bash`), strict mode (`set -euo pipefail`)
- **Indentation**: 2 spaces
- **Quoting**: Always double-quote variables (`"$var"`, `"${var}"`)
- **Functions**: `snake_case` for public, `_snake_case` for private
- **Sections**: `#===` for major sections, `#---` for subsections
- **Comments**: Describe *what* and *why*; document params with `# $N =>` notation
- Full conventions in `.github/instructions/shell-scripts.instructions.md`

## Public API (`lib/security.sh`)

| Function | Purpose |
| --- | --- |
| `security_default_config_json` | Emit the bundled default config as JSON |
| `security_init_config_file $path` | Create a starter config file |
| `security_build_effective_config $cfg $out $sev $deep $fail $net $sfail` | Merge defaults + file + CLI overrides into effective config JSON |
| `security_run $mode $effective_config_json` | Execute inventory or full scan; sets `REVELIO_LAST_REPORT`. Honors `defaults.retainRuns` to prune old runs and traps `INT`/`TERM` to clean up background collectors |
| `security_print_report_summary $report_file` | Render terminal summary for a report |
| `security_export_sarif $input [$output]` | Render advisories as SARIF 2.1.0 (input may be a run dir, report.json, or advisories.json) |
| `security_export_csv $input [$output]` | Render advisories as CSV (one row per vulnerability occurrence) |
| `security_report_exit_code $report_file` | Return non-zero when policy requires failure |
| `security_why_package $pkg $manager` | Show why a package is installed (reverse deps) |
| `diff_run $baseline $candidate $format $out` | (lib/diff.sh) Compare two reports; format = text/json/markdown |
| `schedule_install / schedule_uninstall / schedule_status` | (lib/schedule.sh) Manage scheduled runs via launchd / systemd-user / cron |
| `publish_run $cfg $run_dir $dry_run $force` | (lib/publish.sh) Push a run dir to the configured git repo |

## Configuration

| Key | Default | Purpose |
| --- | --- | --- |
| `defaults.outputDir` | `~/.revelio` | Root directory for run artifacts |
| `defaults.severityThreshold` | `high` | Minimum severity to trigger policy failure |
| `defaults.failOnFindings` | `true` | Exit non-zero when findings exceed threshold |
| `defaults.failOnScannerErrors` | `true` | Exit non-zero when a scanner fails |
| `defaults.deepScan` | `false` | Enable Grype filesystem scans |
| `defaults.allowNetworkQueries` | `true` | Enable OSV/npm/pip/cargo network lookups |
| `defaults.osvBatchSize` | `200` | Packages per OSV batch request |
| `defaults.osvDetailDelay` | `0.1` | Seconds between per-CVE OSV detail calls |
| `inventory.*` | all `true` | Enable/disable per-manager inventory collection |
| `scanners.*` | all `true` | Enable/disable per-scanner vulnerability checks |
| `scanners.grypeTargets` | brew/npm/pipx/cargo/go paths | Directories scanned by Grype (non-deep) |
| `scanners.grypeDeepTargets` | `/Applications`, `~/Applications` | Extra paths added when `deepScan` is true |

## Build and Test

```bash
# Lint
shellcheck -x revelio.sh lib/core.sh lib/file.sh lib/security.sh

# Smoke tests (run before committing)
./ci-smoke.sh
```

## Safety Notes

- `security_run` is the only function that writes to disk outside the run directory. All writes go under `$outputDir/<run-id>/`.
- Runtime environment variables (npm cache, pip cache, Homebrew flags, etc.) are redirected inside the run directory by `_security_prepare_runtime_environment` — no side effects to global tool state.
- Never call `exit` inside library functions; use `return 1`.
