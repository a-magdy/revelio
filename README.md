# revelio

**Host-level dependency audit CLI for macOS.**

Revelio inventories the tools installed on your machine, checks what is outdated, correlates findings across multiple vulnerability sources, and tells you which top-level package is responsible. It is designed for the stuff project-scoped scanners miss: global CLIs, language toolchains, package-manager installs, and transitive dependencies already living on your laptop.

## Why use it

- **Host-scoped, not project-scoped**: scans what is actually installed across Homebrew, npm globals, pip, pipx, uv, cargo, gems, Go tools, and dotnet tools.
- **One report, not five**: combines OSV, npm audit, pip-audit, cargo-audit, and Grype, then deduplicates overlapping findings.
- **Actionable remediation context**: attributes vulnerable transitive packages back to the parent or root package you can actually upgrade.
- **Useful even offline**: inventory mode works without network lookups.
- **No service required**: standalone Bash CLI with no cloud account or daemon.

## What ships today

| Capability | Status | Notes |
| --- | --- | --- |
| Host inventory across major package managers | Yes | Produces inventory artifacts under `~/.revelio/<run-id>/` by default |
| Outdated package checks | Yes | Per-manager outdated summaries are included in the run output |
| Vulnerability aggregation + deduplication | Yes | OSV, npm audit, pip-audit, cargo-audit, Grype |
| Parent / root package attribution | Yes | Helps explain which direct install owns a vulnerable transitive dep |
| `why <package>` reverse dependency tracing | Yes | Supports multiple package managers |
| Report rendering from existing artifacts | Yes | `report` summarizes the latest or a specific run |
| Scheduled runs | Not yet | Planned |
| Bulk upgrade workflows | Not yet | Planned |
| Roll back to an older safer version | Not yet | Planned |
| Compare two reports over time | Not yet | Planned |

## Quick start

### Requirements

- macOS
- Bash 4 or newer (`brew install bash`; macOS's bundled Bash 3.2 is not supported)
- `jq`
- `curl`

Optional scanners and manager CLIs improve coverage when present, including `brew`, `npm`, `pip`, `pipx`, `uv`, `cargo`, `go`, `dotnet`, `pip-audit`, `cargo-audit`, and `grype`.

Revelio fails fast on unsupported Bash versions and prints a Homebrew install hint instead of breaking later on Bash 4-only features.

### Run it

```bash
# If `bash` still resolves to macOS's old /bin/bash, invoke the Homebrew one directly
# "$(brew --prefix)/bin/bash" ./revelio.sh scan

# Full host dependency scan
./revelio.sh scan

# Inventory only, with no network lookups
./revelio.sh inventory --offline

# Read the latest report, or a specific run
./revelio.sh report
./revelio.sh report ~/.revelio/<run-id>

# Explain why something is installed
./revelio.sh why openssl@3
./revelio.sh why nokogiri --manager gem

# Create a starter config in the current directory
./revelio.sh init-config
```

## Core commands

| Command | Purpose |
| --- | --- |
| `scan` | Inventory + outdated checks + vulnerability checks |
| `inventory` | Inventory only; skips vulnerability lookups |
| `report [path]` | Render a terminal summary for the latest or specified run. Respects `--output-dir` and `--config` for locating runs |
| `why <package>` | Show why a package is installed and who depends on it. Use `--manager <mgr>` to limit search; without it, all managers are searched |
| `init-config [path]` | Write a starter config file |

### Common options

- `--config <path>`
- `--output-dir <path>`
- `--severity <none|low|medium|high|critical>`
- `--offline` / `--online`
- `--deep-scan` / `--no-deep-scan`
- `--no-fail` / `--fail`
- `--fail-on-scanner-errors` / `--no-fail-on-scanner-errors`

## What a run produces

Each run writes a timestamped directory under `~/.revelio/<run-id>/` unless you override `defaults.outputDir`.

Key artifacts:

- `report.json` - top-level summary and policy result
- `inventory/packages.json` - normalized package inventory
- `outdated/items.json` - outdated package records
- `scans/findings.json` - raw vulnerability findings
- `scans/advisories.json` - deduplicated, enriched remediation view

Each advisory in `advisories.json` carries:

- `evidenceSources` — which scanners found this (e.g., `["osv","npm-audit"]`)
- `remediationStatus` — `actionable-update-now`, `upstream-pending-release`, or `no-fix-released`
- `remediationMessage` — human-readable guidance
- `recommendedVersion` and `upgradeCommand` — what to run
- `primaryParent` and `responsibleParents` — which direct installs own the vulnerable transitive dep
- npm release-channel fields when applicable: `rootPackage`, `pendingReleaseTag`, `pendingReleaseVersion`

## Design details

### Parent attribution

For each vulnerable transitive dependency, Revelio resolves the immediate parent (`primaryParent`), all depending packages (`responsibleParents`), and the top-level direct install (`rootPackage`). This tells you which `brew upgrade` or `npm install -g` to run rather than which CVE to look up.

### Remediation status and npm release-channel enrichment

Each advisory carries a `remediationStatus`:

- `actionable-update-now` — a stable fix exists
- `upstream-pending-release` — fix is available on a prerelease channel
- `no-fix-released` — no upstream fix yet

For npm globals, when the root package is already on the latest stable release and the transitive vulnerability has no stable-channel fix, Revelio scans active prerelease dist-tags (`beta`, `rc`, `next`, etc.) and checks whether the candidate resolves the vulnerable dependency to a patched version. If so, the advisory is classified as `upstream-pending-release` with the specific release tag and version, so you know whether to wait rather than seeing an open advisory on every run.

### Cross-scanner fusion

Five scanners can report the same CVE. Revelio deduplicates by canonical identity `(manager, ecosystem, package, id, dependencyPath)` and merges `evidenceSources` arrays — one advisory per finding, not five.

### Runtime isolation

Package-manager caches and scanner state are redirected into the run directory so scans do not affect your normal tool state.

## Configuration highlights

`revelio.config.json` controls run behavior. Important defaults:

| Key | Default | Purpose |
| --- | --- | --- |
| `defaults.outputDir` | `~/.revelio` | Root directory for run artifacts |
| `defaults.severityThreshold` | `high` | Minimum severity that triggers failure policy |
| `defaults.failOnFindings` | `true` | Exit non-zero when findings meet the threshold |
| `defaults.failOnScannerErrors` | `true` | Exit non-zero when enabled collectors or scanners fail |
| `defaults.deepScan` | `false` | Adds deep Grype filesystem targets |
| `defaults.allowNetworkQueries` | `true` | Enables OSV and related network lookups |
| `scanners.npmReleaseChannelChecks` | `true` | Enables npm prerelease-channel remediation enrichment |

## How it works

```mermaid
flowchart TD
    CLI["revelio.sh <command>"]
    CLI --> SCAN["scan"]
    CLI --> INV["inventory"]
    CLI --> REPORT["report"]
    CLI --> WHY["why <package>"]

    SCAN --> COLLECT["Collect inventory across managers"]
    INV --> COLLECT
    SCAN --> OUTDATED["Check outdated versions"]
    SCAN --> VULNS["Run vulnerability scanners"]
    VULNS --> FUSION["Deduplicate and enrich advisories"]
    OUTDATED --> BUILD["Build report.json"]
    FUSION --> BUILD
    COLLECT --> BUILD
```

## Roadmap

These are **planned ideas**, not current CLI features.

### Scheduled runs on macOS

- Install a LaunchAgent so Revelio can run at login and on a daily schedule
- Make cadence configurable
- Allow enabling or disabling scheduled scans from config and, later, a dedicated CLI command
- Write reports to the normal output directory so scheduled and manual runs share the same artifact model

### Bulk upgrade assistance

- Generate manager-aware upgrade suggestions for multiple actionable advisories in one pass
- Prefer dry-run or confirmation-first workflows over silent changes
- Keep remediation tied to the advisory output so users know why each upgrade is recommended

### Roll back to an older safer version

- Explore safer-version guidance for ecosystems that support explicit version installs
- Treat this as a constrained workflow, not a blanket "downgrade everything" action
- Preserve auditability so users can see what changed and why

### Compare reports over time

- Add a command to compare two `report.json` files or run directories
- Highlight new findings, resolved findings, package version drift, and policy changes
- Use the existing per-run artifact layout as the comparison input

## Comparison to common tools

Most security scanners are **project-scoped**. Revelio is **host-scoped**: it audits packages already installed on the machine, across package managers, in one run.

| Feature | revelio | Trivy | Grype | Snyk | OSV-scanner |
| --- | --- | --- | --- | --- | --- |
| Host-level package-manager inventory | Yes | Partial | Partial | No | No |
| Multi-ecosystem host scan in one run | Yes | No | No | Partial | No |
| Cross-scanner deduplication | Yes | No | No | No | No |
| Parent package attribution | Yes | No | No | Partial | No |
| No account required | Yes | Yes | Yes | No | Yes |
| Bash-native workflow | Yes | No | No | No | No |

Trivy and Grype scan filesystem paths and container images but do not query native package-manager APIs (`brew list`, `gem list`, `pip list`, etc.), so host-level coverage is partial. Snyk requires a project manifest and an account; it does not scan global host environments.

## Development notes

### Smoke checks

```bash
./ci-smoke.sh
```

That script runs `shellcheck`, exercises the CLI entrypoints, and validates that a report is produced with the expected shape.
