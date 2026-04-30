# revelio

**Host-level dependency audit CLI for macOS.**

Revelio inventories the tools installed on your machine, checks what is outdated, correlates findings across multiple vulnerability sources, and tells you which top-level package is responsible. It is designed for the stuff project-scoped scanners miss: global CLIs, language toolchains, package-manager installs, and transitive dependencies already living on your laptop.

## Why use it

- **Host-scoped, not project-scoped**: scans what is actually installed across Homebrew, npm globals, pip, pipx, uv, cargo, gems, Go tools, and dotnet tools.
- **One report, not five**: combines OSV, npm audit, pip-audit, cargo-audit, and Grype, then deduplicates overlapping findings.
- **Actionable remediation context**: attributes vulnerable transitive packages back to the parent or root package you can actually upgrade, with status, rationale, and suggested commands.
- **Useful even offline**: inventory mode works without network lookups.
- **No service required**: standalone Bash CLI with no cloud account or daemon.

## How it compares

Most security scanners are **project-scoped**. Revelio is **host-scoped**: it audits packages already installed on the machine, across package managers, in one run.

| Feature | revelio | Trivy | Grype | Snyk | OSV-scanner |
| --- | --- | --- | --- | --- | --- |
| Host-level package-manager inventory | Yes | Partial | Partial | No | No |
| Multi-ecosystem host scan in one run | Yes | No | No | Partial | No |
| Cross-scanner deduplication | Yes | No | No | No | No |
| Parent package attribution | Yes | No | No | Partial | No |
| Remediation status guidance | Yes | No | No | Partial | No |
| No account required | Yes | Yes | Yes | No | Yes |
| Bash-native workflow | Yes | No | No | No | No |

Trivy and Grype are strong filesystem and container scanners, but they do not enumerate native package-manager data such as `brew list`, `gem list`, `pip list`, or `go env`, so host-package coverage is only partial. Snyk supports multiple ecosystems, but it expects project context and an account rather than a purely local host audit workflow.

## What ships today

| Capability | Status | Notes |
| --- | --- | --- |
| Host inventory across major package managers | Yes | Produces inventory artifacts under `~/.revelio/<run-id>/` (or `$XDG_STATE_HOME/revelio/` on Linux) |
| Outdated package checks | Yes | Per-manager outdated summaries are included in the run output |
| Vulnerability aggregation + deduplication | Yes | OSV, npm audit, pip-audit, cargo-audit, Grype |
| Parent / root package attribution | Yes | Helps explain which direct install owns a vulnerable transitive dep |
| `why <package>` reverse dependency tracing | Yes | Supports multiple package managers |
| Report rendering from existing artifacts | Yes | `report` summarizes the latest or a specific run |
| Compare two reports over time | Yes | `revelio diff` (text/json/markdown), respects severity threshold |
| Scheduled runs | Yes | `revelio schedule install` (launchd on macOS, systemd-user/cron on Linux) |
| Publish reports to a git remote | Yes | `revelio publish` clones, copies, commits, pushes (token via env var) |
| Linux portability | Yes | Native inventory and outdated checks for `dpkg`/`apt`, `rpm`/`dnf`, `pacman`, `snap`, `flatpak`. Distro-aware OSV ecosystem mapping (Debian/Ubuntu) with Grype as the safety net for vendor-labeled distros. Smoke harness in `docker/` validates against ubuntu/fedora/arch |
| Bulk upgrade workflows | Not yet | Planned |
| Roll back to an older safer version | Not yet | Planned |

## Quick start

### Requirements

- macOS or Linux
- Bash 4 or newer (`brew install bash` on macOS; macOS's bundled Bash 3.2 is not supported)
- `jq`
- `curl`
- `git` (only when using `revelio publish`)

Optional scanners and manager CLIs improve coverage when present:

- **macOS**: `brew`, `npm`, `pip`, `pipx`, `uv`, `cargo`, `go`, `dotnet`
- **Linux**: `dpkg-query`/`apt-cache`, `rpm`/`dnf`, `pacman`/`pactree` (from `pacman-contrib`), `snap`, `flatpak`
- **All platforms**: `pip-audit`, `cargo-audit`, `grype`

Revelio fails fast on unsupported Bash versions. macOS ships Bash 3.2; install Bash 4+ with `brew install bash`. Most modern Linux distros (Ubuntu 20.04+, Fedora 32+, Arch, Debian 11+) ship Bash 5 by default.

### Network behavior

Network lookups (OSV, npm, pip, cargo registries) honor the standard `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` environment variables — `curl` reads them automatically. Use `revelio scan --offline` to skip all network work and rely solely on local indexes + Grype.

### Installation

```bash
git clone https://github.com/a-magdy/revelio.git
cd revelio
```

No build step required. The CLI runs directly from the repository.

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
| `report [path]` | Render an existing run as text (default), JSON, SARIF 2.1.0, or CSV. Use `--format text\|json\|sarif\|csv` and optional `--output <file>`. Without a path, picks the latest run from `--output-dir` |
| `why <package>` | Show why a package is installed and who depends on it. Use `--manager <mgr>` to limit search; without it, all managers are searched |
| `diff <a> <b>` | Compare two reports (run dirs or `report.json` paths). Buckets findings into new/resolved/unchanged and inventory into added/removed/version-drift. `--format text\|json\|markdown`, `--output <file>`, `--since <baseline>` |
| `schedule <action>` | `install`, `uninstall`, or `status`. Backend chosen automatically: launchd on macOS, systemd-user (with cron fallback) on Linux. Options: `--cadence hourly\|daily\|weekly`, `--at HH:MM`, `--mode scan\|inventory`, `--publish` |
| `publish [--latest\|--run <path>]` | Clone the configured git repo, copy the run artifacts under `reports/{hostname}/{run-id}/`, commit, and push. Supports `--dry-run`, `--force`, token via `REVELIO_GIT_TOKEN` (overridable in config) |
| `init-config [path]` | Write a starter config file. Add `--force`/`-f` to overwrite an existing file (a `.bak.<timestamp>` copy is kept) |
| `version` (`--version`/`-V`) | Print the revelio version |

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

- `report.json` — top-level summary and policy result
- `inventory/packages.json` — normalized package inventory
- `outdated/items.json` — outdated package records
- `scans/findings.json` — raw vulnerability findings
- `scans/advisories.json` — deduplicated, enriched remediation view

Each advisory in `advisories.json` carries:

- `evidenceSources` — which scanners found this (e.g., `["osv","npm-audit"]`)
- `remediationStatus` — whether a fix is available now, pending release, or not yet released
- `remediationMessage` — human-readable guidance
- `recommendedVersion` and `upgradeRationale` — why the suggested target was chosen
- `upgradeCommand` — what to run
- `primaryParent` and `responsibleParents` — which direct installs own the vulnerable transitive dep
- npm release-channel fields when applicable: `rootPackage`, `rootInstalledVersion`, `rootLatestVersion`, `rootIsLatest`
- npm pending-release fields: `pendingReleaseTag`, `pendingReleaseVersion`, `pendingResolvedVersion`

The CLI report summary also prints parent-package attribution, remediation status, suggested upgrade commands, and a dedicated hang-tight section when pending-release evidence is present.

## Inventory enrichment

The package inventory includes two important fields per package:

- `installType` — `direct`, `dependency`, `default`, or `unknown`
- `parentPackages` — JSON array of parent package names, sorted and deduplicated

Manager-specific resolution:

- **Homebrew** — `brew leaves` for direct formulae, `brew deps --installed` for the dependency graph
- **npm** — depth-based (`1` = direct, `>1` = dependency), parent inferred from the dependency path
- **Ruby gems** — `gem dependency --reverse-dependencies` for dependency chains, plus the `default:` marker
- **pip** — `pip show` parsing with the `Required-by` field
- **pipx / uv / cargo / go / dotnet** — always treated as direct installs

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

### NDJSON streaming pipeline

Collectors and scanners append NDJSON as they run, then a final `jq -s` consolidation pass turns those streams into JSON artifacts. That keeps large scans composable, reduces memory pressure, and avoids corrupting shared JSON arrays during concurrent collection.

### Runtime isolation

Package-manager caches and scanner state are redirected into the run directory so scans do not affect your normal tool state. Homebrew, npm, pip, uv, gems, and Grype all use per-run state instead of leaking cache or analytics side effects into the user environment.

### Subshell execution model

The scan runs inside a subshell so failures abort cleanly, partial artifacts remain available for debugging, and the CLI can return a clean non-zero exit without leaking intermediate state.

## Configuration

`revelio.config.json` controls run behavior. Important defaults:

| Key | Default | Purpose |
| --- | --- | --- |
| `defaults.outputDir` | `null` (platform default) | Root directory for run artifacts (`~/.revelio` on macOS, `$XDG_STATE_HOME/revelio` on Linux) |
| `defaults.severityThreshold` | `high` | Minimum severity that triggers failure policy |
| `defaults.failOnFindings` | `true` | Exit non-zero when findings meet the threshold |
| `defaults.failOnScannerErrors` | `true` | Exit non-zero when enabled collectors or scanners fail |
| `defaults.deepScan` | `false` | Adds deep Grype filesystem targets |
| `defaults.allowNetworkQueries` | `true` | Enables OSV and related network lookups |
| `defaults.retainRuns` | `0` | When > 0, prune older run directories so only the N most recent are kept |
| `scanners.npmReleaseChannelChecks` | `true` | Enables npm prerelease-channel remediation enrichment |
| `publish.enabled` | `false` | Allow `revelio publish` to push to the configured remote |
| `publish.repoUrl` | `""` | Git remote URL (HTTPS or SSH) |
| `publish.branch` | `main` | Branch to push to |
| `publish.pathTemplate` | `reports/{hostname}/{run-id}/` | Where inside the repo each run lands |
| `publish.commitMessageTemplate` | `chore(revelio): scan {run-id} on {hostname}` | Commit message template |
| `publish.tokenEnvVar` | `REVELIO_GIT_TOKEN` | Env var name to read the auth token from (never written to URL or config) |

## How it works

```mermaid
flowchart TD
    CLI["revelio.sh <command>"]
    CLI --> SCAN["scan"]
    CLI --> INV["inventory --offline"]
    CLI --> WHY["why <package>"]
    CLI --> RPT["report"]
    CLI --> INIT["init-config"]

    subgraph WHY_FLOW ["Why Command"]
        direction TB
        WHY_LOAD["Load latest inventory.json"]
        WHY_SEARCH["Search by package name / manager"]
        WHY_SHOW["Show installType + parentPackages"]
        WHY_LOAD --> WHY_SEARCH --> WHY_SHOW
    end
    WHY --> WHY_LOAD

    SCAN --> COLLECT
    INV --> COLLECT

    subgraph COLLECT ["Collect Inventory - parallel"]
        BREW["Homebrew"]
        NPM["npm"]
        GEM["Ruby gems"]
        PIP["pip"]
        OTHER["pipx / uv / cargo / go / dotnet"]
    end

    COLLECT --> ENRICH["Inventory enrichment: installType + parentPackages"]
    ENRICH --> INVENTORY[("inventory.json")]

    INVENTORY -->|scan| OUTDATED["Outdated checks"]
    OUTDATED --> OUTDATED_JSON[("outdated.json")]

    INVENTORY -->|scan| VULNS
    subgraph VULNS ["Vulnerability scan"]
        OSV["OSV"]
        NPMA["npm audit"]
        PIPA["pip-audit"]
        CARGOA["cargo-audit"]
        GRYPE["Grype"]
    end

    VULNS --> FUSION["Cross-scanner fusion"]
    FUSION --> ADVISORY_ENRICH["Advisory enrichment"]
    ADVISORY_ENRICH --> ADVISORIES[("advisories.json")]

    INVENTORY --> BUILD["Build report"]
    OUTDATED_JSON --> BUILD
    ADVISORIES --> BUILD
    BUILD --> REPORT_JSON[("report.json")]
```

## Roadmap

These are **planned ideas**, not current CLI features.

### Bulk upgrade assistance

- Generate manager-aware upgrade suggestions for multiple actionable advisories in one pass
- Prefer dry-run or confirmation-first workflows over silent changes
- Keep remediation tied to the advisory output so users know why each upgrade is recommended

### Roll back to an older safer version

- Explore safer-version guidance for ecosystems that support explicit version installs
- Treat this as a constrained workflow, not a blanket "downgrade everything" action
- Preserve auditability so users can see what changed and why

## Development

### Smoke checks

```bash
./ci-smoke.sh
```

That script runs `shellcheck`, exercises `help`, `inventory --offline`, `report` (text/json/sarif/csv), `diff`, `publish --dry-run`, `schedule status`, `--quiet`/`--json`, `init-config --force`, and `retainRuns` pruning, plus a best-effort loop that exercises the Linux native collectors when their binaries are present (silently skipped on macOS).

### Linux validation via Docker

The repository ships a small harness that runs the full smoke suite inside ubuntu, fedora, and arch containers — useful when developing on macOS or to validate Linux behavior in CI.

```bash
./docker/run-linux-smoke.sh           # all three distros
./docker/run-linux-smoke.sh ubuntu    # one distro
```

See `docker/README.md` for details and how to add a new distro.

## Contributing

Revelio is in early development. Bug reports and feature requests are welcome via [GitHub Issues](https://github.com/a-magdy/revelio/issues). If you would like to contribute code, please open an issue first to discuss the change.

## Security

If you discover a vulnerability in Revelio itself, please report it privately via [GitHub Security Advisories](https://github.com/a-magdy/revelio/security/advisories/new) rather than opening a public issue.

## License

This project does not yet have a license. Until one is added, standard copyright applies. If you would like to use Revelio in your own work, please open an issue to discuss licensing.
