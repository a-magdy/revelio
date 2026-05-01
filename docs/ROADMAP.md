# Roadmap

> **Purpose**: durable backlog of "what mature OSS CLIs ship" improvements that are
> orthogonal to going public. For pre-launch/legal blockers see [`LAUNCH.md`](LAUNCH.md).
>
> **How to use**: pick a track, follow its **Steps**, satisfy **Acceptance**, mark it
> done. Update **Status** as you go. No dates — only effort sizing.
>
> **Status legend**: `proposed` · `in-progress` · `done` · `blocked`

---

## Cross-cutting rules (apply to every track)

- **Versioning**: bump `REVELIO_VERSION` in `lib/security.sh` to match each new tag.
  Release CI must enforce this.
- **No new runtime deps**: stay within `bash 4+`, `jq`, `curl`, `git`. Optional
  scanners (`grype`, `pip-audit`, `cargo-audit`) remain optional.
- **Bash conventions**: any new `lib/*.sh` follows
  [`.github/instructions/shell-scripts.instructions.md`](../.github/instructions/shell-scripts.instructions.md)
  — strict mode, 2-space indent, double-quoted vars, `snake_case` public /
  `_snake_case` private.
- **Coverage**: every track extends `ci-smoke.sh` or adds bats coverage (track G)
  before merge.
- **Repository Map**: when a track adds new files under `lib/`, `docs/`, or
  top-level, update the **Repository Map** in `CLAUDE.md`.

---

## Dependency graph

```
I (release automation)
  ├── A (Homebrew tap)
  ├── D (install.sh)
  └── J (self-update)

independent: B, E, F, G, H, K, L
```

Start with **I**; A/D/J unblock once releases produce signed tarballs.

---

## 1. Distribution & install

### I — Release automation

- **Status**: proposed
- **Goal**: tagging `vX.Y.Z` produces a GitHub Release with a versioned tarball,
  checksums, and (optionally) signatures.
- **Why**: prerequisite for every other distribution track. Manual releases don't
  scale and break Homebrew formulas / install scripts on every push.
- **Steps**:
  1. Add `.github/workflows/release.yml` triggered on `push: tags: ['v*']`.
  2. Verify `REVELIO_VERSION` in `lib/security.sh` matches the tag — fail fast otherwise.
  3. Build `revelio-${VERSION}.tar.gz` containing `revelio.sh`, `lib/`,
     `revelio.config.json`, `README.md`, `LICENSE` (once added).
  4. Generate `SHA256SUMS` for the tarball.
  5. Create the GitHub Release with auto-generated notes + attach tarball + checksums.
  6. **Optional**: sign with `cosign --keyless`; attach `.sig` and `.pem`.
- **Files / artifacts**: `.github/workflows/release.yml`.
- **Dependencies**: none. Blocks A, D, J.
- **Acceptance**: pushing a `v0.x.y` tag produces a Release with at least
  `revelio-<version>.tar.gz` and `SHA256SUMS` attached; workflow fails when
  `REVELIO_VERSION` ≠ tag.
- **Effort**: low.

### A — Homebrew tap formula

- **Status**: proposed
- **Goal**: users can `brew tap a-magdy/revelio && brew install revelio`.
- **Why**: by far the highest-leverage discovery channel for a macOS-first CLI.
  Standard expectation from the target audience.
- **Steps**:
  1. Create a separate repo `a-magdy/homebrew-revelio` with `Formula/revelio.rb`.
  2. Formula: `url`/`sha256` point at the latest release tarball;
     `depends_on "bash"`, `"jq"`, `"curl"`; `bin.install "revelio.sh" => "revelio"`;
     `libexec.install "lib", "revelio.config.json"`.
  3. `test do` runs `system "#{bin}/revelio", "--version"`.
  4. Wire `revelio` to the right `libexec` paths so `lib/` resolves correctly when
     the script is invoked from `/usr/local/bin` (use `SCRIPT_DIR` resolution that
     follows symlinks; revisit `revelio.sh:48`).
  5. Add `brew` install instructions to README "Quick start".
  6. **Later**: submit to `homebrew-core` once API is stable and 30+ stars.
- **Files / artifacts**: external `homebrew-revelio` repo; possibly small change
  in `revelio.sh` to follow symlinks for `SCRIPT_DIR`.
- **Dependencies**: I.
- **Acceptance**: `brew tap a-magdy/revelio && brew install revelio && revelio --version`
  works on a clean macOS machine; `brew test revelio` passes.
- **Effort**: medium.

### D — `install.sh` one-liner

- **Status**: proposed
- **Goal**: `curl -fsSL https://raw.githubusercontent.com/a-magdy/revelio/main/install.sh | bash`
  installs revelio without git clone.
- **Why**: standard OSS pattern (rustup, ollama, deno, starship). Lower friction
  for Linux users where Homebrew is less universal.
- **Steps**:
  1. Add `install.sh` at repo root.
  2. Detect OS (`uname -s`) and refuse Windows; warn on unknown.
  3. Resolve target version: `${REVELIO_VERSION:-latest}` via GitHub API.
  4. Download `revelio-<version>.tar.gz` + `SHA256SUMS`; verify checksum.
  5. Install into `${REVELIO_PREFIX:-$HOME/.local}/share/revelio`; symlink
     `revelio` into `${REVELIO_PREFIX:-$HOME/.local}/bin`.
  6. Idempotent: re-running upgrades in place.
  7. `install.sh --uninstall` removes the symlink and share dir.
  8. Print PATH-export instruction if `~/.local/bin` is not on PATH.
- **Files / artifacts**: `install.sh` (top-level), README install section update.
- **Dependencies**: I.
- **Acceptance**: clean Ubuntu and macOS containers in the existing `docker/`
  harness can install via `install.sh` and run `revelio --version`; `--uninstall`
  cleans up.
- **Effort**: low.

### J — `revelio self-update` subcommand

- **Status**: proposed
- **Goal**: `revelio self-update` upgrades the local install without re-running
  the original install command.
- **Why**: common in single-binary CLIs (`gh`, `rustup`, `deno`). Closes the loop
  for `install.sh` users who don't have brew auto-update.
- **Steps**:
  1. New `lib/update.sh`; wire `self-update` command in `revelio.sh`.
  2. Resolve latest release via GitHub API; compare to `REVELIO_VERSION`.
  3. Detect install method:
     - **Homebrew** (`brew --prefix revelio` succeeds) → suggest `brew upgrade revelio`.
     - **install.sh** (symlink target lives under `~/.local/share/revelio` or
       `$REVELIO_PREFIX`) → re-run install.sh pinned to the new version.
     - **git clone** → suggest `git pull`.
  4. Always honor a `--dry-run` flag (default in `--check` mode).
  5. Cache the latest-version response under `$XDG_CACHE_HOME/revelio/` for 6h.
- **Files / artifacts**: `lib/update.sh`, change in `revelio.sh`.
- **Dependencies**: I (must have releases to compare against), benefits from D.
- **Acceptance**: `revelio self-update --check` prints current vs latest; running
  on each install method takes the documented action; `--dry-run` makes no changes.
- **Effort**: low.

---

## 2. CLI polish

### B — Shell completions

- **Status**: proposed
- **Goal**: `revelio completion <bash|zsh|fish>` prints completion script to stdout.
- **Why**: standard for serious CLIs (kubectl, gh, rg, fzf). Users hitting Tab
  expect commands and flags to autocomplete.
- **Steps**:
  1. New `lib/completion.sh`; wire `completion` command in `revelio.sh`.
  2. Single source of truth for commands + flags (extract from existing
     `_show_usage` into a structured table that completion + help share).
  3. Generate per-shell scripts:
     - **bash**: `complete -F _revelio revelio`.
     - **zsh**: `#compdef revelio` with `_arguments`.
     - **fish**: `complete -c revelio ...`.
  4. Document install paths in README:
     - bash: `revelio completion bash > /etc/bash_completion.d/revelio`.
     - zsh: `revelio completion zsh > "${fpath[1]}/_revelio"`.
     - fish: `revelio completion fish > ~/.config/fish/completions/revelio.fish`.
  5. Homebrew formula (track A) installs into the right dirs automatically.
- **Files / artifacts**: `lib/completion.sh`, `revelio.sh` wiring, README section.
- **Dependencies**: none (independent of I).
- **Acceptance**: each `completion <shell>` output sources cleanly in that shell;
  Tab completes commands, top-level flags, and subcommand-specific flags.
- **Effort**: medium.

---

## 3. Visibility & demos

### E — HTML report renderer

- **Status**: proposed
- **Goal**: `revelio report --format html [--output <path>]` writes a
  self-contained HTML report styled with the brand palette.
- **Why**: shareable artifact (paste in Slack / attach to issue / commit to
  publish repo). JSON/markdown/SARIF/CSV are great for machines; HTML is great
  for humans.
- **Steps**:
  1. New `lib/report_html.sh`.
  2. Reuse the existing `report.json` schema; do not re-collect.
  3. Single self-contained HTML (inline CSS, no remote assets) using colors from
     [`docs/BRAND.md`](BRAND.md).
  4. Sections: summary header, advisories table with severity badges,
     parent-package attribution, remediation suggestions, scanner errors.
  5. Wire into `revelio.sh report` as a new `--format html` option (current
     formats: text/json/markdown).
  6. Add a smoke test step that asserts the HTML contains `<title>Revelio report</title>`
     and at least one severity badge.
- **Files / artifacts**: `lib/report_html.sh`, change in `revelio.sh`,
  `ci-smoke.sh` extension.
- **Dependencies**: none.
- **Acceptance**: the rendered HTML opens in a browser with no console errors,
  matches brand colors, and survives offline (no remote fonts/scripts).
- **Effort**: medium.

### F — VHS or asciinema demo

- **Status**: proposed
- **Goal**: short looping recording of a real `revelio scan --offline` + `revelio report`
  embedded in README and the Pages landing page.
- **Why**: a moving demo at the top of the README converts curiosity to install
  far better than prose. Standard for CLIs (charm tools, fzf, lazygit).
- **Steps**:
  1. Pick tooling: **VHS** (charmbracelet/vhs) — preferred for clean, scriptable
     SVG/GIF output. Fallback: asciinema if VHS proves heavy.
  2. Add `demo/scan.tape` (or `.cast`).
  3. Tape steps: `revelio scan --offline` against a sample manifest, scroll
     report summary, `revelio report --format markdown` snippet.
  4. Render `assets/demo.gif` (or `.svg`) and commit.
  5. Embed under the logo block in README; embed in `docs/index.html`.
  6. Document re-recording in `demo/README.md`.
- **Files / artifacts**: `demo/scan.tape`, `assets/demo.{gif,svg}`,
  `demo/README.md`, edits to `README.md` and `docs/index.html`.
- **Dependencies**: none. Best paired with E so the demo can show the HTML report.
- **Acceptance**: GIF/SVG renders below 2 MB, loops cleanly, and is referenced
  from both README and the Pages landing page.
- **Effort**: low–medium.

---

## 4. Quality

### G — Bats-core unit tests

- **Status**: proposed
- **Goal**: real unit coverage for `lib/*.sh` helpers; current `ci-smoke.sh` only
  does end-to-end flow.
- **Why**: end-to-end tests are slow and miss edge cases. Bats is the standard
  for serious bash projects (bats-core itself, sherlock, holman/dotfiles).
- **Steps**:
  1. Add `tests/` directory; pin bats-core via git submodule or
     `tests/bats/install.sh`.
  2. One `.bats` file per library: `tests/core.bats`, `tests/file.bats`,
     `tests/platform.bats`, `tests/diff.bats`, `tests/publish.bats`.
  3. Mock external commands via PATH shimming (e.g., a local `bin/` dir prepended
     to `PATH` containing fake `git`, `curl`, `brew`).
  4. Cover at minimum:
     - `lib/diff.sh`: severity threshold filtering, format outputs, slurpfile path.
     - `lib/platform.sh`: scheduler chooser per OS.
     - `lib/publish.sh`: dry-run path, force flag.
     - `lib/core.sh`: `require_param`, `trim`, `to_lowercase`.
     - `lib/file.sh`: `path_normalize`, `is_absolute_path`.
  5. New CI job in `.github/workflows/ci.yml` (matrix: macOS + Ubuntu) that runs
     bats alongside smoke tests.
  6. Document local run in `CONTRIBUTING.md` (whenever that lands per LAUNCH.md).
- **Files / artifacts**: `tests/`, `.github/workflows/ci.yml` job addition.
- **Dependencies**: none.
- **Acceptance**: bats job passes on both macOS and Ubuntu runners; coverage
  spans every `lib/*.sh` module.
- **Effort**: medium.

### H — OSV response cache

- **Status**: proposed
- **Goal**: cache OSV API responses on disk to speed repeat scans and reduce
  load on a public API.
- **Why**: re-running scans (developer iteration, scheduled runs every hour)
  hammers OSV with mostly-identical queries. A small TTL'd cache cuts wall time
  significantly.
- **Steps**:
  1. Cache dir: `${XDG_CACHE_HOME:-$HOME/.cache}/revelio/osv/`.
  2. Key: SHA256 of `ecosystem|package|version`. Value: gzipped JSON response.
  3. TTL: configurable via `defaults.osvCacheTtlHours` in `revelio.config.json`
     (default 24).
  4. New CLI flags: `--no-cache` (bypass and refresh), `--clear-cache` (purge then exit).
  5. Add cache hit / miss / stale counters; render in scan summary.
  6. Apply the same pattern to npm/pip/cargo lookups (separate subdirs) — but
     ship OSV first.
  7. `lib/security.sh` already does OSV batching (`osvBatchSize`); slot the cache
     between batch construction and HTTP call.
- **Files / artifacts**: edits to `lib/security.sh`, `revelio.config.json`,
  smoke test extension.
- **Dependencies**: none.
- **Acceptance**: second consecutive `revelio scan` against the same inventory
  shows >50% cache hit ratio and measurable wall-time reduction; `--no-cache`
  bypasses; `--clear-cache` empties the dir.
- **Effort**: medium.

---

## 5. Project hygiene

### K — Dependabot for GitHub Actions

- **Status**: proposed
- **Goal**: weekly auto-PRs that bump pinned action versions in `.github/workflows/`.
- **Why**: actions silently drift; pinning to floating tags is risky and pinning
  to SHAs without auto-bumps means falling behind on security fixes.
- **Steps**:
  1. Add `.github/dependabot.yml` with the `github-actions` ecosystem,
     `directory: "/"`, `schedule.interval: "weekly"`.
  2. Optional: add a labels block (`dependencies`, `ci`).
- **Files / artifacts**: `.github/dependabot.yml`.
- **Dependencies**: none. Works while repo is private.
- **Acceptance**: Dependabot opens its first PR within a week of merge.
- **Effort**: trivial.

### L — OSSF Scorecard workflow

- **Status**: proposed
- **Goal**: continuous quality/security scoring with a public badge.
- **Why**: visible signal of project hygiene to potential users and contributors;
  catches risky workflow patterns.
- **Steps**:
  1. Add `.github/workflows/scorecard.yml` per OSSF template.
  2. Set `publish_results: true` *only after* the repo flips public.
  3. Add Scorecard badge to README header (alongside CI badge).
- **Files / artifacts**: `.github/workflows/scorecard.yml`, README badge edit.
- **Dependencies**: badge / `publish_results` requires the repo to be public
  (see [`LAUNCH.md`](LAUNCH.md)). The workflow itself can run privately first.
- **Acceptance**: workflow runs green; once public, badge in README links to the
  current Scorecard report.
- **Effort**: trivial.

---

## Explicitly out of scope here

- **License / SECURITY.md / CONTRIBUTING.md / issue templates / repo description /
  topics** — covered by [`LAUNCH.md`](LAUNCH.md).
- **GitHub Action wrapper** (a reusable `uses: a-magdy/revelio-action@v1`) —
  intentionally deferred.
