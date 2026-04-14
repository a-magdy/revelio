---
description: "Bash shell conventions for the revelio CLI."
applyTo: "**/*.sh"
---

# Shell Script Conventions and Library Usage

## Required Header

```bash
#!/usr/bin/env bash
set -euo pipefail
```

## Structure

- `#===` for major sections, `#---` for subsections
- Document purpose, usage, configuration, and warnings at the top of every script

## Naming

- Public functions: `snake_case`
- Private/internal functions: `_snake_case` (underscore prefix)

## Variables

- Always double-quote: `"$var"`, `"${var}"`, `"${array[@]}"`
- Quote command substitutions: `"$(command)"`
- Use `"${var:-default}"` for optional variables under `set -u`

## Functions

- Validate parameters with `require_param` at entry points
- Return codes: `0` = success, `1` = failure
- Never use `exit` inside library functions (`lib/*.sh`) — use `return`

## Documentation and Comments

Write comments that describe **what** and **why**, not **how** — the code shows how.
The goal is to make every function and logical block understandable enough to rewrite
in another language without reading the Bash implementation line by line.

### Function-level doc comments

Every public function must have a doc comment block immediately before it:

```bash
# Check whether a Homebrew formula or cask is installed.
# Handles versioned packages (e.g., python@3.13) by also checking @VERSION variants.
# $1 => package name (required)
# Returns: 0 if installed, 1 otherwise
is_brew_package_installed() {
```

Private/internal functions (`_snake_case`) should also have a doc comment when the
purpose is not obvious from the name alone.

### Parameter and return value docs

- Document every parameter with `# $N => description (required|optional)`.
- Document return values with `# Returns:` or `# Outputs:` when not obvious.
- For functions that set or export variables, document them with `# Sets:` or `# Exports:`.

### Code block comments

Use a short comment before any non-trivial block (5+ lines, branching logic,
pipeline chains, or embedded `jq`/`awk`/`sed`):

```bash
# Resolve the top-level global npm package that owns this transitive dependency
# by extracting the first element from the dependency path chain.
root_parent="$(echo "$dep_path" | awk -F' > ' '{print $1}')"
```

### Inline jq / awk / sed

Embedded DSL expressions (jq filters, awk programs, sed scripts) are especially
hard to port. Prefix them with a plain-English comment describing the
transformation:

```bash
# Group vulnerability findings by (manager, package, version) and pick the
# highest-severity entry from each group.
jq 'group_by([.manager, .package, .version]) | map(max_by(.severity))' "$file"
```

### Section banners

Use `#===` and `#---` banners to separate logical regions so a reader can
navigate without understanding every line:

```bash
#===================================
# Inventory Collectors
#===================================

#--- Homebrew ---
```

### What NOT to comment

- Obvious one-liners (`local name="$1"`)
- ShellCheck directives already serve as their own documentation
- Closing braces or `fi`/`done`/`esac` — only annotate these when the block is
  very long and the matching opener is far away

## Logging

- Use `print_success`, `print_error`, `print_info`, `print_warning` from `core.sh`
- Never use raw `echo` for user-facing output
- Source logging from `core.sh` — do not redefine `print_*` functions locally

## Platform

- Target macOS first

## ShellCheck

- All scripts must pass `shellcheck` with no warnings
- Suppress false positives with `# shellcheck disable=SC####` and a brief reason
- Add `# shellcheck source=` for sourced files

## Library Architecture

```text
lib/core.sh           →  logging, validation, string utilities (no dependencies)
lib/file.sh           →  file/path helpers (requires core)
lib/security.sh       →  inventory, scanning, enrichment, reporting (requires core + file)
```

- `core.sh` must be loaded before any other module
- Modules auto-source `core.sh` if not already loaded (via `declare -f` guard)
- `security.sh` is the main library; `revelio.sh` is the CLI entrypoint that sources it

### `lib/core.sh` — Core Utilities (no dependencies)

- **Logging**: `print_success()`, `print_error()`, `print_info()`, `print_warning()`
- **Validation**: `require_param()`, `command_exists()`, `check_dependencies()`
- **Strings**: `trim()`, `to_lowercase()`

### `lib/file.sh` — File/Path Operations (requires core)

- **Content**: `write_file_content()`
- **Paths**: `path_normalize()`, `is_absolute_path()`, `ensure_absolute_path()`
- **Directories**: `ensure_dir()`

### `lib/security.sh` — Revelio Core (~3000 lines)

Public API (`security_*`) and private helpers (`_security_*`). See `CLAUDE.md` for the full public API table.
