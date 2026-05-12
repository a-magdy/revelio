# Contributing to Revelio

Thanks for your interest in improving Revelio.

## Before you start

- For bug reports and feature requests, open a GitHub issue first so the use case
  or reproduction steps are documented.
- For larger code changes, start with an issue or discussion before opening a PR
  so the scope and approach are aligned early.

## Local validation

Run the repository smoke suite before opening a PR:

```bash
./ci-smoke.sh
```

If you change the Homebrew formula, also run the formula audit on a machine with
Homebrew available:

```bash
tap="local/revelio"
brew tap --custom-remote "$tap" "$(pwd)"
brew audit --strict --formula "$tap/revelio"
brew untap "$tap"
```

## Shell conventions

Revelio is a Bash-first project. Follow the shell conventions in
`.github/instructions/shell-scripts.instructions.md` for any `*.sh` changes:

- use `#!/usr/bin/env bash` with `set -euo pipefail`
- keep public functions `snake_case` and private helpers `_snake_case`
- double-quote variables and command substitutions
- use the shared `print_*` helpers from `lib/core.sh` for user-facing output
- never call `exit` inside library functions under `lib/`

## Documentation expectations

Keep user-facing and contributor-facing docs in sync with code changes:

- update `README.md` when command behavior, install guidance, or outputs change
- update `CLAUDE.md` when the repository map or public module API changes
