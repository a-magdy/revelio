# Going Public — Launch Checklist

Things to do before or immediately after making the repo public.

---

## Brand & GitHub Settings

- [ ] **Enable GitHub Pages** — Settings → Pages → Source → **GitHub Actions** → Save
  The landing page (`docs/index.html`) deploys automatically on next push to `main`.

- [ ] **Upload social preview** — Settings → (scroll to) Social preview → upload `assets/social-preview.png`
  Only available after the repo is public.

- [ ] **Add repo description** — Settings → (top of General) — short one-liner, e.g.:
  *"Host-level dependency audit CLI for macOS and Linux"*

- [ ] **Add topics** — Settings → Topics — suggested:
  `bash`, `cli`, `security`, `vulnerability-scanner`, `package-manager`, `macos`, `linux`, `devtools`, `audit`

- [ ] **Pin the repo** on your GitHub profile if relevant

---

## Legal

- [ ] **Add a license** — the README currently says "This project does not yet have a license."
  Recommended: **MIT** (permissive, widely expected for CLI tools) or **Apache 2.0** (adds patent clause).
  Add a `LICENSE` file at the root — GitHub can generate it for you under Settings → scroll to bottom.

---

## Community

- [ ] **`CONTRIBUTING.md`** — even a short one. Cover: how to open an issue, how to run `ci-smoke.sh`, shell conventions pointer (`shell-scripts.instructions.md`).

- [ ] **Issue templates** — add `.github/ISSUE_TEMPLATE/` with two templates:
  - `bug_report.md` — steps to reproduce, OS, Bash version, manager versions
  - `feature_request.md` — use-case, current workaround

- [ ] **`SECURITY.md`** — the README already explains how to report privately; promote it to a dedicated file so GitHub shows the "Report a vulnerability" button prominently.
  Content: point to GitHub Security Advisories (already in README).

---

## Release

- [ ] **Tag a version** — create `v0.1.0` once you're happy with the state.
  ```bash
  git tag -a v0.1.0 -m "Initial public release"
  git push origin v0.1.0
  ```
  Then create a GitHub Release from the tag with a short changelog.

- [ ] **Set `REVELIO_VERSION`** — confirm the version string in `revelio.sh` matches the tag before pushing.

---

## Suggested Additions for the First Public Release

These aren't blockers, but they'd make a strong first impression:

| Idea | Value | Effort |
|---|---|---|
| **Homebrew formula** — tap or core formula so users can `brew install revelio` | Huge discovery lift | Medium |
| **`install.sh` one-liner** — `curl | bash` convenience script that clones and optionally symlinks | Lower friction than cloning manually | Low |
| **Changelog (`CHANGELOG.md`)** | Expected by open-source users | Low |
| **Screenshot / demo GIF in README** — a `asciinema` or `vhs` recording of a real scan | Shows the tool in action before they install | Medium |
| **CI badge on README** | Already there ✓ | Done |
| **Platform badges on README** | Already there ✓ | Done |
| **`man` page or `--help` completions** — shell completion for `zsh`/`bash` | Quality-of-life | Medium |
| **`CODEOWNERS`** | Useful if you add contributors | Low |
