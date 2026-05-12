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

- [x] **Add a license** — the repo now ships with an MIT `LICENSE` file, and the README + Homebrew formula metadata are aligned.

---

## Community

- [x] **`CONTRIBUTING.md`** — added with issue guidance, `ci-smoke.sh`, and the shell conventions pointer.

- [x] **Issue templates** — `.github/ISSUE_TEMPLATE/bug_report.md` and `feature_request.md` are in place.

- [x] **`SECURITY.md`** — added with a private reporting path via GitHub Security Advisories so GitHub can surface the "Report a vulnerability" flow.

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

> For the deeper, ongoing backlog of OSS-CLI improvements (Homebrew tap, install
> script, shell completions, HTML report, demo recording, bats tests, OSV cache,
> release automation, self-update, Dependabot, Scorecard) see [`ROADMAP.md`](ROADMAP.md).

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
