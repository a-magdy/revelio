# Linux Smoke Harness

This directory contains Docker-based smoke harnesses that run Revelio's `ci-smoke.sh` inside
representative Linux distros, so contributors developing on macOS can validate that the CLI
installs, runs, and produces correct artifacts on Linux.

## What it covers

The harness runs the existing `./ci-smoke.sh` (shellcheck + the in-tree smoke checks) inside
one container per distro family:

| Distro   | Family        | Package manager exercised |
| -------- | ------------- | ------------------------- |
| `ubuntu` | debian-family | `dpkg` / `apt`            |
| `fedora` | redhat-family | `rpm` / `dnf`             |
| `arch`   | arch-family   | `pacman`                  |

These three families cover the mainstream Linux package-management approaches. Validating the
Bash code paths against all three is sufficient confidence for the CLI's portability story.

## Requirements

- `docker` (or any Docker-compatible CLI on `$PATH`)
- `git` (used to locate the repo root for the bind mount)

That's it — everything else is provisioned inside the containers.

## Usage

From the repo root:

```bash
# Run all three distros (default)
./docker/run-linux-smoke.sh

# Run a single distro
./docker/run-linux-smoke.sh ubuntu
./docker/run-linux-smoke.sh fedora
./docker/run-linux-smoke.sh arch
```

The orchestrator streams build and test output live, then prints a summary table:

```
Linux smoke summary:
  ✅ ubuntu
  ✅ fedora
  ❌ arch (exit 1)
```

It exits non-zero if any distro fails, so it's safe to wire into CI.

## Caveats

- **Snap and Flatpak runtime daemons are not exercised.** Both rely on init systems (`systemd`)
  and user sessions that aren't present in plain containers. The harness validates the
  **collector code paths** in `lib/security.sh` (the script must run cleanly when these tools
  are absent or return empty inventories), not the runtime daemons themselves.
- **Network-dependent scanners** (OSV, npm audit, etc.) will run if the container has network
  access. To skip them locally, set the relevant config flags before invoking — or rely on the
  defaults baked into `ci-smoke.sh`.
- **Arch is a rolling distro.** `archlinux:latest` may shift under you. If you need fully
  reproducible runs, pin the base image to a specific date tag (e.g.
  `archlinux:base-YYYYMMDD.x.NNNNNN`) in `Dockerfile.archlinux`.

## Adding a new distro

1. Create `docker/Dockerfile.<name>` following the existing pattern:
   - Pinned base image
   - Install `bash`, `jq`, `curl`, `git`, `ca-certificates`, and `shellcheck` in one `RUN` layer
   - Clean the package manager cache
   - `WORKDIR /work`
   - `CMD ["bash", "./ci-smoke.sh"]`
2. Add the distro short-name to the `ALL_DISTROS` array near the top of
   `docker/run-linux-smoke.sh`. If the Dockerfile suffix doesn't match the short name (as with
   `arch` → `Dockerfile.archlinux`), extend the `dockerfile_for` mapping too.
3. Update the table in this README.
