#!/usr/bin/env bash
# Platform detection and per-OS defaults for revelio.
#
# This module is the single source of truth for "what kind of host am I on?".
# Every other library should ask this module rather than calling `uname` or
# hardcoding paths like `/opt/homebrew`. It enables Linux portability without
# scattering OS checks throughout `lib/security.sh`.

if ! declare -f print_error >/dev/null 2>&1; then
  # shellcheck source=core.sh
  # shellcheck disable=SC1091
  source "$(dirname "${BASH_SOURCE[0]}")/core.sh"
fi

#===================================================================================================
# OS / arch detection
#===================================================================================================

# Detect the host operating system family.
# Outputs: macos | linux | unsupported
platform_os() {
  case "${OSTYPE:-}" in
    darwin*) printf '%s\n' "macos" ;;
    linux*)  printf '%s\n' "linux" ;;
    *)
      # Fall back to uname for shells that don't expose OSTYPE.
      case "$(uname -s 2>/dev/null)" in
        Darwin) printf '%s\n' "macos" ;;
        Linux)  printf '%s\n' "linux" ;;
        *)      printf '%s\n' "unsupported" ;;
      esac
      ;;
  esac
}

# Detect the host CPU architecture, normalised to common labels.
# Outputs: arm64 | x86_64 | <raw uname -m>
platform_arch() {
  local raw
  raw="$(uname -m 2>/dev/null || echo unknown)"
  case "$raw" in
    arm64|aarch64) printf '%s\n' "arm64" ;;
    x86_64|amd64)  printf '%s\n' "x86_64" ;;
    *)             printf '%s\n' "$raw" ;;
  esac
}

# Detect the Linux distribution family from /etc/os-release.
# Useful for picking the right native package manager and OSV ecosystem.
# Outputs: debian | ubuntu | fedora | rhel | centos | rocky | almalinux | suse |
#          opensuse | arch | alpine | unknown
platform_linux_distro() {
  if [[ "$(platform_os)" != "linux" ]]; then
    printf '%s\n' "unknown"
    return 0
  fi

  if [[ -r /etc/os-release ]]; then
    local id="" id_like=""
    # shellcheck disable=SC1091
    id="$(. /etc/os-release && printf '%s\n' "${ID:-}")"
    # shellcheck disable=SC1091
    id_like="$(. /etc/os-release && printf '%s\n' "${ID_LIKE:-}")"

    case "$id" in
      debian|ubuntu|fedora|rhel|centos|rocky|almalinux|arch|alpine)
        printf '%s\n' "$id"
        return 0
        ;;
      opensuse*|sles)
        printf '%s\n' "suse"
        return 0
        ;;
    esac

    # ID didn't match exactly; fall back to ID_LIKE for derivatives (e.g. Pop!_OS, Mint).
    case " $id_like " in
      *" debian "*|*" ubuntu "*) printf '%s\n' "debian"; return 0 ;;
      *" rhel "*|*" fedora "*|*" centos "*) printf '%s\n' "rhel"; return 0 ;;
      *" suse "*) printf '%s\n' "suse"; return 0 ;;
      *" arch "*) printf '%s\n' "arch"; return 0 ;;
    esac
  fi

  printf '%s\n' "unknown"
}

# Read the Linux distribution VERSION_ID from /etc/os-release.
# Useful for building OSV ecosystem identifiers like "Debian:12" or "Ubuntu:22.04".
# Outputs: VERSION_ID value, or empty string if unavailable.
platform_linux_os_version_id() {
  if [[ "$(platform_os)" != "linux" ]]; then
    return 0
  fi
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    ( . /etc/os-release && printf '%s\n' "${VERSION_ID:-}" )
  fi
}

#===================================================================================================
# Default paths
#===================================================================================================

# Resolve the default output directory for run artifacts.
# macOS: ~/.revelio (matches existing behavior).
# Linux: $XDG_STATE_HOME/revelio or ~/.local/state/revelio (XDG Base Directory Spec).
# Outputs: absolute path
platform_default_output_dir() {
  case "$(platform_os)" in
    linux)
      printf '%s\n' "${XDG_STATE_HOME:-$HOME/.local/state}/revelio"
      ;;
    *)
      printf '%s\n' "$HOME/.revelio"
      ;;
  esac
}

# Default Grype filesystem scan targets for a non-deep scan.
# macOS keeps the historical Homebrew/npm/pipx/cargo/go layout.
# Linux covers Linuxbrew + the same language toolchains in their typical homes.
# Outputs: newline-separated list of paths
platform_default_grype_targets() {
  case "$(platform_os)" in
    macos)
      cat <<'EOF'
/opt/homebrew/Cellar
/usr/local/Cellar
~/.npm-global/lib/node_modules
~/.local/pipx/venvs
~/.cargo/bin
~/go/bin
EOF
      ;;
    linux)
      cat <<'EOF'
/home/linuxbrew/.linuxbrew/Cellar
~/.linuxbrew/Cellar
~/.npm-global/lib/node_modules
~/.local/pipx/venvs
~/.local/share/pipx/venvs
~/.cargo/bin
~/go/bin
/var/lib/dpkg
/var/lib/rpm
/var/lib/pacman/local
/var/lib/snapd
/var/lib/flatpak
EOF
      ;;
  esac
}

# Extra Grype targets added when --deep-scan is enabled.
# macOS scans the user-facing app bundle directories.
# Linux scans /usr/local/bin and Flatpak/Snap install roots.
# Outputs: newline-separated list of paths
platform_default_grype_deep_targets() {
  case "$(platform_os)" in
    macos)
      cat <<'EOF'
/Applications
~/Applications
EOF
      ;;
    linux)
      cat <<'EOF'
/usr/local
/opt
~/.local
/var/lib/flatpak/app
~/.local/share/flatpak/app
/snap
EOF
      ;;
  esac
}

#===================================================================================================
# Scheduling backend
#===================================================================================================

# Pick the user-level scheduler this host should use.
# launchd      => macOS LaunchAgents (`launchctl bootstrap`)
# systemd-user => Linux user services (`systemctl --user`)
# cron         => fallback for Linux without an active user systemd manager
# none         => no usable scheduler (e.g. unsupported OS)
# Outputs: launchd | systemd-user | cron | none
platform_user_scheduler() {
  case "$(platform_os)" in
    macos)
      if command_exists launchctl; then
        printf '%s\n' "launchd"
      else
        printf '%s\n' "none"
      fi
      ;;
    linux)
      # Prefer user systemd when the runtime dir exists and systemctl is present.
      if command_exists systemctl && [[ -d "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/systemd" ]]; then
        printf '%s\n' "systemd-user"
      elif command_exists crontab; then
        printf '%s\n' "cron"
      else
        printf '%s\n' "none"
      fi
      ;;
    *)
      printf '%s\n' "none"
      ;;
  esac
}

#===================================================================================================
# Guards
#===================================================================================================

# Refuse to run on platforms revelio doesn't support yet.
# Returns: 0 on supported OS, 1 otherwise (with an explanatory message on stderr).
platform_require_supported() {
  local os
  os="$(platform_os)"
  if [[ "$os" == "unsupported" ]]; then
    print_error "Revelio does not yet support this operating system (OSTYPE=${OSTYPE:-unknown})."
    print_error "Supported: macOS, Linux."
    return 1
  fi
  return 0
}
