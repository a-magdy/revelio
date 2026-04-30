#!/usr/bin/env bash
set -euo pipefail

#===================================================================================================
# Revelio Linux Smoke Harness Orchestrator
#
# Purpose:
#   Build and run ./ci-smoke.sh inside one or more Linux distro containers, covering the three
#   mainstream package-manager families (debian/apt, redhat/dnf, arch/pacman).
#
# Usage:
#   ./docker/run-linux-smoke.sh             # run all distros
#   ./docker/run-linux-smoke.sh ubuntu      # run a single distro
#   ./docker/run-linux-smoke.sh fedora
#   ./docker/run-linux-smoke.sh arch
#   ./docker/run-linux-smoke.sh all
#===================================================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=../lib/core.sh
# shellcheck disable=SC1091
source "$REPO_ROOT/lib/core.sh"

ALL_DISTROS=(ubuntu fedora arch)

usage() {
  cat <<'EOF'
Usage: run-linux-smoke.sh [distro]

  distro   One of: ubuntu, fedora, arch, all (default: all)
EOF
}

# Map short distro name => Dockerfile suffix (arch uses Dockerfile.archlinux).
dockerfile_for() {
  local distro="$1"
  case "$distro" in
    arch) printf '%s\n' "$SCRIPT_DIR/Dockerfile.archlinux" ;;
    *)    printf '%s\n' "$SCRIPT_DIR/Dockerfile.$distro" ;;
  esac
}

run_distro() {
  local distro="$1"
  local image="revelio-smoke-${distro}"
  local dockerfile
  dockerfile="$(dockerfile_for "$distro")"

  if [[ ! -f "$dockerfile" ]]; then
    print_error "No Dockerfile for distro '$distro' (expected $dockerfile)"
    return 1
  fi

  print_info "Building $image from $dockerfile..."
  docker build -t "$image" -f "$dockerfile" "$SCRIPT_DIR"

  print_info "Running ci-smoke.sh inside $image..."
  docker run --rm \
    -v "$REPO_ROOT:/work" \
    -w /work \
    "$image" \
    bash ./ci-smoke.sh
}

main() {
  local target="${1:-all}"

  case "$target" in
    -h|--help)
      usage
      return 0
      ;;
  esac

  check_dependencies docker git

  local distros=()
  if [[ "$target" == "all" ]]; then
    distros=("${ALL_DISTROS[@]}")
  else
    distros=("$target")
  fi

  local results=()
  local overall_rc=0

  for distro in "${distros[@]}"; do
    local rc=0
    if run_distro "$distro"; then
      results+=("✅ $distro")
    else
      rc=$?
      results+=("❌ $distro (exit $rc)")
      overall_rc=1
    fi
  done

  printf '\n'
  print_info "Linux smoke summary:"
  for line in "${results[@]}"; do
    printf '  %s\n' "$line"
  done

  if [[ $overall_rc -eq 0 ]]; then
    print_success "All requested distros passed."
  else
    print_error "One or more distros failed."
  fi

  return $overall_rc
}

main "$@"
