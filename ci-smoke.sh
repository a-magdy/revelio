#!/usr/bin/env bash
set -euo pipefail

#===================================================================================================
# Revelio CLI Smoke Checks
#
# Purpose:
#   Run lightweight quality gates for the standalone revelio CLI package.
#
# Usage:
#   ./ci-smoke.sh
#===================================================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_ENTRYPOINT="$SCRIPT_DIR/revelio.sh"

# shellcheck source=lib/core.sh
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/core.sh"

main() {
  check_dependencies shellcheck jq

  print_info "Running shellcheck..."
  shellcheck -x \
    "$CLI_ENTRYPOINT" \
    "$SCRIPT_DIR/lib/core.sh" \
    "$SCRIPT_DIR/lib/file.sh" \
    "$SCRIPT_DIR/lib/security.sh"

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "${tmp_dir:-}"' EXIT

  print_info "Running CLI smoke test..."
  "$CLI_ENTRYPOINT" help >/dev/null
  "$CLI_ENTRYPOINT" inventory --offline --output-dir "$tmp_dir" >/dev/null

  local run_dir report_file mode
  run_dir="$(find "$tmp_dir" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  report_file="$run_dir/report.json"

  if [[ -z "$run_dir" || ! -f "$report_file" ]]; then
    print_error "Smoke test failed: report.json not produced"
    return 1
  fi

  mode="$(jq -r '.mode // ""' "$report_file")"
  if [[ "$mode" != "inventory" ]]; then
    print_error "Smoke test failed: expected mode=inventory, got mode=$mode"
    return 1
  fi

  print_info "Running no-arg report smoke test..."
  local report_output
  report_output="$("$CLI_ENTRYPOINT" report --output-dir "$tmp_dir" 2>&1)" || {
    print_error "Smoke test failed: no-arg report command failed"
    return 1
  }

  if [[ -z "$report_output" ]]; then
    print_error "Smoke test failed: no-arg report produced no output"
    return 1
  fi

  print_info "Running why command smoke test..."
  local why_output
  why_output="$("$CLI_ENTRYPOINT" why jq --manager brew 2>&1)" || {
    print_warning "Why command smoke test skipped (jq via brew not found)"
    why_output="SKIPPED"
  }

  if [[ "$why_output" != "SKIPPED" && -z "$why_output" ]]; then
    print_error "Smoke test failed: why command produced no output"
    return 1
  fi

  print_info "Running init-config smoke test..."
  local generated_config
  generated_config="$tmp_dir/generated-revelio.config.json"
  "$CLI_ENTRYPOINT" init-config "$generated_config" >/dev/null

  if [[ ! -f "$generated_config" ]]; then
    print_error "Smoke test failed: init-config did not create config file"
    return 1
  fi

  if ! jq -e '.scanners.npmReleaseChannelChecks == true' "$generated_config" >/dev/null; then
    print_error "Smoke test failed: expected scanners.npmReleaseChannelChecks=true in generated config"
    return 1
  fi

  print_info "Validating advisory schema when present..."
  local advisories_file
  advisories_file="$(jq -r '.artifacts.scanAdvisories // ""' "$report_file")"
  if [[ -n "$advisories_file" && -f "$advisories_file" ]]; then
    if ! jq -e 'all(.[]; ((.remediationStatus // null) != null) and ((.remediationMessage // null) != null) and ((.evidenceSources // null) != null))' "$advisories_file" >/dev/null; then
      print_error "Smoke test failed: advisories missing remediation/evidence fields"
      return 1
    fi
  fi

  print_success "Revelio standalone CLI smoke checks passed"
}

main "$@"
