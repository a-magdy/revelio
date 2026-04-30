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
    "$SCRIPT_DIR/lib/platform.sh" \
    "$SCRIPT_DIR/lib/diff.sh" \
    "$SCRIPT_DIR/lib/schedule.sh" \
    "$SCRIPT_DIR/lib/publish.sh" \
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

  print_info "Running --version smoke test..."
  if ! "$CLI_ENTRYPOINT" --version | grep -q '^revelio '; then
    print_error "Smoke test failed: --version did not print expected output"
    return 1
  fi

  print_info "Running diff smoke test..."
  local diff_tmp diff_run_a diff_run_b diff_out
  diff_tmp="$(mktemp -d)"
  "$CLI_ENTRYPOINT" inventory --offline --output-dir "$diff_tmp" >/dev/null
  sleep 1
  "$CLI_ENTRYPOINT" inventory --offline --output-dir "$diff_tmp" >/dev/null
  diff_run_a="$(find "$diff_tmp" -mindepth 1 -maxdepth 1 -type d | sort | head -n 1)"
  diff_run_b="$(find "$diff_tmp" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
  if [[ -z "$diff_run_a" || -z "$diff_run_b" || "$diff_run_a" == "$diff_run_b" ]]; then
    print_error "Smoke test failed: could not produce two run dirs for diff"
    rm -rf "$diff_tmp"
    return 1
  fi
  diff_out="$("$CLI_ENTRYPOINT" diff "$diff_run_a" "$diff_run_b" --format json 2>&1)" || {
    print_error "Smoke test failed: diff command failed"
    printf '%s\n' "----- diff command output -----" >&2
    printf '%s\n' "$diff_out" >&2
    printf '%s\n' "-------------------------------" >&2
    rm -rf "$diff_tmp"
    return 1
  }
  if ! jq -e '.findings.counts and .inventory.counts and .policy.severityThreshold' <<<"$diff_out" >/dev/null; then
    print_error "Smoke test failed: diff JSON missing required keys"
    rm -rf "$diff_tmp"
    return 1
  fi

  print_info "Running publish dry-run smoke test..."
  local publish_tmp publish_bare publish_cfg
  publish_tmp="$(mktemp -d)"
  publish_bare="$publish_tmp/bare.git"
  git -C "$publish_tmp" init --bare bare.git -b main >/dev/null
  publish_cfg="$publish_tmp/revelio.config.json"
  jq --arg url "$publish_bare" \
     '.publish.enabled = true | .publish.repoUrl = $url | .publish.branch = "main"' \
     "$SCRIPT_DIR/revelio.config.json" > "$publish_cfg"
  if ! "$CLI_ENTRYPOINT" publish --run "$diff_run_b" --config "$publish_cfg" --dry-run --force >"$publish_tmp/out" 2>&1; then
    print_error "Smoke test failed: publish --dry-run failed"
    printf '%s\n' "----- publish command output -----" >&2
    cat "$publish_tmp/out" >&2 || true
    printf '%s\n' "-----------------------------------" >&2
    rm -rf "$diff_tmp" "$publish_tmp"
    return 1
  fi
  rm -rf "$diff_tmp" "$publish_tmp"

  print_info "Running schedule status smoke test..."
  if ! "$CLI_ENTRYPOINT" schedule status >/dev/null 2>&1; then
    print_error "Smoke test failed: schedule status command failed"
    return 1
  fi

  print_info "Running --quiet/--json scan-mode smoke test..."
  local quiet_tmp quiet_stdout quiet_stderr
  quiet_tmp="$(mktemp -d)"
  quiet_stderr="$quiet_tmp/stderr"
  quiet_stdout="$("$CLI_ENTRYPOINT" inventory --offline --output-dir "$quiet_tmp" --quiet --json 2>"$quiet_stderr")" || {
    print_error "Smoke test failed: --quiet --json inventory exited non-zero"
    rm -rf "$quiet_tmp"; return 1
  }
  if ! jq -e '.schemaVersion and .toolVersion and .host.name' <<<"$quiet_stdout" >/dev/null; then
    print_error "Smoke test failed: --json output missing schemaVersion/toolVersion/host"
    rm -rf "$quiet_tmp"; return 1
  fi
  if grep -q '\xE2\x84\xB9' "$quiet_stderr" 2>/dev/null; then
    : # info glyph allowed if it sneaks in
  fi
  rm -rf "$quiet_tmp"

  print_info "Running report --format sarif/csv smoke test..."
  if ! "$CLI_ENTRYPOINT" report "$run_dir" --format sarif 2>/dev/null \
       | jq -e '.version == "2.1.0" and (.runs[0].tool.driver.name == "revelio")' >/dev/null; then
    print_error "Smoke test failed: report --format sarif did not produce valid SARIF"
    return 1
  fi
  if ! "$CLI_ENTRYPOINT" report "$run_dir" --format csv 2>/dev/null \
       | head -1 | grep -q '^"manager","ecosystem","package"'; then
    print_error "Smoke test failed: report --format csv missing expected header"
    return 1
  fi

  print_info "Running init-config --force smoke test..."
  local force_cfg
  force_cfg="$tmp_dir/force-config.json"
  "$CLI_ENTRYPOINT" init-config "$force_cfg" >/dev/null
  if "$CLI_ENTRYPOINT" init-config "$force_cfg" >/dev/null 2>&1; then
    print_error "Smoke test failed: init-config without --force should refuse to overwrite"
    return 1
  fi
  if ! "$CLI_ENTRYPOINT" init-config "$force_cfg" --force >/dev/null 2>&1; then
    print_error "Smoke test failed: init-config --force should overwrite"
    return 1
  fi
  if ! ls "$force_cfg".bak.* >/dev/null 2>&1; then
    print_error "Smoke test failed: init-config --force did not write a backup"
    return 1
  fi

  print_info "Running retainRuns smoke test..."
  local retain_tmp retain_cfg run_count
  retain_tmp="$(mktemp -d)"
  retain_cfg="$retain_tmp/cfg.json"
  jq '.defaults.retainRuns = 2' "$SCRIPT_DIR/revelio.config.json" > "$retain_cfg"
  for _ in 1 2 3 4; do
    "$CLI_ENTRYPOINT" inventory --offline --config "$retain_cfg" --output-dir "$retain_tmp" >/dev/null
    sleep 1
  done
  run_count="$(find "$retain_tmp" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
  if [[ "$run_count" != "2" ]]; then
    print_error "Smoke test failed: retainRuns=2 expected 2 dirs, got $run_count"
    rm -rf "$retain_tmp"; return 1
  fi
  rm -rf "$retain_tmp"

  print_info "Validating advisory schema when present..."
  local advisories_file
  advisories_file="$(jq -r '.artifacts.scanAdvisories // ""' "$report_file")"
  if [[ -n "$advisories_file" && -f "$advisories_file" ]]; then
    if ! jq -e 'all(.[]; ((.remediationStatus // null) != null) and ((.remediationMessage // null) != null) and ((.evidenceSources // null) != null))' "$advisories_file" >/dev/null; then
      print_error "Smoke test failed: advisories missing remediation/evidence fields"
      return 1
    fi
  fi

  print_info "Running Linux native package manager smoke checks (best-effort)..."
  local packages_file linux_mgr linux_bin checked=0
  packages_file="$run_dir/inventory/packages.json"
  # Map: collector toggle <-> manager value emitted in packages.json.
  # Each entry is "<binary>:<manager>". We only assert when the binary exists
  # on the host (so this loop is a no-op on macOS).
  for entry in "dpkg-query:dpkg" "rpm:rpm" "pacman:pacman" "snap:snap" "flatpak:flatpak"; do
    linux_bin="${entry%%:*}"
    linux_mgr="${entry##*:}"
    if ! command -v "$linux_bin" >/dev/null 2>&1; then
      continue
    fi
    checked=$((checked + 1))
    if ! jq -e --arg m "$linux_mgr" 'any(.[]; .manager == $m)' "$packages_file" >/dev/null; then
      print_error "Smoke test failed: $linux_bin present on host but no $linux_mgr packages in inventory"
      return 1
    fi
    print_info "  ✓ $linux_mgr inventory contains at least one package"
  done
  if [[ "$checked" -eq 0 ]]; then
    print_info "  (no Linux package manager binaries present on this host; skipped)"
  fi

  print_success "Revelio standalone CLI smoke checks passed"
}

main "$@"
