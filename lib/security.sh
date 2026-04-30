#!/usr/bin/env bash
# Revelio utilities: machine inventory, vulnerability lookups, risk reporting
# Source this file to use revelio helpers from revelio.sh

# Ensure core/file modules are loaded
if ! declare -f print_error &>/dev/null; then
  # shellcheck source=./core.sh
  # shellcheck disable=SC1091
  source "$(dirname "${BASH_SOURCE[0]}")/core.sh"
fi
if ! declare -f write_file_content &>/dev/null; then
  # shellcheck source=./file.sh
  # shellcheck disable=SC1091
  source "$(dirname "${BASH_SOURCE[0]}")/file.sh"
fi
if ! declare -f platform_os &>/dev/null; then
  # shellcheck source=./platform.sh
  # shellcheck disable=SC1091
  source "$(dirname "${BASH_SOURCE[0]}")/platform.sh"
fi

#===================================================================================================
# Public API
#===================================================================================================

REVELIO_LAST_REPORT=""
REVELIO_LAST_RUN_DIR=""

# Single source of truth for the tool version. Surfaced via `revelio --version`,
# stamped into every `report.json` as `toolVersion`, and used by `revelio diff`
# to decide whether two reports were produced by compatible tool versions.
REVELIO_VERSION="0.2.0-dev"

# Schema version for `report.json`. Bump when the report shape changes in a way
# that consumers (diff, publish, downstream tooling) need to detect.
REVELIO_REPORT_SCHEMA_VERSION="1"

# Emit the default configuration JSON for the revelio workflow.
security_default_config_json() {
  local script_root bundled_config
  script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  bundled_config="$script_root/revelio.config.json"

  if command_exists jq && [[ -f "$bundled_config" ]] && jq -e '.' "$bundled_config" >/dev/null 2>&1; then
    cat "$bundled_config"
    return 0
  fi

  cat <<'JSON'
{
  "defaults": {
    "outputDir": null,
    "severityThreshold": "high",
    "failOnFindings": true,
    "failOnScannerErrors": true,
    "deepScan": false,
    "allowNetworkQueries": true,
    "osvBatchSize": 200,
    "osvDetailDelay": 0.1,
    "retainRuns": 0
  },
  "inventory": {
    "homebrew": true,
    "npmGlobal": true,
    "pythonPip": true,
    "pipx": true,
    "uvTools": true,
    "cargo": true,
    "rubyGems": true,
    "rubyGemsExcludeSystem": true,
    "goTools": true,
    "dotnetTools": true,
    "dpkg": true,
    "rpm": true,
    "pacman": true,
    "snap": true,
    "flatpak": true
  },
  "scanners": {
    "outdatedChecks": true,
    "osv": true,
    "npmAudit": true,
    "npmReleaseChannelChecks": true,
    "pipAudit": true,
    "cargoAudit": true,
    "grype": true,
    "grypeTargets": [
      "/opt/homebrew/Cellar",
      "/usr/local/Cellar",
      "/home/linuxbrew/.linuxbrew/Cellar",
      "~/.linuxbrew/Cellar",
      "~/.npm-global/lib/node_modules",
      "~/.local/pipx/venvs",
      "~/.local/share/pipx/venvs",
      "~/.cargo/bin",
      "~/go/bin",
      "/var/lib/dpkg",
      "/var/lib/rpm",
      "/var/lib/pacman/local",
      "/var/lib/snapd",
      "/var/lib/flatpak"
    ],
    "grypeDeepTargets": [
      "/Applications",
      "~/Applications",
      "/usr/local",
      "/opt",
      "~/.local",
      "/var/lib/flatpak/app",
      "~/.local/share/flatpak/app",
      "/snap"
    ]
  },
  "publish": {
    "enabled": false,
    "repoUrl": "",
    "branch": "main",
    "pathTemplate": "reports/{hostname}/{run-id}/",
    "commitMessageTemplate": "chore(revelio): scan {run-id} on {hostname}",
    "tokenEnvVar": "REVELIO_GIT_TOKEN"
  }
}
JSON
}

# Create a starter config file if one does not already exist.
# $1 => target config path
security_init_config_file() {
  require_param "${1:-}" "config_path" "security_init_config_file" || return 1
  local config_path="$1"
  local force="${2:-false}"

  if [[ -f "$config_path" && "$force" != "true" ]]; then
    print_warning "Config already exists: $config_path (use --force to overwrite)"
    return 1
  fi
  if [[ -f "$config_path" && "$force" == "true" ]]; then
    cp "$config_path" "$config_path.bak.$(date -u +%Y%m%dT%H%M%SZ)" 2>/dev/null || true
  fi

  local old_umask
  old_umask="$(umask)"
  umask 077

  ensure_dir "$(dirname "$config_path")"
  write_file_content "$config_path" "$(security_default_config_json)" || {
    umask "$old_umask"
    return 1
  }
  umask "$old_umask"

  chmod 600 "$config_path" 2>/dev/null || true
  print_success "Created config: $config_path"
}

# Build the effective config by merging defaults + optional file + CLI overrides.
# $1 => config file path (optional)
# $2 => output dir override (optional)
# $3 => severity override (optional: none|low|medium|high|critical)
# $4 => deep scan override (optional: true|false)
# $5 => fail on findings override (optional: true|false)
# $6 => network queries override (optional: true|false)
# $7 => fail on scanner errors override (optional: true|false)
security_build_effective_config() {
  local config_path="${1:-}"
  local output_override="${2:-}"
  local severity_override="${3:-}"
  local deep_override="${4:-}"
  local fail_override="${5:-}"
  local network_override="${6:-}"
  local scanner_fail_override="${7:-}"

  local defaults_json merged_json
  defaults_json="$(security_default_config_json)"
  merged_json="$defaults_json"

  if [[ -n "$config_path" ]]; then
    if [[ ! -f "$config_path" ]]; then
      print_error "Config file not found: $config_path"
      return 1
    fi
    if ! jq -e '.' "$config_path" >/dev/null 2>&1; then
      print_error "Invalid JSON config: $config_path"
      return 1
    fi
    merged_json="$(jq -n --argjson defaults "$defaults_json" --slurpfile user "$config_path" '$defaults * ($user[0] // {})')"
  fi

  if [[ -n "$severity_override" ]]; then
    severity_override="$(to_lowercase "$severity_override")"
    if ! _security_validate_severity "$severity_override"; then
      print_error "Invalid severity threshold: $severity_override"
      return 1
    fi
  fi

  if [[ -n "$deep_override" ]]; then
    deep_override="$(_security_normalize_boolean "$deep_override")"
    if [[ -z "$deep_override" ]]; then
      print_error "Invalid deep scan override: $4"
      return 1
    fi
  fi

  if [[ -n "$fail_override" ]]; then
    fail_override="$(_security_normalize_boolean "$fail_override")"
    if [[ -z "$fail_override" ]]; then
      print_error "Invalid fail override: $5"
      return 1
    fi
  fi

  if [[ -n "$network_override" ]]; then
    network_override="$(_security_normalize_boolean "$network_override")"
    if [[ -z "$network_override" ]]; then
      print_error "Invalid network override: $6"
      return 1
    fi
  fi

  if [[ -n "$scanner_fail_override" ]]; then
    scanner_fail_override="$(_security_normalize_boolean "$scanner_fail_override")"
    if [[ -z "$scanner_fail_override" ]]; then
      print_error "Invalid scanner failure override: $7"
      return 1
    fi
  fi

  jq -n \
    --argjson cfg "$merged_json" \
    --arg output_override "$output_override" \
    --arg severity_override "$severity_override" \
    --arg deep_override "$deep_override" \
    --arg fail_override "$fail_override" \
    --arg network_override "$network_override" \
    --arg scanner_fail_override "$scanner_fail_override" '
    $cfg
    | if $output_override != "" then .defaults.outputDir = $output_override else . end
    | if $severity_override != "" then .defaults.severityThreshold = $severity_override else . end
    | if $deep_override != "" then .defaults.deepScan = ($deep_override == "true") else . end
    | if $fail_override != "" then .defaults.failOnFindings = ($fail_override == "true") else . end
    | if $network_override != "" then .defaults.allowNetworkQueries = ($network_override == "true") else . end
    | if $scanner_fail_override != "" then .defaults.failOnScannerErrors = ($scanner_fail_override == "true") else . end
  '
}

# Execute inventory-only or full scan mode and persist a run report.
# $1 => mode ("inventory" or "scan")
# $2 => effective config JSON
security_run() {
  require_param "${1:-}" "mode" "security_run" || return 1
  require_param "${2:-}" "effective_config_json" "security_run" || return 1

  local mode="$1"
  local config_json="$2"

  if [[ "$mode" != "inventory" && "$mode" != "scan" ]]; then
    print_error "Unknown mode for security_run: $mode"
    return 1
  fi

  if ! jq -e '.' >/dev/null 2>&1 <<<"$config_json"; then
    print_error "security_run received invalid config JSON"
    return 1
  fi

  local output_dir_raw output_dir run_id run_dir generated_at old_umask
  output_dir_raw="$(jq -r '.defaults.outputDir // ""' <<<"$config_json")"
  if [[ -z "$output_dir_raw" || "$output_dir_raw" == "null" ]]; then
    output_dir_raw="$(platform_default_output_dir)"
  fi
  output_dir="$(_security_expand_path "$output_dir_raw")"
  if ! is_absolute_path "$output_dir"; then
    output_dir="$(ensure_absolute_path "$output_dir")"
  fi
  _security_validate_output_dir "$output_dir" || return 1

  output_dir="$(path_normalize "$output_dir")"
  run_id="$(_security_generate_run_id)"
  while [[ -e "$output_dir/$run_id" ]]; do
    run_id="$(_security_generate_run_id)"
  done
  run_dir="$output_dir/$run_id"
  generated_at="$(_security_timestamp_utc)"

  old_umask="$(umask)"
  umask 077
  if ! ensure_dir "$run_dir" \
    || ! ensure_dir "$run_dir/inventory" \
    || ! ensure_dir "$run_dir/outdated" \
    || ! ensure_dir "$run_dir/scans"; then
    umask "$old_umask"
    print_error "Failed to create revelio run directories under: $run_dir"
    return 1
  fi
  umask "$old_umask"

  if ! (
    # Trap interrupt and termination so background collectors don't keep running
    # after a Ctrl-C. The trap kills any direct child jobs of this subshell and
    # then re-raises the signal so the parent shell sees the standard exit code.
    trap '_security_handle_signal INT' INT
    trap '_security_handle_signal TERM' TERM

    _security_prepare_runtime_environment "$run_dir"

    write_file_content "$run_dir/effective-config.json" "$config_json"

    print_info "Collecting package inventory..."
    _security_collect_inventory "$config_json" "$run_dir/inventory"

    if [[ "$mode" == "scan" ]]; then
      if [[ "$(_config_bool "$config_json" ".scanners.outdatedChecks" "true")" == "true" ]]; then
        print_info "Collecting outdated package signals..."
        _security_collect_outdated "$config_json" "$run_dir/outdated"
      else
        write_file_content "$run_dir/outdated/items.json" "[]"
        write_file_content "$run_dir/outdated/checks.json" "[]"
        write_file_content "$run_dir/outdated/summary.json" '{"totalOutdated":0,"byManager":{},"checks":[]}'
      fi

      print_info "Running vulnerability checks..."
      _security_scan_vulnerabilities "$config_json" "$run_dir/inventory/packages.json" "$run_dir/scans"
    else
      write_file_content "$run_dir/outdated/items.json" "[]"
      write_file_content "$run_dir/outdated/checks.json" "[]"
      write_file_content "$run_dir/outdated/summary.json" '{"totalOutdated":0,"byManager":{},"checks":[]}'
      write_file_content "$run_dir/scans/findings.json" "[]"
      write_file_content "$run_dir/scans/scanners.json" "[]"
      write_file_content "$run_dir/scans/summary.json" '{"totalFindings":0,"bySeverity":{},"byScanner":{},"scanners":[]}'
    fi

    _security_build_report "$mode" "$config_json" "$generated_at" "$run_dir" "$run_dir/inventory" "$run_dir/outdated" "$run_dir/scans"
    _security_compute_policy "$run_dir/report.json"
  ); then
    print_error "Revelio execution failed. Partial artifacts may exist at: $run_dir"
    return 1
  fi

  REVELIO_LAST_RUN_DIR="$run_dir"
  REVELIO_LAST_REPORT="$run_dir/report.json"
  export REVELIO_LAST_RUN_DIR REVELIO_LAST_REPORT

  _security_prune_old_runs "$config_json" "$output_dir" "$run_dir"
}

# Best-effort signal handler used inside the security_run subshell. Kills any
# background jobs of the current subshell and re-raises the signal so the
# caller sees the standard 128+N exit code.
# $1 => signal name (INT or TERM)
_security_handle_signal() {
  local sig="${1:-INT}"
  local pids
  pids="$(jobs -p 2>/dev/null || true)"
  if [[ -n "$pids" ]]; then
    # shellcheck disable=SC2086
    kill -TERM $pids 2>/dev/null || true
    sleep 0.5
    # shellcheck disable=SC2086
    kill -KILL $pids 2>/dev/null || true
  fi
  trap - "$sig"
  kill -"$sig" $$ 2>/dev/null || true
}

# Prune older run directories under the output dir, keeping the N most recent.
# Controlled by config key `defaults.retainRuns`. A value <= 0 means "keep all"
# (current default for backwards compatibility).
# $1 => effective config JSON
# $2 => output dir
# $3 => current run dir (never pruned)
_security_prune_old_runs() {
  local config_json="$1"
  local output_dir="$2"
  local current_run_dir="$3"

  local keep
  keep="$(jq -r '.defaults.retainRuns // 0' <<<"$config_json" 2>/dev/null)"
  [[ "$keep" =~ ^[0-9]+$ ]] || keep=0
  if [[ "$keep" -le 0 ]]; then
    return 0
  fi

  local entries=()
  local entry
  while IFS= read -r entry; do
    [[ -n "$entry" && -d "$entry" ]] || continue
    [[ "$entry" == "$current_run_dir" ]] && continue
    entries+=("$entry")
  done < <(find "$output_dir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r)

  local total=${#entries[@]}
  # Keep N most recent (excluding the current run, which is always kept on top).
  # Effective ceiling for older runs is keep-1 because the current run counts.
  local ceiling=$(( keep - 1 ))
  [[ "$ceiling" -lt 0 ]] && ceiling=0

  if [[ "$total" -le "$ceiling" ]]; then
    return 0
  fi

  local i
  for (( i = ceiling; i < total; i++ )); do
    local victim="${entries[$i]}"
    # Defensive: only prune dirs that look like revelio runs (contain report.json
    # OR effective-config.json), to avoid nuking unrelated content if a user
    # points outputDir somewhere shared.
    if [[ -f "$victim/report.json" || -f "$victim/effective-config.json" ]]; then
      rm -rf "$victim"
    fi
  done
}

# Render a concise terminal summary for a report file.
# $1 => report file path
security_print_report_summary() {
  require_param "${1:-}" "report_file" "security_print_report_summary" || return 1
  local report_file="$1"

  if [[ ! -f "$report_file" ]]; then
    print_error "Report file not found: $report_file"
    return 1
  fi

  local run_dir mode pkg_count outdated_count vuln_count threshold matched should_fail scanner_failures
  local fail_on_scanner_errors policy_reasons
  local sev_critical sev_high sev_medium sev_low sev_unknown
  local findings_file advisories_file packages_file outdated_file

  run_dir="$(jq -r '.runDir // ""' "$report_file")"
  mode="$(jq -r '.mode // ""' "$report_file")"
  pkg_count="$(jq -r '.inventory.totalPackages // 0' "$report_file")"
  outdated_count="$(jq -r '.outdated.totalOutdated // 0' "$report_file")"
  vuln_count="$(jq -r '.vulnerabilities.totalFindings // 0' "$report_file")"
  threshold="$(jq -r '.policy.severityThreshold // "high"' "$report_file")"
  matched="$(jq -r '.policy.matchingFindings // 0' "$report_file")"
  should_fail="$(jq -r '.policy.shouldFail // false' "$report_file")"
  scanner_failures="$(jq -r '.policy.scannerFailureCount // 0' "$report_file")"
  fail_on_scanner_errors="$(jq -r 'if (.policy.failOnScannerErrors | type) == "boolean" then .policy.failOnScannerErrors else true end' "$report_file")"
  policy_reasons="$(jq -r '.policy.failureReasons // [] | join(", ")' "$report_file")"

  sev_critical="$(jq -r '.vulnerabilities.bySeverity.critical // 0' "$report_file")"
  sev_high="$(jq -r '.vulnerabilities.bySeverity.high // 0' "$report_file")"
  sev_medium="$(jq -r '.vulnerabilities.bySeverity.medium // 0' "$report_file")"
  sev_low="$(jq -r '.vulnerabilities.bySeverity.low // 0' "$report_file")"
  sev_unknown="$(jq -r '.vulnerabilities.bySeverity.unknown // 0' "$report_file")"

  findings_file="$(jq -r '.artifacts.scanFindings // ""' "$report_file")"
  advisories_file="$(jq -r '.artifacts.scanAdvisories // ""' "$report_file")"
  packages_file="$(jq -r '.artifacts.inventoryPackages // ""' "$report_file")"
  outdated_file="$(jq -r '.artifacts.outdatedItems // ""' "$report_file")"

  local sep
  sep="──────────────────────────────────────────────────"
  printf '\n'
  printf '%s◉%s  %srevelio%s  %s·  %s%s\n' \
    "$_C_GREEN" "$_C_RESET" "$_C_BOLD" "$_C_RESET" "$_C_PURPLE" "$mode" "$_C_RESET"
  printf '%s%s%s\n' "$_C_PURPLE" "$sep" "$_C_RESET"
  printf '%s  run  %s%s\n' "$_C_DIM" "$run_dir" "$_C_RESET"
  printf '\n'

  #--- Summary counts
  print_info "Inventory packages tracked: $pkg_count"
  print_info "Outdated packages: $outdated_count"
  print_info "Vulnerabilities: total=$vuln_count (critical=$sev_critical, high=$sev_high, medium=$sev_medium, low=$sev_low, unknown=$sev_unknown)"
  print_info "Scanner/collector failures: $scanner_failures (failOnScannerErrors=$fail_on_scanner_errors)"
  printf '\n'

  #--- Vulnerable packages table
  if [[ "$vuln_count" -gt 0 && -f "$advisories_file" ]]; then
    local advisory_count
    advisory_count="$(jq 'length' "$advisories_file")"
    if [[ "$advisory_count" -gt 0 ]]; then
      printf '%s  %-10s %-8s %-18s %-18s %-12s %-12s %-22s %s%s\n' \
        "$_C_BOLD" "SEVERITY" "MANAGER" "PACKAGE" "PARENT" "INSTALLED" "UPGRADE TO" "STATUS" "VULNS" "$_C_RESET"
      printf '%s  %-10s %-8s %-18s %-18s %-12s %-12s %-22s %s%s\n' \
        "$_C_DIM" "--------" "-------" "-------" "------" "---------" "----------" "------" "-----" "$_C_RESET"
      # Padding is computed inside jq before injecting escape codes to preserve column alignment.
      jq -r \
        --arg c_crit "$_C_CRIT" \
        --arg c_high "$_C_HIGH" \
        --arg c_med  "$_C_MED" \
        --arg c_low  "$_C_LOW" \
        --arg c_dim  "$_C_DIM" \
        --arg c_rst  "$_C_RESET" \
        '.[] |
          (if   .highestSeverity == "critical" then $c_crit
           elif .highestSeverity == "high"     then $c_high
           elif .highestSeverity == "medium"   then $c_med
           elif .highestSeverity == "low"      then $c_low
           else $c_dim end) as $col |
          (.highestSeverity | ascii_upcase | .[0:10] | . + " " * (10 - length)) as $sev |
          "  \($col)\($sev)\($c_rst)\(.manager | .[0:8] | . + " " * (8 - length))\(.package | .[0:18] | . + " " * (18 - length))\((.primaryParent // .package // "unknown") | .[0:18] | . + " " * (18 - length))\(.installedVersion | .[0:12] | . + " " * (12 - length))\((.recommendedVersion // "n/a") | .[0:12] | . + " " * (12 - length))\((.remediationStatus // "n/a") | .[0:22] | . + " " * (22 - length))\(.vulnerabilityCount)"' \
        "$advisories_file"
      printf '\n'

      #--- Dependency tree paths
      local has_dep_paths
      has_dep_paths="$(jq '[.[] | select((.dependencyPaths | length) > 0)] | length' "$advisories_file")"
      if [[ "$has_dep_paths" -gt 0 ]]; then
        printf '%s  🌳 DEPENDENCY TREE:%s\n' "${_C_PURPLE}${_C_BOLD}" "$_C_RESET"
        jq -r '.[] | select((.dependencyPaths | length) > 0) | "  → \(.package)@\(.installedVersion):\n\(.dependencyPaths | map("    " + .) | join("\n"))\n"' "$advisories_file"
      fi

      #--- Attack risk descriptions
      printf '%s  ⚡ ATTACK RISK SUMMARY:%s\n' "${_C_PURPLE}${_C_BOLD}" "$_C_RESET"
      jq -r '.[] | select((.attackDescriptions | length) > 0) | "  → \(.package)@\(.installedVersion): \(.attackDescriptions | join("; "))"' "$advisories_file"
      printf '\n'

      #--- Suggested upgrade commands
      local has_upgrade_commands
      has_upgrade_commands="$(jq '[.[] | select((.upgradeCommand // "") != "")] | length' "$advisories_file")"
      if [[ "$has_upgrade_commands" -gt 0 ]]; then
        printf '%s  🛠️  UPGRADE COMMANDS:%s\n' "${_C_PURPLE}${_C_BOLD}" "$_C_RESET"
        jq -r '.[] | select((.upgradeCommand // "") != "") | "  → \(.manager): \(.package)\n    parent: \(.primaryParent // "unknown")\n    command: \(.upgradeCommand)\n"' "$advisories_file"
      fi

      #--- Pending-release guidance
      local has_pending_release
      has_pending_release="$(jq '[.[] | select(.remediationStatus == "upstream-pending-release")] | length' "$advisories_file")"
      if [[ "$has_pending_release" -gt 0 ]]; then
        printf '%s  ⏳ HANG TIGHT (pending stable release):%s\n' "${_C_PURPLE}${_C_BOLD}" "$_C_RESET"
        jq -r '.[] | select(.remediationStatus == "upstream-pending-release") | "  → \(.manager): \(.package)\n    root: \(.rootPackage // "unknown")\n    \(.remediationMessage // .upgradeRationale // "Pending release-channel signal found.")\n"' "$advisories_file"
      fi

      #--- Upgrade rationale for critical/high
      local has_actionable
      has_actionable="$(jq '[.[] | select(.highestSeverity == "critical" or .highestSeverity == "high") | select((.remediationStatus // "") == "actionable-update-now") | select(.recommendedVersion != null)] | length' "$advisories_file")"
      if [[ "$has_actionable" -gt 0 ]]; then
        printf '%s  📋 UPGRADE RATIONALE (critical/high only):%s\n' "${_C_PURPLE}${_C_BOLD}" "$_C_RESET"
        jq -r '.[] | select(.highestSeverity == "critical" or .highestSeverity == "high") | select((.remediationStatus // "") == "actionable-update-now") | select(.recommendedVersion != null) | "  → \(.manager): \(.package) \(.installedVersion) → \(.recommendedVersion)\n    parent: \(.primaryParent // "unknown")\n    \(.remediationMessage // .upgradeRationale)\n    suggested command: \(.upgradeCommand // "n/a")\n"' "$advisories_file"
      fi
    fi
  fi

  #--- Policy result
  if [[ "$should_fail" == "true" ]]; then
    print_error "Policy failed: threshold='$threshold', matching_findings=$matched, scanner_failures=$scanner_failures${policy_reasons:+, reasons=$policy_reasons}"
  else
    print_success "Policy passed: threshold '$threshold' not exceeded"
  fi
  printf '\n'

  #--- File locations
  printf '%s  📁 KEY FILES:%s\n' "${_C_PURPLE}${_C_BOLD}" "$_C_RESET"
  printf '     Report:          %s\n' "$report_file"
  [[ -n "$findings_file" ]]  && printf '     Vulnerabilities:  %s\n' "$findings_file"
  [[ -n "$advisories_file" ]] && printf '     Advisories:       %s\n' "$advisories_file"
  [[ -n "$packages_file" ]]  && printf '     Packages:         %s\n' "$packages_file"
  [[ -n "$outdated_file" ]]  && printf '     Outdated:         %s\n' "$outdated_file"
  printf '\n'
}

# Return non-zero when report policy requires failure.
# $1 => report file path
security_report_exit_code() {
  require_param "${1:-}" "report_file" "security_report_exit_code" || return 1
  local report_file="$1"

  if [[ ! -f "$report_file" ]]; then
    print_error "Report file not found: $report_file"
    return 1
  fi

  local should_fail
  should_fail="$(jq -r '.policy.shouldFail // false' "$report_file")"
  if [[ "$should_fail" == "true" ]]; then
    return 2
  fi
  return 0
}

#===================================================================================================
# Private helpers
#===================================================================================================

# Extract a boolean value from a JSON config string with a typed default.
# $1 => JSON string
# $2 => jq path expression (e.g. .inventory.homebrew)
# $3 => default value when key is missing or non-boolean ("true" or "false")
# Prints "true" or "false"
_config_bool() {
  local json_str="$1"
  local jq_path="$2"
  local default_val="${3:-true}"
  jq -r --arg default "$default_val" \
    "if (${jq_path} | type) == \"boolean\" then ${jq_path} else (\$default == \"true\") end" \
    <<<"$json_str"
}

_security_timestamp_utc() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

_security_timestamp_compact() {
  date -u +"%Y%m%dT%H%M%SZ"
}

_security_generate_run_id() {
  printf '%s-%s-%04d' "$(_security_timestamp_compact)" "$$" "$((RANDOM % 10000))"
}

_security_expand_path() {
  local path_value="$1"
  if [[ "$path_value" == "~" ]]; then
    echo "$HOME"
  elif [[ "$path_value" == \~/* ]]; then
    echo "${HOME}/${path_value#"~/"}"
  elif [[ "$path_value" == \~* ]]; then
    print_warning "Unsupported user-home shorthand path (use ~/... or absolute path): $path_value" >&2
    echo "$path_value"
  else
    echo "$path_value"
  fi
}

_security_validate_output_dir() {
  local output_dir="$1"

  if [[ -z "$output_dir" ]]; then
    print_error "Output directory cannot be empty"
    return 1
  fi

  if [[ "$output_dir" == "/" ]]; then
    print_error "Refusing to use '/' as output directory"
    return 1
  fi

  if [[ -e "$output_dir" && ! -d "$output_dir" ]]; then
    print_error "Output path exists but is not a directory: $output_dir"
    return 1
  fi

  if [[ -d "$output_dir" && ! -w "$output_dir" ]]; then
    print_error "Output directory is not writable: $output_dir"
    return 1
  fi

  local parent_dir
  parent_dir="$(dirname "$output_dir")"
  if [[ ! -d "$output_dir" && ! -w "$parent_dir" ]]; then
    print_error "Output directory parent is not writable: $parent_dir"
    return 1
  fi

  return 0
}

_security_prepare_runtime_environment() {
  local run_dir="$1"
  local cache_dir="$run_dir/runtime-cache"

  ensure_dir "$cache_dir"
  ensure_dir "$cache_dir/npm"
  ensure_dir "$cache_dir/pip"
  ensure_dir "$cache_dir/uv"
  ensure_dir "$cache_dir/gem/specs"
  ensure_dir "$cache_dir/dotnet"
  ensure_dir "$cache_dir/grype"

  # Keep package manager metadata/cache writes out of user/global locations.
  export HOMEBREW_NO_AUTO_UPDATE=1
  export HOMEBREW_NO_INSTALL_CLEANUP=1
  export HOMEBREW_NO_ANALYTICS=1

  export NPM_CONFIG_UPDATE_NOTIFIER=false
  export npm_config_update_notifier=false
  export NPM_CONFIG_FUND=false
  export npm_config_fund=false
  export NPM_CONFIG_AUDIT=false
  export npm_config_audit=false
  export NPM_CONFIG_PROGRESS=false
  export npm_config_progress=false
  export NPM_CONFIG_CACHE="$cache_dir/npm"
  export npm_config_cache="$cache_dir/npm"

  export PIP_DISABLE_PIP_VERSION_CHECK=1
  export PIP_NO_INPUT=1
  export PIP_CACHE_DIR="$cache_dir/pip"

  export UV_CACHE_DIR="$cache_dir/uv"

  export GEM_SPEC_CACHE="$cache_dir/gem/specs"

  export DOTNET_CLI_TELEMETRY_OPTOUT=1
  export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
  export DOTNET_CLI_HOME="$cache_dir/dotnet"

  export GRYPE_DB_AUTO_UPDATE=false
  export GRYPE_CHECK_FOR_APP_UPDATE=false
  export GRYPE_DB_CACHE_DIR="$cache_dir/grype"
  export SYFT_CHECK_FOR_APP_UPDATE=false
}

_security_normalize_boolean() {
  local raw_value
  raw_value="$(to_lowercase "${1:-}")"
  case "$raw_value" in
    true|1|yes|y|on) echo "true" ;;
    false|0|no|n|off) echo "false" ;;
    *) echo "" ;;
  esac
}

_security_validate_severity() {
  local severity="${1:-}"
  case "$severity" in
    none|low|medium|high|critical) return 0 ;;
    *) return 1 ;;
  esac
}

_security_append_status() {
  local ndjson_file="$1"
  local name="$2"
  local enabled="$3"
  local available="$4"
  local success="$5"
  local message="$6"
  local artifact="${7:-}"

  jq -nc \
    --arg name "$name" \
    --arg enabled "$enabled" \
    --arg available "$available" \
    --arg success "$success" \
    --arg message "$message" \
    --arg artifact "$artifact" \
    '{
      name: $name,
      enabled: ($enabled == "true"),
      available: ($available == "true"),
      success: ($success == "true"),
      message: $message,
      artifact: (if $artifact == "" then null else $artifact end)
    }' >> "$ndjson_file"
}

_security_append_package() {
  local ndjson_file="$1"
  local manager="$2"
  local ecosystem="$3"
  local name="$4"
  local version="$5"
  local source="$6"
  local dependency_path="${7:-}"
  local depth_raw="${8:-0}"
  local install_type="${9:-unknown}"
  local parent_packages="${10:-}"
  local depth=0

  [[ -z "$name" || -z "$version" ]] && return 0
  [[ "$depth_raw" =~ ^[0-9]+$ ]] && depth="$depth_raw"

  local parents_json="[]"
  if [[ -n "$parent_packages" ]]; then
    parents_json="$(jq -nc --arg p "$parent_packages" '$p | split(",") | map(select(. != "")) | sort | unique')"
  fi

  jq -nc \
    --arg manager "$manager" \
    --arg ecosystem "$ecosystem" \
    --arg name "$name" \
    --arg version "$version" \
    --arg source "$source" \
    --arg dependency_path "$dependency_path" \
    --argjson depth "$depth" \
    --arg install_type "$install_type" \
    --argjson parent_packages "$parents_json" '
    {
      manager: $manager,
      ecosystem: (if $ecosystem == "" then null else $ecosystem end),
      name: $name,
      version: $version,
      source: $source,
      dependencyPath: (if $dependency_path == "" then null else $dependency_path end),
      depth: $depth,
      installType: $install_type,
      parentPackages: $parent_packages
    }' >> "$ndjson_file"
}

_security_append_outdated_item() {
  local ndjson_file="$1"
  local manager="$2"
  local name="$3"
  local current="$4"
  local latest="$5"

  [[ -z "$name" ]] && return 0
  jq -nc \
    --arg manager "$manager" \
    --arg name "$name" \
    --arg current "$current" \
    --arg latest "$latest" '
    {
      manager: $manager,
      name: $name,
      current: $current,
      latest: $latest
    }' >> "$ndjson_file"
}

#---------------------------------------------------------------------------------------------------
# Dependency Resolution Helpers
# Used by both inventory collectors and the why command.
#---------------------------------------------------------------------------------------------------

# Resolve Homebrew dependency relationships.
# Populates associative arrays passed by nameref:
#   $1 (nameref) => install_types: package_name -> "direct" | "dependency"
#   $2 (nameref) => parent_map: package_name -> comma-separated parent names
# shellcheck disable=SC2004  # associative array keys, not arithmetic
_security_resolve_brew_deps() {
  local -n _brew_install_types=$1
  local -n _brew_parents=$2

  if ! command_exists brew; then return 1; fi

  local leaves_list
  leaves_list="$(brew leaves 2>/dev/null)" || return 1

  local -A leaves_set=()
  local leaf
  while IFS= read -r leaf; do
    [[ -n "$leaf" ]] && leaves_set["$leaf"]=1
  done <<<"$leaves_list"

  local deps_output
  deps_output="$(brew deps --installed --for-each 2>/dev/null)" || return 1

  local line formula deps dep
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    formula="${line%%:*}"
    formula="$(trim "$formula")"
    deps="${line#*:}"

    for dep in $deps; do
      dep="$(trim "$dep")"
      [[ -z "$dep" ]] && continue
      if [[ -n "${_brew_parents[$dep]:-}" ]]; then
        _brew_parents[$dep]="${_brew_parents[$dep]},$formula"
      else
        _brew_parents[$dep]="$formula"
      fi
    done
  done <<<"$deps_output"

  local pkg
  while IFS=$'\t' read -r pkg _; do
    [[ -z "$pkg" ]] && continue
    if [[ -n "${leaves_set[$pkg]:-}" ]]; then
      _brew_install_types[$pkg]="direct"
    elif [[ -n "${_brew_parents[$pkg]:-}" ]]; then
      _brew_install_types[$pkg]="dependency"
    else
      _brew_install_types[$pkg]="direct"
    fi
  done < <(brew list --formula --versions 2>/dev/null)
}

# Build a set of gem names installed in macOS system paths.
# Populates an associative array (nameref) with system gem names as keys.
# System paths: /Library/Ruby and /System/Library/Frameworks/Ruby.framework
_security_system_gem_names() {
  local -n _sys_gems=$1
  local spec_file gem_name

  local -a system_spec_dirs=()
  # Glob for system gem specification directories
  # shellcheck disable=SC2206
  system_spec_dirs+=(
    /Library/Ruby/Gems/*/specifications
    /Library/Ruby/Gems/*/specifications/default
    /System/Library/Frameworks/Ruby.framework/Versions/*/usr/lib/ruby/gems/*/specifications
    /System/Library/Frameworks/Ruby.framework/Versions/*/usr/lib/ruby/gems/*/specifications/default
  )

  local dir
  for dir in "${system_spec_dirs[@]}"; do
    [[ -d "$dir" ]] || continue
    for spec_file in "$dir"/*.gemspec; do
      [[ -f "$spec_file" ]] || continue
      gem_name="$(basename "$spec_file")"
      # Strip version and .gemspec suffix: "rake-12.3.3.gemspec" -> "rake"
      if [[ "$gem_name" =~ ^(.+)-[0-9][0-9A-Za-z.]*$ ]]; then
        gem_name="${BASH_REMATCH[1]}"
      fi
      gem_name="${gem_name%-[0-9]*}"
      _sys_gems["$gem_name"]=1
    done
  done
}

# Resolve Ruby gem dependency relationships.
# Populates associative arrays passed by nameref:
#   $1 (nameref) => install_types: gem_name -> "direct" | "dependency" | "default"
#   $2 (nameref) => parent_map: gem_name -> comma-separated parent names
#   $3 => raw gem list output (to detect default: marker)
# shellcheck disable=SC2004  # associative array keys, not arithmetic
_security_resolve_gem_deps() {
  local -n _gem_install_types=$1
  local -n _gem_parents=$2
  local gem_list_file="${3:-}"

  if ! command_exists gem; then return 1; fi

  local -A default_gems=()
  if [[ -n "$gem_list_file" && -f "$gem_list_file" ]]; then
    local line
    while IFS= read -r line; do
      if [[ "$line" == *"default:"* ]]; then
        local gname
        gname="$(cut -d' ' -f1 <<<"$line")"
        [[ -n "$gname" ]] && default_gems["$gname"]=1
      fi
    done < "$gem_list_file"
  fi

  local rdeps_output current_gem
  rdeps_output="$(gem dependency --reverse-dependencies 2>/dev/null)" || return 1

  current_gem=""
  local in_used_by=false
  while IFS= read -r line; do
    if [[ "$line" =~ ^Gem\ (.+)-[0-9] ]]; then
      current_gem="${BASH_REMATCH[1]}"
      in_used_by=false
      continue
    fi

    if [[ "$line" == *"Used by"* ]]; then
      in_used_by=true
      continue
    fi

    if [[ "$in_used_by" == true && -n "$current_gem" ]]; then
      local user_gem
      user_gem="$(trim "$line")"
      user_gem="${user_gem%%-[0-9]*}"
      user_gem="$(trim "$user_gem")"

      if [[ -z "$user_gem" ]]; then
        in_used_by=false
        continue
      fi

      # Filter out development-only dependencies
      if [[ "$line" == *"development"* ]]; then
        continue
      fi

      if [[ -n "${_gem_parents[$current_gem]:-}" ]]; then
        _gem_parents[$current_gem]="${_gem_parents[$current_gem]},$user_gem"
      else
        _gem_parents[$current_gem]="$user_gem"
      fi
    fi
  done <<<"$rdeps_output"

  local gem_name
  for gem_name in "${!default_gems[@]}"; do
    _gem_install_types[$gem_name]="default"
  done

  while IFS= read -r line; do
    gem_name="$(cut -d' ' -f1 <<<"$line")"
    [[ -z "$gem_name" ]] && continue
    [[ -n "${_gem_install_types[$gem_name]:-}" ]] && continue

    if [[ -n "${_gem_parents[$gem_name]:-}" ]]; then
      _gem_install_types[$gem_name]="dependency"
    else
      _gem_install_types[$gem_name]="direct"
    fi
  done < <(gem list --local 2>/dev/null)
}

# Resolve pip dependency relationships.
# Populates associative arrays passed by nameref:
#   $1 (nameref) => install_types: package_name -> "direct" | "dependency"
#   $2 (nameref) => parent_map: package_name -> comma-separated parent names
# shellcheck disable=SC2004  # associative array keys, not arithmetic
_security_resolve_pip_deps() {
  local -n _pip_install_types=$1
  local -n _pip_parents=$2

  if ! command_exists python3; then return 1; fi

  local pkg_names
  pkg_names="$(python3 -m pip list --format=json 2>/dev/null | jq -r '.[].name' 2>/dev/null)" || return 1

  [[ -z "$pkg_names" ]] && return 0

  local show_output
  # shellcheck disable=SC2086
  show_output="$(python3 -m pip show $pkg_names 2>/dev/null)" || return 0

  local current_name="" current_required_by=""
  local line
  while IFS= read -r line; do
    if [[ "$line" == "---" ]]; then
      if [[ -n "$current_name" ]]; then
        if [[ -n "$current_required_by" ]]; then
          _pip_parents[$current_name]="$(printf '%s' "$current_required_by" | tr ' ' ',')"
          _pip_install_types[$current_name]="dependency"
        else
          _pip_install_types[$current_name]="direct"
        fi
      fi
      current_name=""
      current_required_by=""
      continue
    fi

    if [[ "$line" == Name:* ]]; then
      current_name="$(trim "${line#Name:}")"
    elif [[ "$line" == Required-by:* ]]; then
      current_required_by="$(trim "${line#Required-by:}")"
    fi
  done <<<"$show_output"

  # Handle last package
  if [[ -n "$current_name" ]]; then
    if [[ -n "$current_required_by" ]]; then
      _pip_parents[$current_name]="$(printf '%s' "$current_required_by" | tr ' ' ',')"
      _pip_install_types[$current_name]="dependency"
    else
      _pip_install_types[$current_name]="direct"
    fi
  fi
}

# Resolve why a package is installed for a specific manager.
# $1 => package name
# $2 => manager (brew|gem|npm|pip|pipx|uv|cargo|go|dotnet)
# Prints human-readable output.
security_why_package() {
  local pkg_name="$1"
  local manager="${2:-}"

  local managers=()
  if [[ -n "$manager" ]]; then
    managers=("$manager")
  else
    managers=(homebrew gem npm pip pipx uv cargo go dotnet dpkg rpm pacman snap flatpak)
  fi

  local found=false
  local mgr
  for mgr in "${managers[@]}"; do
    case "$mgr" in
      homebrew|brew)
        if command_exists brew; then
          _security_why_brew "$pkg_name" && found=true
        fi
        ;;
      gem|rubygems)
        if command_exists gem; then
          _security_why_gem "$pkg_name" && found=true
        fi
        ;;
      npm)
        if command_exists npm; then
          _security_why_npm "$pkg_name" && found=true
        fi
        ;;
      pip|python)
        if command_exists python3; then
          _security_why_pip "$pkg_name" && found=true
        fi
        ;;
      pipx|uv|cargo|go|dotnet)
        _security_why_simple "$pkg_name" "$mgr" && found=true
        ;;
      dpkg|apt)
        _security_why_dpkg "$pkg_name" && found=true
        ;;
      rpm|dnf|yum)
        _security_why_rpm "$pkg_name" && found=true
        ;;
      pacman)
        _security_why_pacman "$pkg_name" && found=true
        ;;
      snap)
        _security_why_snap "$pkg_name" && found=true
        ;;
      flatpak)
        _security_why_flatpak "$pkg_name" && found=true
        ;;
    esac
  done

  if [[ "$found" == false ]]; then
    print_error "Package '$pkg_name' not found in any installed package manager"
    return 1
  fi
}

_security_why_brew() {
  local pkg_name="$1"

  if ! brew list "$pkg_name" &>/dev/null; then
    return 1
  fi

  local version
  version="$(brew info --json=v2 "$pkg_name" 2>/dev/null | jq -r '(.formulae[0].installed[0].version // .casks[0].version // "unknown")' 2>/dev/null)"

  printf '\n'
  print_info "Homebrew: $pkg_name ($version)"

  local uses
  uses="$(brew uses --installed "$pkg_name" 2>/dev/null)"

  if [[ -z "$uses" ]]; then
    printf '  Install type: direct (leaf package)\n'
  else
    printf '  Install type: dependency\n'
    printf '  Required by:\n'
    local dep
    while IFS= read -r dep; do
      [[ -n "$dep" ]] && printf '    - %s\n' "$dep"
    done <<<"$uses"
  fi

  local deps
  deps="$(brew deps --direct "$pkg_name" 2>/dev/null)"
  if [[ -n "$deps" ]]; then
    printf '  Depends on:\n'
    while IFS= read -r dep; do
      [[ -n "$dep" ]] && printf '    - %s\n' "$dep"
    done <<<"$deps"
  fi
}

_security_why_gem() {
  local pkg_name="$1"

  if ! gem list --local --exact "$pkg_name" 2>/dev/null | grep -q "^$pkg_name "; then
    return 1
  fi

  local version_line
  version_line="$(gem list --local --exact "$pkg_name" 2>/dev/null)"

  printf '\n'
  print_info "RubyGems: $version_line"

  if [[ "$version_line" == *"default:"* ]]; then
    printf '  Install type: default (ships with Ruby)\n'
    return 0
  fi

  local rdeps
  rdeps="$(gem dependency "$pkg_name" --reverse-dependencies 2>/dev/null)"

  local in_used_by=false has_users=false
  local line
  while IFS= read -r line; do
    if [[ "$line" == *"Used by"* ]]; then
      in_used_by=true
      continue
    fi
    if [[ "$in_used_by" == true ]]; then
      local user
      user="$(trim "$line")"
      if [[ -z "$user" ]]; then
        break
      fi
      if [[ "$has_users" == false ]]; then
        printf '  Install type: dependency\n'
        printf '  Required by:\n'
        has_users=true
      fi
      printf '    - %s\n' "$user"
    fi
  done <<<"$rdeps"

  if [[ "$has_users" == false ]]; then
    printf '  Install type: direct\n'
  fi
}

_security_why_npm() {
  local pkg_name="$1"

  if ! npm ls -g "$pkg_name" --json &>/dev/null; then
    return 1
  fi

  local tree_json
  tree_json="$(npm ls -g "$pkg_name" --json 2>/dev/null)"

  local version
  version="$(jq -r ".dependencies.\"$pkg_name\".version // empty" <<<"$tree_json" 2>/dev/null)"

  if [[ -z "$version" ]]; then
    local found_in
    found_in="$(jq -r '[paths(type == "object" and .version? and (path | last) == "'"$pkg_name"'")] | first | if . then join(" > ") else empty end' <<<"$tree_json" 2>/dev/null)"
    if [[ -z "$found_in" ]]; then
      return 1
    fi
    version="$(jq -r 'getpath('"$(jq -nc --arg p "$found_in" '$p | split(" > ")')"') | .version // "unknown"' <<<"$tree_json" 2>/dev/null)" || version="unknown"
    printf '\n'
    print_info "npm (global): $pkg_name ($version)"
    printf '  Install type: dependency\n'
    printf '  Dependency path: %s\n' "$found_in"
  else
    printf '\n'
    print_info "npm (global): $pkg_name ($version)"
    printf '  Install type: direct (top-level global package)\n'
  fi
}

_security_why_pip() {
  local pkg_name="$1"

  local show_output
  show_output="$(python3 -m pip show "$pkg_name" 2>/dev/null)" || return 1
  [[ -z "$show_output" ]] && return 1

  local version required_by
  version="$(grep '^Version:' <<<"$show_output" | head -1)"
  version="$(trim "${version#Version:}")"
  required_by="$(grep '^Required-by:' <<<"$show_output" | head -1)"
  required_by="$(trim "${required_by#Required-by:}")"

  printf '\n'
  print_info "pip: $pkg_name ($version)"

  if [[ -n "$required_by" ]]; then
    printf '  Install type: dependency\n'
    printf '  Required by: %s\n' "$required_by"
  else
    printf '  Install type: direct\n'
  fi
}

_security_why_simple() {
  local pkg_name="$1"
  local mgr="$2"

  case "$mgr" in
    pipx)
      command_exists pipx || return 1
      pipx list --json 2>/dev/null | jq -e ".venvs.\"$pkg_name\"" &>/dev/null || return 1
      local version
      version="$(pipx list --json 2>/dev/null | jq -r ".venvs.\"$pkg_name\".metadata.main_package.package_version // \"unknown\"" 2>/dev/null)"
      printf '\n'
      print_info "pipx: $pkg_name ($version)"
      printf '  Install type: direct (pipx-managed)\n'
      ;;
    uv)
      command_exists uv || return 1
      uv tool list 2>/dev/null | grep -q "^$pkg_name " || return 1
      printf '\n'
      print_info "uv: $pkg_name"
      printf '  Install type: direct (uv tool)\n'
      ;;
    cargo)
      command_exists cargo || return 1
      cargo install --list 2>/dev/null | grep -q "^$pkg_name " || return 1
      printf '\n'
      print_info "cargo: $pkg_name"
      printf '  Install type: direct (cargo install)\n'
      ;;
    go)
      command_exists go || return 1
      local found=false
      local bin
      for bin in "$HOME/go/bin"/*; do
        [[ -x "$bin" ]] || continue
        if go version -m "$bin" 2>/dev/null | grep -q "path.*$pkg_name"; then
          printf '\n'
          print_info "go: $pkg_name ($(basename "$bin"))"
          printf '  Install type: direct (go install)\n'
          found=true
          break
        fi
      done
      [[ "$found" == true ]] || return 1
      ;;
    dotnet)
      command_exists dotnet || return 1
      dotnet tool list --global 2>/dev/null | grep -qi "^$pkg_name " || return 1
      printf '\n'
      print_info "dotnet: $pkg_name"
      printf '  Install type: direct (dotnet global tool)\n'
      ;;
    *)
      return 1
      ;;
  esac
}

#---------------------------------------------------------------------------------------------------
# Linux why-package helpers
#---------------------------------------------------------------------------------------------------

_security_why_dpkg() {
  local pkg_name="$1"

  command_exists dpkg-query || return 1
  # Confirm the package is installed (dpkg-query returns 1 otherwise).
  local status
  status="$(dpkg-query -W -f '${db:Status-Status}' "$pkg_name" 2>/dev/null || true)"
  if [[ "$status" != "installed" ]]; then
    return 1
  fi

  local version
  version="$(dpkg-query -W -f '${Version}' "$pkg_name" 2>/dev/null || echo "unknown")"

  printf '\n'
  print_info "dpkg: $pkg_name ($version)"

  if ! command_exists apt-cache; then
    printf '  Install type: unknown (apt-cache not available for reverse-dep lookup)\n'
    return 0
  fi

  # `apt-cache rdepends --installed` prints a header line + an indented list.
  # Empty list means nothing currently installed depends on this package.
  local rdeps
  rdeps="$(apt-cache rdepends --installed "$pkg_name" 2>/dev/null \
    | awk 'NR>2 && NF>0 {sub(/^[[:space:]]+/, ""); print}' \
    | sort -u)"

  if [[ -z "$rdeps" ]]; then
    printf '  Install type: direct (no installed reverse-dependencies)\n'
  else
    printf '  Install type: dependency\n'
    printf '  Required by:\n'
    local dep
    while IFS= read -r dep; do
      [[ -n "$dep" ]] && printf '    - %s\n' "$dep"
    done <<<"$rdeps"
  fi
}

_security_why_rpm() {
  local pkg_name="$1"

  command_exists rpm || return 1
  if ! rpm -q "$pkg_name" >/dev/null 2>&1; then
    return 1
  fi

  local version
  version="$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$pkg_name" 2>/dev/null || echo "unknown")"

  printf '\n'
  print_info "rpm: $pkg_name ($version)"

  local rdeps=""
  if command_exists dnf; then
    rdeps="$(dnf repoquery --installed --whatrequires "$pkg_name" 2>/dev/null | awk 'NF>0')"
  fi

  if [[ -z "$rdeps" ]]; then
    # rpm -q --whatrequires reports capabilities, not packages, but it's the
    # only fallback when dnf isn't present.
    rdeps="$(rpm -q --whatrequires "$pkg_name" 2>/dev/null \
      | grep -v "^no package requires" || true)"
  fi

  if [[ -z "$rdeps" ]]; then
    printf '  Install type: direct (no installed reverse-dependencies)\n'
  else
    printf '  Install type: dependency\n'
    printf '  Required by:\n'
    local dep
    while IFS= read -r dep; do
      [[ -n "$dep" ]] && printf '    - %s\n' "$dep"
    done <<<"$rdeps"
  fi
}

_security_why_pacman() {
  local pkg_name="$1"

  command_exists pacman || return 1
  if ! pacman -Q "$pkg_name" >/dev/null 2>&1; then
    return 1
  fi

  local version
  version="$(pacman -Q "$pkg_name" 2>/dev/null | awk '{print $2}')"

  printf '\n'
  print_info "pacman: $pkg_name ($version)"

  if ! command_exists pactree; then
    printf '  Install type: unknown (pactree not installed; install pacman-contrib for reverse-dep tree)\n'
    return 0
  fi

  local rtree
  rtree="$(pactree -r "$pkg_name" 2>/dev/null | tail -n +2)"

  if [[ -z "$rtree" ]]; then
    printf '  Install type: direct (no installed reverse-dependencies)\n'
  else
    printf '  Install type: dependency\n'
    printf '  Required by (reverse tree):\n'
    local line
    while IFS= read -r line; do
      [[ -n "$line" ]] && printf '    %s\n' "$line"
    done <<<"$rtree"
  fi
}

_security_why_snap() {
  local pkg_name="$1"

  command_exists snap || return 1
  if ! snap list "$pkg_name" >/dev/null 2>&1; then
    return 1
  fi

  local version
  version="$(snap list "$pkg_name" 2>/dev/null | awk 'NR==2 {print $2}')"

  printf '\n'
  print_info "snap: $pkg_name (${version:-unknown})"
  printf '  Install type: direct (snap-managed)\n'
  printf '  Note: snap packages are sandboxed and do not have reverse-dependency relationships.\n'
}

_security_why_flatpak() {
  local pkg_name="$1"

  command_exists flatpak || return 1
  if ! flatpak info "$pkg_name" >/dev/null 2>&1; then
    return 1
  fi

  local version
  version="$(flatpak info "$pkg_name" 2>/dev/null | awk -F': *' '/^[[:space:]]*Version:/ {print $2; exit}')"

  printf '\n'
  print_info "flatpak: $pkg_name (${version:-unknown})"
  printf '  Install type: direct (flatpak-managed)\n'
  printf '  Note: flatpak apps are sandboxed and do not have reverse-dependency relationships.\n'
}

_security_collect_inventory() {
  local config_json="$1"
  local inventory_dir="$2"

  local packages_ndjson="$inventory_dir/packages.ndjson"
  local collectors_ndjson="$inventory_dir/collectors.ndjson"
  : >"$packages_ndjson"
  : >"$collectors_ndjson"

  # Run each collector in parallel using per-collector temp files to avoid
  # concurrent appends corrupting the shared NDJSON files. Each background
  # subshell is not subject to set -e, so individual failures remain non-fatal
  # (collectors already handle their own errors and return 0).
  local -a collectors=(homebrew npm python pipx uv cargo rubygems go dotnet dpkg rpm pacman snap flatpak)
  local c
  for c in "${collectors[@]}"; do
    : >"$inventory_dir/packages-${c}.ndjson"
    : >"$inventory_dir/collectors-${c}.ndjson"
  done

  _security_collect_homebrew_inventory "$config_json" "$inventory_dir" \
    "$inventory_dir/packages-homebrew.ndjson" "$inventory_dir/collectors-homebrew.ndjson" &
  _security_collect_npm_inventory "$config_json" "$inventory_dir" \
    "$inventory_dir/packages-npm.ndjson" "$inventory_dir/collectors-npm.ndjson" &
  _security_collect_python_inventory "$config_json" "$inventory_dir" \
    "$inventory_dir/packages-python.ndjson" "$inventory_dir/collectors-python.ndjson" &
  _security_collect_pipx_inventory "$config_json" "$inventory_dir" \
    "$inventory_dir/packages-pipx.ndjson" "$inventory_dir/collectors-pipx.ndjson" &
  _security_collect_uv_inventory "$config_json" "$inventory_dir" \
    "$inventory_dir/packages-uv.ndjson" "$inventory_dir/collectors-uv.ndjson" &
  _security_collect_cargo_inventory "$config_json" "$inventory_dir" \
    "$inventory_dir/packages-cargo.ndjson" "$inventory_dir/collectors-cargo.ndjson" &
  _security_collect_rubygems_inventory "$config_json" "$inventory_dir" \
    "$inventory_dir/packages-rubygems.ndjson" "$inventory_dir/collectors-rubygems.ndjson" &
  _security_collect_go_inventory "$config_json" "$inventory_dir" \
    "$inventory_dir/packages-go.ndjson" "$inventory_dir/collectors-go.ndjson" &
  _security_collect_dotnet_inventory "$config_json" "$inventory_dir" \
    "$inventory_dir/packages-dotnet.ndjson" "$inventory_dir/collectors-dotnet.ndjson" &
  _security_collect_dpkg_inventory "$config_json" "$inventory_dir" \
    "$inventory_dir/packages-dpkg.ndjson" "$inventory_dir/collectors-dpkg.ndjson" &
  _security_collect_rpm_inventory "$config_json" "$inventory_dir" \
    "$inventory_dir/packages-rpm.ndjson" "$inventory_dir/collectors-rpm.ndjson" &
  _security_collect_pacman_inventory "$config_json" "$inventory_dir" \
    "$inventory_dir/packages-pacman.ndjson" "$inventory_dir/collectors-pacman.ndjson" &
  _security_collect_snap_inventory "$config_json" "$inventory_dir" \
    "$inventory_dir/packages-snap.ndjson" "$inventory_dir/collectors-snap.ndjson" &
  _security_collect_flatpak_inventory "$config_json" "$inventory_dir" \
    "$inventory_dir/packages-flatpak.ndjson" "$inventory_dir/collectors-flatpak.ndjson" &

  wait

  # Concatenate per-collector temp files into the shared NDJSON targets.
  # The temp files are guaranteed to exist (created with : > above) so the
  # loop will not fail even for disabled or unavailable collectors.
  for c in "${collectors[@]}"; do
    local pkg_tmp="$inventory_dir/packages-${c}.ndjson"
    local col_tmp="$inventory_dir/collectors-${c}.ndjson"
    [[ -s "$pkg_tmp" ]] && cat "$pkg_tmp" >> "$packages_ndjson"
    [[ -s "$col_tmp" ]] && cat "$col_tmp" >> "$collectors_ndjson"
  done

  if [[ -s "$packages_ndjson" ]]; then
    jq -s '
      map(select(.name != null and .name != "" and .version != null and .version != ""))
      | unique_by(.manager, .ecosystem, .name, .version, .source, .dependencyPath)
    ' "$packages_ndjson" > "$inventory_dir/packages.json"
  else
    write_file_content "$inventory_dir/packages.json" "[]"
  fi

  if [[ -s "$collectors_ndjson" ]]; then
    jq -s '.' "$collectors_ndjson" > "$inventory_dir/collectors.json"
  else
    write_file_content "$inventory_dir/collectors.json" "[]"
  fi

  jq -n \
    --slurpfile packages "$inventory_dir/packages.json" \
    --slurpfile collectors "$inventory_dir/collectors.json" '
    {
      totalPackages: (($packages[0] // []) | length),
      byManager: (($packages[0] // []) | group_by(.manager) | map({(.[0].manager): length}) | add // {}),
      byEcosystem: (($packages[0] // []) | map(select(.ecosystem != null)) | group_by(.ecosystem) | map({(.[0].ecosystem): length}) | add // {}),
      collectors: ($collectors[0] // [])
    }' > "$inventory_dir/summary.json"
}

_security_collect_homebrew_inventory() {
  local config_json="$1"
  local inventory_dir="$2"
  local packages_ndjson="$3"
  local collectors_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.homebrew" "true")" != "true" ]]; then
    _security_append_status "$collectors_ndjson" "homebrew" "false" "false" "true" "Collector disabled by config"
    return 0
  fi

  if ! command_exists brew; then
    _security_append_status "$collectors_ndjson" "homebrew" "true" "false" "false" "brew command not found"
    return 0
  fi

  local out_file="$inventory_dir/homebrew-installed.json"
  local err_file="$inventory_dir/homebrew-installed.stderr"

  if brew info --json=v2 --installed >"$out_file" 2>"$err_file"; then
    local -A brew_install_types=()
    local -A brew_parents=()
    _security_resolve_brew_deps brew_install_types brew_parents 2>/dev/null || true

    local name version install_type parents
    while IFS=$'\t' read -r name version; do
      install_type="${brew_install_types[$name]:-unknown}"
      parents="${brew_parents[$name]:-}"
      _security_append_package "$packages_ndjson" "homebrew" "" "$name" "$version" "brew formula" "" "0" "$install_type" "$parents"
    done < <(jq -r '.formulae[]? | [.name, ((.installed[0].version // .versions.stable // ""))] | @tsv' "$out_file")

    while IFS=$'\t' read -r token version; do
      _security_append_package "$packages_ndjson" "homebrew" "" "$token" "$version" "brew cask" "" "0" "direct" ""
    done < <(jq -r '.casks[]? | [.token, (.version // "")] | @tsv' "$out_file")

    _security_append_status "$collectors_ndjson" "homebrew" "true" "true" "true" "Collected installed formulae and casks" "$out_file"
  else
    _security_append_status "$collectors_ndjson" "homebrew" "true" "true" "false" "brew info --installed failed" "$err_file"
  fi
}

_security_collect_npm_inventory() {
  local config_json="$1"
  local inventory_dir="$2"
  local packages_ndjson="$3"
  local collectors_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.npmGlobal" "true")" != "true" ]]; then
    _security_append_status "$collectors_ndjson" "npm-global" "false" "false" "true" "Collector disabled by config"
    return 0
  fi

  if ! command_exists npm; then
    _security_append_status "$collectors_ndjson" "npm-global" "true" "false" "false" "npm command not found"
    return 0
  fi

  local out_file="$inventory_dir/npm-global-tree.json"
  local err_file="$inventory_dir/npm-global-tree.stderr"
  if npm list -g --all --json >"$out_file" 2>"$err_file"; then
    while IFS=$'\t' read -r name version dep_path depth; do
      local install_type="direct" parent_pkg=""
      if [[ "$depth" -gt 1 ]]; then
        install_type="dependency"
        # Extract immediate parent from dependency path
        parent_pkg="$(printf '%s' "$dep_path" | awk -F' > ' '{if(NF>=2) print $(NF-1)}')"
      fi
      _security_append_package "$packages_ndjson" "npm" "npm" "$name" "$version" "npm global" "$dep_path" "$depth" "$install_type" "$parent_pkg"
    done < <(jq -r '
      def walk_deps($path):
        (.dependencies // {} | to_entries[]) as $dep
        | {name: $dep.key, version: ($dep.value.version // ""), path: ($path + [$dep.key]), node: $dep.value}
        , ($dep.value | walk_deps($path + [$dep.key]));
      walk_deps([])
      | select(.version != "")
      | [.name, .version, (.path | join(" > ")), (.path | length)]
      | @tsv
    ' "$out_file")

    _security_append_status "$collectors_ndjson" "npm-global" "true" "true" "true" "Collected npm global dependency tree" "$out_file"
  else
    _security_append_status "$collectors_ndjson" "npm-global" "true" "true" "false" "npm list -g --all failed" "$err_file"
  fi
}

_security_collect_python_inventory() {
  local config_json="$1"
  local inventory_dir="$2"
  local packages_ndjson="$3"
  local collectors_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.pythonPip" "true")" != "true" ]]; then
    _security_append_status "$collectors_ndjson" "python-pip" "false" "false" "true" "Collector disabled by config"
    return 0
  fi

  if ! command_exists python3; then
    _security_append_status "$collectors_ndjson" "python-pip" "true" "false" "false" "python3 command not found"
    return 0
  fi

  local out_file="$inventory_dir/pip-list.json"
  local err_file="$inventory_dir/pip-list.stderr"

  if python3 -m pip list --format=json >"$out_file" 2>"$err_file"; then
    local -A pip_install_types=()
    local -A pip_parents=()
    _security_resolve_pip_deps pip_install_types pip_parents 2>/dev/null || true

    local name version install_type parents
    while IFS=$'\t' read -r name version; do
      install_type="${pip_install_types[$name]:-unknown}"
      parents="${pip_parents[$name]:-}"
      _security_append_package "$packages_ndjson" "pip" "PyPI" "$name" "$version" "python3 -m pip" "" "0" "$install_type" "$parents"
    done < <(jq -r '.[] | [.name, .version] | @tsv' "$out_file")

    _security_append_status "$collectors_ndjson" "python-pip" "true" "true" "true" "Collected installed pip packages" "$out_file"
  else
    _security_append_status "$collectors_ndjson" "python-pip" "true" "true" "false" "python3 -m pip list failed" "$err_file"
  fi
}

_security_collect_pipx_inventory() {
  local config_json="$1"
  local inventory_dir="$2"
  local packages_ndjson="$3"
  local collectors_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.pipx" "true")" != "true" ]]; then
    _security_append_status "$collectors_ndjson" "pipx" "false" "false" "true" "Collector disabled by config"
    return 0
  fi

  if ! command_exists pipx; then
    _security_append_status "$collectors_ndjson" "pipx" "true" "false" "false" "pipx command not found"
    return 0
  fi

  local out_file="$inventory_dir/pipx-list.json"
  local err_file="$inventory_dir/pipx-list.stderr"

  if pipx list --json >"$out_file" 2>"$err_file"; then
    while IFS=$'\t' read -r name version; do
      _security_append_package "$packages_ndjson" "pipx" "PyPI" "$name" "$version" "pipx" "" "0" "direct" ""
    done < <(jq -r '
      (.venvs // {} | to_entries[]) as $entry
      | ($entry.value.metadata.main_package // {}) as $pkg
      | [($pkg.package // $entry.key), ($pkg.package_version // "")]
      | @tsv
    ' "$out_file")

    _security_append_status "$collectors_ndjson" "pipx" "true" "true" "true" "Collected pipx environments" "$out_file"
  else
    _security_append_status "$collectors_ndjson" "pipx" "true" "true" "false" "pipx list --json failed" "$err_file"
  fi
}

_security_collect_uv_inventory() {
  local config_json="$1"
  local inventory_dir="$2"
  local packages_ndjson="$3"
  local collectors_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.uvTools" "true")" != "true" ]]; then
    _security_append_status "$collectors_ndjson" "uv-tools" "false" "false" "true" "Collector disabled by config"
    return 0
  fi

  if ! command_exists uv; then
    _security_append_status "$collectors_ndjson" "uv-tools" "true" "false" "false" "uv command not found"
    return 0
  fi

  local out_file="$inventory_dir/uv-tool-list.txt"
  local err_file="$inventory_dir/uv-tool-list.stderr"
  if uv tool list >"$out_file" 2>"$err_file"; then
    while IFS= read -r line; do
      if [[ "$line" =~ ^([A-Za-z0-9._-]+)[[:space:]]+v?([0-9][^[:space:]]*) ]]; then
        _security_append_package "$packages_ndjson" "uv" "PyPI" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "uv tool list" "" "0" "direct" ""
      fi
    done < "$out_file"

    _security_append_status "$collectors_ndjson" "uv-tools" "true" "true" "true" "Collected uv tool list (best effort parser)" "$out_file"
  else
    _security_append_status "$collectors_ndjson" "uv-tools" "true" "true" "false" "uv tool list failed" "$err_file"
  fi
}

_security_collect_cargo_inventory() {
  local config_json="$1"
  local inventory_dir="$2"
  local packages_ndjson="$3"
  local collectors_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.cargo" "true")" != "true" ]]; then
    _security_append_status "$collectors_ndjson" "cargo-install" "false" "false" "true" "Collector disabled by config"
    return 0
  fi

  if ! command_exists cargo; then
    _security_append_status "$collectors_ndjson" "cargo-install" "true" "false" "false" "cargo command not found"
    return 0
  fi

  local out_file="$inventory_dir/cargo-install-list.txt"
  local err_file="$inventory_dir/cargo-install-list.stderr"
  if cargo install --list >"$out_file" 2>"$err_file"; then
    while IFS= read -r line; do
      if [[ "$line" =~ ^([A-Za-z0-9._-]+)[[:space:]]v([0-9][^:[:space:]]*):$ ]]; then
        _security_append_package "$packages_ndjson" "cargo" "crates.io" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "cargo install --list" "" "0" "direct" ""
      fi
    done < "$out_file"

    _security_append_status "$collectors_ndjson" "cargo-install" "true" "true" "true" "Collected cargo installed crates" "$out_file"
  else
    _security_append_status "$collectors_ndjson" "cargo-install" "true" "true" "false" "cargo install --list failed" "$err_file"
  fi
}

_security_collect_rubygems_inventory() {
  local config_json="$1"
  local inventory_dir="$2"
  local packages_ndjson="$3"
  local collectors_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.rubyGems" "true")" != "true" ]]; then
    _security_append_status "$collectors_ndjson" "rubygems" "false" "false" "true" "Collector disabled by config"
    return 0
  fi

  if ! command_exists gem; then
    _security_append_status "$collectors_ndjson" "rubygems" "true" "false" "false" "gem command not found"
    return 0
  fi

  local out_file="$inventory_dir/gem-list.txt"
  local err_file="$inventory_dir/gem-list.stderr"
  local exclude_system="true"
  if command_exists jq; then
    exclude_system="$(_config_bool "$config_json" ".inventory.rubyGemsExcludeSystem" "true")"
  fi

  local -A system_gems=()
  if [[ "$exclude_system" == "true" ]]; then
    _security_system_gem_names system_gems
  fi

  if gem list --local >"$out_file" 2>"$err_file"; then
    local -A gem_install_types=()
    local -A gem_parents=()
    _security_resolve_gem_deps gem_install_types gem_parents "$out_file" 2>/dev/null || true

    local skipped_count=0
    while IFS= read -r line; do
      local gem_name versions first_version install_type parents
      gem_name="$(cut -d' ' -f1 <<<"$line")"
      versions="$(sed -n 's/^[^ ]* (\(.*\))$/\1/p' <<<"$line")"
      [[ -z "$gem_name" || -z "$versions" ]] && continue

      # Skip gems installed in macOS system paths
      if [[ -n "${system_gems[$gem_name]:-}" ]]; then
        ((skipped_count++)) || true
        continue
      fi

      first_version="${versions%%,*}"
      first_version="$(trim "$first_version")"
      first_version="${first_version#default: }"
      install_type="${gem_install_types[$gem_name]:-unknown}"
      parents="${gem_parents[$gem_name]:-}"
      _security_append_package "$packages_ndjson" "gem" "RubyGems" "$gem_name" "$first_version" "gem list --local" "" "0" "$install_type" "$parents"
    done < "$out_file"

    local status_msg="Collected installed gems"
    if [[ "$skipped_count" -gt 0 ]]; then
      status_msg="Collected installed gems (excluded $skipped_count system gems)"
    fi
    _security_append_status "$collectors_ndjson" "rubygems" "true" "true" "true" "$status_msg" "$out_file"
  else
    _security_append_status "$collectors_ndjson" "rubygems" "true" "true" "false" "gem list --local failed" "$err_file"
  fi
}

_security_collect_go_inventory() {
  local config_json="$1"
  local inventory_dir="$2"
  local packages_ndjson="$3"
  local collectors_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.goTools" "true")" != "true" ]]; then
    _security_append_status "$collectors_ndjson" "go-tools" "false" "false" "true" "Collector disabled by config"
    return 0
  fi

  if ! command_exists go; then
    _security_append_status "$collectors_ndjson" "go-tools" "true" "false" "false" "go command not found"
    return 0
  fi

  local gopath gobin bin_dir
  gopath="$(go env GOPATH 2>/dev/null || true)"
  gobin="$(go env GOBIN 2>/dev/null || true)"
  bin_dir="${gobin:-$gopath/bin}"

  if [[ -z "$bin_dir" || ! -d "$bin_dir" ]]; then
    _security_append_status "$collectors_ndjson" "go-tools" "true" "true" "false" "Go bin directory not found ($bin_dir)"
    return 0
  fi

  local out_file="$inventory_dir/go-tools.txt"
  : >"$out_file"
  local inspected=0
  local max_tools=200
  local binary
  for binary in "$bin_dir"/*; do
    [[ -e "$binary" && -x "$binary" && ! -d "$binary" ]] || continue
    inspected=$((inspected + 1))
    if [[ "$inspected" -gt "$max_tools" ]]; then
      break
    fi

    local mod_info
    mod_info="$(go version -m "$binary" 2>/dev/null | awk '$1=="mod"{print $2 "\t" $3; exit}')"
    if [[ -n "$mod_info" ]]; then
      local module_name module_version
      module_name="$(cut -f1 <<<"$mod_info")"
      module_version="$(cut -f2 <<<"$mod_info")"
      printf '%s\t%s\t%s\n' "$binary" "$module_name" "$module_version" >> "$out_file"
      _security_append_package "$packages_ndjson" "go" "Go" "$module_name" "$module_version" "go version -m" "" "0" "direct" ""
    fi
  done

  _security_append_status "$collectors_ndjson" "go-tools" "true" "true" "true" "Collected Go tool metadata from $bin_dir" "$out_file"
}

_security_collect_dotnet_inventory() {
  local config_json="$1"
  local inventory_dir="$2"
  local packages_ndjson="$3"
  local collectors_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.dotnetTools" "true")" != "true" ]]; then
    _security_append_status "$collectors_ndjson" "dotnet-tools" "false" "false" "true" "Collector disabled by config"
    return 0
  fi

  if ! command_exists dotnet; then
    _security_append_status "$collectors_ndjson" "dotnet-tools" "true" "false" "false" "dotnet command not found"
    return 0
  fi

  local out_file="$inventory_dir/dotnet-tools.txt"
  local err_file="$inventory_dir/dotnet-tools.stderr"
  if dotnet tool list --global >"$out_file" 2>"$err_file"; then
    while IFS=$'\t' read -r package_id version; do
      [[ -z "$package_id" || "$package_id" == "Package" ]] && continue
      _security_append_package "$packages_ndjson" "dotnet" "NuGet" "$package_id" "$version" "dotnet tool list --global" "" "0" "direct" ""
    done < <(awk 'NR>2 && NF>=2 {print $1 "\t" $2}' "$out_file")

    _security_append_status "$collectors_ndjson" "dotnet-tools" "true" "true" "true" "Collected dotnet global tools" "$out_file"
  else
    _security_append_status "$collectors_ndjson" "dotnet-tools" "true" "true" "false" "dotnet tool list --global failed" "$err_file"
  fi
}

#---------------------------------------------------------------------------------------------------
# Linux native package managers
#---------------------------------------------------------------------------------------------------

# Resolve the OSV-compatible ecosystem identifier for dpkg-installed packages.
# Debian/Ubuntu derivatives map to "Debian:<VERSION_ID>" or "Ubuntu:<VERSION_ID>".
# Other distros (or missing /etc/os-release) fall back to the generic "Debian"
# label so packages still appear in inventory; the OSV scanner will treat the
# unversioned label as non-queryable and rely on Grype.
_security_dpkg_ecosystem() {
  local distro version_id base
  distro="$(platform_linux_distro 2>/dev/null || echo unknown)"
  version_id="$(platform_linux_os_version_id 2>/dev/null || true)"
  case "$distro" in
    ubuntu) base="Ubuntu" ;;
    *) base="Debian" ;;
  esac
  if [[ -n "$version_id" ]]; then
    printf '%s:%s\n' "$base" "$version_id"
  else
    printf '%s\n' "$base"
  fi
}

# Resolve the ecosystem label for rpm-installed packages.
# OSV does not have a strong rpm-distro ecosystem (Rocky, Alma, RHEL etc.) so
# we emit a coarse vendor label ("RHEL" / "Fedora" / "SUSE") that the OSV
# scanner treats as partial-coverage; Grype provides actual vulnerability data.
_security_rpm_ecosystem() {
  local distro
  distro="$(platform_linux_distro 2>/dev/null || echo unknown)"
  case "$distro" in
    fedora) printf 'Fedora\n' ;;
    suse)   printf 'SUSE\n' ;;
    *)      printf 'RHEL\n' ;;
  esac
}

_security_collect_dpkg_inventory() {
  local config_json="$1"
  local inventory_dir="$2"
  local packages_ndjson="$3"
  local collectors_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.dpkg" "true")" != "true" ]]; then
    _security_append_status "$collectors_ndjson" "dpkg" "false" "false" "true" "Collector disabled by config"
    return 0
  fi

  if ! command_exists dpkg-query; then
    _security_append_status "$collectors_ndjson" "dpkg" "true" "false" "false" "dpkg-query command not found"
    return 0
  fi

  local ecosystem
  ecosystem="$(_security_dpkg_ecosystem)"

  local out_file="$inventory_dir/dpkg-list.tsv"
  local err_file="$inventory_dir/dpkg-list.stderr"

  if dpkg-query -W -f '${Package}\t${Version}\n' >"$out_file" 2>"$err_file"; then
    local name version
    while IFS=$'\t' read -r name version; do
      [[ -z "$name" || -z "$version" ]] && continue
      _security_append_package "$packages_ndjson" "dpkg" "$ecosystem" "$name" "$version" "/var/lib/dpkg/status" "" "0" "unknown" ""
    done < "$out_file"
    _security_append_status "$collectors_ndjson" "dpkg" "true" "true" "true" "Collected dpkg installed packages (ecosystem=$ecosystem)" "$out_file"
  else
    _security_append_status "$collectors_ndjson" "dpkg" "true" "true" "false" "dpkg-query -W failed" "$err_file"
  fi
}

_security_collect_rpm_inventory() {
  local config_json="$1"
  local inventory_dir="$2"
  local packages_ndjson="$3"
  local collectors_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.rpm" "true")" != "true" ]]; then
    _security_append_status "$collectors_ndjson" "rpm" "false" "false" "true" "Collector disabled by config"
    return 0
  fi

  if ! command_exists rpm; then
    _security_append_status "$collectors_ndjson" "rpm" "true" "false" "false" "rpm command not found"
    return 0
  fi

  # The rpm binary alone doesn't mean this host is RPM-managed (Ubuntu CI
  # runners ship rpm-common without an rpmdb). Require an actual DB.
  local rpm_dbpath
  rpm_dbpath="$(rpm --eval '%_dbpath' 2>/dev/null || echo /var/lib/rpm)"
  if [[ ! -d "$rpm_dbpath" ]] || ! ls -A "$rpm_dbpath" >/dev/null 2>&1; then
    _security_append_status "$collectors_ndjson" "rpm" "true" "false" "true" "rpm binary present but no rpmdb at $rpm_dbpath"
    return 0
  fi

  local ecosystem
  ecosystem="$(_security_rpm_ecosystem)"

  local out_file="$inventory_dir/rpm-list.tsv"
  local err_file="$inventory_dir/rpm-list.stderr"

  if rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' >"$out_file" 2>"$err_file"; then
    local name version
    while IFS=$'\t' read -r name version; do
      [[ -z "$name" || -z "$version" ]] && continue
      _security_append_package "$packages_ndjson" "rpm" "$ecosystem" "$name" "$version" "/var/lib/rpm" "" "0" "unknown" ""
    done < "$out_file"
    _security_append_status "$collectors_ndjson" "rpm" "true" "true" "true" "Collected rpm installed packages (ecosystem=$ecosystem)" "$out_file"
  else
    _security_append_status "$collectors_ndjson" "rpm" "true" "true" "false" "rpm -qa failed" "$err_file"
  fi
}

_security_collect_pacman_inventory() {
  local config_json="$1"
  local inventory_dir="$2"
  local packages_ndjson="$3"
  local collectors_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.pacman" "true")" != "true" ]]; then
    _security_append_status "$collectors_ndjson" "pacman" "false" "false" "true" "Collector disabled by config"
    return 0
  fi

  if ! command_exists pacman; then
    _security_append_status "$collectors_ndjson" "pacman" "true" "false" "false" "pacman command not found"
    return 0
  fi

  # Don't claim pacman as available without a local package DB.
  if [[ ! -d /var/lib/pacman/local ]]; then
    _security_append_status "$collectors_ndjson" "pacman" "true" "false" "true" "pacman binary present but no /var/lib/pacman/local"
    return 0
  fi

  local out_file="$inventory_dir/pacman-list.txt"
  local err_file="$inventory_dir/pacman-list.stderr"
  local explicit_file="$inventory_dir/pacman-explicit.txt"

  # Capture the explicit set so we can flag installType.
  local -A explicit_set=()
  if pacman -Qe >"$explicit_file" 2>/dev/null; then
    local ex_name
    while IFS=' ' read -r ex_name _; do
      [[ -n "$ex_name" ]] && explicit_set["$ex_name"]=1
    done < "$explicit_file"
  fi

  if pacman -Q >"$out_file" 2>"$err_file"; then
    local name version install_type
    while IFS=' ' read -r name version; do
      [[ -z "$name" || -z "$version" ]] && continue
      if [[ -n "${explicit_set[$name]:-}" ]]; then
        install_type="direct"
      else
        install_type="dependency"
      fi
      _security_append_package "$packages_ndjson" "pacman" "Arch" "$name" "$version" "/var/lib/pacman/local" "" "0" "$install_type" ""
    done < "$out_file"
    _security_append_status "$collectors_ndjson" "pacman" "true" "true" "true" "Collected pacman installed packages" "$out_file"
  else
    _security_append_status "$collectors_ndjson" "pacman" "true" "true" "false" "pacman -Q failed" "$err_file"
  fi
}

_security_collect_snap_inventory() {
  local config_json="$1"
  local inventory_dir="$2"
  local packages_ndjson="$3"
  local collectors_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.snap" "true")" != "true" ]]; then
    _security_append_status "$collectors_ndjson" "snap" "false" "false" "true" "Collector disabled by config"
    return 0
  fi

  if ! command_exists snap; then
    _security_append_status "$collectors_ndjson" "snap" "true" "false" "false" "snap command not found"
    return 0
  fi

  # snapd needs to be active for `snap list` to return anything meaningful.
  # Treat the collector as unavailable when the daemon isn't running.
  if ! snap list --color=never >/dev/null 2>&1; then
    _security_append_status "$collectors_ndjson" "snap" "true" "false" "true" "snap binary present but snapd not active"
    return 0
  fi

  local out_file="$inventory_dir/snap-list.txt"
  local err_file="$inventory_dir/snap-list.stderr"

  if snap list --color=never >"$out_file" 2>"$err_file"; then
    # snap list columns: Name Version Rev Tracking Publisher Notes
    local name version
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      name="$(awk '{print $1}' <<<"$line")"
      version="$(awk '{print $2}' <<<"$line")"
      [[ "$name" == "Name" ]] && continue
      [[ -z "$name" || -z "$version" ]] && continue
      _security_append_package "$packages_ndjson" "snap" "Snap" "$name" "$version" "snap list" "" "0" "direct" ""
    done < "$out_file"
    _security_append_status "$collectors_ndjson" "snap" "true" "true" "true" "Collected snap installed packages" "$out_file"
  else
    _security_append_status "$collectors_ndjson" "snap" "true" "true" "false" "snap list failed" "$err_file"
  fi
}

_security_collect_flatpak_inventory() {
  local config_json="$1"
  local inventory_dir="$2"
  local packages_ndjson="$3"
  local collectors_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.flatpak" "true")" != "true" ]]; then
    _security_append_status "$collectors_ndjson" "flatpak" "false" "false" "true" "Collector disabled by config"
    return 0
  fi

  if ! command_exists flatpak; then
    _security_append_status "$collectors_ndjson" "flatpak" "true" "false" "false" "flatpak command not found"
    return 0
  fi

  # Don't claim flatpak as available without a configured installation.
  if ! flatpak --installations >/dev/null 2>&1; then
    _security_append_status "$collectors_ndjson" "flatpak" "true" "false" "true" "flatpak binary present but no installations configured"
    return 0
  fi

  local out_file="$inventory_dir/flatpak-list.tsv"
  local err_file="$inventory_dir/flatpak-list.stderr"

  if flatpak list --columns=application,version --app >"$out_file" 2>"$err_file"; then
    local name version
    while IFS=$'\t' read -r name version; do
      [[ -z "$name" ]] && continue
      # flatpak omits version for some apps; keep them visible with a sentinel
      [[ -z "$version" ]] && version="unknown"
      _security_append_package "$packages_ndjson" "flatpak" "Flatpak" "$name" "$version" "flatpak list --app" "" "0" "direct" ""
    done < "$out_file"
    _security_append_status "$collectors_ndjson" "flatpak" "true" "true" "true" "Collected flatpak installed apps" "$out_file"
  else
    _security_append_status "$collectors_ndjson" "flatpak" "true" "true" "false" "flatpak list failed" "$err_file"
  fi
}

_security_collect_outdated() {
  local config_json="$1"
  local outdated_dir="$2"

  local items_ndjson="$outdated_dir/items.ndjson"
  local checks_ndjson="$outdated_dir/checks.ndjson"
  local allow_network
  : >"$items_ndjson"
  : >"$checks_ndjson"

  allow_network="$(_config_bool "$config_json" ".defaults.allowNetworkQueries" "true")"
  if [[ "$allow_network" == "true" ]]; then
    _security_collect_homebrew_outdated "$outdated_dir" "$items_ndjson" "$checks_ndjson"
    _security_collect_npm_outdated "$outdated_dir" "$items_ndjson" "$checks_ndjson"
    _security_collect_python_outdated "$outdated_dir" "$items_ndjson" "$checks_ndjson"
    _security_collect_rubygems_outdated "$config_json" "$outdated_dir" "$items_ndjson" "$checks_ndjson"
    _security_collect_dpkg_outdated "$config_json" "$outdated_dir" "$items_ndjson" "$checks_ndjson"
    _security_collect_rpm_outdated "$config_json" "$outdated_dir" "$items_ndjson" "$checks_ndjson"
    _security_collect_pacman_outdated "$config_json" "$outdated_dir" "$items_ndjson" "$checks_ndjson"
    _security_collect_snap_outdated "$config_json" "$outdated_dir" "$items_ndjson" "$checks_ndjson"
    _security_collect_flatpak_outdated "$config_json" "$outdated_dir" "$items_ndjson" "$checks_ndjson"
  else
    _security_append_status "$checks_ndjson" "homebrew-outdated" "true" "false" "true" "Skipped in offline mode"
    _security_append_status "$checks_ndjson" "npm-outdated" "true" "false" "true" "Skipped in offline mode"
    _security_append_status "$checks_ndjson" "python-pip-outdated" "true" "false" "true" "Skipped in offline mode"
    _security_append_status "$checks_ndjson" "rubygems-outdated" "true" "false" "true" "Skipped in offline mode"
    _security_append_status "$checks_ndjson" "dpkg-outdated" "true" "false" "true" "Skipped in offline mode"
    _security_append_status "$checks_ndjson" "rpm-outdated" "true" "false" "true" "Skipped in offline mode"
    _security_append_status "$checks_ndjson" "pacman-outdated" "true" "false" "true" "Skipped in offline mode"
    _security_append_status "$checks_ndjson" "snap-outdated" "true" "false" "true" "Skipped in offline mode"
    _security_append_status "$checks_ndjson" "flatpak-outdated" "true" "false" "true" "Skipped in offline mode"
  fi

  if [[ -s "$items_ndjson" ]]; then
    jq -s 'map(select(.name != null and .name != ""))' "$items_ndjson" > "$outdated_dir/items.json"
  else
    write_file_content "$outdated_dir/items.json" "[]"
  fi

  if [[ -s "$checks_ndjson" ]]; then
    jq -s '.' "$checks_ndjson" > "$outdated_dir/checks.json"
  else
    write_file_content "$outdated_dir/checks.json" "[]"
  fi

  jq -n \
    --slurpfile items "$outdated_dir/items.json" \
    --slurpfile checks "$outdated_dir/checks.json" '
    {
      totalOutdated: (($items[0] // []) | length),
      byManager: (($items[0] // []) | group_by(.manager) | map({(.[0].manager): length}) | add // {}),
      checks: ($checks[0] // [])
    }' > "$outdated_dir/summary.json"
}

_security_collect_homebrew_outdated() {
  local outdated_dir="$1"
  local items_ndjson="$2"
  local checks_ndjson="$3"

  if ! command_exists brew; then
    _security_append_status "$checks_ndjson" "homebrew-outdated" "true" "false" "false" "brew command not found"
    return 0
  fi

  local out_file="$outdated_dir/homebrew-outdated.json"
  local err_file="$outdated_dir/homebrew-outdated.stderr"
  if brew outdated --json=v2 >"$out_file" 2>"$err_file"; then
    while IFS=$'\t' read -r name current latest; do
      _security_append_outdated_item "$items_ndjson" "homebrew" "$name" "$current" "$latest"
    done < <(jq -r '.formulae[]? | [.name, ((.installed_versions // []) | join(",")), (.current_version // "")] | @tsv' "$out_file")

    while IFS=$'\t' read -r name current latest; do
      _security_append_outdated_item "$items_ndjson" "homebrew-cask" "$name" "$current" "$latest"
    done < <(jq -r '.casks[]? | [.name, ((.installed_versions // []) | join(",")), (.current_version // "")] | @tsv' "$out_file")

    _security_append_status "$checks_ndjson" "homebrew-outdated" "true" "true" "true" "Collected brew outdated results" "$out_file"
  else
    _security_append_status "$checks_ndjson" "homebrew-outdated" "true" "true" "false" "brew outdated failed" "$err_file"
  fi
}

_security_collect_npm_outdated() {
  local outdated_dir="$1"
  local items_ndjson="$2"
  local checks_ndjson="$3"

  if ! command_exists npm; then
    _security_append_status "$checks_ndjson" "npm-outdated" "true" "false" "false" "npm command not found"
    return 0
  fi

  local out_file="$outdated_dir/npm-outdated.json"
  local err_file="$outdated_dir/npm-outdated.stderr"
  local status=0
  npm outdated -g --json >"$out_file" 2>"$err_file" || status=$?

  if [[ -s "$out_file" ]] && jq -e '.' "$out_file" >/dev/null 2>&1; then
    while IFS=$'\t' read -r name current latest; do
      _security_append_outdated_item "$items_ndjson" "npm" "$name" "$current" "$latest"
    done < <(jq -r 'to_entries[]? | [.key, (.value.current // ""), (.value.latest // "")] | @tsv' "$out_file")
    _security_append_status "$checks_ndjson" "npm-outdated" "true" "true" "true" "Collected npm outdated -g output (exit=$status)" "$out_file"
  else
    _security_append_status "$checks_ndjson" "npm-outdated" "true" "true" "false" "npm outdated -g did not return JSON (exit=$status)" "$err_file"
  fi
}

_security_collect_python_outdated() {
  local outdated_dir="$1"
  local items_ndjson="$2"
  local checks_ndjson="$3"

  if ! command_exists python3; then
    _security_append_status "$checks_ndjson" "python-pip-outdated" "true" "false" "false" "python3 command not found"
    return 0
  fi

  local out_file="$outdated_dir/pip-outdated.json"
  local err_file="$outdated_dir/pip-outdated.stderr"
  if python3 -m pip list --outdated --format=json >"$out_file" 2>"$err_file"; then
    while IFS=$'\t' read -r name current latest; do
      _security_append_outdated_item "$items_ndjson" "pip" "$name" "$current" "$latest"
    done < <(jq -r '.[] | [.name, .version, (.latest_version // "")] | @tsv' "$out_file")
    _security_append_status "$checks_ndjson" "python-pip-outdated" "true" "true" "true" "Collected pip outdated packages" "$out_file"
  else
    _security_append_status "$checks_ndjson" "python-pip-outdated" "true" "true" "false" "python3 -m pip list --outdated failed" "$err_file"
  fi
}

_security_collect_rubygems_outdated() {
  local config_json="$1"
  local outdated_dir="$2"
  local items_ndjson="$3"
  local checks_ndjson="$4"

  if ! command_exists gem; then
    _security_append_status "$checks_ndjson" "rubygems-outdated" "true" "false" "false" "gem command not found"
    return 0
  fi

  local exclude_system="true"
  if command_exists jq; then
    exclude_system="$(_config_bool "$config_json" ".inventory.rubyGemsExcludeSystem" "true")"
  fi

  local -A system_gems=()
  if [[ "$exclude_system" == "true" ]]; then
    _security_system_gem_names system_gems
  fi

  local out_file="$outdated_dir/gem-outdated.txt"
  local err_file="$outdated_dir/gem-outdated.stderr"
  if gem outdated >"$out_file" 2>"$err_file"; then
    while IFS= read -r line; do
      local name current latest
      name="$(cut -d' ' -f1 <<<"$line")"
      current="$(sed -n 's/^[^ ]* (\([^<]*\) < .*$/\1/p' <<<"$line")"
      latest="$(sed -n 's/^[^ ]* ([^<]* < \(.*\))$/\1/p' <<<"$line")"
      current="$(trim "$current")"
      latest="$(trim "$latest")"
      [[ -z "$name" || -z "$current" || -z "$latest" ]] && continue
      # Skip gems installed in macOS system paths
      [[ -n "${system_gems[$name]:-}" ]] && continue
      _security_append_outdated_item "$items_ndjson" "gem" "$name" "$current" "$latest"
    done < "$out_file"
    _security_append_status "$checks_ndjson" "rubygems-outdated" "true" "true" "true" "Collected gem outdated output" "$out_file"
  else
    _security_append_status "$checks_ndjson" "rubygems-outdated" "true" "true" "false" "gem outdated failed" "$err_file"
  fi
}

#---------------------------------------------------------------------------------------------------
# Linux outdated checks
#---------------------------------------------------------------------------------------------------

_security_collect_dpkg_outdated() {
  local config_json="$1"
  local outdated_dir="$2"
  local items_ndjson="$3"
  local checks_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.dpkg" "true")" != "true" ]]; then
    _security_append_status "$checks_ndjson" "dpkg-outdated" "false" "false" "true" "Check disabled by config (inventory.dpkg=false)"
    return 0
  fi

  if ! command_exists apt; then
    _security_append_status "$checks_ndjson" "dpkg-outdated" "true" "false" "false" "apt command not found"
    return 0
  fi

  local out_file="$outdated_dir/apt-upgradable.txt"
  local err_file="$outdated_dir/apt-upgradable.stderr"

  # `apt list --upgradable` prints lines like:
  #   pkg/suite new-version arch [upgradable from: old-version]
  # The first line is "Listing..." which we skip.
  if apt list --upgradable >"$out_file" 2>"$err_file"; then
    local line name latest current
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      [[ "$line" == Listing* ]] && continue
      [[ "$line" =~ ^([A-Za-z0-9.+-]+)/[^[:space:]]+[[:space:]]+([^[:space:]]+)[[:space:]]+[^[:space:]]+[[:space:]]+\[upgradable[[:space:]]+from:[[:space:]]+([^][:space:]]+)\]$ ]] || continue
      name="${BASH_REMATCH[1]}"
      latest="${BASH_REMATCH[2]}"
      current="${BASH_REMATCH[3]}"
      _security_append_outdated_item "$items_ndjson" "dpkg" "$name" "$current" "$latest"
    done < "$out_file"
    _security_append_status "$checks_ndjson" "dpkg-outdated" "true" "true" "true" "Collected apt list --upgradable output" "$out_file"
  else
    _security_append_status "$checks_ndjson" "dpkg-outdated" "true" "true" "false" "apt list --upgradable failed" "$err_file"
  fi
}

_security_collect_rpm_outdated() {
  local config_json="$1"
  local outdated_dir="$2"
  local items_ndjson="$3"
  local checks_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.rpm" "true")" != "true" ]]; then
    _security_append_status "$checks_ndjson" "rpm-outdated" "false" "false" "true" "Check disabled by config (inventory.rpm=false)"
    return 0
  fi

  local tool=""
  if command_exists dnf; then
    tool="dnf"
  elif command_exists yum; then
    tool="yum"
  else
    _security_append_status "$checks_ndjson" "rpm-outdated" "true" "false" "false" "neither dnf nor yum found"
    return 0
  fi

  local out_file="$outdated_dir/${tool}-check-update.txt"
  local err_file="$outdated_dir/${tool}-check-update.stderr"

  # dnf/yum check-update exits 100 when updates are available — that's success
  # for our purposes. 0 means no updates. Anything else is a real error.
  local rc=0
  set +e
  "$tool" check-update --quiet >"$out_file" 2>"$err_file"
  rc=$?
  set -e

  case "$rc" in
    0)
      _security_append_status "$checks_ndjson" "rpm-outdated" "true" "true" "true" "$tool check-update reported no updates" "$out_file"
      return 0
      ;;
    100)
      : # updates available; parse below
      ;;
    *)
      _security_append_status "$checks_ndjson" "rpm-outdated" "true" "true" "false" "$tool check-update failed (exit=$rc)" "$err_file"
      return 0
      ;;
  esac

  # Output rows look like:  <name>.<arch>   <new-version>   <repo>
  # Continuation lines (e.g. obsoleted packages section) are headed by blank
  # lines or non-version columns; we filter to lines with three space-separated
  # fields where the first contains a dot (architecture suffix).
  local line name_arch new_ver name
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    # shellcheck disable=SC2206
    local -a fields=($line)
    [[ "${#fields[@]}" -lt 3 ]] && continue
    name_arch="${fields[0]}"
    new_ver="${fields[1]}"
    [[ "$name_arch" != *.* ]] && continue
    name="${name_arch%.*}"
    _security_append_outdated_item "$items_ndjson" "rpm" "$name" "" "$new_ver"
  done < "$out_file"

  _security_append_status "$checks_ndjson" "rpm-outdated" "true" "true" "true" "Collected $tool check-update output (exit=100, updates available)" "$out_file"
}

_security_collect_pacman_outdated() {
  local config_json="$1"
  local outdated_dir="$2"
  local items_ndjson="$3"
  local checks_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.pacman" "true")" != "true" ]]; then
    _security_append_status "$checks_ndjson" "pacman-outdated" "false" "false" "true" "Check disabled by config (inventory.pacman=false)"
    return 0
  fi

  if ! command_exists pacman; then
    _security_append_status "$checks_ndjson" "pacman-outdated" "true" "false" "false" "pacman command not found"
    return 0
  fi

  local out_file="$outdated_dir/pacman-Qu.txt"
  local err_file="$outdated_dir/pacman-Qu.stderr"

  # `pacman -Qu` exits 1 when there are no updates (or when the sync DB hasn't
  # been refreshed). Treat empty output as "no updates"; non-empty parse output.
  # Lines look like:  pkg current -> latest
  set +e
  pacman -Qu >"$out_file" 2>"$err_file"
  local rc=$?
  set -e

  if [[ "$rc" -ne 0 && ! -s "$out_file" ]]; then
    _security_append_status "$checks_ndjson" "pacman-outdated" "true" "true" "true" "pacman -Qu reported no updates (or sync DB not refreshed; consider 'pacman -Sy')" "$err_file"
    return 0
  fi

  local line name current latest
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^([A-Za-z0-9.+_-]+)[[:space:]]+([^[:space:]]+)[[:space:]]+-\>[[:space:]]+([^[:space:]]+)$ ]]; then
      name="${BASH_REMATCH[1]}"
      current="${BASH_REMATCH[2]}"
      latest="${BASH_REMATCH[3]}"
      _security_append_outdated_item "$items_ndjson" "pacman" "$name" "$current" "$latest"
    fi
  done < "$out_file"

  _security_append_status "$checks_ndjson" "pacman-outdated" "true" "true" "true" "Collected pacman -Qu output" "$out_file"
}

_security_collect_snap_outdated() {
  local config_json="$1"
  local outdated_dir="$2"
  local items_ndjson="$3"
  local checks_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.snap" "true")" != "true" ]]; then
    _security_append_status "$checks_ndjson" "snap-outdated" "false" "false" "true" "Check disabled by config (inventory.snap=false)"
    return 0
  fi

  if ! command_exists snap; then
    _security_append_status "$checks_ndjson" "snap-outdated" "true" "false" "false" "snap command not found"
    return 0
  fi

  local out_file="$outdated_dir/snap-refresh-list.txt"
  local err_file="$outdated_dir/snap-refresh-list.stderr"

  if snap refresh --list >"$out_file" 2>"$err_file"; then
    # First line is a header: Name Version Rev ... -- skip it.
    local line name latest
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      name="$(awk '{print $1}' <<<"$line")"
      [[ "$name" == "Name" ]] && continue
      latest="$(awk '{print $2}' <<<"$line")"
      [[ -z "$name" || -z "$latest" ]] && continue
      _security_append_outdated_item "$items_ndjson" "snap" "$name" "" "$latest"
    done < "$out_file"
    _security_append_status "$checks_ndjson" "snap-outdated" "true" "true" "true" "Collected snap refresh --list output" "$out_file"
  else
    _security_append_status "$checks_ndjson" "snap-outdated" "true" "true" "false" "snap refresh --list failed" "$err_file"
  fi
}

_security_collect_flatpak_outdated() {
  local config_json="$1"
  local outdated_dir="$2"
  local items_ndjson="$3"
  local checks_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".inventory.flatpak" "true")" != "true" ]]; then
    _security_append_status "$checks_ndjson" "flatpak-outdated" "false" "false" "true" "Check disabled by config (inventory.flatpak=false)"
    return 0
  fi

  if ! command_exists flatpak; then
    _security_append_status "$checks_ndjson" "flatpak-outdated" "true" "false" "false" "flatpak command not found"
    return 0
  fi

  local out_file="$outdated_dir/flatpak-updates.tsv"
  local err_file="$outdated_dir/flatpak-updates.stderr"

  if flatpak remote-ls --updates --columns=application,version >"$out_file" 2>"$err_file"; then
    local name latest
    while IFS=$'\t' read -r name latest; do
      [[ -z "$name" ]] && continue
      _security_append_outdated_item "$items_ndjson" "flatpak" "$name" "" "$latest"
    done < "$out_file"
    _security_append_status "$checks_ndjson" "flatpak-outdated" "true" "true" "true" "Collected flatpak remote-ls --updates output" "$out_file"
  else
    _security_append_status "$checks_ndjson" "flatpak-outdated" "true" "true" "false" "flatpak remote-ls --updates failed" "$err_file"
  fi
}

_security_scan_vulnerabilities() {
  local config_json="$1"
  local packages_file="$2"
  local scans_dir="$3"

  local findings_ndjson="$scans_dir/findings.ndjson"
  local scanners_ndjson="$scans_dir/scanners.ndjson"
  : >"$findings_ndjson"
  : >"$scanners_ndjson"

  _security_scan_osv "$config_json" "$packages_file" "$scans_dir" "$findings_ndjson" "$scanners_ndjson"
  _security_scan_npm_audit "$config_json" "$scans_dir" "$findings_ndjson" "$scanners_ndjson"
  _security_scan_pip_audit "$config_json" "$scans_dir" "$findings_ndjson" "$scanners_ndjson"
  _security_scan_cargo_audit "$config_json" "$scans_dir" "$findings_ndjson" "$scanners_ndjson"
  _security_scan_grype "$config_json" "$scans_dir" "$findings_ndjson" "$scanners_ndjson"

  _security_merge_findings "$findings_ndjson" "$scans_dir/findings.json"
  _security_build_advisories "$scans_dir/findings.json" "$scans_dir/advisories.json"
  _security_enrich_npm_advisories_release_status "$config_json" "$packages_file" "$scans_dir/advisories.json" "$scanners_ndjson" "$scans_dir"

  if [[ -s "$scanners_ndjson" ]]; then
    jq -s '.' "$scanners_ndjson" > "$scans_dir/scanners.json"
  else
    write_file_content "$scans_dir/scanners.json" "[]"
  fi

  jq -n \
    --slurpfile findings "$scans_dir/findings.json" \
    --slurpfile scanners "$scans_dir/scanners.json" '
    {
      totalFindings: (($findings[0] // []) | length),
      bySeverity: (($findings[0] // []) | group_by(.severity) | map({(.[0].severity): length}) | add // {}),
      byScanner: (
        ($findings[0] // [])
        | [ .[] | ((.sourceScanners // [(.sourceScanner // "unknown")])[]) ]
        | sort
        | group_by(.)
        | map({(.[0]): length})
        | add // {}
      ),
      scanners: ($scanners[0] // [])
    }' > "$scans_dir/summary.json"
}

# Build per-package advisory summaries from enriched findings.
# Groups all vulnerabilities per package, picks the highest minimum-fix version,
# and surfaces parent attribution, attack descriptions, and upgrade guidance.
# $1 => findings.json path
# $2 => advisories.json output path
_security_build_advisories() {
  local findings_file="$1"
  local advisories_file="$2"

  if [[ ! -s "$findings_file" ]]; then
    write_file_content "$advisories_file" "[]"
    return 0
  fi

  jq '
    def sev_rank:
      if . == "critical" then 0
      elif . == "high" then 1
      elif . == "medium" then 2
      elif . == "low" then 3
      else 4 end;

    def semver_parts:
      ltrimstr("v") | split(".") | map(split("-")[0] | tonumber? // 0);

    def semver_is_prerelease:
      ltrimstr("v") | test("-");

    def semver_gte($a; $b):
      ($a | semver_parts) as $ap
      | ($b | semver_parts) as $bp
      | if ($ap[0] // 0) != ($bp[0] // 0) then ($ap[0] // 0) > ($bp[0] // 0)
        elif ($ap[1] // 0) != ($bp[1] // 0) then ($ap[1] // 0) > ($bp[1] // 0)
        elif ($ap[2] // 0) != ($bp[2] // 0) then ($ap[2] // 0) > ($bp[2] // 0)
        else
          # numeric parts are equal: pre-release < stable, so $a >= $b only when
          # $a is NOT pre-release, or both are pre-release (treat as equal)
          (($a | semver_is_prerelease) | not) or ($b | semver_is_prerelease)
        end;

    def dependency_parts($path):
      (($path // "") | split(" > ") | map(select(. != "")));

    def inferred_parent($path; $pkg):
      (dependency_parts($path)) as $parts
      | if ($parts | length) == 0 then $pkg
        elif ($parts | length) == 1 then ($parts[0] // $pkg)
        elif (($parts[-1] // "") == $pkg) then ($parts[-2] // $parts[0] // $pkg)
        else ($parts[-1] // $parts[0] // $pkg)
        end;

    def root_parent($path; $pkg):
      (dependency_parts($path)) as $parts
      | if ($parts | length) >= 2 then ($parts[0] // $pkg)
        else $pkg
        end;

    def finding_parent($finding):
      (($finding.parentPackage // "") as $explicit
      | if $explicit != "" then $explicit
        else inferred_parent($finding.dependencyPath; ($finding.package // ""))
        end);

    def finding_root_parent($finding):
      root_parent($finding.dependencyPath; ($finding.package // ""));

    def upgrade_command($manager; $pkg; $recommended; $primary_parent):
      if ($pkg // "") == "" then null
      elif $manager == "homebrew" then
        "brew upgrade " + $pkg
      elif $manager == "homebrew-cask" then
        "brew upgrade --cask " + $pkg
      elif $manager == "npm" then
        # Transitive deps cannot be upgraded directly; upgrade the root parent instead
        if ($primary_parent != null and $primary_parent != "" and $primary_parent != $pkg) then
          "npm update -g " + $primary_parent
        elif $recommended != null then
          "npm install -g " + $pkg + "@" + $recommended
        else
          "npm update -g " + $pkg
        end
      elif $manager == "pip" then
        if $recommended != null then
          "python3 -m pip install --upgrade \"" + $pkg + ">=" + $recommended + "\""
        else
          "python3 -m pip install --upgrade " + $pkg
        end
      elif $manager == "pipx" then
        "pipx upgrade " + $pkg
      elif $manager == "uv" then
        if $recommended != null then
          "uv tool install " + $pkg + "==" + $recommended + " --force"
        else
          "uv tool upgrade " + $pkg
        end
      elif $manager == "cargo" then
        if $recommended != null then
          "cargo install " + $pkg + " --version " + $recommended + " --force"
        else
          "cargo install " + $pkg + " --force"
        end
      elif $manager == "gem" then
        if $recommended != null then
          "gem install --user-install " + $pkg + " -v " + $recommended
        else
          "gem update --user-install " + $pkg
        end
      elif $manager == "go" then
        if $recommended != null then
          "go install " + $pkg + "@" + $recommended
        else
          "go install " + $pkg + "@latest"
        end
      elif $manager == "dotnet" then
        if $recommended != null then
          "dotnet tool update --global " + $pkg + " --version " + $recommended
        else
          "dotnet tool update --global " + $pkg
        end
      else
        null
      end;

    # Group findings by (manager, package, version)
    group_by([.manager, .package, .version])
    | map(
        (.[0].manager) as $mgr
        | (.[0].package) as $pkg
        | (.[0].version) as $ver
        | (.[0].ecosystem) as $eco
        | (map(.severity) | sort_by(sev_rank) | .[0]) as $highest_sev
        | (length) as $vuln_count

        # Collect all fixed versions from all findings for this package
        | ([.[] | (.fixedVersions // [])[] | select(. != null and . != "")] | unique) as $all_fixes

        # Collect observed parent packages (best effort)
        | ([.[] | finding_parent(.) | select(. != null and . != "")] | unique) as $parents
        | (([$parents[] | select(. != $pkg)] | .[0]) // ($parents[0] // $pkg)) as $primary_parent

        # Identify root-level parent for transitive deps (first element of dependency path)
        | ([.[] | finding_root_parent(.) | select(. != null and . != "" and . != $pkg)] | unique | .[0]) as $root_parent
        | (($root_parent // $pkg)) as $effective_root
        | ([.[] | ((.sourceScanners // [(.sourceScanner // "unknown")])[]) | select(. != null and . != "")] | unique) as $sources

        # Pick the highest fix version (covers all vulns) via semver comparison
        | (if ($all_fixes | length) > 0 then
            $all_fixes | reduce .[] as $v (.[0]; if semver_gte($v; .) then $v else . end)
          else null end) as $recommended_version

        # Rationale for the recommended version
        | (if $recommended_version != null then
            if ($mgr == "npm" and $root_parent != null and $root_parent != "") then
              "Transitive dependency of \($root_parent). Upgrade \($root_parent) to pull in \($pkg) >= \($recommended_version) and resolve \($vuln_count) known vulnerabilit\(if $vuln_count == 1 then "y" else "ies" end) (highest severity: \($highest_sev)). Installing \($pkg) directly at the top level will not fix the nested copy."
            else
              "Upgrade to >= \($recommended_version) to resolve \($vuln_count) known vulnerabilit\(if $vuln_count == 1 then "y" else "ies" end) (highest severity: \($highest_sev)). This is the minimum version that patches all identified issues — not necessarily the latest release, so it minimises breaking changes."
            end
          else
            "No fixed version identified in advisory data. Check package release notes or consider replacing this dependency."
          end) as $rationale

        # Collect unique attack descriptions
        | ([.[] | .attackDescription // "" | select(. != "")] | unique) as $attacks

        # Collect all vuln IDs and summaries
        | (map({
            id: .id,
            sourceScanners: (.sourceScanners // [(.sourceScanner // "unknown")]),
            severity: .severity,
            summary: (.summary // ""),
            attackDescription: (.attackDescription // ""),
            dependencyPath: (.dependencyPath // null),
            parentPackage: finding_parent(.),
            fixedVersions: (.fixedVersions // []),
            references: (.references // [])
          })) as $vulns

        # Collect unique dependency paths across all findings
        | ([.[] | .dependencyPath // "" | select(. != "")] | unique) as $dep_paths

        | {
            manager: $mgr,
            ecosystem: $eco,
            package: $pkg,
            installedVersion: $ver,
            highestSeverity: $highest_sev,
            vulnerabilityCount: $vuln_count,
            responsibleParents: $parents,
            primaryParent: $primary_parent,
            rootPackage: $effective_root,
            dependencyPaths: $dep_paths,
            recommendedVersion: $recommended_version,
            upgradeCommand: upgrade_command($mgr; $pkg; $recommended_version; $root_parent),
            upgradeRationale: $rationale,
            remediationStatus: (if $recommended_version != null then "actionable-update-now" else "no-fix-released" end),
            remediationMessage: $rationale,
            evidenceSources: $sources,
            rootInstalledVersion: null,
            rootLatestVersion: null,
            rootIsLatest: null,
            pendingReleaseTag: null,
            pendingReleaseVersion: null,
            pendingResolvedVersion: null,
            attackDescriptions: $attacks,
            vulnerabilities: $vulns
          }
      )
    | sort_by(
        (.highestSeverity | sev_rank),
        (-.vulnerabilityCount),
        .manager,
        .package
      )
  ' "$findings_file" > "$advisories_file"
}

# Merge scanner findings by canonical vulnerability identity while keeping source provenance.
# This de-duplicates overlap between OSV, npm-audit, and other scanners.
# $1 => findings.ndjson path
# $2 => merged findings.json path
_security_merge_findings() {
  local findings_ndjson="$1"
  local merged_file="$2"

  if [[ ! -s "$findings_ndjson" ]]; then
    write_file_content "$merged_file" "[]"
    return 0
  fi

  jq -s '
    def sev_rank:
      if . == "critical" then 0
      elif . == "high" then 1
      elif . == "medium" then 2
      elif . == "low" then 3
      else 4 end;

    def semver_like:
      test("^[vV]?[0-9]+(\\.[0-9]+){0,2}([-.+][0-9A-Za-z.-]+)?$");

    def choose_version($group):
      (($group | map(.version // "") | map(select(. != "" and semver_like)) | .[0])
      // ($group | map(.version // "") | map(select(. != "")) | .[0] // ""));

    map(select((.id // "") != "" and (.package // "") != ""))
    | sort_by(
        (.manager // ""),
        (.ecosystem // ""),
        (.package // ""),
        (.id // ""),
        (.dependencyPath // "")
      )
    | group_by([
        (.manager // ""),
        (.ecosystem // ""),
        (.package // ""),
        (.id // ""),
        (.dependencyPath // "")
      ])
    | map(
        . as $group
        | ($group[0]) as $first
        | {
            sourceScanner: (($group | map(.sourceScanner // "unknown") | map(select(. != "")) | unique | sort)[0] // "unknown"),
            sourceScanners: ($group | map(.sourceScanner // "unknown") | map(select(. != "")) | unique | sort),
            manager: ($first.manager // "unknown"),
            ecosystem: ($first.ecosystem // null),
            package: ($first.package // ""),
            version: choose_version($group),
            dependencyPath: ($first.dependencyPath // null),
            parentPackage: (($group | map(.parentPackage // "") | map(select(. != "")) | .[0]) // null),
            id: ($first.id // ""),
            aliases: ($group | map(.aliases // []) | add | map(select(. != "")) | unique),
            summary: (($group | map(.summary // "") | map(select(. != "")) | .[0]) // ""),
            severity: (($group | map((.severity // "unknown") | ascii_downcase) | sort_by(sev_rank) | .[0]) // "unknown"),
            fixedVersions: ($group | map(.fixedVersions // []) | add | map(select(. != "")) | unique),
            attackDescription: (($group | map(.attackDescription // "") | map(select(. != "")) | .[0]) // ""),
            published: (($group | map(.published) | map(select(. != null and . != "")) | sort | .[0]) // null),
            modified: (($group | map(.modified) | map(select(. != null and . != "")) | sort | .[-1]) // null),
            references: ($group | map(.references // []) | add | map(select(. != null and . != "")) | unique)
          }
      )
  ' "$findings_ndjson" > "$merged_file"
}

# Compare semantic versions and return success when $1 >= $2.
# $1 => candidate version
# $2 => minimum required version
# Returns: 0 when candidate is greater-or-equal, 1 otherwise
_security_semver_gte() {
  local candidate="${1#v}"
  local minimum="${2#v}"

  [[ -z "$candidate" || -z "$minimum" ]] && return 1
  [[ "$candidate" == "$minimum" ]] && return 0

  local greatest
  greatest="$(printf '%s\n%s\n' "$candidate" "$minimum" | sort -V | tail -n 1)"
  [[ "$greatest" == "$candidate" ]]
}

# Resolve the installed version of the final package in an npm dependency path
# for a specific root package version by traversing npm registry dependency ranges.
# $1 => root package name (e.g., npm)
# $2 => root package version (e.g., 11.12.1)
# $3 => dependency path (e.g., npm > node-gyp > tinyglobby > fdir > picomatch)
# Outputs: resolved terminal package version on success
_security_npm_resolve_dependency_path_version() {
  local root_package="$1"
  local root_version="$2"
  local dependency_path="$3"

  [[ -z "$root_package" || -z "$root_version" || -z "$dependency_path" ]] && return 1

  local normalized_path="${dependency_path// > /|}"
  local -a parts=()
  IFS='|' read -r -a parts <<<"$normalized_path"
  if [[ "${#parts[@]}" -lt 2 ]]; then
    return 1
  fi

  local i
  for ((i = 0; i < ${#parts[@]}; i++)); do
    parts[i]="$(trim "${parts[i]}")"
  done

  [[ "${parts[0]}" == "$root_package" ]] || return 1

  local current_package="$root_package"
  local current_version="$root_version"
  local next_package dependency_range_json dependency_range resolved_json resolved_version

  for ((i = 1; i < ${#parts[@]}; i++)); do
    next_package="${parts[$i]}"
    [[ -z "$next_package" ]] && return 1

    dependency_range_json="$(npm view "${current_package}@${current_version}" "dependencies.${next_package}" --json 2>/dev/null || true)"
    if [[ -z "$dependency_range_json" || "$dependency_range_json" == "null" ]]; then
      return 1
    fi

    dependency_range="$(jq -r 'if type == "string" then . else empty end' <<<"$dependency_range_json" 2>/dev/null)"
    [[ -z "$dependency_range" ]] && return 1

    resolved_json="$(npm view "${next_package}@${dependency_range}" version --json 2>/dev/null || true)"
    if [[ -z "$resolved_json" || "$resolved_json" == "null" ]]; then
      return 1
    fi

    resolved_version="$(jq -r '
      if type == "string" then .
      elif type == "array" then (map(select(type == "string")) | last // "")
      else ""
      end
    ' <<<"$resolved_json" 2>/dev/null)"
    [[ -z "$resolved_version" ]] && return 1

    current_package="$next_package"
    current_version="$resolved_version"
  done

  printf '%s\n' "$current_version"
}

# Enrich npm advisories with release-channel context and remediation status.
# This identifies actionable updates vs. "hang tight" (pending stable release) cases.
# $1 => effective config JSON
# $2 => inventory packages.json path
# $3 => advisories.json path
# $4 => scanners.ndjson path
# $5 => scans directory path
_security_enrich_npm_advisories_release_status() {
  local config_json="$1"
  local packages_file="$2"
  local advisories_file="$3"
  local scanners_ndjson="$4"
  local scans_dir="$5"

  local enabled
  enabled="$(_config_bool "$config_json" ".scanners.npmReleaseChannelChecks" "true")"
  if [[ "$enabled" != "true" ]]; then
    _security_append_status "$scanners_ndjson" "npm-release-channels" "false" "false" "true" "Release-channel enrichment disabled by config"
    return 0
  fi

  local allow_network
  allow_network="$(_config_bool "$config_json" ".defaults.allowNetworkQueries" "true")"
  if [[ "$allow_network" != "true" ]]; then
    _security_append_status "$scanners_ndjson" "npm-release-channels" "true" "false" "true" "Network queries disabled by config"
    return 0
  fi

  if [[ ! -f "$advisories_file" ]] || [[ "$(jq 'length' "$advisories_file" 2>/dev/null || echo "0")" -eq 0 ]]; then
    _security_append_status "$scanners_ndjson" "npm-release-channels" "true" "true" "true" "No advisories to enrich"
    return 0
  fi

  if ! command_exists npm; then
    _security_append_status "$scanners_ndjson" "npm-release-channels" "true" "false" "false" "npm command not found"
    return 0
  fi

  local npm_advisory_count
  npm_advisory_count="$(jq '[.[] | select(.manager == "npm")] | length' "$advisories_file" 2>/dev/null || echo "0")"
  if [[ "$npm_advisory_count" -eq 0 ]]; then
    _security_append_status "$scanners_ndjson" "npm-release-channels" "true" "true" "true" "No npm advisories to enrich"
    return 0
  fi

  local outdated_items_file
  outdated_items_file="$(dirname "$scans_dir")/outdated/items.json"
  if [[ ! -f "$outdated_items_file" ]]; then
    outdated_items_file="$scans_dir/outdated-items-empty.json"
    write_file_content "$outdated_items_file" "[]"
  fi

  local updates_ndjson="$scans_dir/advisory-release-updates.ndjson"
  local merged_updates="$scans_dir/advisory-release-updates.json"
  local enriched_advisories="$scans_dir/advisories-enriched.json"
  : >"$updates_ndjson"

  local processed=0 pending_count=0 actionable_count=0 nofix_count=0 lookup_failures=0

  # Cache npm dist-tags lookups per root package to avoid duplicate network calls.
  declare -A tags_cache=()
  declare -A latest_cache=()

  local idx vuln_package root_package recommended_version dependency_path current_status current_message
  while IFS=$'\t' read -r idx vuln_package root_package recommended_version dependency_path current_status current_message; do
    [[ -z "$idx" || -z "$vuln_package" || -z "$root_package" ]] && continue
    processed=$((processed + 1))

    local root_installed root_latest root_is_latest
    root_installed="$(jq -r --arg root "$root_package" '
      [.[] | select(.manager == "npm" and .name == $root and ((.depth // 0) <= 1)) | .version]
      | .[0] // ""
    ' "$packages_file" 2>/dev/null || true)"

    local tags_json="${tags_cache[$root_package]:-}"
    if [[ -z "$tags_json" ]]; then
      tags_json="$(npm view "$root_package" dist-tags --json 2>/dev/null || true)"
      if [[ -z "$tags_json" ]] || ! jq -e '.' >/dev/null 2>&1 <<<"$tags_json"; then
        tags_json="{}"
        lookup_failures=$((lookup_failures + 1))
      fi
      tags_cache["$root_package"]="$tags_json"
      latest_cache["$root_package"]="$(jq -r '.latest // ""' <<<"$tags_json" 2>/dev/null || true)"
    fi
    root_latest="${latest_cache[$root_package]:-}"

    # Fallback to outdated snapshot when registry metadata for latest is unavailable.
    if [[ -z "$root_latest" ]]; then
      root_latest="$(jq -r --arg root "$root_package" '
        [.[] | select(.manager == "npm" and .name == $root) | .latest]
        | .[0] // ""
      ' "$outdated_items_file" 2>/dev/null || true)"
    fi

    root_is_latest="unknown"
    if [[ -n "$root_installed" && -n "$root_latest" ]]; then
      if [[ "$root_installed" == "$root_latest" ]]; then
        root_is_latest="true"
      else
        root_is_latest="false"
      fi
    fi

    local pending_tag="" pending_version="" pending_resolved=""
    if [[ "$root_is_latest" == "true" && -n "$recommended_version" && -n "$dependency_path" ]]; then
      local candidate_tag candidate_version resolved_candidate
      while IFS=$'\t' read -r candidate_tag candidate_version; do
        [[ -z "$candidate_tag" || -z "$candidate_version" ]] && continue
        if [[ -n "$root_latest" ]] && ! _security_semver_gte "$candidate_version" "$root_latest"; then
          continue
        fi
        resolved_candidate="$(_security_npm_resolve_dependency_path_version "$root_package" "$candidate_version" "$dependency_path" 2>/dev/null || true)"
        if [[ -n "$resolved_candidate" ]] && _security_semver_gte "$resolved_candidate" "$recommended_version"; then
          pending_tag="$candidate_tag"
          pending_version="$candidate_version"
          pending_resolved="$resolved_candidate"
          break
        fi
      done < <(jq -r --arg latest "$root_latest" '
        to_entries
        | map(select(.key != "latest"))
        | map(select(.key | test("(^|[-_.])(next|beta|rc|alpha|canary)([-_.]|$)"; "i")))
        | map(select(.value != null and .value != "" and .value != $latest))
        | unique_by(.value)
        | .[]
        | [.key, .value]
        | @tsv
      ' <<<"${tags_cache[$root_package]}" 2>/dev/null)
    fi

    local remediation_status remediation_message
    remediation_status="${current_status:-actionable-update-now}"
    remediation_message="${current_message:-}"

    if [[ "$root_is_latest" == "false" && -n "$root_latest" ]]; then
      remediation_status="actionable-update-now"
      remediation_message="Root package $root_package is not on latest stable release ($root_installed -> $root_latest). Update $root_package first before re-checking transitive vulnerabilities."
    elif [[ "$root_is_latest" == "true" ]]; then
      if [[ -n "$pending_tag" ]]; then
        remediation_status="upstream-pending-release"
        remediation_message="Root package $root_package is already on latest stable release ($root_installed). Release channel '$pending_tag' ($pending_version) resolves $vuln_package to $pending_resolved (>= $recommended_version). Hang tight for stable release or opt into that channel."
      elif [[ -n "$recommended_version" ]]; then
        remediation_status="no-fix-released"
        remediation_message="Root package $root_package is already latest stable ($root_installed). Checked prerelease channels but none resolve $vuln_package to >= $recommended_version yet."
      else
        remediation_status="no-fix-released"
        if [[ -z "$remediation_message" ]]; then
          remediation_message="No fixed version identified in advisory data."
        fi
      fi
    fi

    case "$remediation_status" in
      actionable-update-now) actionable_count=$((actionable_count + 1)) ;;
      upstream-pending-release) pending_count=$((pending_count + 1)) ;;
      no-fix-released) nofix_count=$((nofix_count + 1)) ;;
    esac

    jq -nc \
      --argjson index "$idx" \
      --arg remediation_status "$remediation_status" \
      --arg remediation_message "$remediation_message" \
      --arg root_package "$root_package" \
      --arg root_installed "$root_installed" \
      --arg root_latest "$root_latest" \
      --arg root_is_latest "$root_is_latest" \
      --arg pending_tag "$pending_tag" \
      --arg pending_version "$pending_version" \
      --arg pending_resolved "$pending_resolved" \
      '{
        index: $index,
        remediationStatus: $remediation_status,
        remediationMessage: $remediation_message,
        rootPackage: $root_package,
        rootInstalledVersion: (if $root_installed == "" then null else $root_installed end),
        rootLatestVersion: (if $root_latest == "" then null else $root_latest end),
        rootIsLatest: (
          if $root_is_latest == "true" then true
          elif $root_is_latest == "false" then false
          else null
          end
        ),
        pendingReleaseTag: (if $pending_tag == "" then null else $pending_tag end),
        pendingReleaseVersion: (if $pending_version == "" then null else $pending_version end),
        pendingResolvedVersion: (if $pending_resolved == "" then null else $pending_resolved end)
      }' >> "$updates_ndjson"
  done < <(
    jq -r '
      to_entries[]
      | select(.value.manager == "npm")
      | [
          .key,
          (.value.package // ""),
          (.value.rootPackage // .value.package // ""),
          (.value.recommendedVersion // ""),
          ((.value.dependencyPaths // [])[0] // ""),
          (.value.remediationStatus // "actionable-update-now"),
          (.value.remediationMessage // .value.upgradeRationale // "")
        ]
      | @tsv
    ' "$advisories_file"
  )

  if [[ -s "$updates_ndjson" ]]; then
    jq -s '.' "$updates_ndjson" > "$merged_updates"
    jq -n \
      --slurpfile advisories "$advisories_file" \
      --slurpfile updates "$merged_updates" '
      reduce ($updates[0] // [])[] as $u ($advisories[0] // [];
        .[$u.index] = (.[$u.index] + {
          remediationStatus: $u.remediationStatus,
          remediationMessage: $u.remediationMessage,
          rootPackage: $u.rootPackage,
          rootInstalledVersion: $u.rootInstalledVersion,
          rootLatestVersion: $u.rootLatestVersion,
          rootIsLatest: $u.rootIsLatest,
          pendingReleaseTag: $u.pendingReleaseTag,
          pendingReleaseVersion: $u.pendingReleaseVersion,
          pendingResolvedVersion: $u.pendingResolvedVersion
        })
      )
    ' > "$enriched_advisories"
    mv "$enriched_advisories" "$advisories_file"
  fi

  local status_message
  status_message="Enriched $processed npm advisories (actionable=$actionable_count, pending-release=$pending_count, no-fix=$nofix_count)"
  if [[ "$lookup_failures" -gt 0 ]]; then
    status_message="$status_message; metadata lookups failed for $lookup_failures package(s)"
    _security_append_status "$scanners_ndjson" "npm-release-channels" "true" "true" "false" "$status_message" "$advisories_file"
  else
    _security_append_status "$scanners_ndjson" "npm-release-channels" "true" "true" "true" "$status_message" "$advisories_file"
  fi
}

_security_scan_osv() {
  local config_json="$1"
  local packages_file="$2"
  local scans_dir="$3"
  local findings_ndjson="$4"
  local scanners_ndjson="$5"

  if [[ "$(_config_bool "$config_json" ".scanners.osv" "true")" != "true" ]]; then
    _security_append_status "$scanners_ndjson" "osv" "false" "false" "true" "Scanner disabled by config"
    return 0
  fi

  local allow_network
  allow_network="$(_config_bool "$config_json" ".defaults.allowNetworkQueries" "true")"
  if [[ "$allow_network" != "true" ]]; then
    _security_append_status "$scanners_ndjson" "osv" "true" "false" "true" "Network queries disabled by config"
    return 0
  fi

  if ! command_exists curl; then
    _security_append_status "$scanners_ndjson" "osv" "true" "false" "false" "curl command not found"
    return 0
  fi

  local query_packages_file="$scans_dir/osv-query-packages.json"
  # OSV recognises a fixed set of ecosystems (https://ossf.github.io/osv-schema/).
  # We accept the language ecosystems we already collect plus the OSV-supported
  # OS distributions (Debian:<ver>, Ubuntu:<ver>, Alpine:v<ver>) emitted by the
  # dpkg collector. RPM/pacman/snap/flatpak are *not* OSV-queryable and are
  # intentionally filtered out here; Grype provides their vulnerability data.
  jq '
    [
      .[] |
      select(.ecosystem != null and .name != null and .name != "" and .version != null and .version != "") |
      select(
        (.ecosystem as $e | ["npm", "PyPI", "crates.io", "RubyGems", "NuGet", "Go"] | index($e)) != null
        or (.ecosystem | test("^(Debian|Ubuntu|Alpine):"))
      ) |
      {
        manager,
        ecosystem,
        name,
        version,
        source,
        dependencyPath,
        depth
      }
    ]
    | unique_by(.ecosystem, .name, .version)
  ' "$packages_file" > "$query_packages_file"

  # Count packages from native managers OSV cannot query, so we can flag the
  # OSV scanner as providing only partial coverage on Linux hosts.
  local skipped_native
  skipped_native="$(jq '[.[] | select(.manager // "" | IN("rpm","pacman","snap","flatpak"))] | length' "$packages_file" 2>/dev/null || echo 0)"
  if [[ "${skipped_native:-0}" -gt 0 ]]; then
    _security_append_status "$scanners_ndjson" "osv-coverage" "true" "true" "true" \
      "Partial coverage: $skipped_native packages from rpm/pacman/snap/flatpak skipped (OSV does not index these ecosystems; rely on Grype)" \
      "$query_packages_file"
  fi

  local total
  total="$(jq 'length' "$query_packages_file")"
  if [[ "$total" -eq 0 ]]; then
    _security_append_status "$scanners_ndjson" "osv" "true" "true" "true" "No packages eligible for OSV lookup" "$query_packages_file"
    return 0
  fi

  local batch_size
  batch_size="$(jq -r '.defaults.osvBatchSize // 200' <<<"$config_json")"
  [[ "$batch_size" =~ ^[0-9]+$ ]] || batch_size=200
  if [[ "$batch_size" -le 0 ]]; then
    batch_size=200
  fi

  local start=0
  local end=0
  local request_failures=0
  local detail_enrichment_message=""
  local endpoint="https://api.osv.dev/v1/querybatch"

  while [[ "$start" -lt "$total" ]]; do
    end=$((start + batch_size))

    local chunk_file="$scans_dir/osv-query-${start}-${end}.json"
    local payload_file="$scans_dir/osv-payload-${start}-${end}.json"
    local response_file="$scans_dir/osv-response-${start}-${end}.json"
    local error_file="$scans_dir/osv-response-${start}-${end}.stderr"

    jq ".[$start:$end]" "$query_packages_file" > "$chunk_file"
    jq -n --slurpfile chunk "$chunk_file" '{
      queries: (($chunk[0] // []) | map({
        package: { name: .name, ecosystem: .ecosystem },
        version: .version
      }))
    }' > "$payload_file"

    if ! curl -fsS \
      --proto '=https' \
      --proto-redir '=https' \
      --tlsv1.2 \
      --retry 3 \
      --retry-delay 1 \
      --connect-timeout 10 \
      --max-time 60 \
      -H "Content-Type: application/json" \
      -X POST \
      "$endpoint" \
      --data-binary "@${payload_file}" \
      >"$response_file" 2>"$error_file"; then
      request_failures=$((request_failures + 1))
      start=$end
      continue
    fi

    if ! jq -e '.' "$response_file" >/dev/null 2>&1; then
      request_failures=$((request_failures + 1))
      start=$end
      continue
    fi

    jq -nc \
      --slurpfile chunk "$chunk_file" \
      --slurpfile response "$response_file" '
      def normalized_severity($v):
        (($v.database_specific.severity // ($v.severity | tostring) // "unknown") | ascii_downcase) as $s
        | if ($s | test("critical")) then "critical"
          elif ($s | test("high")) then "high"
          elif ($s | test("medium")) then "medium"
          elif ($s | test("low")) then "low"
          else "unknown" end;
      [
        range(0; (($chunk[0] // []) | length)) as $i
        | ((($response[0].results[$i].vulns // [])[])?) as $v
        | {
            sourceScanner: "osv",
            manager: ($chunk[0][$i].manager // "unknown"),
            ecosystem: ($chunk[0][$i].ecosystem // null),
            package: ($chunk[0][$i].name // ""),
            version: ($chunk[0][$i].version // ""),
            dependencyPath: ($chunk[0][$i].dependencyPath // null),
            id: ($v.id // ""),
            aliases: ($v.aliases // []),
            summary: ($v.summary // $v.details // ""),
            severity: normalized_severity($v),
            fixedVersions: ([($v.affected // [])[] | (.ranges // [])[] | (.events // [])[] | select(.fixed) | .fixed] | unique),
            attackDescription: "",
            published: ($v.published // null),
            modified: ($v.modified // null),
            references: (($v.references // []) | map(.url))
          }
      ]
    ' | jq -c '.[]' >> "$findings_ndjson"

    start=$end
  done

  local osv_detail_delay
  osv_detail_delay="$(jq -r '.defaults.osvDetailDelay // 0.1' <<<"$config_json")"
  [[ "$osv_detail_delay" =~ ^[0-9]+(\.[0-9]+)?$ ]] || osv_detail_delay=0.1

  detail_enrichment_message="$(_security_enrich_osv_findings "$scans_dir" "$findings_ndjson" "$osv_detail_delay")"

  local status_message
  status_message="OSV batch lookup completed"
  if [[ -n "$detail_enrichment_message" ]]; then
    status_message="$status_message; $detail_enrichment_message"
  fi

  if [[ "$request_failures" -gt 0 ]]; then
    status_message="$status_message; failed batches: $request_failures"
    _security_append_status "$scanners_ndjson" "osv" "true" "true" "false" "$status_message" "$query_packages_file"
  else
    _security_append_status "$scanners_ndjson" "osv" "true" "true" "true" "$status_message" "$query_packages_file"
  fi
}

_security_enrich_osv_findings() {
  local scans_dir="$1"
  local findings_ndjson="$2"
  local detail_delay="${3:-0.1}"

  if [[ ! -s "$findings_ndjson" ]]; then
    echo ""
    return 0
  fi

  local ids_file="$scans_dir/osv-vuln-ids.txt"
  local details_ndjson="$scans_dir/osv-vuln-details.ndjson"
  : >"$details_ndjson"

  jq -r 'select(.sourceScanner == "osv" and (.id // "") != "") | .id' "$findings_ndjson" | sort -u > "$ids_file"
  if [[ ! -s "$ids_file" ]]; then
    echo ""
    return 0
  fi

  local total_ids success_count failure_count
  total_ids="$(wc -l < "$ids_file" | tr -d ' ')"
  success_count=0
  failure_count=0

  local vuln_id
  while IFS= read -r vuln_id; do
    [[ -z "$vuln_id" ]] && continue

    local encoded_id detail_slug detail_file error_file
    encoded_id="$(printf '%s' "$vuln_id" | jq -sRr @uri)"
    detail_slug="$(printf '%s' "$vuln_id" | sed 's/[^A-Za-z0-9_.-]/_/g')"
    detail_file="$scans_dir/osv-vuln-${detail_slug}.json"
    error_file="$scans_dir/osv-vuln-${detail_slug}.stderr"

    if curl -fsS \
      --proto '=https' \
      --proto-redir '=https' \
      --tlsv1.2 \
      --retry 3 \
      --retry-delay 1 \
      --connect-timeout 10 \
      --max-time 60 \
      "https://api.osv.dev/v1/vulns/${encoded_id}" \
      >"$detail_file" 2>"$error_file"; then
      if jq -e '.id' "$detail_file" >/dev/null 2>&1; then
        jq -c '
          def normalized_severity:
            (
              .database_specific.severity
              // .ecosystem_specific.severity
              // (.severity[0].score // "")
            ) as $raw
            | ($raw | tostring | ascii_downcase) as $s
            | if ($s | test("critical")) then "critical"
              elif ($s | test("high")) then "high"
              elif ($s | test("moderate|medium")) then "medium"
              elif ($s | test("low")) then "low"
              elif ($s | test("^[0-9]+(\\.[0-9]+)?$")) then
                (if ($s | tonumber) >= 9 then "critical"
                 elif ($s | tonumber) >= 7 then "high"
                 elif ($s | tonumber) >= 4 then "medium"
                 elif ($s | tonumber) > 0 then "low"
                 else "unknown" end)
              else "unknown"
              end;
          def extract_fixed_versions:
            [(.affected // [])[] | (.ranges // [])[] | (.events // [])[] | select(.fixed) | .fixed]
            | unique;
          def attack_description:
            (.summary // "") as $sum
            | (.details // "") as $det
            | (($sum | ascii_downcase) + " " + ($det | ascii_downcase)) as $text
            | (if ($text | test("remote code|rce|command injection|code execution|arbitrary code")) then "Remote code execution — an attacker could run arbitrary commands on your system"
              elif ($text | test("denial.of.service|dos|crash|hang|infinite loop|resource exhaustion|stack overflow|out.of.memory")) then "Denial of service — an attacker could crash or hang the affected tool"
              elif ($text | test("path traversal|directory traversal|symlink|arbitrary file")) then "Path traversal — an attacker could read or write files outside intended directories"
              elif ($text | test("prototype pollution|pollution")) then "Prototype pollution — an attacker could modify object prototypes to alter application behavior"
              elif ($text | test("xss|cross.site.script|script injection")) then "Cross-site scripting — an attacker could inject malicious scripts"
              elif ($text | test("sqli|sql injection")) then "SQL injection — an attacker could manipulate database queries"
              elif ($text | test("ssrf|server.side request")) then "Server-side request forgery — an attacker could make the tool issue unintended network requests"
              elif ($text | test("information disclosure|information leak|sensitive data|memory exposure|out.of.bounds read")) then "Information disclosure — an attacker could read sensitive data from memory or files"
              elif ($text | test("buffer overflow|heap overflow|out.of.bounds write|memory corruption")) then "Memory corruption — an attacker could corrupt memory, potentially leading to code execution"
              elif ($text | test("authentication bypass|auth bypass|credential")) then "Authentication bypass — an attacker could gain access without valid credentials"
              elif ($text | test("dependency confusion|supply chain|typosquat")) then "Supply chain attack — an attacker could inject malicious code through dependency confusion"
              elif ($text | test("regex|redos|backtrack")) then "ReDoS — an attacker could cause excessive CPU usage via crafted input to regular expressions"
              elif ($text | test("open redirect|redirect")) then "Open redirect — an attacker could redirect users to malicious sites"
              elif ($text | test("injection")) then "Injection — an attacker could inject malicious data into a processing pipeline"
              elif ($sum != "") then $sum
              elif ($det != "") then ($det | split("\n")[0] | .[:200])
              else "Consult advisory references for details"
              end);
          {
            id: (.id // ""),
            aliases: ((.aliases // []) | unique),
            summary: (.summary // .details // ""),
            severity: normalized_severity,
            fixedVersions: extract_fixed_versions,
            attackDescription: attack_description,
            published: (.published // null),
            modified: (.modified // null),
            references: ((.references // []) | map(.url) | map(select(. != null and . != "")) | unique)
          }
        ' "$detail_file" >> "$details_ndjson"
        success_count=$((success_count + 1))
      else
        failure_count=$((failure_count + 1))
      fi
    else
      failure_count=$((failure_count + 1))
    fi

    sleep "$detail_delay"
  done < "$ids_file"

  if [[ -s "$details_ndjson" ]]; then
    local details_json findings_json merged_json
    details_json="$scans_dir/osv-vuln-details.json"
    findings_json="$scans_dir/osv-findings-before-enrichment.json"
    merged_json="$scans_dir/osv-findings-after-enrichment.json"

    jq -s '.' "$details_ndjson" > "$details_json"
    jq -s '.' "$findings_ndjson" > "$findings_json"
    jq -n \
      --slurpfile findings "$findings_json" \
      --slurpfile details "$details_json" '
      ($details[0] // []) as $detail_list
      | ($detail_list | map({key: .id, value: .}) | from_entries) as $by_id
      | ($findings[0] // [])
      | map(
          if .sourceScanner == "osv" and ((.id // "") != "") and ($by_id[.id] != null) then
            . + {
              aliases: (((.aliases // []) + ($by_id[.id].aliases // [])) | unique),
              summary: (if (.summary // "") == "" then ($by_id[.id].summary // "") else .summary end),
              severity: (if (.severity // "unknown") == "unknown" then ($by_id[.id].severity // "unknown") else .severity end),
              fixedVersions: (if ((.fixedVersions // []) | length) == 0 then ($by_id[.id].fixedVersions // []) else .fixedVersions end),
              attackDescription: (if (.attackDescription // "") == "" then ($by_id[.id].attackDescription // "") else .attackDescription end),
              published: (.published // $by_id[.id].published),
              modified: (.modified // $by_id[.id].modified),
              references: (if ((.references // []) | length) == 0 then ($by_id[.id].references // []) else .references end)
            }
          else
            .
          end
        )
    ' > "$merged_json"

    jq -c '.[]' "$merged_json" > "$findings_ndjson"
  fi

  if [[ "$failure_count" -gt 0 ]]; then
    echo "OSV detail enrichment resolved $success_count/$total_ids ids ($failure_count unresolved)"
  else
    echo "OSV detail enrichment resolved $success_count/$total_ids ids"
  fi
}

#--- Native package-manager audit scanners ---

# npm audit — checks global npm packages against the npm advisory database.
# Since `npm audit --global` is not supported, we create a temporary project
# with the global packages as dependencies and audit that.
_security_scan_npm_audit() {
  local config_json="$1"
  local scans_dir="$2"
  local findings_ndjson="$3"
  local scanners_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".scanners.npmAudit" "true")" != "true" ]]; then
    _security_append_status "$scanners_ndjson" "npm-audit" "false" "false" "true" "Scanner disabled by config"
    return 0
  fi

  local allow_network
  allow_network="$(_config_bool "$config_json" ".defaults.allowNetworkQueries" "true")"
  if [[ "$allow_network" != "true" ]]; then
    _security_append_status "$scanners_ndjson" "npm-audit" "true" "false" "true" "Network queries disabled by config"
    return 0
  fi

  if ! command_exists npm; then
    _security_append_status "$scanners_ndjson" "npm-audit" "true" "false" "false" "npm command not found"
    return 0
  fi

  local globals_file="$scans_dir/npm-globals-for-audit.json"
  local out_file="$scans_dir/npm-audit.json"
  local err_file="$scans_dir/npm-audit.stderr"
  local audit_dir="$scans_dir/npm-audit-workspace"
  local audit_status=0

  # Build a synthetic package.json from global package list
  if ! npm list -g --depth=0 --json >"$globals_file" 2>/dev/null; then
    _security_append_status "$scanners_ndjson" "npm-audit" "true" "true" "false" "Failed to list global npm packages" "$err_file"
    return 0
  fi

  ensure_dir "$audit_dir" # intentionally kept inside the run dir so the workspace is preserved for post-run debugging
  jq '{
    name: "revelio-global-probe",
    version: "0.0.0",
    private: true,
    dependencies: (
      (.dependencies // {}) | to_entries
      | map(select(.key != "npm" and .key != "corepack"))
      | map({key: .key, value: (.value.version // "*")})
      | from_entries
    )
  }' "$globals_file" > "$audit_dir/package.json"

  # Create a minimal package-lock so npm audit can work without installing
  jq '{
    name: "revelio-global-probe",
    version: "0.0.0",
    lockfileVersion: 3,
    requires: true,
    packages: (
      {"": {name: "revelio-global-probe", version: "0.0.0", dependencies: (
        (.dependencies // {}) | to_entries
        | map(select(.key != "npm" and .key != "corepack"))
        | map({key: .key, value: (.value.version // "*")})
        | from_entries
      )}} + (
        (.dependencies // {}) | to_entries
        | map(select(.key != "npm" and .key != "corepack"))
        | map({key: ("node_modules/" + .key), value: {version: (.value.version // "0.0.0"), resolved: "", integrity: ""}})
        | from_entries
      )
    )
  }' "$globals_file" > "$audit_dir/package-lock.json"

  # npm audit exits non-zero when vulnerabilities are found — this is expected
  npm audit --json --prefix "$audit_dir" >"$out_file" 2>"$err_file" || audit_status=$?

  if [[ ! -s "$out_file" ]] || ! jq -e '.' "$out_file" >/dev/null 2>&1; then
    _security_append_status "$scanners_ndjson" "npm-audit" "true" "true" "false" "npm audit produced no valid JSON (exit=$audit_status)" "$err_file"
    return 0
  fi

  # Parse npm audit v2 JSON format (advisories in .vulnerabilities object).
  # Keep dependency node-path context so parent package attribution can identify
  # which upstream dependency introduced the vulnerable package.
  jq -c '
    def node_to_chain:
      split("/") | map(select(. != "" and . != "." and . != "node_modules"));
    def node_to_dependency_path:
      (node_to_chain | join(" > "));
    def node_to_parent($package):
      (node_to_chain) as $parts
      | if ($parts | length) == 0 then $package
        elif ($parts | length) == 1 then ($parts[0] // $package)
        elif (($parts[-1] // "") == $package) then ($parts[-2] // $parts[0] // $package)
        else ($parts[-1] // $parts[0] // $package)
        end;
    (.vulnerabilities // {}) | to_entries[] |
    .value as $v |
    ($v.name // .key // "") as $package_name |
    ($v.nodes // []) as $nodes |
    ($nodes[0] // "") as $first_node |
    ($v.via // [])[] |
    select(type == "object") |
    {
      sourceScanner: "npm-audit",
      manager: "npm",
      ecosystem: "npm",
      package: $package_name,
      version: ($v.range // ""),
      dependencyPath: (if $first_node == "" then null else ($first_node | node_to_dependency_path) end),
      parentPackage: (if $first_node == "" then $package_name else ($first_node | node_to_parent($package_name)) end),
      id: (if (.url // "") != "" then (.url | split("/") | last) else (.title // "") end),
      aliases: [],
      summary: (.title // ""),
      severity: ((.severity // "unknown") | ascii_downcase | if . == "critical" or . == "high" or . == "moderate" or . == "medium" or . == "low" then (if . == "moderate" then "medium" else . end) else "unknown" end),
      fixedVersions: (if ($v.fixAvailable | type) == "object" then [($v.fixAvailable.version // "")] | map(select(. != "")) elif ($v.fixAvailable | type) == "boolean" and $v.fixAvailable then [] else [] end),
      attackDescription: "",
      published: null,
      modified: null,
      references: (if (.url // "") != "" then [.url] else [] end)
    }
  ' "$out_file" >> "$findings_ndjson" 2>/dev/null || true

  local finding_count
  finding_count="$(jq '[.vulnerabilities // {} | to_entries[] | .value.via[]? | select(type == "object")] | length' "$out_file" 2>/dev/null || echo "0")"

  _security_append_status "$scanners_ndjson" "npm-audit" "true" "true" "true" "npm audit found $finding_count advisories" "$out_file"
}

# pip-audit — checks installed Python packages against the PyPI advisory database.
# Tries `pip-audit` first; falls back to `python3 -m pip_audit` if available.
_security_scan_pip_audit() {
  local config_json="$1"
  local scans_dir="$2"
  local findings_ndjson="$3"
  local scanners_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".scanners.pipAudit" "true")" != "true" ]]; then
    _security_append_status "$scanners_ndjson" "pip-audit" "false" "false" "true" "Scanner disabled by config"
    return 0
  fi

  local allow_network
  allow_network="$(_config_bool "$config_json" ".defaults.allowNetworkQueries" "true")"
  if [[ "$allow_network" != "true" ]]; then
    _security_append_status "$scanners_ndjson" "pip-audit" "true" "false" "true" "Network queries disabled by config"
    return 0
  fi

  local pip_audit_cmd=""
  if command_exists pip-audit; then
    pip_audit_cmd="pip-audit"
  elif python3 -m pip_audit --version >/dev/null 2>&1; then
    pip_audit_cmd="python3 -m pip_audit"
  fi

  if [[ -z "$pip_audit_cmd" ]]; then
    _security_append_status "$scanners_ndjson" "pip-audit" "true" "false" "false" "pip-audit command not found (install with: pipx install pip-audit)"
    return 0
  fi

  local out_file="$scans_dir/pip-audit.json"
  local err_file="$scans_dir/pip-audit.stderr"
  local audit_status=0

  # pip-audit exits non-zero when vulnerabilities are found
  # shellcheck disable=SC2086
  $pip_audit_cmd --format=json --output="$out_file" 2>"$err_file" || audit_status=$?

  if [[ ! -s "$out_file" ]] || ! jq -e '.' "$out_file" >/dev/null 2>&1; then
    _security_append_status "$scanners_ndjson" "pip-audit" "true" "true" "false" "pip-audit produced no valid JSON (exit=$audit_status)" "$err_file"
    return 0
  fi

  # Parse pip-audit JSON output
  jq -c '
    (.dependencies // [])[] |
    select((.vulns // []) | length > 0) |
    . as $dep |
    .vulns[] |
    {
      sourceScanner: "pip-audit",
      manager: "pip",
      ecosystem: "PyPI",
      package: ($dep.name // ""),
      version: ($dep.version // ""),
      dependencyPath: null,
      id: (.id // ""),
      aliases: (.aliases // []),
      summary: (.description // ""),
      severity: "unknown",
      fixedVersions: [(.fix_versions // [])[]],
      attackDescription: "",
      published: null,
      modified: null,
      references: []
    }
  ' "$out_file" >> "$findings_ndjson" 2>/dev/null || true

  local finding_count
  finding_count="$(jq '[(.dependencies // [])[] | select((.vulns // []) | length > 0) | .vulns[]] | length' "$out_file" 2>/dev/null || echo "0")"

  _security_append_status "$scanners_ndjson" "pip-audit" "true" "true" "true" "pip-audit found $finding_count advisories" "$out_file"
}

# cargo audit — checks installed Rust crates against the RustSec advisory database.
_security_scan_cargo_audit() {
  local config_json="$1"
  local scans_dir="$2"
  local findings_ndjson="$3"
  local scanners_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".scanners.cargoAudit" "true")" != "true" ]]; then
    _security_append_status "$scanners_ndjson" "cargo-audit" "false" "false" "true" "Scanner disabled by config"
    return 0
  fi

  local allow_network
  allow_network="$(_config_bool "$config_json" ".defaults.allowNetworkQueries" "true")"
  if [[ "$allow_network" != "true" ]]; then
    _security_append_status "$scanners_ndjson" "cargo-audit" "true" "false" "true" "Network queries disabled by config"
    return 0
  fi

  if ! command_exists cargo-audit && ! command_exists cargo; then
    _security_append_status "$scanners_ndjson" "cargo-audit" "true" "false" "false" "cargo-audit command not found (install with: cargo install cargo-audit)"
    return 0
  fi

  if ! command_exists cargo-audit; then
    _security_append_status "$scanners_ndjson" "cargo-audit" "true" "false" "false" "cargo-audit not installed (install with: cargo install cargo-audit)"
    return 0
  fi

  local out_file="$scans_dir/cargo-audit.json"
  local err_file="$scans_dir/cargo-audit.stderr"
  local audit_status=0

  # cargo-audit exits non-zero when vulnerabilities are found
  cargo audit --json >"$out_file" 2>"$err_file" || audit_status=$?

  if [[ ! -s "$out_file" ]] || ! jq -e '.' "$out_file" >/dev/null 2>&1; then
    _security_append_status "$scanners_ndjson" "cargo-audit" "true" "true" "false" "cargo audit produced no valid JSON (exit=$audit_status)" "$err_file"
    return 0
  fi

  # Parse cargo-audit JSON format
  jq -c '
    (.vulnerabilities.list // [])[] |
    {
      sourceScanner: "cargo-audit",
      manager: "cargo",
      ecosystem: "crates.io",
      package: (.package.name // ""),
      version: (.package.version // ""),
      dependencyPath: null,
      id: (.advisory.id // ""),
      aliases: (.advisory.aliases // []),
      summary: (.advisory.title // ""),
      severity: ((.advisory.cvss // "") | tostring | if test("^[0-9]") then (split(" ")[0] | tonumber | if . >= 9 then "critical" elif . >= 7 then "high" elif . >= 4 then "medium" elif . > 0 then "low" else "unknown" end) else "unknown" end),
      fixedVersions: [(.versions.patched // [])[]],
      attackDescription: "",
      published: (.advisory.date // null),
      modified: null,
      references: [(.advisory.url // "")] | map(select(. != ""))
    }
  ' "$out_file" >> "$findings_ndjson" 2>/dev/null || true

  local finding_count
  finding_count="$(jq '(.vulnerabilities.list // []) | length' "$out_file" 2>/dev/null || echo "0")"

  _security_append_status "$scanners_ndjson" "cargo-audit" "true" "true" "true" "cargo audit found $finding_count advisories" "$out_file"
}

_security_scan_grype() {
  local config_json="$1"
  local scans_dir="$2"
  local findings_ndjson="$3"
  local scanners_ndjson="$4"

  if [[ "$(_config_bool "$config_json" ".scanners.grype" "true")" != "true" ]]; then
    _security_append_status "$scanners_ndjson" "grype" "false" "false" "true" "Scanner disabled by config"
    return 0
  fi

  local deep_scan
  deep_scan="$(_config_bool "$config_json" ".defaults.deepScan" "false")"
  if [[ "$deep_scan" != "true" ]]; then
    _security_append_status "$scanners_ndjson" "grype" "true" "false" "true" "Deep scan disabled; grype skipped"
    return 0
  fi

  if ! command_exists grype; then
    _security_append_status "$scanners_ndjson" "grype" "true" "false" "false" "grype command not found"
    return 0
  fi

  local targets_file="$scans_dir/grype-targets.txt"
  : >"$targets_file"
  while IFS= read -r target; do
    [[ -z "$target" ]] && continue
    target="$(_security_expand_path "$target")"
    if [[ -d "$target" ]]; then
      printf '%s\n' "$target" >> "$targets_file"
    fi
  done < <(jq -r '((.scanners.grypeTargets // []) + (.scanners.grypeDeepTargets // []))[]?' <<<"$config_json")

  if [[ ! -s "$targets_file" ]]; then
    _security_append_status "$scanners_ndjson" "grype" "true" "true" "false" "No grype targets found on disk"
    return 0
  fi

  local target_count=0
  local failures=0
  while IFS= read -r target_dir; do
    [[ -z "$target_dir" ]] && continue
    target_count=$((target_count + 1))

    local slug
    slug="$(printf '%s' "$target_dir" | sed 's#[/ ]#_#g' | sed 's/[^A-Za-z0-9_.-]/_/g')"
    local out_file="$scans_dir/grype-${slug}.json"
    local err_file="$scans_dir/grype-${slug}.stderr"
    if grype "dir:${target_dir}" --output json >"$out_file" 2>"$err_file"; then
      jq -c '
        .matches[]? |
        {
          sourceScanner: "grype",
          manager: "filesystem",
          ecosystem: (.artifact.language // null),
          package: (.artifact.name // ""),
          version: (.artifact.version // ""),
          dependencyPath: null,
          id: (.vulnerability.id // ""),
          aliases: ((.relatedVulnerabilities // []) | map(.id) // []),
          summary: (.vulnerability.description // ""),
          severity: ((.vulnerability.severity // "unknown") | ascii_downcase | if .=="critical" or .=="high" or .=="medium" or .=="low" then . else "unknown" end),
          published: null,
          modified: null,
          references: []
        }
      ' "$out_file" >> "$findings_ndjson"
    else
      failures=$((failures + 1))
    fi
  done < "$targets_file"

  if [[ "$failures" -gt 0 ]]; then
    _security_append_status "$scanners_ndjson" "grype" "true" "true" "false" "grype scanned $target_count targets with $failures failures" "$targets_file"
  else
    _security_append_status "$scanners_ndjson" "grype" "true" "true" "true" "grype scanned $target_count targets" "$targets_file"
  fi
}

_security_build_report() {
  local mode="$1"
  local config_json="$2"
  local generated_at="$3"
  local run_dir="$4"
  local inventory_dir="$5"
  local outdated_dir="$6"
  local scans_dir="$7"

  jq -n \
    --arg mode "$mode" \
    --arg generated_at "$generated_at" \
    --arg run_dir "$run_dir" \
    --arg inventory_dir "$inventory_dir" \
    --arg outdated_dir "$outdated_dir" \
    --arg scans_dir "$scans_dir" \
    --arg tool_version "$REVELIO_VERSION" \
    --arg schema_version "$REVELIO_REPORT_SCHEMA_VERSION" \
    --arg host_os "$(platform_os)" \
    --arg host_arch "$(platform_arch)" \
    --arg host_name "$(hostname 2>/dev/null || echo unknown)" \
    --argjson config "$config_json" \
    --slurpfile inventory_summary "$inventory_dir/summary.json" \
    --slurpfile outdated_summary "$outdated_dir/summary.json" \
    --slurpfile scan_summary "$scans_dir/summary.json" '
    {
      schemaVersion: $schema_version,
      toolVersion: $tool_version,
      generatedAt: $generated_at,
      mode: $mode,
      runDir: $run_dir,
      host: {
        name: $host_name,
        os: $host_os,
        arch: $host_arch
      },
      config: $config,
      inventory: ($inventory_summary[0] // {}),
      outdated: ($outdated_summary[0] // {}),
      vulnerabilities: ($scan_summary[0] // {}),
      policy: {
        severityThreshold: ($config.defaults.severityThreshold // "high"),
        failOnFindings: (if ($config.defaults.failOnFindings | type) == "boolean" then $config.defaults.failOnFindings else true end),
        failOnScannerErrors: (if ($config.defaults.failOnScannerErrors | type) == "boolean" then $config.defaults.failOnScannerErrors else true end),
        scannerFailureCount: 0,
        matchingFindings: 0,
        failureReasons: [],
        shouldFail: false
      },
      artifacts: {
        config: ($run_dir + "/effective-config.json"),
        report: ($run_dir + "/report.json"),
        inventoryPackages: ($inventory_dir + "/packages.json"),
        inventoryCollectors: ($inventory_dir + "/collectors.json"),
        outdatedItems: ($outdated_dir + "/items.json"),
        scanFindings: ($scans_dir + "/findings.json"),
        scanAdvisories: ($scans_dir + "/advisories.json"),
        scanScanners: ($scans_dir + "/scanners.json")
      }
    }' > "$run_dir/report.json"
}

_security_compute_policy() {
  local report_file="$1"
  local findings_file
  findings_file="$(jq -r '.artifacts.scanFindings' "$report_file")"

  if [[ ! -f "$findings_file" ]]; then
    print_error "Missing findings file: $findings_file"
    return 1
  fi

  local updated_report
  updated_report="$(jq \
    --slurpfile findings "$findings_file" '
    def rank($s):
      if $s == "critical" then 4
      elif $s == "high" then 3
      elif $s == "medium" then 2
      elif $s == "low" then 1
      else 0 end;
    . as $report
    | ($report.policy.severityThreshold // "high") as $threshold
    | (if ($report.policy.failOnFindings | type) == "boolean" then $report.policy.failOnFindings else true end) as $fail_enabled
    | (if ($report.policy.failOnScannerErrors | type) == "boolean" then $report.policy.failOnScannerErrors else true end) as $fail_on_scanner_errors
    | ([($report.inventory.collectors // [])[] | select(.enabled == true and .available == true and .success == false)] | length) as $collector_failures
    | ([($report.outdated.checks // [])[] | select(.enabled == true and .available == true and .success == false)] | length) as $outdated_failures
    | ([($report.vulnerabilities.scanners // [])[] | select(.enabled == true and .available == true and .success == false)] | length) as $scanner_failures
    | ($collector_failures + $outdated_failures + $scanner_failures) as $total_scanner_failures
    | (
        if $threshold == "none" then 999
        else rank($threshold)
        end
      ) as $threshold_rank
    | (
        if $threshold == "none" then 0
        else [($findings[0] // [])[] | select(rank(.severity) >= $threshold_rank)] | length
        end
      ) as $matching
    | (
        [
          (if ($matching > 0 and $fail_enabled == true) then "severity-threshold" else empty end),
          (if ($total_scanner_failures > 0 and $fail_on_scanner_errors == true) then "scanner-errors" else empty end)
        ]
      ) as $failure_reasons
    | .policy.scannerFailureCount = $total_scanner_failures
    | .policy.matchingFindings = $matching
    | .policy.failureReasons = $failure_reasons
    | .policy.shouldFail = (($failure_reasons | length) > 0)
  ' "$report_file")"

  write_file_content "$report_file" "$updated_report"
}

#===================================================================================================
# Exporters: SARIF 2.1.0 and CSV
#===================================================================================================

# Resolve a path that may point to a run dir, a report.json, or an advisories.json.
# Echoes the absolute advisories.json path on stdout, or returns 1 if not found.
# $1 => input path
_security_resolve_advisories_path() {
  local input="$1"
  if [[ -z "$input" ]]; then
    return 1
  fi

  if [[ -f "$input" ]]; then
    case "$(basename "$input")" in
      advisories.json) printf '%s\n' "$input"; return 0 ;;
      report.json)
        local run_dir
        run_dir="$(dirname "$input")"
        if [[ -f "$run_dir/scans/advisories.json" ]]; then
          printf '%s\n' "$run_dir/scans/advisories.json"; return 0
        fi
        ;;
    esac
  fi

  if [[ -d "$input" ]]; then
    if [[ -f "$input/scans/advisories.json" ]]; then
      printf '%s\n' "$input/scans/advisories.json"
      return 0
    fi
    # Inventory-only runs (or scan runs with zero findings) may have no
    # advisories.json. Synthesize an empty array file in the run dir so the
    # exporters can render valid empty output without callers special-casing it.
    if [[ -f "$input/report.json" ]]; then
      ensure_dir "$input/scans" 2>/dev/null || true
      write_file_content "$input/scans/advisories.json" "[]" 2>/dev/null || true
      if [[ -f "$input/scans/advisories.json" ]]; then
        printf '%s\n' "$input/scans/advisories.json"
        return 0
      fi
    fi
  fi

  return 1
}

# Render advisories as SARIF 2.1.0 JSON.
# $1 => run dir, report.json, or advisories.json
# $2 => optional output file (defaults to stdout)
security_export_sarif() {
  require_param "${1:-}" "input" "security_export_sarif" || return 1
  local input="$1"
  local out="${2:-}"

  local advisories
  advisories="$(_security_resolve_advisories_path "$input")" || {
    print_error "Could not locate advisories.json from: $input"
    return 1
  }

  local sarif
  sarif="$(jq -n --slurpfile advisories "$advisories" --arg tool "revelio" --arg version "${REVELIO_VERSION:-0.0.0}" '
    def sev_to_sarif:
      if . == "critical" then "error"
      elif . == "high" then "error"
      elif . == "medium" then "warning"
      elif . == "low" then "note"
      else "none" end;

    ($advisories[0] // []) as $list
    | [ $list[]
        | . as $adv
        | (.vulnerabilities // [{id: ($adv.primaryVulnerabilityId // "REVELIO-UNKNOWN"), severity: $adv.highestSeverity, summary: ""}])[]
        | { adv: $adv, vuln: . } ]
    | . as $rows
    | ($rows | map(.vuln.id) | unique) as $rule_ids
    | {
        version: "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Documents/CommitteeSpecificationDrafts/CSD2/sarif-schema-2.1.0.json",
        runs: [
          {
            tool: {
              driver: {
                name: $tool,
                version: $version,
                informationUri: "https://github.com/a-magdy/revelio",
                rules: [
                  $rule_ids[]
                  | . as $id
                  | ($rows | map(select(.vuln.id == $id))[0]) as $sample
                  | {
                      id: $id,
                      name: $id,
                      shortDescription: { text: ($sample.vuln.summary // $id) },
                      fullDescription:  { text: ($sample.vuln.summary // $id) },
                      defaultConfiguration: { level: ($sample.vuln.severity // "unknown" | sev_to_sarif) },
                      helpUri: ($sample.vuln.references[0]? // null)
                    }
                ]
              }
            },
            results: [
              $rows[]
              | {
                  ruleId: .vuln.id,
                  level: (.vuln.severity // "unknown" | sev_to_sarif),
                  message: { text: ((.vuln.summary // .vuln.id) + " (" + (.adv.manager // "?") + ":" + (.adv.package // "?") + "@" + (.adv.installedVersion // "?") + ")") },
                  locations: [
                    {
                      logicalLocations: [
                        {
                          name: ((.adv.manager // "?") + ":" + (.adv.package // "?")),
                          fullyQualifiedName: (.vuln.dependencyPath // ((.adv.manager // "?") + " > " + (.adv.package // "?"))),
                          kind: "package"
                        }
                      ]
                    }
                  ],
                  properties: {
                    manager: (.adv.manager // null),
                    ecosystem: (.adv.ecosystem // null),
                    package: (.adv.package // null),
                    installedVersion: (.adv.installedVersion // null),
                    fixedVersions: (.vuln.fixedVersions // []),
                    severity: (.vuln.severity // "unknown"),
                    sourceScanners: (.vuln.sourceScanners // [])
                  }
                }
            ]
          }
        ]
      }
  ')" || {
    print_error "Failed to render SARIF"
    return 1
  }

  if [[ -n "$out" ]]; then
    write_file_content "$out" "$sarif"
    print_success "Wrote SARIF: $out"
  else
    printf '%s\n' "$sarif"
  fi
}

# Render advisories as CSV (one row per vulnerability occurrence).
# $1 => run dir, report.json, or advisories.json
# $2 => optional output file (defaults to stdout)
security_export_csv() {
  require_param "${1:-}" "input" "security_export_csv" || return 1
  local input="$1"
  local out="${2:-}"

  local advisories
  advisories="$(_security_resolve_advisories_path "$input")" || {
    print_error "Could not locate advisories.json from: $input"
    return 1
  }

  local csv
  csv="$(jq -nr --slurpfile advisories "$advisories" '
    def csv_field: tostring | gsub("\""; "\"\"") | "\"" + . + "\"";

    [
      "manager","ecosystem","package","installedVersion","vulnerabilityId",
      "severity","summary","fixedVersions","dependencyPath","primaryParent",
      "rootPackage","remediationStatus","upgradeCommand","references"
    ]
    | map(csv_field) | join(",")
    , (
      ($advisories[0] // [])[]
      | . as $adv
      | (.vulnerabilities // [{id: ($adv.primaryVulnerabilityId // "REVELIO-UNKNOWN"), severity: $adv.highestSeverity}])[]
      | [
          ($adv.manager // ""),
          ($adv.ecosystem // ""),
          ($adv.package // ""),
          ($adv.installedVersion // ""),
          (.id // ""),
          (.severity // $adv.highestSeverity // "unknown"),
          (.summary // ""),
          ((.fixedVersions // []) | join(";")),
          (.dependencyPath // ""),
          ($adv.primaryParent // ""),
          ($adv.rootPackage // ""),
          ($adv.remediationStatus // ""),
          ($adv.upgradeCommand // ""),
          ((.references // []) | join(";"))
        ]
      | map(csv_field) | join(",")
    )
  ')" || {
    print_error "Failed to render CSV"
    return 1
  }

  if [[ -n "$out" ]]; then
    write_file_content "$out" "$csv"
    print_success "Wrote CSV: $out"
  else
    printf '%s\n' "$csv"
  fi
}
