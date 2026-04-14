#!/usr/bin/env bash
set -euo pipefail

#===================================================================================================
# Revelio CLI
#
# Audits machine-installed tools and package ecosystems for risk signals:
# - Inventory of installed packages across major ecosystems
# - Outdated package checks
# - Vulnerability lookup (OSV) with optional deep filesystem scanning (grype)
#
# Usage:
#   ./revelio.sh scan [options]
#   ./revelio.sh inventory [options]
#   ./revelio.sh report [path] [--config <path>] [--output-dir <path>]
#   ./revelio.sh init-config [config-path]
#
# Options (scan/inventory):
#   --config <path>       Config file (default: local revelio.config.json, or REVELIO_DEFAULT_CONFIG_FILE when set)
#   --output-dir <path>   Override output directory for run artifacts
#   --severity <level>    none|low|medium|high|critical (scan mode policy threshold)
#   --deep-scan           Enable deep scan mode
#   --no-deep-scan        Disable deep scan mode
#   --no-fail             Disable policy-fail exits (findings + scanner errors)
#   --fail                Enable policy-fail exits (findings + scanner errors)
#   --fail-on-scanner-errors      Fail when enabled scanners/collectors fail
#   --no-fail-on-scanner-errors   Do not fail on scanner/collector failures
#   --offline             Disable network vulnerability queries
#   --online              Enable network vulnerability queries
#   --help                Show help
#===================================================================================================

# Require Bash 4+ because Revelio uses features such as namerefs and
# associative arrays that are not available in macOS's bundled Bash 3.2.
_require_supported_bash() {
  if [[ "${BASH_VERSINFO[0]:-0}" -lt 4 ]]; then
    printf '❌ Revelio requires Bash 4 or newer. macOS ships Bash %s.\n' "${BASH_VERSION:-unknown}" >&2
    printf '   Install a supported version with: brew install bash\n' >&2
    printf '   Then run Revelio with that Bash or put it earlier in your PATH.\n' >&2
    return 1
  fi

  return 0
}

_require_supported_bash || exit 1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/security.sh
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/security.sh"

readonly DEFAULT_CONFIG_FILE="${REVELIO_DEFAULT_CONFIG_FILE:-$SCRIPT_DIR/revelio.config.json}"

_show_usage() {
  cat <<EOF
Usage: $(basename "$0") <command> [options]

Commands:
  scan                      Run inventory + outdated + vulnerability checks (default)
  inventory                 Collect inventory only (no vulnerability lookup)
  report [path]             Print summary for an existing report (defaults to latest)
  why <package>             Show why a package is installed (reverse dependencies)
  init-config [path]        Create a starter config file (default: ./revelio.config.json)
  help                      Show this help

Options for scan/inventory:
  --config <path>           Config file path
  --output-dir <path>       Override output directory
  --severity <level>        none|low|medium|high|critical
  --deep-scan               Enable deep scan mode
  --no-deep-scan            Disable deep scan mode
  --no-fail                 Disable policy-fail exits (findings + scanner errors)
  --fail                    Enable policy-fail exits (findings + scanner errors)
  --fail-on-scanner-errors  Fail when enabled scanners/collectors fail
  --no-fail-on-scanner-errors
                            Ignore scanner/collector failures for exit policy
  --offline                 Disable OSV/network queries
  --online                  Enable OSV/network queries
  --help                    Show command help

Options for report:
  --config <path>           Config file (used to resolve output directory)
  --output-dir <path>       Override output directory to search for latest report

Options for why:
  --manager <mgr>           Limit search to a specific manager (brew, gem, npm, pip, etc.)

Examples:
  $(basename "$0") scan --severity high
  $(basename "$0") scan --deep-scan --output-dir ~/.revelio
  $(basename "$0") inventory
  $(basename "$0") report
  $(basename "$0") report ~/.revelio/20260406T010000Z/report.json
  $(basename "$0") why nokogiri
  $(basename "$0") why openssl@3 --manager brew
  $(basename "$0") init-config
EOF
}

_parse_scan_inventory_args() {
  CONFIG_PATH=""
  OUTPUT_OVERRIDE=""
  SEVERITY_OVERRIDE=""
  DEEP_OVERRIDE=""
  FAIL_OVERRIDE=""
  NETWORK_OVERRIDE=""
  SCANNER_FAIL_OVERRIDE=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config)
        require_param "${2:-}" "config path" "_parse_scan_inventory_args" || return 1
        CONFIG_PATH="$2"
        shift 2
        ;;
      --output-dir)
        require_param "${2:-}" "output dir" "_parse_scan_inventory_args" || return 1
        OUTPUT_OVERRIDE="$2"
        shift 2
        ;;
      --severity)
        require_param "${2:-}" "severity level" "_parse_scan_inventory_args" || return 1
        SEVERITY_OVERRIDE="$2"
        shift 2
        ;;
      --deep-scan)
        DEEP_OVERRIDE="true"
        shift
        ;;
      --no-deep-scan)
        DEEP_OVERRIDE="false"
        shift
        ;;
      --no-fail)
        FAIL_OVERRIDE="false"
        SCANNER_FAIL_OVERRIDE="false"
        shift
        ;;
      --fail)
        FAIL_OVERRIDE="true"
        SCANNER_FAIL_OVERRIDE="true"
        shift
        ;;
      --fail-on-scanner-errors)
        SCANNER_FAIL_OVERRIDE="true"
        shift
        ;;
      --no-fail-on-scanner-errors)
        SCANNER_FAIL_OVERRIDE="false"
        shift
        ;;
      --offline)
        NETWORK_OVERRIDE="false"
        shift
        ;;
      --online)
        NETWORK_OVERRIDE="true"
        shift
        ;;
      --help|-h)
        _show_usage
        return 2
        ;;
      *)
        print_error "Unknown option: $1"
        _show_usage
        return 1
        ;;
    esac
  done
}

_resolve_report_file_path() {
  local input_path="$1"

  if [[ -f "$input_path" ]]; then
    echo "$input_path"
    return 0
  fi

  if [[ -d "$input_path" && -f "$input_path/report.json" ]]; then
    echo "$input_path/report.json"
    return 0
  fi

  print_error "Report path not found: $input_path"
  return 1
}

_resolve_output_dir() {
  local config_path="${1:-}"
  local output_override="${2:-}"

  if [[ -n "$output_override" ]]; then
    _security_expand_path "$output_override"
    return 0
  fi

  if [[ -n "$config_path" && -f "$config_path" ]]; then
    local dir_raw
    dir_raw="$(jq -r '.defaults.outputDir // "~/.revelio"' "$config_path" 2>/dev/null)"
    _security_expand_path "$dir_raw"
    return 0
  fi

  printf '%s\n' "$HOME/.revelio"
}

_resolve_latest_report() {
  local output_dir="$1"

  if [[ ! -d "$output_dir" ]]; then
    print_error "Output directory does not exist: $output_dir"
    return 1
  fi

  local latest_file="" latest_ts=""
  local candidate_dir candidate_report ts

  for candidate_dir in "$output_dir"/*/; do
    [[ -d "$candidate_dir" ]] || continue
    candidate_report="$candidate_dir/report.json"
    [[ -f "$candidate_report" ]] || continue

    ts="$(jq -r '.generatedAt // ""' "$candidate_report" 2>/dev/null)" || continue
    if [[ -z "$ts" ]]; then
      ts="$(basename "$candidate_dir")"
    fi

    if [[ -z "$latest_ts" || "$ts" > "$latest_ts" ]]; then
      latest_ts="$ts"
      latest_file="$candidate_report"
    fi
  done

  if [[ -z "$latest_file" ]]; then
    print_error "No reports found in: $output_dir"
    return 1
  fi

  echo "$latest_file"
}

_run_scan_or_inventory() {
  local mode="$1"
  shift

  local parse_status=0
  if _parse_scan_inventory_args "$@"; then
    :
  else
    parse_status=$?
    [[ "$parse_status" -eq 2 ]] && return 0
    return "$parse_status"
  fi

  check_dependencies jq

  if [[ -z "$CONFIG_PATH" && -f "$DEFAULT_CONFIG_FILE" ]]; then
    CONFIG_PATH="$DEFAULT_CONFIG_FILE"
  fi

  local effective_config
  effective_config="$(security_build_effective_config \
    "$CONFIG_PATH" \
    "$OUTPUT_OVERRIDE" \
    "$SEVERITY_OVERRIDE" \
    "$DEEP_OVERRIDE" \
    "$FAIL_OVERRIDE" \
    "$NETWORK_OVERRIDE" \
    "$SCANNER_FAIL_OVERRIDE")" || return 1

  security_run "$mode" "$effective_config" || return 1
  security_print_report_summary "$REVELIO_LAST_REPORT"

  if [[ "$mode" == "scan" ]]; then
    local policy_exit=0
    security_report_exit_code "$REVELIO_LAST_REPORT" || policy_exit=$?
    return "$policy_exit"
  fi

  return 0
}

_parse_report_args() {
  REPORT_PATH=""
  REPORT_CONFIG_PATH=""
  REPORT_OUTPUT_DIR=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config)
        require_param "${2:-}" "config path" "_parse_report_args" || return 1
        REPORT_CONFIG_PATH="$2"
        shift 2
        ;;
      --output-dir)
        require_param "${2:-}" "output dir" "_parse_report_args" || return 1
        REPORT_OUTPUT_DIR="$2"
        shift 2
        ;;
      --help|-h)
        _show_usage
        return 2
        ;;
      -*)
        print_error "Unknown report option: $1"
        _show_usage
        return 1
        ;;
      *)
        REPORT_PATH="$1"
        shift
        ;;
    esac
  done
}

_run_report() {
  local parse_status=0
  if _parse_report_args "$@"; then
    :
  else
    parse_status=$?
    [[ "$parse_status" -eq 2 ]] && return 0
    return "$parse_status"
  fi

  local report_file

  if [[ -n "$REPORT_PATH" ]]; then
    report_file="$(_resolve_report_file_path "$REPORT_PATH")" || return 1
  else
    local config_for_resolve="${REPORT_CONFIG_PATH:-}"
    if [[ -z "$config_for_resolve" && -f "$DEFAULT_CONFIG_FILE" ]]; then
      config_for_resolve="$DEFAULT_CONFIG_FILE"
    fi

    local output_dir
    output_dir="$(_resolve_output_dir "$config_for_resolve" "$REPORT_OUTPUT_DIR")"
    report_file="$(_resolve_latest_report "$output_dir")" || return 1
    print_info "Using latest report: $report_file"
  fi

  security_print_report_summary "$report_file"
}

_run_init_config() {
  # Default to CWD so init-config doesn't try to overwrite the bundled repo config
  local target_path="${1:-$PWD/revelio.config.json}"
  security_init_config_file "$target_path"
}

_parse_why_args() {
  WHY_PACKAGE=""
  WHY_MANAGER=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --manager)
        require_param "${2:-}" "manager name" "_parse_why_args" || return 1
        WHY_MANAGER="$2"
        shift 2
        ;;
      --help|-h)
        _show_usage
        return 2
        ;;
      -*)
        print_error "Unknown why option: $1"
        _show_usage
        return 1
        ;;
      *)
        WHY_PACKAGE="$1"
        shift
        ;;
    esac
  done
}

_run_why() {
  local parse_status=0
  if _parse_why_args "$@"; then
    :
  else
    parse_status=$?
    [[ "$parse_status" -eq 2 ]] && return 0
    return "$parse_status"
  fi

  if [[ -z "$WHY_PACKAGE" ]]; then
    print_error "Usage: $(basename "$0") why <package-name> [--manager <mgr>]"
    return 1
  fi

  security_why_package "$WHY_PACKAGE" "$WHY_MANAGER"
}

main() {
  local command="${1:-scan}"
  if [[ $# -gt 0 ]]; then
    shift
  fi

  # Allow "scan" options without explicitly writing "scan".
  if [[ "$command" == -* ]]; then
    set -- "$command" "$@"
    command="scan"
  fi

  case "$command" in
    scan)
      _run_scan_or_inventory "scan" "$@"
      ;;
    inventory)
      _run_scan_or_inventory "inventory" "$@"
      ;;
    report)
      _run_report "$@"
      ;;
    why)
      _run_why "$@"
      ;;
    init-config)
      _run_init_config "$@"
      ;;
    help|--help|-h)
      _show_usage
      ;;
    *)
      print_error "Unknown command: $command"
      _show_usage
      return 1
      ;;
  esac
}

main "$@"
