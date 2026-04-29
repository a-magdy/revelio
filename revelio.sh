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

# shellcheck source=lib/diff.sh
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/diff.sh"

# shellcheck source=lib/schedule.sh
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/schedule.sh"

# shellcheck source=lib/publish.sh
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/publish.sh"

readonly DEFAULT_CONFIG_FILE="${REVELIO_DEFAULT_CONFIG_FILE:-$SCRIPT_DIR/revelio.config.json}"

_show_usage() {
  cat <<EOF
Usage: $(basename "$0") <command> [options]

Commands:
  scan                      Run inventory + outdated + vulnerability checks (default)
  inventory                 Collect inventory only (no vulnerability lookup)
  report [path]             Print summary for an existing report (defaults to latest)
  why <package>             Show why a package is installed (reverse dependencies)
  diff <a> <b>              Compare two reports (run dirs or report.json paths)
  schedule <action>         Manage scheduled runs: install | uninstall | status
  publish [--latest|--run]  Push the latest (or specified) run to the configured git repo
  init-config [path]        Create a starter config file (default: ./revelio.config.json)
  version                   Print revelio version and exit
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
  --quiet, -q               Suppress progress output (cron-friendly)
  --json                    Print final report.json to stdout (skips text summary)
  --help                    Show command help

Options for report:
  --config <path>           Config file (used to resolve output directory)
  --output-dir <path>       Override output directory to search for latest report
  --format <fmt>            text|json|sarif|csv (default: text)
  --output <path>           Write rendered report to file instead of stdout

Options for init-config:
  --force, -f               Overwrite an existing config (a .bak.<ts> backup is kept)

Options for why:
  --manager <mgr>           Limit search to a specific manager (brew, gem, npm, pip, etc.)

Options for diff:
  --format <fmt>            Output format: text|json|markdown (default: text)
  --output <path>           Write to file instead of stdout
  --since <run>             Compare against the given baseline; candidate defaults to latest

Options for schedule install:
  --cadence <c>             hourly|daily|weekly (default: daily)
  --at <HH:MM>              Time-of-day for daily/weekly (default: 03:00)
  --mode <m>                scan|inventory (default: scan)
  --publish                 Run "revelio publish --latest" after each scheduled scan

Options for publish:
  --latest                  Publish the most recent run (default if no --run is given)
  --run <path>              Publish a specific run directory or report.json
  --dry-run                 Stage changes but skip the final git push
  --force                   Publish even if the run recorded scanner failures
  --config <path>           Config file (provides publish.repoUrl, branch, etc.)
  --output-dir <path>       Override output directory used to find the latest run

Examples:
  $(basename "$0") scan --severity high
  $(basename "$0") scan --deep-scan --output-dir ~/.revelio
  $(basename "$0") inventory
  $(basename "$0") report
  $(basename "$0") report ~/.revelio/20260406T010000Z/report.json
  $(basename "$0") why nokogiri
  $(basename "$0") why openssl@3 --manager brew
  $(basename "$0") diff ~/.revelio/run-A ~/.revelio/run-B
  $(basename "$0") diff --since ~/.revelio/run-A --format markdown --output diff.md
  $(basename "$0") schedule install --cadence daily --at 03:00
  $(basename "$0") schedule status
  $(basename "$0") schedule uninstall
  $(basename "$0") publish --latest --dry-run
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
  SCAN_QUIET="false"
  SCAN_JSON="false"

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
      --quiet|-q)
        SCAN_QUIET="true"
        shift
        ;;
      --json)
        SCAN_JSON="true"
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
    dir_raw="$(jq -r '.defaults.outputDir // ""' "$config_path" 2>/dev/null)"
    if [[ -n "$dir_raw" && "$dir_raw" != "null" ]]; then
      _security_expand_path "$dir_raw"
      return 0
    fi
  fi

  platform_default_output_dir
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

  if [[ "$SCAN_QUIET" == "true" ]]; then
    export REVELIO_QUIET=1
  fi

  security_run "$mode" "$effective_config" || return 1

  if [[ "$SCAN_JSON" == "true" ]]; then
    jq . "$REVELIO_LAST_REPORT"
  elif [[ "$SCAN_QUIET" != "true" ]]; then
    security_print_report_summary "$REVELIO_LAST_REPORT"
  fi

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
  REPORT_FORMAT="text"
  REPORT_OUTPUT=""

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
      --format)
        require_param "${2:-}" "format" "_parse_report_args" || return 1
        REPORT_FORMAT="$2"
        shift 2
        ;;
      --output)
        require_param "${2:-}" "output path" "_parse_report_args" || return 1
        REPORT_OUTPUT="$2"
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

  local report_file run_dir

  if [[ -n "$REPORT_PATH" ]]; then
    if [[ -d "$REPORT_PATH" && -f "$REPORT_PATH/report.json" ]]; then
      run_dir="$REPORT_PATH"
      report_file="$REPORT_PATH/report.json"
    else
      report_file="$(_resolve_report_file_path "$REPORT_PATH")" || return 1
      run_dir="$(dirname "$report_file")"
    fi
  else
    local config_for_resolve="${REPORT_CONFIG_PATH:-}"
    if [[ -z "$config_for_resolve" && -f "$DEFAULT_CONFIG_FILE" ]]; then
      config_for_resolve="$DEFAULT_CONFIG_FILE"
    fi

    local output_dir
    output_dir="$(_resolve_output_dir "$config_for_resolve" "$REPORT_OUTPUT_DIR")"
    report_file="$(_resolve_latest_report "$output_dir")" || return 1
    run_dir="$(dirname "$report_file")"
    [[ "$REPORT_FORMAT" == "text" ]] && print_info "Using latest report: $report_file"
  fi

  case "$REPORT_FORMAT" in
    text)
      security_print_report_summary "$report_file"
      ;;
    json)
      if [[ -n "$REPORT_OUTPUT" ]]; then
        jq . "$report_file" > "$REPORT_OUTPUT"
        print_success "Wrote JSON: $REPORT_OUTPUT"
      else
        jq . "$report_file"
      fi
      ;;
    sarif)
      security_export_sarif "$run_dir" "$REPORT_OUTPUT"
      ;;
    csv)
      security_export_csv "$run_dir" "$REPORT_OUTPUT"
      ;;
    *)
      print_error "Unknown report format: $REPORT_FORMAT (expected text|json|sarif|csv)"
      return 1
      ;;
  esac
}

_run_init_config() {
  # Default to CWD so init-config doesn't try to overwrite the bundled repo config
  local target_path="$PWD/revelio.config.json"
  local force="false"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --force|-f) force="true"; shift ;;
      --help|-h) _show_usage; return 0 ;;
      -*)
        print_error "Unknown init-config option: $1"; return 1 ;;
      *) target_path="$1"; shift ;;
    esac
  done
  security_init_config_file "$target_path" "$force"
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

_parse_diff_args() {
  DIFF_BASELINE=""
  DIFF_CANDIDATE=""
  DIFF_FORMAT="text"
  DIFF_OUTPUT=""
  DIFF_SINCE=""
  DIFF_CONFIG_PATH=""
  DIFF_OUTPUT_DIR=""

  local positionals=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --format)
        require_param "${2:-}" "format" "_parse_diff_args" || return 1
        DIFF_FORMAT="$2"
        shift 2
        ;;
      --output)
        require_param "${2:-}" "output path" "_parse_diff_args" || return 1
        DIFF_OUTPUT="$2"
        shift 2
        ;;
      --since)
        require_param "${2:-}" "baseline run" "_parse_diff_args" || return 1
        DIFF_SINCE="$2"
        shift 2
        ;;
      --config)
        require_param "${2:-}" "config path" "_parse_diff_args" || return 1
        DIFF_CONFIG_PATH="$2"
        shift 2
        ;;
      --output-dir)
        require_param "${2:-}" "output dir" "_parse_diff_args" || return 1
        DIFF_OUTPUT_DIR="$2"
        shift 2
        ;;
      --help|-h)
        _show_usage
        return 2
        ;;
      -*)
        print_error "Unknown diff option: $1"
        _show_usage
        return 1
        ;;
      *)
        positionals+=("$1")
        shift
        ;;
    esac
  done

  if [[ -n "$DIFF_SINCE" ]]; then
    DIFF_BASELINE="$DIFF_SINCE"
    if [[ ${#positionals[@]} -ge 1 ]]; then
      DIFF_CANDIDATE="${positionals[0]}"
    fi
  else
    if [[ ${#positionals[@]} -lt 2 ]]; then
      print_error "Usage: $(basename "$0") diff <baseline> <candidate>  (or --since <baseline>)"
      return 1
    fi
    DIFF_BASELINE="${positionals[0]}"
    DIFF_CANDIDATE="${positionals[1]}"
  fi
}

_run_diff() {
  local parse_status=0
  if _parse_diff_args "$@"; then
    :
  else
    parse_status=$?
    [[ "$parse_status" -eq 2 ]] && return 0
    return "$parse_status"
  fi

  check_dependencies jq

  # If no candidate is provided (e.g. with --since), default to the latest report.
  if [[ -z "$DIFF_CANDIDATE" ]]; then
    local config_for_resolve="${DIFF_CONFIG_PATH:-}"
    if [[ -z "$config_for_resolve" && -f "$DEFAULT_CONFIG_FILE" ]]; then
      config_for_resolve="$DEFAULT_CONFIG_FILE"
    fi
    local output_dir
    output_dir="$(_resolve_output_dir "$config_for_resolve" "$DIFF_OUTPUT_DIR")"
    DIFF_CANDIDATE="$(_resolve_latest_report "$output_dir")" || return 1
    print_info "Diffing against latest: $DIFF_CANDIDATE"
  fi

  diff_run "$DIFF_BASELINE" "$DIFF_CANDIDATE" "$DIFF_FORMAT" "$DIFF_OUTPUT"
}

_parse_publish_args() {
  PUBLISH_RUN=""
  PUBLISH_DRY_RUN="false"
  PUBLISH_FORCE="false"
  PUBLISH_CONFIG_PATH=""
  PUBLISH_OUTPUT_DIR=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --latest)
        # No-op: latest is the default when no --run is given.
        shift ;;
      --run)
        require_param "${2:-}" "run path" "_parse_publish_args" || return 1
        PUBLISH_RUN="$2"; shift 2 ;;
      --dry-run)
        PUBLISH_DRY_RUN="true"; shift ;;
      --force)
        PUBLISH_FORCE="true"; shift ;;
      --config)
        require_param "${2:-}" "config path" "_parse_publish_args" || return 1
        PUBLISH_CONFIG_PATH="$2"; shift 2 ;;
      --output-dir)
        require_param "${2:-}" "output dir" "_parse_publish_args" || return 1
        PUBLISH_OUTPUT_DIR="$2"; shift 2 ;;
      --help|-h)
        _show_usage; return 2 ;;
      *)
        print_error "Unknown publish option: $1"; return 1 ;;
    esac
  done
}

_run_publish() {
  local parse_status=0
  if _parse_publish_args "$@"; then
    :
  else
    parse_status=$?
    [[ "$parse_status" -eq 2 ]] && return 0
    return "$parse_status"
  fi

  check_dependencies jq git || return 1

  local config_path="${PUBLISH_CONFIG_PATH:-}"
  if [[ -z "$config_path" && -f "$DEFAULT_CONFIG_FILE" ]]; then
    config_path="$DEFAULT_CONFIG_FILE"
  fi

  local effective_config
  effective_config="$(security_build_effective_config \
    "$config_path" "$PUBLISH_OUTPUT_DIR" "" "" "" "" "")" || return 1

  # Resolve the run directory to publish.
  local run_dir
  if [[ -n "$PUBLISH_RUN" ]]; then
    if [[ -f "$PUBLISH_RUN" ]]; then
      run_dir="$(dirname "$PUBLISH_RUN")"
    elif [[ -d "$PUBLISH_RUN" ]]; then
      run_dir="$PUBLISH_RUN"
    else
      print_error "Run path not found: $PUBLISH_RUN"
      return 1
    fi
  else
    local output_dir latest_report
    output_dir="$(_resolve_output_dir "$config_path" "$PUBLISH_OUTPUT_DIR")"
    latest_report="$(_resolve_latest_report "$output_dir")" || return 1
    run_dir="$(dirname "$latest_report")"
  fi

  publish_run "$effective_config" "$run_dir" "$PUBLISH_DRY_RUN" "$PUBLISH_FORCE"
}

_run_schedule() {
  local action="${1:-status}"
  if [[ $# -gt 0 ]]; then shift; fi

  case "$action" in
    install)
      local cadence="daily" at="03:00" mode="scan" publish_after="false"
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --cadence)
            require_param "${2:-}" "cadence" "_run_schedule" || return 1
            cadence="$2"; shift 2 ;;
          --at)
            require_param "${2:-}" "time-of-day" "_run_schedule" || return 1
            at="$2"; shift 2 ;;
          --mode)
            require_param "${2:-}" "mode" "_run_schedule" || return 1
            mode="$2"; shift 2 ;;
          --publish)
            publish_after="true"; shift ;;
          --help|-h)
            _show_usage; return 0 ;;
          *)
            print_error "Unknown schedule install option: $1"; return 1 ;;
        esac
      done
      schedule_install "$cadence" "$at" "$mode" "$SCRIPT_DIR/$(basename "$0")" "$publish_after"
      ;;
    uninstall)
      schedule_uninstall
      ;;
    status|"")
      schedule_status
      ;;
    --help|-h|help)
      _show_usage
      ;;
    *)
      print_error "Unknown schedule action: $action (expected install|uninstall|status)"
      return 1
      ;;
  esac
}

main() {
  local command="${1:-scan}"
  if [[ $# -gt 0 ]]; then
    shift
  fi

  # Handle top-level flags that don't take a subcommand.
  case "$command" in
    --version|-V)
      printf 'revelio %s\n' "$REVELIO_VERSION"
      return 0
      ;;
    --help|-h)
      _show_usage
      return 0
      ;;
  esac

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
    diff)
      _run_diff "$@"
      ;;
    schedule)
      _run_schedule "$@"
      ;;
    publish)
      _run_publish "$@"
      ;;
    init-config)
      _run_init_config "$@"
      ;;
    version|--version|-V)
      printf 'revelio %s\n' "$REVELIO_VERSION"
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
