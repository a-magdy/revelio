#!/usr/bin/env bash
# Core helpers for standalone revelio CLI

# Brand-aligned ANSI colors. Cleared when NO_COLOR is set or stdout is not a tty.
if [[ -z "${NO_COLOR:-}" && -t 1 ]]; then
  _C_RESET=$'\033[0m'   _C_BOLD=$'\033[1m'    _C_DIM=$'\033[2m'
  _C_GREEN=$'\033[92m'  _C_RED=$'\033[91m'    _C_YELLOW=$'\033[33m'
  _C_PURPLE=$'\033[35m' _C_CYAN=$'\033[36m'
  # Severity levels (used in the scan report table)
  _C_CRIT=$'\033[91m'   _C_HIGH=$'\033[31m'   _C_MED=$'\033[33m'   _C_LOW=$'\033[36m'
else
  _C_RESET=''  _C_BOLD=''   _C_DIM=''
  _C_GREEN=''  _C_RED=''    _C_YELLOW=''
  _C_PURPLE='' _C_CYAN=''
  _C_CRIT=''   _C_HIGH=''   _C_MED=''          _C_LOW=''
fi

print_success() {
  [[ "${REVELIO_QUIET:-0}" == "1" ]] && return 0
  printf $'%s\xE2\x9C\x85 %s%s\n' "$_C_GREEN" "$1" "$_C_RESET"
}
print_warning() { printf $'%s\xE2\x9A\xA0\xEF\xB8\x8F %s%s\n' "$_C_YELLOW" "$1" "$_C_RESET"; }
print_error()   { printf $'%s\xE2\x9D\x8C %s%s\n' "$_C_RED" "$1" "$_C_RESET" >&2; }
print_info() {
  [[ "${REVELIO_QUIET:-0}" == "1" ]] && return 0
  printf $'\xE2\x84\xB9\xEF\xB8\x8F %s\n' "$1"
}

require_param() {
  local value="${1:-}"
  local name="${2:-param}"
  local function_name="${3:-function}"
  if [[ -z "$value" ]]; then
    print_error "Missing required parameter: $name in $function_name"
    return 1
  fi
  return 0
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

trim() {
  local str="${1:-}"
  str="${str#"${str%%[![:space:]]*}"}"
  str="${str%"${str##*[![:space:]]}"}"
  printf '%s\n' "$str"
}

to_lowercase() {
  local value="${1:-}"
  if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
    printf '%s\n' "${value,,}"
  else
    printf '%s\n' "$value" | tr '[:upper:]' '[:lower:]'
  fi
}

check_dependencies() {
  local missing=0
  local dep
  for dep in "$@"; do
    if ! command_exists "$dep"; then
      print_error "Missing required dependency: $dep"
      missing=1
    fi
  done

  if [[ "$missing" -ne 0 ]]; then
    return 1
  fi
  return 0
}
