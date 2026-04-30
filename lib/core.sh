#!/usr/bin/env bash
# Core helpers for standalone revelio CLI

print_success() {
  [[ "${REVELIO_QUIET:-0}" == "1" ]] && return 0
  printf "\xE2\x9C\x85 %s\n" "$1"
}
print_warning() { printf "\xE2\x9A\xA0\xEF\xB8\x8F %s\n" "$1"; }
print_error() { printf "\xE2\x9D\x8C %s\n" "$1" >&2; }
print_info() {
  [[ "${REVELIO_QUIET:-0}" == "1" ]] && return 0
  printf "\xE2\x84\xB9\xEF\xB8\x8F %s\n" "$1"
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
