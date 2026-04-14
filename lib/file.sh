#!/usr/bin/env bash
# File/path helpers for standalone revelio CLI

if ! declare -f print_error >/dev/null 2>&1; then
  # shellcheck source=core.sh
  # shellcheck disable=SC1091
  source "$(dirname "${BASH_SOURCE[0]}")/core.sh"
fi

write_file_content() {
  local file_path="${1:-}"
  local content="${2:-}"

  if [[ -z "$file_path" ]]; then
    print_error "Usage: write_file_content <file_path> <content>"
    return 1
  fi

  ensure_dir "$(dirname "$file_path")" || return 1
  printf '%s\n' "$content" > "$file_path"
}

path_normalize() {
  local path="${1:-}"
  local prefix=""
  local result=""
  local segment
  local -a parts=()

  if [[ "${path:0:1}" == "/" ]]; then
    prefix="/"
  fi

  IFS='/' read -ra segments <<< "$path"
  for segment in "${segments[@]}"; do
    case "$segment" in
      ""|".")
        ;;
      "..")
        if [[ ${#parts[@]} -gt 0 ]]; then
          unset 'parts[${#parts[@]}-1]'
        fi
        ;;
      *)
        parts+=("$segment")
        ;;
    esac
  done

  result="${prefix}$(IFS='/'; echo "${parts[*]}")"
  if [[ -z "$result" ]]; then
    result="."
  fi
  printf '%s\n' "$result"
}

is_absolute_path() {
  [[ "${1:0:1}" == "/" ]]
}

ensure_absolute_path() {
  local path="${1:-}"
  if is_absolute_path "$path"; then
    printf '%s\n' "$path"
  else
    printf '%s\n' "$PWD/$path"
  fi
}

ensure_dir() {
  local dir="${1:-}"
  if [[ -z "$dir" ]]; then
    print_error "Usage: ensure_dir <directory>"
    return 1
  fi
  if [[ ! -d "$dir" ]]; then
    mkdir -p "$dir"
  fi
}
