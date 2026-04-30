#!/usr/bin/env bash
# Publish a revelio run to a configured git repository.
#
# Reads `publish.*` keys from the effective config and pushes the run dir
# (or just `report.json`) into a remote git repo so multiple machines can
# share an audit trail without standing up additional infrastructure.
#
# Token handling: the token is read from the named environment variable
# (default REVELIO_GIT_TOKEN) and injected per-invocation via
# `git -c http.extraheader=` so it never appears in remote URLs or logs.
#
# Path-stripping: $HOME is rewritten to ~ in copied JSON artifacts so
# reports remain portable across hosts.

if ! declare -f print_error &>/dev/null; then
  # shellcheck source=core.sh
  # shellcheck disable=SC1091
  source "$(dirname "${BASH_SOURCE[0]}")/core.sh"
fi
if ! declare -f write_file_content &>/dev/null; then
  # shellcheck source=file.sh
  # shellcheck disable=SC1091
  source "$(dirname "${BASH_SOURCE[0]}")/file.sh"
fi
if ! declare -f platform_os &>/dev/null; then
  # shellcheck source=platform.sh
  # shellcheck disable=SC1091
  source "$(dirname "${BASH_SOURCE[0]}")/platform.sh"
fi

#===================================================================================================
# Public API
#===================================================================================================

# Publish a run directory to the configured remote git repo.
# $1 => effective config JSON
# $2 => run directory (must contain report.json)
# $3 => "true" for --dry-run (skip push), else any value
# $4 => "true" for --force (push even on scanner crash)
# Returns: 0 on success, 1 on failure.
publish_run() {
  require_param "${1:-}" "effective_config_json" "publish_run" || return 1
  require_param "${2:-}" "run directory"         "publish_run" || return 1

  local config_json="$1"
  local run_dir="$2"
  local dry_run="${3:-false}"
  local force="${4:-false}"

  if [[ ! -d "$run_dir" || ! -f "$run_dir/report.json" ]]; then
    print_error "Run directory missing report.json: $run_dir"
    return 1
  fi

  # Pull publish.* config and bail early if disabled / unconfigured.
  local enabled repo_url branch path_template commit_template token_env
  enabled="$(jq -r '.publish.enabled // false' <<<"$config_json")"
  repo_url="$(jq -r '.publish.repoUrl // ""' <<<"$config_json")"
  branch="$(jq -r '.publish.branch // "main"' <<<"$config_json")"
  path_template="$(jq -r '.publish.pathTemplate // "reports/{hostname}/{run-id}/"' <<<"$config_json")"
  commit_template="$(jq -r '.publish.commitMessageTemplate // "chore(revelio): scan {run-id} on {hostname}"' <<<"$config_json")"
  token_env="$(jq -r '.publish.tokenEnvVar // "REVELIO_GIT_TOKEN"' <<<"$config_json")"

  if [[ "$enabled" != "true" ]]; then
    print_error "publish.enabled is false in config; refusing to publish."
    return 1
  fi
  if [[ -z "$repo_url" ]]; then
    print_error "publish.repoUrl is empty in config; cannot publish."
    return 1
  fi

  # Refuse to push a run that recorded scanner crashes unless --force.
  if [[ "$force" != "true" ]]; then
    local should_fail
    should_fail="$(jq -r '.policy.shouldFail // false' "$run_dir/report.json")"
    local scanner_failures
    scanner_failures="$(jq -r '.policy.scannerFailureCount // 0' "$run_dir/report.json")"
    if [[ "$scanner_failures" != "0" ]] && [[ "$should_fail" == "true" ]]; then
      print_error "Run reports $scanner_failures scanner failure(s); refusing to publish without --force."
      return 1
    fi
  fi

  check_dependencies git || return 1

  local hostname run_id
  hostname="$(hostname 2>/dev/null || echo unknown)"
  run_id="$(basename "$run_dir")"

  local resolved_path resolved_msg
  resolved_path="$(_publish_render_template "$path_template"   "$hostname" "$run_id")"
  resolved_msg="$(_publish_render_template  "$commit_template" "$hostname" "$run_id")"

  # Stage a working clone in a temp dir so we never mutate the user's repo.
  local work_dir clone_dir
  work_dir="$(mktemp -d)"
  clone_dir="$work_dir/repo"

  # Capture work_dir at trap-registration time (double quotes) so cleanup runs
  # cleanly even after the local goes out of scope under `set -u`.
  # shellcheck disable=SC2064
  trap "_publish_cleanup '$work_dir'" RETURN

  print_info "Publishing run $run_id → $repo_url ($branch:$resolved_path)"

  if ! _publish_clone "$repo_url" "$branch" "$clone_dir" "$token_env"; then
    return 1
  fi

  local target_dir="$clone_dir/$resolved_path"
  ensure_dir "$target_dir" >/dev/null

  if ! _publish_copy_run_dir "$run_dir" "$target_dir"; then
    return 1
  fi

  # Always update a top-level latest.json pointer for convenience.
  if [[ -f "$target_dir/report.json" ]]; then
    cp "$target_dir/report.json" "$clone_dir/latest.json"
  fi

  if ! (
    cd "$clone_dir" || exit 1
    git add -A
    if git diff --cached --quiet; then
      print_info "No changes to publish (artifacts identical to last push)."
      exit 0
    fi
    git -c user.name="revelio" -c user.email="revelio@$hostname" \
      commit -m "$resolved_msg" >/dev/null
    if [[ "$dry_run" == "true" ]]; then
      print_info "[dry-run] Skipping git push."
      exit 0
    fi
    _publish_push "$repo_url" "$branch" "$token_env" || exit 1
  ); then
    return 1
  fi

  if [[ "$dry_run" != "true" ]]; then
    print_success "Published run $run_id to $repo_url ($branch)"
  else
    print_success "[dry-run] Prepared publish of run $run_id (no push performed)"
  fi
}

#===================================================================================================
# Helpers
#===================================================================================================

_publish_cleanup() {
  local dir="${1:-}"
  if [[ -n "$dir" && -d "$dir" ]]; then
    rm -rf "$dir"
  fi
}

# Substitute {hostname} and {run-id} placeholders in path / commit templates.
_publish_render_template() {
  local template="$1" hostname="$2" run_id="$3"
  local out="$template"
  out="${out//\{hostname\}/$hostname}"
  out="${out//\{run-id\}/$run_id}"
  printf '%s\n' "$out"
}

# Resolve a token from its env var name without ever printing the value.
# Sets globals only when called from the same shell (`local -n` style).
_publish_token_value() {
  local var_name="$1"
  if [[ -z "$var_name" ]]; then return 0; fi
  printf '%s' "${!var_name:-}"
}

# Build the per-invocation `git -c http.extraheader=` argv used to inject the
# token into a single push without writing it to .git/config or the URL.
# Outputs: zero or two lines (the two -c args), suitable for `mapfile -t`.
_publish_token_args() {
  local var_name="$1"
  local value
  value="$(_publish_token_value "$var_name")"
  if [[ -z "$value" ]]; then
    return 0
  fi
  # Bearer auth is what GitHub PATs/fine-grained tokens accept; basic auth
  # works too, but bearer keeps the value out of the visible header name.
  printf -- '-c\n'
  printf 'http.extraheader=AUTHORIZATION: bearer %s\n' "$value"
}

# Perform a shallow clone of the publish branch (or initialize an empty
# repo when the branch doesn't yet exist on the remote).
_publish_clone() {
  local repo_url="$1" branch="$2" clone_dir="$3" token_env="$4"

  local -a token_args=()
  mapfile -t token_args < <(_publish_token_args "$token_env")

  if git "${token_args[@]}" clone --depth=1 --branch "$branch" "$repo_url" "$clone_dir" 2>/dev/null; then
    return 0
  fi

  # Branch may not exist yet; clone default and create the branch.
  print_info "Branch '$branch' not found on remote; creating it from default."
  if ! git "${token_args[@]}" clone --depth=1 "$repo_url" "$clone_dir"; then
    print_error "git clone failed for $repo_url"
    return 1
  fi
  (
    cd "$clone_dir" || exit 1
    git checkout -B "$branch" >/dev/null
  )
}

# Copy the run directory into the target path inside the clone.
# Rewrites $HOME to ~ in JSON files so reports are portable across hosts.
_publish_copy_run_dir() {
  local run_dir="$1" target_dir="$2"

  if ! cp -R "$run_dir/." "$target_dir/"; then
    print_error "Failed to copy run dir into clone: $run_dir → $target_dir"
    return 1
  fi

  # Best-effort path-stripping. We only touch JSON files to avoid mangling
  # binary or unrelated content. `sed -i` differs between BSD and GNU; use
  # the portable two-arg form.
  local file home_escaped
  home_escaped="$(printf '%s' "$HOME" | sed 's/[\/&]/\\&/g')"
  while IFS= read -r -d '' file; do
    sed -i.bak "s/${home_escaped}/~/g" "$file" && rm -f "$file.bak"
  done < <(find "$target_dir" -type f -name '*.json' -print0)
}

# Push to the remote with the per-invocation token header.
_publish_push() {
  local repo_url="$1" branch="$2" token_env="$3"
  local -a token_args=()
  mapfile -t token_args < <(_publish_token_args "$token_env")

  if ! git "${token_args[@]}" push -u origin "$branch"; then
    print_error "git push failed (branch=$branch)."
    return 1
  fi
}
