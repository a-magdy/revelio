#!/usr/bin/env bash
# Install / uninstall / inspect scheduled revelio runs.
#
# Picks a scheduling backend per platform via `platform_user_scheduler`:
#   - launchd       (macOS) — writes a LaunchAgent plist under
#                   ~/Library/LaunchAgents/dev.revelio.scan.plist
#   - systemd-user  (Linux) — writes a service + timer under
#                   ~/.config/systemd/user/revelio.{service,timer}
#   - cron          (Linux fallback) — appends a sentinel-tagged crontab line
#
# All three backends share the same wire CLI (`schedule_install`,
# `schedule_uninstall`, `schedule_status`) so revelio.sh dispatches without
# branching per OS.

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
# Constants
#===================================================================================================

readonly REVELIO_LAUNCHD_LABEL="dev.revelio.scan"
readonly REVELIO_LAUNCHD_PLIST_NAME="${REVELIO_LAUNCHD_LABEL}.plist"
readonly REVELIO_SYSTEMD_UNIT_NAME="revelio"
# A sentinel comment so we can find/remove our own crontab line precisely.
readonly REVELIO_CRON_SENTINEL="# revelio scheduled scan (managed by revelio schedule)"

#===================================================================================================
# Public API
#===================================================================================================

# Install (or replace) a scheduled revelio run on this host.
# $1 => cadence: hourly | daily | weekly
# $2 => time-of-day "HH:MM" (used by daily/weekly; ignored by hourly)
# $3 => mode: scan | inventory
# $4 => path to the revelio.sh entrypoint to invoke
# $5 => publish-after-run: "true" | "false"
# Returns: 0 on success, 1 on failure.
schedule_install() {
  require_param "${1:-}" "cadence"           "schedule_install" || return 1
  require_param "${2:-}" "time-of-day HH:MM" "schedule_install" || return 1
  require_param "${3:-}" "mode"              "schedule_install" || return 1
  require_param "${4:-}" "revelio entrypoint" "schedule_install" || return 1

  local cadence="$1" at="$2" mode="$3" entrypoint="$4"
  local publish_after="${5:-false}"

  case "$cadence" in hourly|daily|weekly) ;; *)
    print_error "Invalid cadence: $cadence (expected hourly|daily|weekly)"; return 1 ;;
  esac
  if ! [[ "$at" =~ ^([0-1][0-9]|2[0-3]):[0-5][0-9]$ ]]; then
    print_error "Invalid --at value: $at (expected HH:MM, 00:00-23:59)"; return 1
  fi
  case "$mode" in scan|inventory) ;; *)
    print_error "Invalid mode: $mode (expected scan|inventory)"; return 1 ;;
  esac
  if [[ ! -x "$entrypoint" ]]; then
    print_error "Revelio entrypoint not executable: $entrypoint"; return 1
  fi

  local backend
  backend="$(platform_user_scheduler)"
  case "$backend" in
    launchd)      _schedule_install_launchd     "$cadence" "$at" "$mode" "$entrypoint" "$publish_after" ;;
    systemd-user) _schedule_install_systemd     "$cadence" "$at" "$mode" "$entrypoint" "$publish_after" ;;
    cron)         _schedule_install_cron        "$cadence" "$at" "$mode" "$entrypoint" "$publish_after" ;;
    none|*)
      print_error "No supported user-level scheduler available on this host."
      return 1
      ;;
  esac
}

# Remove any revelio schedule installed by `schedule_install`.
# Returns 0 if removed or already absent.
schedule_uninstall() {
  local backend
  backend="$(platform_user_scheduler)"
  case "$backend" in
    launchd)      _schedule_uninstall_launchd ;;
    systemd-user) _schedule_uninstall_systemd ;;
    cron)         _schedule_uninstall_cron ;;
    none|*)
      print_warning "No supported user-level scheduler available; nothing to uninstall."
      return 0
      ;;
  esac
}

# Print the current schedule status (backend + next run + paths).
schedule_status() {
  local backend
  backend="$(platform_user_scheduler)"
  print_info "Scheduler backend: $backend"
  case "$backend" in
    launchd)      _schedule_status_launchd ;;
    systemd-user) _schedule_status_systemd ;;
    cron)         _schedule_status_cron ;;
    none|*)
      print_warning "No supported user-level scheduler available."
      return 0
      ;;
  esac
}

#===================================================================================================
# Shared helpers
#===================================================================================================

# Build the argv that the scheduler should invoke. We always pass --quiet
# (when present) so cron-style output isn't noisy; revelio falls back to its
# normal output if the flag isn't recognized.
_schedule_build_command() {
  local entrypoint="$1" mode="$2" publish_after="$3"
  local args=("$entrypoint" "$mode")
  args+=("--no-fail")  # scheduled runs should record a report, not exit non-zero on findings
  if [[ "$publish_after" == "true" ]]; then
    # Chain via a one-liner shell command at the scheduler layer so failures in
    # publish don't suppress the report itself.
    printf '%q ' "${args[@]}"
    printf '&& %q publish --latest' "$entrypoint"
    return 0
  fi
  printf '%q ' "${args[@]}"
}

#===================================================================================================
# launchd (macOS)
#===================================================================================================

_schedule_launchd_plist_path() {
  printf '%s\n' "$HOME/Library/LaunchAgents/$REVELIO_LAUNCHD_PLIST_NAME"
}

# Render a LaunchAgent plist to stdout. We use a single
# StartCalendarInterval entry; for hourly we omit Hour so launchd fires at
# the chosen Minute every hour.
_schedule_launchd_render_plist() {
  local cadence="$1" at="$2" mode="$3" entrypoint="$4" publish_after="$5"
  local hour="${at%%:*}" minute="${at##*:}"
  local log_dir="$HOME/Library/Logs/Revelio"
  ensure_dir "$log_dir" >/dev/null

  local interval_block=""
  case "$cadence" in
    hourly)
      interval_block="<key>Minute</key><integer>${minute#0}</integer>"
      ;;
    daily)
      interval_block="<key>Hour</key><integer>${hour#0}</integer><key>Minute</key><integer>${minute#0}</integer>"
      ;;
    weekly)
      # Weekday=1 (Monday). Made deliberately fixed; users who want a
      # different day can edit the plist manually.
      interval_block="<key>Weekday</key><integer>1</integer><key>Hour</key><integer>${hour#0}</integer><key>Minute</key><integer>${minute#0}</integer>"
      ;;
  esac

  local extra=""
  if [[ "$publish_after" == "true" ]]; then
    extra='<true/>'
  else
    extra='<false/>'
  fi

  cat <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${REVELIO_LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>$(_schedule_build_command "$entrypoint" "$mode" "$publish_after")</string>
  </array>
  <key>RunAtLoad</key><false/>
  <key>StartCalendarInterval</key>
  <dict>${interval_block}</dict>
  <key>StandardOutPath</key><string>${log_dir}/scheduled.out.log</string>
  <key>StandardErrorPath</key><string>${log_dir}/scheduled.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>REVELIO_PUBLISH_AFTER_RUN</key>${extra}
  </dict>
</dict>
</plist>
PLIST
}

_schedule_install_launchd() {
  local cadence="$1" at="$2" mode="$3" entrypoint="$4" publish_after="$5"
  local plist
  plist="$(_schedule_launchd_plist_path)"
  ensure_dir "$(dirname "$plist")" >/dev/null

  # If a previous version is loaded, bootout before overwriting so launchd
  # picks up the new plist. Errors here are non-fatal (might not be loaded).
  local uid
  uid="$(id -u)"
  launchctl bootout "gui/$uid" "$plist" >/dev/null 2>&1 || true

  _schedule_launchd_render_plist "$cadence" "$at" "$mode" "$entrypoint" "$publish_after" >"$plist"

  if ! launchctl bootstrap "gui/$uid" "$plist" 2>/dev/null; then
    # Older macOS versions still accept the legacy `load` command.
    launchctl load -w "$plist" || {
      print_error "Failed to load LaunchAgent: $plist"
      return 1
    }
  fi

  print_success "Installed launchd schedule: $plist"
  print_info "Cadence=$cadence at=$at mode=$mode publishAfter=$publish_after"
  print_info "Logs: $HOME/Library/Logs/Revelio/scheduled.{out,err}.log"
}

_schedule_uninstall_launchd() {
  local plist uid
  plist="$(_schedule_launchd_plist_path)"
  uid="$(id -u)"

  if [[ -f "$plist" ]]; then
    launchctl bootout "gui/$uid" "$plist" >/dev/null 2>&1 || \
      launchctl unload "$plist" >/dev/null 2>&1 || true
    rm -f "$plist"
    print_success "Removed launchd schedule: $plist"
  else
    print_info "No revelio LaunchAgent installed."
  fi
}

_schedule_status_launchd() {
  local plist uid
  plist="$(_schedule_launchd_plist_path)"
  uid="$(id -u)"
  if [[ -f "$plist" ]]; then
    print_info "Plist: $plist"
    launchctl print "gui/$uid/$REVELIO_LAUNCHD_LABEL" 2>/dev/null \
      | grep -E '^\s*(state|last exit code|next run|program)' \
      || print_warning "LaunchAgent file exists but is not currently loaded."
  else
    print_info "No revelio LaunchAgent installed."
  fi
}

#===================================================================================================
# systemd --user (Linux)
#===================================================================================================

_schedule_systemd_unit_dir() {
  printf '%s\n' "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
}

# Render the .service unit. Type=oneshot so the timer actually waits for the
# previous run to finish before scheduling another.
_schedule_systemd_render_service() {
  local mode="$1" entrypoint="$2" publish_after="$3"
  cat <<UNIT
[Unit]
Description=Revelio scheduled scan ($mode)
Documentation=https://github.com/a-magdy/revelio

[Service]
Type=oneshot
Environment=PATH=/usr/local/bin:/usr/bin:/bin:%h/.local/bin
ExecStart=/bin/sh -c "$(_schedule_build_command "$entrypoint" "$mode" "$publish_after")"
Nice=10
UNIT
}

_schedule_systemd_render_timer() {
  local cadence="$1" at="$2"
  local oncalendar
  case "$cadence" in
    hourly) oncalendar="*-*-* *:${at##*:}:00" ;;
    daily)  oncalendar="*-*-* ${at}:00" ;;
    weekly) oncalendar="Mon *-*-* ${at}:00" ;;
  esac
  cat <<UNIT
[Unit]
Description=Revelio scheduled scan timer

[Timer]
OnCalendar=${oncalendar}
Persistent=true
Unit=${REVELIO_SYSTEMD_UNIT_NAME}.service

[Install]
WantedBy=timers.target
UNIT
}

_schedule_install_systemd() {
  local cadence="$1" at="$2" mode="$3" entrypoint="$4" publish_after="$5"
  local unit_dir service timer
  unit_dir="$(_schedule_systemd_unit_dir)"
  ensure_dir "$unit_dir" >/dev/null
  service="$unit_dir/${REVELIO_SYSTEMD_UNIT_NAME}.service"
  timer="$unit_dir/${REVELIO_SYSTEMD_UNIT_NAME}.timer"

  _schedule_systemd_render_service "$mode" "$entrypoint" "$publish_after" >"$service"
  _schedule_systemd_render_timer   "$cadence" "$at"                       >"$timer"

  systemctl --user daemon-reload || {
    print_error "systemctl --user daemon-reload failed"
    return 1
  }
  systemctl --user enable --now "${REVELIO_SYSTEMD_UNIT_NAME}.timer" || {
    print_error "Failed to enable revelio.timer"
    return 1
  }

  print_success "Installed systemd-user schedule: $timer"
  print_info "Cadence=$cadence at=$at mode=$mode publishAfter=$publish_after"
  print_info "Logs: journalctl --user -u ${REVELIO_SYSTEMD_UNIT_NAME}.service"
  if ! loginctl show-user "$(id -un)" 2>/dev/null | grep -q '^Linger=yes'; then
    print_warning "User linger is OFF; timers won't run when you're logged out."
    print_warning "Enable with: sudo loginctl enable-linger \"\$(id -un)\""
  fi
}

_schedule_uninstall_systemd() {
  local unit_dir service timer
  unit_dir="$(_schedule_systemd_unit_dir)"
  service="$unit_dir/${REVELIO_SYSTEMD_UNIT_NAME}.service"
  timer="$unit_dir/${REVELIO_SYSTEMD_UNIT_NAME}.timer"

  systemctl --user disable --now "${REVELIO_SYSTEMD_UNIT_NAME}.timer" >/dev/null 2>&1 || true
  rm -f "$service" "$timer"
  systemctl --user daemon-reload >/dev/null 2>&1 || true

  print_success "Removed systemd-user schedule (service + timer)."
}

_schedule_status_systemd() {
  local timer="${REVELIO_SYSTEMD_UNIT_NAME}.timer"
  if systemctl --user list-timers --all 2>/dev/null | grep -q "$timer"; then
    systemctl --user list-timers --all | grep -E "(NEXT|$timer)" || true
    systemctl --user status "$timer" --no-pager 2>/dev/null \
      | grep -E '^\s*(Loaded|Active|Trigger):' || true
  else
    print_info "No revelio systemd-user timer installed."
  fi
}

#===================================================================================================
# cron (fallback)
#===================================================================================================

# Convert cadence + HH:MM into a 5-field cron schedule.
_schedule_cron_expression() {
  local cadence="$1" at="$2"
  local hour="${at%%:*}" minute="${at##*:}"
  case "$cadence" in
    hourly) printf '%s\n' "${minute#0} * * * *" ;;
    daily)  printf '%s\n' "${minute#0} ${hour#0} * * *" ;;
    weekly) printf '%s\n' "${minute#0} ${hour#0} * * 1" ;;
  esac
}

# Read the current crontab, drop any line tagged with our sentinel, then
# re-install with the new line appended. Empty input (no existing crontab)
# is handled by ignoring the read failure.
_schedule_install_cron() {
  local cadence="$1" at="$2" mode="$3" entrypoint="$4" publish_after="$5"
  if ! command_exists crontab; then
    print_error "crontab is not installed; cannot install cron schedule."
    return 1
  fi

  local cron_expr cmd new_line tmp
  cron_expr="$(_schedule_cron_expression "$cadence" "$at")"
  cmd="$(_schedule_build_command "$entrypoint" "$mode" "$publish_after")"
  new_line="${cron_expr} ${cmd} >> ${HOME}/.revelio-cron.log 2>&1 ${REVELIO_CRON_SENTINEL}"

  tmp="$(mktemp)"
  crontab -l 2>/dev/null \
    | grep -v -F "$REVELIO_CRON_SENTINEL" \
    > "$tmp" || true
  printf '%s\n' "$new_line" >> "$tmp"

  if ! crontab "$tmp"; then
    rm -f "$tmp"
    print_error "Failed to install crontab line."
    return 1
  fi
  rm -f "$tmp"

  print_success "Installed cron schedule."
  print_info "Cadence=$cadence at=$at mode=$mode publishAfter=$publish_after"
  print_info "Logs: $HOME/.revelio-cron.log"
}

_schedule_uninstall_cron() {
  if ! command_exists crontab; then
    print_info "crontab not installed; nothing to remove."
    return 0
  fi
  local tmp
  tmp="$(mktemp)"
  if ! crontab -l 2>/dev/null | grep -v -F "$REVELIO_CRON_SENTINEL" > "$tmp"; then
    rm -f "$tmp"
    print_info "No existing crontab to clean."
    return 0
  fi
  crontab "$tmp" || {
    rm -f "$tmp"
    print_error "Failed to update crontab."
    return 1
  }
  rm -f "$tmp"
  print_success "Removed revelio cron line(s)."
}

_schedule_status_cron() {
  if ! command_exists crontab; then
    print_info "crontab not installed."
    return 0
  fi
  local matches
  matches="$(crontab -l 2>/dev/null | grep -F "$REVELIO_CRON_SENTINEL" || true)"
  if [[ -z "$matches" ]]; then
    print_info "No revelio cron line installed."
  else
    print_info "Active revelio cron line(s):"
    printf '  %s\n' "$matches"
  fi
}
