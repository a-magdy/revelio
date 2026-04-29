#!/usr/bin/env bash
# Compare two revelio reports.
#
# Produces a structured delta between two `report.json` files (or two run
# directories that contain one). The diff is computed across three axes:
#
#   1. Findings (advisories) — keyed on (manager, ecosystem, package, id,
#      dependencyPath) so the same fusion identity revelio uses internally
#      drives diff classification. Buckets: new, resolved, unchanged.
#   2. Inventory drift — packages whose installed version moved between
#      runs, plus added/removed packages.
#   3. Policy — change in severityThreshold or shouldFail outcome.
#
# Output formats: text (terminal default), json (machine-readable),
# markdown (publish-friendly). Exit code respects the `severityThreshold`
# of the *baseline* report: non-zero when any new finding meets or
# exceeds that threshold (and there are no new findings that resolved).

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

#===================================================================================================
# Public API
#===================================================================================================

# Compute the diff between two reports and emit it in the requested format.
# $1 => path to baseline report.json (or run dir)
# $2 => path to candidate report.json (or run dir)
# $3 => format: text | json | markdown (default: text)
# $4 => optional output file (default: stdout)
# Returns: 0 if no new findings at-or-above baseline threshold, 1 otherwise.
diff_run() {
  require_param "${1:-}" "baseline report" "diff_run" || return 1
  require_param "${2:-}" "candidate report" "diff_run" || return 1

  local baseline_arg="$1"
  local candidate_arg="$2"
  local format="${3:-text}"
  local out_file="${4:-}"

  local baseline_file candidate_file
  baseline_file="$(_diff_resolve_report "$baseline_arg")" || return 1
  candidate_file="$(_diff_resolve_report "$candidate_arg")" || return 1

  case "$format" in
    text|json|markdown) ;;
    *)
      print_error "Unknown diff format: $format (expected text|json|markdown)"
      return 1
      ;;
  esac

  local diff_json
  diff_json="$(_diff_compute "$baseline_file" "$candidate_file")" || return 1

  local rendered
  case "$format" in
    json)     rendered="$(jq '.' <<<"$diff_json")" ;;
    markdown) rendered="$(_diff_render_markdown "$diff_json")" ;;
    text)     rendered="$(_diff_render_text "$diff_json")" ;;
  esac

  if [[ -n "$out_file" ]]; then
    write_file_content "$out_file" "$rendered" || return 1
  else
    printf '%s\n' "$rendered"
  fi

  # Exit code: derive from the baseline's severityThreshold and the count of
  # new findings at or above that rank.
  local should_fail
  should_fail="$(jq -r '.policy.shouldFail' <<<"$diff_json")"
  if [[ "$should_fail" == "true" ]]; then
    return 1
  fi
  return 0
}

#===================================================================================================
# Helpers
#===================================================================================================

# Resolve a CLI argument (file path or directory) to a concrete report.json.
_diff_resolve_report() {
  local arg="$1"
  if [[ -f "$arg" ]]; then
    printf '%s\n' "$arg"
    return 0
  fi
  if [[ -d "$arg" && -f "$arg/report.json" ]]; then
    printf '%s\n' "$arg/report.json"
    return 0
  fi
  print_error "Report path not found: $arg"
  return 1
}

# Read the advisories file referenced by a report, or emit an empty array
# when the report has no scan artifacts (e.g. inventory-only mode).
_diff_load_advisories() {
  local report_file="$1"
  local advisories_path
  advisories_path="$(jq -r '.artifacts.scanAdvisories // ""' "$report_file" 2>/dev/null)"
  if [[ -n "$advisories_path" && -f "$advisories_path" ]]; then
    cat "$advisories_path"
  else
    printf '[]\n'
  fi
}

# Read the inventory packages file referenced by a report.
_diff_load_packages() {
  local report_file="$1"
  local packages_path
  packages_path="$(jq -r '.artifacts.inventoryPackages // ""' "$report_file" 2>/dev/null)"
  if [[ -n "$packages_path" && -f "$packages_path" ]]; then
    cat "$packages_path"
  else
    printf '[]\n'
  fi
}

# Compute the structured diff between two report.json files as JSON.
# Outputs a single JSON object with `meta`, `findings`, `inventory`, and `policy` keys.
_diff_compute() {
  local baseline_file="$1"
  local candidate_file="$2"

  local baseline_advisories candidate_advisories baseline_packages candidate_packages
  baseline_advisories="$(_diff_load_advisories "$baseline_file")"
  candidate_advisories="$(_diff_load_advisories "$candidate_file")"
  baseline_packages="$(_diff_load_packages "$baseline_file")"
  candidate_packages="$(_diff_load_packages "$candidate_file")"

  # The advisory fusion key is (manager, ecosystem, package, id, dependencyPath).
  # We build that key here to match what `_security_fuse_findings` produces and
  # bucket advisories into new/resolved/unchanged. Severity rank is reused for
  # the policy gate downstream.
  jq -n \
    --slurpfile base_report_arr "$baseline_file" \
    --slurpfile cand_report_arr "$candidate_file" \
    --argjson base_adv "$baseline_advisories" \
    --argjson cand_adv "$candidate_advisories" \
    --argjson base_pkgs "$baseline_packages" \
    --argjson cand_pkgs "$candidate_packages" '
    # Severity ranks used everywhere else in revelio.
    def rank($s):
      if $s == "critical" then 4
      elif $s == "high" then 3
      elif $s == "medium" then 2
      elif $s == "low" then 1
      else 0 end;

    # Fusion key for an advisory.
    def adv_key:
      [(.manager // ""), (.ecosystem // ""), (.package // ""), (.id // ""),
       ((.dependencyPath // []) | tostring)] | @tsv;

    # Inventory key for a package (manager + name).
    def pkg_key:
      [(.manager // ""), (.name // .package // "")] | @tsv;

    ($base_report_arr[0]) as $base_report
    | ($cand_report_arr[0]) as $cand_report
    # Build advisory maps the long way (reduce) to preserve duplicate keys as
    # arrays rather than silently collapsing them as `from_entries` would.
    | reduce ($base_adv[]) as $a ({}; .[($a | adv_key)] += [$a]) as $base_map
    | reduce ($cand_adv[]) as $a ({}; .[($a | adv_key)] += [$a]) as $cand_map

    | ($base_map | keys_unsorted) as $base_keys
    | ($cand_map | keys_unsorted) as $cand_keys

    | ([$cand_keys[] | select(. as $k | ($base_map[$k] // []) | length == 0)]
        | map($cand_map[.][0])) as $new_findings
    | ([$base_keys[] | select(. as $k | ($cand_map[$k] // []) | length == 0)]
        | map($base_map[.][0])) as $resolved_findings
    | ([$cand_keys[] | select(. as $k | ($base_map[$k] // []) | length > 0)]
        | map($cand_map[.][0])) as $unchanged_findings

    # Build inventory maps: key -> first matching package record.
    | reduce ($base_pkgs[]) as $p ({}; .[($p | pkg_key)] = $p) as $base_pkg_map
    | reduce ($cand_pkgs[]) as $p ({}; .[($p | pkg_key)] = $p) as $cand_pkg_map

    | ($base_pkg_map | keys_unsorted) as $base_pkg_keys
    | ($cand_pkg_map | keys_unsorted) as $cand_pkg_keys

    | ([$cand_pkg_keys[] | select(. as $k | $base_pkg_map[$k] | not)]
        | map($cand_pkg_map[.])) as $added_packages
    | ([$base_pkg_keys[] | select(. as $k | $cand_pkg_map[$k] | not)]
        | map($base_pkg_map[.])) as $removed_packages
    | ([$cand_pkg_keys[]
         | . as $k
         | select(($base_pkg_map[$k] // null) != null)
         | select((($cand_pkg_map[$k]).version // "") != (($base_pkg_map[$k]).version // ""))
         | {
             manager: ($cand_pkg_map[$k].manager // ""),
             name:    ($cand_pkg_map[$k].name // ""),
             from:    ($base_pkg_map[$k].version // ""),
             to:      ($cand_pkg_map[$k].version // "")
           }]) as $version_drift

    # Policy gate: derive baseline threshold rank, count new findings >= threshold.
    | (($base_report.policy.severityThreshold // "high")) as $threshold
    | (if $threshold == "none" then 999 else rank($threshold) end) as $threshold_rank
    | ([$new_findings[] | select(rank(.highestSeverity // .severity // "unknown") >= $threshold_rank)] | length) as $new_at_threshold
    | ($new_at_threshold > 0) as $should_fail

    | {
        meta: {
          baseline: {
            file: $base_report.runDir,
            generatedAt: $base_report.generatedAt,
            toolVersion: ($base_report.toolVersion // null),
            schemaVersion: ($base_report.schemaVersion // null),
            host: ($base_report.host // null)
          },
          candidate: {
            file: $cand_report.runDir,
            generatedAt: $cand_report.generatedAt,
            toolVersion: ($cand_report.toolVersion // null),
            schemaVersion: ($cand_report.schemaVersion // null),
            host: ($cand_report.host // null)
          },
          schemaMismatch: (
            ($base_report.schemaVersion // null) != ($cand_report.schemaVersion // null)
          )
        },
        findings: {
          new: $new_findings,
          resolved: $resolved_findings,
          unchanged: $unchanged_findings,
          counts: {
            new: ($new_findings | length),
            resolved: ($resolved_findings | length),
            unchanged: ($unchanged_findings | length)
          }
        },
        inventory: {
          added: $added_packages,
          removed: $removed_packages,
          versionDrift: $version_drift,
          counts: {
            added: ($added_packages | length),
            removed: ($removed_packages | length),
            versionDrift: ($version_drift | length)
          }
        },
        policy: {
          severityThreshold: $threshold,
          newFindingsAtOrAboveThreshold: $new_at_threshold,
          shouldFail: $should_fail
        }
      }
  '
}

# Render the diff as plain terminal text. Mirrors the layout of
# `security_print_report_summary` so users see a familiar shape.
_diff_render_text() {
  local diff_json="$1"
  jq -r '
    def fmt_finding:
      "  - [\(.highestSeverity // .severity // "?")] \(.manager // "?")/\(.package // "?")@\(.installedVersion // .version // "?") (\(.id // (.identifiers // [] | join(","))))";

    "Revelio diff",
    "  baseline:  \(.meta.baseline.file)  (\(.meta.baseline.generatedAt))",
    "  candidate: \(.meta.candidate.file)  (\(.meta.candidate.generatedAt))",
    (if .meta.schemaMismatch then "  ⚠️  schema version differs (\(.meta.baseline.schemaVersion) → \(.meta.candidate.schemaVersion))" else empty end),
    "",
    "Findings:",
    "  new:       \(.findings.counts.new)",
    "  resolved:  \(.findings.counts.resolved)",
    "  unchanged: \(.findings.counts.unchanged)",
    "",
    (if (.findings.new | length) > 0 then ("New findings:", (.findings.new | map(fmt_finding) | .[])) else empty end),
    (if (.findings.resolved | length) > 0 then ("", "Resolved findings:", (.findings.resolved | map(fmt_finding) | .[])) else empty end),
    "",
    "Inventory:",
    "  added:        \(.inventory.counts.added)",
    "  removed:      \(.inventory.counts.removed)",
    "  versionDrift: \(.inventory.counts.versionDrift)",
    (if (.inventory.versionDrift | length) > 0 then
       ("", "Version drift:",
        (.inventory.versionDrift | map("  - \(.manager)/\(.name): \(.from) → \(.to)") | .[]))
     else empty end),
    "",
    "Policy:",
    "  severityThreshold: \(.policy.severityThreshold)",
    "  new at-or-above:   \(.policy.newFindingsAtOrAboveThreshold)",
    "  shouldFail:        \(.policy.shouldFail)"
  ' <<<"$diff_json"
}

# Render the diff as Markdown for committing alongside published reports.
_diff_render_markdown() {
  local diff_json="$1"
  jq -r '
    def fmt_finding:
      "- **[\(.highestSeverity // .severity // "?")]** `\(.manager // "?")` / `\(.package // "?")@\(.installedVersion // .version // "?")` — \(.id // (.identifiers // [] | join(", ")))";

    "# Revelio Diff",
    "",
    "| | Baseline | Candidate |",
    "|---|---|---|",
    "| Run        | `\(.meta.baseline.file)` | `\(.meta.candidate.file)` |",
    "| Generated  | \(.meta.baseline.generatedAt) | \(.meta.candidate.generatedAt) |",
    "| Tool ver.  | \(.meta.baseline.toolVersion // "n/a") | \(.meta.candidate.toolVersion // "n/a") |",
    "| Host       | \(.meta.baseline.host.name // "n/a") | \(.meta.candidate.host.name // "n/a") |",
    "",
    (if .meta.schemaMismatch then "> ⚠️ Schema version differs (\(.meta.baseline.schemaVersion) → \(.meta.candidate.schemaVersion)). Diff is best-effort." else empty end),
    "",
    "## Findings",
    "",
    "| | Count |",
    "|---|---|",
    "| New        | \(.findings.counts.new) |",
    "| Resolved   | \(.findings.counts.resolved) |",
    "| Unchanged  | \(.findings.counts.unchanged) |",
    "",
    (if (.findings.new | length) > 0
       then ("### New", "", (.findings.new | map(fmt_finding) | .[]), "")
       else empty end),
    (if (.findings.resolved | length) > 0
       then ("### Resolved", "", (.findings.resolved | map(fmt_finding) | .[]), "")
       else empty end),
    "## Inventory",
    "",
    "| | Count |",
    "|---|---|",
    "| Added         | \(.inventory.counts.added) |",
    "| Removed       | \(.inventory.counts.removed) |",
    "| Version drift | \(.inventory.counts.versionDrift) |",
    "",
    (if (.inventory.versionDrift | length) > 0
       then ("### Version drift", "",
             "| Manager | Package | From | To |",
             "|---|---|---|---|",
             (.inventory.versionDrift | map("| \(.manager) | \(.name) | \(.from) | \(.to) |") | .[]),
             "")
       else empty end),
    "## Policy",
    "",
    "- Severity threshold: **\(.policy.severityThreshold)**",
    "- New findings at or above threshold: **\(.policy.newFindingsAtOrAboveThreshold)**",
    "- shouldFail: **\(.policy.shouldFail)**"
  ' <<<"$diff_json"
}
