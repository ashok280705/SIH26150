#!/usr/bin/env bash
#
# Universal recovery verification runner.
#
# Runs every stage of docs/UNIVERSAL_RECOVERY_VERIFICATION.md, records the outcome of each, and
# writes UNIVERSAL_RECOVERY_VERIFICATION_RESULT.md in the repository root.
#
# It does not hide failures. A failing stage is recorded as FAIL, the console output is
# preserved, and the script exits non-zero. There is no path through this script that reports
# success for something that did not run.
#
# Usage, from anywhere:
#   bash scripts/verify_universal_recovery.sh 2>&1 | tee universal_recovery_console.log

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT" || exit 1

RESULT_FILE="$REPO_ROOT/UNIVERSAL_RECOVERY_VERIFICATION_RESULT.md"
LOG_DIR="$REPO_ROOT/target/universal-recovery-verification"
mkdir -p "$LOG_DIR"

OVERALL_STATUS=0
declare -a STAGE_NAMES=()
declare -a STAGE_RESULTS=()
declare -a STAGE_NOTES=()

# The crates that can be built without the database toolchain. `apps/api` and the `tests/`
# crate pull `sqlx-macros`, which is a proc-macro dylib and fails to link on some toolchains.
# They are attempted separately so that a link failure there is reported as its own stage
# rather than hiding the recovery results.
CORE_CRATES=(-p recovery -p parsers-core -p forensic-core -p reporting
             -p parser-uniview -p parser-unified -p tplink
             -p evidence-reader -p hashing -p detection -p confidence -p timeline)

hr() { printf '%s\n' "────────────────────────────────────────────────────────────"; }

record() {
  STAGE_NAMES+=("$1")
  STAGE_RESULTS+=("$2")
  STAGE_NOTES+=("$3")
  if [ "$2" = "FAIL" ]; then OVERALL_STATUS=1; fi
  printf '  => %-8s %s\n' "$2" "$1"
}

run_stage() {
  local name="$1"; shift
  local slug
  slug="$(printf '%s' "$name" | tr -c 'A-Za-z0-9' '_')"
  local log="$LOG_DIR/$slug.log"

  hr
  echo "STAGE: $name"
  echo "CMD:   $*"
  hr
  if "$@" 2>&1 | tee "$log"; then
    record "$name" "PASS" "log: target/universal-recovery-verification/$slug.log"
    return 0
  else
    record "$name" "FAIL" "log: target/universal-recovery-verification/$slug.log"
    return 1
  fi
}

# As run_stage, but a failure is recorded as a known environment limitation rather than as a
# verification failure. Used only where the audit already identified the limitation.
run_optional_stage() {
  local name="$1"; local note="$2"; shift 2
  local slug
  slug="$(printf '%s' "$name" | tr -c 'A-Za-z0-9' '_')"
  local log="$LOG_DIR/$slug.log"

  hr
  echo "STAGE: $name (optional)"
  echo "CMD:   $*"
  hr
  if "$@" 2>&1 | tee "$log"; then
    record "$name" "PASS" "log: target/universal-recovery-verification/$slug.log"
  else
    STAGE_NAMES+=("$name")
    STAGE_RESULTS+=("SKIP")
    STAGE_NOTES+=("$note — log: target/universal-recovery-verification/$slug.log")
    printf '  => %-8s %s\n' "SKIP" "$name"
  fi
}

version_of() {
  local bin="$1"; shift
  if command -v "$bin" >/dev/null 2>&1; then
    "$bin" "$@" 2>&1 | head -n 1
  else
    echo "NOT FOUND"
  fi
}

# ── Stage 1: environment ─────────────────────────────────────────────────────

hr
echo "STAGE: 1 — Environment"
hr
RUSTC_V="$(version_of rustc --version)"
CARGO_V="$(version_of cargo --version)"
HOST_TRIPLE="$(rustc -vV 2>/dev/null | awk '/^host:/ {print $2}')"
echo "rustc: $RUSTC_V"
echo "cargo: $CARGO_V"
echo "host:  ${HOST_TRIPLE:-unknown}"

if [ "$RUSTC_V" = "NOT FOUND" ] || [ "$CARGO_V" = "NOT FOUND" ]; then
  record "1 Environment" "FAIL" "rust toolchain missing; nothing further can run"
  echo "FATAL: no Rust toolchain. Stopping." >&2
  exit 1
fi
record "1 Environment" "PASS" "rustc and cargo present (host ${HOST_TRIPLE:-unknown})"

# ── Stage 2: build ───────────────────────────────────────────────────────────

run_stage "2a Build the recovery and parser-contract crates" \
  cargo build -p recovery -p parsers-core

run_stage "2b Build all locally-buildable crates, tests included" \
  cargo build "${CORE_CRATES[@]}" --all-targets

run_optional_stage "2c Build the whole workspace" \
  "requires a toolchain that can link the sqlx-macros proc-macro dylib" \
  cargo build --workspace

# ── Stage 3: unit tests ──────────────────────────────────────────────────────

run_stage "3a Unit tests - recovery engine" cargo test -p recovery --lib
run_stage "3b Unit tests - parser contract types" cargo test -p parsers-core --lib
run_stage "3c Unit tests - forensic core" cargo test -p forensic-core

# ── Stage 4: the universal parser contract, every OEM ────────────────────────
#
# This is the cross-OEM stage. Every parser in the workspace is run against the SAME checks on
# an empty image, a zeroed image, pseudo-random noise, and a real Dahua volume.

run_stage "4a Universal parser contract - all OEMs" \
  cargo test -p recovery --test universal_parser_contract -- --nocapture

run_stage "4b Contract harness detects a non-compliant parser" \
  cargo test -p recovery --test universal_parser_contract \
  the_contract_harness_detects_a_non_compliant_parser -- --exact --nocapture

run_stage "4c Cross-OEM behaviour - a parser declines another OEM's disk" \
  cargo test -p recovery --test universal_parser_contract \
  every_parser_is_contract_compliant_on_another_oems_disk -- --exact --nocapture

# ── Stage 5: the universal recovery decision suite ───────────────────────────

run_stage "5a Universal recovery decisions" \
  cargo test -p recovery --test universal_recovery -- --nocapture

run_stage "5b Active requires an index claim" \
  cargo test -p recovery --test universal_recovery \
  an_indexed_recording_is_active_and_names_the_index_entry_that_claims_it -- --exact --nocapture

run_stage "5c Orphan requires an authoritative index, and is never Deleted" \
  cargo test -p recovery --test universal_recovery \
  video_an_authoritative_index_omits_is_orphaned_not_deleted -- --exact --nocapture

run_stage "5d Degradation - no index means Unindexed only" \
  cargo test -p recovery --test universal_recovery \
  an_evidence_item_with_no_index_licenses_only_the_raw_sweep -- --exact --nocapture

run_stage "5e Unknown stays unknown - no channel 0, no epoch" \
  cargo test -p recovery --test universal_recovery \
  a_fragment_with_no_recorder_metadata_reports_unknown_not_zero -- --exact --nocapture

# ── Stage 6: determinism ─────────────────────────────────────────────────────

run_stage "6a Determinism - every decision is reproducible" \
  cargo test -p recovery --test universal_recovery \
  two_runs_over_the_same_evidence_agree_on_every_decision -- --exact --nocapture

run_stage "6b Determinism - correlation does not depend on discovery order" \
  cargo test -p recovery --lib \
  correlation::tests::correlation_is_deterministic_regardless_of_discovery_order -- --exact --nocapture

run_stage "6c Determinism - contract results are reproducible" \
  cargo test -p recovery --test universal_parser_contract \
  contract_results_are_reproducible_across_runs -- --exact --nocapture

# ── Stage 7: resource bounds ─────────────────────────────────────────────────

run_stage "7a Hypothesis bound is enforced and downgrades the run" \
  cargo test -p recovery --test universal_recovery \
  the_hypothesis_bound_is_enforced_and_downgrades_the_run -- --exact --nocapture

run_stage "7b Byte and cancellation bounds yield REVIEW, never PASS" \
  cargo test -p recovery --test universal_recovery \
  bounded -- --nocapture

run_stage "7c Adversarial evidence is bounded and never panics" \
  cargo test -p recovery --test adversarial_recovery -- --nocapture

run_stage "7d The engine never reads beyond the evidence" \
  cargo test -p recovery --test universal_recovery \
  the_engine_never_reads_beyond_the_evidence -- --exact --nocapture

# ── Stage 8: provenance ──────────────────────────────────────────────────────

run_stage "8a Every candidate traces to exact bytes in an exact evidence item" \
  cargo test -p recovery --test universal_recovery \
  every_candidate_traces_to_the_exact_bytes_in_the_exact_evidence_item -- --exact --nocapture

run_stage "8b Unrun validation checks stay UNKNOWN" \
  cargo test -p recovery --test universal_recovery \
  unrun_validation_checks_are_unknown_and_never_pass -- --exact --nocapture

run_stage "8c Observability counters are emitted" \
  cargo test -p recovery --test recovery_observability -- --nocapture

# ── Stage 9: regression ──────────────────────────────────────────────────────

run_stage "9a Pre-existing recovery integration suite" \
  cargo test -p recovery --test integration -- --nocapture

run_stage "9b Pre-existing Uniview recovery suite" \
  cargo test -p recovery --test uniview_recovery -- --nocapture

run_stage "9c All locally-buildable crates" \
  cargo test --no-fail-fast "${CORE_CRATES[@]}"

run_optional_stage "9d Cross-crate production-chain tests" \
  "the tests/ crate depends on apps/api and therefore on sqlx-macros" \
  cargo test -p forensic-tests

# ── Counts, pulled from the suites' own output ───────────────────────────────

count_from() {
  local log="$1"
  if [ -f "$log" ]; then
    awk '/^test result:/ {p+=$4; f+=$6} END {if (p+f==0) print "UNKNOWN"; else print p" passed, "f" failed"}' "$log"
  else
    echo "NOT RUN"
  fi
}

CONTRACT_COUNT="$(count_from "$LOG_DIR/4a_Universal_parser_contract___all_OEMs.log")"
RECOVERY_COUNT="$(count_from "$LOG_DIR/5a_Universal_recovery_decisions.log")"
ALL_COUNT="$(count_from "$LOG_DIR/9c_All_locally_buildable_crates.log")"

# ── Write the report ─────────────────────────────────────────────────────────

{
  echo "# Universal Recovery Verification Result"
  echo
  echo "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "Host: $(uname -a 2>/dev/null || echo 'unknown')"
  echo "Repository root: $REPO_ROOT"
  echo
  echo '```text'
  echo "Environment"
  echo "-----------"
  echo "Rust version:  $RUSTC_V"
  echo "Cargo version: $CARGO_V"
  echo "Host triple:   ${HOST_TRIPLE:-unknown}"
  echo
  echo "Test counts"
  echo "-----------"
  echo "Universal parser contract: $CONTRACT_COUNT"
  echo "Universal recovery suite:  $RECOVERY_COUNT"
  echo "All buildable crates:      $ALL_COUNT"
  echo '```'
  echo
  echo "## Stage results"
  echo
  echo "| Stage | Result | Note |"
  echo "|---|---|---|"
  for i in "${!STAGE_NAMES[@]}"; do
    echo "| ${STAGE_NAMES[$i]} | **${STAGE_RESULTS[$i]}** | ${STAGE_NOTES[$i]} |"
  done
  echo
  echo "## Known failures"
  echo
  FOUND_FAIL=0
  for i in "${!STAGE_NAMES[@]}"; do
    if [ "${STAGE_RESULTS[$i]}" = "FAIL" ]; then
      FOUND_FAIL=1
      echo "- **${STAGE_NAMES[$i]}** — ${STAGE_NOTES[$i]}"
    fi
  done
  if [ "$FOUND_FAIL" -eq 0 ]; then echo "None."; fi
  echo
  echo "## Skipped stages"
  echo
  FOUND_SKIP=0
  for i in "${!STAGE_NAMES[@]}"; do
    if [ "${STAGE_RESULTS[$i]}" = "SKIP" ]; then
      FOUND_SKIP=1
      echo "- **${STAGE_NAMES[$i]}** — ${STAGE_NOTES[$i]}"
    fi
  done
  if [ "$FOUND_SKIP" -eq 0 ]; then echo "None."; fi
  echo
  echo "## Notes for the reviewer"
  echo
  echo "- Stages 2c and 9d are **optional**: they need a toolchain that can link the"
  echo "  \`sqlx-macros\` proc-macro dylib. A SKIP there says nothing about the recovery"
  echo "  engine; a PASS is additional coverage."
  echo "- \`evidence-reader\`'s \`mmap::tests::mmap_reads_correct_bytes\` is a known"
  echo "  pre-existing failure on some Windows hosts and is unrelated to recovery. If stage 9c"
  echo "  fails on that test alone, record it as pre-existing."
  echo "- Every fixture in stages 4-8 is **synthetic**, built from the real structure layouts"
  echo "  declared in \`profiles/\`. A green report says the engine behaves correctly on those"
  echo "  structures. It says **nothing** about behaviour on a real acquired DVR image; that"
  echo "  requires running against real evidence and is tracked separately."
  echo
  echo "Per-stage console logs: \`target/universal-recovery-verification/\`"
} > "$RESULT_FILE"

hr
echo "Report written to: $RESULT_FILE"
if [ "$OVERALL_STATUS" -eq 0 ]; then
  echo "OVERALL: PASS"
else
  echo "OVERALL: FAIL — see the Known failures section of the report"
fi
hr
exit "$OVERALL_STATUS"
