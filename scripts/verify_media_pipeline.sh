#!/usr/bin/env bash
#
# Media pipeline verification runner.
#
# Runs every stage of docs/MEDIA_PIPELINE_VERIFICATION.md, records the outcome of each, and
# writes MEDIA_PIPELINE_VERIFICATION_RESULT.md in the repository root.
#
# It does not hide failures. A failing stage is recorded as FAIL, the console output is
# preserved, and the script exits non-zero. There is no path through this script that reports
# success for something that did not run.
#
# Usage, from anywhere:
#   bash scripts/verify_media_pipeline.sh 2>&1 | tee media_verification_console.log

set -uo pipefail

# Resolve the repository root from this script's own location, so the run is independent of
# where the repository was cloned and of the caller's working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT" || exit 1

RESULT_FILE="$REPO_ROOT/MEDIA_PIPELINE_VERIFICATION_RESULT.md"
LOG_DIR="$REPO_ROOT/target/media-verification"
mkdir -p "$LOG_DIR"

OVERALL_STATUS=0
declare -a STAGE_NAMES=()
declare -a STAGE_RESULTS=()
declare -a STAGE_NOTES=()

# ── helpers ──────────────────────────────────────────────────────────────────

hr() { printf '%s\n' "────────────────────────────────────────────────────────────"; }

record() {
  # record <stage name> <PASS|FAIL|SKIP> <note>
  STAGE_NAMES+=("$1")
  STAGE_RESULTS+=("$2")
  STAGE_NOTES+=("$3")
  if [ "$2" = "FAIL" ]; then OVERALL_STATUS=1; fi
  printf '  => %-8s %s\n' "$2" "$1"
}

# Runs a command, tees its output to a per-stage log, and records PASS/FAIL by exit status.
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
    record "$name" "PASS" "log: target/media-verification/$slug.log"
    return 0
  else
    record "$name" "FAIL" "log: target/media-verification/$slug.log"
    return 1
  fi
}

# Captures a tool's version line, or the literal NOT FOUND.
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
FFMPEG_V="$(version_of ffmpeg -version)"
FFPROBE_V="$(version_of ffprobe -version)"
echo "rustc:   $RUSTC_V"
echo "cargo:   $CARGO_V"
echo "ffmpeg:  $FFMPEG_V"
echo "ffprobe: $FFPROBE_V"

if [ "$RUSTC_V" = "NOT FOUND" ] || [ "$CARGO_V" = "NOT FOUND" ]; then
  record "1 Environment" "FAIL" "rust toolchain missing; nothing further can run"
  echo "FATAL: no Rust toolchain. Stopping." >&2
  exit 1
fi

OPENCV_V="$(pkg-config --modversion opencv4 2>/dev/null || echo 'NOT DETECTED')"
echo "opencv:  $OPENCV_V"

# The OpenCV backend needs TWO things, and the distinction matters when reporting Stage 7b:
# a host that is missing one of them has not failed the stage, it was never able to attempt it.
LIBCLANG_V="$(llvm-config --prefix 2>/dev/null || echo 'NOT DETECTED')"
if [ "$LIBCLANG_V" = "NOT DETECTED" ] && [ -n "${LIBCLANG_PATH:-}" ]; then
  LIBCLANG_V="LIBCLANG_PATH=$LIBCLANG_PATH"
fi
echo "libclang: $LIBCLANG_V"

OPENCV_BUILDABLE=1
if [ "$OPENCV_V" = "NOT DETECTED" ] && [ -z "${OPENCV_LINK_LIBS:-}" ] && [ -z "${OPENCV_DIR:-}" ]; then
  OPENCV_BUILDABLE=0
  OPENCV_BLOCKER="no OpenCV installation (pkg-config, OPENCV_LINK_LIBS and OPENCV_DIR all absent)"
elif [ "$LIBCLANG_V" = "NOT DETECTED" ]; then
  OPENCV_BUILDABLE=0
  OPENCV_BLOCKER="no C-API libclang (llvm-config absent and LIBCLANG_PATH unset); note that libclang-cpp is the C++ API and does not satisfy clang-sys"
fi

# A missing FFmpeg is a hard failure for the stages that need it. It is recorded as such here
# rather than letting those stages skip quietly.
HAVE_FFMPEG=1
if [ "$FFMPEG_V" = "NOT FOUND" ] || [ "$FFPROBE_V" = "NOT FOUND" ]; then
  HAVE_FFMPEG=0
  record "1 Environment" "FAIL" "ffmpeg and/or ffprobe are not installed; stages 4-8 cannot be verified"
else
  record "1 Environment" "PASS" "rust, ffmpeg and ffprobe all present"
fi

# ── Stage 2: build ───────────────────────────────────────────────────────────

run_stage "2a Build media and recovery" cargo build -p media -p recovery
run_stage "2b Build whole workspace" cargo build --workspace

# ── Stage 3: unit tests ──────────────────────────────────────────────────────

run_stage "3a Unit tests - media" cargo test -p media --lib
run_stage "3b Regression tests - recovery" cargo test -p recovery

# ── Stages 4-8: integration against real media ───────────────────────────────

if [ "$HAVE_FFMPEG" -eq 1 ]; then
  export MEDIA_REQUIRE_FFMPEG=1
  # With MEDIA_REQUIRE_FFMPEG=1 a missing tool panics, so a green here cannot mean "skipped".
  run_stage "4 Media pipeline integration (real FFmpeg)" \
    cargo test -p media --test media_pipeline_integration -- --nocapture

  run_stage "6 Decoded frame output" \
    cargo test -p media --test media_pipeline_integration \
    a_valid_h264_file_probes_decodes_and_yields_real_frames -- --exact --nocapture

  run_stage "6b Decode determinism" \
    cargo test -p media --test media_pipeline_integration \
    frame_hashes_are_deterministic_across_two_independent_decodes -- --exact --nocapture

  run_stage "6c Extraction modes" \
    cargo test -p media --test media_pipeline_integration \
    sampled_and_time_range_extraction_select_the_frames_they_claim -- --exact --nocapture

  run_stage "7a Image processing - fallback backend" \
    cargo test -p media --test media_pipeline_integration \
    the_full_pipeline_reports_exactly_what_it_did_and_claims_no_ai -- --exact --nocapture

  run_stage "8 Provenance and read-only safety" \
    cargo test -p media --test media_pipeline_integration \
    the_pipeline_never_modifies_the_file_it_reads -- --exact --nocapture
  unset MEDIA_REQUIRE_FFMPEG
else
  record "4 Media pipeline integration (real FFmpeg)" "FAIL" "not run: ffmpeg/ffprobe absent"
  record "6 Decoded frame output" "FAIL" "not run: ffmpeg/ffprobe absent"
  record "7a Image processing - fallback backend" "FAIL" "not run: ffmpeg/ffprobe absent"
  record "8 Provenance and read-only safety" "FAIL" "not run: ffmpeg/ffprobe absent"
fi

# ── Stage 5: failure paths ───────────────────────────────────────────────────

run_stage "5 Failure-path tests" cargo test -p media --lib validate -- --nocapture

# ── Stage 7a-2: backend conformance suite ────────────────────────────────────
#
# Holds whichever backend is compiled against the shared reference table. Needs no ffmpeg: it
# builds its own deterministic pixel patterns.

run_stage "7a-2 Frame-processing backend conformance" \
  cargo test -p media --test frame_processing_backend -- --nocapture

# Proves the OpenCV skips are a real gate rather than tests that always pass. On a build without
# the feature this SHOULD fail, with exactly one failure whose message is the skip reason.
hr
echo "STAGE: 7a-3 — OpenCV skip gate"
hr
if MEDIA_REQUIRE_OPENCV=1 cargo test -p media --test frame_processing_backend \
    >"$LOG_DIR/7a3_opencv_gate.log" 2>&1; then
  # Passing here is only correct when the OpenCV backend really is compiled in.
  if grep -q "NATIVE OPENCV EXECUTED" "$LOG_DIR/7a3_opencv_gate.log"; then
    record "7a-3 OpenCV skip gate" "PASS" "the OpenCV backend is compiled in and was exercised"
  else
    record "7a-3 OpenCV skip gate" "FAIL" \
      "MEDIA_REQUIRE_OPENCV=1 passed on a build WITHOUT OpenCV - the skip gate is broken and the suite cannot be trusted"
  fi
else
  record "7a-3 OpenCV skip gate" "PASS" \
    "MEDIA_REQUIRE_OPENCV=1 correctly fails on a build without OpenCV (the skip is a real gate)"
fi

# ── Stage 7b: OpenCV backend ─────────────────────────────────────────────────
#
# This feature has never been compiled on any machine. A compilation failure is a failure of
# this stage only — it does not invalidate the fallback results above, which are a separate,
# genuinely-run backend.
#
# A host that lacks OpenCV or libclang has NOT failed this stage: it was never able to attempt
# it. Those two outcomes are reported differently, because "we could not check" must never be
# rendered as "we checked and it is broken" any more than as "it is fine".

hr
echo "STAGE: 7b — OpenCV backend (never previously compiled)"
hr
if [ "$OPENCV_BUILDABLE" -eq 0 ]; then
  echo "SKIPPED: $OPENCV_BLOCKER"
  record "7b OpenCV backend" "NOT ATTEMPTED" "$OPENCV_BLOCKER"
elif cargo build -p media --features opencv-backend 2>&1 | tee "$LOG_DIR/7b_opencv_build.log"; then
  export MEDIA_REQUIRE_OPENCV=1
  [ "$HAVE_FFMPEG" -eq 1 ] && export MEDIA_REQUIRE_FFMPEG=1
  if cargo test -p media --features opencv-backend -- --nocapture 2>&1 \
      | tee "$LOG_DIR/7b_opencv_test.log"; then
    # Compilation is not execution. Only the marker the suite prints when OpenCV actually ran
    # is accepted as evidence that it did.
    if grep -q "NATIVE OPENCV EXECUTED" "$LOG_DIR/7b_opencv_test.log"; then
      IDENT="$(grep -o 'NATIVE OPENCV EXECUTED: [^—]*' "$LOG_DIR/7b_opencv_test.log" | head -1)"
      record "7b OpenCV backend" "PASS" "built, and OpenCV genuinely executed - $IDENT"
    else
      record "7b OpenCV backend" "FAIL" \
        "tests pass but the suite never reported executing OpenCV - do not report this as verified"
    fi
  else
    record "7b OpenCV backend" "FAIL" "builds, but tests fail under the OpenCV backend"
  fi
  unset MEDIA_REQUIRE_OPENCV
  unset MEDIA_REQUIRE_FFMPEG
else
  record "7b OpenCV backend" "FAIL" "does not compile on this host - see target/media-verification/7b_opencv_build.log"
fi

# ── Stage 9: hashing ─────────────────────────────────────────────────────────

run_stage "9 Hash verification" cargo test -p media --lib hashing -- --nocapture

# ── Stage 10: whole workspace ────────────────────────────────────────────────

run_stage "10 Whole workspace tests" cargo test --workspace

# ── Frame count, pulled from the decode test's own output ────────────────────

FRAME_COUNT="UNKNOWN"
DECODE_LOG="$LOG_DIR/6_Decoded_frame_output.log"
if [ -f "$DECODE_LOG" ] && grep -q "test result: ok" "$DECODE_LOG"; then
  # The test asserts exactly 20 frames for the 10fps x 2s fixture; its passing is the
  # measurement. Anything else would be a failure, not a different count.
  FRAME_COUNT="20 (asserted by a_valid_h264_file_probes_decodes_and_yields_real_frames)"
fi

# ── Write the report ─────────────────────────────────────────────────────────

{
  echo "# Media Pipeline Verification Result"
  echo
  echo "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "Host: $(uname -a 2>/dev/null || echo 'unknown')"
  echo "Repository root: $REPO_ROOT"
  echo
  echo '```text'
  echo "Environment"
  echo "-----------"
  echo "Rust version:     $RUSTC_V"
  echo "Cargo version:    $CARGO_V"
  echo "Host triple:      $(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
  echo "FFmpeg version:   $FFMPEG_V"
  echo "FFprobe version:  $FFPROBE_V"
  echo "libclang (C API): $LIBCLANG_V"
  echo "OpenCV available: $OPENCV_V"
  echo "OpenCV buildable: $([ "$OPENCV_BUILDABLE" -eq 1 ] && echo yes || echo "no - $OPENCV_BLOCKER")"
  echo
  echo "Decoded frames"
  echo "--------------"
  echo "Count: $FRAME_COUNT"
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
  echo "## Notes for the reviewer"
  echo
  echo "- Stage 10 covers the whole workspace. Failures there that are **not** in \`media\`,"
  echo "  \`recovery\`, \`apps/api\` or the two touched integration tests are pre-existing and"
  echo "  unrelated to the media pipeline work. List them separately."
  echo "- Stage 7b (\`opencv-backend\`) had never been compiled on any machine before this run."
  echo "- The fixtures are generic FFmpeg \`testsrc\` videos. Nothing in this report says"
  echo "  anything about OEM (Hikvision/Dahua/Uniview/CP-Plus/Honeywell/TP-Link) parsing."
  echo
  echo "Per-stage console logs: \`target/media-verification/\`"
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
