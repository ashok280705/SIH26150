# Media Pipeline — Remote Verification Procedure

This document is the verification package for the media subsystem
(`crates/media`, plus the FFmpeg changes in `crates/recovery` and the API/UI wiring).

It exists because the development machine **cannot build or run the whole workspace**:
`sqlx-macros` fails to link there (`x86_64-w64-mingw32-gcc … ld returned 116`), which blocks
`apps/api` and the `forensic-tests` crate. Everything in this document is therefore stated as
something *to be verified*, not as something already observed — except where the "Already
executed" table below says otherwise.

All paths are repository-relative. Run every command from the repository root. Nothing here
depends on where the repository is checked out.

---

## 0. What was already executed on the development machine

These results were produced on the development machine and are reproducible. They are listed
so the verification operator knows what is already known and what still needs proving.

| Command | Result |
|---|---|
| `cargo test -p media --lib` | **106 passed, 0 failed** — includes a real process-timeout test that spawns a child, lets the budget expire, and asserts the child was terminated |
| `cargo test -p media --test frame_processing_backend` | **26 passed, 0 failed** on the **pure-Rust fallback backend only.** The OpenCV-specific tests within it reported `SKIPPED`; see the note below. |
| `MEDIA_REQUIRE_OPENCV=1 cargo test -p media --test frame_processing_backend` | **1 failed, 25 passed** — the expected result on a build without OpenCV, proving the skip is a real gate and not a test that always passes |
| `cargo test -p recovery` | **117 passed, 0 failed** across 6 targets |
| `cargo check -p media --all-targets` | clean |
| `cargo check -p recovery --all-targets` | clean |
| `cargo test -p media --test media_pipeline_integration` | 16 tests; **14 of them SKIPPED** because the development machine has no `ffmpeg`/`ffprobe`. Only the two that do not need FFmpeg actually ran. Note that the harness prints skips as `ok`; the `SKIPPED` lines go to stderr and need `--nocapture`. |

**Never executed on the development machine — this is what you are verifying:**

- any `ffmpeg` or `ffprobe` invocation
- any actual video decode, and therefore any actual `VideoFrame`
- any OpenCV-backed operation (the `opencv-backend` feature has never been compiled anywhere —
  see [Stage 7b](#7b-opencv-backend--never-yet-compiled-anywhere), which records the exact
  blocker on the development machine)
- anything in `apps/api` or `forensic-tests` (they do not link on that machine)
- anything in `apps/frontend` (no `node_modules` there)

### OpenCV status, stated once and without hedging

| Question | Answer |
|---|---|
| Is OpenCV optional? | **Yes.** Feature `opencv-backend`, off by default. The workspace builds, tests and runs without OpenCV installed, and no part of the media pipeline requires it. |
| How is it enabled? | `cargo build -p media --features opencv-backend` on a host that has both an OpenCV 4.x installation and a C-API `libclang`. See [Stage 1](#stage-1--environment). |
| What does the OpenCV backend implement? | Colour conversion (`cvt_color`), resize (`INTER_LINEAR`), ROI crop (`Mat::roi`), and the luma quality statistics (`meanStdDev`, `Laplacian`). Those four operations, and nothing else. |
| What does the fallback implement? | The same four, to the same contract, in pure Rust. It is a real implementation, not a stub. |
| Do they agree? | Per operation, to the tolerances in [Stage 7b](#7b-opencv-backend--never-yet-compiled-anywhere). Some are exact by construction; the rest are *expected* to agree and have **never been compared on a real host**, because no host has had both. |
| Has the native backend been compiled? | **No. Never, on any machine.** |
| Has the native backend been executed? | **No.** Compilation would not itself be execution; neither has happened. |
| What happens when OpenCV is absent? | The fallback runs and reports itself as `pure_rust_fallback` in every processing step, in the run summary and in the toolchain capability report. `FrameProcessor::require_opencv` returns `OPENCV_UNAVAILABLE`, and a `ProcessingPlan` with `require_backend: Some(OpenCv)` aborts the run before decoding rather than substituting. |
| Known limitations | The native backend is unverified beyond syntax (see Stage 7b). `PixelFormat` covers `BGR24`, `RGB24` and `GRAY8` only — FFmpeg converts to one of these during decode, so no YUV path reaches this layer. `cv::setNumThreads(1)` is process-global OpenCV state. |

---

## Stage 1 — Environment

```bash
rustc --version
```

```bash
cargo --version
```

```bash
ffmpeg -version
```

```bash
ffprobe -version
```

**Expected:** `rustc`/`cargo` 1.82 or newer (the workspace sets `rust-version = "1.82"`).
`ffmpeg` and `ffprobe` must both print a version banner. If either is missing, install FFmpeg
before continuing — Stages 4–8 cannot be verified without it, and the procedure is designed so
that a missing tool produces a **failure**, never a silent pass.

The build host must also have a working C linker. If you see
`x86_64-w64-mingw32-gcc … ld returned 116` you are reproducing the development machine's
limitation and must use a different host or the MSVC toolchain.

OpenCV is **optional** and is only needed for Stage 7b. The rest of the media pipeline builds,
runs and is verified without it; with the feature off, image processing runs a pure-Rust
backend that reports itself as `pure_rust_fallback` and never claims to be OpenCV.

Building `--features opencv-backend` needs **two** separate things, and missing either one
stops the build:

1. **`libclang`**, for the `clang-sys` crate that generates the OpenCV bindings. This must be
   the C API — a file literally named `libclang.dll` (Windows) or `libclang.so`/`.dylib`. LLVM's
   `libclang-cpp.dll` is the C++ API and does **not** satisfy it. Either put `llvm-config` on
   `PATH` or set `LIBCLANG_PATH` to the directory containing the library.
2. **An OpenCV 4.x installation** — headers and link libraries.

```bash
# Linux / macOS
pkg-config --modversion opencv4
llvm-config --prefix
```

```powershell
# Windows: confirm the OpenCV install and libclang are both discoverable
$env:OPENCV_LINK_LIBS; $env:OPENCV_LINK_PATHS; $env:OPENCV_INCLUDE_PATHS
$env:LIBCLANG_PATH
```

On Windows, the practical route is the **MSVC** toolchain plus `vcpkg install opencv4:x64-windows`
and `winget install LLVM.LLVM` (which ships `libclang.dll`). The `x86_64-pc-windows-gnu` target
the development machine uses has no prebuilt OpenCV and is not a supported host for Stage 7b.

---

## Stage 2 — Build

Build the media subsystem and the crate it changes:

```bash
cargo build -p media -p recovery
```

Then the whole workspace, which additionally covers `apps/api`:

```bash
cargo build --workspace
```

**Expected:** both finish with `Finished` and no `error:` lines. Warnings are acceptable; there
is one pre-existing unused-import warning in `crates/parsers/tplink/src/types.rs` that is
unrelated to this work.

If `cargo build --workspace` fails inside `apps/api` or `apps/api/src/handlers.rs`, that is a
**real finding**: those files were edited but never compiled. Record the exact error text.

---

## Stage 3 — Unit tests

Pure Rust, no external dependencies. These must pass on any host:

```bash
cargo test -p media --lib
```

**Expected:** `test result: ok. 99 passed; 0 failed`. Among them, and worth noting in the
report because they are the load-bearing ones:

| Test | What it proves |
|---|---|
| `exec::tests::timeout_actually_terminates_an_overrunning_child` | a 300 ms budget against a 30 s child returns in under 10 s — the child was killed, not merely timed |
| `exec::tests::concurrency_is_bounded_by_the_configured_permit_count` | two runs against one permit serialise |
| `exec::tests::non_zero_exit_is_never_reported_as_success` | exit status is authoritative |
| `exec::tests::a_missing_executable_is_reported_as_unavailable_not_as_a_decode_failure` | `FFPROBE_UNAVAILABLE` ≠ decode failure |
| `validate::tests::a_missing_ffprobe_yields_unavailable_and_never_pass` | no ffprobe ⇒ `UNKNOWN`, never `PASS` |
| `hashing::tests::a_zero_filled_digest_is_rejected_rather_than_compared` | a placeholder hash cannot pass verification |
| `frame::tests::a_wall_clock_is_only_as_strong_as_its_weakest_input` | a derived timestamp is not promoted to a DVR assertion |
| `process::tests::bgr_to_gray_uses_bt601_luma_weights` | colour conversion is exact, not approximate |

Regression check on the crate this work also touched:

```bash
cargo test -p recovery
```

**Expected:** `ok` on all six targets, 117 tests total, 0 failed.

---

## Stage 4 — Media pipeline smoke test (needs FFmpeg)

This is the stage that proves the pipeline genuinely reaches decoded frames.

**No test media needs to be supplied.** The integration test builds its own fixtures with
FFmpeg's `testsrc` generator, in a temporary directory that is deleted afterwards: a 320x240,
10 fps, 2-second H.264 MP4 (exactly 20 frames), an H.265 MP4 where the host can encode one, a
truncated file, an empty file, a non-media file, and an audio-only container.

Set `MEDIA_REQUIRE_FFMPEG=1`. This turns "FFmpeg is missing, so the test skipped" into a
**failure**, so a misconfigured verification host cannot report a false green:

```bash
MEDIA_REQUIRE_FFMPEG=1 cargo test -p media --test media_pipeline_integration -- --nocapture
```

On Windows PowerShell:

```powershell
$env:MEDIA_REQUIRE_FFMPEG = "1"; cargo test -p media --test media_pipeline_integration -- --nocapture
```

**Expected:** `test result: ok. 16 passed; 0 failed`.

Two tests may still print `SKIPPED` and pass, for a stated reason that is not a missing
FFmpeg:

- `hevc_decodes_when_the_host_ffmpeg_can_encode_it` — skips if the build has no `libx265`
  **encoder**. This says nothing about HEVC decoding; it only means no HEVC fixture could be
  created.
- `an_audio_only_container_reports_no_video_stream` — skips if the build cannot produce AAC.

Record any such skip in the report. A skip is not a pass.

---

## Stage 5 — Failure paths

These are covered by named tests inside the same integration binary. Run them individually so
each outcome is separately recorded:

```bash
MEDIA_REQUIRE_FFMPEG=1 cargo test -p media --test media_pipeline_integration a_missing_file_is_media_not_found -- --exact --nocapture
```

```bash
MEDIA_REQUIRE_FFMPEG=1 cargo test -p media --test media_pipeline_integration an_empty_file_is_media_empty -- --exact --nocapture
```

```bash
MEDIA_REQUIRE_FFMPEG=1 cargo test -p media --test media_pipeline_integration a_file_that_is_not_media_is_rejected_by_ffprobe -- --exact --nocapture
```

```bash
MEDIA_REQUIRE_FFMPEG=1 cargo test -p media --test media_pipeline_integration a_truncated_media_file_does_not_validate_as_decodable -- --exact --nocapture
```

```bash
MEDIA_REQUIRE_FFMPEG=1 cargo test -p media --test media_pipeline_integration an_audio_only_container_reports_no_video_stream -- --exact --nocapture
```

```bash
MEDIA_REQUIRE_FFMPEG=1 cargo test -p media --test media_pipeline_integration a_decode_timeout_terminates_the_decoder_and_is_never_a_success -- --exact --nocapture
```

```bash
MEDIA_REQUIRE_FFMPEG=1 cargo test -p media --test media_pipeline_integration a_probe_timeout_is_reported_as_timeout_and_not_as_a_pass -- --exact --nocapture
```

| Test | Asserted outcome |
|---|---|
| missing file | error code `MEDIA_NOT_FOUND`, status `INVALID`, decode refused |
| empty file | error code `MEDIA_EMPTY`, and **no digest is produced** for zero bytes |
| non-media bytes | status `INVALID` or `CORRUPTED`, never `VALID` |
| truncated media | never `VALID`; decoding is refused rather than attempted |
| audio-only container | error code `NO_VIDEO_STREAM` — not "valid with zero frames" |
| decode timeout (1 ms budget) | `FFMPEG_TIMEOUT` family; the decoder is terminated |
| probe timeout (1 ms budget) | never `VALID` |

For the **ffprobe-unavailable** case — the one that must not report `PASS` — force it by
pointing the toolchain at a path that does not exist:

```bash
FORENSIC_FFPROBE_PATH=/nonexistent/ffprobe cargo test -p media --lib validate::tests -- --nocapture
```

**Expected:** `a_missing_ffprobe_yields_unavailable_and_never_pass` passes. The environment
override is only consulted when the named file exists, so this run also exercises the normal
discovery fallback; the test itself constructs an explicitly-absent toolchain, so it is
deterministic either way.

---

## Stage 6 — Frame output verification

Exit code 0 is not evidence that frames were produced, so the assertions are on measurable
values. `a_valid_h264_file_probes_decodes_and_yields_real_frames` asserts, on the 320x240 /
10 fps / 2 s fixture:

- `frames_emitted == 20` — the exact, deterministic frame count for that generator
- each frame buffer is exactly `320 * 240 * 3 = 230400` bytes
- `peak_frame_buffer_bytes == 230400` — one frame resident, not the recording
- frame metadata carries `width`, `height`, a presentation timestamp and its source
- frame 0's timestamp is `0.0 s`, frame 10's is `1.0 s`, labelled `FRAME_RATE_DERIVED`
- frame 0 and frame 5 have **different** SHA-256 digests, so the decoder advanced through the
  stream rather than repeating one picture
- `FrameProcessor::quality(frame).has_tonal_variation == true` — the picture has real content,
  which a blank or fabricated buffer would not
- the FFmpeg argv contains `rawvideo` and contains **no** `copy`, so a stream copy could not
  have satisfied the command

Run it alone and read the output:

```bash
MEDIA_REQUIRE_FFMPEG=1 cargo test -p media --test media_pipeline_integration a_valid_h264_file_probes_decodes_and_yields_real_frames -- --exact --nocapture
```

Determinism:

```bash
MEDIA_REQUIRE_FFMPEG=1 cargo test -p media --test media_pipeline_integration frame_hashes_are_deterministic_across_two_independent_decodes -- --exact --nocapture
```

Extraction modes — sequential, every-N-frames, every-N-seconds, time-range, and the honest
reporting of seek accuracy:

```bash
MEDIA_REQUIRE_FFMPEG=1 cargo test -p media --test media_pipeline_integration sampled_and_time_range_extraction_select_the_frames_they_claim -- --exact --nocapture
```

**Expected:** every-5th-frame yields 4 frames from 20; one-per-second yields 2; an input-side
seek reports `KEYFRAME_APPROXIMATE` and an output-side seek reports `EXACT`; a frame budget
stops with `FRAME_LIMIT_REACHED`.

Bounded memory on large media:

```bash
MEDIA_REQUIRE_FFMPEG=1 cargo test -p media --test media_pipeline_integration a_decoder_side_rescale_bounds_memory_without_changing_the_frame_count -- --exact --nocapture
```

---

## Stage 7 — Image processing

### 7a. Fallback backend (default build)

```bash
MEDIA_REQUIRE_FFMPEG=1 cargo test -p media --test media_pipeline_integration the_full_pipeline_reports_exactly_what_it_did_and_claims_no_ai -- --exact --nocapture
```

This drives real decoded frames through resize, colour conversion, ROI and quality metrics, and
asserts the recorded processing chain is `["resize", "cvt_color", "roi"]` with the backend that
actually ran.

Run the dedicated backend conformance suite, which holds whichever backend is compiled against
the shared reference table:

```bash
cargo test -p media --test frame_processing_backend -- --nocapture
```

**Expected on a default build:** 26 tests pass, and the `--nocapture` output contains

```text
NATIVE OPENCV NOT EXERCISED: this run used pure_rust_fallback.
SKIPPED: native OpenCV backend construction — …  This is a skip, not a pass.
```

That is the correct, honest answer for a build without OpenCV — it is **not** an OpenCV
verification. `FrameProcessor::require_opencv` returns `OPENCV_UNAVAILABLE`, and a
`ProcessingPlan` with `require_backend: Some(OpenCv)` fails the whole run before decoding
rather than quietly using the fallback.

To prove the skip is a real gate rather than a test that always passes:

```bash
MEDIA_REQUIRE_OPENCV=1 cargo test -p media --test frame_processing_backend
```

**Expected on a default build:** exactly one failure,
`the_native_opencv_backend_constructs_and_reports_its_real_library_version`, whose panic
message is the skip reason. A run that reports 26 passes under this variable on a build without
OpenCV means the gate has been broken and the suite can no longer be trusted.

### 7b. OpenCV backend — never yet compiled anywhere

> This remains the single highest-risk item in this package. The `opencv-backend` feature has
> **never been built on any machine**, and nothing in this repository claims otherwise.
>
> What *is* true, and is all that is true:
>
> * The backend is written against the **`opencv` 0.94** API, with each call checked against
>   that crate's vendored sources and generated API stubs (`src/manual/core/mat.rs`,
>   `docs/core.rs`, `docs/imgproc.rs`) — `Mat::new_rows_cols_with_data` /
>   `new_rows_cols_with_bytes`, `Mat::roi`, `imgproc::resize`, `imgproc::cvt_color_def`,
>   `imgproc::laplacian`, `core::mean_std_dev_def`, `core::set_num_threads`,
>   `core::get_version_string`.
> * The module is **syntactically valid**: `cfg`-stripping happens after parsing, so
>   `cargo check -p media` on a default build would already have rejected a parse error in it.
> * Name resolution, type checking and linking are **unverified**. Expect to fix compilation
>   errors. Report exactly what you had to change.

**Development-machine result — one attempt, recorded rather than retried:**

```text
$ cargo build -p media --features opencv-backend
error: failed to run custom build command for `clang-sys v1.9.1`
  cargo:warning=could not execute `llvm-config` … (error: program not found)
  panicked at clang-sys-1.9.1/build/dynamic.rs:229:
  called `Result::unwrap()` on an `Err` value: "couldn't find any valid shared libraries
  matching: ['clang.dll', 'libclang.dll'], set the `LIBCLANG_PATH` environment variable…"
```

Two independent blockers on that host, neither of which this work can remove:

| Blocker | Evidence |
|---|---|
| No C-API `libclang` | Only `libclang-cpp.dll` (the C++ API) is present, from `llvm-mingw`. No `llvm-config` on `PATH`. |
| No OpenCV installation | `OPENCV_DIR`, `OPENCV_LINK_LIBS`, `OPENCV_INCLUDE_PATHS` all unset; no `vcpkg`, no `pkg-config`, no `C:\opencv`. |

The host triple is `x86_64-pc-windows-gnu`. The build never reached this crate's code, so the
failure says nothing about whether the backend is correct — only that it could not be tried.

On a host that meets the Stage 1 requirements:

```bash
cargo build -p media --features opencv-backend
```

```bash
MEDIA_REQUIRE_OPENCV=1 cargo test -p media --features opencv-backend --test frame_processing_backend -- --nocapture
```

```bash
cargo test -p media --features opencv-backend --lib process
```

```bash
MEDIA_REQUIRE_FFMPEG=1 cargo test -p media --features opencv-backend --test media_pipeline_integration -- --nocapture
```

**Expected if it builds:** every assertion in the conformance suite holds under OpenCV too, the
`--nocapture` output reads `NATIVE OPENCV EXECUTED: opencv <version> (single-threaded)`, and the
backend recorded on every processing step becomes that same string rather than
`pure_rust_fallback`.

The tolerances the suite enforces are the ones the two backends are actually claimed to meet —
not byte-for-byte identity, which only some operations have:

| Operation | Tolerance | Why |
|---|---|---|
| Channel swap `BGR24 ↔ RGB24` | exact | A byte permutation has one answer. |
| `GRAY8 → BGR24/RGB24` | exact | Channel replication has one answer. |
| ROI crop | exact | Copying a sub-rectangle has one answer. |
| `BGR24/RGB24 → GRAY8` | ≤ 1 LSB | Both use BT.601 in Q14 with `(x + 1<<13) >> 14`, so they are *expected* to be identical — but OpenCV's SIMD/IPP paths may round one step differently, and that expectation has never been observed to hold. The fallback is additionally asserted exact against the reference. |
| Resize `INTER_LINEAR` | ≤ 2 LSB | Same half-pixel-centred sampling grid, different arithmetic: `f64` with half-up rounding in the fallback, 5-bit fixed-point weights in OpenCV. The difference is quantisation, not geometry. |
| Luma mean / std dev | 1e-9 absolute | Same definition (population, divisor `N`), both in `f64`. |
| Laplacian variance | 1e-6 relative | Same 3×3 kernel over the **interior only** — OpenCV's border extrapolation is cropped away so the definitions match rather than merely resemble each other. |

If it does not build **on a host that has both libclang and OpenCV**, record the errors and
report Stage 7b as **FAILED — OpenCV backend does not compile**. Do not report it as skipped:
the feature exists and was meant to build. If the host lacks either dependency, report Stage 7b
as **NOT ATTEMPTED — environment does not support it**, naming which one was missing.

### 7c. Determinism and backend identity

What the OpenCV backend controls, and what it does not:

* It calls `cv::setNumThreads(1)` once, removing thread-count-dependent variation in OpenCV's
  parallel loops. When that call succeeds the identity string carries `(single-threaded)`; when
  it fails the suffix is omitted, so provenance never claims a setting that was not applied.
* It uses `Mat` exclusively and never `UMat`, which is the only type through which OpenCV
  dispatches to OpenCL. No OpenCL call is therefore needed or made.
* It records OpenCV's own `getVersionString()` in the identity, because SIMD and IPP code paths
  are selected when OpenCV itself is built and differ between installations.

This constrains **this module**. It is not a claim that the application is globally
deterministic, and it is not offered as one. The pure-Rust fallback is deterministic outright:
fixed-order integer and `f64` arithmetic with no dispatch.

---

## Stage 8 — Provenance

```bash
MEDIA_REQUIRE_FFMPEG=1 cargo test -p media --test media_pipeline_integration a_valid_h264_file_probes_decodes_and_yields_real_frames -- --exact --nocapture
```

The same test asserts the full chain Evidence → MediaArtifact → VideoFrame → ProcessedFrame:

- `frame.provenance.evidence_id == artifact.provenance.evidence_id`
- `frame.provenance.artifact_id == "art-h264"`
- `frame.provenance.artifact_source_offset == Some(1048576)` — the evidence offset the artifact
  came from
- `frame.provenance.source_recording_id == Some("rec-7")`
- `frame.provenance.artifact_media_hash` equals the artifact's own SHA-256
- `frame.frame_id == "art-h264:frame:0"`, and a frame that has been resized, colour-converted
  and cropped **still** carries that id and that evidence id

Plus the unit-level chain test:

```bash
cargo test -p media --lib process::tests::processing_preserves_the_link_back_to_the_decoded_frame_and_the_evidence -- --exact --nocapture
```

---

## Stage 9 — Hashing

```bash
cargo test -p media --lib hashing -- --nocapture
```

**Expected:** 9 tests pass, covering:

- the FIPS 180-4 `SHA-256("abc")` vector is reproduced exactly
- a file digest equals the in-memory digest of the same bytes
- 64 KiB chunking does not change the digest for a file larger than the buffer
- an **empty** file yields `MEDIA_EMPTY` rather than the well-known empty-string digest, which
  would look like a real hash in a report
- a **missing** file yields `MEDIA_NOT_FOUND` rather than any digest
- an all-zero recorded digest is **rejected** as a placeholder, not compared
- source and derived digests differ, because they cover different bytes

And the three-way separation over real media:

```bash
MEDIA_REQUIRE_FFMPEG=1 cargo test -p media --test media_pipeline_integration a_valid_h264_file_probes_decodes_and_yields_real_frames -- --exact --nocapture
```

which asserts `media_hash != source-like hash != frame pixel hash != processed-frame hash`.

Forensic read-only safety:

```bash
MEDIA_REQUIRE_FFMPEG=1 cargo test -p media --test media_pipeline_integration the_pipeline_never_modifies_the_file_it_reads -- --exact --nocapture
```

**Expected:** the file's SHA-256 and length are byte-identical before and after a full pipeline
run.

---

## Stage 10 — Whole workspace

```bash
cargo test --workspace
```

Separate the results into two groups in your report:

**Media pipeline tests** (this work):
- `cargo test -p media --lib` — 99 tests
- `cargo test -p media --test media_pipeline_integration` — 16 tests
- `cargo test -p recovery` — 117 tests, of which the reconstructor and ffmpeg-service tests were
  modified by this work

**Unrelated existing project tests** — everything in `forensic-tests`, the parser crates,
`detection`, `confidence`, `timeline`, `reporting`, `pipeline`, `apps/api`. If any of these
fail, list them **separately and by name**. Do not merge them into the media result, and do not
hide them.

Two of them were touched only at their call sites and are expected to pass:
`tests/tests/dahua_orphan_production_chain.rs` and `tests/tests/hikvision_production_chain.rs`
now pass `None` to `VideoReconstructor::reconstruct` instead of `false, false`.

---

## Stage 11 — API and frontend (never compiled on the development machine)

```bash
cargo build -p forensic-api
```

```bash
cargo test -p forensic-tests
```

The API's reconstruct response gained a `media_pipeline` block and a `remux_error` field. With
FFmpeg present, `media_pipeline.decoded` should be `true` and `frames_extracted` non-zero for a
recording that really remuxes; with FFmpeg absent, `validation_status` must read
`VALIDATION_NOT_RUN` or `VALIDATION_UNAVAILABLE` and `decoded` must be `false`.

```bash
cd apps/frontend && npm ci && npx tsc --noEmit
```

**Expected:** no type errors. `apps/frontend/src/types/index.ts` gained `MediaPipelineStatus`,
and three views now call a shared `remuxUnavailableMessage(res)` helper. This has never been
type-checked.

---

## One-command run

```bash
bash scripts/verify_media_pipeline.sh
```

On Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify_media_pipeline.ps1
```

The script runs every stage, **fails if any stage fails**, and writes
`MEDIA_PIPELINE_VERIFICATION_RESULT.md` in the repository root. It does not hide failures: a
failing stage is recorded as `FAIL` and the script exits non-zero.

---

## What to send back

Send exactly these two things:

1. **`MEDIA_PIPELINE_VERIFICATION_RESULT.md`** — written by the script in the repository root.
2. **The full console output** of the script, redirected to a file:

   ```bash
   bash scripts/verify_media_pipeline.sh 2>&1 | tee media_verification_console.log
   ```

If you ran anything by hand instead of the script, send the console output of each command
under the stage headings above.

The result file records:

```text
Environment
-----------
Rust version:
Cargo version:
Host triple:
FFmpeg version:
FFprobe version:
libclang (C API) present:
OpenCV available:

Build
-----
Result:

Unit tests
----------
Result:

Media validation
----------------
Result:

FFmpeg decode
-------------
Result:

Decoded frames
--------------
Count:

Image processing (fallback backend)
-----------------------------------
Result:

OpenCV backend
--------------
Result:              (PASS / FAILED / NOT ATTEMPTED — environment does not support it)
Backend identity:    (the exact `opencv <version> …` string, or `pure_rust_fallback`)
Native OpenCV genuinely executed:   (yes / no — compilation alone is not execution)
Blocker if not attempted:

Provenance
----------
Result:

Hash verification
-----------------
Result:

Failure-path tests
------------------
Result:

Full workspace
--------------
Result:

Known failures
--------------
```

---

## Scope boundary

Everything in this document verifies the **media pipeline**. The fixtures are generic synthetic
videos produced by FFmpeg's `testsrc`, not DVR images.

Nothing here validates OEM forensic parsing, storage geometry, recording indexes or recovery
heuristics for Hikvision, Dahua, Uniview, CP-Plus, Honeywell or TP-Link. That validation lives
in the `forensic-tests` crate and the `validation_corpus/` manifests, and this work did not
change it. A green result here means the media subsystem works; it says nothing about OEM
compatibility.
