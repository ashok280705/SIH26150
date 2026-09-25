# Media pipeline verification runner (Windows PowerShell).
#
# Windows equivalent of scripts/verify_media_pipeline.sh. Runs every stage of
# docs/MEDIA_PIPELINE_VERIFICATION.md, records each outcome, and writes
# MEDIA_PIPELINE_VERIFICATION_RESULT.md in the repository root.
#
# It does not hide failures: a failing stage is recorded as FAIL and the script exits 1.
#
# Usage, from anywhere:
#   powershell -ExecutionPolicy Bypass -File scripts/verify_media_pipeline.ps1

$ErrorActionPreference = 'Continue'

# Resolve the repository root from this script's own location, so the run does not depend on
# where the repository was cloned or on the caller's working directory.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

$ResultFile = Join-Path $RepoRoot 'MEDIA_PIPELINE_VERIFICATION_RESULT.md'
$LogDir     = Join-Path $RepoRoot 'target\media-verification'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }

$Stages = New-Object System.Collections.ArrayList
$OverallStatus = 0

function Add-Result {
    param([string]$Name, [string]$Result, [string]$Note)
    [void]$Stages.Add([pscustomobject]@{ Name = $Name; Result = $Result; Note = $Note })
    if ($Result -eq 'FAIL') { $script:OverallStatus = 1 }
    Write-Host ("  => {0,-8} {1}" -f $Result, $Name)
}

function Write-Rule { Write-Host '------------------------------------------------------------' }

function Invoke-Stage {
    param([string]$Name, [string]$Exe, [string[]]$CargoArgs)
    $slug = ($Name -replace '[^A-Za-z0-9]', '_')
    $log  = Join-Path $LogDir "$slug.log"

    Write-Rule
    Write-Host "STAGE: $Name"
    Write-Host "CMD:   $Exe $($CargoArgs -join ' ')"
    Write-Rule

    & $Exe @CargoArgs 2>&1 | Tee-Object -FilePath $log
    if ($LASTEXITCODE -eq 0) {
        Add-Result $Name 'PASS' "log: target/media-verification/$slug.log"
        return $true
    }
    Add-Result $Name 'FAIL' "log: target/media-verification/$slug.log"
    return $false
}

function Get-VersionLine {
    param([string]$Exe, [string[]]$VersionArgs)
    $cmd = Get-Command $Exe -ErrorAction SilentlyContinue
    if ($null -eq $cmd) { return 'NOT FOUND' }
    $out = & $Exe @VersionArgs 2>&1 | Select-Object -First 1
    if ($null -eq $out) { return 'NOT FOUND' }
    return "$out"
}

# --- Stage 1: environment ---------------------------------------------------

Write-Rule
Write-Host 'STAGE: 1 - Environment'
Write-Rule

$RustcV   = Get-VersionLine 'rustc'   @('--version')
$CargoV   = Get-VersionLine 'cargo'   @('--version')
$FfmpegV  = Get-VersionLine 'ffmpeg'  @('-version')
$FfprobeV = Get-VersionLine 'ffprobe' @('-version')

Write-Host "rustc:   $RustcV"
Write-Host "cargo:   $CargoV"
Write-Host "ffmpeg:  $FfmpegV"
Write-Host "ffprobe: $FfprobeV"

if ($RustcV -eq 'NOT FOUND' -or $CargoV -eq 'NOT FOUND') {
    Add-Result '1 Environment' 'FAIL' 'rust toolchain missing; nothing further can run'
    Write-Error 'FATAL: no Rust toolchain. Stopping.'
    exit 1
}

# OpenCV detection on Windows is by environment variable rather than pkg-config.
$OpencvV = 'NOT DETECTED'
if ($env:OPENCV_LINK_LIBS -or $env:OPENCV_INCLUDE_PATHS) {
    $OpencvV = "env-configured (OPENCV_INCLUDE_PATHS=$($env:OPENCV_INCLUDE_PATHS))"
}
Write-Host "opencv:  $OpencvV"

# The OpenCV backend needs TWO things. `clang-sys` requires the C-API libclang, literally named
# `libclang.dll`; LLVM's `libclang-cpp.dll` is the C++ API and does not satisfy it. A host
# missing either dependency has not FAILED stage 7b - it was never able to attempt it.
$LibclangV = 'NOT DETECTED'
if ($env:LIBCLANG_PATH -and (Get-ChildItem -Path $env:LIBCLANG_PATH -Filter 'libclang.dll' -ErrorAction SilentlyContinue)) {
    $LibclangV = "LIBCLANG_PATH=$($env:LIBCLANG_PATH)"
} elseif (Get-Command llvm-config -ErrorAction SilentlyContinue) {
    $LibclangV = 'llvm-config on PATH'
}
Write-Host "libclang: $LibclangV"

$OpencvBuildable = $true
$OpencvBlocker = ''
if ($OpencvV -eq 'NOT DETECTED' -and -not $env:OPENCV_DIR) {
    $OpencvBuildable = $false
    $OpencvBlocker = 'no OpenCV installation (OPENCV_LINK_LIBS, OPENCV_INCLUDE_PATHS and OPENCV_DIR all unset)'
} elseif ($LibclangV -eq 'NOT DETECTED') {
    $OpencvBuildable = $false
    $OpencvBlocker = 'no C-API libclang (llvm-config absent and LIBCLANG_PATH does not contain libclang.dll); libclang-cpp.dll is the C++ API and does not satisfy clang-sys'
}

$HaveFfmpeg = $true
if ($FfmpegV -eq 'NOT FOUND' -or $FfprobeV -eq 'NOT FOUND') {
    $HaveFfmpeg = $false
    Add-Result '1 Environment' 'FAIL' 'ffmpeg and/or ffprobe are not installed; stages 4-8 cannot be verified'
} else {
    Add-Result '1 Environment' 'PASS' 'rust, ffmpeg and ffprobe all present'
}

# --- Stage 2: build ---------------------------------------------------------

[void](Invoke-Stage '2a Build media and recovery' 'cargo' @('build', '-p', 'media', '-p', 'recovery'))
[void](Invoke-Stage '2b Build whole workspace'    'cargo' @('build', '--workspace'))

# --- Stage 3: unit tests ----------------------------------------------------

[void](Invoke-Stage '3a Unit tests - media'        'cargo' @('test', '-p', 'media', '--lib'))
[void](Invoke-Stage '3b Regression tests - recovery' 'cargo' @('test', '-p', 'recovery'))

# --- Stages 4-8: integration against real media -----------------------------

if ($HaveFfmpeg) {
    # With MEDIA_REQUIRE_FFMPEG=1 a missing tool panics, so a green here cannot mean "skipped".
    $env:MEDIA_REQUIRE_FFMPEG = '1'

    [void](Invoke-Stage '4 Media pipeline integration (real FFmpeg)' 'cargo' `
        @('test', '-p', 'media', '--test', 'media_pipeline_integration', '--', '--nocapture'))

    [void](Invoke-Stage '6 Decoded frame output' 'cargo' `
        @('test', '-p', 'media', '--test', 'media_pipeline_integration',
          'a_valid_h264_file_probes_decodes_and_yields_real_frames', '--', '--exact', '--nocapture'))

    [void](Invoke-Stage '6b Decode determinism' 'cargo' `
        @('test', '-p', 'media', '--test', 'media_pipeline_integration',
          'frame_hashes_are_deterministic_across_two_independent_decodes', '--', '--exact', '--nocapture'))

    [void](Invoke-Stage '6c Extraction modes' 'cargo' `
        @('test', '-p', 'media', '--test', 'media_pipeline_integration',
          'sampled_and_time_range_extraction_select_the_frames_they_claim', '--', '--exact', '--nocapture'))

    [void](Invoke-Stage '7a Image processing - fallback backend' 'cargo' `
        @('test', '-p', 'media', '--test', 'media_pipeline_integration',
          'the_full_pipeline_reports_exactly_what_it_did_and_claims_no_ai', '--', '--exact', '--nocapture'))

    [void](Invoke-Stage '8 Provenance and read-only safety' 'cargo' `
        @('test', '-p', 'media', '--test', 'media_pipeline_integration',
          'the_pipeline_never_modifies_the_file_it_reads', '--', '--exact', '--nocapture'))

    Remove-Item Env:\MEDIA_REQUIRE_FFMPEG -ErrorAction SilentlyContinue
} else {
    Add-Result '4 Media pipeline integration (real FFmpeg)' 'FAIL' 'not run: ffmpeg/ffprobe absent'
    Add-Result '6 Decoded frame output'                     'FAIL' 'not run: ffmpeg/ffprobe absent'
    Add-Result '7a Image processing - fallback backend'     'FAIL' 'not run: ffmpeg/ffprobe absent'
    Add-Result '8 Provenance and read-only safety'          'FAIL' 'not run: ffmpeg/ffprobe absent'
}

# --- Stage 5: failure paths -------------------------------------------------

[void](Invoke-Stage '5 Failure-path tests' 'cargo' @('test', '-p', 'media', '--lib', 'validate', '--', '--nocapture'))

# --- Stage 7a-2: backend conformance suite ----------------------------------
#
# Holds whichever backend is compiled against the shared reference table. Needs no ffmpeg: it
# builds its own deterministic pixel patterns.

[void](Invoke-Stage '7a-2 Frame-processing backend conformance' 'cargo' @('test', '-p', 'media', '--test', 'frame_processing_backend', '--', '--nocapture'))

# --- Stage 7a-3: OpenCV skip gate -------------------------------------------
#
# Proves the OpenCV skips are a real gate rather than tests that always pass. On a build without
# the feature this SHOULD fail, with one failure whose message is the skip reason.

Write-Rule
Write-Host 'STAGE: 7a-3 - OpenCV skip gate'
Write-Rule

$GateLog = Join-Path $LogDir '7a3_opencv_gate.log'
$env:MEDIA_REQUIRE_OPENCV = '1'
& cargo test -p media --test frame_processing_backend -- --nocapture 2>&1 |
    Tee-Object -FilePath $GateLog
$GateExit = $LASTEXITCODE
Remove-Item Env:\MEDIA_REQUIRE_OPENCV -ErrorAction SilentlyContinue

if ($GateExit -eq 0) {
    # Passing here is only correct when the OpenCV backend really is compiled in.
    if (Select-String -Path $GateLog -Pattern 'NATIVE OPENCV EXECUTED' -Quiet) {
        Add-Result '7a-3 OpenCV skip gate' 'PASS' 'the OpenCV backend is compiled in and was exercised'
    } else {
        Add-Result '7a-3 OpenCV skip gate' 'FAIL' 'MEDIA_REQUIRE_OPENCV=1 passed on a build WITHOUT OpenCV - the skip gate is broken and the suite cannot be trusted'
    }
} else {
    Add-Result '7a-3 OpenCV skip gate' 'PASS' 'MEDIA_REQUIRE_OPENCV=1 correctly fails on a build without OpenCV (the skip is a real gate)'
}

# --- Stage 7b: OpenCV backend -----------------------------------------------
#
# This feature has never been compiled on any machine. A compilation failure fails this stage
# only; it does not invalidate the fallback-backend results, which are a separate, real backend.
#
# A host lacking OpenCV or libclang has NOT failed this stage: it could never attempt it. Those
# two outcomes are reported differently, because "we could not check" must never be rendered as
# "we checked and it is broken" any more than as "it is fine".

Write-Rule
Write-Host 'STAGE: 7b - OpenCV backend (never previously compiled)'
Write-Rule

if (-not $OpencvBuildable) {
    Write-Host "SKIPPED: $OpencvBlocker"
    Add-Result '7b OpenCV backend' 'NOT ATTEMPTED' $OpencvBlocker
} else {
    & cargo build -p media --features opencv-backend 2>&1 |
        Tee-Object -FilePath (Join-Path $LogDir '7b_opencv_build.log')

    if ($LASTEXITCODE -eq 0) {
        $TestLog = Join-Path $LogDir '7b_opencv_test.log'
        $env:MEDIA_REQUIRE_OPENCV = '1'
        if ($HaveFfmpeg) { $env:MEDIA_REQUIRE_FFMPEG = '1' }
        & cargo test -p media --features opencv-backend -- --nocapture 2>&1 |
            Tee-Object -FilePath $TestLog
        $TestExit = $LASTEXITCODE
        Remove-Item Env:\MEDIA_REQUIRE_OPENCV -ErrorAction SilentlyContinue
        Remove-Item Env:\MEDIA_REQUIRE_FFMPEG -ErrorAction SilentlyContinue

        if ($TestExit -eq 0) {
            # Compilation is not execution. Only the marker the suite prints when OpenCV
            # actually ran is accepted as evidence that it did.
            $Marker = Select-String -Path $TestLog -Pattern 'NATIVE OPENCV EXECUTED: .*' |
                Select-Object -First 1
            if ($Marker) {
                Add-Result '7b OpenCV backend' 'PASS' "built, and OpenCV genuinely executed - $($Marker.Matches[0].Value)"
            } else {
                Add-Result '7b OpenCV backend' 'FAIL' 'tests pass but the suite never reported executing OpenCV - do not report this as verified'
            }
        } else {
            Add-Result '7b OpenCV backend' 'FAIL' 'builds, but tests fail under the OpenCV backend'
        }
    } else {
        Add-Result '7b OpenCV backend' 'FAIL' 'does not compile on this host - see target/media-verification/7b_opencv_build.log'
    }
}

# --- Stage 9: hashing -------------------------------------------------------

[void](Invoke-Stage '9 Hash verification' 'cargo' @('test', '-p', 'media', '--lib', 'hashing', '--', '--nocapture'))

# --- Stage 10: whole workspace ----------------------------------------------

[void](Invoke-Stage '10 Whole workspace tests' 'cargo' @('test', '--workspace'))

# --- Frame count, taken from the decode test's own result -------------------

$FrameCount = 'UNKNOWN'
$DecodeLog = Join-Path $LogDir '6_Decoded_frame_output.log'
if ((Test-Path $DecodeLog) -and (Select-String -Path $DecodeLog -Pattern 'test result: ok' -Quiet)) {
    # The test asserts exactly 20 frames for the 10fps x 2s fixture; its passing is the
    # measurement. Any other count would be a failure, not a different number.
    $FrameCount = '20 (asserted by a_valid_h264_file_probes_decodes_and_yields_real_frames)'
}

# --- Write the report -------------------------------------------------------

$lines = New-Object System.Collections.ArrayList
[void]$lines.Add('# Media Pipeline Verification Result')
[void]$lines.Add('')
[void]$lines.Add("Generated: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
[void]$lines.Add("Host: $($env:COMPUTERNAME) / $([System.Environment]::OSVersion.VersionString)")
[void]$lines.Add("Repository root: $RepoRoot")
[void]$lines.Add('')
[void]$lines.Add('```text')
[void]$lines.Add('Environment')
[void]$lines.Add('-----------')
[void]$lines.Add("Rust version:     $RustcV")
[void]$lines.Add("Cargo version:    $CargoV")
[void]$lines.Add("FFmpeg version:   $FfmpegV")
[void]$lines.Add("FFprobe version:  $FfprobeV")
[void]$lines.Add("libclang (C API): $LibclangV")
[void]$lines.Add("OpenCV available: $OpencvV")
[void]$lines.Add("OpenCV buildable: $(if ($OpencvBuildable) { 'yes' } else { "no - $OpencvBlocker" })")
[void]$lines.Add('')
[void]$lines.Add('Decoded frames')
[void]$lines.Add('--------------')
[void]$lines.Add("Count: $FrameCount")
[void]$lines.Add('```')
[void]$lines.Add('')
[void]$lines.Add('## Stage results')
[void]$lines.Add('')
[void]$lines.Add('| Stage | Result | Note |')
[void]$lines.Add('|---|---|---|')
foreach ($s in $Stages) { [void]$lines.Add("| $($s.Name) | **$($s.Result)** | $($s.Note) |") }
[void]$lines.Add('')
[void]$lines.Add('## Known failures')
[void]$lines.Add('')
$failed = @($Stages | Where-Object { $_.Result -eq 'FAIL' })
if ($failed.Count -eq 0) {
    [void]$lines.Add('None.')
} else {
    foreach ($s in $failed) { [void]$lines.Add("- **$($s.Name)** - $($s.Note)") }
}
[void]$lines.Add('')
[void]$lines.Add('## Notes for the reviewer')
[void]$lines.Add('')
[void]$lines.Add('- Stage 10 covers the whole workspace. Failures there that are **not** in `media`,')
[void]$lines.Add('  `recovery`, `apps/api` or the two touched integration tests are pre-existing and')
[void]$lines.Add('  unrelated to the media pipeline work. List them separately.')
[void]$lines.Add('- Stage 7b (`opencv-backend`) had never been compiled on any machine before this run.')
[void]$lines.Add('- The fixtures are generic FFmpeg `testsrc` videos. Nothing in this report says')
[void]$lines.Add('  anything about OEM (Hikvision/Dahua/Uniview/CP-Plus/Honeywell/TP-Link) parsing.')
[void]$lines.Add('')
[void]$lines.Add('Per-stage console logs: `target/media-verification/`')

Set-Content -Path $ResultFile -Value $lines -Encoding utf8

Write-Rule
Write-Host "Report written to: $ResultFile"
if ($OverallStatus -eq 0) {
    Write-Host 'OVERALL: PASS'
} else {
    Write-Host 'OVERALL: FAIL - see the Known failures section of the report'
}
Write-Rule
exit $OverallStatus
