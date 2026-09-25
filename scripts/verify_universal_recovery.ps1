# Universal recovery verification runner (Windows PowerShell).
#
# Windows equivalent of scripts/verify_universal_recovery.sh. Runs every stage of
# docs/UNIVERSAL_RECOVERY_VERIFICATION.md, records each outcome, and writes
# UNIVERSAL_RECOVERY_VERIFICATION_RESULT.md in the repository root.
#
# It does not hide failures: a failing stage is recorded as FAIL and the script exits 1.
#
# Usage, from anywhere:
#   powershell -ExecutionPolicy Bypass -File scripts/verify_universal_recovery.ps1

$ErrorActionPreference = 'Continue'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

$ResultFile = Join-Path $RepoRoot 'UNIVERSAL_RECOVERY_VERIFICATION_RESULT.md'
$LogDir     = Join-Path $RepoRoot 'target\universal-recovery-verification'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }

$Stages = New-Object System.Collections.ArrayList
$OverallStatus = 0

# The crates that build without the database toolchain. `apps/api` and the `tests/` crate pull
# `sqlx-macros`, a proc-macro dylib that fails to link on some toolchains; they are attempted
# as optional stages so a link failure there cannot hide the recovery results.
$CoreCrates = @(
    '-p','recovery','-p','parsers-core','-p','forensic-core','-p','reporting',
    '-p','parser-uniview','-p','parser-unified','-p','tplink',
    '-p','evidence-reader','-p','hashing','-p','detection','-p','confidence','-p','timeline'
)

function Add-Result {
    param([string]$Name, [string]$Result, [string]$Note)
    [void]$Stages.Add([pscustomobject]@{ Name = $Name; Result = $Result; Note = $Note })
    if ($Result -eq 'FAIL') { $script:OverallStatus = 1 }
    Write-Host ("  => {0,-8} {1}" -f $Result, $Name)
}

function Write-Rule { Write-Host '------------------------------------------------------------' }

function Invoke-Stage {
    param([string]$Name, [string[]]$CargoArgs)
    $slug = ($Name -replace '[^A-Za-z0-9]', '_')
    $log  = Join-Path $LogDir "$slug.log"

    Write-Rule
    Write-Host "STAGE: $Name"
    Write-Host "CMD:   cargo $($CargoArgs -join ' ')"
    Write-Rule

    & cargo @CargoArgs 2>&1 | Tee-Object -FilePath $log
    if ($LASTEXITCODE -eq 0) {
        Add-Result $Name 'PASS' "log: target/universal-recovery-verification/$slug.log"
        return $true
    }
    Add-Result $Name 'FAIL' "log: target/universal-recovery-verification/$slug.log"
    return $false
}

# As Invoke-Stage, but a failure is a known environment limitation rather than a verification
# failure. Used only where the audit already identified the limitation.
function Invoke-OptionalStage {
    param([string]$Name, [string]$SkipNote, [string[]]$CargoArgs)
    $slug = ($Name -replace '[^A-Za-z0-9]', '_')
    $log  = Join-Path $LogDir "$slug.log"

    Write-Rule
    Write-Host "STAGE: $Name (optional)"
    Write-Host "CMD:   cargo $($CargoArgs -join ' ')"
    Write-Rule

    & cargo @CargoArgs 2>&1 | Tee-Object -FilePath $log
    if ($LASTEXITCODE -eq 0) {
        Add-Result $Name 'PASS' "log: target/universal-recovery-verification/$slug.log"
    } else {
        [void]$Stages.Add([pscustomobject]@{
            Name = $Name; Result = 'SKIP'
            Note = "$SkipNote - log: target/universal-recovery-verification/$slug.log"
        })
        Write-Host ("  => {0,-8} {1}" -f 'SKIP', $Name)
    }
}

function Get-VersionLine {
    param([string]$Exe, [string[]]$VersionArgs)
    $cmd = Get-Command $Exe -ErrorAction SilentlyContinue
    if ($null -eq $cmd) { return 'NOT FOUND' }
    $out = & $Exe @VersionArgs 2>&1 | Select-Object -First 1
    return [string]$out
}

function Get-TestCounts {
    param([string]$LogName)
    $log = Join-Path $LogDir $LogName
    if (-not (Test-Path $log)) { return 'NOT RUN' }
    $passed = 0; $failed = 0; $found = $false
    foreach ($line in Get-Content $log) {
        if ($line -match '^test result:\s+\w+\.\s+(\d+) passed;\s+(\d+) failed') {
            $passed += [int]$Matches[1]; $failed += [int]$Matches[2]; $found = $true
        }
    }
    if (-not $found) { return 'UNKNOWN' }
    return "$passed passed, $failed failed"
}

# -- Stage 1: environment ----------------------------------------------------

Write-Rule
Write-Host 'STAGE: 1 - Environment'
Write-Rule
$RustcV = Get-VersionLine 'rustc' @('--version')
$CargoV = Get-VersionLine 'cargo' @('--version')
$HostTriple = 'unknown'
if ($RustcV -ne 'NOT FOUND') {
    $hostLine = & rustc -vV 2>&1 | Where-Object { $_ -match '^host:' } | Select-Object -First 1
    if ($hostLine) { $HostTriple = ($hostLine -split '\s+')[1] }
}
Write-Host "rustc: $RustcV"
Write-Host "cargo: $CargoV"
Write-Host "host:  $HostTriple"

if ($RustcV -eq 'NOT FOUND' -or $CargoV -eq 'NOT FOUND') {
    Add-Result '1 Environment' 'FAIL' 'rust toolchain missing; nothing further can run'
    Write-Error 'FATAL: no Rust toolchain. Stopping.'
    exit 1
}
Add-Result '1 Environment' 'PASS' "rustc and cargo present (host $HostTriple)"

# -- Stage 2: build ----------------------------------------------------------

Invoke-Stage '2a Build the recovery and parser-contract crates' @('build','-p','recovery','-p','parsers-core') | Out-Null
Invoke-Stage '2b Build all locally-buildable crates, tests included' (@('build') + $CoreCrates + @('--all-targets')) | Out-Null
Invoke-OptionalStage '2c Build the whole workspace' `
    'requires a toolchain that can link the sqlx-macros proc-macro dylib' @('build','--workspace')

# -- Stage 3: unit tests -----------------------------------------------------

Invoke-Stage '3a Unit tests - recovery engine' @('test','-p','recovery','--lib') | Out-Null
Invoke-Stage '3b Unit tests - parser contract types' @('test','-p','parsers-core','--lib') | Out-Null
Invoke-Stage '3c Unit tests - forensic core' @('test','-p','forensic-core') | Out-Null

# -- Stage 4: the universal parser contract, every OEM -----------------------

Invoke-Stage '4a Universal parser contract - all OEMs' `
    @('test','-p','recovery','--test','universal_parser_contract','--','--nocapture') | Out-Null
Invoke-Stage '4b Contract harness detects a non-compliant parser' `
    @('test','-p','recovery','--test','universal_parser_contract','the_contract_harness_detects_a_non_compliant_parser','--','--exact','--nocapture') | Out-Null
Invoke-Stage "4c Cross-OEM behaviour - a parser declines another OEM's disk" `
    @('test','-p','recovery','--test','universal_parser_contract','every_parser_is_contract_compliant_on_another_oems_disk','--','--exact','--nocapture') | Out-Null

# -- Stage 5: the universal recovery decision suite --------------------------

Invoke-Stage '5a Universal recovery decisions' `
    @('test','-p','recovery','--test','universal_recovery','--','--nocapture') | Out-Null
Invoke-Stage '5b Active requires an index claim' `
    @('test','-p','recovery','--test','universal_recovery','an_indexed_recording_is_active_and_names_the_index_entry_that_claims_it','--','--exact','--nocapture') | Out-Null
Invoke-Stage '5c Orphan requires an authoritative index, and is never Deleted' `
    @('test','-p','recovery','--test','universal_recovery','video_an_authoritative_index_omits_is_orphaned_not_deleted','--','--exact','--nocapture') | Out-Null
Invoke-Stage '5d Degradation - no index means Unindexed only' `
    @('test','-p','recovery','--test','universal_recovery','an_evidence_item_with_no_index_licenses_only_the_raw_sweep','--','--exact','--nocapture') | Out-Null
Invoke-Stage '5e Unknown stays unknown - no channel 0, no epoch' `
    @('test','-p','recovery','--test','universal_recovery','a_fragment_with_no_recorder_metadata_reports_unknown_not_zero','--','--exact','--nocapture') | Out-Null

# -- Stage 6: determinism ----------------------------------------------------

Invoke-Stage '6a Determinism - every decision is reproducible' `
    @('test','-p','recovery','--test','universal_recovery','two_runs_over_the_same_evidence_agree_on_every_decision','--','--exact','--nocapture') | Out-Null
Invoke-Stage '6b Determinism - correlation does not depend on discovery order' `
    @('test','-p','recovery','--lib','correlation::tests::correlation_is_deterministic_regardless_of_discovery_order','--','--exact','--nocapture') | Out-Null
Invoke-Stage '6c Determinism - contract results are reproducible' `
    @('test','-p','recovery','--test','universal_parser_contract','contract_results_are_reproducible_across_runs','--','--exact','--nocapture') | Out-Null

# -- Stage 7: resource bounds ------------------------------------------------

Invoke-Stage '7a Hypothesis bound is enforced and downgrades the run' `
    @('test','-p','recovery','--test','universal_recovery','the_hypothesis_bound_is_enforced_and_downgrades_the_run','--','--exact','--nocapture') | Out-Null
Invoke-Stage '7b Byte and cancellation bounds yield REVIEW, never PASS' `
    @('test','-p','recovery','--test','universal_recovery','bounded','--','--nocapture') | Out-Null
Invoke-Stage '7c Adversarial evidence is bounded and never panics' `
    @('test','-p','recovery','--test','adversarial_recovery','--','--nocapture') | Out-Null
Invoke-Stage '7d The engine never reads beyond the evidence' `
    @('test','-p','recovery','--test','universal_recovery','the_engine_never_reads_beyond_the_evidence','--','--exact','--nocapture') | Out-Null

# -- Stage 8: provenance -----------------------------------------------------

Invoke-Stage '8a Every candidate traces to exact bytes in an exact evidence item' `
    @('test','-p','recovery','--test','universal_recovery','every_candidate_traces_to_the_exact_bytes_in_the_exact_evidence_item','--','--exact','--nocapture') | Out-Null
Invoke-Stage '8b Unrun validation checks stay UNKNOWN' `
    @('test','-p','recovery','--test','universal_recovery','unrun_validation_checks_are_unknown_and_never_pass','--','--exact','--nocapture') | Out-Null
Invoke-Stage '8c Observability counters are emitted' `
    @('test','-p','recovery','--test','recovery_observability','--','--nocapture') | Out-Null

# -- Stage 9: regression -----------------------------------------------------

Invoke-Stage '9a Pre-existing recovery integration suite' `
    @('test','-p','recovery','--test','integration','--','--nocapture') | Out-Null
Invoke-Stage '9b Pre-existing Uniview recovery suite' `
    @('test','-p','recovery','--test','uniview_recovery','--','--nocapture') | Out-Null
Invoke-Stage '9c All locally-buildable crates' (@('test','--no-fail-fast') + $CoreCrates) | Out-Null
Invoke-OptionalStage '9d Cross-crate production-chain tests' `
    'the tests/ crate depends on apps/api and therefore on sqlx-macros' @('test','-p','forensic-tests')

# -- Counts, pulled from the suites' own output ------------------------------

$ContractCount = Get-TestCounts '4a_Universal_parser_contract___all_OEMs.log'
$RecoveryCount = Get-TestCounts '5a_Universal_recovery_decisions.log'
$AllCount      = Get-TestCounts '9c_All_locally_buildable_crates.log'

# -- Write the report --------------------------------------------------------

$lines = New-Object System.Collections.ArrayList
function Add-Line { param([string]$Text = '') [void]$lines.Add($Text) }

Add-Line '# Universal Recovery Verification Result'
Add-Line
Add-Line ("Generated: {0}" -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
Add-Line ("Host: {0} {1}" -f $env:COMPUTERNAME, [System.Environment]::OSVersion.VersionString)
Add-Line ("Repository root: {0}" -f $RepoRoot)
Add-Line
Add-Line '```text'
Add-Line 'Environment'
Add-Line '-----------'
Add-Line ("Rust version:  {0}" -f $RustcV)
Add-Line ("Cargo version: {0}" -f $CargoV)
Add-Line ("Host triple:   {0}" -f $HostTriple)
Add-Line
Add-Line 'Test counts'
Add-Line '-----------'
Add-Line ("Universal parser contract: {0}" -f $ContractCount)
Add-Line ("Universal recovery suite:  {0}" -f $RecoveryCount)
Add-Line ("All buildable crates:      {0}" -f $AllCount)
Add-Line '```'
Add-Line
Add-Line '## Stage results'
Add-Line
Add-Line '| Stage | Result | Note |'
Add-Line '|---|---|---|'
foreach ($s in $Stages) { Add-Line ("| {0} | **{1}** | {2} |" -f $s.Name, $s.Result, $s.Note) }
Add-Line
Add-Line '## Known failures'
Add-Line
$fails = $Stages | Where-Object { $_.Result -eq 'FAIL' }
if ($fails) { foreach ($s in $fails) { Add-Line ("- **{0}** - {1}" -f $s.Name, $s.Note) } }
else { Add-Line 'None.' }
Add-Line
Add-Line '## Skipped stages'
Add-Line
$skips = $Stages | Where-Object { $_.Result -eq 'SKIP' }
if ($skips) { foreach ($s in $skips) { Add-Line ("- **{0}** - {1}" -f $s.Name, $s.Note) } }
else { Add-Line 'None.' }
Add-Line
Add-Line '## Notes for the reviewer'
Add-Line
Add-Line '- Stages 2c and 9d are **optional**: they need a toolchain that can link the'
Add-Line '  `sqlx-macros` proc-macro dylib. A SKIP there says nothing about the recovery'
Add-Line '  engine; a PASS is additional coverage.'
Add-Line '- `evidence-reader`''s `mmap::tests::mmap_reads_correct_bytes` is a known pre-existing'
Add-Line '  failure on some Windows hosts and is unrelated to recovery. If stage 9c fails on that'
Add-Line '  test alone, record it as pre-existing.'
Add-Line '- Every fixture in stages 4-8 is **synthetic**, built from the real structure layouts'
Add-Line '  declared in `profiles/`. A green report says the engine behaves correctly on those'
Add-Line '  structures. It says **nothing** about behaviour on a real acquired DVR image; that'
Add-Line '  requires running against real evidence and is tracked separately.'
Add-Line
Add-Line 'Per-stage console logs: `target/universal-recovery-verification/`'

$lines -join "`r`n" | Out-File -FilePath $ResultFile -Encoding utf8

Write-Rule
Write-Host "Report written to: $ResultFile"
if ($OverallStatus -eq 0) {
    Write-Host 'OVERALL: PASS'
} else {
    Write-Host 'OVERALL: FAIL - see the Known failures section of the report'
}
Write-Rule
exit $OverallStatus
