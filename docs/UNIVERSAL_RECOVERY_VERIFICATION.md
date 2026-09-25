# Universal recovery verification

How to verify, on another machine, the universal parser contract and the universal recovery
engine described in [UNIVERSAL_RECOVERY_ARCHITECTURE.md](UNIVERSAL_RECOVERY_ARCHITECTURE.md).

Run one command:

```bash
bash scripts/verify_universal_recovery.sh 2>&1 | tee universal_recovery_console.log
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify_universal_recovery.ps1 *>&1 | Tee-Object universal_recovery_console.log
```

It writes `UNIVERSAL_RECOVERY_VERIFICATION_RESULT.md` in the repository root, per-stage logs in
`target/universal-recovery-verification/`, and exits non-zero on any failure. There is no path
through it that reports success for something that did not run.

---

## 1. Evidence status vocabulary

Every claim in this repository about the recovery engine carries one of these. They are not
interchangeable, and a stronger one is never assumed from a weaker one.

| Status | Meaning |
|---|---|
| `IMPLEMENTED` | the code exists and is reachable from the production entry point |
| `STATICALLY VERIFIED` | verified by reading the code and by `cargo check`; not executed |
| `UNIT TESTED` | an automated test exercises it and passes |
| `RUNTIME VERIFIED` | executed end to end against a real acquired DVR image |
| `VERIFICATION PENDING` | implemented, not yet executed on the machine making the claim |

**Nothing in this repository is `RUNTIME VERIFIED` against a real DVR image.** Every fixture is
synthetic, built from the structure layouts declared in `profiles/`. Synthetic fixtures verify
that the engine reasons correctly about those structures; they cannot verify that the
structures match every firmware revision in the field.

---

## 2. Environment used for the audit

| | |
|---|---|
| Host | Windows 11, `x86_64-pc-windows-gnu` |
| Toolchain | cargo 1.98.1 |
| Result | core crates build and test; `apps/api` and `tests/` do **not** link |

### The one environment limitation

`sqlx-macros` is a proc-macro dylib. Under the mingw toolchain on this host it fails at the
link step (`collect2.exe: error: ld returned 116 exit status`). This blocks any crate that
depends, directly or transitively, on `apps/api`:

* `apps/api`
* `tests/` (the `forensic-tests` crate)
* `parser-dahua`, `parser-hikvision`, `parser-cpplus-ubs` and `parser-honeywell` **when built
  with `--all-targets`**, because `forensic-tests` is among their dev-dependencies. Their
  libraries build fine, and they are fully exercised through the recovery crate's suites.

This is a toolchain issue, not a code issue, and it is unrelated to this work. Stages 2c and 9d
of the runner are therefore optional: they are attempted and a link failure is recorded as SKIP
with the reason, never as a silent pass.

On a host with an MSVC toolchain, or on Linux, those stages should pass and give additional
coverage.

### Other known pre-existing failure

`evidence-reader`'s `mmap::tests::mmap_reads_correct_bytes` fails on this host (a page-alignment
assumption in the test). `crates/evidence-reader` was not modified by this work. If stage 9c
fails on that test alone, record it as pre-existing.

---

## 3. What each stage verifies

| Stage | Verifies | Status if green |
|---|---|---|
| 1 | a usable Rust toolchain | — |
| 2a–2b | the recovery engine, the contract harness and every buildable crate compile, tests included | `STATICALLY VERIFIED` |
| 2c | the whole workspace compiles | optional |
| 3a–3c | unit tests of the engine, the contract types and the forensic core | `UNIT TESTED` |
| 4a | **every** OEM parser against the **same** contract, on four evidence shapes | `UNIT TESTED` |
| 4b | the harness detects a deliberately non-compliant parser | `UNIT TESTED` |
| 4c | each parser declines another OEM's disk without fabricating | `UNIT TESTED` |
| 5a–5e | recovery decisions: Active, Orphaned, Deleted, Unindexed, Corrupted, and honest unknowns | `UNIT TESTED` |
| 6a–6c | determinism of decisions, of correlation, and of the contract itself | `UNIT TESTED` |
| 7a–7d | hypothesis, byte, cancellation and read bounds; adversarial input | `UNIT TESTED` |
| 8a–8c | provenance to exact bytes, UNKNOWN for unrun checks, observability counters | `UNIT TESTED` |
| 9a–9c | the pre-existing suites still pass — no regression | `UNIT TESTED` |
| 9d | cross-crate production chains | optional |

---

## 4. Running individual checks

The runner is a convenience. Each stage is an ordinary cargo invocation:

```bash
# Every OEM parser against the universal contract, with the per-check report printed
cargo test -p recovery --test universal_parser_contract -- --nocapture

# The recovery decision matrix
cargo test -p recovery --test universal_recovery -- --nocapture

# Determinism
cargo test -p recovery --test universal_recovery two_runs_over_the_same_evidence_agree_on_every_decision -- --exact

# Resource bounds
cargo test -p recovery --test universal_recovery the_hypothesis_bound_is_enforced_and_downgrades_the_run -- --exact
cargo test -p recovery --test adversarial_recovery

# Provenance
cargo test -p recovery --test universal_recovery every_candidate_traces_to_the_exact_bytes_in_the_exact_evidence_item -- --exact
```

`--nocapture` on stage 4a is worth using: the contract harness prints a per-check table for
every parser on every evidence shape, which is the artifact to read when judging compliance
rather than just pass/fail.

---

## 5. What a green report does and does not say

**It says:**

* the universal layer contains no OEM-specific branching, and every parser satisfies one
  shared contract;
* a parser handed foreign bytes returns nothing rather than inventing geometry, entries,
  channels or clocks;
* `Active` is reachable only from an index claim, `Orphaned` only from an authoritative index,
  and `Deleted` only from an explicit deallocation marker;
* missing information is reported as UNKNOWN with a reason, never as 0, the epoch, or a guessed
  codec;
* fragments are grouped and ordered from recorder evidence only, and physical adjacency is
  never used as a substitute;
* every configured bound actually terminates something, and a bounded run is REVIEW, never
  PASS;
* identical evidence produces identical decisions, ordering and provenance.

**It does not say:**

* that recovery works on a real acquired DVR image. Fixtures are synthetic.
* anything about firmware revisions not represented in `profiles/`.
* that the three parsers with no index reader (`cpplus-ubs`, `honeywell`, `tplink`) can recover
  indexed recordings. They cannot, by design and by declaration; they reach the raw-recovery
  tier only.
* that `DataState::Overwritten` works. No parser supplies a wrap pointer, so the path is
  unreachable. See finding F9 in
  [RECOVERY_ENGINE_AUDIT.md](RECOVERY_ENGINE_AUDIT.md).

---

## 6. Verifying against a real DVR image

Not covered by the runner, and the step that would move claims from `UNIT TESTED` to
`RUNTIME VERIFIED`:

1. Acquire an image of a supported recorder's disk, read-only, with a write blocker.
2. Register it and run the pipeline (`pipeline::run_pipeline`), or drive
   `RecoveryEngine::execute_recovery` directly with the detected profile and parser.
3. Read `RecoveryOutcome::capabilities` and `::strategies` **first**. They state what the
   parser established on that specific disk and which strategies that licensed. A disk whose
   index region is damaged will correctly report no authoritative index and no orphan
   findings — that is the engine working, not failing.
4. Check `RecoveryOutcome::recordings` rather than `::candidates` for the recording count, and
   read each recording's `ordering` and `evidence`.
5. Compare against ground truth from the recorder's own UI where one is available.
6. Record the result with its evidence status. A single successful real-image run makes claims
   about *that model and firmware*, not about the OEM.
