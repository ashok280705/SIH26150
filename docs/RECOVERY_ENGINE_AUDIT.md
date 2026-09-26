# Recovery engine audit

**Date:** 2026-09-25
**Scope:** `crates/recovery`, `crates/parsers-core`, and the recovery-relevant surfaces of
`crates/forensic-core`, `crates/pipeline`, `crates/detection`, `crates/confidence` and
`crates/parsers/*`.
**Method:** code-level trace of the production execution path. Documentation and READMEs were
read but not treated as evidence; every claim below cites a file and, where the claim is about
behaviour, a test that demonstrates it.

This document records what was found, what was changed, and what was deliberately left alone.
It is the audit half; the target design is in
[UNIVERSAL_RECOVERY_ARCHITECTURE.md](UNIVERSAL_RECOVERY_ARCHITECTURE.md) and
[UNIVERSAL_PARSER_ARCHITECTURE.md](UNIVERSAL_PARSER_ARCHITECTURE.md).

---

## 1. The execution path as it actually runs

Traced from `pipeline::run_pipeline` → `recovery::RecoveryEngine::execute_recovery`.

```text
Evidence (EvidenceReader, read-only at the type level)
   │
   ▼
OEM detection                    crates/detection — produces an OEM key + profile
   │                             NOT treated as evidence by the engine; passed in
   ▼
OEM parser                       Parser::storage_geometry() / ::recording_index()
   │                             a parser failure degrades the run, never aborts it
   ▼                             (engine.rs:177-200)
Standardized representation      StorageGeometry / RecordingIndex — plain Regions
   │                             parsers-core/src/storage.rs
   ▼
Recovery planning                plan::plan_recovery — RangeSet complement,
   │                             claimed vs available vs unclaimed, bounded targets
   ▼
Candidate generation             levels::scan_target_all — OEM structural carve first,
   │                             whole-window classification as fallback
   ▼
Candidate classification         classification::classify_region_state
   │                             index evidence × video evidence → DataState
   ▼
Validation                       FrameValidationReport per candidate; unrun checks Unknown
   │
   ▼
Fragment / temporal correlation  ← ADDED BY THIS AUDIT (correlation.rs)
   │                               previously absent from the production path
   ▼
Recovery decision                RecoveryOutcome
   │
   ▼
Provenance                       Provenance chain per candidate, evidence id preserved
```

Every transition above is implemented. Before this audit, the correlation transition was the
one gap: the engine's output was a flat candidate list and nothing turned it back into
recordings.

---

## 2. Findings

Each finding states what is wrong, why, where, the evidence, the fix, and the regression risk,
as required.

### F1 — The pipeline had no fragment or temporal correlation stage · BLOCKING · fixed

**What is wrong.** `execute_recovery` returned a flat `Vec<RecoveryCandidate>` with one entry
per OEM container record or per scan window, and nothing downstream grouped them. A single
carved 40 MB recording made of several hundred DHAV frames was reported as several hundred
"recovered recordings".

**Why it is wrong.** It makes a count of recovered recordings meaningless, and it discards
fields the scanner had already established: `DiscoveredFragment::parent_recording`,
`sequence_number` and `end_timestamp_unix` were populated (`levels.rs:488-545`) and never read
by any production caller.

**Where.** `crates/recovery/src/engine.rs` (the scan loop ended at `candidates.push`);
`crates/pipeline/src/lib.rs:352` turned each candidate into its own timeline event.

**Evidence.** `grep` for the four modules that would have performed this work
(`fragmentation`, `hypothesis`, `video`, `wrap_storage`) found call sites only in
`crates/recovery/tests/` and `tests/tests/regression_suite.rs` — never in `src/`. They were
implemented, tested, and unreachable from the engine.

**Fix.** New `crates/recovery/src/correlation.rs`, called from the engine after scanning.
Groups fragments on recorder-supplied evidence only, orders them from sequence numbers or the
recorder clock, and returns `TemporalOrdering::Unknown` with a reason when neither exists.
`fragmentation::reassemble_fragments` is now reachable: it produces the two-dimensional
logical/physical report for any group ordered by sequence number.

**Regression risk.** The stage is additive — `candidates` and `fragments` are unchanged, so
every existing consumer sees what it saw before. The one behavioural coupling is deliberate: a
correlation that hits its bounds sets `run.truncated`, which downgrades the run to REVIEW. Two
existing bound tests (`integration.rs`) still pass unchanged.

---

### F2 — `RecoveryBounds::max_hypotheses` was carried but never enforced · BLOCKING · fixed

**What is wrong.** `max_hypotheses` was set by every caller (`apps/api/src/handlers.rs:1600`,
`crates/pipeline/src/lib.rs:720`, six test call sites) and read by nothing.
`RecoveryRun::hypothesis_count` was assigned `0` at construction and never updated
(`engine.rs:262`).

**Why it is wrong.** A configured bound that terminates nothing reads as a safety control in
review while providing none. It is the same class of defect the FFmpeg timeout note in
`ffmpeg/service.rs:153` already calls out for subprocess budgets.

**Where.** `crates/recovery/src/engine.rs`, `crates/forensic-core/src/recovery.rs:289,304`.

**Evidence.** Repository-wide search for `max_hypotheses` and `hypothesis_count`; no read in
any `src/` path.

**Fix.** Correlation groups *are* the reconstruction hypotheses, so `max_hypotheses` now bounds
them via `CorrelationBounds::from_recovery_bounds`, `hypothesis_count` reports the groups
formed before bounding, and exceeding the bound truncates the run.
Test: `universal_recovery.rs::the_hypothesis_bound_is_enforced_and_downgrades_the_run`.

**Regression risk.** Callers that pass a small `max_hypotheses` now get REVIEW where they
previously got PASS. That is the intended correction, not a regression: the previous PASS was
unearned.

---

### F3 — `rank_hypotheses` truncated before ranking · HIGH · fixed

**What is wrong.** `hypotheses.truncate(max)` ran *before* the sort, so the survivors were
whichever hypotheses were generated first, and the reported top hypothesis could be the
worst-scoring one in the set.

**Why it is wrong.** It makes the result a function of generation order rather than of the
evidence, defeating the module's own stated purpose — its doc comment promises a deterministic
content-derived ranking.

**Where.** `crates/recovery/src/hypothesis.rs:43-44` (before the fix).

**Evidence.** Ten hypotheses scored `0.0..0.9` in ascending order, bounded to three, previously
yielded `h0, h1, h2` with `h0` (score 0.0) as the winner.

**Fix.** Sort, then truncate. Regression tests:
`bounding_keeps_the_highest_scoring_hypotheses_not_the_first_generated` and
`ranking_does_not_depend_on_generation_order_even_when_bounded`.

**Regression risk.** The pre-existing `test_bounded_hypothesis_count` still passes; it asserts
only the length and the REVIEW downgrade.

---

### F4 — Systematic argument swap put a type name where the examiner-facing reason goes · HIGH · fixed

**What is wrong.** `ValidationState::new` is `(state, reason, operation, subject)`
(`forensic-core/src/validation.rs:72`). Eleven production call sites passed a function or type
name as the `reason` and the human explanation as the `operation`.

**Why it is wrong.** `reason` is the field a report shows an examiner. A truncated recovery run
explained itself as `"RecoveryRun"` instead of `"Search space was truncated; global optimum not
guaranteed"`. The explanation was not lost — it was filed under the wrong key, where nothing
displays it.

**Where.** `forensic-core/src/recovery.rs:317,326` (`RecoveryRun::finalize`);
`recovery/src/hypothesis.rs` ×4; `recovery/src/video.rs` ×3;
`recovery/src/wrap_storage.rs` ×2; `reporting/src/provenance.rs` ×1.

**Evidence.** A scan for `ValidationState::new` calls whose `reason` literal contains no
whitespace while the `operation` literal does. Two further sites in `recovery.rs` test
fixtures were left alone; they are test data, not production output.

**Fix.** Arguments swapped at each site, with the parameter order noted in a comment so the
next reader does not repeat it. `.unwrap()` replaced with `.expect("<why this cannot fail>")`.

**Regression risk.** No test asserted on either field at these sites. The new assertions in
`universal_recovery.rs` (`a_cancelled_run_is_review_and_explains_itself`,
`the_hypothesis_bound_is_enforced_and_downgrades_the_run`) now pin the corrected text.

---

### F5 — An OEM name was hard-coded in the generic claim layer · MEDIUM · fixed

**What is wrong.** `claims::availability_reason` looked up `"dahua_availability_reason"` before
the conventional `"availability_reason"` key.

**Why it is wrong.** It is the only OEM name in production code outside the parser crates. Any
other OEM that recorded a prefixed availability reason had its wording silently replaced by the
generic default, and adding an OEM meant editing a generic function — the exact coupling the
universal layer exists to prevent.

**Where.** `crates/recovery/src/claims.rs:285` (before the fix).

**Evidence.** A case-insensitive search for all seven OEM names across
`crates/recovery/src`, `crates/parsers-core/src`, `crates/forensic-core/src`,
`crates/pipeline/src`, `crates/confidence/src` and `crates/timeline/src`. Every other hit was a
test fixture, a doc example or a profile-data string. This was the only production one.

**Fix.** The bare conventional key, then any `<namespace>_availability_reason`, resolved in
`BTreeMap` order so the choice stays deterministic. No parser changed.

**Regression risk.** None for Dahua — its key still matches, now via the suffix rule. Other
OEMs gain behaviour they never had.

---

### F6 — The crate did not build · BLOCKING · fixed

**What is wrong.** `cargo check -p recovery` failed with four errors: `tokio::time` and
`tokio::select!` were used in `ffmpeg/service.rs` but the crate's pinned feature list omitted
`time` and `macros`.

**Why it is wrong.** Nothing downstream of the recovery crate could be compiled or tested.

**Where.** `crates/recovery/Cargo.toml:25-30`.

**Fix.** Added `"time"` and `"macros"`, with a comment recording that the enforced FFmpeg
timeout depends on them. The deliberate avoidance of `features = ["full"]` is preserved.

**Regression risk.** None; the two features are additive and the crate's no-network, no-fs
position is unchanged.

---

### F7 — `declared_entry_count` semantics were ambiguous in the contract · MEDIUM · documented

**What is wrong.** `IndexAuthority::Partial` was documented as covering the case where "its
declared entry count disagrees with what could be parsed", while
`RecordingIndex::declared_entry_count` is the count the *structure* declares. For a slot-table
format such as the Dahua block table, free slots correctly yield no recording, so parsed is
routinely less than declared on a complete, authoritative read.

**Why it matters.** Taken literally, the stricter reading would force a compliant slot-table
parser to downgrade a complete read to `Partial`, which would destroy every orphan finding on
that OEM. The first draft of the contract harness encoded the strict reading and failed the
Dahua parser on a healthy fixture — which is how this was found.

**Where.** `crates/parsers-core/src/storage.rs`.

**Fix.** Documentation only, on both types. The universal invariant is now stated explicitly:
a parser may never produce *more* recordings than the structure declares, and a lower count is
not itself evidence of a partial read. The harness enforces that invariant.
**No parser was changed.**

---

### F8 — Three parsers return `Ok(true)` unconditionally from `recognize_candidate` · LOW · recorded, not fixed

**What is wrong.** `parser-cpplus-ubs`, `parser-honeywell` and `tplink` return `Ok(true)`
without reading the bytes. The trait documentation
(`parsers-core/src/parser.rs:74-76`) states that this makes the signal useless.

**Why it is not fixed here.** The signal is no longer load-bearing. `scan_target_all` consults
it only as a corroborating observation recorded on the finding, and
`classify_region_state` cannot see it at all, so it cannot influence a data state. Fixing it
requires OEM-specific format knowledge inside those three parsers, which this task's scope
explicitly excludes. The consequence today is cosmetic: a fragment's validation reason may say
"CP-Plus container framing also recognised here" about bytes that are not CP-Plus.

**Where.** `crates/parsers/cpplus-ubs/src/parser.rs:200`,
`crates/parsers/honeywell/src/parser.rs:192`, `crates/parsers/tplink/src/parser.rs:480`.

**Status.** Measured and printed by
`universal_parser_contract.rs::recognize_candidate_honesty_is_measured_and_reported`, which
asserts only that the signal is not meaningless platform-wide. **Open gap.**

---

### F9 — `DataState::Overwritten` is unreachable from the index-aware path · recorded, not fixed

`wrap_storage::detect_wrap_boundary` can produce physical overwrite evidence from a
`CircularBufferEvidence::WrapPointKnown` geometry, and `classify_recovery` can map it to
`Overwritten`. Neither is called by `execute_recovery`, and no OEM parser currently returns
anything but `CircularBufferEvidence::Unknown`, so there is no evidence for the path to
consume.

This is left as-is deliberately. Wiring it without a parser that supplies a wrap pointer would
produce overwrite findings from no evidence, which is worse than the honest gap. The capability
model now reports the absence explicitly rather than leaving it to be inferred.
**Open gap.**

---

### F10 — Provenance records wall-clock time · accepted

`levels::build_provenance` stamps `TransformationStep::performed_at` with `chrono::Utc::now()`,
so two runs over identical evidence produce provenance records that differ in that field.

This is correct and is not nondeterminism in a decision: when an analysis ran is an audit fact
that must be recorded. No candidate, state, ordering, offset or hash depends on it —
`two_runs_over_the_same_evidence_agree_on_every_decision` demonstrates that every decision is
stable. Recorded here so it is not re-flagged.

---

## 3. Capability audit

Assessed against the production path, per the required vocabulary.

| Capability | Before | After | Basis |
|---|---|---|---|
| Active recordings | IMPLEMENTED | IMPLEMENTED | `RegionClaim::Indexed` + validated video only |
| Deleted recordings | IMPLEMENTED | IMPLEMENTED | requires `AllocationEvidence::FreeMarked`; no "absent ⇒ deleted" path exists |
| Orphaned recordings | IMPLEMENTED | IMPLEMENTED | two routes: unclaimed-within-authoritative-scope, and surviving-but-unreachable metadata |
| Fragmented recordings | PARTIAL | IMPLEMENTED | discovery was implemented; grouping and ordering were unreachable, now in `correlation.rs` |
| Partially overwritten | PARTIAL | PARTIAL | truncated reads are marked REVIEW and structurally invalid video is `Corrupted`; `Overwritten` stays unreachable (F9) |
| Raw / unindexed recovery | IMPLEMENTED | IMPLEMENTED | whole-window sweep; findings can only reach `Unindexed` |
| Corrupted recordings | IMPLEMENTED | IMPLEMENTED | signature-without-structure ⇒ `Corrupted`, and `Corrupted` is never forced to `Unrecoverable` |

---

## 4. Recovery level audit

The levels are **not** a dispatch cascade — that was removed before this audit and the removal
holds. `RecoveryLevel` is a *consequence* of the claim that governs a region.

| Level | Input | Detection | Candidate generation | Validation | Output | Failure behaviour |
|---|---|---|---|---|---|---|
| L1 | `RegionClaim::Indexed` | authoritative index entry claims the bytes | 256 KiB head probe per claim | codec structure + container record state | `Active`, or `Deleted` with a free marker | unreadable target → `skipped_ranges`, run continues |
| L2 | `AvailableUnreferenced` / `UnclaimedWithinIndexScope` | surviving metadata, or a gap inside authoritative scope | probe for the first, 1 MiB chunked sweep for the second | as L1 | `Orphaned` | same |
| L3 | `OutsideIndexScope` / `NoIndexEvidence` | no authoritative statement covers the bytes | 1 MiB chunked sweep | as L1 | `Unindexed` | same |

This is a genuine escalation: each level is licensed by strictly weaker index evidence and
yields a strictly weaker conclusion. It is not "deeper because it reads more bytes" — L1 reads
the *least*.

---

## 5. Candidate generation and evidentiary strength

| Mechanism | Implemented in | Strength | Strongest state it can license |
|---|---|---|---|
| Authoritative index entry + validated media | `plan.rs` step 1, `classification.rs` | Strong | `Active` / `Deleted` |
| Surviving unreachable metadata + validated media | `plan.rs` step 2 | Strong | `Orphaned` |
| Authoritative-scope gap + validated media | `claims.rs` `split_by_scope` | Strong | `Orphaned` |
| OEM container record + validated codec | `Parser::scan_region_for_candidates` | Medium | `Unindexed` |
| Sequence numbers across fragments | `correlation.rs` | Strong | ordering only |
| Recorder timestamps across fragments | `correlation.rs` | Medium | ordering only |
| Codec signature only | `reconstructor::classify_codec` | Weak | `Corrupted` |
| Physical adjacency | — | not used | nothing |

The last row is the important one: physical adjacency is not an input to any decision. It is
recorded as a `PhysicalDiscontinuity` observation and never grouped or ordered on.

**No path exists from "signature found" to "recording recovered".** `classify_region_state`
returns `Corrupted` for signature-without-structure, and returns `None` — no candidate at all —
for a region with no codec evidence.

---

## 6. Determinism audit

| Risk | Status |
|---|---|
| `HashMap` iteration affecting output | None in production (`recovery/src` and `parsers-core/src` use `BTreeMap` only) |
| Unstable sorting | Scan targets, findings and correlation groups all sort on a total key ending in a physical offset |
| Wall-clock time in decisions | None; only in the audit timestamp (F10) |
| Random selection | None |
| Concurrency-dependent ordering | The engine is single-threaded over an ordered plan |
| Generation-order dependence | Was present in `rank_hypotheses` (F3), fixed |

Demonstrated by `two_runs_over_the_same_evidence_agree_on_every_decision`,
`candidates_are_ordered_by_physical_offset`,
`correlation_is_deterministic_regardless_of_discovery_order` and
`contract_results_are_reproducible_across_runs`.

---

## 7. Resource safety audit

| Bound | Enforced where | Status |
|---|---|---|
| `max_scan_bytes` | `engine.rs` — checked *before* the read that would exceed it | IMPLEMENTED |
| `max_scan_regions` | `engine.rs` loop guard | IMPLEMENTED |
| `max_candidates` | `engine.rs`, outer loop and inner findings loop | IMPLEMENTED |
| `max_hypotheses` | `correlation.rs` via `CorrelationBounds` | IMPLEMENTED (was NOT — F2) |
| per-group membership | `CorrelationBounds::max_fragments_per_group` | IMPLEMENTED (new) |
| `time_limit` | `engine.rs` per-target check | IMPLEMENTED |
| cancellation | `engine.rs` per-target check | IMPLEMENTED |
| read window / memory | `ScanContext::max_window_bytes`, `BoundedReader` | IMPLEMENTED |
| FFmpeg wall-clock | `ffmpeg/service.rs` `tokio::time::timeout` + kill + reap | IMPLEMENTED |
| unbounded recursion | none present — the engine iterates a flat plan | N/A |

Planner cost is linear in the number of index entries and in `universe / chunk_size`.
Correlation is `O(n log n)` in fragments — a `BTreeMap` group, then a sort per group — with no
pairwise combination step, which is what keeps a high-candidate-density image from becoming
combinatorial.

---

## 8. What was deliberately not changed

* **No OEM parser file was modified.** See the OEM safety list in
  [UNIVERSAL_RECOVERY_ARCHITECTURE.md](UNIVERSAL_RECOVERY_ARCHITECTURE.md#oem-safety).
* **The `Parser` trait is unchanged.** It was found sufficient; see
  [UNIVERSAL_PARSER_ARCHITECTURE.md](UNIVERSAL_PARSER_ARCHITECTURE.md).
* **No second parser interface, range type or confidence model was introduced.**
* **`classify_region_state` is untouched.** Its rule table was audited against every listed
  requirement and found correct.
* **`plan_recovery` and `claims.rs` range algebra are untouched** apart from F5.
* **No AI, and no expansion of OEM filesystem reverse engineering.**

---

## 9. Open gaps

1. **F8** — three parsers' `recognize_candidate` does not inspect bytes. Cosmetic today;
   requires OEM-parser changes that are out of scope here.
2. **F9** — `DataState::Overwritten` is unreachable because no parser supplies a wrap pointer.
   Needs OEM work, not engine work.
3. **Timeline placement of unknowns.** `pipeline::candidates_to_events` still withholds any
   candidate without a concrete channel *and* timestamp, because `TimelineEvent` has no
   representation for an unknown camera or clock. Correlated recordings now carry the grouping
   and ordering evidence the timeline model would need, but changing `TimelineEvent` is a
   separate piece of work.
4. **Runtime verification on real DVR images.** Everything here is verified against synthetic
   fixtures built from the real structure layouts in `profiles/`. See
   [UNIVERSAL_RECOVERY_VERIFICATION.md](UNIVERSAL_RECOVERY_VERIFICATION.md).
5. **`apps/api` and `tests/` cannot be built on the audit machine** — `sqlx-macros` fails to
   link under the mingw toolchain. Unrelated to this work; see the verification document.
6. **`evidence-reader`'s `mmap_reads_correct_bytes` fails on this machine**, pre-existing and
   untouched by this work (a page-alignment assumption in the test on Windows).
