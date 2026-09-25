# SIH 2026 Final-Submission Audit — VidForge PPT vs. Actual Implementation

**Audit date:** 2026-09-25
**Deck audited:** `TakeUForward.pdf_20260925_190600_0000.pdf` — 6 slides, SIH 2026 idea-submission template
**Problem statement:** PS 26150 — *Development of a Multi-Vendor DVR/NVR Forensic Analysis Tool for Standardized Acquisition, Recovery, and Analysis of Surveillance Evidence* · Theme: Blockchain & Cybersecurity · Category: Software
**Team:** 137599 — TakeUForward
**Repository:** `D:\shubham\VIDEO`, branch `feature/hikvision-completion`, HEAD `bed8c19`

**Method.** Every statement about the project below was checked against source on disk, against the
three verification documents in `docs/`, and against `PROJECT_IMPLEMENTATION_AUDIT.md`. Where a
prior document and the code disagreed, the code was taken as authoritative and the disagreement is
recorded. Where the code was newer than a prior audit (the `crates/media` work post-dates
`PROJECT_IMPLEMENTATION_AUDIT.md`), the newer state is reported.

**Status vocabulary used throughout** — the repository's own, extended with the labels the brief
requested:

| Label | Meaning |
|---|---|
| `VERIFIED` | executed and observed on this machine, green |
| `UNIT TESTED` | an automated test exercises it and passes; fixtures are synthetic |
| `IMPLEMENTED — VERIFICATION PENDING` | code exists and is reachable; never executed |
| `PARTIAL` | works for some OEMs / some inputs only |
| `ARCHITECTURE ONLY` | types, contracts and boundaries exist; the thing behind them does not |
| `[BUILD-BEFORE-SUBMISSION]` | not true today, realistically completable before submission |
| `[REMOVE CLAIM]` | asserted in the deck, not supported by the project, not buildable in time |

**One caveat on scope.** The official PS 26150 body text was not available to this audit — the only
uploaded artifact was the deck, which carries the PS title but not the full requirement text. The
requirement matrix in §4 is therefore built from (a) the PS title's three mandated verbs
— *standardized acquisition*, *recovery*, *analysis* — and (b) the requirement list supplied in the
audit brief. Before submission, re-check §4 against the official PS PDF; a requirement present
there and absent here is the one gap this audit cannot see.

---

## 1. EXECUTIVE ASSESSMENT

**The project is substantially stronger than the deck. The deck is also, in four specific places,
claiming things the project does not do.** Both halves of that sentence matter.

### The good news, stated precisely

This is not a hackathon shell. It is 77,012 lines of Rust across 199 files in 14 crates, with 1,162
test functions, a last full verification run of **481 passing / 1 failing** (the one failure is a
pre-existing page-alignment assumption in an `mmap` test, unrelated to any claim in the deck), and
a reproducible one-command verification runner that writes a machine-generated result file and
**exits non-zero on any failure**. The recovery engine is genuinely OEM-agnostic — `crates/recovery`
declares no OEM parser in `[dependencies]`, and every OEM name in its source sits inside a
`#[cfg(test)]` block. The codebase repeatedly and explicitly refuses to invent data, and it
documents where it refuses.

Most importantly: **the deck's data-flow diagram is not a drawing, it is an enum.** Every box on
slide 2 — Intake, Detection, Confidence, Threshold Gate, OEM Extraction, Unified Extraction,
Analyst Review, Parsed Gate, Preliminary Timeline, Gap Gate, Recovery, Recovery Gate, Final
Timeline — exists as a variant of `PipelineStage` in `crates/pipeline/src/lib.rs:69-83`, each
recording a `StageStatus` and a human-readable reason. Almost no SIH deck can say that. **The deck
does not currently say it, and that is the single largest missed opportunity in the submission.**

### The bad news, stated precisely

Four claims in the deck are not supported by the project, and two of them are not buildable in time:

| # | Deck claim | Reality |
|---|---|---|
| 1 | "Parallel Detection Across **8 OEMs**" (slide 2, twice; 8 vendor logos in the DFD) | **6** detectors exist. Matrix and Godrej have a directory containing a single file named `NOT_IMPLEMENTED.md`. Of the 6, exactly **3** (Hikvision, Dahua, Uniview) parse a real filesystem; 2 are self-declared skeletons; 1 (TP-Link) fabricates a recording with an invented timestamp. |
| 2 | "**AI**-based face, object & motion detection" (slide 2) + "Python • PyTorch • ONNX Runtime — AI-Based Forensic Analytics" (slide 3) + "AI-ASSISTED FORENSIC ANALYTICS: Face/Object/Motion/Event Detection" (slide 3 diagram) + "AI & MULTI-CAMERA ANALYSIS" (slide 4) | **Zero.** `grep -ri "onnx\|pytorch\|torch"` over the entire repository returns **no hits**. `apps/ai-service/main.py` returns two hardcoded detections and never reads the submitted clip bytes, and nothing in the Rust workspace can reach it (no HTTP client dependency exists anywhere). The `media` crate's analysis boundary is real and honest — with no engine registered it returns the constant `AI_ANALYSIS_NOT_CONFIGURED` and zero findings. The code is more honest than the slide. |
| 3 | "verify it with **MD5**/SHA-256 hashes" (slide 2) | `HashAlgorithm` has exactly one variant: `Sha256` (`crates/forensic-core/src/hash.rs:12-15`). `grep -ri md5` over `crates/` and `apps/` returns **no hits**. |
| 4 | "OpenCV — Frame & Image Processing / Motion Analysis" presented as a shipped stack item (slide 3) | The OpenCV backend is an **optional, off-by-default cargo feature** that has **never been compiled on any host**, stated in those words at `crates/media/src/lib.rs:47-50`. The pure-Rust fallback is real and tested (26 tests), reports itself as `pure_rust_fallback`, and never claims to be OpenCV. |

Claims 1, 3 and 4 are fixable in the deck with wording changes and are partly buildable. **Claim 2
is not buildable before submission to the standard the rest of this codebase holds, and it is the
one that will do real damage** — because an NTRO evaluator who asks "show me the face detection"
gets a hardcoded `0.91` confidence for a person at 12.5s, in a project whose entire remaining
surface is built on refusing to fabricate. The contrast is what makes it dangerous, not the
absence.

### The strategic read

The deck is currently selling a *generic surveillance AI platform*. The project is a *forensic
recovery architecture with unusually rigorous evidential discipline*. The second is far rarer, far
harder, and far more aligned with an NTRO evaluation than the first. **The deck is under-selling
the project's actual moat and over-selling its weakest area.** Fixing that inversion is the whole
job of this audit.

### Submission risk — the one operational item

`apps/api` and the `tests/` crate **do not link on the development machine** (`sqlx-macros` proc-macro
dylib fails under the mingw toolchain: `ld returned 116`). The core crates build and test fine; this
is a toolchain issue, not a code issue. But it means **the end-to-end demo has never run on the
development machine**. If the demo is given on that machine, there is no demo. This is the highest
operational risk in the submission and it is addressed in §20 as the first engineering task.

---

## 2. CURRENT PROJECT STATE

### 2.1 Scale

| Metric | Value |
|---|---|
| Rust source | 77,012 lines, 199 files |
| Crates | 14 library crates + `apps/api` + `apps/frontend` (Tauri 2 / React / TS) + `apps/ai-service` (Python stub) |
| Largest areas | `crates/parsers` 34,438 · `crates/recovery` 12,329 · `crates/media` 8,554 · `crates/forensic-core` 6,302 |
| Test functions in tree | 1,162 |
| Last full verification run | 481 passed, 1 failed (pre-existing `mmap` page-alignment test) |
| Universal contract + recovery suites | 8 + 20 = 28, all green |
| Commits | 39, 2026-08-28 → 2026-09-25 |
| Frontend views | 13 (`Case, Evidence, Acquisition, Detection, Parsing, PreliminaryTimeline, Recovery, Timeline, VideoPlayer, Custody, Reports, Overview, PhasePlaceholder`) |
| Real DVR disk images in repo | **0** — every fixture and all 85+ validation-corpus manifests are synthetic, generated from the real structure layouts declared in `profiles/` |

### 2.2 The classification the brief asked for

**A. VERIFIED (executed, observed green on this machine)**

- The one-command verification runner: `scripts/verify_universal_recovery.{sh,ps1}` → writes
  `UNIVERSAL_RECOVERY_VERIFICATION_RESULT.md`, 26 of 28 stages PASS, 2 SKIP (documented toolchain
  reason), 1 FAIL (pre-existing, unrelated). **There is no path through it that reports success for
  something that did not run.**
- Universal parser contract: all 6 OEM parsers against one shared contract on four evidence shapes
  (8 tests). Includes a deliberately non-compliant parser that the harness must reject — proving
  the harness is a gate, not decoration.
- Cross-OEM safety: each parser handed another OEM's disk returns nothing rather than inventing
  geometry, entries, channels or clocks.
- Recovery decision matrix (20 tests): `Active` reachable only from an index claim; `Orphaned` only
  from an authoritative index; `Deleted` only from an explicit deallocation marker; missing
  information reported as UNKNOWN with a reason, never as `0` or the epoch.
- Determinism: identical evidence → identical decisions, ordering and provenance; correlation
  independent of discovery order.
- Resource bounds: hypothesis, byte, cancellation and read-window bounds each *actually terminate
  something*, and a bounded run is `REVIEW`, never `PASS`.
- Provenance: every candidate traces to exact bytes in an exact evidence item; unrun validation
  checks stay `UNKNOWN`.
- `media` crate: 106 lib tests green, including a real process-timeout test that spawns a child,
  lets the budget expire, and asserts the child was terminated.
- `recovery` crate: 117 tests green across 6 targets.

**B. IMPLEMENTED BUT NOT RUNTIME VERIFIED**

- FFmpeg decode to real frames (`crates/media/src/decode.rs`, `-f rawvideo`). The development
  machine has no `ffmpeg`/`ffprobe`, so 14 of 16 media integration tests SKIPPED. **No actual video
  decode has ever run here.**
- The whole `apps/api` HTTP surface and the 13-view frontend (never built here).
- Media reconstruction → remux path (works per prior audit, not re-executed).

**C. PARTIALLY IMPLEMENTED**

- OEM coverage: 3 deep (Hikvision, Dahua, Uniview), 2 declared skeletons (CP-Plus UBS, Honeywell),
  1 fabricating prototype (TP-Link), 1 unified fallback.
- Uniview: structural parsing complete and precise; media reconstruction deliberately not
  implemented; `scan_region_for_candidates` returns empty **on purpose**, documented as "No Uniview
  DATA framing is known" — honest degradation, not an omission.
- Hash handling: SHA-256 computed and preserved at ingest and for derived artifacts; **the evidence
  hash is never recomputed and compared**, yet `handlers.rs:165` writes the string
  `"Ingest hash verified"`. That wording is a defect.
- Timeline: engine, cross-camera correlator and gap analysis exist and are wired into
  `crates/pipeline`; but `candidates_to_events` withholds any candidate lacking *both* a concrete
  channel and timestamp, because `TimelineEvent` has no representation for an unknown camera or
  clock.
- Reporting: JSON/CSV/formatted exporters complete; several report fields canned or never populated.

**D. ARCHITECTURALLY DESIGNED (boundary real, thing behind it absent)**

- The media → AI boundary. `crates/media/src/analysis.rs` defines exactly what an engine receives
  and returns, guarantees "a detection is only ever reported when an engine actually inferred it",
  and ships **no detector**. This is good engineering and must be presented as *a boundary*, not as
  *analytics*.
- OpenCV backend: written against the `opencv` 0.94 API, structurally complete, **never compiled on
  any host**.
- `forensic-core/src/ai_pipeline.rs`: real boundary logic (`validate_ai_input`,
  `handle_ai_degradation`), **zero production callers**.

**E. PLANNED** — real-image validation; Matrix/Godrej/CP-Plus (non-UBS) parsers; `DataState::Overwritten`
(unreachable until a parser supplies a wrap pointer).

**F. NOT IMPLEMENTED** — MD5; any ML inference of any kind; face/object/motion detection; OpenCV
execution.

**G. CLAIMED IN PPT BUT NOT SUPPORTED** — the four items in §1. Plus: "8 OEMs"; "Synchronizes
footage across cameras" is stronger than what ships (cross-camera correlation exists; clock-drift
*correction* is a slide label, not a verified capability).

### 2.3 What the project has that the deck never mentions

This list is the core of the recommendation set. Every item is real, testable, and currently invisible
to an evaluator:

1. **A machine-generated verification report** with PASS/SKIP/FAIL per stage and per-stage console
   logs, that cannot report success for an unrun stage.
2. **A universal parser contract** (`crates/parsers-core/src/contract.rs`) that every OEM parser is
   tested against — *including a deliberately broken parser the harness must reject*.
3. **Runtime capability assessment** — 10 dimensions derived from what the parser actually returned
   on *this disk*, distinct from declared implementation maturity. A disk with a destroyed index
   correctly reports no authoritative index and no orphan findings. **That is the engine working,
   not failing.**
4. **Strategy refusal with reasons.** All 6 strategies appear in every output whether licensed or
   not, each with its reason — so a report can state *"structural recovery was not performed because
   no authoritative index governs these bytes"* rather than leaving an examiner to infer it from an
   absent section. **This is the single most forensically distinctive thing in the project.**
5. **Physical adjacency is never used to group or order fragments.** It is recorded as a
   `PhysicalDiscontinuity` observation and acted on never. Two records adjacent on disk may be two
   halves of one recording or two unrelated recordings months apart.
6. **Determinism as a tested property**, with a `DeterminismKey` that excludes environment metadata.
7. **Read-only at the type level** — the `EvidenceReader` trait exposes no write method. No
   `OpenOptions`, no `.write(true)`, nowhere in `crates/`.
8. **Bounded search is never PASS.** Any bound being hit sets `run.truncated` and downgrades the run
   to REVIEW, because a bounded search cannot guarantee a global optimum.
9. **`fragment_id` is a SHA-256 of the evidence id and the exact range** — the same bytes always
   produce the same id across runs and representations; nothing downstream mints a new one.
10. **`crates/media` cannot acquire OEM knowledge by accident** — it deliberately has no dependency
    on `recovery` or `parsers/*`.

---

## 3. PPT vs PROJECT CONSISTENCY MATRIX

| # | PPT Claim | Slide | Actual Project State | Evidence | Status | Action |
|---|---|---|---|---|---|---|
| 1 | "Parallel Detection Across 8 OEMs" | 2 (×2), 3 | 6 detectors; Matrix + Godrej are `NOT_IMPLEMENTED.md` files | `crates/detection/src/detectors/` (6 files); `profiles/matrix/`, `profiles/godrej/` | **MISLEADING** | Change to "6 OEM detectors · 3 with full filesystem parsers". `[REMOVE CLAIM]` on 8 |
| 2 | 8 vendor logos in the DFD | 2 | 2 of the 8 have no code at all | same | **MISLEADING** | Remove Matrix + Godrej logos, or grey them under a "profile declared, parser pending" tier |
| 3 | "Identify and parse proprietary DVR/NVR formats" | 2 | True for Hikvision, Dahua, Uniview. False for CP-Plus UBS, Honeywell. TP-Link fabricates. | §4 OEM matrix, `PROJECT_IMPLEMENTATION_AUDIT.md` | **PARTIAL** | Add a maturity tier to the slide — see §6 item 1 |
| 4 | "MD5/SHA-256 hashes" | 2 | SHA-256 only; zero MD5 references | `forensic-core/src/hash.rs:12-15`; `grep -ri md5` = 0 | **UNSUPPORTED** | Either `[REMOVE CLAIM]` → "SHA-256" or `[BUILD-BEFORE-SUBMISSION]` (≈2h, trivial) |
| 5 | "ensure the evidence remains unchanged" | 2 | Read-only at the type level; no write path exists | `EvidenceReader` trait; no `OpenOptions` in `crates/` | **VERIFIED** | **Keep and strengthen** — this is under-claimed |
| 6 | "Score OEMs using evidence; route uncertain cases for analyst validation" | 2 | `crates/confidence` + `PipelineStage::{Confidence, ThresholdGate, AnalystReview}` | `crates/pipeline/src/lib.rs:69-83` | **UNIT TESTED** | Keep; cite the enum |
| 7 | "Intelligent L1 L2 L3 Deleted Evidence Recovery" | 2, 4, 5 | L1/L2/L3 exist as `RecoveryLevel`, but they are a **consequence of claim strength**, not a dispatch cascade. The dispatch cascade was deliberately removed. | `docs/RECOVERY_ENGINE_AUDIT.md` §4 | **IMPLEMENTED — described inaccurately** | Rewrite: levels are licensed by index evidence, not by "trying harder". See §8 |
| 8 | "L1 Indexed → L2 Orphan/Slack → L3 Raw Carving" | 3, 4, 5 | Close, but "Slack" is not the mechanism. L2 = surviving unreachable metadata, **or** a gap inside authoritative index scope | `RECOVERY_ENGINE_AUDIT.md` §4 | **INACCURATE TERMINOLOGY** | Replace "Orphan/Slack" with "Orphaned (unreferenced metadata · unclaimed-in-scope)" |
| 9 | "Recovers missing/deleted evidence" | 2, 5 | True, with a hard constraint the deck omits: `Deleted` requires an explicit free marker; there is **no path from "absent from index" to "Deleted"** | `UNIVERSAL_RECOVERY_VERIFICATION.md` §5 | **IMPLEMENTED — under-described** | **Add the constraint.** It is a credibility asset, not a limitation |
| 10 | "Synchronizes cameras / footage across cameras" | 2 (×2), 5 | `CrossCameraCorrelator` + `timeline::clock` exist and are wired. "Correct Clock Drift" (slide 3 box) is a label with no verified implementation behind it | `crates/timeline/`, `pipeline/src/lib.rs:60-64` | **PARTIAL** | Soften to "cross-camera event correlation and timestamp normalization"; drop "clock drift correction" |
| 11 | "AI-based face, object & motion detection" | 2 | **Nothing.** No models, no ONNX, no PyTorch, no inference | `grep -ri "onnx\|pytorch\|torch"` = 0 hits; `media/src/analysis.rs:24` | **UNSUPPORTED** | `[REMOVE CLAIM]` — replace with the *boundary* framing, §8 |
| 12 | "Python • PyTorch • ONNX Runtime — AI-Based Forensic Analytics" | 3 (tech stack) | Not a dependency anywhere. `apps/ai-service/requirements.txt` declares neither | same | **UNSUPPORTED** | `[REMOVE CLAIM]` — remove the logo row entirely |
| 13 | "AI-ASSISTED FORENSIC ANALYTICS · Face/Object/Motion/Event Detection" (terminal box of the architecture diagram) | 3 | The terminal box of the *actual* pipeline is `AnalysisPipeline` returning `AI_ANALYSIS_NOT_CONFIGURED` | `media/src/pipeline.rs:1-21` | **UNSUPPORTED** | Relabel the box "ANALYSIS BOUNDARY (engine-pluggable) — *planned*" and mark it in the planned tier |
| 14 | "OpenCV — Frame & Image Processing · Motion Analysis" as a shipped stack item | 3 | Optional cargo feature, off by default, **never compiled on any host** | `media/src/lib.rs:47-50`; `MEDIA_PIPELINE_VERIFICATION.md` §0 | **MISLEADING** | Move to a "pluggable / optional" tier, or replace with "Frame processing — pure-Rust backend (tested) + optional OpenCV backend" |
| 15 | "FFmpeg — Video Reconstruction & Validation · Codec/GOP/Decode/Remux" | 3 | Remux + ffprobe QC verified previously; **decode implemented in `crates/media/src/decode.rs` but never executed** (no ffmpeg on dev host) | `MEDIA_PIPELINE_VERIFICATION.md` §0 | **IMPLEMENTED — VERIFICATION PENDING** | Keep, but this *must* be executed before the demo — see §20 |
| 16 | "Rust • Tokio • Rayon — Scanning/Parsing/Carving" | 3 | Accurate. Rust core is the bulk of the system | 77k lines | **VERIFIED** | Keep |
| 17 | "Tauri 2 • React • TypeScript — 13 views" (implied) | 3 | 13 views exist and were previously wired to real endpoints | `apps/frontend/src/views/` | **IMPLEMENTED — VERIFICATION PENDING** (not built on this host) | Keep; **must be screenshotted** — §14 |
| 18 | "SQLite — Case/Timeline/Provenance" | 3 | Real (via sqlx) — and the reason `apps/api` won't link here | `apps/api` | **IMPLEMENTED — VERIFICATION PENDING** | Keep |
| 19 | "Preserves integrity through hashing & chain of custody" | 2, 5 | Custody events + `CustodyView` + `write_guard` emitting `WriteDenied` are real. But the **evidence hash is never re-verified** while the UI says "Ingest hash verified" | `PROJECT_IMPLEMENTATION_AUDIT.md` §19 rows 6–7 | **PARTIAL — one wording defect in the product** | `[BUILD-BEFORE-SUBMISSION]` — implement re-verification (≈3h). Cheapest credibility win in the project |
| 20 | "Unified Forensic Schema for Future DVR/NVRs" | 2, 4, 5 | Real and strong: one `Parser` trait, normalized return types, absolute physical offsets, honest degradation defaults, contract-tested | `crates/parsers-core/`, `contract.rs` | **UNIT TESTED** | **Keep and promote** — this is the #1 differentiator and it is buried at position 5 of a bullet list |
| 21 | "Offline-First: Bit-Level Forensic Analysis" | 2 | Accurate. No network dependency in the forensic path | — | **VERIFIED** | Keep |
| 22 | "New OEMs added through independent parsers — without redesigning the system" | 4, 5 | **Structurally true and demonstrable**: capabilities are derived at runtime, strategies read capabilities not names, and a parser that establishes nothing still reaches the raw tier | `UNIVERSAL_RECOVERY_ARCHITECTURE.md` §9 | **UNIT TESTED** | **Keep — and give it a diagram.** §11-D |
| 23 | "Parallel modules, modular design and scalable storage for large-scale processing" | 4 | Plan-driven bounded scanning with `bytes_avoided_vs_full_scan` is real and is the best-engineered hot path. But there are **no benchmarks**, and prior audit flags 6 HIGH-severity performance defects (naive O(n·m) carve scan, no `spawn_blocking`, volume re-parsed per export) | `PROJECT_IMPLEMENTATION_AUDIT.md` §20 | **PARTIAL — do not quantify** | Keep qualitatively. **Never put a throughput number on a slide.** None has been measured |
| 24 | "Forensically explainable — traces recovered footage to source locations and validation evidence" | 5 | **True, and stronger than stated**: 13-field `Provenance`, evidence id → planner region → scanned region → fragment region, content hashes, parser+profile version and hash | `UNIVERSAL_RECOVERY_ARCHITECTURE.md` §6 | **UNIT TESTED** | **Promote to a headline.** Currently item 4 of 4 in a corner panel |
| 25 | "Rebuilds recordings from scattered fragments using time, channel, and stream relationships" | 5 | Accurate and understated. Three grouping tiers, ordering from sequence numbers → recorder clock → `Unknown` (never guessed) | `UNIVERSAL_RECOVERY_ARCHITECTURE.md` §4 | **UNIT TESTED** | Keep; add "and reports `Unknown` when the recorder supplied no ordering evidence" |
| 26 | "Read-only access + hash verification" (Operational Feasibility) | 4 | Read-only: verified. Hash *verification*: see #19 | — | **PARTIAL** | Fix the product, then the claim is clean |
| 27 | "Human validation for uncertain cases" | 2, 4 | `PipelineStage::AnalystReview` + `StageStatus::RequiresAnalyst` are real enum variants that halt the flow | `pipeline/src/lib.rs:76,88-92` | **UNIT TESTED** | Keep; cite the gate |
| 28 | Evidence Reader diagram (IDISK / TRYREAD / E01) | 6 | Matches `crates/evidence-reader/` structure. E01/EWF support asserted on the slide — **verify before submission** that an E01 reader actually exists rather than a planned variant | `evidence-reader/src/{raw,reader,mmap}.rs` | **VERIFY** | Confirm E01; if absent, `[REMOVE CLAIM]` or `[BUILD-BEFORE-SUBMISSION]` |

### Features implemented but missing from the deck entirely

| Feature | Why it belongs on a slide |
|---|---|
| Machine-generated verification report, fails loudly | Converts "we tested it" into "here is the artifact" — the single strongest credibility move available |
| Universal parser contract with a deliberately-broken parser as a test | Proves the abstraction is enforced, not aspirational |
| Runtime capability assessment (10 dimensions) | Explains *why* recovery degrades gracefully instead of failing |
| Strategy refusal with stated reasons | Forensically unique. No consumer recovery tool does this |
| "Physical adjacency never groups or orders" | One sentence that separates this from every carving tool |
| Determinism as a tested property | Directly relevant to evidence admissibility |
| Bounded run ⇒ REVIEW, never PASS | Same |
| `crates/media` cannot acquire OEM knowledge by construction | Proves the layering is structural, not conventional |
| 13 frontend views wired to real endpoints | The deck says "PROTOTYPE" with a clip-art hand and shows nothing |

---

## 4. SIH / NTRO REQUIREMENT MATRIX

*(Derived from the PS title and the brief's requirement list. Re-validate against the official PS body.)*

| Requirement | PPT Coverage | Implementation Coverage | Evidence | Gap | Priority |
|---|---|---|---|---|---|
| **Multi-OEM support** | 🟢 strong (but inflated to 8) | 🟡 6 detectors, 3 real parsers | `detectors/`, OEM matrix | Deck overstates; implementation uneven | **P0** — correct the number, add the tier |
| **Device / OEM identification** | 🟢 | 🟢 profile-driven, deterministic, confidence-scored, analyst gate | `crates/detection`, `crates/confidence` | none | — |
| **Proprietary filesystem parsing** | 🟢 | 🟡 HIKBTREE, DHFS, UNIVIEW_FS complete; 3 OEMs absent | `crates/parsers/` 34k lines | Coverage | **P1** |
| **Forensic imaging / acquisition** | 🟡 mentioned once | 🟡 read-only reader, source-safety inspection, custody event at ingest. Write-blocker state is **caller-asserted, not measured** | `source_safety.rs`, `AcquisitionView` | Deck doesn't show it; product doesn't measure it | **P1** |
| **Video metadata extraction** | 🟢 | 🟢 for 3 OEMs | parser tests | — | — |
| **Proprietary video/container handling** | 🟡 | 🟢 DHAV, PS/HIKBTREE framing, codec classification, payload/framing separation | `dahua/dhav.rs`, `hikvision/ps.rs` | Under-shown | **P2** |
| **Deleted footage recovery** | 🟢 headline | 🟢 with a *stricter* evidential rule than claimed | recovery suite | Deck under-describes the rigour | **P0** (as an upgrade, not a fix) |
| **Timestamp normalization** | 🟢 | 🟡 normalization real; "clock drift correction" unproven | `timeline/clock.rs` | Claim slightly ahead | **P1** |
| **MD5 / SHA-256** | 🔴 claims MD5 | 🔴 SHA-256 only | `hash.rs:12-15` | MD5 absent | **P0** — 2h build or remove |
| **Event correlation** | 🟢 | 🟡 cross-camera correlator wired; unknown-channel candidates withheld from timeline | `pipeline`, `timeline/correlation.rs` | Known open gap #3 | **P2** |
| **Chain of custody** | 🟡 one bullet | 🟢 custody events, `WriteDenied`, `CustodyView`, 13-field provenance | `write_guard.rs`, `reporting/provenance.rs` | Massively under-shown | **P0** (promotion) |
| **Forensic reporting** | 🟡 | 🟡 JSON/CSV/formatted exporters complete; some fields canned | `crates/reporting/` | Canned fields | **P1** |
| **AI analytics** | 🔴 claimed as shipped | 🔴 none | `analysis.rs:24` | Total | **P0** — reframe as boundary |
| **Face / object / motion analysis** | 🔴 claimed | 🔴 none | same | Total | **P0** — remove |
| **SOP / manuals** | 🔴 absent | 🟡 3 verification docs + 2 architecture docs + a runner | `docs/` | Deck never mentions them | **P1** — one line + a QR |
| **Validation** | 🟡 "forensic validation" | 🟢 **exceptional** — reproducible runner, contract harness, adversarial suite, determinism suite, 85+ corpus manifests | `UNIVERSAL_RECOVERY_VERIFICATION_RESULT.md` | Invisible in the deck | **P0** (promotion) |
| **Comparative OEM analysis** | 🔴 absent | 🟡 profiles encode per-OEM structure; no comparison artifact | `profiles/` | Deck has no OEM comparison | **P2** |
| **Forensic image / evidence handling** | 🟡 | 🟢 read-only at the type level, absolute offsets preserved, bounded reads | §19 of prior audit | Under-shown | **P1** |
| **Scalability / extensibility** | 🟢 | 🟢 genuinely structural | `UNIVERSAL_RECOVERY_ARCHITECTURE.md` §9 | Told, not shown | **P0** (diagram) |

**Score: 🟢 8 · 🟡 9 · 🔴 3.** The three reds are all AI/MD5 and all are deck problems, not
project problems. Two of the three are fixable by deleting text.

---

## 5. SLIDE-BY-SLIDE AUDIT

**A constraint the brief did not account for, stated plainly:** this is the **official SIH 2026
idea-submission template**. The six slides and their headings — *Title · Idea/Proposed Solution ·
Technical Approach · Feasibility & Viability · Impact & Benefits · Research & References* — are
**mandated**. Slides cannot be reordered, added or removed without risking rejection at screening.
So the brief's instruction *"give the ideal final slide order; do not preserve the existing order"*
has one correct answer: **keep the six mandated slides in the mandated order, and re-order,
re-weight and replace content inside each panel.** Every recommendation below respects that.

| Slide | Purpose | Problem | Verdict | Recommended Change |
|---|---|---|---|---|
| **1 — Title** | PS ID, title, theme, team | Nothing wrong. Also: does nothing. Zero information about the project | **MODIFY** | Add one 8–10 word capability line under the title: *"Recovers deleted surveillance footage from proprietary DVR filesystems — with provenance."* Free real estate, currently blank |
| **2 — Proposed Solution** | What it is + DFD + uniqueness + how it addresses the PS | (a) the left column is a 45-word paragraph an evaluator will not read; (b) "8 OEMs" is false; (c) "MD5" is false; (d) "AI-based face/object/motion" is false; (e) the DFD is excellent but is rendered in ~9pt in one-third of the slide and is unreadable at screening size; (f) **UNIQUENESS and HOW IT ADDRESSES THE PROBLEM overlap ~60%** — "Recovers L1-L3" and "Intelligent L1 L2 L3 Recovery" are the same claim twice | **MODIFY — heaviest rework** | Kill the paragraph → one 12-word sentence. Merge the two right-hand lists into one 5-item list, dedupe. Correct 8→6, drop MD5, drop AI. **Enlarge the DFD**: give it 45% of slide width and drop the 8 logos to 6 |
| **3 — Technical Approach** | Tech stack + architecture | (a) the architecture diagram has **34+ boxes and is unreadable at any projection size** — this is the worst readability problem in the deck; (b) the tech stack lists PyTorch/ONNX (absent) and OpenCV (never compiled); (c) "PARSING DIAGRAMS OF OEMS", "PROTOTYPE", "VIDEO" are **clip-art hands pointing at hyperlinks** — at screening, an evaluator sees three cartoon hands and no prototype; (d) the diagram substantially **duplicates slide 2's DFD** — two renderings of one pipeline across two slides | **MODIFY — second heaviest** | Replace the 34-box diagram with the **layered OEM→Universal diagram (§11-A)**, ~12 boxes. Cut the tech stack from 6 rows to 4, remove Python/PyTorch/ONNX, retier OpenCV. **Replace at least one clip-art hand with a real screenshot** |
| **4 — Feasibility & Viability** | Feasibility, scalability, viability, challenges | Structurally the **best slide in the deck** — the Challenges→Solution table is the clearest thing in it. Problems: (a) 5 panels is one too many, "VIABILITY" and "TECHNICAL FEASIBILITY" say the same four things in different order — *Modular OEM architecture*, *Tiered recovery*, *Forensic validation* appear in **both**; (b) "AI & MULTI-CAMERA ANALYSIS" is unsupported; (c) zero evidence — no test counts, no verification artifact | **MODIFY** | Merge VIABILITY + TECHNICAL FEASIBILITY into one panel (4 items, deduped). Use the freed panel for **EVIDENCE OF IMPLEMENTATION**: 77k lines · 14 crates · 1,162 tests · 481 green · one-command reproducible verification. Drop the AI item |
| **5 — Impact & Benefits** | Benefits, differentiators, impact, vision | (a) **four panels, all prose bullets, nearly interchangeable** — "Faster forensic examination" / "Reduced manual efforts" / "Cross-vendor investigation" are three phrasings of one idea; (b) TECHNICAL DIFFERENTIATORS is the strongest panel on the slide and is in the bottom-right corner in the smallest box; (c) "AI" appears again | **MODIFY** | **Promote TECHNICAL DIFFERENTIATORS to the top-left**, full width or half. Collapse the three benefit panels into one 4-item list. Add the two differentiators the project has and the deck omits: *strategy refusal with reasons*, *physical adjacency is never used to order* |
| **6 — Research & References** | Research grounding + references | (a) the Evidence Reader diagram is ~20 boxes of **internal implementation trivia** (`TRYREAD()`, `System OS API`, `Sector (Raw Bytes)`) — this is a code-review artifact, not an evaluator artifact; (b) the Research column is four generic headings that could describe any DVR project — "Studied DVR/NVR forensic investigation workflows" conveys nothing; (c) **the actual references are a single word, "Link"**, behind a clip-art hand. An NTRO evaluator checking references finds one hyperlink | **MODIFY — biggest credibility leak** | Replace the Evidence Reader diagram with the **Recovery Depth diagram (§11-E)**. Replace generic research bullets with **3–5 named, citable references** (NIST SP 800-101/86, DFRWS papers on video carving, published DVR filesystem reverse-engineering work, the FFmpeg/ISO container specs actually used). Keep the Recovery Engine column — it is the best diagram on the slide |

### Ideal order

**Unchanged — mandated.** The re-ordering that matters is *within* slides:

- Slide 2: DFD first (visual), then the 5-item uniqueness list, then the one-line description last.
- Slide 3: architecture diagram gets 65% of the slide; stack becomes a thin left rail.
- Slide 4: Challenges→Solution table moves to the top (it is the clearest artifact in the deck).
- Slide 5: differentiators first, benefits second, vision last.
- Slide 6: references first (they are the slide's title), diagrams second.

---

## 6. CONTENT TO ADD

Each item states why it changes an evaluator's judgement.

1. **An OEM maturity tier, on slide 2, replacing the flat row of 8 logos.**
   ```
   FULL FILESYSTEM PARSER   Hikvision (HIKBTREE) · Dahua (DHFS) · Uniview (UNIVIEW_FS)
   DETECTION + PROFILE      CP-Plus UBS · Honeywell · TP-Link
   PROFILE DECLARED         Matrix · Godrej          (parser pending)
   ```
   **Why:** it converts the deck's single most attackable claim into its most credible one. An
   evaluator who reads "8 OEMs" and finds 3 real ones distrusts everything else on the slide. An
   evaluator who reads a three-tier honest chart concludes the team knows exactly where it stands —
   which is the rarest signal in a hackathon submission. It also *keeps all eight names on screen*.

2. **An evidence panel on slide 4** (replacing the merged viability duplication):
   ```
   77,012 lines Rust · 14 crates · 1,162 test functions
   481 tests green in the last full run · 28 universal-contract + recovery tests
   One command reproduces every result and exits non-zero on any failure
   Every fixture synthetic, built from real OEM structure layouts — stated in the report
   ```
   **Why:** this is the difference between "we built a tool" and "here is the artifact that proves
   it". The last line is the most persuasive: a team that volunteers its own limitation is believed
   about everything else.

3. **The strategy-refusal sentence, verbatim, on slide 5.**
   > *"Structural recovery was not performed because no authoritative index governs these bytes."*
   > Every strategy appears in every report — licensed or refused, with its reason.

   **Why:** no consumer recovery tool does this. It is a single sentence that an evaluator with a
   forensics background will immediately recognise as non-trivial, and it is currently absent.

4. **The evidential-rule box on slide 2 or 5** (three lines):
   ```
   Active    ⟸ requires an index claim
   Deleted   ⟸ requires an explicit free marker — never inferred from absence
   Orphaned  ⟸ requires an authoritative index that governs bytes it does not claim
   ```
   **Why:** it answers the question every forensic evaluator asks — *"how do you know it was
   deleted rather than never indexed?"* — before it is asked. It also silently demonstrates that
   the team understands the difference, which most do not.

5. **"Physical adjacency is never used to group or order fragments"**, one line on slide 5.
   **Why:** this is the sentence that separates the project from file carving. Two records adjacent
   on disk may be two halves of one recording or two unrelated recordings months apart.

6. **A real screenshot on slide 3**, replacing one clip-art hand. See §14 for exactly which.
   **Why:** the deck currently offers *zero* pixels of the actual product. "PROTOTYPE" with a
   cartoon hand reads as "we have a link to something".

7. **3–5 named references on slide 6.**
   **Why:** the slide is titled *Research and References* and contains one word of reference. This
   is free marks being left on the table.

8. **A one-line limitations statement on slide 4 or 6.**
   > *"Validated against synthetic images generated from real OEM structure layouts. Real-image
   > validation is the next milestone."*

   **Why:** counter-intuitively this **raises** the score. Evaluators assume synthetic validation;
   a team that says so unprompted is trusted on the rest. A team that is caught having implied
   otherwise is not.

9. **A QR code or short link to the verification document**, small, on slide 6.
   **Why:** an evaluator who wants to check has a 10-second path. Most won't. The presence of the
   path is the signal.

---

## 7. CONTENT TO REMOVE

| Remove | Where | Why |
|---|---|---|
| "Python • PyTorch • ONNX Runtime — AI-Based Forensic Analytics" (whole stack row + logo) | 3 | Zero references in the repository. Highest-risk item in the deck |
| "5. AI-based face, object & motion detection" | 2 | Unsupported |
| "4. AI & MULTI-CAMERA ANALYSIS — analyze evidence with AI" | 4 | Unsupported |
| "AI-ASSISTED FORENSIC ANALYTICS" terminal box as a *shipped* stage | 3 | Relabel to boundary/planned, do not delete the box — the boundary is real |
| "MD5/" from "MD5/SHA-256" | 2 | Not implemented (or implement it — §15) |
| "8 OEMs" (both occurrences) and the Matrix + Godrej logos at full colour | 2, 3 | 2 of 8 have no code |
| The 45-word opening paragraph | 2 | Nobody reads a paragraph on slide 2. Everything in it is repeated in the 4 numbered blocks below it |
| Duplicate items between VIABILITY and TECHNICAL FEASIBILITY (*Modular OEM architecture*, *Tiered recovery*, *Forensic validation*) | 4 | Stated twice in adjacent panels |
| Duplicate items between UNIQUENESS and HOW IT ADDRESSES THE PROBLEM (L1-L3 recovery, multi-camera, evidence-based detection) | 2 | ~60% overlap between two adjacent panels |
| "Faster forensic examination" / "Reduced manual efforts" as separate bullets | 5 | One idea, two bullets |
| The Evidence Reader diagram (IDISK / TRYREAD() / System OS API / Sector Raw Bytes) | 6 | Internal implementation trivia. An evaluator does not need to know your read-path function names; the slot is worth far more as a recovery-depth visual |
| Three clip-art pointing hands | 3, 6 | They are the only "visual" the prototype currently gets. Replace at least two with real screenshots |
| "Correct Clock Drift" as a claimed stage | 3 | Normalization is real; drift *correction* is not verified |
| "Scalable storage for large-scale processing" if it invites a throughput question | 4 | **No benchmark has ever been run.** Keep the qualitative claim, never attach a number |

---

## 8. CONTENT TO REWRITE

**Slide 2 — opening paragraph.** *Current:* 45 words.
> **Replace with:** "VidForge turns proprietary DVR/NVR storage into standardized, provenance-carrying
> forensic evidence — including footage the recorder can no longer see."

**Slide 2 — OEM Detection block.** *Current:* "Identify and parse proprietary DVR/NVR formats in
parallel across 8 OEMs."
> **Replace with:** "**OEM DETECTION & PARSING** — 6 detectors, profile-driven and deterministic.
> Three full filesystem parsers: HIKBTREE (Hikvision), DHFS (Dahua), UNIVIEW_FS (Uniview)."

**Slide 2 — Evidence Ingestion block.** *Current:* mentions MD5.
> **Replace with:** "**EVIDENCE INGESTION** — read-only at the type level: the evidence reader
> exposes no write method. SHA-256 at ingest, custody event recorded, absolute physical offsets
> preserved end to end."

**Slide 2 — merged UNIQUENESS list** (replacing two overlapping panels):
> 1. **One parser contract, every OEM.** A new recorder needs a parser — not a new recovery engine.
> 2. **Capability-driven recovery.** What the parser established *on this disk* decides which
>    strategies are licensed. Refused strategies are reported with their reason.
> 3. **Evidence-bounded classification.** `Deleted` requires a free marker. `Orphaned` requires an
>    authoritative index. Absence is never promoted to deletion.
> 4. **Fragment reconstruction without guessing.** Grouped and ordered from recorder evidence only;
>    physical adjacency is never used.
> 5. **Deterministic and provenance-complete.** Same bytes → same decisions, same ids, traceable to
>    the exact source range.

**Slide 3 — L-levels.** *Current:* "L1: Indexed Recovery / L2: Orphan / Slack Recovery / L3: Raw Carving".
> **Replace with:**
> "**L1 — Indexed.** An authoritative index claims these bytes. → `Active`, or `Deleted` with a free marker.
> **L2 — Unreferenced / unclaimed-in-scope.** Surviving metadata describes them, or an authoritative index governs them without claiming them. → `Orphaned`.
> **L3 — No index evidence.** No authoritative statement covers these bytes. → `Unindexed`.
> The level is a *consequence of the evidence*, not an escalation of effort. **L1 reads the fewest bytes.**"

*(That last sentence is worth a slide on its own. It is the clearest single proof that the team
understood the problem rather than reaching for a carver.)*

**Slide 3 — OpenCV row.**
> **Replace with:** "**Frame processing** — pure-Rust backend, 26 tests. Optional OpenCV backend,
> selectable per run; the pipeline reports which backend ran, by name and version, and fails rather
> than substituting."

*(Every word of that is true, and it is a more impressive claim than "OpenCV".)*

**Slide 3 — AI terminal box.**
> **Replace with:** "**ANALYSIS BOUNDARY** — standardized frames + provenance handed to a pluggable
> engine. With no engine registered the pipeline reports `AI_ANALYSIS_NOT_CONFIGURED` and produces
> zero findings. *Detector integration: planned.*"

*(Showing the literal constant is the move. It proves the team built the boundary and refused to
fake what sits behind it.)*

**Slide 4 — Forensic Safe Processing.** *Current:* "Read-only access + hash verification".
> **Replace with (after building §15 item 2):** "Read-only at the type level — the evidence reader
> exposes no write method. SHA-256 recomputed and compared against the acquisition record."
> **Until then:** "Read-only at the type level. SHA-256 recorded at ingest with a custody event."

**Slide 5 — differentiator 4.** *Current:* "Forensically Explainable — traces recovered footage to source locations and validation evidence."
> **Replace with:** "**Every artifact answers, without a score:** which bytes · which evidence item ·
> which parser and profile version · which strategy · which checks passed, failed, or **did not
> run**. Unrun checks are `UNKNOWN` — never `PASS`."

**Slide 6 — research bullets.** *Current:* "Studied DVR/NVR forensic investigation workflows".
> **Replace with named work.** E.g. "NIST SP 800-86 (forensic techniques into incident response) ·
> NIST SP 800-101r1 (integrity and validation practice) · published reverse-engineering of the
> HIKBTREE and DHFS on-disk structures · DFRWS work on fragmented-video carving and file-fragment
> classification · ISO/IEC 14496-12 for container framing."
> **Verify each citation before printing it.** A wrong citation is worse than none.

---

## 9. TECHNICAL DIFFERENTIATORS

**Current verdict: the deck reads as "another video recovery tool."** The words that dominate it —
*recovery*, *AI*, *timeline*, *multi-camera*, *modular* — are the words every DVR-recovery project
uses. Nothing on slides 2, 4 or 5 could not be written by a team with a signature carver and a
YOLO import.

The project's actual moat is **evidential discipline**: it is architecturally incapable of
producing a conclusion it cannot justify. That is invisible in the current deck. These are the
differentiators that are **real, testable, and deserve visual emphasis**, ranked by how hard they
are to fake:

| Rank | Differentiator | Evidence | Where to put it |
|---|---|---|---|
| **1** | **Capability assessment is runtime, not declared.** 10 dimensions derived from what the parser returned *on this disk*. A damaged index correctly yields no orphan findings — the engine working, not failing | `recovery::capabilities::assess_capabilities`; explicitly distinguished from `CapabilityStages` | Slide 3, as a labelled band in the new architecture diagram |
| **2** | **Strategies are licensed or refused, always with a reason, always reported** | 6 strategies, each with a reason string, in every output | Slide 5, top-left, verbatim quote |
| **3** | **Absence is never promoted to deletion.** `Deleted` requires `AllocationEvidence::FreeMarked` | `UNIVERSAL_RECOVERY_VERIFICATION.md` §5 | Slide 2, 3-line evidential-rule box |
| **4** | **One parser contract, contract-tested — including against a deliberately broken parser** | `parsers-core/src/contract.rs`, test 4b | Slide 3, the OEM→Universal diagram |
| **5** | **Physical adjacency is never used to group or order** | `RECOVERY_ENGINE_AUDIT.md` §5, last row | Slide 5, one line |
| **6** | **Unrun checks are UNKNOWN, never PASS. A bounded run is REVIEW, never PASS** | `FrameValidationReport`; `RecoveryRun::finalize` | Slide 5 |
| **7** | **Determinism is a tested property**, with a key that excludes environment metadata | determinism suite, 3 tests | Slide 4, evidence panel |
| **8** | **Adding an OEM requires a parser, not a new recovery algorithm** — because strategies read capabilities, not names. A parser that establishes nothing still reaches the raw tier | `UNIVERSAL_RECOVERY_ARCHITECTURE.md` §9 | Slide 4 or 5, as diagram §11-D |
| **9** | **Read-only at the type level** — not by policy, by the absence of a method | `EvidenceReader` trait | Slide 2 |
| **10** | **Provenance without a score.** Eight separate questions answered separately, never collapsed into one number | 13-field `Provenance` | Slide 5 |

**Do not claim as differentiators** (every competing team will also claim them, and two are untrue):
"modular architecture", "proven tech stack", "AI analytics", "faster investigation", "multi-camera
sync", "unified schema" *as a phrase* (the underlying contract is a differentiator; the buzzword is not).

---

## 10. DIAGRAM AUDIT

### D1 — Slide 2, Data-Flow Diagram

- **Technically correct?** **Yes — remarkably so.** Every node maps to a `PipelineStage` variant.
  This is the most accurate diagram in the deck.
- **Understandable in 10–15s?** **No.** ~22 boxes at ~8pt in one-third of the slide width.
- **Missing layer?** The capability-assessment step between parsing and recovery — the project's #1
  differentiator is absent from its own flow chart.
- **Redundant?** Yes — with D2 on slide 3, which draws the same pipeline again with more boxes.
- **Verdict: KEEP — MODIFY (enlarge, simplify, and make it the only pipeline diagram in the deck).**

**Exact changes:**
1. Widen to ~45% of slide width (take it from the paragraph you are deleting).
2. Reduce the OEM logo strip from 8 to 6; retier or grey Matrix and Godrej.
3. **Add one box** between *Extract Evidence Items* and the recovery branch: **`CAPABILITY ASSESSMENT
   — what this disk supported`**.
4. Remove the *Report to Analyst* box top-right — it duplicates the *Analyst intervention* path and
   adds two crossing arrows.
5. Collapse *Preliminary Timeline → Gaps? → Deletion Recovery Engine → Final Timeline* into a single
   labelled loop: **`Timeline → gaps? → Recovery → Timeline`**, one back-arrow.
6. Colour-code by status, with a legend: **solid = implemented · outline = planned**. `AI Analytics`
   becomes the only outlined box. This single change makes the deck self-honest at a glance.
7. Increase minimum text size to 10pt; if it does not fit, you have too many boxes.

### D2 — Slide 3, Architecture Diagram

- **Technically correct?** Mostly, but it **contradicts slide 2 in shape** while describing the same
  flow, and its terminal box (AI analytics with face/object detection) is unsupported.
- **Understandable in 10–15s?** **No — this is the worst readability failure in the deck.** 34+
  boxes, ~7pt text, arrows crossing in four directions, three separate decision diamonds.
- **Redundant?** **Yes, heavily** — ~70% overlap with D1.
- **Verdict: REPLACE.**

Replace with the **layered OEM→Universal diagram (§11-A)**. Rationale: slide 2 already owns the
*flow*. Slide 3 should own the *layering* — which is the thing the flow cannot show and which is the
actual architectural claim. Two diagrams, two jobs, zero duplication.

### D3 — Slide 6, Evidence Reader

- **Technically correct?** Yes, and irrelevant. `TRYREAD()`, `System OS API`, `Sector (Raw Bytes)`
  are internal implementation detail.
- **Understandable?** Structurally yes; *valuable* no.
- **Verdict: REPLACE** with the Recovery Depth diagram (§11-E).

If the team insists on keeping an acquisition visual, reduce it to four boxes —
`Physical disk · Raw image · E01/EWF` → `EvidenceReader (read-only: no write method exists)` →
`Bounded, offset-preserving reads` → `SHA-256 + custody event` — and label it **Acquisition**, not
*Evidence Reader*. That version earns its space; the current one does not.

### D4 — Slide 6, Recovery Engine

- **Technically correct?** Yes. `Gaps Recovery → L1/L2 metadata-guided | L3 raw scan → fragment
  validation → fragment DB → stream/camera association → reconstruction → timeline → video
  validation → recovered evidence` matches the implementation.
- **Understandable in 10–15s?** Yes — it is linear and ~12 boxes. **This is the best-constructed
  diagram in the deck.**
- **Verdict: KEEP — minor MODIFY.** Add the classification outputs at the *Recovery evidence*
  terminal: `Active · Deleted · Orphaned · Unindexed · Corrupted`. That one addition converts it
  from "a recovery flow" into "a *classification* flow", which is the distinctive claim.

---

## 11. DIAGRAMS TO ADD

### A. OEM → Universal Architecture — **HIGHEST VALUE. Slide 3, replacing D2.**

```
  Hikvision   Dahua    Uniview   │  CP-Plus UBS  Honeywell  TP-Link  │  Matrix  Godrej
  HIKBTREE    DHFS     UNIVIEW_FS│      detection + profile only     │ profile declared
  ───────────────────────────────┴───────────────────────────────────┴────────────────
                                  ↓  OEM-SPECIFIC PARSERS
  ══════════════════════════════════════════════════════════════════════════════════
              STANDARDIZED PARSER CONTRACT    one trait · contract-tested · Ok(None) is valid
  ══════════════════════════════════════════════════════════════════════════════════
                                  ↓
     CAPABILITY ASSESSMENT     10 dimensions · derived from THIS disk, not declared
                                  ↓
     STRATEGY SELECTION        6 strategies · each licensed or refused, with a reason
                                  ↓
     UNIVERSAL RECOVERY ENGINE     no OEM name appears in this layer outside tests
                                  ↓
     VALIDATION  →  CORRELATION  →  PROVENANCE  →  FORENSIC ARTIFACTS
```

**Why this is the most valuable addition in the audit.** It is the only diagram that shows the
*claim*: everything above the double line is per-OEM, everything below is shared, and the double
line is enforced by a test. Evaluators assessing scalability need exactly this and nothing else.
It also solves the "8 OEMs" problem visually and honestly — all eight names stay on screen, tiered.

**Visual hierarchy:** the double line is the heaviest element on the slide. The three tiers of OEM
boxes are visibly different weights. "no OEM name appears in this layer outside tests" is a caption,
not a box.

### B. Recovery Decision Flow — **Slide 5 or as a build of D1. Accurate to the implementation.**

```
                    Evidence region
                          │
        ┌─── Is there an authoritative index claim on these bytes? ───┐
       YES                                                            NO
        │                                                             │
  ┌─ free marker? ─┐                          ┌─ Does an authoritative index GOVERN
 YES              NO                          │  these bytes without claiming them? ─┐
  │                │                         YES                                    NO
DELETED          ACTIVE                       │                                      │
                                          ORPHANED                          raw candidate scan
                                                                                     │
                                                                          ┌── validates? ──┐
                                                                         YES              NO
                                                                          │                │
                                                                     UNINDEXED        CORRUPTED
```

**Why:** it answers "how do you know it was deleted?" in one image, and it visibly shows that there
is **no arrow from "not in the index" to DELETED** — which is the forensic point. Only use this
exact shape; it matches `classification.rs` and `claims.rs`. Do not add a "probably deleted" branch.

### C. End-to-End Pipeline with implemented/planned distinction

Only build this if you drop D1 or D2 entirely — otherwise it is a third drawing of one pipeline.
If built: solid boxes for `Intake → Detection → Confidence → Gate → Parse → Capability → Recovery →
Validation → Correlation → Media reconstruction → Timeline → Report/Custody`, one outlined box for
`Analysis boundary (planned)`. **Recommendation: skip it.** D1 with the status legend (§10, change 6)
already does this job in a slot you already own.

### D. OEM Expansion Model — **Slide 4 or 5. Strong, cheap, high-clarity.**

Two columns, side by side:

```
   CONVENTIONAL                          VIDFORGE
   ────────────                          ────────
   new OEM → new detector                new OEM → new parser
           → new filesystem logic                → (implements the existing contract)
           → new recovery heuristic
           → new fragmentation rules      everything below is UNCHANGED:
           → new validation                 capability assessment
           → new reconstruction             strategy selection
           → new report path                recovery · validation · correlation
                                            provenance · reporting
   ~6 integration points                  1 integration point
```

**Why:** it makes scalability *arithmetic* instead of adjectival. Add the killer caption: **"A parser
that establishes nothing still works — it reaches the raw-recovery tier. Every capability it later
gains upgrades it automatically, because strategy selection reads capabilities, not names."**

### E. Recovery Depth — **Slide 6, replacing D3.**

```
  L1  INDEXED            authoritative index claims these bytes    →  Active · Deleted
      ▓░░░  reads the FEWEST bytes

  L2  UNREFERENCED /     surviving metadata, or a governed-but-    →  Orphaned
      UNCLAIMED-IN-SCOPE unclaimed gap
      ▓▓░░

  L3  NO INDEX EVIDENCE  no authoritative statement covers them    →  Unindexed · Corrupted
      ▓▓▓▓  reads the MOST bytes

  ── The level is licensed by the strength of the index evidence, not by effort.
     A bounded run is reported as REVIEW — never PASS.
```

**Why:** the deck says "L1→L2→L3" five times across four slides and never explains what distinguishes
them. This explains it once, correctly, and the "L1 reads the fewest bytes" inversion is a strong
signal of genuine understanding. **Use only four levels if you add a fourth — do not invent an "L4
AI" tier.**

---

## 12. DESIGN SYSTEM RECOMMENDATION

**Current state:** cream `#FDF6E3`-ish background, mustard-yellow panel headers, black serif
(Times/Cambria) throughout, 1px black rules, no accent, no status colour. It reads as an academic
handout, not a cybersecurity submission. It is *legible*, which is more than many decks manage —
but it has **zero visual hierarchy**: every panel header is identical, so nothing is emphasised, so
the evaluator's eye has no entry point.

### Palette

| Role | Colour | Use |
|---|---|---|
| Primary | **`#0B2545`** deep navy | Slide titles, panel headers, diagram spine, the double line in §11-A |
| Secondary | **`#134074`** mid blue | Sub-headers, box outlines, secondary flow arrows |
| Accent | **`#C9A227`** restrained gold | *One* emphasis per slide only — the differentiator, the evidence number. Keeps a visual thread to the existing yellow without the highlighter effect |
| Background | **`#FFFFFF`** or **`#F7F9FC`** | Replace the cream — it reads as a photocopy when projected |
| Body text | **`#1A1A1A`** | Never pure black on white at small sizes |
| Muted / planned | **`#6B7A8F`** | **Planned/unimplemented elements. This colour is the honesty mechanism** — an outlined `#6B7A8F` box is instantly readable as "not yet" |
| Verified / pass | **`#2E7D32`** | Test counts, PASS states, the verified OEM tier |
| Review / caution | **`#B8860B`** | REVIEW states, partial tiers |
| Fail / absent | **`#B3261E`** | Use sparingly; mostly for a FAIL state in a screenshot |

Avoid neon-on-black "cyberpunk". NTRO/government evaluation rewards restraint. Navy + white + one
gold accent reads as *defence-sector technical*, which is exactly the register you want.

### Typography

| Role | Font | Size (on a 13.33×7.5in slide) |
|---|---|---|
| Slide title | **Inter SemiBold** or Segoe UI Semibold | 32–36pt |
| Panel header | Inter SemiBold, letter-spaced, uppercase | 16–18pt |
| Body / bullets | **Inter Regular** | **14pt minimum — never below 12pt** |
| Diagram box labels | Inter Medium | **11pt minimum** |
| Code / constants (`AI_ANALYSIS_NOT_CONFIGURED`, `Ok(None)`) | **JetBrains Mono** or Consolas | 10–11pt |
| Captions / limitations | Inter Regular Italic | 11pt |

Drop the serif. Times at 8pt inside a diagram box is the single biggest readability cost in the
current deck. A monospace face for constants and type names is worth adding: it visually separates
*the product's own vocabulary* from *marketing prose*, and that separation is itself a credibility
signal.

### Layout

- **Margins:** 0.4in outer, uniform. Currently the panels run edge-to-edge, which creates the
  "wall of boxes" impression.
- **Grid:** 12-column. Slide 2 → 4/5/3 (solution / DFD / uniqueness). Slide 3 → 3/9 (stack rail /
  architecture). Slide 4 → 4/4/4 top, 6/6 bottom. Slide 5 → 6/6 over 12.
- **Gutter:** 0.2in between panels. Non-negotiable — the current 1px shared borders are why it reads
  as a table rather than as cards.
- **Whitespace:** target **≤ 60% ink coverage per slide**. Slides 3 and 4 are currently ~85%.
- **Cards:** 4px radius, 1px `#134074` border, no fill, header bar in `#0B2545` with white text.
  Drop the mustard fill entirely.
- **Diagram placement:** one diagram per slide, ≥ 40% of the slide area, never below 11pt text.

### Visual hierarchy — what the eye should hit

| Order | Slide 2 | Slide 3 | Slide 4 | Slide 5 |
|---|---|---|---|---|
| 1st | The DFD | The double line separating OEM from Universal | The evidence numbers (77k / 1,162 / 481) | "Strategies are refused with reasons" |
| 2nd | The 5 uniqueness items | The three OEM maturity tiers | Challenges → Solution table | The evidential-rule box |
| 3rd | The one-line description | The tech-stack rail | The merged viability list | Impact bullets |

### Component design

| Component | Verdict |
|---|---|
| **Cards** | Keep, restyle (above) |
| **Badges** | **Add** — small pill labels `IMPLEMENTED` / `TESTED` / `PLANNED` on diagram boxes and OEM tiers. Highest information-per-pixel addition available |
| **Icons** | Keep the six tech-stack logos. **Remove the three clip-art pointing hands** — they are the least professional element in the deck |
| **Tables** | Keep. The Challenges→Solution table is the clearest artifact you have. Add a second: the OEM maturity tier |
| **Timelines** | Not needed. You have no schedule to show and the mandated template has no slot for one |
| **Architecture blocks** | Uniform width within a tier, varying only between tiers. Currently widths vary arbitrarily, which implies significance that isn't there |
| **Arrows** | Single weight, single colour (`#134074`), **no crossing arrows**. D1 and D2 both have crossings; every one is removable by reordering boxes |
| **Screenshots** | **Add** (see §14). Thin `#6B7A8F` 1px border, no drop shadow, no browser chrome, no laptop mockup |
| **Metrics** | **Add** — four numbers in `#0B2545` at 28pt with 11pt labels under them. This is the cheapest credibility-per-pixel element in the entire deck |
| **Decorative elements** | None. No gradients, no glow, no circuit-board background, no padlock clip art |

---

## 13. SCREENING / EVALUATOR ASSESSMENT

### First 30 seconds (title + a glance at slide 2)

*Understood:* multi-vendor DVR forensics; 8 vendors; recovery; AI; hashing; timelines.
*Impression:* **"Standard PS restatement with an AI bullet."** The slide-2 paragraph is skipped. The
DFD is noticed as dense and not read. The eight logos are the strongest visual and they are the
least true thing on the slide.
**Verdict: the first 30 seconds currently work against the project.**

### First 2 minutes (slides 2–4)

*Understood:* there is a real pipeline; there are gates and an analyst loop; there is tiered
recovery; the tech stack is credible; the Challenges→Solution table is clear and lands well.
*Not understood:* what makes this different from a signature carver; whether any of it runs; how
much is built vs. designed.
*First doubts form here:* the slide-3 diagram is unreadable, so an evaluator cannot verify the
architecture claims and falls back on impressions. PyTorch/ONNX in the stack sets an expectation
that nothing later satisfies.

### End of deck

*Remembered:* "DVR recovery, many vendors, L1-L2-L3, AI, timelines." That is the memory of a generic
project.
*Not remembered (because never shown):* 77k lines · 1,162 tests · a reproducible verification runner
· a contract-tested parser abstraction · strategy refusal with reasons · a deliberate refusal to
fabricate.

### Confusion points

1. Slide 2's DFD and slide 3's architecture diagram describe the same pipeline in different shapes —
   an evaluator spends attention reconciling them instead of absorbing either.
2. "L1/L2/L3" appears five times and is never defined.
3. "Unified parser" appears in both diagrams as a fallback with no explanation of what it does.
4. "PROTOTYPE" and "VIDEO" are hyperlinks behind clip art — an evaluator reading a printout or PDF
   has no idea whether anything was built.

### Unanswered questions an evaluator will have

- *Does it run?* Nothing in the deck answers this.
- *On what evidence was it validated?* Nothing. (Answer exists and is good: synthetic fixtures from
  real structure layouts — and saying so is an asset.)
- *How much of this is built?* Nothing.
- *What is actually novel here?* The deck's answer is "AI + modular", which is not novel.
- *How do you distinguish deleted from never-indexed?* The project has an excellent answer. The deck
  never raises the question.

### Credibility gaps, ordered by damage

1. **AI claimed four times, implemented zero times.** If probed, the honest answer contradicts four
   separate slides. **This is the one that can lose the submission.**
2. **"8 OEMs"** when 2 have a file named `NOT_IMPLEMENTED.md`. Trivially checkable if the repo is
   shared.
3. **MD5** — one word, zero code.
4. **Zero product pixels.** Three cartoon hands where screenshots should be.
5. **"Link"** as the entirety of the references on the slide titled *Research and References*.

### Strongest slides · weakest slides

- **Strongest:** Slide 4, specifically the Challenges→Solution table. Clear, well-structured, true.
- **Second:** Slide 6's Recovery Engine column — the clearest diagram in the deck.
- **Weakest:** Slide 3. Its diagram is unreadable, its stack contains two unsupported entries, and
  its prototype evidence is clip art.
- **Second weakest:** Slide 5 — four panels of interchangeable prose that bury the deck's single
  best panel in the bottom-right corner.

### "What would make this evaluator believe this is a working engineering system?"

Five concrete changes, in order of effect per unit of work:

1. **Put four numbers on slide 4 in 28pt:** `77,012 lines · 14 crates · 1,162 tests · 481 green`.
   Nothing else in the deck converts "concept" to "system" this cheaply.
2. **Show the verification artifact.** A cropped screenshot of
   `UNIVERSAL_RECOVERY_VERIFICATION_RESULT.md` — the stage table with PASS rows, **including the
   SKIP rows with their stated reasons**. The SKIPs are what make it believable; a table of 28 green
   rows looks generated, a table with 2 honest SKIPs looks *real*.
3. **One product screenshot** (§14) — the Recovery view with classified candidates and offsets.
4. **Delete every AI claim** and replace the terminal box with the literal
   `AI_ANALYSIS_NOT_CONFIGURED` constant. A team that ships a boundary and refuses to fake what sits
   behind it reads as *more* competent, not less. This is counter-intuitive and it is correct.
5. **Add the limitation line.** *"Validated against synthetic images generated from real OEM
   structure layouts; real-image validation is the next milestone."* Volunteered limitations are the
   strongest credibility signal available in a hackathon deck, because almost nobody does it.

---

## 14. DEMONSTRATION RECOMMENDATIONS

**Rank order of demonstrable value** (what actually moves an evaluator):

1. Recovered/classified candidates with absolute offsets and classification states — *the product's
   core claim*.
2. The verification result table — *proof that it runs and that failures are reported*.
3. OEM detection with confidence scores and the analyst gate — *proof the front of the pipeline works*.
4. A recovered video actually playing — *the emotional proof; nothing else substitutes*.
5. Provenance / chain of custody for one artifact — *the forensic proof*.
6. Hex viewer over the parsed structure region — *proof it is bit-level, not file-level*.

### Screenshots to produce, exactly specified

**S1 — Recovery view (slide 3, replacing a clip-art hand). Highest priority.**
- *Screen:* `RecoveryView.tsx` after a run on a synthetic Hikvision or Dahua image.
- *Must be visible:* the candidate list with, per row — classification (`Active` / `Deleted` /
  `Orphaned` / `Unindexed`), absolute byte offset, size, channel, recorder timestamp, recovery level.
  At least one row of **each** of `Active`, `Deleted`, `Orphaned`, `Unindexed`. At least one
  `UNKNOWN` field rendered as `UNKNOWN`.
- *Highlight:* a thin gold box around one `Deleted` row + a one-line caption — *"Deleted requires an
  explicit free marker in the OEM structures. Absence from the index is never enough."*
- *Must NOT be visible:* any AI panel, any empty state, any placeholder text, any `test_` string, any
  local file path with a user name.

**S2 — Verification result (slide 4). Second priority.**
- *Screen:* `UNIVERSAL_RECOVERY_VERIFICATION_RESULT.md` rendered, or the console tail of the runner.
- *Must be visible:* the `Test counts` block, ~8–10 stage rows including **at least one SKIP with its
  reason**, and the "Every fixture is synthetic" reviewer note.
- *Highlight:* the test-count block.
- *Must NOT be visible:* the full 28-row table (too dense), the FAIL row unless the accompanying
  caption explains it is a pre-existing unrelated `mmap` test — if you cannot fit that caption,
  crop it out rather than explain it badly.

**S3 — Detection + confidence (slide 2, optional).**
- *Screen:* `DetectionView.tsx`.
- *Must be visible:* the detected OEM, the confidence score, the contributing evidence items
  (headers/signatures/structures), and the threshold gate outcome.
- *Must NOT be visible:* any OEM shown as detected that has no parser.

**S4 — Custody / provenance (slide 5, optional).**
- *Screen:* `CustodyView.tsx` or a provenance panel.
- *Must be visible:* SHA-256, custody events in order with timestamps, source region chain
  (evidence id → region → fragment), parser and profile version + hash.
- *Must NOT be visible:* the string `"Ingest hash verified"` until §15 item 2 is actually
  implemented. **Showing that string before the re-verification exists would be presenting a defect
  as a feature — do not do it.**

**S5 — Recovered video playing (for the live demo / video link, not the deck).**
- The single most persuasive artifact available. Requires FFmpeg on the demo machine (§20, task 1).

### Hard rules for every screenshot

- Real output from a real run. **Never mock up a screen.** If a screen cannot be produced, drop the
  slot — an empty slot costs far less than a fabricated one.
- No user names, absolute paths, IDE windows, terminal prompts with machine names, or window chrome.
- Crop tight, 1px `#6B7A8F` border, no shadow, no device mockup.
- If a value is `UNKNOWN`, **leave it visible.** It is evidence of the honesty discipline, not a flaw.

---

## 15. CONTENT / CLAIMS THAT MUST NOT APPEAR

### Must be removed — unsupported and not buildable in time

| Claim | Label |
|---|---|
| Face detection, object detection, motion detection, event detection as shipped capability | `[REMOVE CLAIM]` |
| "PyTorch", "ONNX Runtime" anywhere in the deck | `[REMOVE CLAIM]` |
| "AI-Based Forensic Analytics" as a stack component | `[REMOVE CLAIM]` |
| "AI & Multi-Camera Analysis" as a feasibility item | `[REMOVE CLAIM]` |
| "8 OEMs" with equal implied support | `[REMOVE CLAIM]` → 6 detectors / 3 full parsers, tiered |
| OpenCV presented as a verified, shipped component | Retier — the feature exists, has never been compiled |
| "Clock drift correction" | `[REMOVE CLAIM]` — normalization is real, correction is not verified |

### Must not be added — would weaken or falsify

- **Any performance number.** No benchmark has ever been run. "Processes X TB/hour", "2× faster",
  "<N minutes" — all fabrication. The prior audit records 6 HIGH-severity performance defects; a
  throughput claim invites exactly the question you cannot answer.
- **Any accuracy or recovery-rate percentage.** "94% recovery rate" would be invented. No ground-truth
  corpus exists.
- **Any claim of real-DVR validation.** Zero real images exist in the repository.
- **Raw source code.** One constant (`AI_ANALYSIS_NOT_CONFIGURED`) or one type name in monospace is
  a design element; a code block is not.
- **Test logs as walls of text.** The stage *table* is the artifact; the console output is not.
- **Fabricated hashes or fabricated evidence screenshots.**
- **Vendor logos for Matrix and Godrej at the same visual weight** as implemented OEMs.
- **Generic stock imagery** — CCTV cameras, padlocks, hooded figures, binary rain, circuit boards.
- **A business model / revenue / market-size slide.** See §18.
- **Comparison tables naming commercial forensic products** (DVR Examiner, Amped, Magnet) with
  claimed feature parity. You have not benchmarked against them. Compare against *the generic
  approach* — "signature carving" vs "index-evidence-driven recovery" — not against named products.
- **The `evidence-reader` internal call graph** (`TRYREAD()`, `System OS API`).

---

## 16. MUST CHANGE BEFORE SUBMISSION

| # | Change | Slide | Effort |
|---|---|---|---|
| 1 | **Delete all four AI capability claims**; replace the terminal architecture box with the analysis *boundary* + `AI_ANALYSIS_NOT_CONFIGURED`, marked planned | 2, 3, 4 | 30 min |
| 2 | **Remove Python/PyTorch/ONNX from the tech stack** | 3 | 10 min |
| 3 | **"8 OEMs" → the three-tier OEM maturity chart** (§6 item 1) | 2, 3 | 45 min |
| 4 | **Remove "MD5"** (or implement it — §17 item 1) | 2 | 2 min |
| 5 | **Retier OpenCV** to "optional backend; pure-Rust backend is the tested default" | 3 | 15 min |
| 6 | **Replace the 34-box slide-3 diagram** with the layered OEM→Universal diagram (§11-A) | 3 | 2–3 h |
| 7 | **Add the evidence panel** — 77,012 / 14 / 1,162 / 481 + "one command reproduces every result" | 4 | 45 min |
| 8 | **Add the limitation line** — "validated against synthetic images built from real OEM structure layouts" | 4 or 6 | 5 min |
| 9 | **Add ≥1 real screenshot** (S1 preferred) replacing a clip-art hand | 3 | 1 h *after* the API builds |
| 10 | **Replace "Link" with 3–5 named, verified references** | 6 | 1 h |
| 11 | **Fix the L1/L2/L3 wording** — levels are licensed by evidence, not effort; "Orphan/Slack" → "Unreferenced / unclaimed-in-scope" | 3, 4, 5 | 30 min |
| 12 | **Dedupe** UNIQUENESS ↔ HOW IT ADDRESSES (slide 2) and VIABILITY ↔ TECHNICAL FEASIBILITY (slide 4) | 2, 4 | 45 min |

**Total: roughly one focused day**, plus item 9 which is gated on the API building.

## 17. SHOULD CHANGE IF TIME PERMITS

| # | Change | Effort |
|---|---|---|
| 1 | **Implement MD5 alongside SHA-256** so the claim becomes true. `HashAlgorithm` is a single-variant enum; adding a variant and a second streaming digest is genuinely small, and dual-hashing is standard forensic practice examiners expect. `[BUILD-BEFORE-SUBMISSION]` | ~2 h |
| 2 | **Implement evidence-hash re-verification** and fix the `"Ingest hash verified"` string so it describes what happened. Closes the one outright falsehood *in the product*. `[BUILD-BEFORE-SUBMISSION]` | ~3 h |
| 3 | Add the **OEM Expansion Model diagram** (§11-D) to slide 4 or 5 | 1.5 h |
| 4 | Add the **Recovery Decision Flow** (§11-B) to slide 5 | 1.5 h |
| 5 | Add the **Recovery Depth diagram** (§11-E) to slide 6, replacing the Evidence Reader | 1.5 h |
| 6 | **Promote TECHNICAL DIFFERENTIATORS to the top of slide 5**; collapse the three benefit panels into one | 1 h |
| 7 | Add the **evidential-rule box** (Active/Deleted/Orphaned requirements) to slide 2 | 30 min |
| 8 | Add **screenshot S2** (verification result) to slide 4 | 45 min |
| 9 | Apply the **navy/gold palette and Inter typography** throughout | 3–4 h |
| 10 | Add **status badges** (`IMPLEMENTED` / `TESTED` / `PLANNED`) to diagram boxes | 1 h |

## 18. OPTIONAL POLISH

| # | Change |
|---|---|
| 1 | One-line capability statement under the title on slide 1 |
| 2 | Increase all diagram text to ≥11pt; eliminate every crossing arrow |
| 3 | Uniform 0.2in gutters; drop ink coverage to ≤60% on slides 3 and 4 |
| 4 | Monospace face for type names and constants |
| 5 | QR code to the verification document on slide 6 |
| 6 | Replace the mustard header fill with navy bars + white text |
| 7 | Consistent box widths within each architecture tier |
| 8 | Remove all three clip-art hands (keep the links as text) |
| 9 | Add classification outputs to the terminal box of slide 6's Recovery Engine diagram |
| 10 | Fix the two spelling errors in panel headers: "ARCHITECTIURE" (slide 3), "SCALIBILITY" / "FEASIBILTY" (slide 4). **Do this even if you do nothing else in this list** — three typos in mandatory panel headings is a gratuitous, free-to-fix credibility cost |

---

## 19. FINAL SLIDE-BY-SLIDE STRUCTURE

*(Six slides, mandated order, optimised within each.)*

### Slide 1 — Title
- **Objective:** identification + one line that makes an evaluator want slide 2.
- **Content:** PS ID 26150 · full PS title · Theme · Category · Team ID 137599 · TakeUForward ·
  **one added line:** *"VidForge — recovering deleted surveillance footage from proprietary DVR
  filesystems, with provenance."*
- **Visual:** SIH logo, team logo, navy rule. Nothing else.
- **Remove:** nothing.
- **Density:** very low (intentional).

### Slide 2 — Idea / Proposed Solution
- **Objective:** what it is, how the flow works, why it is different. **The DFD is the hero.**
- **Content (6 items max):**
  1. One-sentence description (12 words).
  2. **Evidence ingestion** — read-only at the type level; SHA-256; custody event; offsets preserved.
  3. **OEM detection & parsing** — 6 detectors; 3 full filesystem parsers (HIKBTREE, DHFS, UNIVIEW_FS).
  4. **Confidence + analyst gate** — uncertain attribution halts the pipeline for a human.
  5. **Capability-driven recovery** — what the parser established on *this* disk licenses the strategies.
  6. **Evidential rules box** — Active ⟸ index claim · Deleted ⟸ free marker · Orphaned ⟸ authoritative index.
- **Visual:** the DFD at ~45% width, 6 logos in 3 maturity tiers, solid = implemented / outlined =
  planned, legend present, capability-assessment box added.
- **Remove:** the 45-word paragraph; the duplicated uniqueness/how-it-addresses lists (merge to one
  5-item list); "8 OEMs"; "MD5"; the AI bullet.
- **Density:** medium-high (this slide earns it).

### Slide 3 — Technical Approach
- **Objective:** *why this scales across OEMs.* **The layering is the hero, not the flow.**
- **Content:**
  1. Tech stack, 4 rows: Rust/Tokio/Rayon · Tauri 2 + React/TS · SQLite · FFmpeg (+ optional OpenCV
     backend, pure-Rust default).
  2. The layered OEM→Universal diagram (§11-A).
  3. Caption: *"No OEM name appears in the recovery layer outside tests."*
  4. Caption: *"A new recorder needs a parser — not a new recovery engine."*
  5. One screenshot (S1).
- **Visual:** 3/9 split — thin stack rail, large diagram.
- **Remove:** the 34-box diagram; Python/PyTorch/ONNX; two clip-art hands; OpenCV as a shipped claim.
- **Density:** medium. This slide is currently the densest and must become one of the lightest.

### Slide 4 — Feasibility & Viability
- **Objective:** *it is built, it is validated, and here is what is hard about it.*
- **Content:**
  1. **EVIDENCE OF IMPLEMENTATION** — 77,012 lines · 14 crates · 1,162 tests · 481 green · one
     command reproduces everything and exits non-zero on failure.
  2. Challenges → Solution table (keep as-is, moved up).
  3. Merged **Feasibility & Viability** panel, 4 deduped items: proven stack · one parser contract ·
     evidence-licensed recovery tiers · determinism + provenance.
  4. **Scalability:** adding an OEM = one parser; capability assessment and strategy selection
     unchanged.
  5. Limitation line: *"Validated against synthetic images generated from real OEM structure layouts;
     real-image validation is the next milestone."*
  6. Screenshot S2 (verification table).
- **Visual:** four large metric numbers; the Challenges→Solution table; optionally the OEM Expansion
  Model (§11-D).
- **Remove:** the VIABILITY / TECHNICAL FEASIBILITY duplication (one panel of the two); the AI item.
- **Density:** medium — currently ~85% ink, target ≤60%.

### Slide 5 — Impact & Benefits
- **Objective:** *why this is not another carver.* Differentiators lead.
- **Content:**
  1. **Strategies are licensed or refused — always with a reason, always in the report.** Verbatim
     example quote.
  2. **Absence is never promoted to deletion.**
  3. **Physical adjacency is never used to group or order fragments.**
  4. **Unrun checks are UNKNOWN, never PASS. A bounded run is REVIEW, never PASS.**
  5. **Investigative impact** — cross-vendor evidence through one workflow; recovers footage the
     recorder can no longer see; reduces manual proprietary-format analysis; auditable output.
  6. **Vision** — one forensic representation across recorders; new OEMs via parsers only.
- **Visual:** differentiators as four cards across the top half; the Recovery Decision Flow (§11-B)
  bottom-left; impact + vision as a compact right column.
- **Remove:** three interchangeable benefit panels → one; the AI reference; "faster" and "reduced
  effort" as separate bullets.
- **Density:** medium.

### Slide 6 — Research & References
- **Objective:** *this is grounded in published forensic practice, and the recovery model is sound.*
- **Content:**
  1. **3–5 named, verified references**, actual titles and identifiers.
  2. Research grounding, 3 specific lines (what was reverse-engineered, from what, and what it
     established) — not "studied workflows".
  3. The Recovery Depth diagram (§11-E).
  4. The Recovery Engine flow (existing D4, keep) with classification outputs added at the terminal.
  5. Link/QR to the verification document.
- **Visual:** two diagrams, one reference column.
- **Remove:** the Evidence Reader internals diagram; the word "Link" as a reference; the clip-art hand.
- **Density:** medium-low.

---

## 20. ENGINEERING NEXT STEPS

Prioritised by evaluator impact ÷ effort, with dependencies respected. **No AI work appears in the
first three tiers** — the parser, recovery and media fundamentals are the differentiator, and AI
built in the remaining time would be a demo of a pretrained model that the architecture already
correctly refuses to pretend it has.

### NEXT 1–2 ENGINEERING TASKS (do these first, in this order)

**1. Make `apps/api` and `tests/` build and run on a demo machine.** *Blocking everything below.*
   `sqlx-macros` will not link under the mingw toolchain. Switch to the MSVC toolchain
   (`rustup default stable-x86_64-pc-windows-msvc` + VS Build Tools), or use a Linux box/WSL.
   **Effort:** 2–6 h, mostly install time. **Risk:** low-medium — a second toolchain may surface
   latent compile errors in `handlers.rs`, which was edited but never compiled on this host. The
   media verification doc flags exactly this. **Why first:** without it there is no end-to-end demo,
   no screenshots, and no runtime verification of anything. Every other item depends on it.

**2. Install FFmpeg on the demo machine and execute the media pipeline end to end.**
   Unblocks 14 currently-skipped integration tests, and converts the decode path from
   `IMPLEMENTED — VERIFICATION PENDING` to executed. **Effort:** 1–3 h. **Risk:** low.
   **Why:** the deck claims Codec/GOP/Decode/Remux and no decode has ever run. It is also the only
   route to a playable recovered video, which is the strongest demo artifact available.

### BEFORE FINAL DEMO

**3. One full pipeline run on a synthetic Hikvision or Dahua image, through the UI, captured.**
   Produces S1, S3, S4 and the recovered-video clip. **Effort:** 3–5 h. **Depends on:** 1, 2.
   **Evaluator impact: highest of any item in this list.**

**4. Fix the `"Ingest hash verified"` string and implement evidence-hash re-verification.**
   `handlers.rs:165` currently asserts a verification that never happened. **Effort:** ~3 h.
   **Risk:** low. **Why now:** it is the only place the *product itself* overstates, it is cheap,
   and it makes a slide-4 claim true rather than requiring it be softened.

**5. Ensure the TP-Link parser cannot fabricate a recording during a demo.**
   It emits a `Recording` with an invented region, invented timestamp and
   `TimeZoneState::Known("UTC+05:30")` under a `Pass` state for any image ≥1 MiB. **Either** make it
   return `Ok(None)` **or** ensure TP-Link is never selected in the demo path. **Effort:** 1–2 h for
   the honest fix. **Risk:** low. **Why:** a single fabricated row in a live demo destroys the
   evidential-discipline story the whole submission now rests on. This is the highest
   *damage-avoidance* item in the list.

### BEFORE FINAL SUBMISSION

**6. Add MD5 alongside SHA-256.** Makes a deck claim true and matches examiner expectation. ~2 h, low risk.

**7. Populate the canned report fields**, or remove them from the exporter so no report ships a field
   that looks computed and is not. ~3 h.

**8. Verify the E01/EWF path** asserted on slide 6 actually exists and works; if not, remove it from
   the diagram. ~1 h. **Do not ship a diagram claiming a format the reader cannot open.**

**9. Write a one-page SOP** — acquire → ingest → detect → parse → recover → validate → report → export
   — and reference it on slide 6. ~2 h. The PS explicitly implies procedural output and the project
   has none.

**10. Fix the three panel-header typos in the deck.** 5 minutes.

### POST-SUBMISSION / FUTURE (do not spend current time here)

- Real-DVR-image acquisition and validation — the single most valuable engineering item in the
  project's life, and **not achievable credibly in the remaining window.** Present it as the next
  milestone, which is exactly what it is.
- Matrix, Godrej and CP-Plus (non-UBS) parsers.
- A real detection engine behind the analysis boundary.
- Native OpenCV backend compilation + fallback-agreement comparison.
- The six HIGH-severity performance defects (naive O(n·m) carve scanning, no `spawn_blocking`, volume
  re-parsed per export). Real, but invisible to an evaluator and irrelevant at demo scale.
- `DataState::Overwritten` reachability (needs a parser to supply a wrap pointer).
- Timeline representation for unknown-channel / unknown-clock candidates.

---

## 21. FINAL CLAIM-ACCURACY REGISTER

| Claim | Current PPT | Actual Status | Evidence | Keep? | Required Action | Build Before Submission? |
|---|---|---|---|---|---|---|
| 8 OEMs, parallel detection | Slides 2 (×2), 3 | 6 detectors; Matrix/Godrej = `NOT_IMPLEMENTED.md` | `crates/detection/src/detectors/`, `profiles/` | **No, as worded** | 3-tier maturity chart, 6 detectors / 3 full parsers | No — deck fix |
| Proprietary filesystem parsing | Slides 2, 3, 4 | **UNIT TESTED** for HIKBTREE, DHFS, UNIVIEW_FS | 34,438 lines in `crates/parsers` | **Yes** | Name the three filesystems | No |
| MD5 + SHA-256 | Slide 2 | SHA-256 only; **MD5 absent** | `hash.rs:12-15`; `grep -ri md5` = 0 | **No** | Remove, or implement | **Yes — optional, ~2 h** |
| SHA-256 at ingest, custody event | Slide 2 | **UNIT TESTED** | `crates/hashing`, `handlers.rs:128` | **Yes** | — | No |
| "Hash verification" | Slide 4 | Derived artifacts only; **evidence hash never re-verified**, yet labelled verified | `service.rs:307`; `handlers.rs:165` | **Not as worded** | Implement re-verification, fix the string | **Yes — ~3 h, recommended** |
| Read-only / evidence unchanged | Slides 2, 4 | **VERIFIED** — no write method exists on the trait | `EvidenceReader`; no `OpenOptions` in `crates/` | **Yes — strengthen** | Say "at the type level" | No |
| Write-blocker / source safety | Implied slide 2 | **PARTIAL** — caller-asserted, not measured | `source_safety.rs`; `handlers.rs:147` | Yes, softly | Do not claim measurement | No |
| Confidence scoring + analyst gate | Slides 2, 4 | **UNIT TESTED** | `crates/confidence`; `PipelineStage::{Confidence,ThresholdGate,AnalystReview}` | **Yes** | Cite the pipeline stages | No |
| L1/L2/L3 tiered recovery | Slides 2, 3, 4, 5 | **IMPLEMENTED — described inaccurately.** Levels are a consequence of index-evidence strength, not an effort cascade | `RECOVERY_ENGINE_AUDIT.md` §4 | **Yes — rewrite** | New wording (§8); "L1 reads the fewest bytes" | No |
| "Orphan / Slack" recovery | Slides 3, 4, 5 | Mechanism is unreferenced metadata **or** unclaimed-in-scope. "Slack" is not it | `claims.rs::split_by_scope` | **Rename** | "Unreferenced / unclaimed-in-scope" | No |
| Recovers deleted evidence | Slides 2, 5 | **UNIT TESTED**, under a *stricter* rule than claimed | recovery decision suite | **Yes — upgrade** | Add "requires an explicit free marker" | No |
| Fragment reconstruction | Slide 5 | **UNIT TESTED** — 3 grouping tiers, evidence-only ordering | `correlation.rs` | **Yes** | Add "reports Unknown when no ordering evidence exists" | No |
| Physical adjacency not used | **Absent** | **UNIT TESTED** | `RECOVERY_ENGINE_AUDIT.md` §5 | **Add** | One line, slide 5 | No |
| Strategy refusal with reasons | **Absent** | **UNIT TESTED** — 6 strategies, every one reported | `capabilities::select_strategies` | **Add — top differentiator** | Verbatim quote, slide 5 | No |
| Runtime capability assessment | **Absent** | **UNIT TESTED** — 10 dimensions | `capabilities::assess_capabilities` | **Add** | Band in the slide-3 diagram | No |
| Determinism | **Absent** | **UNIT TESTED** — 3 tests | determinism suite | **Add** | Evidence panel, slide 4 | No |
| Unrun ⇒ UNKNOWN; bounded ⇒ REVIEW | **Absent** | **UNIT TESTED** | `FrameValidationReport`; `RecoveryRun::finalize` | **Add** | Slide 5 | No |
| Provenance / forensic explainability | Slide 5 (weak, corner) | **UNIT TESTED** — 13-field, 8 questions answered separately | `UNIVERSAL_RECOVERY_ARCHITECTURE.md` §6 | **Yes — promote** | Rewrite per §8 | No |
| Chain of custody | Slides 2, 5 (1 bullet) | **IMPLEMENTED** — custody events, `WriteDenied`, `CustodyView` | `write_guard.rs` | **Yes — promote** | Screenshot S4 | No |
| Timestamp normalization | Slides 2, 3 | **PARTIAL** — normalization real | `timeline/clock.rs` | Yes | Keep | No |
| Clock drift correction | Slide 3 diagram | **UNSUPPORTED** — label only | — | **No** | Remove the box label | No |
| Multi-camera correlation | Slides 2, 3, 5 | **PARTIAL** — correlator wired; unknown-channel candidates withheld from the timeline | `timeline/correlation.rs`; open gap #3 | Yes, softened | "cross-camera event correlation" | No |
| Unified schema for future DVR/NVRs | Slides 2, 4, 5 | **UNIT TESTED** — one contract, contract-harness tested incl. a broken parser | `parsers-core/src/contract.rs` | **Yes — promote to #1** | Diagram §11-A | No |
| New OEM = new parser only | Slides 4, 5 | **UNIT TESTED** — structural | `UNIVERSAL_RECOVERY_ARCHITECTURE.md` §9 | **Yes** | Diagram §11-D | No |
| FFmpeg — remux + validation | Slide 3 | Remux/probe previously working; **decode implemented, never executed** | `MEDIA_PIPELINE_VERIFICATION.md` §0 | **Yes** | `[IMPLEMENTED — VERIFICATION PENDING]`; execute before demo | **Yes — install FFmpeg** |
| OpenCV — frame/image processing | Slide 3 | **ARCHITECTURE ONLY** — optional feature, **never compiled on any host** | `media/src/lib.rs:47-50` | **Not as worded** | Retier: pure-Rust default (26 tests) + optional OpenCV backend | No |
| Motion analysis | Slide 3 | Quality/luma statistics exist; **motion analysis does not** | `media/src/process.rs` | **No** | Remove the words | No |
| AI — face / object / motion / event detection | Slides 2, 3 (×2), 4 | **NONE.** Zero ONNX/PyTorch hits; the stub fabricates and is unreachable | `grep` = 0; `ai-service/main.py:75-98` | **No** | `[REMOVE CLAIM]` — replace with the boundary | **No — not buildable credibly** |
| Analysis boundary (pluggable engine) | **Absent** | **IMPLEMENTED** — returns `AI_ANALYSIS_NOT_CONFIGURED`, zero findings | `media/src/analysis.rs:24` | **Add** | Relabel the terminal box; show the constant | No |
| Tauri 2 / React / TS desktop app, 13 views | Slide 3 | **IMPLEMENTED — VERIFICATION PENDING** here | `apps/frontend/src/views/` | **Yes** | Screenshot S1 | **Yes — needs task 1** |
| SQLite case/timeline/provenance | Slide 3 | **IMPLEMENTED — VERIFICATION PENDING** (the reason `apps/api` won't link here) | `apps/api` | Yes | — | **Yes — task 1** |
| "Parallel modules, scalable for large data" | Slide 4 | **PARTIAL** — bounded plan-driven scanning is real; **no benchmark exists**; 6 HIGH perf defects recorded | `engine.rs`; prior audit §20 | Yes, qualitative only | **Never attach a number** | No |
| E01 / EWF support | Slide 6 diagram | **UNVERIFIED by this audit** | `crates/evidence-reader/` | **Verify first** | Confirm or remove | Verify — ~1 h |
| Reproducible verification runner | **Absent** | **VERIFIED** — 28 stages, exits non-zero on failure, machine-generated report | `UNIVERSAL_RECOVERY_VERIFICATION_RESULT.md` | **Add — highest-credibility item available** | Evidence panel + screenshot S2 | No |
| Synthetic-only validation | **Absent** | **True and stated in-repo** | verification doc §1 | **Add** | One limitation line | No |

---

### Closing note

The gap between this deck and this project is not a quality gap — it is an **inversion**. The deck
spends its strongest real estate on the weakest claim (AI) and buries its strongest asset
(evidential discipline, and an actual reproducible verification artifact) in a corner or omits it
entirely. Every recommendation above is a version of the same move: **delete what cannot be
defended, and promote what has already been built and tested.** Doing only §16 — about one focused
day of work, most of it deletion — converts this from a deck that invites the question *"can you
show me the AI?"* into one that invites *"how do you know it was deleted?"* — a question this
project answers better than almost any tool in its category.

*End of audit.*
