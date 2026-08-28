# OPEN-1 — Rust EWF/E01 dependency selection

| | |
|---|---|
| **Status** | **DEFER adoption.** Candidate selected and license-verified; the testing condition of Req 8.8 is not yet met. `.E01` remains a *planned integration* |
| **Task** | tasks.md task 1 (OPEN-1). Gates E01 only — it does **not** gate Phase 1 |
| **Requirements** | Req 8.8 (E01 as planned integration; no custom E01 reader) |
| **Design** | Component 1 (Evidence Reader); Open Items to Confirm item 1; R1–R25 matrix row 8.8 (PARTIAL — dependency-gated) |
| **Evidence date** | crates.io metadata read 2026-08-28. Downloads, versions, and maintenance signals are as of that date |
| **Output** | Documentation only. No Rust code, no `Cargo.toml` change, no dependency added |

## Decision

**Preferred candidate: [`ewf`](https://crates.io/crates/ewf) v0.4.10, Apache-2.0.** **Adoption is deferred**
until the verification gate below is executed against real E01 fixtures.

This is not a hedge. Req 8.8 sets three conditions before the platform may claim `.E01`: the
dependency must be **selected**, **license-verified**, *and* **tested** for read-only, segmented,
and compressed E01 handling. OPEN-1 is a documentation-only spike that adds no code and no
fixtures, so it can satisfy the first two conditions and structurally cannot satisfy the third.
Declaring "adopt" here would assert a test result that does not exist — exactly the kind of
unearned claim Req 8.8 exists to prevent.

## Candidates evaluated

| Crate | Latest | License | Maintenance signal | Verdict |
|---|---|---|---|---|
| [`ewf`](https://crates.io/crates/ewf) | 0.4.10 (2026-08-08) | Apache-2.0 | 17 versions since 2026-03-05; 11,293 downloads (9,494 recent); 4,222 lines Rust; MSRV 1.85, edition 2021 | **Preferred candidate** |
| [`ewf-image`](https://crates.io/crates/ewf-image) | 0.2.0 (2026-07-18) | Apache-2.0 | 3 versions since 2026-07-09; 130 downloads; 13,836 code lines / 7 comment lines; MSRV 1.96, edition 2024 | Rejected as reader |
| [`ewf-forensic`](https://crates.io/crates/ewf-forensic) | 0.7.6 (2026-08-08) | **not verified** | 12 versions since 2026-05-13; 278 downloads; same repo/owner as `ewf` | Out of scope — auditor, not a reader |
| [`libewf`](https://github.com/libyal/libewf) (C, via FFI) | — | **not verified** | Mature, long-established reference implementation | Rejected as dependency; retained as test oracle |
| [`zff`](https://crates.io/crates/zff) | 2.0.1 stable | not checked | — | Not applicable — different container format, not EWF |
| [`disk-forensic`](https://crates.io/crates/disk-forensic) | 0.11.7 | not checked | — | Not applicable — multi-container orchestrator, far wider surface than needed |

Licenses and versions above come from the crates.io version API for each crate. Two facts worth
recording precisely:

- **`ewf` relicensed mid-life.** Versions 0.1.0–0.2.1 were published as MIT; 0.3.0 (2026-06-28)
  onward are Apache-2.0. Both are permissive and both are compatible with this platform, so the
  change is not a blocker — but any adoption must pin a `>= 0.3.0` version so the recorded license
  matches the code actually built.
- **No `libewf` Rust binding exists on crates.io.** A crates.io search for `libewf` returns only
  the two `ewf`/`ewf-forensic` crates above — there is no `libewf-sys` or equivalent maintained
  binding. The FFI route therefore means authoring and owning an `unsafe` shim plus a native build
  dependency, which is a larger long-term liability than the pure-Rust option.

## Assessment of the preferred candidate

Everything in the "claimed" column is the crate's own documentation
([`ewf` README](https://crates.io/crates/ewf), [docs.rs/ewf](https://docs.rs/ewf)). None of it has
been independently confirmed by this platform.

| Criterion | Claimed | Our verification status |
|---|---|---|
| **License compatibility** | Apache-2.0; "zero GPL dependencies" | **Verified** via crates.io version metadata. Permissive, no copyleft obligation, no attribution problem for a court-facing tool |
| **Read-only behaviour** | `EwfReader::open()` exposes `Read + Seek`; no write API documented | **Unverified.** Absence of a documented write method is not proof of absence — must be confirmed by API audit |
| **Segmented E01** | Auto-discovers `.E01` through `.EZZ` | **Unverified.** Needs a genuinely multi-segment fixture |
| **Compressed E01** | zlib chunk decompression with configurable LRU cache (default 100 chunks ≈ 3.2 MB) | **Unverified.** The bounded, configurable cache is the right shape for Req 8.2/8.3, but the cap must be reconciled with the OPEN-2 read-window budget rather than left at its default |
| **Corrupt / truncated images** | Guards against malformed chunk tables with implausible entry counts; tolerates both `table` and `table2` sections; extracts read-error entries from `error2` sections | **Unverified, and the most significant gap.** Truncation is not documented at all. Req 8.10 requires sparse/unallocated regions to be distinguished from real end-of-source, and Req 8.11 requires out-of-bounds rejection. Whether this crate's errors can be mapped onto that distinction is unknown |
| **Maintenance risk** | 127 tests claimed at 99.86% line coverage; full-media MD5 compared against libewf and The Sleuth Kit over 6 public images (303+ GiB) | **Moderate-to-high.** See below |

**Maintenance risk in detail.** The crate is roughly five months old (first published 2026-03-05),
still pre-1.0 at 0.4.10, and published by a single maintainer. Pre-1.0 means breaking changes are
permitted between minor versions, and a single-maintainer project carries a bus factor of one. Its
own README still shows `ewf = "0.2"` in the install snippet while shipping 0.4.10, a small
documentation-hygiene signal. Against that, the differential-validation claim — bit-identical
full-media MD5 against libewf and The Sleuth Kit — is precisely the right kind of evidence for a
forensic container reader, and it is reproducible on our side rather than something we must take on
trust. Download velocity (9,494 of 11,293 downloads recent) suggests active use, not abandonment.

**Why `ewf-image` is rejected as the reader.** It reads *and writes* E01. Design Component 1 states
plainly that no write methods exist on the evidence path, and Req 8.7 requires read-only opening.
Linking a library that can emit E01 bytes puts a write capability inside the evidence-handling
dependency graph, which is a liability that has to be argued away in court rather than simply not
existing. Its other signals reinforce the decision: three releases in nine days, 130 downloads,
13,836 code lines carrying 7 comment lines, and an MSRV of 1.96 on edition 2024 that would drag the
whole workspace's toolchain floor upward.

**Why `libewf` stays relevant anyway.** It is the reference implementation the field trusts, and
`ewf` claims bit-identical output against it. That makes libewf the natural **differential-testing
oracle** for the verification gate, independent of whether it is ever linked. Using it that way
needs no license decision, because a test oracle run out-of-process is not a distributed dependency.
Its license was not verified in this spike; if it is ever proposed as a linked dependency, that
verification becomes a blocking prerequisite.

**One scoping note.** Req 8.8 concerns `.E01` only. `ewf` additionally advertises Ex01 (EWF v2) and
L01/Lx01 logical evidence support. Those are out of scope here and must not be claimed, tested, or
surfaced as capabilities on the strength of this note. E01 container decoding is payload-agnostic —
it is independent of whether the imaged media holds a DVR filesystem — so DVR-specific E01 fixtures
are not required for container-level validation.

## Verification gate (the work that would turn this into "adopt")

Not part of this task. Recorded so the adoption decision is reproducible rather than a judgement
call later:

1. **API audit for write surface.** Confirm no public API on the chosen version can write, truncate,
   or otherwise mutate the source, and that the file handle is opened read-only.
2. **Segmented fixture.** A multi-segment E01 read end to end, with byte-identical output against a
   raw image of the same media.
3. **Compressed fixture.** A compressed E01 read end to end, with the decompression cache pinned to
   the OPEN-2 window budget instead of the crate default, confirming peak memory stays bounded and
   independent of total image size (Req 8.2, 8.3).
4. **Corrupt and truncated fixtures.** Deliberately damaged and deliberately truncated images must
   produce typed errors, never panics, and those errors must map onto `ForensicError` such that
   Req 8.10's sparse-versus-truncation distinction and Req 8.11's out-of-bounds rejection are both
   expressible. **If that mapping cannot be built, this candidate fails the gate** regardless of how
   well it performs on healthy images.
5. **Differential check.** Full-media hash agreement against libewf or The Sleuth Kit on at least
   one public image, reproduced by us rather than cited from the crate's README.
6. **Acquisition-error plumbing.** Confirm `error2` read-error entries can populate the existing
   `Acquisition` model (`bad_sector_ranges`, `unresolved_ranges`) so a partial E01 acquisition is
   never presented as complete (Req 7.7–7.9).

Adoption also requires a pinned version `>= 0.3.0` (for the Apache-2.0 license) and a recorded
fallback position, given the pre-1.0 and single-maintainer risk.

## Standing constraint until this note is approved (Req 8.8)

Explicitly, and unchanged by this spike:

- **`.E01` stays a planned integration.** The platform must not claim, advertise, or imply `.E01`
  support in code, documentation, capability matrices, reports, or UI.
- **Phase 1 ships `.raw`, `.dd`, and `.img` only**, plus physical disks. `ImageFormat::E01` may exist
  as a declared enum variant, but opening an E01 source returns `UnsupportedFormat`.
- **A custom E01 reader MUST NOT be written.** No hand-rolled EWF header, section-chain, chunk-table,
  or zlib-chunk parser, not even a partial or "just enough to read the header" one. If E01 support is
  wanted, the route is approving a dependency through this note — not implementing the format
  ourselves to make a requirement look satisfied.
- Row 8.8 of the R1–R25 matrix stays **PARTIAL — dependency-gated**.

## Not decided here

Read-window and buffer bounds (OPEN-2, already decided), FFmpeg packaging (OPEN-3), confidence and
recovery configuration values (OPEN-4), Ex01/L01 support, `ewf-forensic` as an E01 integrity-triage
layer, and whether E01 lands in Phase 1 or later. This note selects a candidate, verifies its
license, and defines the gate. It adopts nothing.
