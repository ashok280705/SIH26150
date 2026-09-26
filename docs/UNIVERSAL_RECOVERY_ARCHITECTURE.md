# Universal recovery architecture

The recovery engine as it stands after the audit in
[RECOVERY_ENGINE_AUDIT.md](RECOVERY_ENGINE_AUDIT.md). This describes what the code does, not a
target state.

---

## 1. The pipeline

```text
                    Evidence  (EvidenceReader — no write path exists at the type level)
                       │
                       ▼
                OEM Detection            crates/detection → OEM key + OemProfile
                       │                 not evidence of anything; passed in, never inferred here
                       ▼
                 OEM Parser              Parser::storage_geometry() / ::recording_index()
                       │                 a failure degrades the run and is logged, never fatal
                       ▼
          Standardized Representation    StorageGeometry · RecordingIndex · IndexedRecording
                       │                 plain Regions; the engine reads no OEM structure
                       ▼
           Capability Assessment         recovery::capabilities::assess_capabilities
                       │                 what THIS evidence supported — derived, not declared
                       ▼
           Recovery Strategy Planner     recovery::capabilities::select_strategies
                       │                 + recovery::plan::plan_recovery
          ┌────────────┼────────────┬─────────────┐
          ▼            ▼            ▼             ▼
      Indexed     Available     Structural      Raw
      Recovery    Metadata      Orphan          Recovery
      (probe)     (probe)       (sweep)         (sweep)
          │            │            │             │
          └────────────┴──────┬─────┴─────────────┘
                              ▼
                       Candidate Set          recovery::levels::scan_target_all
                              │               OEM structural carve, else window classification
                              ▼
                    Candidate Validation      codec structure · container record state
                              │               unrun checks are UNKNOWN, never PASS
                              ▼
                    Fragment Correlation      recovery::correlation — recorder evidence only
                              │
                              ▼
                    Temporal Correlation      sequence numbers, else recorder clock,
                              │               else TemporalOrdering::Unknown
                              ▼
                    Recovery Decision         DataState × RecoveryStatus, independent
                              │
                              ▼
                       Provenance             evidence id → planner region → scanned region
                                              → fragment region, with content hashes
```

---

## 2. Capability-driven strategy selection

The universal layer reasons about capabilities, never about OEM names. There is no
`if hikvision { … }` anywhere in `crates/recovery/src`.

```text
Parser output
   │
   ▼
RecoveryCapabilities            10 dimensions, each with available: bool + a reason
   ├── StorageGeometry          the parser read geometry from the recorder's structures
   ├── RecordingIndex           an index was LOCATED (NotFound is not "located")
   ├── AuthoritativeIndexScope  absence from the index is evidence, within a known region
   ├── DeletionMetadata         some entry carries an allocation marker
   ├── UnreferencedMetadata     surviving metadata for recordings the recorder cannot reach
   ├── RecorderTimestamps       some entry or fragment carries a clock reading
   ├── ChannelAttribution       some entry or fragment carries a channel
   ├── PayloadBoundaries        framing was separated from elementary stream
   ├── CodecMetadata            an OEM-declared codec label exists
   └── ContainerCarving         the structural carver bounded records by declared length
   │
   ▼
StrategySelection               6 strategies, each licensed or refused WITH A REASON
```

| Strategy | Licensed when | Yields at most |
|---|---|---|
| `IndexedRecovery` | an index was located and claims ranges here | `Active` / `Deleted` |
| `AvailableMetadataRecovery` | surviving metadata describes unreachable ranges | `Orphaned` |
| `StructuralOrphanRecovery` | an authoritative index governs bytes it does not claim | `Orphaned` |
| `RawRecovery` | any region carries no authoritative index statement | `Unindexed` |
| `FragmentCorrelation` | fragments carry a parent recording or a channel | grouping |
| `TemporalCorrelation` | ≥2 fragments carry a sequence number or a clock | ordering |

Every strategy appears in the output whether licensed or not, each with its reason, so a report
can state *"structural recovery was not performed because no authoritative index governs these
bytes"* rather than leaving an examiner to infer it from an absent section.

### `RecoveryCapabilities` is not `CapabilityStages`

`forensic_core::CapabilityStages` is implementation maturity — *"is Uniview parsing implemented
in this build?"* — declared ahead of time, a property of the codebase.
`recovery::RecoveryCapabilities` is runtime evidence — *"did the parser return an index for
this disk?"* The same parser yields different capabilities on a healthy image and on one whose
index region is destroyed. They are separate types with no conversion between them, the same
way `CapabilityStage` and `ValidationState` are kept structurally distinct.

---

## 3. Graceful degradation

Missing capabilities reduce what may be concluded; they never stop the run.

```text
geometry ✓  index ✓  authoritative ✓   →  Active · Deleted · Orphaned · Unindexed
geometry ✓  index ✓  partial only      →  Active · Deleted · Unindexed        (no Orphaned)
geometry ✓  index ✗                    →  Unindexed only
geometry ✗  index ✗                    →  Unindexed only, whole-window sweep
parser errors on both                  →  Unindexed only, error logged, run completes
```

Only the top row can produce an orphan finding, because only an authoritative index makes
absence evidential. There is no path anywhere from "not in the index" to `Deleted`: that
requires `AllocationEvidence::FreeMarked`, which is a positive marker the OEM structures
record.

---

## 4. Correlation

The stage between *"N pieces of video were found"* and *"these pieces are one recording"*.

**Grouping** uses recorder-supplied evidence only:

| Tier | Basis | Strength |
|---|---|---|
| A | every member carries the same `parent_recording` id from the recorder's metadata | Strong |
| B | same channel, inside the same OEM-described originating region | Medium |
| C | the recorder supplied nothing — the fragment stands alone | — |

Tier B is bounded by the *originating region* — the claimed or unclaimed range the planner
derived from OEM structures — rather than by a distance threshold. A threshold would be a tuned
constant standing in for evidence; the originating region is evidence.

**Ordering** is established from evidence or not at all:

```text
all members carry distinct sequence numbers  →  BySequenceNumber       (Strong)
all members carry distinct recorder clocks   →  ByRecorderTimestamp    (Medium)
duplicate sequence numbers                   →  Unknown + sequence-conflict recorded
duplicate timestamps                         →  Unknown + timestamp-collision recorded
anything missing                             →  Unknown + no-ordering-evidence recorded
```

An `Unknown` group still lists its members, in **physical offset order, labelled as such**, and
is validated REVIEW. Physical order is a statement about the disk, not about time.

**Physical adjacency is never used to group or to order.** Two container records adjacent on
disk may be two halves of one recording or two unrelated recordings months apart. Adjacency is
recorded as a `PhysicalDiscontinuity` observation and nothing else.
Gaps are recorded and never filled; overlapping members are reported and never merged; a group
whose members were classified differently reports no single state rather than collapsing them.

---

## 5. The evidence model

Correlation attaches `CorrelationEvidence { kind, strength, detail }` to every decision.
`EvidenceStrength` is an **ordinal label on a named observation, not a score**: it is never
summed, averaged or converted to a number, and it never replaces the observation it labels. The
platform's numeric scoring lives in `crates/confidence` and concerns OEM attribution; this does
not compete with it, and no second scoring system was introduced.

| Observation | Strength |
|---|---|
| filesystem / index reference | Strong |
| recorder metadata (parent recording id) | Strong |
| valid media structure | Strong |
| on-disk sequence numbers | Strong |
| timestamp continuity | Medium |
| channel within one described region | Medium |
| physical discontinuity | Weak (recorded, never acted on) |
| signature only | Weak (⇒ `Corrupted`, never a recording) |

---

## 6. Provenance

Every recovered artifact answers, without reduction to a single number:

| Question | Field |
|---|---|
| Where did this candidate come from? | `Provenance::source_regions` — evidence item → planner region → scanned region → fragment region |
| Which bytes support it? | `RecoveryCandidate::source_offsets`, absolute; `Provenance::output_hash` |
| Which parser information supports it? | `Provenance::parser_version` (`id@version`), `profile_version`, `profile_hash` |
| Which strategy produced it? | `DiscoveredFragment::discovery_method`, `RecoveryCandidate::recovery_level` |
| Which checks passed, which failed? | `FrameValidationReport` — five independent states, unrun ones `Unknown` |
| Which fragments were used? | `CorrelatedRecording::fragment_ids` + `regions` |
| Why this classification? | `Provenance::validation_state.reason`, prose, verbatim-displayable |
| How strongly, and on what basis? | `DiscoveredFragment::confidence` — `FieldEvidence<f64>` with a named additive basis string |

`fragment_id` is a SHA-256 of the evidence id and the exact range, so the same bytes always
produce the same id across runs and across representations — nothing downstream mints a new
one.

---

## 7. Bounds

| Bound | Enforced in |
|---|---|
| `max_scan_bytes` | `engine.rs`, checked before the read that would exceed it |
| `max_scan_regions`, `max_candidates` | `engine.rs` loop guards |
| `max_hypotheses` | `correlation.rs` via `CorrelationBounds::max_groups` |
| per-group membership | `CorrelationBounds::max_fragments_per_group` |
| `time_limit`, cancellation | `engine.rs`, per target |
| read window | `ScanContext::max_window_bytes` + `BoundedReader` |
| FFmpeg wall clock | `ffmpeg/service.rs`, timeout + kill + reap |

Any bound being hit sets `run.truncated`, and `RecoveryRun::finalize` downgrades the run to
REVIEW. **A bounded search is never PASS**, because it cannot guarantee a global optimum.

Complexity is linear in index entries and in `universe / chunk_size` for planning, and
`O(n log n)` in fragments for correlation — a `BTreeMap` group then a sort per group, with no
pairwise combination step. That is what keeps a high-candidate-density or hostile image from
becoming combinatorial.

---

## 8. OEM safety

**No file under `crates/parsers/` was modified by this work.** Specifically unchanged:

```
crates/parsers/hikvision/**   (14 source files)
crates/parsers/dahua/**       (15 source files)
crates/parsers/uniview/**     (13 source files)
crates/parsers/cpplus-ubs/**
crates/parsers/honeywell/**
crates/parsers/tplink/**
crates/parsers/unified/**
profiles/**                   (all OEM profile data)
```

No OEM filesystem interpretation, storage geometry logic, recording-index logic, fragmentation
assumption or recovery heuristic was touched. The only cross-boundary change was in the
*generic* direction: `recovery/src/claims.rs` stopped hard-coding one vendor's metadata key, so
the universal layer now adapts to whatever a parser records instead of naming vendors.

`crates/recovery/Cargo.toml` gained the parser crates as `[dev-dependencies]` so the contract
suite can run against them. That adds no production dependency on any OEM crate — the recovery
engine still depends only on `parsers-core`.

---

## 9. Adding an OEM

```text
New OEM
   ↓
OEM-specific parser  (implement Parser; Ok(None) is a valid answer everywhere)
   ↓
standardized Parser contract  (verified by parsers_core::contract)
   ↓
capabilities derived at runtime from what it returns
   ↓
the existing universal recovery engine
```

and **not** a new recovery algorithm, a new fragmentation algorithm, a new validation system or
a new reconstruction system. A parser that establishes nothing still works — it reaches the
raw-recovery tier — and every capability it later gains upgrades it automatically, because
strategy selection reads capabilities rather than names.
