# Design Document

## Overview

The Multi-Vendor DVR/NVR Forensic Analysis Platform is a software-only, forensic-grade
workstation for analyzing HDD images and physical disks recovered from DVR/NVR devices
across multiple OEMs. Current supported target OEMs are Dahua, Hikvision, Honeywell,
CP Plus/UBS, and Uniview; extensible to future/not-yet-implemented vendors TP-Link, Godrej,
and Matrix.

The system is built as a Rust workspace (forensic core + Axum/Tokio backend), a
React/TypeScript frontend, an optional Python AI service, and PostgreSQL for metadata.
It is **deterministic, explainable, and evidence-preserving**: the same evidence and the
same profile versions must always produce the same result, every conclusion must be
traceable to observed bytes at specific offsets, and original evidence is never modified.

This document translates the requirements into an architecture that:

- enforces read-only evidence handling at both the OS-handle and application layers,
- keeps detection and parsing as separate, trait-based concerns,
- externalizes all OEM knowledge into versioned, hash-tracked profiles (no hard-coded
  signatures in source),
- models OEM attribution honestly (`confirmed` vs `compatible_candidate` vs `unknown`),
  preferring UNKNOWN over a wrong OEM claim,
- streams multi-terabyte evidence with bounded memory,
- and records complete provenance and chain of custody for every artifact.

### Design Goals and Non-Goals

**Goals**
- Forensic soundness: read-only, hashed, provenance-tracked. The Platform produces
  **forensically defensible reports with documented provenance, integrity, limitations,
  and chain of custody** — it does not and cannot guarantee legal admissibility.
- Explainability: every score decomposes into evidence items with offsets.
- Determinism: reproducible results given identical inputs and profile versions.
- Extensibility: new OEMs added via new profile + Detector/Parser impls, no core rewrite.

**Non-Goals**
- Acquisition/imaging hardware control (the platform ingests already-acquired images and
  read-only physical disks; it does not perform write-blocked hardware imaging itself).
- **Hardware write blocking.** Software read-only handles are not a substitute for a
  hardware write blocker. Where forensic procedure requires hardware write blocking, that
  is outside this software's scope.
- Guaranteeing legal admissibility. The Platform supports defensibility; a court decides
  admissibility.
- Proving OEM exclusivity where research has not established it (CP Plus stays a
  compatible-candidate).
- Real-time video streaming; reconstruction is an offline, validated process.
- Treating provisional OEM research as fact. All OEM signatures/offsets ship as
  PROVISIONAL / MODEL-SPECIFIC / FIRMWARE-SPECIFIC / UNVALIDATED until confirmed against
  real evidence. The Platform prefers UNKNOWN over an incorrect OEM attribution.

### Mapping to Requirements

| Design Area | Requirements |
|---|---|
| Read-only evidence + reader | 1, 8 |
| Case/evidence model | 7 |
| Hashing + chain of custody | 5 |
| Detection orchestrator + detectors | 2, 3, 9 |
| Confidence engine | 10 |
| OEM profiles | 6, 11 |
| Parsers | 3, 4, 12 |
| Recovery engine | 13 |
| Video reconstruction | 14 |
| Timeline + correlation | 15 |
| AI analytics (optional) | 16 |
| Reporting | 17 |
| UI + hex viewer | 18 |
| Testing + benchmarks | 19 |
| Determinism (bounded) | 20 |
| Capability maturity model | 21 |
| Validation states | 22 |
| Acquisition verification | 23 |
| Adversarial parsing/recovery | 24 |
| Uniview OEM (detector/parser/recovery) | 25 |

## Architecture

### High-Level Pipeline

```
READ-ONLY EVIDENCE
      │
      ▼
HASH / CHAIN OF CUSTODY  ──►  (SHA-256 at ingest, every action logged)
      │
      ▼
EVIDENCE READER  (read_at(offset,len), bounded buffers, cancel, progress)
      │
      ▼
DETECTION ORCHESTRATOR  ──►  runs all detectors in parallel over one reader
      │
      ├── Dahua Detector ─────┐
      ├── Hikvision Detector ─┤   each consumes its versioned OEM_Profile,
      ├── Honeywell Detector ─┤   emits an independent DetectorOutput
      ├── CP Plus/UBS Detector┤   (evidence + Detection_Status only; NO attribution)
      └── Uniview Detector ───┘
      │
      ▼
CONFIDENCE ENGINE  (threshold + margin + quality → Classification + Attribution_Status)
      │        (the Confidence_Engine — not the Detector — sets final Attribution_Status)
      ▼
OEM / STORAGE-FAMILY SELECTION  (Attribution_Status: confirmed | compatible_candidate
      │                          | unsupported | unknown)
      ▼
OEM-SPECIFIC PARSER  (filesystem, metadata, recordings, timestamp/TimelineEvent extraction,
      │               structural validation, recovery knowledge — NOT recovery orchestration)
      │
      ▼
RECOVERY ENGINE  (L1 indexed | L2 orphan/slack | L3 raw carving)
      │
      ▼
VIDEO RECONSTRUCTOR  (frame validation, GOP ordering, gap marking, decode test)
      │
      ▼
TIMELINE ENGINE  (normalize timestamps, unify, cross-camera correlate)
      │
      ▼
[OPTIONAL] AI ANALYTICS  (assistive findings, full provenance)
      │
      ▼
REPORTING  (PDF/JSON/CSV) + PROVENANCE + hashes + limitations
```

### System Topology

```
┌─────────────────────────────────────────────────────────────┐
│ React + TypeScript Frontend (Vite, Tailwind, shadcn/ui)       │
│  Case · Evidence · Acquisition · Detection · Parsing ·        │
│  Recovery · Timeline · Evidence/Provenance · Reports · Hex    │
└───────────────────────────┬───────────────────────────────────┘
                            │ HTTP/JSON (REST)
┌───────────────────────────▼───────────────────────────────────┐
│ Rust Backend  (Axum + Tokio)                                   │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ Forensic Core (crates)                                     │ │
│  │  forensic-core · evidence-reader · hashing · detection ·   │ │
│  │  confidence · recovery · timeline · reporting ·            │ │
│  │  parsers/{dahua,hikvision,honeywell,cpplus-ubs,uniview}    │ │
│  └──────────────────────────────────────────────────────────┘ │
└───────┬───────────────────────────┬───────────────────────────┘
        │                           │
        │ read-only                                    │ HTTP (optional)
        ▼                                              ▼
┌──────────────────────────────────────────┐   ┌────────────────────────────┐
│ Evidence Store                             │   │ AI Service (Python/FastAPI) │
│ (read-only, app-level immutability)        │   │  OpenCV + PyTorch           │
└──────────────────────────────────────────┘   └────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ PostgreSQL  (cases, evidence, detection results, evidence items,│
│  parser runs, recordings, recovery candidates, timeline events, │
│  AI findings, chain-of-custody, hashes, provenance)             │
│  — never stores raw multi-TB media —                            │
└───────────────────────────────────────────────────────────────┘
```

### Workspace Layout

```
sih2026/
├── Cargo.toml                 # Rust workspace root
├── requirements.md
├── design.md
├── tasks.md
├── crates/
│   ├── forensic-core/         # shared domain types, error types, traits
│   ├── evidence-reader/       # read-only streaming reader + formats
│   ├── hashing/               # SHA-256 + hash records
│   ├── detection/             # Detector trait, orchestrator
│   ├── confidence/            # confidence engine
│   ├── recovery/              # 3-level recovery + video reconstruction
│   ├── timeline/              # normalization + correlation
│   ├── reporting/             # PDF/JSON/CSV + provenance
│   └── parsers/
│       ├── dahua/
│       ├── hikvision/
│       ├── honeywell/
│       ├── cpplus-ubs/
│       └── uniview/
├── apps/
│   ├── api/                   # Axum binary wiring crates + DB
│   └── frontend/              # React + TypeScript + Vite
├── profiles/                  # versioned OEM_Profiles (data, not code)
│   ├── dahua/
│   ├── hikvision/
│   ├── honeywell/
│   ├── cpplus/
│   └── uniview/
├── services/
│   └── ai/                    # Python FastAPI service (optional)
├── tests/                     # cross-crate + fixture generators
├── docs/
└── cases/                     # local dev/test only; git-ignored
```

Rationale: a single Rust workspace lets the forensic core stay in one dependency graph
(shared types via `forensic-core`), while `apps/api` is the only crate that touches the
network and DB, keeping the core pure and testable. The frontend is a sibling app; there
is **no Node.js backend** (Req: tech stack).

## Cross-Cutting Concerns

### Read-Only Enforcement (Req 1, 8)

Two layers, with the OS-handle layer as the **primary** guarantee and the application
guard as a **secondary** defense (an app-level WriteGuard alone is not sufficient):

1. **OS-handle layer (primary)** — the reader always requests read-only OS handles and
   never obtains a writable handle to evidence. Covers `.raw`, `.dd`, `.img`, `.E01`, and
   physical disks.
   - **Linux**: files/devices opened `O_RDONLY`; physical disks (`/dev/sdX`) opened
     read-only; memory maps use `PROT_READ`.
   - **Windows**: `CreateFile` with `GENERIC_READ` + `FILE_SHARE_READ`; physical drives
     (`\\.\PhysicalDriveN`) opened read-only; maps use `PAGE_READONLY`.
   - **Limitation**: a read-only open prevents *this process* from writing but does not
     stop another privileged process, nor does it provide hardware-level write blocking.
     Hardware write blockers are out of scope (see Non-Goals).
2. **Application guard (secondary)** — the `EvidenceReader` trait exposes **no write
   method** at the type level. A `WriteGuard` additionally intercepts any attempted write
   path resolving inside the evidence location, denies it, and emits a `chain_of_custody`
   event of type `write_denied`.

Derived artifacts and the DB must resolve to paths outside the configured evidence
directory; a path-validation helper rejects writes that resolve inside it. Evidence-dir
immutability (Req 1.5) is enforced best-effort at the application layer; OS/hardware-level
immutability is out of scope.

### Determinism (bounded)

Determinism applies to **forensic results**, not to environment-dependent artifact
metadata.

- **Determinism inputs (the full key).** A `Forensic_Result` is a pure function of *all* of:
  the **evidence bytes** (and their `source_hash`), the **OEM_Profile version + hash**, the
  **ConfidenceConfig version + hash**, the **recovery configuration** (`RecoveryBounds` and
  related settings), and the **relevant parser/component versions**. Given identical values
  for every one of these inputs, the forensic result is identical. No wall-clock time, RNG,
  or thread-ordering influences a result.
- **Stable ordering (enumerated).** Every stage imposes a total, content-derived order so
  results never depend on scheduling:
  1. **detector evidence** — evidence items sorted by `(offset, kind, length)`;
  2. **candidates** — sorted by `(confidence, oem_key)` with a deterministic tie-break on
     `oem_key`;
  3. **score calculation** — an order-independent (commutative) sum over sorted items;
  4. **classification** — decision rules applied in the fixed Req 10.11 order;
  5. **parser order** — parsers/records emitted in a stable, keyed order;
  6. **recovery order** — regions/candidates processed and reported in sorted order;
  7. **hypothesis order** — reconstruction hypotheses ranked by a deterministic key with an
     explicit tie-break;
  8. **final merge** — per-detector results merged in a stable, sorted order.
- **Parallelism never changes the result.** Rayon/Tokio parallelism is for throughput only;
  parallel detection/recovery produces a `Forensic_Result` identical to a serial run
  (Req 20.4).
- **Forensic_Result equality (exclusions).** Equality is computed **excluding**
  timestamps, database identifiers, temporary paths, and processing durations (Req 20.2);
  determinism tests compare forensic results with exactly these fields excluded.
- Profile **and** config versions + hashes are captured in every result so runs are
  reproducible and auditable.

### OEM Knowledge Safety (non-negotiable) (Req 2, 6, 11)

OEM knowledge is **never fabricated and never hard-coded as authoritative**. This rule is
non-negotiable and governs all detectors, parsers, and profiles.

- **No invented knowledge.** The Platform does not invent, infer, or guess OEM signatures,
  magic values, offsets, filesystem/recording/frame structures, confidence weights,
  validation rules, model/firmware applicability, or OEM-exclusive evidence. Illustrative
  examples in this document (e.g. Dahua DHFS/DHAV and 512/1024/2048 offsets; Hikvision
  frame-layout examples; Honeywell partition/layout observations; CP Plus/UBS values
  0x20170502, 0x20131031, 0x5050, 0x1357, page sizes 4096/8192) are **not** authoritative
  facts and must not be converted into source constants.
- **Profile-driven knowledge.** Detector and Parser implementations contain generic
  interpretation algorithms and OEM-specific *processing logic* where required (e.g. the
  per-OEM parser crates `parsers/{dahua,hikvision,honeywell,cpplus-ubs}`). However,
  OEM-specific *factual knowledge* — signatures, offsets, structures, validation rules,
  applicability, and authoritative confidence weights — is supplied through versioned
  `OEM_Profile` data and research-backed configuration, never hard-coded as authoritative
  facts. The anti-pattern below is forbidden:

  ```rust
  // FORBIDDEN — authoritative OEM magic hard-coded in source
  if bytes == SOME_HARDCODED_DAHUA_MAGIC { return Oem::Dahua; }
  ```

  Instead a detector consumes a profile-defined rule and records, per evidence item: the
  profile version, profile hash, `evidence_status`, applicability, observed bytes, source
  offset, and validation result.
- **Evidence_Status required.** Every signature/rule carries an `Evidence_Status`
  (`validated | provisional | model_specific | firmware_specific | unvalidated`). A
  non-`validated` value may be used only within its stated applicability, retains its
  status through to the result, and **cannot alone** establish `confirmed` attribution.
- **Prefer UNKNOWN over WRONG.** Where evidence is insufficient, the rule is left absent or
  marked non-`validated`; the system reports `compatible_candidate` or `unknown` rather
  than inventing a value to make a detector "work". CP Plus/UBS remains
  **"UBS storage / CP Plus-compatible candidate"** unless OEM-exclusive evidence is
  actually established; a matching UBS signature never by itself yields `confirmed` CP Plus.
- **Synthetic fixtures are labeled.** Synthetic test fixtures represent documented
  profile-shaped test data only and are never described or used as real OEM evidence.

### Provenance & Chain of Custody (Req 5, 16, 17)

Every derived artifact records: source image id + hash, source offsets (byte ranges),
producing component + version, profile version(s) used, output hash. The
`Chain_Of_Custody` logs `{timestamp, examiner, action, artifact, result}` for every
significant action (ingest, detection run, parse, recovery, export, report, write-denied).

### Error Handling

- Core crates return `Result<T, ForensicError>` (thiserror). No panics on malformed
  evidence — corruption is data, not a crash. Inconsistencies become evidence items /
  integrity flags, never silent failures.
- The API maps `ForensicError` to structured HTTP problem responses; long operations
  return a job id and stream progress.

## Components and Interfaces

### 1. Evidence Reader (Req 8)

```rust
/// Read-only, streaming access to evidence. No write methods exist.
pub trait EvidenceReader: Send + Sync {
    /// Total size in bytes.
    fn len(&self) -> u64;

    /// Positioned read. Fills `buf` from `offset`; returns bytes read.
    /// Never allocates memory proportional to total evidence size.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError>;

    /// Optional read-only memory map for a bounded region, where beneficial.
    fn mmap_region(&self, offset: u64, len: usize)
        -> Result<Option<ReadOnlyMap<'_>>, ForensicError>;

    fn source_kind(&self) -> SourceKind; // Raw | Dd | Img | E01 | PhysicalDisk
}

/// Bounded streaming iterator over fixed-size windows, with cancel + progress.
pub struct RegionScanner<'r> { /* reader, window_size, cursor, cancel, progress */ }
```

- Formats `.raw`, `.dd`, `.img` are raw byte streams; physical disks use positioned reads
  (`pread`). **`.E01` is a PLANNED INTEGRATION**: it depends on selecting a
  license-compatible Rust EWF library verified for read-only, segmented, and compressed
  E01 with sane error handling. Until that dependency is confirmed, Phase 1 ships
  `.raw/.dd/.img`; E01 is not implemented by assumption (see Implementation Blockers).
- Max window/buffer size is a configured constant (default e.g. 8–64 MiB); the reader
  never reads the whole image.
- `RegionScanner` is `Sync`-friendly so Rayon can scan disjoint regions in parallel.
- **Progress/cancellation** apply to long-running operations (sequential reads, region
  scans, hashing, recovery scans). A random-access `read_at` may complete immediately
  without progress reporting; cancellation is honored by the long-running operations.
- **Sparse/truncation semantics**: the reader preserves logical offsets and distinguishes
  sparse/unallocated logical regions from actual source truncation/end-of-source. Sparse
  holes are never silently reported as truncation; actual truncation is reported separately.
  Out-of-bounds requests are rejected with `OutOfBounds`.

### 2. Case & Evidence Model (Req 7)

`Case_Manager` creates cases (unique id + creating examiner) and registers evidence with
acquisition metadata. Required-field validation rejects incomplete additions and names
the missing field.

```rust
struct Case { id: CaseId, created_by: ExaminerId, created_at: DateTime<Utc>, /* ... */ }

struct Evidence {
    id: EvidenceId,
    case_id: CaseId,               // exactly one case
    source_device: String,
    acquisition_time: DateTime<Utc>,
    capacity_bytes: u64,
    image_format: ImageFormat,     // Raw | Dd | Img | E01 | PhysicalDisk
    acquisition_tool: Option<String>,   // optional (Req 7.2, 7.6)
    acquisition_tool_version: Option<String>,
    sha256: Hash,
    responsible_examiner: ExaminerId,
    source_state: SourceState,     // read_only | read_write | unknown (Req 1.8)
    acquisition: Option<Acquisition>,   // acquisition completeness/verification (Req 7.7–7.9, 23)
}
```

**Acquisition model (Req 7.7–7.9, Req 23).** When acquisition information is available it is
captured as a concrete, hashed record linked to the evidence; when it is unavailable the
status is `unknown` and completeness is **never fabricated**. An incomplete acquisition is
**never** labeled `complete`.

```rust
enum AcquisitionStatus { Complete, Partial, Failed, Unknown }

struct Acquisition {
    status: AcquisitionStatus,          // complete | partial | failed | unknown
    tool: Option<String>,
    tool_version: Option<String>,
    map_reference: Option<PathBuf>,     // acquisition map/receipt (preserved, hashed)
    map_hash: Option<Hash>,
    bad_sector_ranges: Vec<Region>,
    unresolved_ranges: Vec<Region>,
    verification_status: ValidationState, // PASS | REVIEW | FAIL | UNKNOWN
    verification_reason: String,
}
```

Unavailable acquisition data resolves to `AcquisitionStatus::Unknown` with a recorded reason
rather than an invented `Complete`; bad-sector and unresolved ranges are preserved so partial
acquisitions are visible to the examiner and the report.

### 3. Hashing (Req 5)

`Hashing_Service` computes SHA-256 by streaming through the reader in bounded windows
(never loading the whole image). Hashes are stored as `HashRecord { artifact, algo, value,
computed_at, status, duration_ms, bytes_hashed }` and linked to provenance for exports and
reports. SHA-256 is required; the `algo` field allows additional algorithms in future
without schema change. For a multi-TB image the hash is computed via streaming reads and
the record captures how long it took and how many bytes were covered.

### 4. OEM Profiles (Req 2, 6, 11)

Profiles are **data artifacts** (TOML) loaded at runtime, not Rust constants. All candidate
signatures, offsets, and ranges live here and **must** carry an `Evidence_Status` field.
`Evidence_Status` is the single canonical domain concept (defined in requirements.md); the
serialized profile key is `evidence_status`. The word "basis" is used only as explanatory
prose for that same concept and is **not** a separate domain field.

Every signature/rule `evidence_status` is one of: `validated`, `provisional`,
`model_specific`, `firmware_specific`, `unvalidated`. The loader rejects a profile whose
signature lacks `evidence_status`. Current status of known research values (all ship
non-`validated` until confirmed against real evidence):

| OEM | Values | evidence_status |
|---|---|---|
| Dahua | DHFS, DHFS 4.1, DHAV; offsets 512/1024/2048 | `provisional` (offsets are search strategies, not universal rules) |
| Hikvision | illustrative bytes, frame-layout assumptions | `unvalidated`/`provisional` — must not be hard-coded |
| Honeywell | partition/layout observations | `model_specific` / `provisional` |
| CP Plus/UBS | 0x20170502, 0x20131031, 4096/8192, 0x5050, 0x1357 | `provisional` / `model_specific` (CP-VNR-3104 firmware; not proven exclusive) |

No signature may raise attribution to `confirmed` without OEM-exclusive evidence.

```toml
# profiles/cpplus/ubs-v1.toml   (illustrative shape, values are PROVISIONAL)
profile_id      = "cpplus-ubs"
profile_version = "cpplus-ubs-1.0.0"
schema_version  = "1"                       # REQUIRED: loader validates against this schema
storage_family  = "UBS"
oem             = "CP Plus"
attribution     = "compatible_candidate"    # NOT "confirmed"
validation_state = "REVIEW"                  # profile-level state; not a passing operation

[[signatures]]
name = "ubs_partition_marker"
value_hex = "20170502"
endianness = "little"
evidence_status = "provisional" # REQUIRED: validated|provisional|model_specific|firmware_specific|unvalidated
evidence_source = "CP-VNR-3104 firmware RE notes (provisional; not proven exclusive)"
applies_to = { models = ["CP-VNR-3104"], firmware = ["*"], hardware_variant = ["*"], storage_variant = ["UBS"] }

[confidence_weights]
ubs_partition_marker = 0.15
# ... single-signature weight is intentionally insufficient to confirm alone
# Loader REJECTS this profile if ANY signature/rule omits evidence_status, or if the
# profile is malformed/schema-invalid (ProfileInvalid).
```

```rust
struct OemProfile {
    profile_id: String,               // stable identity of this profile (Req 11)
    profile_version: String,          // version identifier (Req 11.2)
    schema_version: String,           // profile schema version the loader validates against
    profile_hash: Hash,               // content hash recorded into every result (Req 11.3)
    oem: Option<String>,
    storage_family: String,
    attribution: AttributionStatus,   // Confirmed | CompatibleCandidate | Unsupported | Unknown
    signatures: Vec<SignatureRule>,   // each SignatureRule carries a REQUIRED evidence_status
    offset_constraints: Vec<OffsetConstraint>,
    expected_ranges: Vec<RangeRule>,
    validation_rules: Vec<ValidationRule>,  // each carries a REQUIRED evidence_status
    confidence_weights: HashMap<String, f64>,
    applicability: Applicability,     // model, firmware, hardware_variant, storage_variant (Req 6.5–6.6, 11.7)
    evidence_source: Option<String>,  // reference/citation for the rules (Req 11.7)
    validation_state: ValidationState,// profile-level PASS | REVIEW | FAIL | UNKNOWN (Req 11.7)
}

struct Applicability {
    model: Option<Vec<String>>,
    firmware: Option<Vec<String>>,
    hardware_variant: Option<Vec<String>>,
    storage_variant: Option<Vec<String>>,
}
```

**Profile loader (strict, fail-closed).** The loader validates `schema_version` and the
whole profile against the schema, computes and records `profile_hash`, and **rejects any
profile in which a signature, offset, magic value, structure, range, or validation rule
lacks an `evidence_status`** (Req 11.5, 11.8). It also **rejects malformed or otherwise
invalid profiles** (bad schema, unparseable TOML, inconsistent applicability) with a
`ProfileInvalid` error rather than loading a partial profile. The loaded `profile_version`
+ `profile_hash` are recorded into every result so reports can cite exactly which profile
produced a claim. Each signature/rule additionally records `evidence_source`/reference and
its own applicability so per-model/firmware/variant scope is explicit.

### 5. Detection (Req 2, 3, 9)

```rust
pub trait Detector: Send + Sync {
    fn oem_key(&self) -> &str;
    /// Inspect the read-only reader using the given profile; produce evidence.
    /// MUST NOT interpret recording content (that is the Parser's job).
    /// Returns a `DetectorOutput` (evidence + Detection_Status only). The Detector
    /// NEVER sets a final Attribution_Status; that is the Confidence_Engine's job.
    fn detect(&self, reader: &dyn EvidenceReader, profile: &OemProfile)
        -> Result<DetectorOutput, ForensicError>;
}
```

The `Detection_Orchestrator` loads all available profiles, constructs the corresponding
detectors, and runs `detect` in parallel (Tokio tasks / Rayon) over the **same** reader.
Each detector collects evidence independently; the orchestrator never lets one result
mutate another's evidence. New OEMs join automatically when a profile + detector impl is
present — no orchestration edits.

**Detector output carries NO attribution.** The `DetectorOutput` produced by each Detector
contains evidence, candidate regions, and a `Detection_Status` only. It deliberately has
**no `attribution_status` field** — a Detector cannot claim an OEM. The Confidence_Engine
consumes `DetectorOutput`s and produces a `ClassifiedDetectionResult` that is the *only*
place `Classification` and `Attribution_Status` are set.

```rust
/// Emitted by a Detector. Evidence + Detection_Status only — NO Attribution_Status.
struct DetectorOutput {
    oem_key: String,
    storage_family: Option<String>,
    status: DetectionStatus,                 // Confirmed | Ambiguous | Insufficient | NotDetected
    evidence: Vec<EvidenceItem>,
    candidate_regions: Vec<Region>,
    warnings: Vec<String>,
    profile_version: String,
    profile_hash: Hash,
}

/// Produced ONLY by the Confidence_Engine from one DetectorOutput (plus cross-detector
/// context). This — not the Detector — is where Classification and Attribution_Status live.
struct ClassifiedDetectionResult {
    detector_output: DetectorOutput,
    raw_score: f64,                          // raw weighted sum
    confidence: f64,                         // normalized 0.0–1.0
    top_candidate: Option<String>,
    second_candidate: Option<String>,
    margin: f64,                             // top1 − top2 confidence separation
    evidence_quality: f64,
    classification: Classification,          // Confirmed | CompatibleCandidate | Ambiguous
                                             // | Insufficient | Unknown
    attribution_status: AttributionStatus,   // Confirmed | CompatibleCandidate
                                             // | Unsupported | Unknown  (set HERE, not by Detector)
    validation_state: ValidationState,       // PASS | REVIEW | FAIL | UNKNOWN
    explanation: String,
}

struct EvidenceItem {
    source_evidence_id: EvidenceId,          // which evidence source these bytes came from
    kind: String,
    offset: u64,
    length: u64,
    observed: Vec<u8>,                       // bounded snippet actually read at offset..offset+length
    expected: Vec<u8>,                       // bounded snippet the profile rule expected
    rule_match_status: RuleMatchStatus,      // Match | Mismatch | Partial | Absent
                                             //   (did the OBSERVED bytes match EXPECTED?)
    evidence_status: EvidenceStatus,         // validated | provisional | model_specific
                                             //   | firmware_specific | unvalidated (rule provenance)
    score_contribution: f64,
    explanation: String,
    profile_version: String,
    profile_hash: Hash,
    applicability: Option<Applicability>,    // model/firmware/variant this item is scoped to
}
```

`Evidence_Status` (the *provenance* of the profile RULE — how well established it is) and
`rule_match_status` (whether the *observed* bytes matched what the rule *expected*) are
distinct axes and are **never** conflated: a `validated` rule can still produce a
`Mismatch`, and a `provisional` rule can produce a `Match`.

**Detector/Parser content boundary (Req 3.1).** Every detector below reasons over
**storage-structure evidence only** (partitions, superblocks/headers, filesystem/region
metadata, signatures, offsets, structural boundary arithmetic). A detector **does not
interpret recording, packet, frame, or video CONTENT** — recording/index/frame/payload/video
interpretation belongs downstream to the **Parser** (metadata/index/recording), the
**Recovery Engine** (candidate recovery), and the **Video Reconstructor** (frame assembly).

Per-OEM detection pipelines (all profile-driven, all producing evidence items, all
storage-structure only):

- **Dahua** — candidate search → **DHFS/storage-structure** evidence → surrounding
  structure → structural validation → size/boundary → metadata/index locators. **DHFS/storage
  structure is the detector's evidence.** DHAV *presence* may serve as structural
  corroboration, but **DHAV/frame/video CONTENT interpretation is downstream** (Parser/
  Reconstructor); **DHAV alone never confirms Dahua** and "DHAV found" is never sufficient.
- **Hikvision** — candidate → surrounding **storage structure** → header → size/offset →
  structural boundary arithmetic (`start + size = expected boundary`) as a *structural*
  check. Boundary mismatch lowers confidence but does not by itself mean "not Hikvision"
  (corruption/fragmentation/overwrite possible). **Recording/frame/video interpretation is
  the Parser/Reconstructor's job**, not the detector's. No illustrative bytes are hard-coded;
  only validated profile signatures are used.
- **Honeywell** — partition/layout/**topology** (partition = region; sector = addressing
  unit, byte offset = sector_size × start_sector) → candidate recording region → storage
  metadata locators. **Partition/layout/topology is detection**; **recording/index
  interpretation is the Parser's job.** Observed layouts are profile observations, not
  universal rules.
- **CP Plus / UBS** — **UBS/superblock/page/CRC storage evidence**: UBS partition marker →
  superblock → page-size validation → CRC/consistency → storage-structure locators. **This
  storage evidence is detection**; **recording DB/index/packet/video interpretation is the
  Parser's job.** Output is **"UBS storage / CP Plus-compatible candidate"** unless
  OEM-exclusive evidence exists.
- **Uniview** — bounded initial scan (profile-controlled; 16 KiB is not universal) →
  **super/super-data/storage metadata** candidate → magic/version → surrounding metadata →
  structural validation. Profile-controlled **`EcPortId` and timestamp metadata are
  CORROBORATING evidence** that support detection (validated by profile rules); per Req 25.4
  the illustrative `EcPortId` form `00000#EC1001` and timestamp evidence are corroborating and
  profile-validated and are **never alone proof** of Uniview. **DI/index/DATA/video-payload
  interpretation is the Parser/Recovery/Reconstructor's job.** See the OEM Implementation
  Specification for the full Uniview flow.

**Attribution ownership.** Each Detector emits a `DetectorOutput` carrying evidence items
and a `Detection_Status` (`Confirmed | Ambiguous | Insufficient | NotDetected`) only —
`DetectorOutput` has no `attribution_status` field. The **Confidence_Engine** — not the
Detector — consumes the `DetectorOutput`s and produces the `ClassifiedDetectionResult`, which
is the sole carrier of `Classification` and the final `Attribution_Status`. These three
concepts (`Detection_Status`, `Classification`, `Attribution_Status`) are distinct (see
Confidence Engine) and are never treated as interchangeable.

### 6. Confidence Engine (Req 10)

Deterministic weighted-evidence model — **no ML**. Three concepts are kept distinct:
**score** (raw weighted sum), **confidence** (normalized 0..1), **classification**
(the decision). All constants live in profile/config data, never in source.

**Per-evidence score.** For each validated evidence item:

```
evidence_score(item) = signature_weight × validation_factor × quality_factor
```

- `signature_weight` — from the profile's `confidence_weights` (per signature/rule).
- `validation_factor` — how the item validated. The example mapping (`Match = 1.0`,
  `Partial = 0.5`, `Mismatch = 0.0`, `Absent = 0.0`) is an **initial engineering default /
  provisional configuration**, not a scientifically validated forensic constant; the actual
  values are read from profile/config data.
- `quality_factor` — evidence quality: structural corroboration (a signature backed by a
  consistent surrounding structure and a satisfied boundary check) scores higher than an
  isolated magic value. Any concrete values shown are **initial engineering defaults /
  provisional configuration** and live in profile/config, never in source.

All numeric values in this section are illustrative engineering defaults. No threshold,
weight, validation factor, or quality factor in this document is a validated forensic
constant, and none may be hard-coded as authoritative in source.

**Per-OEM score and confidence.**

```
oem_score(oem)  = Σ evidence_score(applicable items for oem)         // stable, order-independent sum
confidence(oem) = oem_score(oem) / max_achievable_score(oem, applicable_rules)  // normalized 0..1
```

The sum includes every Evidence_Item that is applicable to the OEM (i.e. validated within
its declared applicability), **regardless of its Evidence_Status** — a `provisional`,
`model_specific`, `firmware_specific`, or `unvalidated` item may contribute to the score
within its declared applicability. Contributing to the score does **not** change an item's
Evidence_Status: a high numerical score never upgrades non-validated evidence to
`validated`, and non-validated evidence cannot alone establish `confirmed` attribution
(which additionally requires OEM_Exclusive_Evidence). `max_achievable_score` is computed over
**only the APPLICABLE rule set** — the signatures/rules whose applicability matches the
evidence's model/firmware/hardware/storage variant — so that rules which do not apply to the
evidence under examination are excluded from the denominator and cannot distort confidence.
This keeps confidence comparable across OEMs and independent of the total profile size.

**Two separate versioned configuration inputs.** The Confidence_Engine consumes two
distinct, versioned configuration sources and hard-codes neither in source:

- **`OEM_Profile`** supplies **OEM-specific evidence/signature weights**
  (`confidence_weights` per signature/rule) — knowledge about a particular OEM.
- **`ConfidenceConfig`** supplies **classification policy** — threshold, minimum margin,
  minimum evidence quality — applied uniformly across OEMs.

```
OEM_Profile      → OEM-specific evidence weights ─┐
ConfidenceConfig → classification policy ─────────┼─► Confidence_Engine → classification
```

All numeric values in both inputs are **initial engineering defaults / provisional
configuration** unless validated; none is a validated forensic constant.

**Classification** (evaluated after all detectors finish):

```rust
struct ConfidenceConfig {          // classification POLICY (uniform, not OEM-specific), versioned
    config_version: String,        // version of this policy
    config_hash: Hash,             // recorded into every result for reproducibility
    threshold: f64,                // min confidence for a positive result
    min_margin: f64,               // min top1 - top2 separation
    min_quality: f64,              // min aggregate evidence quality
    validation_factors: Map<RuleMatchStatus, f64>, // Match/Partial/Mismatch/Absent → factor
    quality_factors: Map<String, f64>,             // named quality contributions
}

enum Classification {
    Confirmed { oem_key: String },           // strong, unambiguous, exclusive evidence
    CompatibleCandidate { oem_key: String }, // meets threshold but no exclusive evidence
    Ambiguous { top_candidates: Vec<String> },
    Insufficient,                            // e.g., single magic only / low quality
    Unknown,                                 // nothing credible
}
```

The two configuration sources stay separate: **OEM_Profile** supplies OEM-specific
evidence/signature weights, and **ConfidenceConfig** supplies the uniform classification
policy (threshold, margins, quality, validation/quality factors) applied identically across
OEMs. **No authoritative forensic numeric constant is hard-coded in source**; every number
in either input is *provisional engineering configuration* unless independently validated.

Decision rules — evaluated in **exactly** this order to match Req 10.11:
1. If the evidence is **structurally insufficient** OR it rests only on a **lone magic value**
   (or fails `min_quality`, low quality) → `Insufficient`.
2. Else if **no** candidate reaches `threshold` → `Unknown`.
3. Else if the **top-two margin** `top1.confidence − top2.confidence < min_margin` →
   `Ambiguous` (flagged for deeper validation; the engine never picks a marginal winner).
4. Else if `threshold` **and** `min_margin` **and** `min_quality` are all satisfied **and**
   the top OEM has **OEM_Exclusive_Evidence** → `Confirmed`.
5. Else → `CompatibleCandidate` (this is the default CP Plus/UBS outcome).

This order deliberately performs the insufficient/lone-magic/low-quality check **first** — so
a lone magic value is classified `Insufficient` and is never mislabeled `Unknown` (Req 2.3) —
then the threshold check, then the margin check, and only then
`Confirmed`/`CompatibleCandidate`.
The classification is explainable: it references the contributing evidence items and the
exact numbers (scores, confidences, margin, quality) that drove the decision. The Platform
prefers `Unknown` over asserting a wrong OEM.

**Evidence_Status is preserved, never upgraded by score.** The Confidence_Engine carries
each contributing `EvidenceItem`'s `Evidence_Status` through unchanged. A
`provisional`/`model_specific`/`firmware_specific`/`unvalidated` rule may contribute only
within its declared applicability, and a high numerical score **never** upgrades it into
`validated` forensic evidence. Consistent with the OEM-exclusive-evidence requirement, a
`confirmed` classification requires OEM_Exclusive_Evidence and is never reached on the
strength of non-validated rules alone — the engine prefers `compatible_candidate` or
`unknown`.

### 7. Parsers (Req 3, 4, 12)

**Responsibility boundary (Req 12.1).**
The Parser owns *OEM knowledge*; the Recovery Engine owns *recovery orchestration and state
classification*; the Video Reconstructor owns *frame assembly*. The Parser therefore does
**not** run recovery levels itself — it exposes OEM-specific recovery *knowledge*
(recognizing and validating this OEM's structures) that the Recovery Engine calls.

```rust
pub trait Parser: Send + Sync {
    fn oem_key(&self) -> &str;

    // OEM interpretation
    fn parse_filesystem(&self, r: &dyn EvidenceReader, p: &OemProfile)
        -> Result<Filesystem, ForensicError>;
    fn parse_metadata(&self, ...) -> Result<Metadata, ForensicError>;
    fn parse_recordings(&self, ...) -> Result<Vec<Recording>, ForensicError>;
    // OEM-specific extraction of timestamped event info into TimelineEvent candidates.
    // Does NOT build the final unified timeline (that is the Timeline_Engine's job).
    fn extract_timeline_events(&self, ...) -> Result<Vec<TimelineEvent>, ForensicError>;

    // OEM-specific structural validation + recovery KNOWLEDGE (called by Recovery Engine)
    fn validate_structure(&self, region: &[u8], p: &OemProfile) -> StructureReport;
    fn recognize_candidate(&self, region: &[u8], p: &OemProfile) -> Option<CandidateHint>;
}
```

The orchestrator passes the selected `storage_family` + `profile_version` to the parser
(detection output is parser input). Parsers never decide OEM identity and never own the
recovery-level state machine.

Timestamps: parsers retain the `Raw_Timestamp` exactly as stored and layer additional,
*separate* time classes on top of it. **No timestamp field ever overwrites another.** The
model keeps `Recorder_Native_Time`, `Normalized_Timestamp`, and `Reference_Time` as distinct
evidence classes (Req 4.5–4.7); an **unknown timezone stays `Unknown` and is never silently
treated as UTC** (Req 4.6).

```rust
/// Distinct time classes for one observed timestamp. Nothing here is ever overwritten.
struct TimeEvidence {
    raw: RawTimestamp,                          // bytes exactly as stored (Req 4.1)
    recorder_native: Option<RecorderNativeTime>,// device-clock interpretation of `raw`
    normalized: Option<NormalizedTime>,         // investigative time (e.g. UTC) — never replaces raw
    reference: Option<ReferenceTime>,           // corrected/reference time (never overwrites the above)
    timezone: TimeZoneState,                    // Known(tz) | Unknown  (never silently UTC)
    normalization_method: Option<String>,       // how `normalized` was derived (Req 4.4)
    correction: Option<ClockCorrection>,        // present only WHERE clock correction was performed
}

enum TimeZoneState { Known(Tz), Unknown }

/// Records a documented clock correction (Req 4.7); the original timestamp is preserved.
struct ClockCorrection {
    method: String,
    anchor_evidence: Provenance,   // what the correction was anchored to
    offset: Duration,
    drift: Option<f64>,            // where applicable
    residual: Option<Duration>,    // residual/error after correction
}

struct Recording {
    channel: u32,
    time: TimeEvidence,            // replaces the old TimestampPair; raw is always retained
    source_image: EvidenceId,
    source_offsets: Vec<Region>,
    parser_id: String,
    parser_version: String,
    status: RecordingStatus,       // Active | ...
    integrity: Integrity,          // Ok | Inconsistent(details) | ...
    exported_video_path: Option<PathBuf>,
}
```

`Recorder_Native_Time`, `Normalized_Timestamp`, and `Reference_Time` are three separate
classes; a correction stores its method, anchor, offset, drift, and residual without ever
mutating `raw`. Structures inconsistent with the profile are recorded in `integrity`, not
discarded.

### 8. Recovery Engine (Req 13)

The Recovery Engine owns the three-level orchestration, recovery-state classification, and
candidate-validation orchestration; it calls Parser recovery knowledge (`validate_structure`,
`recognize_candidate`) for OEM-specific decisions.

- **Level 1 — Indexed**: valid filesystem/index → recording entry → physical video.
- **Level 2 — Orphan/Slack**: metadata missing, payload remains → candidate detection →
  structural validation → recover.
- **Level 3 — Raw Carving**: metadata destroyed → windowed scan (bounded, cancellable,
  progress-reporting) → candidate video structures → frame validation → reconstruction.

Recovery classification is **two-dimensional**. `DataState` describes *what happened to the
data on the medium*; `RecoveryStatus` describes *whether the required content can still be
reconstructed*. The two are independent and are never collapsed into one value.

`DataState` (what happened on the medium):
- **Active** — valid indexed/recognized recording represented by valid storage structures.
- **Deleted** — metadata indicates deletion but recoverable content may remain.
- **Orphaned** — content remains but normal index linkage is missing.
- **Corrupted** — evidence exists but required structures/content are damaged or
  inconsistent. Corruption is **not** automatically unrecoverable.
- **Overwritten** — evidence indicates previous content has been replaced by newer content.
  Overwritten content is **never** reconstructed or fabricated.

`RecoveryStatus` (can the required content be reconstructed):
- **Recoverable** — required content can be reconstructed from available evidence.
- **PartiallyRecoverable** — some required content can be reconstructed and gaps remain.
- **Unrecoverable** — required content cannot be reconstructed from available evidence,
  including confirmed overwrite *or* insufficient remaining data.

Example: `data_state = Overwritten` with `recovery_status = Unrecoverable` means the prior
content was overwritten and therefore the required previous content is not recoverable —
both facts are retained, neither silently replaces the other.

```rust
enum DataState { Active, Deleted, Orphaned, Corrupted, Overwritten }
enum RecoveryStatus { Recoverable, PartiallyRecoverable, Unrecoverable }

struct RecoveryCandidate {
    recovery_level: RecoveryLevel,       // L1 | L2 | L3
    data_state: DataState,               // what happened on the medium
    recovery_status: RecoveryStatus,     // whether required content can be reconstructed
    source_offsets: Vec<Region>,
    validation: FrameValidationReport,   // signatures, structure, timestamps, channel, continuity
    /* provenance ... */
}
```

`DataState` and `RecoveryStatus` are **independent dimensions and must not be collapsed**.
`Overwritten` (a `DataState`) records *what happened to the medium*; its replaced content is
**never reconstructed or fabricated**. `Unrecoverable` (a `RecoveryStatus`) is a separate
determination that required content cannot be reconstructed from the available evidence,
including a confirmed overwrite **or** insufficient remaining data. An item may therefore be
`data_state = Overwritten` and `recovery_status = Unrecoverable` at the same time without one
silently replacing the other. Corruption (a `DataState`) is **not** automatically
`Unrecoverable`. Candidate frames are validated against OEM signatures, structure,
timestamps, channel, and continuity before acceptance.

### 9. Video Reconstruction (Req 14)

Does not concatenate video-looking bytes. It validates frame headers, sizes, timestamps,
channels, and sequence; uses I-frame/GOP relationships to order frames; marks gaps
(never synthesizes fill); prefers remux/transmux (FFmpeg) over re-encoding; runs a decode
test on the output and records the decode result; hashes the exported video.

**Assumption/dependency**: FFmpeg is available on the workstation for remux and the
decode test. If FFmpeg is **unavailable**, the decode/QC step assigns
`Validation_State = UNKNOWN` (required validation did not run) — or `REVIEW` where a
candidate exists but is unverified — with an explicit reason. A stage that did not run is
**never** reported as `PASS`, and frames/continuity are **never** fabricated.

### 10. Timeline & Correlation (Req 15)

The Parser performs OEM-specific extraction of timestamped recording/event information into
`TimelineEvent` candidates (`extract_timeline_events`); the Timeline_Engine owns unified
timeline construction, timestamp ordering, normalization coordination, and cross-camera
correlation. The flow is: Parser → `TimelineEvent` candidates → Timeline_Engine → unified
timeline → cross-camera correlation.

The Timeline_Engine builds the unified timeline across all cameras in a case from those
candidates. Events link to camera, their `TimeEvidence` (raw + recorder-native + normalized),
recording id, and source offsets. Ordering uses `Normalized_Timestamp` while retaining each
event's `Raw_Timestamp` and `Recorder_Native_Time`. Physical (on-disk) order, recorder-native
chronological order, and normalized chronological order are kept **distinguishable and are
never automatically equated** (Req 15.6); physical disk order is not assumed chronological.
Cross-camera correlation groups events by normalized time windows. The Parser does not
construct the final unified timeline.

### 11. AI Analytics — Optional (Req 16)

A separate Python FastAPI service invoked only on parser-validated evidence. Every finding
links to clip, recording id, camera, timestamp, source offset, parser version, and hash,
and is labeled **AI-assisted** (never absolute truth). AI is **optional**: when the AI
service is unavailable or disabled, the pipeline still completes parsing, recovery, timeline,
and reporting **without** AI findings. AI absence is **not** a forensic `Validation_State`
(it is not a PASS/REVIEW/FAIL/UNKNOWN outcome of a forensic operation). AI outputs are
`Derived_Artifacts` labeled AI-assisted and never alter or replace native evidence.

### 12. Reporting (Req 17)

Generates PDF, JSON, and CSV. Each report explicitly includes:

- case info, evidence info, and **acquisition status** (complete/partial/failed/unknown);
- **Detection_Status**, **Classification**, and **Attribution_Status**, plus the supporting
  evidence list (never a bare percentage);
- **OEM_Profile versions AND hashes** and the **profile applicability** (model/firmware/
  variant) behind each claim;
- filesystem analysis, recordings, recovered/deleted data with **DataState** and
  **RecoveryStatus** (the two dimensions shown separately);
- timeline, cross-camera events, and AI findings (labeled AI-assisted, derived);
- the **capabilities actually executed** and the **unsupported capabilities**;
- **ambiguous results, REVIEW results, and UNKNOWN results** called out explicitly;
- **validation status** (PASS/REVIEW/FAIL/UNKNOWN per operation, with reasons);
- **provenance** for every artifact, distinguishing **native vs derived**;
- source offsets, parser versions, chain of custody, and an explicit **limitations** section.

Each report is SHA-256 hashed and its provenance recorded. The report **SHALL NOT present
profile-only knowledge as reconstruction support** (Req 17.6): a capability that exists only
as profile/research knowledge is never rendered as if it were evidence of an actual
reconstruction.

### 13. UI & Hex Viewer (Req 18)

React + TypeScript (Vite, Tailwind, shadcn/ui used restrained, TanStack Table, Recharts
where needed). Navigation: Case, Evidence, Acquisition, Detection, Parsing, Recovery,
Timeline, Evidence/Provenance, Reports.

The **primary/overview screen** shows (Req 18.7): case, evidence name, SHA-256 hash,
evidence size, analysis status, OEM/storage candidates, confidence, the evidence supporting
detection, OEM_Profile version, and warnings. Detection screens show the supporting evidence
list, never only a percentage. The examiner drills: OEM result → evidence item → source
offset → hex bytes.

The **Capability Matrix** shows, per OEM, the **five Capability_Stage dimensions**
(Detection, Profiling, Parsing, Reconstruction, Validation) as
`NOT_IMPLEMENTED | PARTIAL | IMPLEMENTED`, rendered **separately** from each operation's
**Validation_State** (`PASS | REVIEW | FAIL | UNKNOWN`). The two axes are never merged and a
Validation_State is never rendered as a maturity stage (Req 18.9, 21, 22). The UI never shows
only "Supported".

The **Hex Viewer** renders offset, hex bytes, ASCII, the selected evidence range, and
interpretation. Selecting an `Evidence_Item` follows the flow **`Evidence_Item → evidence_id
→ offset → length → EvidenceReader → original bytes`**, reading **directly through the
`EvidenceReader` against the source evidence** (never from an exported copy when the source is
available) so the examiner verifies the claim against original bytes. The **frontend never
reads arbitrary filesystem paths** — all byte access goes through the API/`EvidenceReader`,
which resolves an evidence id + offset + length; the UI cannot open a path directly.

Visual style: light neutral background, charcoal text, thin borders, restrained blue
accents, compact tables, clear typography. No neon, gradients, glassmorphism, glowing
cards, chatbot/AI graphics, or unnecessary animation.

## Data Models

PostgreSQL stores **metadata only**; **no multi-TB media in the DB**. The schema is fully
relational with foreign keys so every requirement is queryable. Core tables (FKs noted):

```
cases(id, name, created_by, created_at, ...)

acquisitions(id, status,                       -- complete|partial|failed|unknown (Req 7.7–7.9, 23)
             tool, tool_version,
             map_reference, map_hash,
             bad_sector_ranges JSONB, unresolved_ranges JSONB,
             verification_status,               -- PASS|REVIEW|FAIL|UNKNOWN
             verification_reason)

evidence(id, case_id → cases.id,
         source_device, acquisition_time, capacity_bytes,
         image_format, acquisition_tool, acquisition_tool_version,
         sha256, responsible_examiner, storage_path,
         source_state,                          -- read_only|read_write|unknown (Req 1.8)
         acquisition_id → acquisitions.id)      -- separate acquisitions table (preferred)

source_safety_reports(id, evidence_id → evidence.id,
         source_state, decision, reason, inspected_at)     -- Req 1.8–1.12

detection_results(id, evidence_id → evidence.id,
         oem, storage_family,
         detection_status,                      -- from the Detector (DetectorOutput)
         attribution_status,                    -- WRITTEN BY THE CONFIDENCE_ENGINE, not the detector
         classification, confidence, margin,    -- written by the Confidence_Engine
         validation_state,                      -- PASS|REVIEW|FAIL|UNKNOWN
         profile_version, profile_hash,         -- BOTH persisted
         created_at)

evidence_items(id, detection_result_id → detection_results.id,
         source_evidence_id → evidence.id,
         kind, offset, length,
         observed, expected,                    -- BOUNDED snippets, not payloads
         rule_match_status,                     -- Match|Mismatch|Partial|Absent
         evidence_status,                       -- validated|provisional|model_specific|firmware_specific|unvalidated
         score_contribution, explanation,
         profile_version, profile_hash, applicability JSONB)

parser_runs(id, evidence_id → evidence.id, parser_id, parser_version,
            profile_version, profile_hash, status, validation_state, ...)

recordings(id, parser_run_id → parser_runs.id, channel,
           raw_ts, recorder_native_ts, normalized_ts, reference_ts,
           timezone_state, normalization_method, clock_correction JSONB,
           source_offsets → source_regions, status, integrity,
           exported_video_path, sha256)

recovery_candidates(id, evidence_id → evidence.id,
                    recovery_run_id → recovery_runs.id,        -- FK to the bounded run
                    recovery_level, data_state, recovery_status,
                    source_offsets → source_regions, validation JSONB, sha256)

recovery_runs(id, evidence_id → evidence.id,
              searched_regions JSONB, searched_bytes,
              skipped_ranges JSONB, candidate_count, rejected, accepted,
              hypothesis_count, truncated, cancelled,
              validation_state, reason)                        -- Req 13.9–13.10

timeline_events(id, case_id → cases.id, camera, recording_id → recordings.id,
                raw_ts, recorder_native_ts, normalized_ts, source_offsets → source_regions)

ai_findings(id, recording_id → recordings.id, kind, camera, timestamp,
            source_offset, parser_version, hash, label, confidence)   -- Derived_Artifacts

artifacts(id, evidence_id → evidence.id,
          kind,                                 -- 'native' | 'derived' (queryable)
          derived_kind,                         -- e.g. elementary_stream|remux|review_copy|ai (NULL for native)
          provenance_id → provenance.id, output_hash)

provenance(id, source_evidence_id → evidence.id, source_hash,
           source_regions → source_regions, producing_component, component_version,
           oem_profile_version, oem_profile_hash, parser_version, recovery_level,
           output_hash, transformation_history JSONB, validation_state)   -- Req 5.8–5.9

validation_corpus(id, case_id, source_hash,
                  expected_detection, expected_detection_status, expected_classification,
                  expected_attribution_status, expected_regions JSONB,
                  expected_parser_state, expected_recovery_state, expected_validation_state,
                  expected_warnings JSONB, provenance JSONB, synthetic BOOLEAN)   -- Req 19.10–19.11

capability_stages(id, oem_key,
                  detection_stage, profiling_stage, parsing_stage,
                  reconstruction_stage, validation_stage)      -- NOT_IMPLEMENTED|PARTIAL|IMPLEMENTED (Req 3.6–3.7, 21)

validation_states(id, subject_type, subject_id, operation, state, reason)  -- PASS|REVIEW|FAIL|UNKNOWN (Req 22)

chain_of_custody(id, case_id → cases.id, timestamp, examiner, action, artifact, result)

hashes(id, artifact_type, artifact_id, algo, value, computed_at,
       status, duration_ms, bytes_hashed)

profiles(id, oem_key, profile_id, profile_version, schema_version, profile_hash, loaded_at)

confidence_configs(id, config_version, config_hash, threshold, min_margin, min_quality,
                   validation_factors JSONB, quality_factors JSONB, loaded_at)

source_regions(id, artifact_type, artifact_id, evidence_id → evidence.id,
               start_offset, length, region_type)
```

**Structured vs JSONB.** Values that need forensic querying are normalized into tables
rather than buried in JSON. In particular, `source_offsets` is promoted to the
`source_regions` table so an examiner can query **"what bytes X..Y of evidence E produced
this artifact/evidence item"** across detection items, recordings, recovery candidates,
provenance, and timeline events. Non-queried blobs (e.g. a detector's `validation` detail,
free-form notes) may remain JSONB. `evidence_items.observed`/`expected` store **bounded**
byte snippets, not payloads.

**Attribution ownership in the schema.** `detection_results.attribution_status`,
`classification`, `confidence`, and `margin` are **written by the Confidence_Engine**, not
the detector; only `detection_status` originates from the Detector's `DetectorOutput`. Both
`profile_version` **and** `profile_hash` are persisted so every claim cites the exact profile.

**Native vs derived is queryable.** `artifacts.kind` distinguishes `native` from `derived`
and each row links to a `provenance` row, so an examiner can query native-vs-derived lineage
and confirm a native artifact was never replaced by a derived copy.

**Frontend byte access.** The frontend **never accesses arbitrary filesystem paths**; the Hex
Viewer reads bytes **only** through the API/`EvidenceReader` (resolving `evidence_id → offset
→ length`), never by opening a path directly.

Storage layout: `evidence` rows point to read-only files in the evidence directory (held
under application-level immutability, not an OS/hardware immutability guarantee); derived
artifacts (exported video, reports) live in a separate artifacts directory, never inside the
evidence directory.

## Error Handling

Malformed or corrupted evidence is treated as **data, not failure**. The system never
panics on bad bytes and never fabricates content to recover from an error.

- **Core crates** return `Result<T, ForensicError>` (thiserror). Variants cover:
  `Io`, `OutOfBounds`, `UnsupportedFormat`, `ProfileInvalid`, `CorruptStructure`,
  `WriteDenied`, `DecodeFailed`, `Cancelled`.
- **Corruption/inconsistency** encountered during detection becomes an `EvidenceItem`
  with `rule_match_status = Mismatch/Partial`; during parsing it becomes a `Recording`
  integrity flag; during recovery it maps to a `DataState` such as `Corrupted` with a
  separate `RecoveryStatus` (corruption is not automatically `Unrecoverable`). None of these
  are surfaced as crashes.
- **Write attempts against evidence** return `WriteDenied` and emit a `write_denied`
  chain-of-custody event (Req 1.4).
- **Cancellation** of long operations returns `Cancelled` with progress preserved so the
  UI can report partial completion.
- **AI service unavailable or disabled**: AI is optional, so the pipeline completes
  parsing, recovery, timeline, and reporting **without** AI findings (Req 16.5) rather than
  failing. AI absence is not a forensic `Validation_State`.
- **API layer** maps `ForensicError` to structured problem responses; it never leaks
  internal panics. Long operations return a job id and stream progress/error events.

## Correctness Properties

These invariants are the basis of the property-based tests and must hold for all inputs.

### Property 1: Read-only invariant
No code path obtains a writable handle to evidence; any write attempt is denied and logged.
Evidence bytes are identical before and after any operation (verified by re-hashing).

**Validates: Requirements 1.1, 1.4**

### Property 2: Bounded memory
`read_at` and `RegionScanner` never allocate memory proportional to total evidence size;
peak memory stays under the configured window cap regardless of image size.

**Validates: Requirements 8.2, 8.3**

### Property 3: Read fidelity
For any in-bounds `(offset, len)`, `read_at` returns exactly the underlying bytes;
concatenating sequential windowed reads equals a single read of the same range.

**Validates: Requirements 8.1, 8.2**

### Property 4: Determinism
Identical determinism inputs — evidence bytes/hash, OEM_Profile version+hash,
ConfidenceConfig version+hash, recovery configuration, and relevant parser/component
versions — produce identical `Forensic_Result`s (classification, evidence items, offsets,
confidence scores, recovery states); detector/parser execution order and thread scheduling
never affect results. Environment-dependent metadata (timestamps, DB IDs, temp paths,
durations) is excluded from the comparison.

**Validates: Requirements 9.1, 9.5, 20.1, 20.3, 20.4**

### Property 5: Evidence independence
One detector's evidence collection is never mutated by another detector.

**Validates: Requirements 9.5**

### Property 6: Confidence honesty
When the top-two margin is below `min_margin`, classification is never `Confirmed`; a single
magic match never yields `Confirmed`; absence of credible evidence yields `Unknown` rather
than a guessed OEM.

**Validates: Requirements 2.3, 10.2, 10.3**

### Property 7: Attribution honesty
`attribution_status = confirmed` requires OEM-exclusive evidence; otherwise
`compatible_candidate` or `unknown` (CP Plus is never "confirmed" without exclusive
evidence).

**Validates: Requirements 2.4**

### Property 8: Timestamp preservation
Normalization never mutates the raw timestamp; the raw value is always recoverable and
stored alongside the normalized value. `Recorder_Native_Time`, `Normalized_Timestamp`, and
`Reference_Time` are distinct classes and none overwrites another; an unknown timezone stays
`Unknown` and is never silently treated as UTC.

**Validates: Requirements 4.1, 4.2, 4.3, 4.5, 4.6**

### Property 9: No fabrication
`Overwritten` data (a `DataState`) is never reconstructed regardless of `RecoveryStatus`;
video gaps are marked and never filled with synthesized frames. `DataState` and
`RecoveryStatus` are never collapsed into one value.

**Validates: Requirements 13.3, 14.3**

### Property 10: Provenance completeness
Every derived artifact resolves to source image, source offsets, producing component +
version, profile version(s), and an output hash.

**Validates: Requirements 5.2, 5.4**

## Testing Strategy

Per OEM, corpora of **known-good, known-negative, corrupted, partial, and false-positive**
fixtures. Because real evidence cannot be committed, a **synthetic fixture generator**
produces small deterministic images embedding profile-shaped structures so tests run in CI
without real HDDs. A random image containing a lone magic value must **not** pass OEM
detection (guards Req 2.3 / confidence engine).

Measured benchmarks (recorded for review): detection accuracy, false-positive rate,
false-negative rate, parsing success rate, recovery rate, false recovery rate, timestamp
accuracy, throughput, and memory use.

Additional required tests (Req 19.6–19.8, Req 20). These specifically guard against
**false forensic attribution** and unsafe reads:

- **Read-only enforcement**: an attempted write to evidence is denied and logged.
- **Determinism**: identical input + profile version yields identical *forensic results*
  (excluding timestamps, DB IDs, paths, durations).
- **Bounded memory**: reading/scanning a large sparse image stays under a memory cap.
- **Lone magic value**: a single magic value never yields `Confirmed` attribution, does not
  by itself establish `CompatibleCandidate`, and is classified as `Insufficient` or
  `Unknown` according to the classification rules.
- **Magic at incorrect offset**: rejected, not attributed.
- **Valid signature with corrupted surrounding structure**: quality lowered, not confirmed.
- **Overlapping OEM signatures**: resolved via margin/quality, not first-match.
- **Ambiguous confidence**: classified `Ambiguous`, no winner picked.
- **Unknown filesystem**: classified `Unknown`, not forced to an OEM.
- **Truncated image**: handled without panic; partial results flagged.
- **Sparse image**: bounded memory holds.
- **Out-of-bounds reads**: rejected with `OutOfBounds`.
- **Cancellation**: long operation stops and reports `Cancelled`.
- **Write attempt**: denied + logged.
- **Profile version change**: recorded; results reference the new version.
- **Deterministic repeated analysis**: repeated runs match on forensic fields.
- **Overwritten recovery candidate**: `data_state = Overwritten` with
  `recovery_status = Unrecoverable`, never reconstructed; the two dimensions are not
  collapsed.
- **Fragmented recording**: reassembled or gap-marked, never fabricated.
- **Missing video frames**: gaps marked, no synthesized frames.

### Property-Based Testing (targeted)

Property tests are valuable where inputs are combinatorial and invariants are strong:

- **EvidenceReader**: for any `(offset, len)` within bounds, `read_at` returns exactly the
  underlying bytes and never reads out of bounds; concatenated windowed reads equal a
  direct read of the same range.
- **Confidence engine**: classification is monotonic and margin-respecting — if the margin
  is below `min_margin`, the result is never `Confirmed`; permuting detector input order
  never changes the classification (determinism/independence).
- **Timestamp model**: normalization never mutates the raw value; `raw` is always
  recoverable from a `TimeEvidence`, and an unknown timezone stays `Unknown` (never UTC).
- **Recovery classification**: an `Overwritten` `DataState` never yields reconstructed
  content; `DataState` and `RecoveryStatus` remain independent and are never collapsed; a
  `Corrupted` `DataState` is never forced to `Unrecoverable`.

Deterministic example-based tests cover the per-OEM pipelines against fixtures; PBT covers
the invariants above.

## Requirements Changes (APPLIED)

The following changes have been **applied** to `requirements.md`. Exact criteria are listed
so the change history is explicit, never silent.

| # | Requirement(s) affected | Change |
|---|---|---|
| C-1 | 9.3, new 2.6 | Attribution_Status field + confirmed-only-with-exclusive-evidence |
| C-2 | new 10.5–10.7 | Deterministic weighted model; score≠confidence≠classification; constants in config |
| C-3 | 7.2, new 7.6 | Acquisition tool + version (optional) |
| C-4 | new Req 20 | Bounded forensic-result determinism |
| C-5 | 13.2–13.8 | Two-dimensional model: DataState (5) + RecoveryStatus (3); overwritten≠unrecoverable; corrupted≠unrecoverable |
| C-6 | 12.1, new 12.5, 3.5 | Parser/Recovery boundary; parser never makes final attribution |
| C-7 | Introduction | "Forensically defensible" wording; no admissibility guarantee |
| C-8 | new 19.6–19.8 | Adversarial tests + synthetic fixtures |
| C-9 | new 5.6–5.7 | Hash status/bytes/duration; streaming hashing |
| C-10 | 1.6, 1.7 | OS-handle read-only primary; software ≠ hardware write blocker |
| C-11 | 8.1, new 8.8 | Raw formats first; E01 planned integration |
| C-12 | 11.5, 11.6 | Evidence_Status required on every profile signature/rule |
| C-13 | 18.4, new 18.6, 18.7 | Hex viewer reads source via EvidenceReader; overview fields |

Change-history detail (all APPLIED). In each entry below, "Current" describes the
pre-change state and the quoted text is the wording that has **already been applied** to
requirements.md — it is not pending.

### C-1 — Generalized OEM attribution status (Req 9.3, new Req 2.6)
- **Current**: Req 9.3 lists "OEM, storage family, confidence score, status, ..."; Req 2.4
  handles CP Plus as a special case only.
- **Problem**: Attribution honesty is not a first-class field for all OEMs.
- **Applied text**: Req 9.3 → *"THE Detector_Output SHALL include the OEM candidate, storage
  family, Detection_Status, evidence list, candidate regions, warnings, and OEM_Profile
  version; THE Detector_Output SHALL NOT include a final Attribution_Status, confidence
  score, or Classification."* New Req 9.6 → the Confidence_Engine combines each Detector_Output
  into a Classified_Detection_Result carrying the confidence, Classification, and
  Attribution_Status. Add Req 2.6 → *"THE Confidence_Engine SHALL set Attribution_Status to
  `confirmed` only WHERE OEM_Exclusive_Evidence is present; otherwise THE Confidence_Engine
  SHALL use `compatible_candidate` or `unknown`; THE Detector SHALL NOT set the final
  Attribution_Status."*
- **Reason**: Encodes "prefer UNKNOWN over WRONG OEM" across all OEMs.

### C-2 — Confidence scoring model made explicit (Req 10)
- **Current**: Req 10 requires threshold + margin + evidence quality but no model.
- **Problem**: `score`, `confidence`, and `classification` are not distinguished.
- **Applied text**: Add Req 10.5 → *"THE Confidence_Engine SHALL compute a deterministic
  weighted-evidence score per OEM, SHALL normalize it to a confidence in the range 0..1,
  and SHALL derive a classification distinct from the score and confidence. THE
  Confidence_Engine SHALL read all scoring constants from profile or configuration data."*
- **Reason**: Makes the model testable and keeps constants out of source.

### C-3 — Record acquisition tool and version (Req 7.2)
- **Current**: Req 7.2 records source device, acquisition time, capacity, image format.
- **Problem**: Chain of custody benefits from the acquiring tool + version.
- **Applied text**: Req 7.2 → *"WHEN an Examiner adds an HDD image to a case, THE
  Case_Manager SHALL record the source device, acquisition time, capacity, and image
  format, and SHALL record the acquisition tool and acquisition tool version WHERE
  provided."* (Optional when unknown.)
- **Reason**: Strengthens provenance/defensibility.

### C-4 — Determinism requirement, bounded (new Req 20)
- **Current**: none.
- **Problem**: Determinism is a design goal but not a requirement, and must exclude
  environment-dependent metadata.
- **Applied text**: New Req 20 → *"WHERE evidence bytes and OEM_Profile versions are
  identical, THE Platform SHALL produce identical forensic results (detection
  classification, evidence items, offsets, confidence scores, recovery states). THE
  Platform SHALL NOT be required to reproduce artifact metadata that is inherently
  environment-dependent (timestamps, database identifiers, file paths, run durations)."*
- **Reason**: Reproducibility that is testable and honest about metadata.

### C-5 — Complete recovery data-state enumeration + definitions (Req 13.2, new Req 13.6)
> **Superseded**: the single six-value enum below was later refined into the
> **two-dimensional** model (DataState + RecoveryStatus) described in the Recovery Engine
> section and Req 13.2–13.8. The text below is retained only as change history.
- **Current**: Req 13.2 lists deleted, orphaned, corrupted, overwritten.
- **Problem**: `active` and `unrecoverable` missing; overwrite/unrecoverable undefined.
- **Applied text**: Req 13.2 → *"WHEN recovering data, THE Recovery_Engine SHALL classify
  each item as one of `active`, `deleted`, `orphaned`, `corrupted`, `overwritten`, or
  `unrecoverable`."* Add Req 13.6 → *"THE Recovery_Engine SHALL mark data `overwritten`
  WHERE physical evidence indicates prior content has been replaced, and `unrecoverable`
  WHERE required evidence is unavailable (confirmed overwrite or insufficient remaining
  data); THE Recovery_Engine SHALL NOT treat corruption as automatically unrecoverable."*
- **Reason**: Aligns model with recovery architecture; prevents overclaiming loss.

### C-6 — Parser/Recovery responsibility boundary (Req 12.1)
- **Current**: Req 12.1 says the Parser exposes "deleted-data recovery."
- **Problem**: Conflicts with the separate Recovery Engine in the design.
- **Applied text**: Req 12.1 → *"THE Parser SHALL expose operations for filesystem,
  metadata, recording/index interpretation, OEM-specific structural validation, and
  OEM-specific recovery knowledge through a common interface. THE Recovery_Engine SHALL own
  recovery-level orchestration (L1/L2/L3), recovery-state classification, and
  candidate-validation orchestration, invoking Parser recovery knowledge as needed."*
- **Reason**: Clean separation of OEM knowledge vs recovery orchestration.

### C-7 — "Court-admissible" wording (Introduction)
- **Current**: Introduction says "court-admissible forensic reports."
- **Problem**: Software cannot guarantee legal admissibility.
- **Applied text**: Replace with *"forensically defensible reports with documented
  provenance, integrity, limitations, and chain of custody."*
- **Reason**: Accurate claim.

### C-8 — Expanded adversarial tests + fixtures (new Req 19.6, 19.7)
- **Current**: Req 19 lists corpora + benchmarks.
- **Applied text**: Add Req 19.6 → *"THE Platform SHALL include tests for lone magic
  value, magic value at incorrect offset, valid signature with corrupted surrounding
  structure, overlapping OEM signatures, ambiguous confidence, unknown filesystem,
  truncated image, sparse image, out-of-bounds reads, cancellation, write attempt, profile
  version change, deterministic repeated analysis, overwritten recovery candidate,
  fragmented recording, and missing video frames."* Add Req 19.7 → *"THE Platform SHALL
  provide a synthetic fixture generator so tests run without real evidence."*
- **Reason**: Directly guards against false attribution and unsafe reads.

### C-9 — Hash operation metadata (new Req 5.6)
- **Current**: Req 5 hashes evidence/exports but records only hash + value.
- **Applied text**: Add Req 5.6 → *"THE Hashing_Service SHALL record hash status, hash
  duration, and bytes hashed for each hash operation."*
- **Reason**: Auditable hashing over multi-TB images.

### Note — Requirement numbering
- The claimed duplicate "Requirement 13" does not exist in the current `requirements.md`
  (Req 13 = Multi-Level Recovery, Req 14 = Video Reconstruction). **No renumbering needed.**

## Key Architecture Decisions (confirmed)

1. **Profile format**: TOML; every signature/rule carries a required `evidence_status` field
   (`validated|provisional|model_specific|firmware_specific|unvalidated`). `Evidence_Status`
   is the single canonical concept; "basis" is prose only, never a separate field.
2. **DB access**: `sqlx` + PostgreSQL; `source_regions` normalized for queryable offsets;
   JSONB only for non-queried blobs.
3. **AI boundary**: HTTP to an optional Python FastAPI service; graceful degradation.
4. **Confidence**: deterministic weighted-evidence model; constants in profile/config;
   `score` ≠ `confidence` ≠ `classification`.
5. **Read-only**: no write API + read-only OS handles (primary), WriteGuard + COC logging
   (secondary); hardware write blocking out of scope.
6. **Responsibility split**: Parser (OEM knowledge) / Recovery Engine (orchestration +
   states) / Video Reconstructor (frame assembly).

## Open Items to Confirm

1. **.E01**: select and license-verify a Rust EWF library (read-only, segmented,
   compressed, error handling). Until confirmed, E01 is a **planned integration** and Phase
   1 ships `.raw/.dd/.img`.
2. **Max read window size**: configurable constant (proposed default 8–64 MiB).
3. **FFmpeg**: runtime dependency for remux + decode test (Phase 4).

---

# Final Engineering Specification Extensions

The sections below extend the approved architecture (they do not replace it) to form the
final implementation baseline. Supported target OEMs are **Dahua, Hikvision, Honeywell,
CP Plus/UBS, and Uniview**. TP-Link, Godrej, and Matrix remain future/extensible and are
**not** implemented. Everything here is *specified/designed/planned/research-backed*, not
claimed as implemented.

## Capability Maturity Model

Capability is tracked as five independent stages, never a single "supported" boolean:

```
Detection → Profiling → Parsing → Reconstruction → Validation
```

- **Detection** — "What storage/OEM is this?" (evidence-backed candidate/attribution).
- **Profiling** — "What is the topology/geometry/region structure?"
- **Parsing** — "How are metadata/index/recordings represented?"
- **Reconstruction** — "Can physical evidence be assembled into recordings?"
- **Validation** — "Did reconstruction pass structural/time/codec/integrity checks?"

Each of the five dimensions carries an independent **Capability_Stage** maturity value from
`{NOT_IMPLEMENTED, PARTIAL, IMPLEMENTED}`, set from implemented capability only and never
advertised higher than reality. Example (illustrative, not a claim of completion):
Hikvision → Detection: IMPLEMENTED, Profiling: IMPLEMENTED, Parsing: PARTIAL,
Reconstruction: NOT_IMPLEMENTED, Validation: PARTIAL.

**Capability_Stage is distinct from Validation_State.** Capability_Stage
(`NOT_IMPLEMENTED | PARTIAL | IMPLEMENTED`) describes *implementation maturity*.
Validation_State (`PASS | REVIEW | FAIL | UNKNOWN`) describes the *outcome of a specific
operation*. A stage value is never rendered as PASS, and a validation outcome is never
rendered as a maturity stage. The UI and reports keep the two separate.

## Source Safety

Before parsing a physical block device, the Platform inspects the source state and records
`Source_State ∈ {read_only, read_write, unknown}`. By default it **rejects**: mounted
write-enabled sources, writable block sources, and unsafe source states, producing a visible
failure rather than silently proceeding. It records the source state, the safety decision,
and the reason in the Chain_Of_Custody. Hardware write blockers are preferred; **software
controls do not replace them** and hardware write blocking is out of scope.

**Concrete inspection model/API (Req 1.8–1.12).**

```rust
enum SourceState { ReadOnly, ReadWrite, Unknown }
enum SafetyDecision { Accepted, Rejected }

struct SourceSafetyReport {
    source_state: SourceState,   // read_only | read_write | unknown
    decision: SafetyDecision,    // accepted | rejected
    reason: String,
    inspected_at: DateTime<Utc>,
}

/// Runs BEFORE analysis for physical block devices. Rejects read_write or
/// mounted/write-enabled sources by default with a VISIBLE failure.
fn inspect_source(source: &Source) -> SourceSafetyReport;
```

`inspect_source` runs **before** any analysis of a physical block device. A `read_write`,
mounted, or write-enabled source is **rejected by default** with a visible failure (never a
silent proceed); the resulting `{source_state, decision, reason}` is recorded in the
`Chain_Of_Custody`. Where the state cannot be determined it is `Unknown` and **`Unknown` is
never reported as `read_only`**.

Three separate things are distinguished and never conflated:
- **(a) read-only OS handle** — how *this process* opened the source (a software guarantee
  about this process only);
- **(b) actual source safety state** — the observed `Source_State` of the underlying source
  (`read_only`/`read_write`/`unknown`), which may differ from (a);
- **(c) hardware write blocking** — a physical device in the acquisition chain. This is
  **out of scope**; software never claims to replace a hardware write blocker.

## Storage Topology Profiler

A common topology profiler identifies, where applicable: MBR, GPT, partitions,
unpartitioned regions, filesystem signatures, raw regions, and candidate OEM regions. Key
rules: **partition ≠ sector**, **partition ≠ OEM**, **filesystem ≠ recording storage**. A
partition establishes only a *candidate region*. The profiler never mounts proprietary DVR
storage. Its outputs are candidate regions with provenance, consumed downstream by
detectors/parsers.

## Bounded Scanning

`RegionScanner` performs all scanning with explicit bounds: `start`, `length`, `window
size`, `alignment`, `cancellation`, `progress`, and `candidate limits`. Every scan records
the searched range, searched bytes, skipped ranges, and a termination reason. **If scanning
is truncated, the associated validation is `REVIEW`** (no global-optimum claim). Scanning
never allocates memory proportional to total image size.

## OEM Forensic Detection and Parsing Implementation Specification

This specification describes detector/parser flows per OEM. All OEM-specific values live in
versioned OEM_Profile data with an `evidence_status`; none are hard-coded as authoritative
facts. Detectors produce evidence and never confirm on a lone magic value; parsers never
decide final OEM attribution.

### Dahua

Reference (treated as a reference, not automatic forensic truth):
`https://github.com/dw2102/X-Ways-DHFS4_1-X-Tension.git`.

**Detector flow:** candidate search → DHFS / DHFS 4.1 evidence → surrounding structure →
structural validation → size/boundary validation → metadata/index → DHAV/frame evidence →
confidence. The design explicitly distinguishes **DHFS/storage structure** from
**DHAV/video structure**; **DHAV alone must not establish Dahua**.

**Parser flow:** filesystem → metadata → recording/index → physical video → DHAV/frame
validation → recordings.

**Edge cases:** lone magic, wrong offset, corrupted filesystem, invalid size, boundary
mismatch, fragmented recording, deleted, orphaned, missing frames, overwritten, truncated
image, conflicting OEM signatures.

**Evidence status:** DHFS, DHFS 4.1, DHAV, and 512/1024/2048 candidate offsets are
`provisional` (offsets are search strategies, not universal rules) until validated.

### Hikvision

Reference: `https://github.com/akira7799/hikvision-dvr-parser.git`.

**Detector flow:** candidate → surrounding structure → header → size/offset → frame
structure → boundary → next-frame consistency → timestamp → channel plausibility → payload
→ confidence. Boundary reasoning: `start + size = expected boundary`. A boundary mismatch
does **not** automatically mean non-Hikvision (possible causes: corruption, fragmentation,
overwrite, missing data) — it affects confidence via evidence items.

**Parser flow:** storage structures → metadata → HIKBTREE/other applicable index structures
→ recording → frame/video. Unsupported HIKBTREE variants are **not** claimed as universally
implemented.

**Edge cases:** lone magic, wrong offset, corrupted structure, invalid size, boundary
mismatch, fragmented, deleted, orphaned, missing frames, overwritten, truncated, conflicting
OEM signatures.

**Evidence status:** all illustrative byte signatures and frame-layout examples are
`unvalidated`/`provisional`; no illustrative bytes are hard-coded.

### Honeywell

Reference: supplied/internal Honeywell research/parser source.

**Core concept: `partition != sector`.** A sector is an addressing unit; a partition is a
region of storage. **Sector size is not universally 512.**

**Practical flow:**

```
HDD / image
  → partition metadata/table where available
  → determine sector size (NOT assumed 512)
  → partition start sector
  → start_sector × sector_size
  → absolute byte offset
  → candidate Honeywell region
  → Honeywell structural validation
  → metadata / index
  → recording structures
  → confidence
  → Honeywell parser
```

**Non-assumptions (mandatory):**
- Do **not** assume sector size = 512 universally.
- Do **not** assume the largest partition is Honeywell (**largest-partition-is-not-proof**).
- Do **not** treat a partition as proof of Honeywell (partition = candidate region only).

**No partition table:** do not crash, do not fabricate a partition table; use only supported
alternative candidate strategies from the profile.

**Bounds/arithmetic:** compute the absolute byte offset with checked arithmetic; if
`start_sector × sector_size` falls outside the evidence, return `OutOfBounds`.

**Parser flow:** candidate region → Honeywell storage/filesystem structures → metadata/index
→ recording structures → timestamps/channels → physical recording. The detector/profiler
performs the candidate handoff to the parser.

**Edge cases:** no partition table, multiple partitions, unpartitioned region, non-512
sector, invalid sector size, invalid partition, partition beyond image, largest partition
not Honeywell, corrupted metadata, missing index, deleted, orphaned, fragmented, missing
frames, overwritten, truncated, conflicting OEM candidates.

**Evidence status:** observed partition/layout characteristics are `model_specific` /
`provisional`, not universal rules.

### CP Plus / UBS

Reference: existing CP Plus firmware reverse-engineering work (e.g. CP-VNR-3104).

Candidate values from current research — `0x20170502`, `0x20131031`, `0x5050`, `0x1357`,
and page-size observations `4096` / `8192` — are **NOT universal facts**. They are marked
`provisional` / `model_specific` / `firmware_specific` / `unvalidated` as applicable.

**Detector flow:** UBS candidate → superblock → page-size validation → CRC/consistency →
recording database/index → packet validation → confidence.

**Final attribution:** **"UBS storage / CP Plus-compatible candidate"** unless
OEM-exclusive evidence exists. A matching UBS signature (including `0x20170502`) never alone
yields "CP Plus confirmed"; USB/UBS storage is not equated with confirmed CP Plus.

**Parser flow:** UBS storage → superblock → page/storage structures → recording DB/index →
recording metadata → video.

**Edge cases:** lone magic, wrong offset, CRC failure, corrupt superblock, invalid page
size, incomplete DB, deleted index, orphan payload, fragmentation, missing frames,
overwrite, unknown firmware.

### Uniview

Reference: existing Uniview reverse-engineering research involving `disktool`, `super`,
`super-data`, super-block validation, the storage-region vocabulary, `EcPortId`, timestamp
metadata, `DI`, `MP_MAIN_IDX_S`-style index, timestamp-to-block mapping, `DATA` region, and
recovery/index behavior.

Uniview is a **current first-class target OEM; its implementation maturity is tracked
per-dimension via Capability_Stage, and being a target OEM is NOT a claim of completed
implementation.** Established research vocabulary includes:
`super`, `ui-ctl`, `ui-data`, `di`, `flow`, `data`; `super`/`super-data`; super-block
validation; magic/version observations; timestamp metadata; `EcPortId`; timestamp-to-block
mapping; `MP_MAIN_IDX_S`-style index; and `DATA` recording region. Candidate values observed
include `0x1367` and `0x1587` — these **MUST NOT** be treated as universal signatures
(profile-controlled, non-`validated` until confirmed).

**Detector flow:**

```
HDD / image
  → read-only
  → bounded initial scan
  → super / super-data candidate
  → candidate magic / version
  → surrounding metadata
  → timestamp validation
  → EcPortId validation where applicable
  → structural validation
  → evidence
  → confidence
```

**Initial scan:** a 16 KiB initial read may be used as a bounded strategy **where supported
by the applicable profile/research**. `16 KiB = 16384 bytes`; with `sector size = 512`,
`16384 / 512 = 32 sectors`. **16 KiB is NOT a universal rule for all Uniview devices.** The
profile controls the initial scan range, alignment, expected structures, and applicability.

**Timestamp:** timestamp evidence is **corroborating** evidence. Validate year, month, day,
hour, minute, second according to the actual profile encoding. Do not invent a timestamp
encoding.

**EcPortId:** research indicates a conceptual form `ChannelNumber#DeviceId`, e.g.
`00000#EC1001`. This example is **NOT** an unconditional signature; validate using profile
rules. `EcPortId` is corroborating evidence.

**Storage regions:** document `super`, `ui-ctl`, `ui-data`, `di`, `flow`, `data`. Do not
invent universal absolute boundaries; region boundaries are profile/model/firmware dependent
where necessary.

**DI / index:**

```
requested timestamp → DI/index → index entry → timestamp + block_offset
  → physical storage → DATA → recording
```

The `MP_MAIN_IDX_S`-style structure is research-derived and remains profile-controlled
unless validated across variants.

**Parser flow:** detection → super metadata → identify regions → DI/index → timestamp→block
→ DATA → video payload → frame validation → Recording.

**Recovery interaction:** L1: index → recording → data. L2: missing linkage → orphan payload
→ validate. L3: metadata unavailable → bounded carving → frame validation.

**Edge cases:** missing superblock, wrong magic location, lone magic, corrupted super
metadata, invalid timestamp, missing EcPortId, invalid EcPortId, model mismatch, firmware
mismatch, region inconsistency, missing DI, orphan DATA, fragmented recording, missing
frames, corrupted frames, overwrite, truncated image, out-of-bounds block, multiple
candidates, conflicting OEM signatures, unknown variant.

**Evidence status:** `super`/region vocabulary, `EcPortId` form, `MP_MAIN_IDX_S`-style
index, and candidate values `0x1367`/`0x1587` are `provisional` and
`model_specific`/`firmware_specific` where applicable; none are universal until validated.

## Recovery Engine (Expanded)

Levels: **L1 index-driven**, **L2 orphan/slack**, **L3 raw carving**. Recovery uses bounded
adversarial search. Every recovery run records: search bounds, candidate count, rejected
candidates, accepted candidates, ambiguity, truncation, and validation status. If the
algorithm explores only a bounded search space, it **does not claim a global optimum** and
reports `REVIEW`. DataState and RecoveryStatus remain independent (per the approved model);
overwritten content is never reconstructed.

**Concrete bounds/run structs (Req 13.9–13.10).**

```rust
struct RecoveryBounds {
    max_scan_bytes: u64,
    max_scan_regions: u32,
    max_candidates: u32,
    max_hypotheses: u32,
    max_search_depth: Option<u32>,
    cancel: CancelToken,
    time_limit: Option<Duration>,
}

struct RecoveryRun {
    searched_regions: Vec<Region>,
    searched_bytes: u64,
    skipped_ranges: Vec<Region>,
    candidate_count: u32,
    rejected: u32,
    accepted: u32,
    hypothesis_count: u32,
    truncated: bool,
    cancelled: bool,
    validation_state: ValidationState,   // PASS | REVIEW | FAIL | UNKNOWN
    reason: String,
}
```

A deliberately **bounded** search that did not explore the full space sets
`validation_state = REVIEW` and **never claims a global optimum**; `truncated`/`cancelled`
and the searched/skipped ranges make the extent of the search explicit and reproducible.

## Reconstruction Graph / Hypothesis Model

A generic reconstruction abstraction supports competing hypotheses (candidate A, B, C). It
may model nodes, edges, and constraints (physical overlap, continuity, timestamps, channel,
codec/frame validity). Selection is deterministic.

**Deterministic tie-break.** Hypotheses are ranked by a content-derived score; when two or
more hypotheses tie on score, selection falls back to an explicit, deterministic tie-break
key (e.g. lowest starting `source_offset`, then smallest region set, then lexicographic
candidate id) so the ranking is fully reproducible and never scheduling-dependent. A
deterministic tie-break is used **only** to make ordering reproducible — it is **not** used
to resolve genuine forensic ambiguity. **Where genuine ambiguity remains** (multiple
hypotheses remain plausible after all constraints are applied), the reconstruction is
assigned `Validation_State = REVIEW` and the system **never arbitrarily picks a winner**.
For OEMs with path-dependent state, parser-specific stateful candidate validation is allowed.
A universal graph solver is **not** claimed appropriate for every OEM.

## Native vs Derived Artifacts

Distinct artifact classes, each with separate provenance, hash, and transformation record:
native recovered bytes, extracted elementary stream, remuxed video, decoded review copy, and
AI-derived artifact. **Native evidence is never silently replaced by a derived copy.**

**Concrete abstraction (Req 5.8–5.9).**

```rust
enum Artifact {
    Native(NativeArtifact),    // bytes taken directly from source evidence
    Derived(DerivedArtifact),  // produced by transforming a native (or another derived) artifact
}

struct NativeArtifact { provenance: Provenance, /* bytes-from-source descriptor */ }

/// Extracted elementary stream, remuxed video, decoded review copy, AI-derived output, etc.
/// Carries its OWN provenance and NEVER silently replaces the native artifact.
struct DerivedArtifact { kind: String, provenance: Provenance }

struct Provenance {
    source_evidence_id: EvidenceId,
    source_hash: Hash,
    source_regions: Vec<Region>,          // which byte ranges of the source produced this
    producing_component: String,
    component_version: String,
    oem_profile_version: Option<String>,
    oem_profile_hash: Option<Hash>,
    parser_version: Option<String>,
    recovery_level: Option<RecoveryLevel>,
    output_hash: Hash,
    transformation_history: Vec<String>,  // ordered record of transforms applied
    validation_state: ValidationState,    // PASS | REVIEW | FAIL | UNKNOWN
}
```

A `NativeArtifact` is bytes taken directly from the source. A `DerivedArtifact` (extracted
elementary stream, remuxed video, decoded review copy, AI-derived output) carries its own
`Provenance` and **never silently replaces the native artifact** — both are retained and
independently queryable.

## Codec / Media Validation

Includes FFprobe/media inspection, decode test, frame-count validation, timestamp continuity
checks, channel continuity checks, and GOP/I-frame checks where applicable. **Codec identity
does not prove OEM identity**: H.264 ≠ Dahua, H.265 ≠ Uniview, Annex-B ≠ a particular
recorder.

## Time Evidence

Explicit model with three separate classes that never overwrite one another: **Raw recorder
time** (Recorder_Native_Time), **Normalized time**, and **Corrected/Reference time**. If
correction is derived, store the method, anchors, offset, drift, and residual; the original
timestamp is preserved. Timezone is `unknown` when unknown (never silently UTC).

## Validation Corpus

Design a `validation_corpus/` directory. Each case contains a manifest with: source hash,
source type, expected detector, expected evidence regions, expected classification, expected
parser stage, expected reconstruction stage, expected validation state, expected warnings,
and provenance. Corpus cases are deterministic. Synthetic fixtures are clearly labeled
`synthetic` and are **never** described as real forensic evidence.

## Validation State

Every major operation that runs produces a Validation_State of `PASS`, `REVIEW`, `FAIL`, or
`UNKNOWN` with a reason. This is **separate** from Capability_Stage (implementation
maturity). Two distinct axes are reported side by side, never merged:

- **Capability_Stage** (per dimension): e.g. `Detection: IMPLEMENTED / Profiling: IMPLEMENTED
  / Parsing: PARTIAL / Reconstruction: NOT_IMPLEMENTED / Validation: PARTIAL`.
- **Validation_State** (per operation that ran): e.g. `Detection: PASS / Parsing: REVIEW /
  Reconstruction: UNKNOWN` (a stage that is `NOT_IMPLEMENTED` or did not run is reported as
  `UNKNOWN`, never `PASS`).

An operation that has not executed or been verified is **never** turned into `PASS`, and a
`NOT_IMPLEMENTED` capability is never presented as a passing validation.

## Failure / Adversarial Handling

All parsers and recovery modules treat evidence as adversarial input and must handle without
panic: integer overflow, offset overflow, length overflow, malformed headers, malformed
strings, impossible timestamps, corrupted indexes, cyclic indexes, enormous candidate
counts, fragmented recordings, partial writes, partial reads, sparse files, truncated
images, cancellation, interrupted operations, concurrent detector execution, and conflicting
OEM signatures. Checked arithmetic is used for all offset/size computations; out-of-bounds
access is rejected.

## Acquisition Verification

Where acquisition is part of the evidence package: preserve the acquisition map and receipt;
hash the acquisition output and the map/receipt; record unresolved regions, bad-sector
regions, and completion state. `Acquisition_Status ∈ {complete, partial, failed, unknown}`.
An incomplete acquisition is **never** labeled complete.

## Testing and QA (Release Gates)

Release gates (minimum): formatting/lint, compile, unit tests, integration tests,
malformed-input tests, synthetic corpus, detector regression, parser regression, recovery
regression, provenance tests, determinism tests, bounded-memory tests, read-only tests,
CLI/API smoke tests, and a fresh-install test. Coverage targets may be configured as a
**release gate** and measured during implementation; **no coverage percentage is claimed as
already achieved.**

## Performance

Benchmarks are defined for: multi-TB sequential read, random reads, detector latency,
profile scanning, parser throughput, recovery throughput, peak memory, and cancellation
latency. The platform must **not** require loading a 2 TB/3 TB image into RAM.

## Multi-Terabyte Practical Model

For a 3 TB image, detection does not normally scan 3 TB. Instead:

```
read-only source → bounded detection reads → candidate OEM → profile/topology
  → parser → targeted regions → recovery if requested
```

OEM-specific targeting examples:
- **Honeywell:** partition → sector size → partition start → byte offset → candidate region.
- **Uniview:** bounded super scan → super metadata → DI → block → DATA.
- **Dahua:** DHFS candidate → filesystem → recording/index → DHAV.
- **Hikvision:** candidate/master structure → geometry → metadata/index → recording.
- **CP Plus:** UBS candidate → superblock → page/index → recording.

## Database / Data Model (Extensions)

The canonical schema is defined in the **Data Models** section above; this section only notes
the extension coverage. That schema (PostgreSQL, metadata only — no multi-TB media) provides
concrete tables/columns for: `capability_stages` (five per-OEM stage columns),
`validation_states` (per-operation PASS/REVIEW/FAIL/UNKNOWN), `acquisitions`
(`acquisition_status` + verification), `source_safety_reports`, `source_regions` (queryable
offsets), profile applicability + model/firmware/variant (`evidence_items.applicability`,
`profiles`), recovery search bounds/results (`recovery_runs`), the machine-readable
`validation_corpus`, reconstruction hypothesis metadata (JSONB on `recovery_candidates`/
`recovery_runs`), `artifacts` + `provenance` (native-vs-derived transformation provenance
stored distinctly), and `confidence_configs` (versioned classification policy). No concept is
defined twice: the Data Models tables are authoritative and the sections above reference them.

## UI (Extensions)

Add UI concepts (Req 18.8): Capability Matrix, Detection Evidence, Storage Topology, Parser
Status, Recovery Status, Validation Status, profile applicability (including model/firmware
applicability), Source Provenance, Acquisition Status, Warnings, and Limitations. For each
OEM, the **five Capability_Stage dimensions** (Detection / Profiling / Parsing /
Reconstruction / Validation) are shown **separately**, and Capability_Stage (implementation
maturity) is presented **separately from** the per-operation Validation_State
(PASS/REVIEW/FAIL/UNKNOWN) — a Validation_State is never rendered as a Capability_Stage
(Req 18.9). The UI never shows only "Supported". All raw-byte access is via the
API/`EvidenceReader` (evidence id + offset + length); the frontend never opens arbitrary
filesystem paths.

## OEM Profile Directory

```
profiles/
  dahua/
  hikvision/
  honeywell/
  cpplus/
  uniview/
```

Future (present as directories only, NOT marked implemented): `tplink/`, `godrej/`,
`matrix/`.

## Requirements Traceability Matrix (R1–R25)

This matrix maps every acceptance criterion of Requirements 1–25 to the design section, the
concrete model/API that implements it, the responsible component, and the test that guards
it. There is **NO GAP**: every criterion of every requirement is covered. Status is either
**PASS** (design specifies a complete, self-consistent mechanism) or **PARTIAL** (mechanism
is specified but gated on an external dependency the spec does **not** claim to have
implemented).

**Naming note.** Rust type names are CamelCase and map 1:1 to the `requirements.md` domain
terms: `DataState` == `Data_State`, `RecoveryStatus` == `Recovery_Status`, `ValidationState`
== `Validation_State`, `AttributionStatus` == `Attribution_Status`, `EvidenceStatus` ==
`Evidence_Status`, `SourceState` == `Source_State`, `AcquisitionStatus` == `Acquisition_Status`.

| Requirement.Criterion | Design Section | Concrete Model/API | Responsibility | Test | Status |
|---|---|---|---|---|---|
| 1.1–1.7 Read-only handling | Cross-Cutting → Read-Only Enforcement; §1 | `EvidenceReader` (no write method), `WriteGuard`, read-only OS handles | Evidence_Reader | Read-only enforcement; write-attempt denied+logged; Property 1 | PASS |
| 1.8–1.12 Source safety | Source Safety | `SourceSafetyReport`, `inspect_source()`, `Evidence.source_state`, `source_safety_reports` | Platform / Evidence_Reader | Source-safety rejection (mounted/write-enabled); write-attempt | PASS |
| 2.1–2.5, 2.7 Explainable, non-fabricated | §5 Detection; §6 Confidence | `DetectorOutput`, `EvidenceItem`, `ClassifiedDetectionResult`, `Classification` | Detector + Confidence_Engine | Lone-magic; unknown filesystem; overlapping signatures; Property 6/7 | PASS |
| 2.6 Attribution ownership | §5 Attribution ownership; §6 | `ClassifiedDetectionResult.attribution_status` (set only by Confidence_Engine) | Confidence_Engine | Property 7 (attribution honesty); lone-magic | PASS |
| 2.8 Full evidence item | §5 Detection | `EvidenceItem` (source_evidence_id, evidence_status, rule_match_status, …) | Detector | Detection evidence-item test; schema test | PASS |
| 3.1–3.5 Detection/parsing split | §5 boundary; §7 Parsers | `Detector` trait vs `Parser` trait; `DetectorOutput` → `ClassifiedDetectionResult` | Detector / Parser / Confidence_Engine | Detector-does-not-interpret-content; Property 5 | PASS |
| 3.6–3.7 Capability maturity per OEM | Capability Maturity Model | `Capability_Stage` (5 dims); `capability_stages` | Platform | Capability-matrix test | PASS |
| 4.1–4.4 Raw + normalized preserved | §7 Parsers → TimeEvidence | `TimeEvidence`, `normalization_method` | Parser | Property 8; timestamp-accuracy benchmark | PASS |
| 4.5–4.7 Distinct time classes + correction | §7 TimeEvidence; Time Evidence | `TimeEvidence` (recorder_native/normalized/reference, `TimeZoneState`), `ClockCorrection` | Parser / Timeline_Engine | Property 8; unknown-timezone test | PASS |
| 5.1–5.7 Hashing + chain of custody | §3 Hashing; Provenance & CoC | `Hashing_Service`, `HashRecord` (status/duration/bytes), streaming reads, `chain_of_custody` | Hashing_Service / Chain_Of_Custody | Streaming-hash; bounded-memory; write-denied logging | PASS |
| 5.8–5.9 Provenance + native/derived | Native vs Derived Artifacts | `Artifact` enum, `Provenance`; `artifacts`/`provenance` tables | Chain_Of_Custody | Property 10 (provenance completeness); native-vs-derived | PASS |
| 6.1–6.6 Extensible OEM architecture | §4 OEM Profiles; §5 Orchestrator | `OemProfile`, `Applicability`, profile loader; auto-join on profile add | Detection_Orchestrator | New-profile-joins; profile-version-change | PASS |
| 7.1–7.6 Case + evidence model | §2 Case & Evidence | `Case`, `Evidence`, `Case_Manager` required-field validation | Case_Manager | Required-field rejection test | PASS |
| 7.7–7.9 Acquisition completeness | §2 Acquisition; Acquisition Verification | `Acquisition`, `AcquisitionStatus`; `acquisitions` | Case_Manager | Incomplete-not-labeled-complete test | PASS |
| 8.1–8.7, 8.9–8.11 Reader abstraction | §1 Evidence Reader | `EvidenceReader` trait, `RegionScanner` | Evidence_Reader | Bounded-memory; sparse; out-of-bounds; cancellation; Property 2/3 | PASS |
| 8.8 E01/EWF support | §1 Evidence Reader; Open Items | `ImageFormat::E01` (planned integration) | Evidence_Reader | Raw/dd/img format tests (E01 dependency-gated) | PARTIAL — planned integration / dependency-gated; spec does not claim implementation |
| 9.1–9.5 Parallel detection | §5 Detection; Determinism | `Detection_Orchestrator`, `DetectorOutput`, `EvidenceItem` | Detection_Orchestrator | Determinism (order independence); Property 4/5 | PASS |
| 10.1–10.10 Confidence scoring | §6 Confidence Engine | `Confidence_Engine`, `ConfidenceConfig`, `Classification`, `ClassifiedDetectionResult` | Confidence_Engine | Ambiguous-confidence; lone-magic; Property 6 | PASS |
| 10.11 Classification decision order | §6 Decision rules | `ConfidenceConfig` decision rules (exact Req 10.11 order) | Confidence_Engine | Classification-order; ambiguous; lone-magic | PASS |
| 11.1–11.8 Versioned profiles | §4 OEM Profiles | `OemProfile` (profile_id/version/schema_version/hash), strict loader (rejects missing evidence_status / malformed) | Profile loader | Profile-load-rejection; profile-version-change | PASS |
| 12.1–12.5 OEM parsers | §7 Parsers | `Parser` trait, `Recording`, `StructureReport`, `CandidateHint` | Parser / Recovery_Engine | Parser regression; integrity-flag test | PASS |
| 13.1–13.8 Recovery states | §8 Recovery Engine | `DataState`, `RecoveryStatus`, `RecoveryCandidate` | Recovery_Engine | Overwritten-unrecoverable; corrupted≠unrecoverable; Property 9 | PASS |
| 13.9–13.10 Bounded recovery | §8; Recovery Engine (Expanded) | `RecoveryBounds`, `RecoveryRun` (REVIEW when bounded) | Recovery_Engine | Bounded-search REVIEW; cancellation | PASS |
| 14.1–14.4, 14.6–14.8, 14.10 Reconstruction | §9 Video Reconstruction; Codec Validation | `Video_Reconstructor`, Reconstruction hypotheses, `Validation_State` | Video_Reconstructor | Missing-frames gap; fragmented; Property 9 | PASS |
| 14.5, 14.9 Decode test / QC | §9 Video Reconstruction | Decode test; `Validation_State=UNKNOWN/REVIEW` when FFmpeg absent | Video_Reconstructor | Decode-test QC (FFmpeg dependency-gated) | PARTIAL — planned integration / dependency-gated; spec does not claim implementation |
| 15.1–15.6 Timeline + correlation | §10 Timeline | `Timeline_Engine`, `TimelineEvent`, `TimeEvidence` ordering | Timeline_Engine / Parser | Timeline-ordering; physical≠chronological test | PASS |
| 16.1–16.6 AI analytics (optional) | §11 AI Analytics | AI service (optional), `DerivedArtifact` (AI-assisted) | AI_Analytics | AI-disabled pipeline-completes test | PASS |
| 17.1–17.6 Reporting | §12 Reporting | `Reporting_Service` contents; profile-only-not-reconstruction guard | Reporting_Service | Report-contents; report hash+provenance | PASS |
| 18.1–18.8 Forensic UI | §13 UI & Hex Viewer; UI Extensions | UI navigation, overview screen, `Hex Viewer` flow, Capability Matrix | UI / Hex_Viewer | Hex-viewer-via-EvidenceReader; overview-fields | PASS |
| 18.9 Stage vs state in UI | §13; Capability Maturity; Validation State | Capability Matrix (5 dims) rendered separately from `Validation_State` | UI | Capability-matrix separation test | PASS |
| 19.1–19.11 Testing + corpora | Testing Strategy; Validation Corpus | Synthetic fixture generator; `validation_corpus`; adversarial suite | Test harness | Full adversarial list; corpus cases; benchmarks | PASS |
| 20.1–20.4 Deterministic results | Determinism (bounded) | `Forensic_Result`, determinism inputs + stable ordering | Platform | Determinism; parallel order-independence | PASS |
| 21.1–21.4 Capability maturity | Capability Maturity Model | `Capability_Stage` (5 dims); `capability_stages` | Platform | Capability-matrix test | PASS |
| 22.1–22.3 Validation states | Validation State | `ValidationState` enum; `validation_states` | Platform | Validation-state test (no PASS for unrun) | PASS |
| 23.1–23.4 Acquisition verification | Acquisition Verification; §2 | `Acquisition`; `acquisitions` | Case_Manager / Platform | Incomplete-not-complete; map-hash test | PASS |
| 24.1–24.4 Adversarial parsing | Failure / Adversarial Handling | Checked arithmetic, `ForensicError`, no-panic contract | Parsers / Recovery_Engine | Malformed-input; truncated; overflow; out-of-bounds | PASS |
| 25.1–25.3, 25.5–25.7 Uniview OEM | Uniview OEM Spec; §5/§7/§8 | Uniview `Detector`/`Parser`, `OemProfile` (region vocab), `Capability_Stage` | Uniview Detector/Parser/Recovery | Uniview edge-case suite; lone-magic | PASS |
| 25.4 EcPortId/timestamp corroborating | Uniview OEM Spec; §5 Uniview bullet | Uniview detector (`EcPortId` + timestamp corroborating, profile-validated) | Uniview Detector | EcPortId-not-alone-proof test | PASS |

Every row names a concrete model/API defined in this design and a test drawn from the
Testing Strategy, the adversarial test list, the Correctness Properties, or the validation
corpus. The only `PARTIAL` rows are **8.8 (E01/EWF)** and **14.5/14.9 (FFmpeg decode/QC)**,
both dependency-gated planned integrations; no `PARTIAL` row is left without a stated reason,
and no criterion is omitted.

## References

- Dahua: `https://github.com/dw2102/X-Ways-DHFS4_1-X-Tension.git` (reference, not automatic truth).
- Hikvision: `https://github.com/akira7799/hikvision-dvr-parser.git`.
- Honeywell: supplied/internal Honeywell research/parser source.
- CP Plus: existing CP Plus firmware reverse-engineering work (e.g. CP-VNR-3104).
- Uniview: existing Uniview reverse-engineering research (`disktool`, `super`/`super-data`,
  super-block validation, storage-region vocabulary, `EcPortId`, timestamp metadata, `DI`,
  `MP_MAIN_IDX_S`-style index, timestamp-to-block mapping, `DATA` region, recovery/index
  behavior).
- Vidrensic: `https://github.com/imedkablavi/vidrensic` — reviewed for architecture/
  engineering ideas only (capability maturity, validation corpus, synthetic testing, explicit
  validation states, acquisition verification, adversarial parsing, bounded reconstruction,
  provenance, read-only safety, ambiguity handling). **Its code is not copied**; only publicly
  visible engineering concepts inform this design.

## Change History (Consolidated Final Spec)

- **C-14** — Expanded OEM implementation specifications and added Uniview as a first-class OEM.
- **C-15** — Added the capability maturity model (Detection/Profiling/Parsing/Reconstruction/Validation).
- **C-16** — Added explicit PASS/REVIEW/FAIL/UNKNOWN validation states.
- **C-17** — Added acquisition verification/completeness tracking.
- **C-18** — Added adversarial parser/recovery requirements.
- **C-19** — Added the machine-readable deterministic validation corpus.
- **C-20** — Added topology profiling and bounded scanning.
- **C-21** — Added native-vs-derived artifact provenance.
- **C-22** — Added model/firmware/storage-variant applicability.
- **C-23** — Added explicit multi-terabyte performance requirements.
- **C-24** — Added reconstruction hypothesis/ambiguity handling.
- **C-25** — Added QC and release-gate requirements.
- **C-26** — Added the Uniview detector/parser/recovery specification.
