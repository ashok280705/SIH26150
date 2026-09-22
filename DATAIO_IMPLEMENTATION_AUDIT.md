# DATAIO IMPLEMENTATION AUDIT

**Audit type:** READ-ONLY. No production code was modified, refactored, renamed, deleted, or generated.
**Specification under review:** `DATAIO_IMPLEMENTATION_SPEC.md` (provided as a chat document; **NOT present in the repository** — a filename search for `DATAIO` across the workspace returned no files).
**Codebase under review:** `c:\Users\HP\Downloads\COMPUTER\SIH-TakeUForward\VIDEO` — Rust workspace, verified to compile with `cargo check --workspace --all-targets` (exit 0, warnings only).
**Audit date:** 2026-09-21

---

# 1. Executive Summary

## 1.1 The single most important finding, stated first

**The specification is written for a C#/.NET codebase. The current project is a Rust workspace.**

- The spec proposes `IDisk`, `IRandomAccessReader`, `IBlockDevice`, `IEvidenceSource`, `ReadResult`, `Span<byte>`, `IDisposable`, `IProperty<T>`, DI containers, `Assembly.LoadFile`, WMI, and `kernel32` P/Invoke. Every one of these is a .NET construct.
- The current project is a Cargo workspace (`Cargo.toml`, `edition = "2021"`, `rust-version = "1.82"`) with 20 member crates. There is no `.csproj`, no `.sln`, no C# file anywhere.

Consequence: **the specification's interfaces cannot be "adopted" literally at all.** What can be adopted is the specification's *requirements and invariants*, re-expressed as Rust traits and types. Every statement in this audit about "adopting the spec" means adopting its behavioural requirements, not its declared interfaces. Any plan that treats Phase 13 of the spec as a to-do list of interfaces to add will fail immediately.

A second, related consequence: the spec's entire evidentiary basis is a reverse-engineered .NET assembly (`DME.DataIO.dll`). Roughly half the spec's content is a catalogue of that assembly's *defects* and instructions not to reproduce them. **The current project never had those defects to begin with**, because it was not derived from that assembly. Large parts of the spec are therefore not "requirements we are missing" but "mistakes we already avoided." This audit separates those two categories explicitly, because conflating them would wildly overstate how much work is outstanding.

## 1.2 What the current project already has

A byte-addressed, read-only evidence reader with genuinely strong foundations in several areas the spec identifies as critical:

- **A read-only trait with no write method at the type level.** `EvidenceReader` (`crates/evidence-reader/src/reader.rs:41-93`) exposes `len`, `is_empty`, `read_at`, `source_kind`, `source_path`, `read_exact_at`, `read_region`. There is no write method, and no way to add one without editing the trait.
- **Byte addressing as the primitive.** `read_at(offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError>` is the single primitive. This is exactly the spec's Phase 2.8 `[DESIGN]` requirement ("make byte-range reading a first-class contract and derive sector reads from it, rather than the reverse"). The current project got this right from the start.
- **Universally checked, integer-only offset arithmetic.** `crates/forensic-core/src/checked.rs` provides `checked_add`, `checked_mul`, `checked_sub`, `checked_sector_offset`, `checked_end_offset`, `validate_region_bounds`, `validate_bounds`. All use Rust's `checked_*` intrinsics returning `Option`, mapped to `ForensicError::ArithmeticOverflow`. **There is no mask/shift address arithmetic and no floating-point address arithmetic anywhere in the read path** — satisfying spec FI-03 and FI-05 outright.
- **A bounded partition-style reader that cannot escape its window.** `BoundedReader` (`crates/evidence-reader/src/bounded.rs`) holds a private `inner` reference, validates the window at construction against the parent length, rejects local offsets `>= self.length` (`bounded.rs:78-85`), clamps read length to the window, and offers `to_absolute_offset` for provenance. It implements `EvidenceReader`, so `len()` returns the *window* length. This is a close match to the spec's `IPartition::OpenReader()` requirement including invariant #2 ("does not expose the parent device").
- **Bounded, accounted scanning.** `RegionScanner` + `ScanReport { searched_range, searched_bytes, skipped_ranges, termination_reason }` with `TerminationReason { Completed, Cancelled, LimitReached, Truncated, OutOfBounds }` (`crates/evidence-reader/src/scanner.rs:27-61`). Truncation is an explicit, typed outcome — not a silent success.
- **Structured errors carrying the failing range.** `ForensicError::OutOfBounds { context, offset, length, source_len }` (`crates/forensic-core/src/error.rs:28-35`) names the requested range *and* the valid range. `Cancelled` carries `bytes_processed`.
- **A real partial-acquisition model.** `Acquisition` (`crates/forensic-core/src/acquisition.rs`) has `AcquisitionStatus { Complete, Partial, Failed, Unknown }` defaulting to `Unknown`, plus `bad_sector_ranges: Vec<Region>` and `unresolved_ranges: Vec<Region>`. The builders `with_bad_sectors`/`with_unresolved` **force `Complete` down to `Partial`** when ranges are present (`acquisition.rs:110-127`). This is the spec's FI-11/Phase 9.9 "never present an incomplete acquisition as complete" requirement, already enforced at the type level.
- **Byte-level provenance.** `Provenance` + `SourceRegion` (`crates/forensic-core/src/provenance.rs`) record which evidence byte ranges produced each artifact, with component version, profile version + hash, parser version, recovery level, output hash, and an ordered transformation history. This satisfies most of spec FI-06.
- **Source-safety gating.** `inspect_source` (`crates/evidence-reader/src/source_safety.rs:84-110`) rejects `ReadWrite`, accepts `Unknown` with a warning, and **never reports an undetermined state as `ReadOnly`**. The spec has no equivalent requirement; this is a current-project strength the spec does not cover.
- **Application-level write denial.** `WriteGuard` (`crates/forensic-core/src/write_guard.rs`) denies writes resolving inside the evidence directory and emits a `CustodyAction::WriteDenied` custody event.
- **Determinism inputs modelled explicitly.** `DeterminismKey` (`crates/forensic-core/src/determinism.rs:23-40`) captures evidence hash, profile version + hash, config version + hash, recovery config, and all component versions, with environment metadata excluded from comparison.
- **Window-size-independent streaming hash.** `HashingService` (`crates/hashing/src/lib.rs`) hashes through `RegionScanner`, and a test asserts the digest is identical across window sizes 4 KiB–64 KiB and equal to the in-memory digest (`hashing/src/lib.rs:203-225`).
- **E01 correctly refused rather than faked.** `RawReader::open` rejects `.E01`/`.E0*` with `UnsupportedFormat` (`crates/evidence-reader/src/raw.rs:38-47`), and `docs/decisions/OPEN-1-ewf-e01-dependency.md` documents a candidate crate, a license verification, a six-item verification gate, and an explicit prohibition on hand-rolling an EWF parser. This is *better discipline than the spec asks for* — the spec says "do not attempt to write an E01 reader from this specification"; the project has already written down why, what would unblock it, and what must not be claimed meanwhile.

## 1.3 How much of the specification is implemented

Counting only the spec requirements that are **applicable** to this project (excluding .NET-specific mechanics, excluding legacy formats the spec itself says not to implement, and excluding "do not reproduce this defect" items that were never present):

| Band | Applicable requirements | Implemented | Partial | Missing |
|---|---|---|---|---|
| Read primitive & result contract | 9 | 4 | 3 | 2 |
| Geometry / sector model | 8 | 0 | 1 | 7 |
| Bounds & overflow | 7 | 7 | 0 | 0 |
| Partition layer | 12 | 2 | 3 | 7 |
| Range/coverage algebra | 7 | 0 | 2 | 5 |
| Content addressing (extents) | 6 | 0 | 1 | 5 |
| Retry / error semantics | 8 | 3 | 2 | 3 |
| Container formats (raw, segmented, sparse, E01) | 8 | 2 | 1 | 5 |
| Forensic integrity (FI-01…FI-14) | 14 | 6 | 5 | 3 |
| Resource lifetime | 4 | 4 | 0 | 0 |
| **Total** | **83** | **28** | **18** | **37** |

**Approximately 34% fully implemented, 22% partially implemented, 44% missing.** Weighting by forensic risk rather than by count, the picture is better than that ratio suggests: the highest-risk items the spec identifies (overflow, bounds, read-only enforcement, deterministic disposal) are the ones already complete, while most of the missing 44% is *new capability* (geometry provenance, segmented images, sparse capture, extent maps, range algebra) rather than *broken behaviour needing repair*.

## 1.4 Major missing pieces

1. **No `ReadResult` equivalent — the spec's single most emphasised requirement (FI-04) is unmet.** `read_at` returns `Result<usize, ForensicError>`: a bare byte count. There is no outcome discriminator (`Complete`/`Partial`/`NotRecorded`/`Failed`), and **no enumeration of ranges that were zero-filled rather than read**. A caller cannot distinguish a genuine run of zero bytes from bytes that were never read. See §9.
2. **No sector-geometry model at all.** No sector size, no sector count, no tail bytes, no provenance, no degraded mode. `checked_sector_offset(sector, sector_size)` exists as a *helper* but nothing supplies or tracks `sector_size`. The only two sources of a sector size in the whole codebase are hard-coded `512` fallbacks: `crates/detection/src/topology.rs:59` (`sector_size_override.unwrap_or(512)`) and `crates/parsers/honeywell/src/parser.rs:41` (`profile.layout.get("sector_size").copied().unwrap_or(512)`).
3. **Partition layer is MBR-primary-only.** `StorageTopologyProfiler` (`crates/detection/src/topology.rs:58-128`) parses the 4 primary MBR entries and nothing else. `TopologyType::Gpt` is declared (`topology.rs:23`) and **never produced by any code path**. No GPT, no extended/EBR chains, no overlap detection, no clamping-with-finding, no findings model at all. Out-of-range partitions are **silently dropped** (`topology.rs:96`).
4. **No reusable range-set algebra.** `estimate_coverage` + `merge_regions` (`crates/timeline/src/gaps.rs:137-196`) computes union and complement once, for one purpose, returning a `CoverageEstimate`. There is no `Add`/`Subtract`/`Intersect`/`Complement` API usable by other layers.
5. **No content-addressing / extent-map layer.** A recording's bytes cannot be described as a scattered extent list and served as one stream. Recordings currently carry `source_offsets: Vec<Region>` but nothing turns that into a reader.
6. **No retry policy.** Zero retry logic exists. A transient I/O failure on a failing DVR drive aborts the read.
7. **No segmented-image support and no sparse/record-on-read capture.**
8. **No Windows physical-disk path.** `RawReader::open_device` is gated `#[cfg(unix)]` (`crates/evidence-reader/src/raw.rs:79`), and `ReadOnlyMmap` returns `UnsupportedFormat` on non-Unix (`crates/evidence-reader/src/mmap.rs:82-89`). The declared development platform is Windows. `SourceKind::PhysicalDisk` therefore exists but is unreachable on the host platform.

## 1.5 Major compatibility concerns

1. **Language/platform mismatch (structural).** Covered in §1.1. Not a blocker for the spec's *ideas*; an absolute blocker for its *interfaces*.
2. **Half-open vs inclusive ranges (silent-corruption risk).** `forensic_core::Region` is **half-open** `[offset, offset+length)` — `region.rs:41` (`contains` uses `byte_offset < end`), `region.rs:141-147` (test asserts adjacent regions do **not** overlap). The spec's `ByteRange` is **inclusive on both ends** with `Length = End - Start + 1` (spec §13.7). Introducing a spec-shaped `ByteRange` alongside `Region` without a hard conversion boundary would produce off-by-one errors that pass type-checking and silently mis-report byte ranges in court-facing output. **This is the highest-risk compatibility item in the audit.**
3. **Address-space ambiguity already present in the parser contract.** The `Parser` trait takes `&dyn EvidenceReader` (`crates/parsers-core/src/parser.rs:21-70`). It is called two different ways:
   - `crates/parsing/src/orchestrator.rs:67-84` passes the **whole-image** reader to `validate_structure`, `parse_filesystem`, `parse_metadata`, `parse_recordings`, `extract_timeline_events`.
   - `crates/recovery/src/levels.rs:225` and `:258` pass a **`BoundedReader`** (offset 0 = region start) to `recognize_candidate`.
   - `crates/recovery/src/validation.rs:23,51` passes whichever reader it was handed to **both** `validate_structure` and `recognize_candidate`.
   Nothing in the type system distinguishes the two. Parsers that read absolute offsets — e.g. `crates/parsers/hikvision/src/parser.rs:45` (`read_exact_at(0, superblock_size)`), `crates/parsers/uniview/src/parser.rs:78` (`read_exact_at(512, 1)`) and `:84` (`read_exact_at(1024, 4)`), `crates/parsers/tplink/src/parser.rs:340` (`read_at(0, &mut mbr)`) — will read *window-relative* bytes when handed a `BoundedReader` and *image-absolute* bytes otherwise. This is precisely the defect class the spec's Phase 7.2 and FI-08 describe. **It is a pre-existing defect in the current code, not something the spec would introduce** — and adopting the spec's typed-address-space requirement would fix it.
4. **`read_exact_at` mislabels a short read as `OutOfBounds`.** `reader.rs:72-85`: when `bytes_read < length` it returns `ForensicError::out_of_bounds("short read", …)`. A truncated source and an out-of-range request are reported as the same error variant, which `RegionScanner` then maps to `TerminationReason::Truncated` (`scanner.rs:172-176`) regardless of which actually happened. Tightening this changes error classification for existing callers.
5. **`read_at` clamps silently.** `raw.rs:138-140` computes `to_read = buf.len().min(remaining)` and returns the count. Tail clamping is invisible to the caller beyond the count itself. The spec requires clamping to be *reported* (Phase 10.1, "expose whether clamping occurred").

---

# 2. Current DataIO Architecture

Verified against the actual crate graph and call sites. Dependencies point downward.

```
                        ┌──────────────────────────────────────────┐
                        │  apps/api  (axum; ONLY network + DB)     │
                        │  handlers.rs:350-360 opens RegionScanner  │
                        └───────────────────┬──────────────────────┘
                                            │
        ┌───────────────────┬───────────────┼───────────────┬───────────────────┐
        ▼                   ▼               ▼               ▼                   ▼
  crates/detection   crates/parsing   crates/recovery  crates/hashing    crates/timeline
        │                   │               │               │                   │
  StorageTopology     orchestrator.rs   levels.rs      HashingService      gaps.rs
  Profiler            :67-84            :46,222,257    (RegionScanner)     estimate_coverage
  (MBR primaries      passes WHOLE      wraps regions  streaming SHA-256   merge_regions
   only; GPT enum     IMAGE reader      in Bounded-                        (one-shot union
   never produced)    to parsers        Reader; 8 MiB                       + complement)
        │                   │            window cap          │                   │
        │                   ▼                │               │                   │
        │          crates/parsers-core       │               │                   │
        │          Parser trait (7 methods,  │               │                   │
        │          each takes &dyn Evidence- │               │                   │
        │          Reader + &OemProfile)     │               │                   │
        │                   │                │               │                   │
        │          ┌────────┴────────┐       │               │                   │
        │          ▼                 ▼       │               │                   │
        │   parsers/{dahua,hikvision,honeywell,cpplus-ubs,uniview,tplink,unified}
        │   ── read ABSOLUTE offsets: read_exact_at(0,…), (512,…), (1024,…)
        │                                    │               │                   │
        └───────────────────┬────────────────┴───────────────┴───────────────────┘
                            ▼
        ╔═══════════════════════════════════════════════════════════════════╗
        ║  crates/evidence-reader   ← the DataIO-equivalent crate            ║
        ║                                                                   ║
        ║  reader.rs      EvidenceReader trait  (Send + Sync, NO write fn)   ║
        ║                   len() -> u64                                    ║
        ║                   read_at(u64, &mut [u8]) -> Result<usize>   ◄── THE primitive
        ║                   source_kind() / source_path()                   ║
        ║                   read_exact_at(u64, usize) -> Result<Vec<u8>>    ║
        ║                   read_region(&Region)     -> Result<Vec<u8>>     ║
        ║                                                                   ║
        ║  bounded.rs     BoundedReader<'a>  (window; private inner;        ║
        ║                   to_absolute_offset; impls EvidenceReader)       ║
        ║  scanner.rs     RegionScanner + ScanReport + TerminationReason     ║
        ║  raw.rs         RawReader  (Mutex<File>; seek+read; E01 refused;  ║
        ║                   open_device is #[cfg(unix)] ONLY)               ║
        ║  mmap.rs        ReadOnlyMmap (PROT_READ; #[cfg(unix)] only)       ║
        ║  source_safety  inspect_source -> SafetyDecision                  ║
        ║  config.rs      ReaderConfig  <- config/reader.toml (16 MiB max)  ║
        ║  progress.rs    CancellationToken / ProgressInfo                  ║
        ╚═══════════════════════════════════╤═══════════════════════════════╝
                                            ▼
        ╔═══════════════════════════════════════════════════════════════════╗
        ║  crates/forensic-core   (#![forbid(unsafe_code)])                 ║
        ║                                                                   ║
        ║  checked.rs     checked_add / checked_mul / checked_sub            ║
        ║                 checked_sector_offset(sector, sector_size)         ║
        ║                 checked_end_offset / validate_region_bounds        ║
        ║                 validate_bounds     ◄── ALL integer, ALL checked   ║
        ║  region.rs      Region { offset: u64, length: u64 }  HALF-OPEN     ║
        ║  error.rs       ForensicError (9 variants)                         ║
        ║  provenance.rs  Provenance / SourceRegion / TransformationStep     ║
        ║  acquisition.rs Acquisition + AcquisitionStatus (gaps => Partial)  ║
        ║  write_guard.rs WriteGuard (path-level write denial + custody)     ║
        ║  determinism.rs DeterminismKey / ForensicResult / comparison       ║
        ║  case.rs        SourceState / ImageFormat (E01 declared, gated)    ║
        ╚═══════════════════════════════════════════════════════════════════╝

  MISSING LAYERS (no crate, no module, no type):
    ✗ Geometry model          (sector size/count/tail + provenance + degraded mode)
    ✗ Sector-addressed reads  (no read_sectors anywhere in the workspace)
    ✗ Read-result contract    (no Complete/Partial/NotRecorded/Failed discriminator)
    ✗ Range-set algebra       (no Add/Subtract/Intersect/Complement type)
    ✗ Extent map / content addressing
    ✗ Retry policy
    ✗ Segmented raw images
    ✗ Sparse / record-on-read capture
    ✗ E01 / EWF               (deliberately gated by OPEN-1 — documented, not an oversight)
    ✗ Windows physical-disk gateway
```

## 2.1 Notable structural observation

The current architecture **already avoids** the one structural mistake the spec singles out. Spec §2.1 records that the original `IDisk` carries `Partitions`, `PartitioningType` and `PartitionSignature`, making the evidence layer depend on the partition layer — a circular layering the spec instructs implementers not to reproduce.

In the current project, `EvidenceReader` carries **no partition information whatsoever**. Partition discovery lives in a *higher* crate (`crates/detection`) which depends on `evidence-reader`, never the reverse (`crates/detection/src/topology.rs:13` — `use evidence_reader::EvidenceReader;`). The dependency direction is correct and matches the spec's L0-must-not-depend-on-L3 rule exactly.

---

# 3. Specification Architecture

As proposed by `DATAIO_IMPLEMENTATION_SPEC.md` Phase 12. All of it is tagged `[DESIGN]` by the spec itself — it is the spec authors' own design, not reverse-engineered fact.

```
┌─ L6  Vendor DVR Layer          (explicitly OUT of DataIO scope; consumes L2–L5)
│      IVendorFormatProbe, IIndexReader, RecordingSet, CoverageContribution
│
├─ L5  Coverage / Range Layer
│      ByteRange            immutable, INCLUSIVE both ends, Length = End-Start+1
│      IRangeSet / RangeSet immutable; Add, AddAll, Subtract, SubtractAll,
│                           Union, Intersect, Complement(within), Contains,
│                           Covers, TotalLength, Count, Min/Max (null when empty)
│      CoverageModel        named sets: structural, claimed-intact,
│                           claimed-recovered, unreadable, unrecorded, carved
│      Invariants: always sorted / non-overlapping / non-adjacent; ONE merge
│                  predicate (adjacency); checked arithmetic; NO value-enumerating API
│
├─ L4  Content Addressing Layer
│      Extent      SourceOffset (address-space tagged), Length, LogicalOffset,
│                  Kind ∈ {Data, Sparse, Uninitialised, Unreadable}
│      ExtentMap   ordered, validated, non-overlapping; Resolve(logicalOffset, length)
│      ExtentStream / IContentReader
│      Invariants: every extent carries its address space; Sparse + Uninitialised
│                  EXPLICITLY zero-filled AND reported; Unreadable => Partial;
│                  a short device read never returns Complete
│
├─ L3  Partition Layer
│      IPartitionTableReader.Read(IBlockDevice) -> PartitionTableSet
│      PartitionTableSet   Schemes (ALL detected, not one winner) + per-scheme
│                          Partitions / RawStructureBytes / Findings;
│                          WholeDevice ALWAYS present; Recommended + reason
│      IPartition          Index, StartSector, SectorCount, ByteLength,
│                          RawTypeByte, TypeGuid?, Name?, Findings,
│                          OpenReader() -> IBlockDevice bounded to [0, ByteLength)
│      IFilesystemProbe    Identify -> multiple candidates with confidence
│      Invariants: partition reader cannot address outside its window and does NOT
│                  expose the parent; pre-clamp values preserved; clamp/overlap/
│                  out-of-range are FINDINGS not log lines; EBR depth + cycle limits;
│                  GPT done properly (header size, BOTH CRC32s, backup header,
│                  real entry count, type+unique GUIDs, UTF-16 name, NO 12-entry cap)
│
├─ L2  Addressing Layer
│      IBlockDevice : IRandomAccessReader
│                     BytesPerSector, SectorCount, TailBytes,
│                     ReadSectors(SectorIndex, long, Span<byte>) -> ReadResult
│      Typed addresses: ByteOffset (address-space tagged), SectorIndex,
│                       ByteLength, SectorCount
│      Conversions requiring an EXPLICIT factor:
│                       ToByteOffset, ToSectorIndex, OffsetWithinSector,
│                       SectorsSpanned = (off%ss + len + ss - 1) / ss
│      SectorBufferedReader  buffer is ALWAYS a whole number of sectors
│      Invariants: integer only (never mask/shift, never double); correct for ANY
│                  sector size >= 1; cross-space conversion needs explicit base;
│                  every operation overflow-checked
│
├─ L1  Reader Layer
│      IRandomAccessReader  Length; ReadAt(long byteOffset, Span<byte>) -> ReadResult
│      ReadResult           Outcome ∈ {Complete, Partial, NotRecorded, Failed}
│                           BytesRead, ZeroFilledRanges, Category,
│                           PlatformErrorCode, Attempts
│      IRetryPolicy         MaxAttempts, Delay(attempt), ShouldRetry(category)
│      RecordingReader      read-through capture decorator
│      ReadFailureCategory  Argument, OutOfRange, Oversized, TransientIo,
│                           PermanentIo, BackendClosed, CapacityExhausted,
│                           ContainerCorrupt
│      Invariants: Complete <=> BytesRead == requested AND ZeroFilledRanges empty;
│                  Partial => exactly BytesRead leading bytes valid, remainder
│                  EXPLICITLY zeroed AND reported; NotRecorded enumerates ranges;
│                  retry iterative + bounded, never for non-retryable categories;
│                  reads DETERMINISTIC
│
└─ L0  Evidence Layer
       IEvidenceSourceFactory  Sniff(locator) -> ranked candidates (no side effects)
                               Open(locator, explicit ContainerKind, options)
       IEvidenceSource         Kind, Locator, Geometry, Device, IsDegraded,
                               Findings, ComputeIdentity(mode), Dispose()
       EvidenceGeometry        BytesPerSector + provenance, TotalBytes (MEASURED,
                               never a product) + provenance, derived SectorCount,
                               derived TailBytes, ConflictingClaims
       Provenance precedence   OperatorDeclared > Measured > DecodedFromContainer
                               > InferredFromExternalLog > Assumed
       IPlatformBlockDeviceGateway   the ONLY place OS-specific code lives:
                               EnumerateDevices, Open, QueryLogicalSectorSize,
                               QueryPhysicalSectorSize (512e detection),
                               QueryByteLength, ReadAt, Close — every member
                               carries the raw platform error code
       Invariants: read-only; sector size >= 512 or DEGRADED MODE (no silent 512);
                   every disagreeing claim retained as a finding;
                   NO licence/authorisation gate
```

## 3.1 Spec items explicitly scoped out by the spec itself

Recorded so they are not mistaken for gaps: generic filesystem parsers (exFAT/ext/FAT32/JFS/XFS), support database + profiler, the regex/automata pattern finder, legacy `IData`/`IDataMap`/`SdrImage`, the four typed offset structs *as designed*, LVM2, the licence gate / obfuscation runtime, and the `Distributed` evidence type.

## 3.2 Spec requirements that are blocked inside the spec itself

- **E01/EWF format** — spec H-1: "Blocks Phase 5 entirely… *Not* resolvable from the original assembly."
- **Container detection from file extension** — spec H-2: all string literals encrypted; `[UNKNOWN]`.
- **GPT header field at +40 and the 12-entry cap** — spec H-5: `[UNKNOWN]` semantics.
- **Forensic-imager log formats** — spec M-11: all delimiters `[UNKNOWN]`.
- **Sparse format reserved field and version 1.0.1** — spec M-6: `[UNKNOWN]`.
- **LVM2 extent arithmetic** — spec L-15: `[UNKNOWN]`.

---

# 4. Implementation Coverage

Status values: **IMPLEMENTED**, **PARTIALLY IMPLEMENTED**, **DIFFERENT IMPLEMENTATION**, **STUB**, **MISSING**, **UNKNOWN**.

"N/A (.NET)" in the Compatibility column means the requirement is a .NET mechanic with no Rust analogue needed.

## 4.1 Evidence abstraction

| Specification Requirement | Current Implementation | Status | Evidence | Compatibility | Recommendation |
|---|---|---|---|---|---|
| A single read-only evidence abstraction | `EvidenceReader` trait — one trait, no write method at type level | **IMPLEMENTED** | `crates/evidence-reader/src/reader.rs:41-93` | Compatible in concept; trait ≠ interface | Keep. Do not replace with a spec-shaped `IEvidenceSource`. |
| Evidence layer must NOT expose partitions (no circular dependency) | `EvidenceReader` carries zero partition data; partition code lives in the higher `detection` crate | **IMPLEMENTED** | `reader.rs:41-93`; `crates/detection/src/topology.rs:13` imports evidence-reader, not vice versa | Compatible | Keep. Already correct. |
| Evidence identity (`Kind`, `Locator`) | `source_kind() -> SourceKind`, `source_path() -> &str` | **PARTIALLY IMPLEMENTED** | `reader.rs:60,63`; `SourceKind` at `reader.rs:10-21` | Compatible | `source_path` is documented "for logging/display only" — not a structured locator. Add a locator type when segmented images arrive (a segment set has no single path). |
| Evidence identity hash (`ComputeIdentity`) | `HashingService::hash_reader` — full streaming SHA-256 | **IMPLEMENTED (better than spec default)** | `crates/hashing/src/lib.rs:45-53` | Compatible | Keep. Spec's sampled-MD5 fingerprint is optional and explicitly non-integrity; **do not add it** unless large-device re-identification becomes a real need. |
| Separate identity from integrity (FI-11) | Only a full cryptographic hash exists; no sampled fingerprint to confuse it with | **IMPLEMENTED by absence** | `crates/hashing/src/lib.rs` | Compatible | Keep. If a sampled fingerprint is ever added it must be labelled non-integrity. |
| Degraded-mode open when geometry unknown | No geometry concept, therefore no degraded mode | **MISSING** | No `IsDegraded`, no geometry type anywhere | Needs new type | Add with the geometry model. |
| `Findings` on the evidence source | No findings model anywhere in the codebase | **MISSING** | grep for `Finding` returns nothing in `crates/` | Needs new type | Add — see §11. |
| Explicit container kind at open (no extension guessing) | Container kind is **inferred from file extension** at `raw.rs:63-71`; `.dd`→Dd, `.img`→Img, everything else→Raw | **DIFFERENT IMPLEMENTATION** | `crates/evidence-reader/src/raw.rs:63-71` | Compatible; spec prefers explicit + sniff | Low priority. Current behaviour is transparent and deterministic; spec's objection was aimed at *encrypted* extension tests, which is not the situation here. |
| No licence / authorisation gate | No gate exists | **IMPLEMENTED by absence** | — | Compatible | Keep. |

## 4.2 Read primitive and result contract

| Specification Requirement | Current Implementation | Status | Evidence | Compatibility | Recommendation |
|---|---|---|---|---|---|
| Byte addressing is the primitive; sector reads derived from it | `read_at(offset, buf)` is the only primitive; everything composes it | **IMPLEMENTED** | `reader.rs:74` | Compatible — matches spec Phase 2.8 `[DESIGN]` exactly | Keep. Notable win: the spec had to *argue* for this because the original inverted it. |
| Caller-provided buffer, not callee-allocated `out byte[]` | `read_at(&self, offset: u64, buf: &mut [u8])` — caller owns the buffer | **IMPLEMENTED** | `reader.rs:74` | Compatible | Keep. `read_exact_at` and `read_region` allocate a `Vec`, which is a convenience layer above the primitive — acceptable. |
| **`ReadResult` with `Outcome ∈ {Complete, Partial, NotRecorded, Failed}`** | `Result<usize, ForensicError>` — a bare count on success, an error on failure. No outcome discriminator. | **MISSING** | `reader.rs:74` | **Requires a new return type on the core trait** | **Highest-value addition.** See §11.1 and §14 Stage 2. |
| **`ZeroFilledRanges` — zeros never indistinguishable from data** | Nothing reports zero-filled ranges. `read_at` clamps at the tail; unread bytes in the caller's buffer keep whatever the caller put there. | **MISSING** | `raw.rs:138-140` | Needs `ReadResult` | **The spec's FI-04, its most emphasised forensic requirement. Unmet.** |
| `Complete ⟺ BytesRead == requested && ZeroFilledRanges empty` | No such invariant expressible | **MISSING** | — | Needs `ReadResult` | Add with `ReadResult`. |
| Partial read: leading `BytesRead` valid, remainder explicitly zeroed and reported | Remainder is **not** zeroed by `read_at` (only the bytes actually read are written). `read_exact_at` pre-zeroes the whole `Vec` (`reader.rs:79`) then errors on short read, so the caller gets `Err` and no buffer. | **PARTIALLY IMPLEMENTED** | `reader.rs:78-86`; `raw.rs:142-144` | Needs `ReadResult` | Behaviour is *safe* (caller gets an error, not a silently-zeroed buffer) but *lossy* — the valid prefix is discarded. Spec: "Never discard the good prefix." |
| Read failure categories (8 categories) | `ForensicError` has 9 variants but only 3 are read-relevant: `Io`, `OutOfBounds`, `ArithmeticOverflow`. No `Oversized`, `TransientIo`/`PermanentIo` split, `BackendClosed`, `CapacityExhausted`, `ContainerCorrupt` (there is `CorruptStructure`, used for parse not read). | **PARTIALLY IMPLEMENTED** | `crates/forensic-core/src/error.rs:18-66` | Extending an enum is a breaking change for exhaustive `match` — but current matches are non-exhaustive (`scanner.rs:172-177` uses `Err(ForensicError::OutOfBounds{..}) => … , Err(e) => return Err(e)`) so extension is low-risk | Add categories when retry arrives (retryable vs non-retryable is the distinction that matters). |
| Failures carry the affected byte range | `OutOfBounds { context, offset, length, source_len }` | **IMPLEMENTED** | `error.rs:28-35` | Compatible | Keep. Better than the spec's baseline (the original had encrypted messages and no range). |
| Failures carry the platform error code | `ForensicError::Io { context, source: std::io::Error }` — `std::io::Error` carries `raw_os_error()`, so the code is preserved, though not surfaced as a field | **PARTIALLY IMPLEMENTED** | `error.rs:20-24`; `raw.rs:131-133` | Compatible | Low priority. `raw_os_error()` is reachable; consider surfacing it in reports. |
| `Attempts` history in the result | No retry, so no attempt history | **MISSING** | — | Needs retry policy | Add with retry. |
| Maximum single-read size validated in **bytes** | `ReaderConfig.read_window.max_bytes` = 16 MiB default, range-validated 8–64 MiB; `ScanOptions.window_size`. But this bounds the *scanner window*, not an arbitrary `read_at` call — `read_at` accepts any buffer size. | **PARTIALLY IMPLEMENTED** | `crates/evidence-reader/src/config.rs:22-30,71-91`; `scanner.rs:70-79` | Compatible | Good enough. The config-not-constant approach (OPEN-2) is arguably better than the spec's "documented constant". |
| Zero-length read succeeds trivially | `read_at` returns `Ok(0)` when `buf.is_empty()` | **IMPLEMENTED** | `raw.rs:110-112` | Compatible | Keep. |
| Reads are deterministic | No random keep-alive, no background probing, no unrequested reads anywhere | **IMPLEMENTED** | No `Random`/`rand` in evidence-reader; no timer/repeater | Compatible | Keep. Spec FI-02 satisfied by construction; the original violated it. |

## 4.3 Physical disk access

| Specification Requirement | Current Implementation | Status | Evidence | Compatibility | Recommendation |
|---|---|---|---|---|---|
| Open a block device read-only | `RawReader::open_device` uses `File::open` (read-only) | **PARTIALLY IMPLEMENTED — Unix only** | `crates/evidence-reader/src/raw.rs:79-105` (`#[cfg(unix)]`) | **Unreachable on the declared Windows host** | Add a Windows path, or state plainly that physical-disk acquisition is Unix-only. |
| Platform gateway isolating all OS code | No gateway abstraction. `#[cfg(unix)]` is scattered across `raw.rs:79` and `mmap.rs:13,41,82,121`. | **MISSING** | `raw.rs`, `mmap.rs` | Needs new abstraction | Adopt the spec's gateway idea when adding Windows support — it is the right shape and makes a fake gateway possible for tests. |
| Query logical sector size | Nothing queries it. No IOCTL/`DeviceIoControl` equivalent. | **MISSING** | — | Needs gateway | Required for any real physical-disk work. |
| Query physical sector size (512e detection) | Missing | **MISSING** | — | Needs gateway | Spec-only improvement; nice-to-have. |
| Query total byte length | `open_device` seeks to end (`raw.rs:87-89`) | **PARTIALLY IMPLEMENTED** | `raw.rs:87-92` | Compatible | Seek-to-end works on Unix block devices; on Windows it does not reliably report raw device size. |
| Positional read | `seek` + `read` under a `Mutex<File>` | **DIFFERENT IMPLEMENTATION** | `raw.rs:126-144` | Compatible | Works and is `Send + Sync`. Note: the `Mutex` serialises all reads, so the `Send + Sync` trait bound advertised for "parallel detection" (`reader.rs:38`) does not actually deliver parallel I/O throughput. Not a correctness issue. |
| Surface platform error code | Wrapped in `ForensicError::Io` | **PARTIALLY IMPLEMENTED** | `raw.rs:131-133,142-144` | Compatible | See §4.2. |
| Deterministic close / dispose | Rust `Drop` — `File` closes when `RawReader` drops; `ReadOnlyMmap` calls `munmap` in `Drop` (`mmap.rs:120-127`) | **IMPLEMENTED (structurally superior)** | `mmap.rs:120-127`; RAII throughout | Compatible | Keep. The spec devotes FI-13 and §2.18 to disposal leaks in the original; Rust ownership makes them impossible here. **No action needed.** |
| Narrowest share mode (FI-01) | `File::open` on Windows maps to `GENERIC_READ` with default sharing; not explicitly narrowed | **PARTIALLY IMPLEMENTED** | `raw.rs:50-52`; comment at `raw.rs:49` | Compatible | Only matters once a Windows device path exists. Record the sharing mode granted. |
| Device enumeration with metadata | Missing | **MISSING** | — | Needs gateway | Needed for an operator device picker. |
| Idle keep-alive probe | Absent | **MISSING — and correctly so** | — | — | **Do not add the original's random probe.** Spec FI-02 explicitly condemns it. If bridged-drive dropouts become real, add a *fixed-location, separately-logged* probe. |
| CHS geometry | Absent | **MISSING — correctly** | — | — | Spec confirms CHS is unused in the read path. Do not add. |

## 4.4 Raw, segmented, sparse, E01

| Specification Requirement | Current Implementation | Status | Evidence | Compatibility | Recommendation |
|---|---|---|---|---|---|
| Single flat raw image | `RawReader` — `File::open`, long-lived handle, `Mutex<File>`, seek+read | **IMPLEMENTED** | `crates/evidence-reader/src/raw.rs:27-105` | Compatible | Keep. |
| `.raw` / `.dd` / `.img` in scope | All three, distinguished by extension | **IMPLEMENTED** | `raw.rs:63-71` | Compatible | Keep. |
| Segmented raw images (segment set) | No segment discovery, no segment set type, no cross-segment read | **MISSING** | No occurrence of `segment` in `crates/evidence-reader` | Needs new source type | Add when a real segmented acquisition appears. Spec's guidance is sound: validate every segment length up front, integer-only segment selection, check every read's return value, and **do not** impose the original's 512-multiple rule. |
| Sparse-capture container (record-on-read) | Absent | **MISSING** | — | Needs new decorator + format | Genuinely valuable for failing DVR drives. Medium priority. If adopted, follow the spec's fix: signal unrecorded regions explicitly rather than returning silent zeros. |
| Sparse regions reported, never silently zeroed | No sparse concept. Note the crate doc at `lib.rs:23` claims "Sparse/unallocated regions are never reported as source truncation", but `raw.rs:126-144` has no sparse handling — a sparse file hole reads as real zeros indistinguishably. | **STUB (documented intent, no mechanism)** | `crates/evidence-reader/src/lib.rs:23`; `raw.rs:126-144` | Needs `ReadResult` | **The documentation overstates the implementation.** Either implement the distinction or soften the claim. |
| E01 / EWF support | Refused with `UnsupportedFormat`; `ImageFormat::E01` declared but gated | **MISSING — deliberately and correctly** | `raw.rs:38-47`; `crates/forensic-core/src/case.rs:59`; `docs/decisions/OPEN-1-ewf-e01-dependency.md` | Compatible | **Keep the gate.** Project discipline here exceeds the spec: candidate selected (`ewf` 0.4.10, Apache-2.0), license verified, six-item verification gate written, hand-rolled EWF parser explicitly prohibited. |
| Legacy `SdrImage` | Absent | **MISSING — correctly** | — | — | Spec says do not implement. Agreed. |

## 4.5 Sector geometry

| Specification Requirement | Current Implementation | Status | Evidence | Compatibility | Recommendation |
|---|---|---|---|---|---|
| Sector size is discovered, provenance-tagged data | No geometry type exists. Two independent hard-coded `512` fallbacks. | **MISSING** | `crates/detection/src/topology.rs:59`; `crates/parsers/honeywell/src/parser.rs:41` | Needs new type | **Adopt.** Highest-value spec import after `ReadResult`. |
| Provenance precedence: OperatorDeclared > Measured > DecodedFromContainer > InferredFromExternalLog > Assumed | No provenance | **MISSING** | — | Needs new type | Adopt the ordering. It is the spec's own correction of the original's inverted rule and is clearly right. |
| No silent global 512 default | `topology.rs:59` — `sector_size_override.unwrap_or(512)`. Caller-overridable, but the default is silent and untagged. | **PARTIALLY IMPLEMENTED** | `topology.rs:59` | Compatible | Tag it `Assumed` and surface it in reports. |
| Total byte length is **measured**, never a product | `RawReader.len` = `metadata.len()` — a measured file length, never derived | **IMPLEMENTED** | `raw.rs:54-58` | Compatible | Keep. The original discarded the measured length; this project never did. |
| `SectorCount` derived from measured bytes | No sector count anywhere | **MISSING** | — | Needs geometry | Adopt. |
| `TailBytes` explicitly accounted | Absent | **MISSING** | — | Needs geometry | Adopt. Cheap, and prevents a non-sector-multiple image hiding data in an invisible tail. |
| Conflicting geometry claims retained as findings | Absent | **MISSING** | — | Needs findings model | Adopt with geometry. |
| Integer-only sector arithmetic; never mask/shift, never floating point | `checked_sector_offset` = `checked_mul(sector, sector_size)`, rejecting `sector_size == 0` | **IMPLEMENTED** | `crates/forensic-core/src/checked.rs:33-41` | Compatible | Keep. **The current project is already correct for non-power-of-two sector sizes**, which the original was not. This is a clear current-better. |
| Validate `sector_size > 0`; warn on non-power-of-two; reject 0 | `sector_size == 0` rejected in two places | **PARTIALLY IMPLEMENTED** | `checked.rs:34-40`; `topology.rs:60-63` | Compatible | Add the `>= 512` check and the non-power-of-two warning with the geometry model. |
| Buffering expressed in whole sectors | `ScanOptions.window_size` is a byte count, sector-unaware | **MISSING** | `scanner.rs:70-79,127-128` | Compatible | Low priority — matters only once sector-addressed reads exist. |
| Sector-addressed read API (`ReadSectors`) | **No `read_sectors` anywhere in the workspace** | **MISSING** | grep `read_sectors|ReadSectors` → only in this audit | Additive; no existing caller to break | Add as a derived convenience over `read_at`, per spec §13.2. |

## 4.6 Partition handling

| Specification Requirement | Current Implementation | Status | Evidence | Compatibility | Recommendation |
|---|---|---|---|---|---|
| MBR signature detection | `mbr_buf[510] == 0x55 && mbr_buf[511] == 0xAA` | **IMPLEMENTED** | `crates/detection/src/topology.rs:77` | Compatible | Keep. Matches spec §2.11 exactly. |
| MBR 4 primary entries at 446, stride 16; type +4; start LBA u32 +8; length u32 +12 | Exactly that | **IMPLEMENTED** | `topology.rs:79-87` | Compatible | Keep. Offsets verified correct against spec §2.11 and §13.1. |
| Raw type byte preserved | Stored as `partition_type: String` formatted `"0x{:02X}"` | **DIFFERENT IMPLEMENTATION** | `topology.rs:99` | Compatible | The spec wants the raw byte plus a display-name lookup; a formatted string loses the numeric value for later logic. Minor. Prefer keeping the byte and formatting at the edge. |
| Partition byte offset = `StartSector * BytesPerSector` via checked arithmetic | `checked_sector_offset(start_lba, sector_size)` and `(num_sectors, sector_size)` | **IMPLEMENTED** | `topology.rs:91-93` | Compatible | Keep. |
| Extended / EBR chain recursion | **Absent.** Only the 4 primaries are read. | **MISSING** | `topology.rs:79` — `for i in 0..4` | Additive | Add when a real DVR image with logical partitions appears. |
| EBR cycle detection + depth limit | N/A — no recursion to protect | **MISSING (moot)** | — | — | Add together with EBR support, never after. |
| GPT detection and parsing | **`TopologyType::Gpt` is declared and never produced by any code path.** No LBA-1 read, no `"EFI PART"` check, no entry array. | **STUB** | `topology.rs:23` (declared); no producer anywhere in `crates/` | Additive | **The most misleading item in the codebase**: the enum variant implies a capability that does not exist. Either implement GPT or document the variant as reserved. |
| GPT done properly (CRC32s, backup header, real entry count, GUIDs, UTF-16 name, no 12-cap) | N/A | **MISSING** | — | Additive | If GPT is implemented, follow the spec here — it is a genuine improvement over the original and costs little extra once you are parsing the header at all. |
| Protective-MBR / hybrid detection | Absent | **MISSING** | — | Additive | Add with GPT. |
| Report ALL detected schemes, not one winner | Returns exactly one `TopologyType` | **DIFFERENT IMPLEMENTATION** | `topology.rs:47-51` (`topology_type` is a single field) | Changing the return shape breaks `crates/detection/src/detectors/tplink.rs:41` and `tests/tests/tplink_sample_raw_test.rs:33` | Worth adopting for DVR evidence (vendor-proprietary layouts with vestigial MBRs), but it is a breaking change to a struct with live consumers. Medium effort. |
| Whole-device view ALWAYS available, even when nothing is recognised | `UnpartitionedRaw` with one region covering `[0, total_len)` is returned whenever no partitions are found — **unconditionally**, with no filesystem-recognition requirement | **IMPLEMENTED** | `topology.rs:64-72,121-127` | Compatible | **Keep. This is a genuine current-better.** The spec's Phase 7.8 item 5 calls the original's behaviour (discard unrecognised whole-disk volumes) "exactly backwards" for DVR work. The current project already does the right thing. |
| Bounded per-partition reader with address space `[0, ByteLength)` | `BoundedReader` provides exactly this and is used by recovery levels | **IMPLEMENTED** | `crates/evidence-reader/src/bounded.rs:20-101`; used at `crates/recovery/src/levels.rs:46,222,257` | Compatible | Keep. But note it is **not** wired to `PartitionCandidate` — nothing calls `BoundedReader::new` with a partition region. The capability exists; the connection does not. |
| Partition reader does not expose the parent device | `BoundedReader.inner` is a private field with no accessor | **IMPLEMENTED** | `bounded.rs:13-17` | Compatible | Keep. |
| Pre-clamp recorded values preserved; clamping is a finding | **Neither.** Out-of-range partitions are **silently dropped** — `validate_region_bounds(&reg, total_len).is_ok()` gates insertion. No clamp, no record, no finding. | **MISSING** | `topology.rs:96-105` | Additive | **A real forensic gap.** A partition table declaring a partition past the end of the image is a meaningful anomaly; dropping it silently loses it. Fix is small and non-breaking (add a findings vector). |
| Overlapping entries detected and reported | No overlap check at all | **MISSING** | `topology.rs:79-107` | Additive | Same fix as above. `Region::overlaps` already exists (`region.rs:63-77`) — the primitive is there, unused here. |
| Zero-length / all-zero entries skipped with a finding | Skipped (`p_type == 0` at `topology.rs:83`; `num_sectors > 0` at `:89`) but **no finding recorded** | **PARTIALLY IMPLEMENTED** | `topology.rs:82-89` | Additive | Add the finding. |
| Structured `Findings` model | Does not exist anywhere | **MISSING** | — | Additive | Prerequisite for four rows above. |
| Filesystem-type probe returning multiple candidates with confidence | No filesystem probe in the partition layer. OEM detection exists separately in `crates/detection/src/detectors/*` and already returns confidence-bearing output. | **DIFFERENT IMPLEMENTATION** | `crates/detection/src/detectors/`, `crates/confidence/` | Compatible | **Current design is arguably better for this product.** The project detects *OEM families* with a confidence engine, which is the useful question for DVR work; generic filesystem typing is secondary. |
| Malformed table never crashes | `if reader.read_at(0, &mut mbr_buf).is_ok() && …` — read failure falls through to the whole-device path; no panic path | **IMPLEMENTED** | `topology.rs:77` | Compatible | Keep. |

## 4.7 Range tracking / coverage

| Specification Requirement | Current Implementation | Status | Evidence | Compatibility | Recommendation |
|---|---|---|---|---|---|
| A `ByteRange` value type | `Region { offset: u64, length: u64 }` — offset+length, **half-open** | **DIFFERENT IMPLEMENTATION** | `crates/forensic-core/src/region.rs:14-20,41-47` | **Semantic conflict: spec `ByteRange` is inclusive-inclusive** | **Do not introduce a second range type.** Keep `Region`. Half-open with explicit length is the less error-prone representation and it is already load-bearing across ~20 crates. |
| Overflow rejected at range construction | `Region::new` returns `Err(ArithmeticOverflow)` when `offset + length` overflows | **IMPLEMENTED** | `region.rs:23-31`; test `region.rs:186-190` | Compatible | Keep. |
| `Contains`, `Overlaps`, `Intersect` | All three on `Region` | **IMPLEMENTED** | `region.rs:49-88` | Compatible | Keep. |
| Immutable ranges | `Region` is `Copy` with public fields but no mutating methods; operations return new values | **IMPLEMENTED** | `region.rs:14-20` | Compatible | Keep. Note public fields allow direct mutation by callers (`gaps.rs:157` constructs `Region { offset, length }` literally, bypassing `Region::new`'s overflow check) — a minor hole. |
| A range **set** with a maintained canonical invariant | No set type. `merge_regions` produces a merged `Vec<Region>` inside one function. | **MISSING** | `crates/timeline/src/gaps.rs:143` | Additive | **Adopt.** Self-contained, zero dependencies, and the spec gives full pseudocode. |
| `Union` / `Add` | `merge_regions` (union only, one-shot) | **PARTIALLY IMPLEMENTED** | `gaps.rs:143` | Additive | Promote to a reusable type. |
| `Subtract` with mid-range split | **Absent.** Nothing subtracts one range set from another. | **MISSING** | — | Additive | Adopt — this is the operation DVR coverage accounting actually needs. |
| `Intersect` (set-level) | Only pairwise `Region::intersection` | **PARTIALLY IMPLEMENTED** | `region.rs:79-88` | Additive | Adopt at set level. |
| `Complement(within)` | Computed inline inside `estimate_coverage` as the gap walk | **PARTIALLY IMPLEMENTED** | `gaps.rs:147-170` | Additive | Promote to a reusable operation. |
| `TotalLength`, `Count`, `Min`, `Max` | `accounted_bytes` computed inline; no `Count`/`Min`/`Max` | **PARTIALLY IMPLEMENTED** | `gaps.rs:144-145` | Additive | Adopt. |
| `Min`/`Max` return null on empty, not an exception | N/A | **MISSING (moot)** | — | — | Rust `Option` makes this natural. |
| No value-enumerating API over 64-bit ranges | No such API exists | **IMPLEMENTED by absence** | — | Compatible | Keep. The original's `GetMissingValues` trap is absent. |
| One merge predicate (adjacency) | `merge_regions` uses one predicate (implementation at `gaps.rs:143`, single call site) | **IMPLEMENTED** | `gaps.rs:143` | Compatible | Keep. The original's three-predicate inconsistency is absent. |
| Coverage model: structural / claimed-intact / claimed-recovered / unreadable / unrecorded / carved | `CoverageEstimate { total_bytes, accounted_bytes, unaccounted_bytes, coverage_ratio, largest_unaccounted, unaccounted_regions, method }` — **one** accounted set vs total | **PARTIALLY IMPLEMENTED** | `crates/timeline/src/gaps.rs:51-60` | Additive | The named-sets model is the right target. Current version cannot express "this recording overlaps an unreadable range." |
| Recording intersecting an unreadable range must never be exported as complete | **Not enforced.** `Acquisition` enforces the analogous rule at acquisition level (`acquisition.rs:110-127`), but nothing cross-checks a `Recording`'s `source_offsets` against unreadable ranges. | **PARTIALLY IMPLEMENTED** | `acquisition.rs:110-127` (acquisition level only) | Additive | **Adopt.** Spec §9.9 calls this "the forensically critical one." The building blocks (`Region::overlaps`, `bad_sector_ranges`, `IntegrityFlag`) all exist; the cross-check does not. |

## 4.8 Content addressing (extents)

| Specification Requirement | Current Implementation | Status | Evidence | Compatibility | Recommendation |
|---|---|---|---|---|---|
| `Extent` with address-space tag and `Kind ∈ {Data, Sparse, Uninitialised, Unreadable}` | No extent type. `Recording.source_offsets: Vec<Region>` and `RecoveryCandidate.source_offsets: Vec<Region>` are plain untagged region lists. | **MISSING** | `crates/recovery/src/levels.rs:200` | Additive | Adopt when multi-extent recordings are supported. |
| `ExtentMap` — ordered, validated, non-overlapping | Absent | **MISSING** | — | Additive | Adopt with `Extent`. |
| Extent stream (scattered extents → one readable stream) | Absent. Recovery reads a **single contiguous window** per candidate. | **MISSING** | `crates/recovery/src/levels.rs:42-54` | Additive | **This is the most significant *functional* gap for DVR work**: a fragmented recording cannot currently be read as one stream. |
| Sparse/uninitialised explicitly zero-filled AND reported | Absent | **MISSING** | — | Needs `ReadResult` | Adopt. |
| Unreadable regions zero-filled, reported, read is `Partial` | Absent | **MISSING** | — | Needs `ReadResult` | Adopt. |
| Extent-map total vs declared length discrepancy is a finding | Dahua clamps a declared payload length to the image: `let available = reader.len().saturating_sub(pkt.payload_offset); let region_len = pkt.payload_len.min(available).max(1);` — clamps correctly but records no finding | **PARTIALLY IMPLEMENTED** | `crates/parsers/dahua/src/parser.rs:193-196` | Additive | Good instinct (the comment says "a declared length can never describe bytes outside the evidence"). Add the finding. |

## 4.9 Retry and error semantics

| Specification Requirement | Current Implementation | Status | Evidence | Compatibility | Recommendation |
|---|---|---|---|---|---|
| Bounded, iterative retry with backoff | **No retry logic anywhere** | **MISSING** | — | Additive | Adopt at medium priority. Needed for failing physical drives; irrelevant for file-backed images. |
| Retry never applied to non-retryable categories | N/A | **MISSING (moot)** | — | — | Adopt with retry. |
| Retry policy is configuration, not a public call parameter | N/A — no retry parameter pollutes the trait | **IMPLEMENTED by absence** | `reader.rs:74` | Compatible | Keep the clean signature. The original's public `retryAttemptNumber` parameter is exactly what the spec says to avoid. |
| Uniform bounds checking at one entry point | `read_at` implementations each check; `BoundedReader` checks its window; `validate_region_bounds` is the shared helper | **IMPLEMENTED** | `raw.rs:114-121`; `bounded.rs:78-85`; `checked.rs:64-89` | Compatible | Keep. Consistent across all implementations — unlike the original's seven divergent behaviours. |
| Negative / invalid offsets rejected | Unrepresentable: offsets are `u64` | **IMPLEMENTED by type** | `reader.rs:74` | Compatible | Keep. The original's missing negative checks cannot occur here. |
| Out-of-range is a non-retryable argument-class error, not an indexer exception | `ForensicError::OutOfBounds` — a domain error, never a panic | **IMPLEMENTED** | `error.rs:28-35` | Compatible | Keep. Better than the original's `IndexOutOfRangeException`. |
| Short read distinguishable from out-of-range | **Both reported as `OutOfBounds`.** `read_exact_at` returns `out_of_bounds("short read", …)`. | **PARTIALLY IMPLEMENTED** | `reader.rs:78-86` | Tightening changes classification for existing callers | Fix with `ReadResult`. Currently `RegionScanner` maps any `OutOfBounds` to `TerminationReason::Truncated` (`scanner.rs:172-176`), so a genuine caller bug is reported as evidence truncation — the same laundering the spec criticises in §3.7. |
| Never a null-reference / panic signal | `#![forbid(unsafe_code)]` in forensic-core; no `unwrap` on evidence-derived values in the reader; malformed evidence returns `Err` | **IMPLEMENTED** | `crates/forensic-core/src/lib.rs:16` | Compatible | Keep. Note `unwrap` **is** used on `try_into()` of already-bounds-checked slices (e.g. `crates/parsers/dahua/src/parser.rs:152,322`) — safe but worth a lint policy. |
| Cancellation returns a defined result with progress preserved | `ForensicError::Cancelled { context, bytes_processed }`; `TerminationReason::Cancelled` with `searched_bytes` | **IMPLEMENTED (spec has no equivalent)** | `error.rs:57-62`; `scanner.rs:34`; `progress.rs:39-53` | — | Keep. A current-project capability the spec does not require. |
| Disposal failures surfaced, never swallowed | Rust `Drop` cannot fail; `File`/`munmap` release deterministically | **IMPLEMENTED structurally** | `mmap.rs:120-127` | Compatible | Keep. |
| Structural anomalies become findings attached to artifacts, not log lines | **Partially.** `ValidationState` + `ParserRun` carry structured outcomes with reason/operation/subject, which is close in spirit. But there is no `Finding` type and no findings list on `StorageTopology` / `PartitionCandidate`. | **PARTIALLY IMPLEMENTED** | `crates/forensic-core/src/validation.rs`; `parser_run.rs`; absent in `topology.rs` | Additive | **Adopt a `Finding` type for the partition/geometry layers.** `ValidationState` already proves the pattern works. |

## 4.10 Forensic integrity requirements (FI-01 … FI-14)

| Spec FI | Requirement | Current Implementation | Status | Evidence |
|---|---|---|---|---|
| FI-01 | Read-only evidence access | Trait has no write method; `File::open` read-only; `WriteGuard` path denial; `inspect_source` rejects `ReadWrite`; `ReadOnlyMmap` uses `PROT_READ` | **IMPLEMENTED** (share-mode narrowing unaddressed, moot until Windows device path exists) | `reader.rs:41-93`; `raw.rs:50-52`; `write_guard.rs:47-77`; `source_safety.rs:84-110`; `mmap.rs:66` |
| FI-02 | Deterministic reads; no unrequested reads | No keep-alive, no random probing, no background timers | **IMPLEMENTED** | No `rand`/timer in `crates/evidence-reader` |
| FI-03 | Exact offsets; no floating point, no mask/shift in address arithmetic | All address arithmetic via `checked_*` integer helpers | **IMPLEMENTED** | `checked.rs:14-41`. (`f64` appears only in `coverage_ratio` at `gaps.rs:179-184` and `ProgressInfo::fraction` at `progress.rs:70-78` — reporting values, not addresses.) |
| FI-04 | **No silent truncation; every read reports valid-byte count and zero-filled ranges** | Valid count is returned; **zero-filled ranges are not reported and sparse holes are indistinguishable from real zeros** | **PARTIALLY IMPLEMENTED — the central gap** | `raw.rs:126-144`; `reader.rs:74` |
| FI-05 | Overflow protection | Every offset/length op checked; `Region::new` rejects overflow; tested against `u64::MAX` | **IMPLEMENTED** | `checked.rs:14-41,228-250`; `region.rs:23-31` |
| FI-06 | Source offsets preserved | `SourceRegion`/`Provenance` record byte ranges per artifact; `BoundedReader::to_absolute_offset` maps window→absolute | **PARTIALLY IMPLEMENTED** — address spaces are untyped, so a window-relative offset can be stored as if absolute | `provenance.rs:22-48`; `bounded.rs:52-66` |
| FI-07 | Sector-size correctness | No geometry model; two silent `512` defaults | **PARTIALLY IMPLEMENTED** — arithmetic is correct for any sector size, but nothing discovers or records one | `topology.rs:59`; `parsers/honeywell/src/parser.rs:41` |
| FI-08 | Partition-relative vs disk-relative addressing enforced | `BoundedReader` enforces bounds and hides the parent; but the same `Parser` methods receive whole-image and bounded readers with no type distinction | **PARTIALLY IMPLEMENTED** | `bounded.rs:13-101`; `parsing/src/orchestrator.rs:67-84` vs `recovery/src/levels.rs:225,258` |
| FI-09 | Reproducibility | `DeterminismKey` captures evidence hash, profile version+hash, config version+hash, recovery config, component versions; environment metadata excluded | **IMPLEMENTED** | `determinism.rs:23-74` |
| FI-10 | Error transparency | Typed errors carrying ranges; `ValidationState`/`ParserRun` carry structured reasons; **but** short-read vs out-of-range collapsed, and partition anomalies unrecorded | **PARTIALLY IMPLEMENTED** | `error.rs:18-66`; `reader.rs:78-86`; `topology.rs:96` |
| FI-11 | Identity separate from integrity | Only a full SHA-256 exists; no sampled hash to be mistaken for integrity | **IMPLEMENTED** | `crates/hashing/src/lib.rs:45-53` |
| FI-12 | Analysis path cannot modify the container | No write path on the evidence type; `WriteGuard` blocks evidence-directory writes | **IMPLEMENTED** | `reader.rs:41-93`; `write_guard.rs:47-77` |
| FI-13 | Bounded, auditable resource lifetime | RAII: `File` and `munmap` released on `Drop`; no leak possible | **IMPLEMENTED** | `mmap.rs:120-127` |
| FI-14 | Interpretation decisions explicit and operator-visible | `sector_size_override` parameter and `ReaderConfig` are operator-facing; **but** the chosen sector size, the container-kind inference, and the partition-scheme choice are not recorded in output | **PARTIALLY IMPLEMENTED** | `topology.rs:58-59`; `raw.rs:63-71`; `config.rs:47-68` |

---

# 5. Current Implementation — Simple Explanation

## 5.1 `EvidenceReader` — the one way to read evidence

**What it does.** Defines what "readable evidence" means for the whole platform. Anything that can hand back bytes at a byte offset can be evidence. The trait says: tell me your total length, and let me read bytes at an offset into a buffer I own.

**Is it actually working?** Production. It is the single read path for every crate that touches evidence.

**Who uses it.** Everything. `crates/detection` (topology + all six OEM detectors), all seven parser crates via the `Parser` trait, `crates/recovery`, `crates/hashing`, `apps/api`, and the test suites. Confirmed at `crates/parsers-core/src/parser.rs:21-70` — all seven `Parser` methods take `&dyn EvidenceReader`.

**Does changing it affect the DVR parsers?** **Yes — maximally.** It is the widest-blast-radius type in the project. Changing `read_at`'s return type touches every implementor (`RawReader`, `BoundedReader`, and at least six test mocks at `bounded.rs:110-138`, `scanner.rs:216-243`, `topology.rs:135-152`, `hashing/src/lib.rs:152-176`, `recovery/tests/*`, `tests/tests/tplink_synthetic_dry_run.rs:30-95`) and every caller.

**Compatible with the spec?** Structurally yes, in the right direction: byte-first with sector reads derived, which is exactly what spec Phase 2.8 asks for. The gap is the *return type*: `Result<usize>` where the spec requires a `ReadResult` with an outcome discriminator and zero-filled-range reporting.

## 5.2 `RawReader` — files and (on Unix) devices

**What it does.** Opens a `.raw`/`.dd`/`.img` file read-only and serves bytes. Seeks then reads under a mutex so it stays shareable across threads. Refuses `.E01`.

**Is it actually working?** Production for files. **Physical devices: Unix only** (`raw.rs:79` is `#[cfg(unix)]`), so on the declared Windows host `SourceKind::PhysicalDisk` is not constructible.

**Who uses it.** `apps/api/src/handlers.rs:7` and the test suites; it is the only concrete non-wrapper reader.

**Behaviour worth knowing.** Three specifics:
- Rejects a read whose *start* is past the end (`raw.rs:114-121`), but **clamps** a read that merely *extends* past the end (`raw.rs:138-140`). A tail read returns a short count rather than an error.
- Performs a **single** `read()` call (`raw.rs:142`). A short read from the OS is passed straight through as a smaller count — correct, but the caller must notice.
- Container kind comes from the file extension (`raw.rs:63-71`).

**Spec compatibility.** Compatible. Missing the spec's geometry query and partial-read reporting.

## 5.3 `BoundedReader` — a window you cannot escape

**What it does.** Wraps another reader and exposes only `[start, start+length)`. Inside the window, offset 0 means the window's first byte. Reads past the window end are rejected; reads that would straddle the end are clamped to it. `to_absolute_offset` converts a window offset back to a real evidence offset for provenance.

**Is it actually working?** Production, used by all three recovery levels.

**Who uses it.** `crates/recovery/src/levels.rs:46` (`read_bounded_window`), `:222` (L1), `:257` (L2). Also exercised directly by `tests/tests/regression_suite.rs:305`.

**Does changing it affect the DVR parsers?** Indirectly but importantly — recovery hands a `BoundedReader` to `parser.recognize_candidate` (`levels.rs:225,258`), so parser behaviour depends on its offset semantics.

**Spec compatibility.** This is the closest thing in the project to the spec's `IPartition::OpenReader()`, and it satisfies the two invariants the spec cares most about: it bounds every read, and `inner` is private with no accessor so a parser cannot reach the parent device. **What is missing is the wiring** — nothing constructs a `BoundedReader` from a `PartitionCandidate`.

## 5.4 `RegionScanner` — bounded scanning with honest accounting

**What it does.** Walks a region in fixed-size windows, calling a visitor per chunk. Checks cancellation and a byte budget each iteration. Returns a `ScanReport` saying what was actually searched and **why it stopped**: `Completed`, `Cancelled`, `LimitReached`, `Truncated`, or `OutOfBounds`.

**Is it actually working?** Production.

**Who uses it.** `crates/hashing/src/lib.rs:72` (streaming SHA-256), `apps/api/src/handlers.rs:356` (bounded search), and `tests/tests/phase1_foundational.rs:82,117`.

**Spec compatibility.** Aligned with the spec's intent and in one respect ahead of it: the spec has no cancellation requirement, and `TerminationReason` already provides the "did this complete or not" signal the spec wants. `skipped_ranges` exists in `ScanReport` (`scanner.rs:58`) but is **always empty** — `let skipped_ranges = Vec::new();` at `scanner.rs:131` and never pushed to. It is a placeholder for the sparse/skipped accounting the spec requires.

## 5.5 `forensic_core::checked` — all offset arithmetic, in one place

**What it does.** Every add, multiply, subtract, sector-to-byte conversion and bounds check on evidence-derived numbers. Returns an error instead of wrapping.

**Is it actually working?** Production, and tested against extremes — `checked.rs:228-250` exercises every helper across `{0, 1, u64::MAX/2, u64::MAX-1, u64::MAX}` asserting no panic.

**Who uses it.** `crates/evidence-reader` (scanner, mmap, bounded), `crates/detection/src/topology.rs:14`, `crates/recovery`, `crates/timeline`.

**Spec compatibility.** **Fully satisfies spec FI-05 and FI-03.** `checked_sector_offset` uses multiplication, not shifting, so it is correct for 520-byte and 4160-byte sectors — cases where the original was silently wrong. The spec's Phase 4 Q4 lists non-power-of-two sectors as "the failure mode most likely to produce plausible but wrong forensic output"; this project is immune to it.

## 5.6 `Region` — a byte range

**What it does.** `{offset, length}` as unsigned 64-bit values, meaning **half-open** `[offset, offset+length)`. Construction rejects overflow. Provides `end`, `contains`, `overlaps`, `intersection`.

**Is it actually working?** Production; the platform's universal byte-range currency.

**Who uses it.** Essentially everything: provenance, acquisition, recovery candidates, recordings, timeline events, scan reports, partition candidates, coverage estimates.

**Does changing it affect the DVR parsers?** **Yes — replacing or duplicating it is the single riskiest change available.**

**Spec compatibility.** **Semantically different from the spec's `ByteRange`.** Spec: inclusive both ends, `Length = End - Start + 1`. Current: half-open with explicit length; `region.rs:141-147` asserts adjacent regions do *not* overlap, which is correct for half-open and wrong for inclusive. Both models are valid; mixing them silently produces off-by-one errors. See §8.2.

## 5.7 `StorageTopologyProfiler` — MBR primaries, and nothing else

**What it does.** Reads sector 0. If the `0x55AA` signature is present, decodes the four primary MBR entries, converts each to a byte region using checked arithmetic, keeps those that fit inside the image, and returns `TopologyType::Mbr`. Otherwise returns `TopologyType::UnpartitionedRaw` with one region covering the whole image.

**Is it actually working?** Partially. MBR primaries: working and correct. **GPT: not implemented despite `TopologyType::Gpt` existing** (`topology.rs:23`, never produced). Extended partitions: not implemented (`for i in 0..4`).

**Who uses it.** `crates/detection/src/detectors/tplink.rs:41` (gates region selection on `topology_type == TopologyType::Mbr`), `crates/detection/src/detectors/honeywell.rs` (referenced in doc comments), and `tests/tests/tplink_sample_raw_test.rs:33-37` which asserts exactly two MBR partitions with types `0x82` and `0x83`.

**Does changing it affect the DVR parsers?** Yes — the TP-Link detector reads `topology.partitions` and pushes each `part.region` as a candidate region (`tplink.rs:43-44`). Changing `StorageTopology`'s shape breaks that plus the sample-raw test.

**Spec compatibility.** Same offsets and same signature test as spec §2.11, so the MBR core is compatible. Diverges on: no GPT, no EBR, no findings, silent dropping instead of clamping-with-record, one winning scheme instead of all schemes, and `sector_size` defaulting to a silent `512`.

**One notable current-better:** the whole-device fallback is unconditional. The spec (Phase 7.8 item 5) criticises the original for discarding an unrecognised whole-disk volume and calls that "exactly backwards" for DVR evidence. This project already returns it every time.

## 5.8 `estimate_coverage` / `merge_regions` — coverage, computed once

**What it does.** Takes the byte regions that parsed recordings claim, merges overlaps, sums them, and walks the gaps to produce unaccounted regions (suppressing holes below a threshold so sector padding does not create noise). Returns totals and a ratio.

**Is it actually working?** Production, with tests for overlap merging and small-hole suppression (`gaps.rs:432-461`).

**Who uses it.** `analyze` in the same module (`gaps.rs:251`), feeding the "are there gaps?" gate.

**Spec compatibility.** This is a **special case of** the spec's L5 range algebra: union plus complement-over-the-whole-image, computed inline for one purpose. What it cannot do is the operation the spec calls forensically critical — intersect a recording's claimed ranges with unreadable ranges to prove a recording is incomplete. It also constructs `Region` struct literals directly (`gaps.rs:157,166,175`), bypassing `Region::new`'s overflow check; safe here because the inputs are already-validated regions, but it is a pattern that would not survive hostile input.

## 5.9 `Acquisition` — the existing partial-coverage guarantee

**What it does.** Records how evidence was acquired: status, tool, receipt reference and hash, and two lists of regions — bad sectors and unresolved ranges. The builders enforce the key rule: **add any gap range and a `Complete` status is automatically downgraded to `Partial`** (`acquisition.rs:110-127`). Default status is `Unknown`, never `Complete`.

**Is it actually working?** Production, with tests asserting the downgrade (`acquisition.rs:186-207`).

**Spec compatibility.** This already implements, at the acquisition level, the spec's core forensic principle ("never present an incomplete acquisition as complete"). **The unmet half is at the recording level** — nothing checks whether a `Recording`'s `source_offsets` intersect `bad_sector_ranges`. The data and the primitive (`Region::overlaps`) both exist; the check does not.

## 5.10 `Parser` trait — the DVR integration surface

**What it does.** Seven methods, each taking `&dyn EvidenceReader` plus `&OemProfile`: `parse_filesystem`, `parse_metadata`, `parse_recordings`, `extract_timeline_events`, `validate_structure`, `recognize_candidate`, plus `id`/`version`. All OEM facts (magics, offsets, layout) come from the profile, never from Rust constants.

**Is it actually working?** Production, with seven implementations.

**Who uses it.** `crates/parsing/src/orchestrator.rs:67-84` (full-image path), `crates/recovery/src/levels.rs:225,258` and `crates/recovery/src/validation.rs:23,51` (bounded path).

**The critical observation.** The trait cannot express *which address space* the reader represents. In practice:
- Parsers read absolute offsets: `read_exact_at(0, superblock_size)` (`hikvision/src/parser.rs:45`, `uniview/src/parser.rs:45`, `dahua/src/parser.rs:111`), `read_exact_at(512, 1)` and `read_exact_at(1024, 4)` (`uniview/src/parser.rs:78,84`), `read_at(0, &mut mbr)` (`tplink/src/parser.rs:340`).
- Recovery hands them a window where offset 0 is not the image start.

So the same call means different bytes depending on the caller, with nothing to flag it. **This is a pre-existing defect, and it is the strongest single argument for importing the spec's typed-address-space requirement.**

## 5.11 Things the spec spends pages on that are already non-issues here

Worth stating explicitly so effort is not misdirected:

| Spec concern | Why it does not apply |
|---|---|
| Disposal leaks (FI-13, §2.18) — handles never disposed, DI containers leaked, no finalisers | Rust RAII. `File` closes on drop; `munmap` in `Drop` (`mmap.rs:120-127`). Structurally impossible. |
| Unchecked arithmetic (`CheckForOverflowUnderflow = False`) | Every op uses `checked_*` (`checked.rs`). |
| Mask/shift offset helpers valid only for power-of-two sectors | Multiplication only (`checked.rs:33-41`). |
| `double` in address arithmetic | No floating point in any address path. |
| Negative start sectors unchecked | Offsets are `u64`; unrepresentable. |
| Random keep-alive reads breaking determinism (FI-02) | No keep-alive exists. |
| Licence/authorisation gate | None. |
| String-encryption runtime | None. |
| `IDisk` exposing `Partitions` (circular layering) | `EvidenceReader` has no partition members; partition code is in a higher crate. |
| Public `retryAttemptNumber` parameter | No retry parameter on the trait. |
| Three inconsistent range-merge predicates | One `merge_regions` implementation, one call site. |
| `GetMissingValues` materialising every 64-bit value | No value-enumerating API. |
| Sampled MD5 mistaken for an integrity hash | Only full SHA-256 exists. |

---

# 6. Specification — Simple Explanation

## 6.1 Evidence abstraction

One way to talk about a piece of evidence, whatever it physically is. The spec's key structural rule: **split the "give me bytes" contract from the "here is the partition layout" contract**, because the original merged them and created a circular dependency. Evidence should know its identity, its geometry, and how to read bytes — nothing about partitions.

## 6.2 Physical disk access

All OS-specific code behind **one** narrow gateway: list devices, open read-only, ask the logical sector size, ask the physical sector size (so 512e drives can be identified), ask the total byte length, read at a byte offset, close. Every call returns the raw OS error code rather than logging and discarding it. One gateway means the core is portable and a fake gateway makes everything testable without hardware.

## 6.3 Raw and segmented images

A single flat image file is a byte-for-byte copy — read it directly. A segmented image is an ordered set of files pretending to be one disk. The spec's warnings, learned from the original's bugs: validate **every** segment's length when you open the set (do not assume all middles match the first), select segments with integer arithmetic (not floating point), **always check what a read returned**, and do not invent alignment rules unrelated to the real sector size.

## 6.4 E01 / EWF

**The spec explicitly cannot specify this.** The original delegated E01 entirely to a third-party library, so the reverse engineering produced zero format knowledge. The instruction is unambiguous: get an independent public specification, or license a library, and put it behind the block-read contract. Do not hand-roll a partial parser.

## 6.5 Sparse disk (two different meanings)

1. **A capture container** — a proprietary format that records exactly the disk regions you actually read, so you can replay an examination without the original drive. Fully specified: 64-byte header, 16-byte block-map records, block-indexed payload. The critical fix: blocks that were never recorded must be **reported as unrecorded**, not returned as silent zeros.
2. **Holes inside a dense image** — the spec requires holes to be explicitly zero-filled **and** reported, never left as whatever the caller's buffer happened to contain.

## 6.6 Sector geometry, sector size, sector count, byte addressing

- **Byte addressing is primary.** Sector reads are a convenience layer above byte reads.
- **Sector size is discovered data with a recorded source**, never a constant. Five provenance levels: `OperatorDeclared`, `Measured`, `DecodedFromContainer`, `InferredFromExternalLog`, `Assumed`. Operator-declared wins; assumed must be visible in every report.
- **No silent default.** If nothing can supply a sector size, the evidence opens in **degraded mode**: byte reads allowed, sector and partition operations refused. The spec is emphatic that quietly assuming 512 is worse than refusing, because the failure mode is not a crash but plausible-looking wrong output.
- **Byte length is measured; sector count is derived**, and `TailBytes = TotalBytes % BytesPerSector` is recorded so a non-sector-multiple image cannot hide data in an invisible tail.
- All conversions integer: `sector = offset / size`, `offsetInSector = offset % size`, `sectorsSpanned = (offset % size + length + size - 1) / size`.

## 6.7 Sector addressing, partition addressing, partition bounds

Three address spaces that must never be interchangeable: device-absolute bytes, partition-relative bytes, and sector indices. Converting between them requires passing the base or the scale factor explicitly — no bare casts. A partition is handed out as a **reader whose entire valid address space is that partition**: offset 0 is the partition's first byte, reads past the end fail, and the parent device is not reachable.

## 6.8 MBR

Read one sector. Check `0x55 0xAA` at bytes 510/511. Four entries at byte 446, stride 16; type byte at +4, start LBA (32-bit) at +8 **relative to the sector the table was read from**, length in sectors at +12. Absolute start = read sector + relative start. Reject impossible entries, clamp overruns **but record what was originally declared**, report overlaps, and recurse into extended containers (`0x05`, `0x0F`, `0x85`, `0xC5`, `0xCF`) using an EBR base — with a depth limit and cycle detection, which the original had neither of.

## 6.9 GPT

Header at LBA 1, signature `"EFI PART"`. Then do it **properly**, because the original did not: validate the header size and both CRC32s, read the real entry count and entry size from the header, read the partition type GUID and unique GUID and the UTF-16 name, honour the actual entry count (no 12-entry cap), and fall back to the backup header at the last LBA if the primary fails. Every deviation from the format spec is recorded as a finding.

## 6.10 Random access readers, block devices, `ReadResult`

One primitive: read at a byte offset into a caller-owned buffer. It returns a **`ReadResult`**, not a boolean and not a bare count:

- `Outcome` — `Complete`, `Partial`, `NotRecorded`, or `Failed`
- `BytesRead` — how many leading bytes genuinely came from the evidence
- `ZeroFilledRanges` — **exactly which ranges were zeros the reader substituted rather than read**
- `Category`, `PlatformErrorCode`, `Attempts`

The binding invariant: `Complete` if and only if every requested byte was read and nothing was zero-filled.

A block device adds `BytesPerSector`, `SectorCount`, `TailBytes`, and a `ReadSectors` convenience that must not duplicate the bounds logic.

## 6.11 Partial reads, failed reads, zero-filled ranges, failure categories, retry

- **Partial read:** keep the good prefix, zero the rest, and report both the valid length and the zero-filled ranges. Never discard the good prefix; never present it as complete.
- **Failed read:** one of eight categories — `Argument`, `OutOfRange`, `Oversized`, `TransientIo`, `PermanentIo`, `BackendClosed`, `CapacityExhausted`, `ContainerCorrupt`.
- **Retry:** iterative (not recursive), bounded, with explicit backoff, per-attempt telemetry, and **never applied to non-retryable categories**. Retry policy is configuration, not a parameter callers can manipulate.

## 6.12 Overflow protection, bounds checking

Checked arithmetic on every offset, length, sector and count computation. Validate bounds **before** any I/O and before any allocation. A documented maximum single-read size validated in **bytes**, not sectors.

## 6.13 Range tracking, `RangeSet` / `ByteRange`

An immutable set of inclusive byte ranges kept permanently sorted, non-overlapping and non-adjacent. Operations: add, subtract, union, intersect, complement within a window, contains, covers, total length, count, min, max, ordered enumeration. One merge predicate (adjacency) used everywhere. No API that enumerates individual byte values.

Purpose for DVR work: coverage accounting. Total device minus structurally-accounted minus claimed-by-intact-recordings minus claimed-by-recovered minus physically-unreadable equals carving candidates. And dually — claimed ranges intersected with unreadable ranges identifies recordings with holes, which **must never be exported as complete**.

## 6.14 Source offset preservation, evidence provenance

Every extent, interval and finding carries a typed, unambiguous source address, so any recovered artifact traces byte-for-byte back to device-absolute offsets.

## 6.15 Resource disposal, determinism, error handling

Deterministic disposal, explicit ownership flags on wrappers, disposal failures aggregated and surfaced. Identical evidence plus identical declared geometry plus identical tool version must yield byte-identical outputs — including the read sequence — across runs and machines. Every failure names the operation, the byte range, the evidence locator, the platform code and the attempt history; every structural anomaly becomes a finding attached to an artifact rather than a log line.

## 6.16 Test requirements

Property-based conversion round-trips across sector sizes `{512, 520, 1024, 2048, 4096, 4160}`; `SectorsSpanned` against a brute-force oracle; boundary reads at offset 0, the last byte, and every internal buffer/block/segment boundary; partial-read zero-fill and reporting; retry exhaustion and non-retryable short-circuit; synthetic MBR/GPT/hybrid/none corpora including cyclic EBR chains, >12-entry GPTs and bad-CRC GPTs; range-set property laws; and forensic tests proving no unrequested reads occurred, that a zero-fill is never mistaken for data, and that coverage accounting closes over the device.

## 6.17 Integration with DVR filesystem parsers

A parser is given a bounded reader, a known sector size with provenance, a bounded sector count, tail bytes, explicit read results, an extent-map builder and range algebra. It **must not** reach past its bounded reader, assume 512-byte sectors, mix address spaces in one result, ignore a read result, silently pad a size shortfall, treat zeros as data, or present a recording as complete when its extents intersect an unreadable range. It produces vendor identification with justifying bytes, an index artifact with raw bytes and offsets, a recording set with extent maps, findings, and a coverage contribution.

The whole contract reduces to one sentence from the spec: *given a locator and an explicit container kind, DataIO returns a read-only, deterministic, bounded, byte-exact view of the evidence at a known sector size with known provenance, in which every region that was not physically read is explicitly identified, and every structural anomaly encountered is recorded rather than discarded.*

---

# 7. Current vs Specification

Assessment values: **CURRENT BETTER**, **SPEC BETTER**, **ROUGHLY EQUIVALENT**, **DIFFERENT TRADE-OFF**, **CANNOT DETERMINE**.

## 7.1 Read primitive shape (byte-first vs sector-first)

**CURRENT:** `read_at(offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError>`. Byte-addressed, caller-owned buffer, no sector concept in the trait.

**SPEC:** `IRandomAccessReader.ReadAt(long byteOffset, Span<byte>) -> ReadResult`, with `IBlockDevice` adding sector reads derived from it.

**DIFFERENCE:** Structurally the same decision. The spec had to argue for byte-first because the original was sector-only; the current project started byte-first. The spec adds a sector layer on top, which the current project lacks.

**ASSESSMENT: ROUGHLY EQUIVALENT** (on the primitive itself).

**WHY:** Both put byte addressing at the bottom and both use a caller-owned buffer. The spec's extra sector layer is an addition, not a correction. The current signature is idiomatic Rust and needs no change to satisfy the spec's architectural intent.

## 7.2 Read result / partial-read reporting

**CURRENT:** `Result<usize, ForensicError>`. Success carries a byte count. `read_at` clamps at the tail and returns the short count. `read_exact_at` turns a short read into `Err(OutOfBounds{context:"short read"})`, discarding the partial data. Nothing anywhere reports which bytes were substituted zeros.

**SPEC:** `ReadResult { Outcome ∈ {Complete, Partial, NotRecorded, Failed}, BytesRead, ZeroFilledRanges, Category, PlatformErrorCode, Attempts }`, with `Complete ⟺ BytesRead == requested && ZeroFilledRanges.IsEmpty`.

**DIFFERENCE:** The current API cannot express "these 4 KiB are real data and these 512 bytes are zeros I made up." The spec's whole FI-04 exists to make that expressible.

**ASSESSMENT: SPEC BETTER — decisively, and this is the most important row in this section.**

**WHY:** In a DVR case, a region of zeros can mean recorded-but-blank video, an unallocated hole, or a sector the drive could not read. Those three have completely different evidentiary weight. The current API returns identical bytes and an identical count for all three. That is the one place where the current implementation can produce *plausible but wrong* forensic output, which is the failure mode the spec correctly identifies as worse than a crash. Note this is a **capability gap, not a bug**: the current code never claims more than it knows, it simply cannot record what it does know.

## 7.3 Overflow and bounds safety

**CURRENT:** Every offset/length operation through `checked_*` helpers returning `Result` (`checked.rs:14-41`). `Region::new` rejects overflow (`region.rs:23-31`). Offsets are `u64`, so negatives are unrepresentable. Extremes tested for no-panic (`checked.rs:228-250`). `#![forbid(unsafe_code)]` in forensic-core.

**SPEC:** Requires checked arithmetic throughout, explicit negative-offset rejection, validation before allocation, and a documented maximum read size in bytes. Records that the original built with overflow checking *disabled* and contained an unreachable overflow handler as a result.

**DIFFERENCE:** The current project already meets or exceeds every requirement in this area.

**ASSESSMENT: CURRENT BETTER.**

**WHY:** Rust's `u64` makes negative offsets unrepresentable rather than merely checked, and `checked_*` makes overflow a compile-time-visible `Result` rather than a runtime setting that can be switched off in a project file. The spec's Phase 8.5 table lists nine partial mitigations in the original; the current project needs none of them.

## 7.4 Sector-size handling and geometry

**CURRENT:** No geometry model. `checked_sector_offset(sector, sector_size)` is correct for any positive sector size, but nothing discovers, stores, or records a sector size. Two silent `512` fallbacks: `topology.rs:59`, `parsers/honeywell/src/parser.rs:41`.

**SPEC:** `EvidenceGeometry` with `BytesPerSector` + provenance (5 levels), measured `TotalBytes` + provenance, derived `SectorCount`, explicit `TailBytes`, `ConflictingClaims`, plus a degraded mode that refuses sector operations rather than assuming 512.

**DIFFERENCE:** The current project has correct sector *arithmetic* and no sector *model*. The spec has both.

**ASSESSMENT: SPEC BETTER.**

**WHY:** Two distinct reasons. First, the arithmetic being safe does not help if the input is a silent guess — a 4Kn drive analysed at an assumed 512 produces partition offsets wrong by a factor of 8, and the MBR still parses, so nothing visibly fails. Second, forensic reporting needs to state *where* the sector size came from; "we assumed 512" and "the operator declared 4096" are different claims and currently indistinguishable. The spec's inversion of the original's precedence (operator-declared beats measured beats inferred-from-log) is also clearly correct and costs nothing to adopt.

**Caveat on urgency (honest):** the spec's own open question H-3 admits it does not know whether 4Kn or non-power-of-two sectors actually occur in DVR evidence. Since `TotalBytes` here is always a measured file length and all current parsers work in absolute bytes, an assumed sector size currently affects only `StorageTopologyProfiler`'s LBA→byte conversion. The gap is real but its blast radius today is one function.

## 7.5 Partition handling

**CURRENT:** MBR four primaries, correct offsets, checked conversion, unconditional whole-device fallback. No GPT (variant declared, never produced). No EBR. No findings. Out-of-range partitions silently dropped (`topology.rs:96`). No overlap check. Single winning scheme.

**SPEC:** All schemes reported with per-scheme findings; full correct GPT; EBR with depth and cycle limits; pre-clamp values preserved; clamping, overlap and out-of-range as findings; whole-device always present; bounded partition reader.

**DIFFERENCE:** The current implementation covers the most common case correctly and records nothing about anomalies.

**ASSESSMENT: SPEC BETTER, with one CURRENT BETTER sub-item.**

**WHY spec better:** A partition table that declares a partition extending past the end of the image is exactly the kind of thing a DVR forensic report should mention. Currently it vanishes at `topology.rs:96` with no trace. Same for overlapping entries — `Region::overlaps` already exists and is simply not used here. And `TopologyType::Gpt` existing without an implementation is worse than not having the variant, because it implies a capability in a court-facing type.

**WHY one current-better:** the unconditional whole-device fallback (`topology.rs:64-72,121-127`). The spec spends a paragraph criticising the original for discarding unrecognised whole-disk volumes and calls that behaviour "exactly backwards" for DVR evidence. The current project already returns it every time, with no filesystem-recognition precondition. Keep that.

## 7.6 Bounded / partition-relative reading

**CURRENT:** `BoundedReader` — window validated at construction, local offsets bounds-checked, reads clamped to the window, `to_absolute_offset` for provenance, private `inner` with no accessor, implements `EvidenceReader` so it substitutes anywhere.

**SPEC:** `IPartition.OpenReader() -> IBlockDevice` bounded to `[0, ByteLength)`, must not expose the parent, plus typed address spaces so a partition-relative offset cannot be passed where an absolute one is expected.

**DIFFERENCE:** The mechanism matches closely. The spec adds type-level address-space distinction; the current project relies on convention. And nothing currently connects `BoundedReader` to `PartitionCandidate`.

**ASSESSMENT: ROUGHLY EQUIVALENT on the mechanism; SPEC BETTER on enforcement.**

**WHY:** `BoundedReader` genuinely satisfies the spec's two hard invariants — bounded reads and no parent access. What it cannot prevent is the situation at `crates/recovery/src/levels.rs:225` versus `crates/parsing/src/orchestrator.rs:67`: the same `Parser` method receiving a window in one path and the whole image in the other, with parsers like `uniview/src/parser.rs:78,84` reading fixed offsets 512 and 1024. The spec's typed addresses would make that a compile error. This is a real pre-existing defect and the strongest practical argument for importing that one spec idea.

## 7.7 Error handling

**CURRENT:** `ForensicError` — 9 variants, `OutOfBounds` carrying `{context, offset, length, source_len}`, `Cancelled` carrying `bytes_processed`, `Io` wrapping `std::io::Error` (so `raw_os_error()` is preserved). Exhaustive `Display`. `ValidationState` + `ParserRun` carry structured, reportable parse outcomes.

**SPEC:** Eight read-failure categories, every failure carrying category + range + locator + platform code + attempt history, every structural anomaly a finding on an artifact. Records that the original had encrypted messages, a bare `bool` covering four distinct conditions, and `GetLastWin32Error()` logged then discarded.

**DIFFERENCE:** Current error types are structured and range-carrying — far ahead of the original. Two gaps: short-read and out-of-range collapse into one variant (`reader.rs:78-86`), and there is no retryable/non-retryable distinction.

**ASSESSMENT: ROUGHLY EQUIVALENT, trending SPEC BETTER.**

**WHY:** The current model already does the thing that matters most — errors are typed values carrying the failing range, not messages. The spec's finer categorisation matters mainly once retry exists (you must know what is retryable) and for the short-read/out-of-range distinction, which currently causes `RegionScanner` to report a caller bug as evidence truncation (`scanner.rs:172-176`) — the same "laundering" the spec criticises in §3.7.

## 7.8 Retry behaviour

**CURRENT:** None.

**SPEC:** Bounded iterative retry, explicit backoff, per-attempt telemetry, `ShouldRetry(category)`, reopen only when the handle is provably invalid, policy as configuration.

**DIFFERENCE:** Absent vs specified.

**ASSESSMENT: SPEC BETTER for physical media; ROUGHLY EQUIVALENT for file-backed images.**

**WHY:** Retrying a `read()` on a local file almost never helps — the failure is structural. Retrying a failing SATA/USB drive frequently does, and failing drives are the normal case in DVR forensics. But since physical-disk support is currently Unix-only and unreachable on the declared Windows host, retry has no live use case today. Correctly sequenced *after* a working device path exists.

## 7.9 Range / coverage handling

**CURRENT:** `merge_regions` + `estimate_coverage` — union and complement, computed once, inside one function, returning a `CoverageEstimate` with a single accounted set. `Region::overlaps`/`intersection` exist pairwise.

**SPEC:** Immutable `RangeSet` with add/subtract/union/intersect/complement/covers/total-length, canonical invariant always held, plus a `CoverageModel` of named sets (structural, claimed-intact, claimed-recovered, unreadable, unrecorded, carved).

**DIFFERENCE:** One-shot special case vs reusable algebra.

**ASSESSMENT: SPEC BETTER.**

**WHY:** The operation the spec calls forensically critical — intersect claimed ranges with unreadable ranges to prove a recording has holes — cannot be expressed today. `Acquisition` already stores `bad_sector_ranges` and `unresolved_ranges`, and `Recording` already stores byte regions, so the *data* for that check exists and the check is simply unwritable without set subtraction/intersection. Also worth noting: the spec's own §9.10 admits the original's range engine had **zero in-assembly consumers**, so this is spec design work rather than reverse-engineered fact — but it is good design work, and the current project has a concrete use for it.

## 7.10 Content addressing (extents → stream)

**CURRENT:** No extent layer. Recovery reads a single contiguous window per candidate, capped at 8 MiB (`crates/recovery/src/levels.rs:35,42-54`), and flags `truncated_view` which becomes a `ValidationStateKind::Review` (`levels.rs:169-183`).

**SPEC:** `Extent` with address-space tag and `Kind ∈ {Data, Sparse, Uninitialised, Unreadable}`, validated `ExtentMap`, `ExtentStream`, sparse/unreadable explicitly zero-filled and reported.

**DIFFERENCE:** Contiguous-window-only vs scattered-extent streaming.

**ASSESSMENT: SPEC BETTER.**

**WHY:** DVR recordings are routinely fragmented across non-contiguous clusters. Without an extent layer a fragmented recording cannot be exported as one stream, which is a functional limitation, not just an architectural one. Credit where due: the current code handles its own limitation honestly — the 8 MiB cap produces `Review` with the reason "window truncated to scan cap, bytes beyond the cap were not examined" (`levels.rs:173`) rather than silently claiming completeness.

## 7.11 Resource management

**CURRENT:** Rust RAII. `File` closes on drop. `ReadOnlyMmap::drop` calls `munmap` (`mmap.rs:120-127`). No finalisers needed, no leak possible, no ownership flags needed.

**SPEC:** Deterministic disposal, explicit ownership flags on every wrapper, aggregated disposal failures, a test asserting zero open handles after teardown. FI-13 exists because the original never disposed its device handle, never disposed its E01 virtual disk or DI container, and swallowed disposal failures.

**DIFFERENCE:** The spec's entire FI-13 is a set of disciplines needed in a GC language. Rust provides them structurally.

**ASSESSMENT: CURRENT BETTER.**

**WHY:** Ownership and `Drop` make the failure class impossible rather than merely tested-against. `leaveOpen` flags — which the spec requires on every wrapper — are unnecessary because borrowing (`BoundedReader<'a>` holding `&'a dyn EvidenceReader`) expresses non-ownership in the type system. No work needed here at all.

## 7.12 Read-only / forensic-safety enforcement

**CURRENT:** Four independent layers: no write method on the trait; `File::open` read-only; `WriteGuard` denying evidence-directory paths with a custody event; `inspect_source` rejecting `ReadWrite` sources and never fabricating `ReadOnly` from an undetermined state. Plus `ReadOnlyMmap` using `PROT_READ` with `MAP_PRIVATE`.

**SPEC:** FI-01 (read-only, narrowest share mode), FI-12 (recording target must be a distinct type that cannot be constructed from an evidence locator). No source-state inspection requirement at all.

**DIFFERENCE:** The current project has a source-safety gate the spec does not require. The spec has a share-mode requirement the current project does not address.

**ASSESSMENT: CURRENT BETTER.**

**WHY:** Defence in depth across four layers, plus the `Unknown`-is-never-`ReadOnly` rule (`source_safety.rs:103-109`), is stronger than the spec's FI-01. The share-mode gap is real but moot: it only matters for a live device handle, and there is no Windows device path yet. Notably the original opened the evidence device with read **and write** sharing (spec §5.1.1) — a defect the current project does not have to unwind.

## 7.13 Determinism

**CURRENT:** No unrequested reads of any kind. `DeterminismKey` (`determinism.rs:23-40`) captures evidence hash, profile version + hash, config version + hash, recovery config and all component versions, with timestamps/DB IDs/temp paths/durations excluded from comparison. Hash proven window-size-independent (`hashing/src/lib.rs:203-225`).

**SPEC:** FI-09 requires byte-identical outputs including read sequences across runs and machines, and records three reproducibility hazards in the original (random keep-alive, licence gate, per-read decoder stream).

**DIFFERENCE:** None of the original's three hazards exist here. The current project additionally models the determinism *input set* explicitly, which the spec mentions but does not specify a type for.

**ASSESSMENT: CURRENT BETTER.**

**WHY:** `DeterminismKey` is a concrete artifact the spec only gestures at, and the hazards FI-09 was written to prevent are structurally absent. One honest limitation: there is no *test* asserting that a full analysis issues exactly the reads it requested — the spec's fake-gateway approach (§16.5 item 3) would give that, and no such harness exists here.

## 7.14 Extensibility

**CURRENT:** Trait-based. New sources implement `EvidenceReader`; `BoundedReader` shows decoration works. But new sources cannot express geometry, partial reads, or unrecorded regions, because the trait has no vocabulary for them.

**SPEC:** Layered contracts (L0–L5) with ten interfaces, five load-bearing. Explicitly aims for a smaller interface count than the original's ~17 + 4 structs.

**DIFFERENCE:** Current is simpler and thinner; spec is richer and more expressive.

**ASSESSMENT: DIFFERENT TRADE-OFF.**

**WHY:** The current trait's thinness is why adoption is *easy* (adding capability is additive) and also why it is *needed* (a sparse-capture source has nothing to report `NotRecorded` with). The spec's layering is correct for the target feature set but is more structure than a raw-file-only reader justifies. The right move is to grow the current trait toward the spec's vocabulary as each capability lands, not to build all five layers up front.

## 7.15 Compatibility with DVR parsers

**CURRENT:** `Parser` trait, seven methods, each `&dyn EvidenceReader + &OemProfile`. All OEM facts in versioned profile data, never Rust constants. Seven implementations. Called with the whole-image reader in `parsing/src/orchestrator.rs:67-84` and with a `BoundedReader` in `recovery/src/levels.rs:225,258`.

**SPEC:** Parser receives a bounded reader, geometry with provenance, explicit read results, extent-map builder, range algebra; must not reach past its reader, assume 512, mix address spaces, ignore read results, pad silently, treat zeros as data, or export incomplete recordings as complete.

**DIFFERENCE:** The current contract delivers the bounded reader (sometimes) and none of the rest.

**ASSESSMENT: SPEC BETTER on the contract; CURRENT BETTER on one point the spec does not make.**

**WHY spec better:** The address-space ambiguity described in §7.6 is a live defect, and parsers cannot currently detect a partial read or an unrecorded region because the API cannot tell them.

**WHY current better on one point:** the spec never states that OEM facts must be data rather than code. This project enforces it — `Cargo.toml` comments and `crates/forensic-core/src/lib.rs:25-27` both state that no OEM signature, magic, offset or weight may be a source constant, and parsers read magics from `profile.signatures` (`dahua/src/parser.rs:113-114`) and layout from `profile.layout` (`hikvision/src/parser.rs:42`). For a multi-vendor tool that must add OEMs without recompiling, this is a more valuable architectural property than anything in spec Phase 13.

## 7.16 Testability

**CURRENT:** `EvidenceReader` is trivially mockable and mocked in at least six places (`bounded.rs:110-138`, `scanner.rs:216-243`, `topology.rs:135-152`, `hashing/src/lib.rs:152-176`, `recovery/tests/adversarial_recovery.rs`, `tests/tests/tplink_synthetic_dry_run.rs:30-95`). A deterministic fixture generator exists (`tests/src/fixtures.rs`, 468 lines, with `FixtureShape::{Normal, Sparse, Truncated, Fragmented, WrongOffset, Partial}`). A validation corpus exists. CI workflow present.

**SPEC:** Requires a synthetic device generator, a partition-structure builder, a **recording fake platform gateway**, a byte-exactness harness, property-based testing, a handle-leak detector, and a real-evidence smoke corpus.

**DIFFERENCE:** Current has mocking and a fixture generator; missing the partition-structure builder, the recording gateway, property-based testing, and byte-exactness oracles.

**ASSESSMENT: ROUGHLY EQUIVALENT today; SPEC BETTER as a target.**

**WHY:** The existing fixture generator plus per-OEM adversarial shapes is real, working infrastructure the spec assumes has to be built. What is genuinely missing is the spec's two highest-value test tools: the *recording* fake gateway (which is what makes "no unrequested reads" and determinism testable at all) and a synthetic partition-structure builder (which is what makes GPT/EBR work safe to write). A handle-leak detector is unnecessary — Rust ownership covers it.

## 7.17 Maintainability

**CURRENT:** Small, focused crate (8 modules, ~1,100 lines in `evidence-reader`). Doc comments cite requirement numbers throughout. Decision docs (`docs/decisions/OPEN-1`, `OPEN-2`) record open questions with evidence and gates. Compiles clean.

**SPEC:** Ten interfaces across six layers, ~3,300 lines of specification behind them.

**DIFFERENCE:** Current is materially smaller.

**ASSESSMENT: CURRENT BETTER today; CANNOT DETERMINE at feature parity.**

**WHY:** The current code is smaller because it does less. Its genuinely superior maintainability practices — requirement traceability in doc comments, written decision records with verification gates, OEM facts as versioned data — are things the spec does not ask for and should be preserved through any migration. Whether the current structure stays maintainable once geometry, extents, range algebra and segmented sources land is not knowable from present code.

## 7.18 Summary table

| Subsystem | Assessment |
|---|---|
| Read primitive shape | ROUGHLY EQUIVALENT |
| Read result / partial-read reporting | **SPEC BETTER (decisive)** |
| Overflow and bounds safety | **CURRENT BETTER** |
| Sector size / geometry | SPEC BETTER |
| Partition handling | SPEC BETTER (whole-device fallback: CURRENT BETTER) |
| Bounded / partition-relative reading | ROUGHLY EQUIVALENT (enforcement: SPEC BETTER) |
| Error handling | ROUGHLY EQUIVALENT → SPEC BETTER |
| Retry | SPEC BETTER (physical media only) |
| Range / coverage algebra | SPEC BETTER |
| Content addressing / extents | SPEC BETTER |
| Resource management | **CURRENT BETTER** |
| Read-only / forensic safety enforcement | **CURRENT BETTER** |
| Determinism | **CURRENT BETTER** |
| Extensibility | DIFFERENT TRADE-OFF |
| DVR parser contract | SPEC BETTER (OEM-facts-as-data: CURRENT BETTER) |
| Testability | ROUGHLY EQUIVALENT → SPEC BETTER |
| Maintainability | CURRENT BETTER today / CANNOT DETERMINE at parity |

---

# 8. Compatibility Analysis

**Overall verdict: PARTIALLY COMPATIBLE.** The specification's *requirements and invariants* are compatible with the current architecture and can be introduced incrementally. The specification's *declared interfaces* are not compatible at all, because they are .NET types. Adoption therefore means re-expressing spec requirements in Rust, additively, one capability at a time.

## 8.1 API compatibility

### Can the proposed interfaces coexist with the current ones?

**Not as written — they are C# interfaces.** There is nothing to coexist with. The real question is whether the *requirements* can be added to the current Rust traits without breaking existing code. Requirement by requirement:

| Spec requirement | Additive or breaking? | Detail |
|---|---|---|
| `ReadResult` as the return of the primitive read | **BREAKING** (contained) | Changing `EvidenceReader::read_at`'s return type touches 2 real implementors (`RawReader`, `BoundedReader`) and ~6 test mocks, plus every call site. Mitigation: add `read_at_detailed` returning a rich result as a **defaulted** trait method that wraps `read_at`, then migrate callers, then flip the default. Two-stage, no big-bang. |
| Sector-addressed reads (`read_sectors`) | **ADDITIVE** | No `read_sectors` exists anywhere, so nothing can break. Add as a defaulted method requiring geometry. |
| `EvidenceGeometry` with provenance | **ADDITIVE** | New type. No existing signature carries geometry, so nothing changes. Wiring it into `StorageTopologyProfiler::profile` replaces the `Option<u64>` override parameter — that touches 4 call sites (`detectors/tplink.rs:41`, `tests/tests/phase2_detection.rs:226`, `tests/tests/tplink_sample_raw_test.rs:33`, plus the module's own tests). |
| `Finding` model on topology/partitions | **ADDITIVE-ish** | Adding a `findings: Vec<Finding>` field to `StorageTopology` breaks struct-literal construction and `PartialEq` comparisons in tests. There are 3 construction sites, all inside `topology.rs`. Low cost. |
| `RangeSet` algebra | **PURELY ADDITIVE** | New type in `forensic-core`. `estimate_coverage` can be reimplemented on top of it without changing its public signature. |
| `Extent` / `ExtentMap` / extent stream | **PURELY ADDITIVE** | Nothing exists to conflict with. |
| Retry policy | **ADDITIVE** | New type; opt-in at reader construction. |
| Platform gateway | **ADDITIVE** | Would sit beneath `RawReader`; `RawReader`'s public API need not change. |
| Typed address spaces | **BREAKING, WIDE** | Would change `Region`'s meaning or introduce parallel types across ~20 crates. See §8.4 and §8.6. |
| All-schemes partition result | **BREAKING, CONTAINED** | `StorageTopology.topology_type: TopologyType` → a list. Breaks `detectors/tplink.rs:41` and `tests/tests/tplink_sample_raw_test.rs:33`. |

### One important asymmetry

The current trait is **thin enough to grow**. Rust's defaulted trait methods mean geometry, sector reads and detailed read results can all be added with default implementations that degrade gracefully (return "geometry unavailable", or wrap `read_at`). No implementor is forced to change on day one. This is the single biggest factor making incremental adoption realistic.

## 8.2 Type compatibility

| Spec type | Current counterpart | Conflict? | Assessment |
|---|---|---|---|
| `IRandomAccessReader` | `EvidenceReader` trait | No conflict | Same role. Current is missing only the result type. |
| `IBlockDevice` | *(nothing)* | No conflict | Purely additive. |
| `EvidenceGeometry` | *(nothing)* | No conflict | Purely additive. |
| `ReadResult` | `Result<usize, ForensicError>` | **Conflict in shape, not in name** | Rust's `Result` is the idiomatic error channel; the spec's `Outcome`-plus-`Failed` model folds failure into the success type. A Rust-native adaptation should keep `Result<ReadOutcome, ForensicError>` — errors stay in `Err`, and `ReadOutcome` carries `Complete`/`Partial`/`NotRecorded` with `bytes_read` and `zero_filled: Vec<Region>`. Do not import the spec's `Failed` variant; that is a C# idiom for a language without `Result`. |
| **`ByteRange`** | **`Region`** | **DIRECT SEMANTIC CONFLICT** | Spec: inclusive-inclusive, `Length = End - Start + 1`. Current: half-open, explicit `length`. Both correct; **mixing them is silently wrong**. |
| `RangeSet` | `merge_regions` + `CoverageEstimate` | No type conflict | Current is a function, not a type. Additive. |
| `IPartition` | `PartitionCandidate` + `BoundedReader` | Partial overlap | `PartitionCandidate` is data (`topology.rs:29-42`); `BoundedReader` is the reader. The spec merges them via `OpenReader()`. Adding a method that produces a `BoundedReader` from a `PartitionCandidate` is additive and small. |
| `ReadFailureCategory` | `ForensicError` variants | No conflict | Extending the enum is safe because existing matches are non-exhaustive (`scanner.rs:172-177`). |
| `IEvidenceSource` | `EvidenceReader` + `Evidence` (`case.rs`) | Partial overlap | Current splits "readable thing" (`EvidenceReader`) from "case record" (`Evidence`). That split is arguably cleaner than the spec's merged `IEvidenceSource`. |
| `IDisposable` | Rust `Drop` | No conflict | Rust is structurally superior; nothing to import. |
| `IProperty<T>` | *(nothing)* | No conflict | The provenance *idea* is worth importing; the three-value `Actual/Inferred/Forced` shape should be replaced by a Rust enum of five provenance levels per the spec's own correction. |

### The `ByteRange` / `Region` conflict in detail — the highest-risk item in this audit

Concrete evidence of the current semantics:
- `region.rs:41-47` — `contains` returns `byte_offset >= self.offset && byte_offset < end`. Exclusive upper bound.
- `region.rs:141-147` — test: region `[100,150)` and region `[150,200)` are asserted **not** to overlap ("adjacent, not overlapping").
- `region.rs:79-88` — `intersection` computes `length = end - start`, no `+1`.
- `checked.rs:64-89` — `validate_region_bounds` rejects when `offset + length > source_len`, i.e. a region ending exactly at `source_len` is valid (`checked.rs:190-194`).

If a spec-shaped inclusive `ByteRange` were introduced alongside `Region`, then:
- Every conversion needs `±1`, and a missed one produces a range wrong by exactly one byte.
- Adjacency changes meaning: `[100,149]` and `[150,200]` are *adjacent and mergeable* in the spec model; `[100,150)` and `[150,200)` are *adjacent and non-overlapping* in the current model. A `RangeSet` built on the wrong assumption would either over-merge or fail to merge.
- The error would type-check, produce plausible output, and surface only as a one-byte discrepancy in a court-facing report.

**Recommendation: keep `Region` and build the spec's `RangeSet` algebra on half-open semantics.** Do not introduce a second range type. The spec's inclusive choice is inherited from the original assembly's `Range<T>` (spec §9.2 marks the inclusivity itself as `[INFERRED]`, not confirmed) and carries no advantage here.

## 8.3 Parser compatibility

### What each parser actually expects from the reader

All seven parsers receive `&dyn EvidenceReader` and use only `len()`, `read_at()` and `read_exact_at()`. None uses `read_region`, `source_kind` or `source_path` for logic. Verified call sites:

| Parser | What it reads | Offsets used | Line evidence |
|---|---|---|---|
| **Hikvision** | superblock at 0, size from `profile.layout["superblock_size"]` (default 512); HKSEG gate at `profile.layout["hkseg_start"]` (default 512) | **absolute** | `hikvision/src/parser.rs:42,45,102-103` |
| **Dahua** | DHFS superblock at 0; index header at `index_offset` with `+8` bounds pre-check; DHAV packet scan from offset 0 over a 16 MiB window | **absolute** | `dahua/src/parser.rs:110-111,148-149,258,341-345` |
| **Uniview** | superblock at 0; **model byte at fixed 512**; **firmware bytes at fixed 1024**; EC1001 at `profile.layout["ec1001_start"]` (default 512) | **absolute, two hard-coded** | `uniview/src/parser.rs:45,78,84,120-121,157-164` |
| **Honeywell** | header at 0, `sector_size` from `profile.layout["sector_size"]` **defaulting to 512** | **absolute** | `honeywell/src/parser.rs:41,45` |
| **CP Plus / UBS** | profile-driven header read | **absolute** | `cpplus-ubs/src/parser.rs` |
| **TP-Link** | **MBR at offset 0**, checks `0x55AA` and partition types `0x82`/`0x83` at `446+4` / `462+4`; also calls `StorageTopologyProfiler` | **absolute** | `tplink/src/parser.rs:339-344`; `tplink/src/raw_layout.rs:12-16` |
| **Unified** | orchestration over the others | **absolute** | `unified/src/parser.rs` |

### The address-space problem, precisely

Two call paths exist and nothing distinguishes them:

```
PATH A — whole-image reader
  crates/parsing/src/orchestrator.rs:67   parser.validate_structure(reader, profile)
                                    :71   parser.parse_filesystem(reader, profile)
                                    :75   parser.parse_metadata(reader, profile)
                                    :79   parser.parse_recordings(reader, profile)
                                    :83   parser.extract_timeline_events(reader, profile)
        => offset 0 IS the image start.  Absolute reads are correct.

PATH B — BoundedReader window
  crates/recovery/src/levels.rs:222  let bounded = BoundedReader::new(reader, region.offset, region.length)?;
                               :225  parser.recognize_candidate(&bounded, profile)
                               :257  let bounded = BoundedReader::new(...)
                               :258  parser.recognize_candidate(&bounded, profile)
        => offset 0 IS the region start.  Absolute reads silently read the WRONG bytes.

PATH C — ambiguous
  crates/recovery/src/validation.rs:23  parser.validate_structure(reader, profile)
                              :51       parser.recognize_candidate(reader, profile)
        => whichever reader the caller supplied. Cannot be determined at the call site.
```

**Consequences, stated conservatively:**
- `recognize_candidate` is only ever called with a bounded reader (paths B and C), so a parser implementing it against absolute offsets is reading window-relative bytes. Current implementations of `recognize_candidate` are shallow (Dahua checks `DHFS` at offset 0 and scans for DHAV, `dahua/src/parser.rs:258,261`), so the practical impact today is limited — a region starting mid-image will not have `DHFS` at its offset 0, which produces a *false negative*, not a false positive. That is the safer direction, but it is accidental, not designed.
- **This is a pre-existing defect. The specification does not cause it; the specification would fix it.**

### Would adopting spec requirements break the parsers?

| Change | Breaks parsers? | Why |
|---|---|---|
| Add `ReadResult`-style detailed read as a new defaulted method | **No** | Parsers keep calling `read_at`/`read_exact_at` unchanged. |
| Change `read_at`'s return type outright | **Yes — all 7** | Every call site needs updating. Avoidable via the two-stage approach in §8.1. |
| Add geometry to the reader | **No** | New methods; parsers ignore them until they opt in. |
| Add `read_sectors` | **No** | Nothing calls it today. |
| Add `Finding` to `StorageTopology` | **No parsers** | Breaks `detectors/tplink.rs:41` region selection only if the shape changes; adding a field does not. |
| Implement GPT / EBR | **No** | Purely more partitions discovered. `detectors/tplink.rs:41` gates on `== TopologyType::Mbr`, so GPT images would newly take a different branch — behaviour change, not a break. |
| Report all schemes instead of one | **Yes, 1 detector + 1 test** | `detectors/tplink.rs:41`, `tests/tests/tplink_sample_raw_test.rs:33`. |
| Typed address spaces on the `Parser` trait | **Yes — all 7** | This is the wide one. Every parser's read calls would need an address-space-tagged offset. |
| `RangeSet`, extents, retry | **No** | Additive; no parser touches them. |
| Enforce sector size instead of defaulting 512 | **Yes, 2 parsers** | `honeywell/src/parser.rs:41` and any profile relying on the `unwrap_or(512)` default would need an explicit profile value or a geometry-supplied one. |

## 8.4 Addressing compatibility

| Question | Answer | Evidence |
|---|---|---|
| Do parsers assume **absolute byte offsets**? | **Yes, universally.** Every parser read uses an image-absolute offset or a profile-supplied absolute offset. | `hikvision:45`, `uniview:45,78,84`, `dahua:111,149,258`, `honeywell:45`, `tplink:340` |
| Do parsers assume **sector-relative offsets**? | **No.** No parser converts sectors to bytes. Only `StorageTopologyProfiler` does (`topology.rs:91-93`). | — |
| Do parsers assume **partition-relative offsets**? | **No** — and this is the problem, because `recognize_candidate` always receives a partition-style window. | `levels.rs:225,258` |
| Do parsers assume **512-byte sectors**? | **Two do, via defaults.** `honeywell/src/parser.rs:41` — `profile.layout.get("sector_size").copied().unwrap_or(512)`. `StorageTopologyProfiler` — `sector_size_override.unwrap_or(512)` at `topology.rs:59`. Others use profile-supplied *byte* offsets, which are sector-size-independent. | `honeywell:41`, `topology:59` |
| Do parsers assume specific **stream behaviour**? | **No streams exist.** Positional reads only; no `Seek`/`Position` state to depend on. This removes an entire class of spec concerns (`DiskStream.Position` unvalidated, buffer-size mismatches). | `reader.rs:74` |
| Is the **address space part of the type**? | **No.** All offsets are bare `u64`; all ranges are bare `Region`. The spec's core requirement here is unmet. | `reader.rs:74`; `region.rs:14-20` |
| Is **absolute-offset provenance** recoverable from a window? | **Yes.** `BoundedReader::to_absolute_offset` (`bounded.rs:52-66`) and `start_offset()` (`bounded.rs:69-71`). | `bounded.rs:52-71` |

**Net:** addressing is *uniform* (always absolute bytes) and therefore *consistent* — the current project does not have the original's mixed-convention defect where one filesystem emitted absolute sectors and its siblings emitted relative ones. What it has is a weaker version: uniform absolute assumptions, and one call path that violates them.

## 8.5 Behavioural compatibility

What would change downstream if spec semantics were adopted:

| Semantic change | Downstream effect | Severity |
|---|---|---|
| **Short read reported as `Partial` instead of `Err(OutOfBounds)`** | `read_exact_at` currently errors and discards the prefix (`reader.rs:78-86`). Parsers written as `if let Ok(buf) = reader.read_exact_at(...)` (e.g. `dahua:111,149`) would now receive `Ok` with a partial buffer and **must** check the outcome, or they will parse zeros as data. **This is the one change that could make a currently-safe parser unsafe if done carelessly.** | **HIGH — must be handled deliberately** |
| **Truncation distinguished from out-of-range** | `RegionScanner` maps all `OutOfBounds` to `TerminationReason::Truncated` (`scanner.rs:172-176`). Splitting them changes `ScanReport.termination_reason` values, which `HashingService` turns into `Review` vs `Pass` (`hashing/src/lib.rs:82-104`). Some currently-`Review` hashes would become errors or vice versa. | MEDIUM |
| **Zero-filling made explicit** | New information only; nothing currently depends on zeros being unreported. | LOW |
| **Clamping reported** | `read_at` clamps at the tail (`raw.rs:138-140`). Reporting it adds information; callers already handle short counts (`scanner.rs:165-186`). | LOW |
| **Sector size enforced rather than defaulted** | `topology.rs:59` and `honeywell:41` would need real values. Images analysed with an assumed 512 would either need an operator-declared size or open in degraded mode. **Existing test expectations change**: `tests/tests/tplink_sample_raw_test.rs:33-37` assumes 512. | MEDIUM |
| **Partition clamping instead of silent dropping** | `topology.rs:96` currently drops out-of-range partitions. Clamping them in would make new regions appear in `StorageTopology.partitions`, which `detectors/tplink.rs:43-44` pushes as candidate regions — so detection input changes. | MEDIUM |
| **GPT implemented** | Images currently reported `UnpartitionedRaw` would become `Gpt`, changing `detectors/tplink.rs:41`'s branch and the candidate regions produced. | MEDIUM |
| **Retry added** | Read timing becomes non-deterministic in wall-clock terms; byte results stay deterministic. `HashRecord.duration_ms` varies — already excluded from determinism comparison (`determinism.rs:64-73`). | LOW |
| **`RangeSet` replacing `merge_regions`** | If built on half-open semantics, results are identical. If built on inclusive semantics without careful conversion, `CoverageEstimate` values shift by one byte per boundary. | LOW if half-open, **HIGH if inclusive** |

## 8.6 Breaking changes — complete list

Ordered by migration difficulty.

### BC-1 — `EvidenceReader::read_at` return type change
**WHAT BREAKS:** Both real implementors (`RawReader` at `raw.rs:107`, `BoundedReader` at `bounded.rs:73`), ~6 test mocks, and every call site in `detection`, all 7 parsers, `recovery`, `hashing`, `apps/api`, and the test suites.
**WHY:** It is the single method every consumer uses.
**DIFFICULTY: HIGH** as a direct change; **LOW–MEDIUM** if done as an additive defaulted method (`read_at_detailed`) with a staged migration. **Use the staged route.**

### BC-2 — Typed address spaces
**WHAT BREAKS:** Every offset parameter and every `Region` field across ~20 crates. Provenance, acquisition, recovery candidates, recordings, timeline events, scan reports, partition candidates.
**WHY:** `Region` and `u64` offsets are the platform's universal currency.
**DIFFICULTY: VERY HIGH.** This is the spec's "replace the fundamental addressing model" case.
**Cheaper alternative achieving most of the benefit:** introduce a newtype only where the ambiguity actually bites — a distinct reader type (or a marker on `BoundedReader`) so `Parser` methods can declare whether they accept a whole-image or a window reader. That addresses the one real defect without touching `Region`.

### BC-3 — Introducing an inclusive `ByteRange` alongside half-open `Region`
**WHAT BREAKS:** Nothing at compile time. That is the danger. Silent one-byte errors in reported ranges, plus incorrect adjacency/merge behaviour in any `RangeSet` built on the wrong model.
**WHY:** The two models differ by exactly one in every boundary computation, and the compiler cannot distinguish them.
**DIFFICULTY: MEDIUM to implement, VERY HIGH to make safe.**
**Recommendation: do not do this.** Build `RangeSet` on `Region`'s existing half-open semantics.

### BC-4 — `StorageTopology` reporting all schemes instead of one winner
**WHAT BREAKS:** `crates/detection/src/detectors/tplink.rs:41` (`topology.topology_type == TopologyType::Mbr`); `tests/tests/tplink_sample_raw_test.rs:33` (`assert_eq!(topology.topology_type, TopologyType::Mbr)`); `topology.rs`'s own tests at `:177,:161`.
**WHY:** `topology_type` is a single-valued public field.
**DIFFICULTY: MEDIUM.** Two production lines, three test assertions. Can be softened by keeping `topology_type` as the recommended scheme and adding a `schemes` list beside it.

### BC-5 — Enforcing sector-size provenance (removing silent 512)
**WHAT BREAKS:** `topology.rs:59`; `honeywell/src/parser.rs:41`; `tests/tests/phase2_detection.rs:226` (passes `Some(4096)` — fine); `tests/tests/tplink_sample_raw_test.rs` (relies on the 512 default).
**WHY:** Two code paths currently manufacture a sector size from nothing.
**DIFFICULTY: MEDIUM.** Small code change, but it forces a decision about what to do when no sector size is available for a plain `.raw` file — which is *the normal case* for this project. The spec's answer (degraded mode, refuse sector operations) would disable `StorageTopologyProfiler` for every raw image unless the operator declares a size. **This needs a product decision before it is implemented**; a reasonable middle path is `Assumed(512)` tagged and surfaced in every report rather than refused.

### BC-6 — `ForensicError` gaining variants
**WHAT BREAKS:** Any exhaustive `match`. Checked: `scanner.rs:172-177` matches one variant with a catch-all; `error.rs:172-201` enumerates variants in a test that asserts `errors.len() == 9` — **that assertion would need updating**.
**WHY:** Rust enums are closed.
**DIFFICULTY: LOW.** One test assertion plus any new handling.

### BC-7 — Adding `findings: Vec<Finding>` to `StorageTopology` / `PartitionCandidate`
**WHAT BREAKS:** Struct-literal construction at `topology.rs:67,112,122` and `:96-105`; `PartialEq` comparisons in tests.
**WHY:** Both structs have public fields and derive `PartialEq`.
**DIFFICULTY: LOW.** All construction sites are in one file.

### BC-8 — Short-read semantics change in `read_exact_at`
**WHAT BREAKS:** Behaviourally, not at compile time. Parsers using `if let Ok(buf) = reader.read_exact_at(...)` (`dahua:111,149`; `uniview:78,84,121,164`; `hikvision:45`) currently get `Err` on truncation and skip the branch. If a partial buffer became `Ok`, they would parse partially-zero data as real.
**WHY:** The guard is `Ok`/`Err`, not an outcome check.
**DIFFICULTY: MEDIUM, and dangerous if rushed.** **Recommendation: leave `read_exact_at` exactly as it is.** Its strict all-or-nothing contract is what keeps existing parsers safe. Add partial-read reporting on a *new* method instead.

### BC-9 — Retry changing wall-clock timing
**WHAT BREAKS:** Nothing forensic. `duration_ms` in `HashRecord` varies; already excluded from determinism comparison (`determinism.rs:64-73`).
**DIFFICULTY: LOW.**

### BC-10 — Replacing `merge_regions` with a `RangeSet`
**WHAT BREAKS:** Nothing, if `estimate_coverage`'s signature is preserved and half-open semantics are kept.
**DIFFICULTY: LOW.**

## 8.7 Compatibility conclusion

| Dimension | Verdict |
|---|---|
| API compatibility | **Partially compatible** — spec interfaces are .NET and unusable as-is; spec requirements map cleanly onto Rust traits, mostly additively |
| Type compatibility | **Partially compatible** — one genuine conflict (`ByteRange` vs `Region`), which should be resolved by rejecting the spec's inclusive model |
| Parser compatibility | **Compatible** for every additive change; **incompatible** for typed address spaces and for a direct `read_at` signature change |
| Addressing compatibility | **Compatible** — parsers uniformly assume absolute bytes, which the spec's model can express; one existing call path (bounded `recognize_candidate`) is already inconsistent and would be *fixed* by the spec's approach |
| Behavioural compatibility | **Compatible with care.** One high-severity item: do not loosen `read_exact_at`'s strictness. One product decision needed: what to do when no sector size is available for a raw image |
| Breaking changes | **10 identified.** 5 LOW, 4 MEDIUM, 1 VERY HIGH. The VERY HIGH one (typed address spaces) is avoidable via a narrower fix |

**Can the specification be introduced incrementally without breaking the existing DVR parsers? Yes** — provided every change is additive-first (new defaulted trait methods, new types beside old ones), `read_exact_at` keeps its strict contract, and `Region` stays half-open.

---

# 9. Forensic Safety Comparison

Only risks supported by actual code or actual spec text are listed. Where a risk is theoretical rather than reachable in the current codebase, that is stated.

## 9.1 Point-by-point

### Is evidence modified?

**CURRENT: No — enforced at four independent layers.**
1. `EvidenceReader` has no write method (`reader.rs:41-93`), and no way to add one without editing the trait.
2. `File::open` opens read-only (`raw.rs:50-52`).
3. `ReadOnlyMmap` maps `PROT_READ | MAP_PRIVATE` (`mmap.rs:66-69`).
4. `WriteGuard` denies any write path resolving inside the evidence directory and emits a `CustodyAction::WriteDenied` custody event (`write_guard.rs:47-104`).
Plus `inspect_source` refuses to analyse a `ReadWrite` source at all (`source_safety.rs:96-101`).

**SPEC: No** — FI-01 and FI-12, with two refinements the current project lacks: narrowest platform share mode, and a recording target that is a distinct type structurally incapable of pointing at evidence.

**ASSESSMENT: CURRENT BETTER.** Four layers plus a source-safety gate the spec does not require. The share-mode refinement is unreachable today because no Windows device path exists (`raw.rs:79` is `#[cfg(unix)]`). The recording-target refinement is moot because no recording capability exists.

### Are unreadable bytes distinguishable from actual zero bytes?

**CURRENT: No.** This is the one genuine forensic gap.
- `read_at` returns only a count (`reader.rs:74`). A sparse file hole, a genuinely-zero recorded region, and a region the OS returned short on all produce indistinguishable bytes plus a count.
- `raw.rs:126-144` has no sparse handling and no zero-fill tracking.
- `ScanReport.skipped_ranges` exists (`scanner.rs:58`) but is initialised empty at `scanner.rs:131` and **never pushed to** — a placeholder.
- The crate documentation at `lib.rs:23` claims "Sparse/unallocated regions are never reported as source truncation." That is true in the narrow sense that sparse holes produce no error, but it **overstates the implementation**: there is no mechanism that identifies a region as sparse at all.

**SPEC: Yes** — `ReadResult.ZeroFilledRanges` plus the `NotRecorded` outcome, with the invariant that `Complete` requires an empty zero-filled set. FI-04 calls this "the single most important forensic requirement in this document."

**ASSESSMENT: SPEC BETTER — decisively. This is the most significant forensic finding of this audit.**

**Why it matters concretely:** in a DVR case, a run of zeros inside a claimed recording can mean the camera recorded a black frame, the region was never written, or the drive could not read it. Those carry different evidentiary weight and the current API collapses them. **Mitigating fact:** the current code never *asserts* completeness it cannot back — `read_exact_at` errors rather than returning a partially-zeroed buffer, and `Acquisition` downgrades `Complete` to `Partial` whenever gap ranges are recorded (`acquisition.rs:110-127`). So the current behaviour is *silent about what it does not know*, not *actively misleading*. That is materially better than the original assembly the spec describes, which reported success while returning zero-filled holes.

### Are partial reads detectable?

**CURRENT: Partially.**
- `read_at` returns the actual count, so a caller *can* detect a short read — and callers do: `scanner.rs:165-186` checks `bytes_read == 0` → `Truncated`, and advances by the actual count; `recovery/src/levels.rs:50-52` truncates its buffer to the count returned.
- `read_exact_at` converts a short read into `Err` (`reader.rs:78-86`), which is safe but discards the valid prefix.
- Recovery detects and *reports* its own window truncation: `truncated_view` becomes `ValidationStateKind::Review` with the reason "window truncated to scan cap, bytes beyond the cap were not examined" (`levels.rs:169-183`).
- `HashingService` downgrades to `Review` when the scan did not complete (`hashing/src/lib.rs:82-104`).
- **But:** `read_exact_at` labels a short read as `OutOfBounds`, and `RegionScanner` maps any `OutOfBounds` to `TerminationReason::Truncated` (`scanner.rs:172-176`), so a caller-side bounds bug is reported as evidence truncation.

**SPEC: Yes, fully** — `Outcome::Partial` with exact `BytesRead`, the valid prefix preserved, and the remainder zeroed and enumerated.

**ASSESSMENT: SPEC BETTER**, but the gap is narrower than it first appears. Every place that *matters* today (scanner, recovery, hashing) already detects and propagates truncation into a `Review` validation state. What is missing is precision (which bytes) and correct attribution (truncation vs caller error).

### Are source offsets preserved?

**CURRENT: Yes, with one type-level weakness.**
- `SourceRegion { evidence_id, region, description }` and `Provenance.source_regions: Vec<SourceRegion>` record exactly which evidence bytes produced each artifact (`provenance.rs:22-48,72-100`).
- `Provenance` additionally carries producing component + version, profile version + hash, parser version, recovery level, output hash, and an ordered `transformation_history` (`provenance.rs:72-100`).
- `RecoveryCandidate.source_offsets: Vec<Region>` (`levels.rs:200`) and `TimelineEvent.source_offsets` preserve byte ranges.
- `BoundedReader::to_absolute_offset` maps a window offset back to absolute (`bounded.rs:52-66`).
- **Weakness:** nothing in the type system prevents a window-relative offset being stored in a `SourceRegion` as though it were absolute. In `recovery/src/levels.rs:195-199` the `SourceRegion` is built from `region.clone()` — the absolute search region, which is correct — but that correctness is by discipline, not by type.

**SPEC: Yes**, plus typed addresses making the weakness impossible.

**ASSESSMENT: ROUGHLY EQUIVALENT in practice; SPEC BETTER in enforcement.** The current provenance model is genuinely rich — richer than anything the spec specifies, since the spec's FI-06 asks only that addresses be typed and traceable, whereas this project also records profile hashes and transformation history.

### Are bounds enforced?

**CURRENT: Yes, consistently.**
- `read_at` rejects `offset >= len` (`raw.rs:114-121`) and clamps the length (`raw.rs:138-140`).
- `BoundedReader` validates its window at construction against the parent length (`bounded.rs:29-45`) and rejects local offsets past the window end (`bounded.rs:78-85`).
- `validate_region_bounds` is the shared check (`checked.rs:64-89`), used by `RegionScanner::new` (`scanner.rs:104`), `ReadOnlyMmap::map_region` (`mmap.rs:36`) and `read_region` (`reader.rs:90`).
- Negative offsets are unrepresentable (`u64`).
- Zero-length regions handled explicitly and tested at the boundary (`checked.rs:47-60,190-205`).

**SPEC: Yes**, with the same requirements, written largely to correct the original's seven divergent bounds behaviours.

**ASSESSMENT: CURRENT BETTER.** Uniform across every implementation, `u64` eliminating a whole error class, and bounds validated before allocation in the paths that allocate.

### Is arithmetic overflow prevented?

**CURRENT: Yes, comprehensively.** `checked_add`, `checked_mul`, `checked_sub`, `checked_sector_offset`, `checked_end_offset` all return `Result` (`checked.rs:14-41`). `Region::new` rejects overflow (`region.rs:23-31`). `BoundedReader` uses `checked_add` for window arithmetic (`bounded.rs:33-35,58-60,87-89`). Tested across `{0, 1, u64::MAX/2, u64::MAX-1, u64::MAX}` asserting no panic (`checked.rs:228-250`).
**One minor hole:** `Region` has public fields, and `gaps.rs:157,166,175` constructs `Region { offset, length }` as struct literals, bypassing `Region::new`'s overflow check. Inputs there are already-validated regions, so it is not currently reachable — but it is a pattern that would not survive hostile input.

**SPEC: Yes** — FI-05. Written because the original built with overflow checking *disabled*.

**ASSESSMENT: CURRENT BETTER.** The spec's requirement is met and exceeded; the only residual item is a lint-level concern about struct-literal construction.

### Are read failures explicit?

**CURRENT: Yes, as typed values.** `ForensicError` with 9 variants; `OutOfBounds` carries `{context, offset, length, source_len}` (`error.rs:28-35`); `Cancelled` carries `bytes_processed` (`error.rs:57-62`); `Io` wraps `std::io::Error` preserving `raw_os_error()`. No panics on evidence-derived values; `#![forbid(unsafe_code)]` in forensic-core.
**Gaps:** short-read and out-of-range share one variant; no retryable/non-retryable distinction; the OS error code is preserved but not surfaced as a reportable field.

**SPEC: Yes**, with 8 categories and attempt history. Written because the original returned a bare `bool` covering four distinct conditions and logged-then-discarded the Win32 error.

**ASSESSMENT: ROUGHLY EQUIVALENT.** The current model already does the thing that matters — failures are structured values carrying the failing range, not opaque messages.

### Is behaviour deterministic?

**CURRENT: Yes.**
- No keep-alive, no background timers, no random reads — nothing in `crates/evidence-reader` issues a read the caller did not request.
- Hash proven independent of window size (`hashing/src/lib.rs:203-225`).
- `DeterminismKey` models the full input set: evidence hash, profile version + hash, config version + hash, recovery config, all component versions; environment metadata (timestamps, DB IDs, temp paths, durations) explicitly excluded (`determinism.rs:23-74`).
- Deterministic fixture generation (`tests/src/fixtures.rs`, `DeterministicRng`).
**Limitation:** there is no *test* asserting that a full analysis issued exactly the reads it requested. The spec's recording-fake-gateway (§16.5 item 3) would provide that.

**SPEC: Yes** — FI-02 and FI-09, written to correct three reproducibility hazards in the original (random keep-alive reads, a licence gate, and a per-read decoder stream loaded by filename).

**ASSESSMENT: CURRENT BETTER.** None of the original's hazards exist, and `DeterminismKey` is a concrete artifact the spec only gestures at.

### Are resources disposed safely?

**CURRENT: Yes, structurally.** Rust RAII: `File` closes when `RawReader` drops; `ReadOnlyMmap::drop` calls `munmap` (`mmap.rs:120-127`); `BoundedReader` borrows rather than owns (`&'a dyn EvidenceReader`), so double-free and premature-close are impossible. No finalisers, no ownership flags, no aggregated-disposal-failure handling needed.

**SPEC: Requires** deterministic disposal, explicit ownership flags on every wrapper, aggregated disposal failures, and a test asserting zero open handles after teardown — all because the original never disposed its device handle, never disposed its E01 virtual disk or DI container, and swallowed disposal failures (FI-13, spec §2.18).

**ASSESSMENT: CURRENT BETTER.** The entire failure class is eliminated by the language. **No work required.**

### Can a parser accidentally read outside its assigned partition/range?

**CURRENT: Mixed — and this is the second real gap.**
- When given a `BoundedReader`: **no.** The window is validated at construction, local offsets past the end are rejected (`bounded.rs:78-85`), reads are clamped to the window, and `inner` is private with no accessor (`bounded.rs:13-17`) so the parent device is unreachable. This is stronger than the original's `Volume.TryRead`, which the spec notes had **no upper bound at all**.
- When given the whole-image reader (`parsing/src/orchestrator.rs:67-84`): **there is no partition assignment to violate** — the parser is deliberately given the whole image.
- **The actual risk:** nothing distinguishes the two. `recognize_candidate` is always called with a window (`levels.rs:225,258`; `validation.rs:51`) while parsers read absolute offsets (`uniview:78,84` read fixed 512 and 1024). A parser cannot tell which it has.
- **Practical severity today: LOW.** Because a window's offset 0 is mid-image, absolute-offset reads inside a window fail to match their magic and produce *false negatives* (a candidate is skipped), not false positives (wrong bytes attributed to a recording). The safe direction — but by accident.
- Nothing currently connects `PartitionCandidate` (`topology.rs:29-42`) to a `BoundedReader`, so partition-scoped parsing is not actually exercised.

**SPEC: No** — typed address spaces plus `IPartition.OpenReader()` make it a compile error.

**ASSESSMENT: ROUGHLY EQUIVALENT on the mechanism; SPEC BETTER on enforcement.**

### Additional: is an incomplete result ever presented as complete?

**CURRENT: Mostly no, enforced in three places:**
- `Acquisition::with_bad_sectors` / `with_unresolved` force `Complete` → `Partial` when gap ranges exist (`acquisition.rs:110-127`), and `AcquisitionStatus::default()` is `Unknown`, never `Complete` (`acquisition.rs:36-41`).
- `HashingService` returns `Review` when the scan did not complete (`hashing/src/lib.rs:82-104`).
- Recovery marks a truncated window `Review` with an explicit reason (`levels.rs:169-183`).
- `analyze_gaps` reports `Unknown` rather than "no gaps" when a dimension could not be measured (`gaps.rs:14-16` doc, `:293-333`).
**The gap:** nothing cross-checks a `Recording`'s `source_offsets` against `Acquisition.bad_sector_ranges`. The spec (§9.9) calls this "the forensically critical one." Both data sets exist; the intersection is never computed because there is no set algebra to compute it with.

**SPEC: No**, and it requires the cross-check explicitly.

**ASSESSMENT: CURRENT BETTER at acquisition level; SPEC BETTER at recording level.**

## 9.2 Forensic safety scorecard

| Forensic property | Current | Spec | Assessment |
|---|---|---|---|
| Evidence never modified | 4 enforcement layers + source-safety gate | 2 requirements | **CURRENT BETTER** |
| Unreadable vs real zeros distinguishable | **No mechanism** | `ZeroFilledRanges` + `NotRecorded` | **SPEC BETTER (decisive)** |
| Partial reads detectable | Count returned; truncation → `Review`; prefix discarded by `read_exact_at`; misattributed as `OutOfBounds` | Exact `BytesRead` + preserved prefix + enumerated fill | SPEC BETTER |
| Source offsets preserved | Rich provenance incl. profile hash + transformation history; untyped addresses | Typed addresses | ROUGHLY EQUIVALENT / SPEC BETTER on enforcement |
| Bounds enforced | Uniform, `u64`, shared validator, pre-allocation | Uniform | **CURRENT BETTER** |
| Overflow prevented | All ops checked; extremes tested | Required | **CURRENT BETTER** |
| Read failures explicit | Typed, range-carrying | 8 categories + attempts | ROUGHLY EQUIVALENT |
| Deterministic | No unrequested reads; `DeterminismKey` | Required; no key type specified | **CURRENT BETTER** |
| Resources disposed | RAII, structurally safe | Extensive discipline required | **CURRENT BETTER** |
| Cannot escape assigned range | `BoundedReader` bounds + hidden parent; address space untyped | Typed + bounded | ROUGHLY EQUIVALENT / SPEC BETTER on enforcement |
| Incomplete never shown complete | Enforced at acquisition, hash, recovery | Enforced incl. recording × unreadable | CURRENT BETTER (acquisition) / SPEC BETTER (recording) |

**Net forensic assessment:** the current implementation is **safer than the spec's baseline in six of eleven properties** and weaker in three, of which one — the zero-fill distinction — is materially important. Crucially, the current implementation's weaknesses are **omissions** (it cannot record what it knows) rather than **misrepresentations** (it does not claim what it does not know). The original assembly the spec describes had the opposite profile: it actively reported success while returning fabricated zeros. Adopting the spec's `ReadResult` closes the one gap that could lead to a wrong forensic conclusion.

---

# 10. What We Should Keep

Components that work and should remain, with the reason each is worth protecting.

## 10.1 Keep unchanged — do not touch

| Component | Location | Why keep |
|---|---|---|
| **`forensic_core::checked` — all of it** | `crates/forensic-core/src/checked.rs` | Fully satisfies spec FI-03 and FI-05. Integer-only, overflow-checked, correct for non-power-of-two sector sizes, tested against `u64` extremes. The spec spends Phase 8.5 cataloguing nine partial mitigations in the original; this needs none of them. |
| **`Region` with half-open semantics** | `crates/forensic-core/src/region.rs` | Load-bearing across ~20 crates. Half-open with explicit length is less error-prone than the spec's inclusive model, and the spec itself marks the inclusivity as `[INFERRED]`, not confirmed. **Replacing or duplicating this is the single riskiest available change.** |
| **RAII resource management** | throughout | Eliminates the entire failure class behind spec FI-13 and §2.18. Rust ownership makes `leaveOpen` flags and disposal-failure aggregation unnecessary. |
| **`u64` offsets** | throughout | Makes negative-offset bugs unrepresentable rather than merely checked. |
| **`WriteGuard` + custody events** | `crates/forensic-core/src/write_guard.rs` | Defence in depth beyond what the spec requires, with an audit trail. |
| **`inspect_source` / `SafetyDecision`** | `crates/evidence-reader/src/source_safety.rs` | The spec has no equivalent. The `Unknown`-is-never-`ReadOnly` rule (`:103-109`) is exactly right and should never be softened. |
| **No keep-alive / no background reads** | (absence) | Satisfies FI-02 by construction. **Do not add the original's random probe** — the spec explicitly condemns it as forensically noisy. |
| **No licence gate, no obfuscation** | (absence) | Spec says never reproduce. Agreed. |
| **`#![forbid(unsafe_code)]` in forensic-core** | `crates/forensic-core/src/lib.rs:16` | Keep. The `unsafe` needed for mmap is correctly confined to `evidence-reader`, which documents why it cannot forbid it (`lib.rs:25-26`). |

## 10.2 Keep and build on

| Component | Location | Why keep |
|---|---|---|
| **`EvidenceReader` byte-first primitive** | `crates/evidence-reader/src/reader.rs:41-93` | Matches spec Phase 2.8's `[DESIGN]` conclusion exactly. Thin enough to extend via defaulted methods without breaking implementors — the key enabler for incremental adoption. |
| **Trait has no write method** | `reader.rs:41-93` | The primary read-only guarantee. Preserve through every change. |
| **`read_exact_at`'s strict all-or-nothing contract** | `reader.rs:78-86` | **Explicitly keep as-is.** Its strictness is what keeps existing parsers safe (§8.6 BC-8). Add partial-read reporting on a *new* method; do not loosen this one. |
| **`BoundedReader`** | `crates/evidence-reader/src/bounded.rs` | Satisfies the spec's two hard partition-reader invariants: bounds-enforced reads and no parent access. `to_absolute_offset` preserves provenance. Needs wiring to partitions, not replacing. |
| **`RegionScanner` + `ScanReport` + `TerminationReason`** | `crates/evidence-reader/src/scanner.rs` | Bounded memory with honest accounting and a typed stop reason. Cancellation support exceeds the spec. `skipped_ranges` is the natural home for the spec's sparse/skipped reporting. |
| **`ReaderConfig` (read window as data, not a constant)** | `crates/evidence-reader/src/config.rs` + `config/reader.toml` + `docs/decisions/OPEN-2` | Arguably better than the spec's "documented constant": range-validated, operator-tunable, with a written decision record. |
| **`Acquisition` gap→`Partial` enforcement** | `crates/forensic-core/src/acquisition.rs:110-127` | Already implements the spec's core "never present incomplete as complete" principle at acquisition level, at the type level. Extend the same pattern to recordings. |
| **`Provenance` / `SourceRegion`** | `crates/forensic-core/src/provenance.rs` | Richer than the spec requires — profile version + hash, parser version, recovery level, ordered transformation history. Satisfies most of FI-06. |
| **`DeterminismKey`** | `crates/forensic-core/src/determinism.rs:23-74` | A concrete artifact the spec only gestures at. |
| **`HashingService` (full SHA-256, window-independent)** | `crates/hashing/src/lib.rs` | Satisfies FI-11's "integrity" half. **Do not add the spec's sampled MD5 fingerprint** unless large-device re-identification becomes a real need — and if added, label it non-integrity. |
| **`ValidationState` / `ParserRun`** | `crates/forensic-core/src/validation.rs`, `parser_run.rs` | Already proves the "structured outcome, not a log line" pattern works. The template for the `Finding` model the partition layer needs. |
| **Unconditional whole-device fallback** | `crates/detection/src/topology.rs:64-72,121-127` | A genuine current-better. Spec Phase 7.8 item 5 calls the original's discard-if-unrecognised behaviour "exactly backwards" for DVR evidence. Already correct here. |
| **MBR primary parsing** | `crates/detection/src/topology.rs:74-107` | Offsets and signature test verified against spec §2.11 and §13.1. Correct. Extend, do not rewrite. |
| **E01 gate + OPEN-1 decision record** | `raw.rs:38-47`; `docs/decisions/OPEN-1-ewf-e01-dependency.md` | **Exceeds the spec's discipline.** Candidate selected and license-verified, six-item verification gate written, hand-rolled EWF parser explicitly prohibited, and a standing rule that E01 must not be claimed anywhere until the gate passes. Keep all of it. |
| **OEM facts as versioned profile data, never Rust constants** | `Cargo.toml` comments; `crates/forensic-core/src/lib.rs:25-27`; `crates/forensic-core/src/profile.rs`; `profiles/` | **The spec never asks for this, and it is more valuable for a multi-vendor DVR tool than anything in spec Phase 13.** Parsers read magics from `profile.signatures` and offsets from `profile.layout`. Protect it through any migration. |
| **Requirement traceability in doc comments** | throughout | Every module cites the requirements it implements. Makes audits like this one possible. |
| **Deterministic fixture generator + validation corpus** | `tests/src/fixtures.rs`; `validation_corpus/` | Working test infrastructure the spec assumes must be built from scratch. `FixtureShape::{Normal, Sparse, Truncated, Fragmented, WrongOffset, Partial}` already covers several spec-required adversarial shapes. |
| **Dependency direction: evidence layer knows nothing about partitions** | `crates/detection/src/topology.rs:13` imports `evidence_reader`, never the reverse | Already avoids the one structural mistake the spec singles out (§2.1 circular layering). |
| **Cancellation + progress** | `crates/evidence-reader/src/progress.rs` | No spec equivalent. Necessary for long carving passes. |
| **Recovery's honest truncation reporting** | `crates/recovery/src/levels.rs:169-183` | Marks a capped window `Review` with the reason "bytes beyond the cap were not examined" rather than claiming completeness. Exactly the right instinct; the pattern to generalise. |

---

# 11. What We Should Add

Missing specification components, in recommended order. Each entry states the spec source, why it matters *for this project specifically*, and the migration difficulty (see §12 for the full difficulty table).

## 11.1 A read-outcome type (spec L1 `ReadResult`) — **highest priority**

**Spec source:** §13.1, FI-04, Phase 10.1.

**What is missing:** `read_at` returns `Result<usize, ForensicError>`. There is no way to say "these bytes are real, those were zeros I substituted."

**Why it matters here:** it is the only gap in the current implementation that can lead to a *wrong forensic conclusion* rather than merely a missing capability. A sparse hole, a genuinely-blank recorded region, and an unreadable sector are currently indistinguishable.

**Recommended Rust shape** (adapted, not copied — the spec's `Failed` variant is a C# idiom for a language without `Result`):

- A new **defaulted** trait method, e.g. `read_at_reported(&self, offset, buf) -> Result<ReadOutcome, ForensicError>`, whose default implementation wraps the existing `read_at` and reports `Complete` or `Partial` based on the count.
- `ReadOutcome { kind: Complete | Partial | NotRecorded, bytes_read: usize, zero_filled: Vec<Region>, clamped: bool }`.
- Errors stay in `Err(ForensicError)` — do not fold failure into the outcome enum.

**Critical constraint:** leave `read_exact_at` exactly as it is. Its strict all-or-nothing contract is what keeps the seven existing parsers safe (§8.6 BC-8).

**Difficulty: LOW** as an additive defaulted method. **HIGH** if `read_at` itself is changed.

## 11.2 An evidence-geometry model (spec L0 `EvidenceGeometry`) — **high priority**

**Spec source:** §13.4, Phase 4, FI-07.

**What is missing:** no sector size, sector count, or tail-byte concept. Two silent `512` defaults (`topology.rs:59`, `honeywell/src/parser.rs:41`).

**Why it matters here:** `StorageTopologyProfiler` converts LBAs to byte offsets using an assumed sector size. On a 4Kn image every partition offset would be wrong by a factor of eight, the MBR would still parse, and nothing would visibly fail. Also, a forensic report should be able to state where the sector size came from.

**What to add:**
- `bytes_per_sector` + `SectorSizeProvenance { OperatorDeclared, Measured, DecodedFromContainer, InferredFromExternalLog, Assumed }`.
- `total_bytes` (already measured — `RawReader.len` from `metadata.len()`) with its own provenance.
- Derived `sector_count` and explicit `tail_bytes = total_bytes % bytes_per_sector`.
- `conflicting_claims` retained.
- Adopt the spec's **corrected** precedence: `OperatorDeclared > Measured > DecodedFromContainer > InferredFromExternalLog > Assumed`.

**Product decision required before implementing:** the spec's degraded mode would refuse sector operations when no sector size is available — which is *every plain `.raw` file*, the normal case here. Recommended middle path: keep operating with `Assumed(512)` but surface that tag in every report and in `StorageTopology`. Do not silently assume.

**Difficulty: MEDIUM.** New type is additive; wiring it into `StorageTopologyProfiler::profile` changes 4 call sites and some test expectations.

## 11.3 A `Finding` model for geometry and partitions — **high priority, low cost**

**Spec source:** §13.5, §13.6, FI-10, Phase 7.8 items 3 and 7.

**What is missing:** no findings type anywhere. Specifically:
- Out-of-range partitions are **silently dropped** at `topology.rs:96` — the declared start/length vanish with no trace.
- No overlap detection, despite `Region::overlaps` existing and being unused here.
- Zero-length and zero-type entries skipped (`topology.rs:82-89`) with no record.
- Dahua clamps a declared payload length to the image (`dahua/src/parser.rs:193-196`) with no finding.

**Why it matters here:** a partition table declaring a partition past the end of the image, or two overlapping entries, is exactly what a DVR forensic report should mention. It is currently discarded.

**What to add:** a `Finding { severity, code, message, region: Option<Region>, declared: Option<Region> }` plus `findings: Vec<Finding>` on `StorageTopology` and `PartitionCandidate`. Preserve pre-clamp declared values. `ValidationState` (`crates/forensic-core/src/validation.rs`) is the proven template.

**Difficulty: LOW.** All three `StorageTopology` construction sites are inside `topology.rs`.

## 11.4 Reusable range-set algebra (spec L5 `RangeSet`) — **high priority**

**Spec source:** §13.7, Phase 9.

**What is missing:** `merge_regions` + `estimate_coverage` (`gaps.rs:137-196`) compute union and complement once, inline, for one purpose. No `Subtract`, no set-level `Intersect`, no reusable `Complement`.

**Why it matters here:** the spec's forensically critical operation — intersect a recording's claimed byte ranges with unreadable ranges to prove the recording has holes — is currently unwritable. The data already exists: `Acquisition.bad_sector_ranges` and `unresolved_ranges` (`acquisition.rs:71-75`), `Recording.source_offsets`, `Region::overlaps`. Only the algebra is missing.

**What to add:** an immutable `RangeSet` over **`Region`'s existing half-open semantics** (do **not** import the spec's inclusive `ByteRange` — see §8.2/BC-3), with `add`, `subtract`, `union`, `intersect`, `complement_within`, `contains`, `covers`, `total_length`, `count`, `min`, `max`, ordered iteration. Maintain the canonical invariant (sorted, non-overlapping, non-adjacent) with one merge predicate. Reimplement `estimate_coverage` on top without changing its signature.

**Difficulty: LOW.** Zero dependencies, purely additive, and the spec supplies full pseudocode for every operation including all six subtraction shapes.

## 11.5 Recording-level completeness cross-check — **high priority, low cost**

**Spec source:** Phase 9.9, FI-04, Phase 14.2.

**What is missing:** `Acquisition` enforces gap→`Partial` at acquisition level (`acquisition.rs:110-127`), but nothing checks whether a `Recording`'s byte ranges intersect known bad-sector or unresolved ranges.

**Why it matters here:** the spec states it plainly — a recording whose bytes intersect an unreadable region must never be exported as complete. `Recording` already has an `IntegrityFlag` (`crates/forensic-core/src/recording.rs`), so the destination for the result exists.

**Difficulty: LOW**, once §11.4 exists.

## 11.6 Complete the partition layer: GPT, EBR, clamping, all-schemes — **medium priority**

**Spec source:** §2.11, §2.12, §13.5, Phase 7.

**What is missing:**
- **GPT entirely.** `TopologyType::Gpt` is declared at `topology.rs:23` and produced by **no code path**. This is the most misleading construct in the codebase — a court-facing enum implying a capability that does not exist.
- **Extended/EBR chains.** `for i in 0..4` (`topology.rs:79`) reads primaries only.
- **Clamping instead of silent dropping** (`topology.rs:96`).
- **Overlap detection.**
- **All schemes reported** rather than one winner.

**Why it matters here:** DVR evidence with logical partitions or GPT layouts is currently mis-profiled as `UnpartitionedRaw`. Since `detectors/tplink.rs:41` gates on `topology_type == TopologyType::Mbr`, such images take the wrong branch.

**If GPT is implemented, follow the spec fully** — header size validation, both CRC32s, backup header fallback, real entry count from the header, type and unique GUIDs, UTF-16 name, no 12-entry cap. The spec's §2.12 is explicit that the original was "provably lossy" here, and the extra correctness costs little once the header is being parsed at all. **Note spec H-5:** the original's field-at-+40 semantics and 12-entry cap are `[UNKNOWN]`, so implementing the real format will produce results that differ from the original on some disks — that divergence is correct and should be documented.

**Immediate minimum:** either implement GPT or mark `TopologyType::Gpt` as reserved in a doc comment. Shipping an unimplemented variant in a forensic type is worse than not having it.

**Difficulty: MEDIUM** for GPT + EBR + findings + clamping. **MEDIUM** for all-schemes (breaks `detectors/tplink.rs:41` and one test).

## 11.7 Wire `BoundedReader` to partitions — **medium priority, low cost**

**Spec source:** §13.6 (`IPartition.OpenReader()`).

**What is missing:** `BoundedReader` exists and satisfies the spec's invariants, but **nothing constructs one from a `PartitionCandidate`**. Partition-scoped parsing is therefore not exercised — parsers always get the whole image (`parsing/src/orchestrator.rs:67-84`) or a recovery search window (`levels.rs:222,257`).

**Difficulty: LOW.** A method producing a `BoundedReader` from a `PartitionCandidate.region`.

## 11.8 Address-space distinction for the `Parser` contract — **medium priority**

**Spec source:** §8.7, FI-08, Phase 7.2.

**What is missing:** nothing distinguishes a whole-image reader from a window reader. `recognize_candidate` always receives a `BoundedReader` (`levels.rs:225,258`; `validation.rs:51`) while parsers read absolute offsets (`uniview/src/parser.rs:78,84` read fixed 512 and 1024).

**Why it matters here:** this is a **live pre-existing defect**, independent of the spec. Practical severity today is low — the mismatch yields false negatives, not wrong attributions — but it is safe by accident, not by design.

**Recommendation: adopt the narrow fix, not the spec's full typed-address-space model.** Introducing typed addresses across `Region` and every `u64` offset is VERY HIGH effort (§8.6 BC-2). Instead distinguish at the *reader* level: a marker or distinct type so a `Parser` method signature can declare whether it accepts image-absolute or window-relative addressing. That fixes the actual defect at a fraction of the cost.

**Difficulty: MEDIUM** for the narrow fix; **VERY HIGH** for the spec's full model.

## 11.9 Windows physical-disk path + platform gateway — **medium priority (product-dependent)**

**Spec source:** §13.8 (`IPlatformBlockDeviceGateway`), §2.2, Phase 5.

**What is missing:** `RawReader::open_device` is `#[cfg(unix)]` (`raw.rs:79`); `ReadOnlyMmap` returns `UnsupportedFormat` on non-Unix (`mmap.rs:82-89`). The declared host is Windows, so `SourceKind::PhysicalDisk` is unreachable there.

**Why it matters here:** either physical-disk acquisition works on the target platform or the platform's capability matrix should say it does not. Currently the enum variant exists and cannot be constructed.

**What the spec gets right:** one narrow gateway (enumerate, open, query logical sector size, query physical sector size, query byte length, read at, close) with every member carrying the raw platform error code. That isolates `#[cfg]` to one module and — importantly — makes a **recording fake gateway** possible, which is what makes determinism and "no unrequested reads" testable (§11.11).

**Also adopt from the spec:** narrowest share mode with the granted mode recorded (FI-01); do **not** adopt the original's read+write sharing.

**Difficulty: MEDIUM–HIGH**, mostly platform work.

## 11.10 Extent map / content addressing (spec L4) — **medium priority**

**Spec source:** §12 L4, §13, Phase 14.

**What is missing:** no `Extent`, no `ExtentMap`, no extent stream. Recovery reads a single contiguous window capped at 8 MiB (`levels.rs:35,42-54`).

**Why it matters here:** DVR recordings are routinely fragmented. A fragmented recording cannot currently be read or exported as one stream. This is a functional limitation, not just architectural.

**What to add:** `Extent { source: Region, logical_offset: u64, kind: Data | Sparse | Uninitialised | Unreadable }`, a validated ordered `ExtentMap`, and a reader over it. Per the spec: sparse and uninitialised regions **explicitly zero-filled and reported**; unreadable regions make the containing read `Partial`.

**Depends on:** §11.1 (needs a way to report zero-filled ranges).

**Difficulty: MEDIUM.** Purely additive — nothing exists to conflict with.

## 11.11 Recording fake gateway + byte-exactness harness — **medium priority**

**Spec source:** §16.5 items 3 and 4, FI-02.

**What is missing:** six mock readers exist (`bounded.rs:110-138`, `scanner.rs:216-243`, `topology.rs:135-152`, `hashing/src/lib.rs:152-176`, `recovery/tests/*`, `tests/tests/tplink_synthetic_dry_run.rs:30-95`) but none **records every call** or can **inject failures by offset or attempt number**. There is therefore no test proving an analysis issues exactly the reads it requested.

**Why it matters here:** determinism is currently a property of the code's structure (no timers, no random reads), not a tested assertion. A recording gateway converts it into a test. It is also the only practical way to test retry and partial-read paths without real failing hardware.

**Difficulty: LOW.** Test-only code; the trait is already trivially mockable.

## 11.12 Retry policy — **lower priority (sequenced after §11.9)**

**Spec source:** §13.1 `IRetryPolicy`, Phase 10.3.

**What is missing:** no retry logic anywhere.

**Why lower priority:** retrying a `read()` on a local file almost never helps. Retrying a failing SATA/USB drive frequently does — but physical-disk support does not work on the target platform yet. Retry before a device path exists is code with no live use case.

**What to adopt:** bounded iterative retry (not recursive), explicit backoff, per-attempt telemetry in the read outcome, `should_retry(category)` distinguishing transient I/O from argument errors, and **policy as configuration, not a call parameter** — the current trait's clean signature already avoids the original's public `retryAttemptNumber`, and that should be preserved.

**Difficulty: MEDIUM.** Requires the retryable/non-retryable error distinction first.

## 11.13 Segmented raw image support — **lower priority (demand-driven)**

**Spec source:** §2.4, §6.2.

**What is missing:** no segment discovery, no segment-set type, no cross-segment read.

**Adopt the spec's corrections, not the original's behaviour:** validate **every** segment's length at open time (the original assumed all middles matched the first and never checked), integer-only segment selection (the original used floating point), **always check what each read returned** (the original ignored it — the spec calls this "correctness-critical"), and **do not** impose the original's 512-multiple rejection rule, which is unrelated to real geometry.

Also needed: a structured locator, since a segment set has no single path (`source_path` is currently documented display-only, `reader.rs:57`).

**Difficulty: MEDIUM.** Additive new source type.

## 11.14 Sparse record-on-read capture — **lower priority (operationally valuable)**

**Spec source:** §2.6.1, §6.4, Phase 17 Phase 3b.

**What is missing:** no capture container, no read-through recording decorator.

**Why it is worth considering:** read a failing DVR drive once, record exactly what was read, then replay the entire analysis offline byte-identically. Genuinely useful for the target domain.

**Key spec correction to honour:** unrecorded blocks must be reported as **`NotRecorded`**, not returned as silent zeros. Depends on §11.1.

**Format decision required:** the spec documents the original's container completely (64-byte header, 16-byte map records, block-indexed payload) and notes it lacks per-block integrity hashes and an explicit recorded-range index. Reading that format is low-risk and useful for existing captures; writing a new versioned format with those two additions is the better choice for new work.

**Difficulty: MEDIUM–HIGH.**

## 11.15 E01 / EWF — **blocked, correctly**

**Spec source:** §2.5, §6.3, Phase 5, spec H-1.

**Status:** deliberately gated. `RawReader::open` rejects `.E01` (`raw.rs:38-47`); `docs/decisions/OPEN-1-ewf-e01-dependency.md` records candidate `ewf` 0.4.10 (Apache-2.0), a license verification, a six-item verification gate, and an explicit prohibition on hand-rolling a parser.

**The spec agrees and cannot help:** spec H-1 states the reverse engineering produced **zero** E01 format knowledge and that Phase 5 "cannot start from `DATAIO_REVERSE_ENGINEERING_RAW.md`."

**Recommendation: no change.** Keep the gate. The existing decision record is more rigorous than the spec's guidance. **Do not** let this block anything else — the spec places it last for exactly this reason.

## 11.16 Things the spec proposes that this project should NOT add

| Spec item | Why not |
|---|---|
| Sampled MD5 evidence fingerprint | Only add if fast re-identification of very large devices becomes a real need, and then label it non-integrity. Adding it now creates a hash that could be mistaken for integrity — the exact confusion FI-11 warns about. The project's full-SHA-256-only position is currently safer. |
| Random keep-alive probe | The spec itself condemns it (FI-02). If bridged-drive dropouts appear, use a fixed-location, separately-logged probe. |
| Inclusive `ByteRange` alongside `Region` | §8.2/BC-3: silent one-byte errors that type-check. Build `RangeSet` on `Region`. |
| Full typed-address-space model across all offsets | §8.6 BC-2: VERY HIGH cost. The narrow reader-level fix (§11.8) addresses the actual defect. |
| `IDisposable`-style ownership flags on wrappers | Rust borrowing already expresses this. |
| Legacy `SdrImage` | The spec says do not implement. |
| LVM2 | Spec defers it; geometry arithmetic is `[UNKNOWN]`. DVR evidence is overwhelmingly MBR/GPT/unpartitioned. |
| Licence gate, obfuscation runtime | Spec says never reproduce. |
| Generic filesystem parsers (exFAT/ext/FAT32/JFS/XFS) | Spec scopes them out of the DataIO foundation. Add only when a real case requires one. |
| Spec's `Failed` variant folded into the outcome enum | A C# idiom for a language without `Result`. Keep errors in `Err`. |
| Loosening `read_exact_at` | §8.6 BC-8: its strictness is a safety feature for existing parsers. |

---

# 12. What We Should Change

Existing components needing modification, with the specific change and its risk.

| # | Component | Location | Change needed | Why | Difficulty |
|---|---|---|---|---|---|
| C-1 | `StorageTopologyProfiler` — silent dropping | `crates/detection/src/topology.rs:96-105` | Clamp out-of-range partitions to the image end and record a `Finding` preserving the declared start/length, instead of dropping them via `validate_region_bounds(...).is_ok()` | A partition table declaring a partition past the end of the image is a reportable anomaly. It currently vanishes without trace. | **LOW** |
| C-2 | `StorageTopologyProfiler` — no overlap check | `topology.rs:79-107` | Detect overlapping entries and record findings. `Region::overlaps` (`region.rs:63-77`) already exists and is unused here | Overlapping MBR entries indicate tampering or corruption — a forensic signal currently discarded. | **LOW** |
| C-3 | `TopologyType::Gpt` declared but unimplemented | `topology.rs:23`; no producer | Either implement GPT or document the variant as reserved | A court-facing enum implying a capability that does not exist is worse than omitting the variant. | **LOW** (document) / **MEDIUM** (implement) |
| C-4 | Silent `512` sector-size default | `topology.rs:59`; `crates/parsers/honeywell/src/parser.rs:41` | Replace `unwrap_or(512)` with a provenance-tagged geometry value; keep `Assumed(512)` as a last resort but surface the tag in output | FI-07. An assumed sector size that never appears in a report is an unrecorded interpretation decision (FI-14). | **MEDIUM** (needs §11.2 + a product decision) |
| C-5 | `read_exact_at` mislabels short reads | `crates/evidence-reader/src/reader.rs:78-86` | Distinguish "source truncated" from "request out of range". **Keep the strict all-or-nothing contract** — change only the error classification | Currently `RegionScanner` maps any `OutOfBounds` to `TerminationReason::Truncated` (`scanner.rs:172-176`), so a caller bounds bug is reported as evidence truncation — the same laundering the spec criticises in §3.7. | **LOW–MEDIUM** (needs a new error variant; BC-6) |
| C-6 | `read_at` clamps silently | `crates/evidence-reader/src/raw.rs:138-140` | Report that clamping occurred (via the new read outcome of §11.1), not just the resulting count | Phase 10.1: "expose whether clamping occurred." | **LOW** (once §11.1 exists) |
| C-7 | `ScanReport.skipped_ranges` is a permanent placeholder | `crates/evidence-reader/src/scanner.rs:58,131` | Populate it, or document it as reserved. It is declared and **never pushed to** | A public field that is structurally always empty misleads consumers. | **LOW** |
| C-8 | Overstated sparse claim in crate docs | `crates/evidence-reader/src/lib.rs:23` | Either implement the sparse/truncation distinction or soften the claim | The doc says "Sparse/unallocated regions are never reported as source truncation," but `raw.rs:126-144` has no sparse mechanism at all — a sparse hole is indistinguishable from real zeros. **Documentation currently overstates the implementation.** | **LOW** (doc) / **MEDIUM** (implement) |
| C-9 | Parser address-space ambiguity | `crates/parsing/src/orchestrator.rs:67-84` vs `crates/recovery/src/levels.rs:225,258` and `crates/recovery/src/validation.rs:23,51` | Make the addressing contract explicit at the reader or signature level | A live pre-existing defect: `recognize_candidate` always gets a window; parsers read absolute offsets (`uniview:78,84`). Currently safe only by accident (false negatives, not false positives). | **MEDIUM** (narrow fix) / **VERY HIGH** (full typed addresses) |
| C-10 | `estimate_coverage` bypasses `Region::new` | `crates/timeline/src/gaps.rs:157,166,175` | Construct via `Region::new` so the overflow check applies, or make the fields private | Struct-literal construction skips the only overflow guard. Not currently reachable (inputs are pre-validated) but the pattern would not survive hostile input. | **LOW** |
| C-11 | `estimate_coverage` reimplements set algebra inline | `gaps.rs:137-196` | Reimplement on top of the new `RangeSet`, preserving the public signature | Removes duplicate logic and makes the union/complement operations reusable. | **LOW** (after §11.4) |
| C-12 | `RawReader::open_device` is Unix-only | `crates/evidence-reader/src/raw.rs:79` | Add a Windows path (behind a platform gateway) or document `SourceKind::PhysicalDisk` as Unix-only | The declared host is Windows; the variant is currently unconstructible there. | **MEDIUM–HIGH** |
| C-13 | `ReadOnlyMmap` is Unix-only | `crates/evidence-reader/src/mmap.rs:82-89` | Add a Windows mapping or document the limitation. Note `map_region`'s first parameter is `_file` (underscore-prefixed) purely so the non-Unix build compiles — a smell worth cleaning up | Same platform gap. | **MEDIUM** |
| C-14 | `RawReader` serialises all reads through one `Mutex<File>` | `raw.rs:28,126-144` | Consider positional reads (`FileExt::read_at` on Unix / `seek_read` on Windows) to allow true concurrency | The trait advertises `Send + Sync` "for parallel detection" (`reader.rs:38`), but the mutex means reads are serialised. Correctness is unaffected; the advertised benefit is not delivered. | **LOW–MEDIUM** |
| C-15 | Container kind inferred from file extension | `raw.rs:63-71` | Optionally add explicit-kind-plus-sniff per spec §13.9 | **Low priority.** The spec's objection targeted *encrypted* extension tests in the original; this project's inference is transparent and deterministic. Only worth changing when segmented or sparse containers arrive. | **LOW** |
| C-16 | Recording completeness not cross-checked against bad sectors | no such code | Add the intersection check and set `Recording.IntegrityFlag` accordingly | Spec §9.9's forensically critical operation. `Acquisition` already enforces the analogous rule at acquisition level (`acquisition.rs:110-127`); recordings are unprotected. | **LOW** (after §11.4) |
| C-17 | `error.rs` variant-count test will break on extension | `crates/forensic-core/src/error.rs:196-200` (`assert_eq!(errors.len(), 9, ...)`) | Update when adding error variants | Mechanical, but it will fail the build and should be anticipated. | **LOW** |

---

# 13. What We Should NOT Change Yet

Changing these now would create risk without proportionate benefit.

| # | Component | Location | Why not yet |
|---|---|---|---|
| N-1 | **`Region`'s half-open semantics** | `crates/forensic-core/src/region.rs` | Load-bearing across ~20 crates. Introducing the spec's inclusive `ByteRange` beside it produces one-byte errors that **type-check and produce plausible output** (§8.6 BC-3). The spec's own §9.2 marks the inclusivity as `[INFERRED]`, not confirmed. **There is no benefit and a serious risk.** Build `RangeSet` on `Region`. |
| N-2 | **`read_at`'s signature** | `crates/evidence-reader/src/reader.rs:74` | A direct return-type change touches 2 implementors, ~6 mocks and every caller across 9 crates in one commit. The additive defaulted-method route (§11.1) achieves the same outcome with a fraction of the blast radius. Do the additive version first; retire the old method only after every caller has migrated. |
| N-3 | **`read_exact_at`'s strict contract** | `reader.rs:78-86` | Its all-or-nothing behaviour is a **safety feature**. Seven parsers guard on `if let Ok(buf) = reader.read_exact_at(...)` (`dahua:111,149`; `uniview:78,84,121,164`; `hikvision:45`). Making a partial buffer return `Ok` would cause them to parse substituted zeros as real data (§8.6 BC-8). Add partial reporting on a new method; leave this one alone. |
| N-4 | **Full typed address spaces across all offsets** | `region.rs`, every `u64` offset | VERY HIGH effort (§8.6 BC-2) touching provenance, acquisition, recovery, recordings, timeline and partitions. The narrow reader-level fix (§11.8) addresses the actual defect. Revisit only if the narrow fix proves insufficient. |
| N-5 | **The E01 gate** | `raw.rs:38-47`; `docs/decisions/OPEN-1` | The gate is correct and better-documented than the spec's guidance, and the spec confirms it has **zero** E01 format knowledge to contribute (H-1). Opening it early means either a hand-rolled parser (explicitly prohibited) or an unverified dependency. Keep the gate; run the six-item verification gate when E01 becomes a real requirement. |
| N-6 | **RAII / resource management** | throughout | The spec's FI-13 disciplines are for a GC language. Adding `leaveOpen` flags or disposal-failure aggregation to Rust code would be pure complexity for zero safety gain. |
| N-7 | **`checked` arithmetic helpers** | `crates/forensic-core/src/checked.rs` | Already fully satisfy FI-03 and FI-05 and are correct for non-power-of-two sector sizes. Nothing in the spec improves on them. |
| N-8 | **`inspect_source` / source-safety policy** | `crates/evidence-reader/src/source_safety.rs` | The spec has no equivalent and offers no guidance. In particular, do not weaken the `Unknown`-is-never-`ReadOnly` rule (`:103-109`) or the `ReadWrite` rejection while "aligning with the spec" — the spec is silent, not permissive. |
| N-9 | **OEM-facts-as-versioned-data architecture** | `crates/forensic-core/src/profile.rs`; `profiles/` | The spec never mentions it and its Phase 13 examples would embed layout knowledge in code. For a multi-vendor tool this property is more valuable than any spec interface. Protect it explicitly during any refactor. |
| N-10 | **Reporting all partition schemes instead of one winner** | `topology.rs:47-51` | Worth doing eventually, but it breaks `detectors/tplink.rs:41` and `tests/tests/tplink_sample_raw_test.rs:33` (BC-4). Sequence it **after** GPT and EBR exist — reporting multiple schemes is only useful once more than one scheme can be detected. |
| N-11 | **Retry policy** | no such code | Correctly sequenced after a working physical-disk path (§11.12). Retry has no live use case while `open_device` is Unix-only on a Windows host, and adding it now means untestable code. |
| N-12 | **Sampled evidence fingerprint** | no such code | Adding a second hash that is not an integrity hash creates exactly the confusion FI-11 warns about. Only add with a concrete need and an explicit non-integrity label. |
| N-13 | **Degraded-mode refusal of sector operations** | no such code | The spec's rule (refuse sector ops when no sector size is available) would disable `StorageTopologyProfiler` for every plain `.raw` image — the normal case here. Needs a product decision (§11.2) before implementation, not a mechanical port. |
| N-14 | **Generic filesystem parsers** | no such code | The spec scopes them out of the DataIO foundation. Adding exFAT/ext4 support now would be speculative work ahead of a real case requiring it. |
| N-15 | **Splitting `evidence-reader` into spec-shaped L0–L5 crates** | crate layout | The current 8-module crate is coherent and compiles clean. Restructuring into six layers before the capabilities that justify them exist would be architecture-for-its-own-sake. Let the layering emerge as geometry, extents and range algebra land. |

---

# 14. Migration Strategy

Staged plan. No code in this section — this is sequencing and rationale only.

## 14.0 Architectural strategy decision

Four options were considered against the actual dependency analysis.

| Option | Verdict |
|---|---|
| **A — Keep current DataIO and improve it incrementally** | **RECOMMENDED, with qualification** |
| B — Replace current DataIO with the spec architecture | **REJECTED** |
| C — Build the spec architecture alongside and migrate gradually | **REJECTED as a whole; partially folded into A** |
| D — Another approach | Not needed; A covers it |

### Why B is rejected

1. The spec's architecture is expressed in .NET interfaces that cannot be ported literally. "Replacing with the spec architecture" would mean inventing a Rust equivalent of a design that was itself never implemented — the spec is a Stage-2 document with no corresponding code.
2. Replacement would require changing `EvidenceReader::read_at` and `Region` simultaneously, touching 9 crates and 7 parsers in one operation (§8.6 BC-1, BC-2, BC-3).
3. The current implementation is **better than the spec's baseline in six of eleven forensic properties** (§9.2). Replacement would risk losing `WriteGuard`, `inspect_source`, the OEM-facts-as-data architecture, `DeterminismKey`, and RAII safety — none of which the spec specifies.
4. The spec's own Phase 19.6 advice — "Do not start with the physical-disk reader… the most expensive place to discover that the read contract was wrong" — applies with more force here: the read contract is already in production use by seven parsers.

### Why C is rejected as a whole

Building a parallel L0–L5 stack beside `evidence-reader` would create two evidence abstractions in one workspace. Every consumer would need to know which to use, mocks would double, and `Region`-vs-`ByteRange` conversion boundaries would multiply the BC-3 risk at every seam. The one genuinely valuable part of C — building new capabilities as new types rather than by mutating existing ones — is already how Option A works in Rust, via additive defaulted trait methods.

### Why A, with qualification

The current architecture is compatible with the spec's *requirements* and its trait is thin enough to grow. Every high-value spec import (§11.1–§11.5) is additive or near-additive. The qualification: "incrementally improve" must mean **importing specific spec requirements in a deliberate order**, not opportunistic tinkering. That order is below.

**One more reason A is right:** the spec is a specification for building DataIO *from nothing*, derived from a decompiled assembly. This project already has a working, compiling, tested evidence layer that is forensically sound in most respects. The spec's value here is as a **requirements checklist and a catalogue of known failure modes**, not as a blueprint to build against.

## 14.1 Stage 0 — Zero-risk clarifications (no behaviour change)

**Goal:** remove misleading constructs before anyone builds on them.

1. Document `TopologyType::Gpt` (`topology.rs:23`) as reserved-and-unimplemented, or open a tracked item to implement it. **A forensic type must not imply a capability it lacks.** (C-3)
2. Correct or soften the sparse claim at `crates/evidence-reader/src/lib.rs:23` so the documentation matches `raw.rs:126-144`. (C-8)
3. Document `ScanReport.skipped_ranges` (`scanner.rs:58`) as reserved, since it is initialised empty at `:131` and never populated. (C-7)
4. Document that `SourceKind::PhysicalDisk` is Unix-only (`raw.rs:79`) and that `ReadOnlyMmap` is Unix-only (`mmap.rs:82-89`). (C-12, C-13)
5. Record in the capability matrix that sector size is currently an untagged assumed 512 in the two places it appears.

**Risk: none.** No code behaviour changes. **Value: high** — prevents downstream reliance on constructs that do not do what their names suggest, and makes the platform's real capability boundary honest.

## 14.2 Stage 1 — `RangeSet` (foundation, fully isolated)

**Goal:** a reusable immutable range-set algebra over `Region`'s existing half-open semantics.

**Why first:** zero dependencies, purely additive, fully specified by the spec (Phase 9.3–9.5 gives complete pseudocode including all six subtraction shapes), and needed by Stages 2, 4 and 5. The spec's own Phase 17 moved range tracking earlier for exactly this reason: "cheap to build, expensive to retrofit."

**Scope:** `add`, `subtract`, `union`, `intersect`, `complement_within`, `contains`, `covers`, `total_length`, `count`, `min`, `max`, ordered iteration. Canonical invariant maintained (sorted, non-overlapping, non-adjacent) with one merge predicate. No value-enumerating API.

**Hard constraint:** half-open, built on `Region`. **Do not introduce the spec's inclusive `ByteRange`** (N-1, BC-3).

**Then:** reimplement `estimate_coverage` on top without changing its public signature (C-11), and fix the struct-literal construction at `gaps.rs:157,166,175` (C-10).

**Verification:** property tests for the spec's laws — `(A − B) ∪ (A ∩ B) == A`, `complement(complement(s, w), w) == s ∩ w` — plus the canonical invariant asserted after every operation, plus all six subtraction shapes, plus `u64` boundary behaviour. Existing `estimate_coverage` tests (`gaps.rs:432-461`) must pass unchanged.

**Risk: LOW.** Additive; one internal reimplementation behind a stable signature.

## 14.3 Stage 2 — Read-outcome reporting (the central forensic fix)

**Goal:** make partial reads and substituted zeros expressible. This closes the one gap that can produce a wrong forensic conclusion (§9.1, FI-04).

**Approach — additive, two-phase:**
- **2a:** add a **defaulted** trait method returning a rich outcome (`kind: Complete | Partial | NotRecorded`, `bytes_read`, `zero_filled: Vec<Region>`, `clamped: bool`) whose default implementation wraps the existing `read_at`. No implementor changes. No caller changes. Nothing breaks.
- **2b:** override it in `RawReader` to report tail clamping (C-6) and in `BoundedReader` to report window clamping. Migrate `RegionScanner` and `recovery::read_bounded_window` to the new method so truncation reporting becomes precise.

**Hard constraints:**
- **Do not change `read_at`'s signature** (N-2).
- **Do not loosen `read_exact_at`** (N-3, BC-8). Its strictness protects seven parsers.
- Keep errors in `Err(ForensicError)`; do not import the spec's `Failed` outcome variant.

**Also in this stage:** split short-read from out-of-range in the error model (C-5), so `RegionScanner` stops reporting caller bugs as evidence truncation (`scanner.rs:172-176`). Expect to update the variant-count assertion at `error.rs:196-200` (C-17, BC-6).

**Verification:** boundary reads at offset 0, last byte, and exactly-at-`len`; reads straddling the window end of a `BoundedReader`; short-read injection via a mock; assert `Complete` ⟺ full count and empty `zero_filled`. All existing tests must pass unchanged — that is the signal the change was genuinely additive.

**Risk: LOW–MEDIUM.** Low because additive; medium because the error-classification split changes `TerminationReason` outcomes that `HashingService` turns into `Review` vs `Pass` (`hashing/src/lib.rs:82-104`).

## 14.4 Stage 3 — Findings model + partition-layer honesty

**Goal:** stop discarding structural anomalies.

1. Add a `Finding` type (severity, code, message, affected region, declared-before-clamp region), modelled on the proven `ValidationState` pattern.
2. Add `findings: Vec<Finding>` to `StorageTopology` and `PartitionCandidate` (BC-7 — all three construction sites are inside `topology.rs`).
3. Change `topology.rs:96-105` from silent dropping to clamp-and-record, preserving declared values (C-1).
4. Add overlap detection using the existing unused `Region::overlaps` (C-2).
5. Record findings for skipped zero-type and zero-length entries (`topology.rs:82-89`).
6. Add a finding where Dahua clamps a declared payload length (`dahua/src/parser.rs:193-196`).

**Watch:** clamping previously-dropped partitions makes new regions appear in `StorageTopology.partitions`, which `detectors/tplink.rs:43-44` feeds as candidate regions. Detection input changes. Verify against `tests/tests/tplink_sample_raw_test.rs`.

**Verification:** synthetic MBRs with an overrunning entry, two overlapping entries, a zero-type entry, and a zero-length entry — each producing the expected finding with declared values preserved.

**Risk: LOW–MEDIUM.** Contained to one file plus one detector's input.

## 14.5 Stage 4 — Geometry model with provenance

**Goal:** make sector size discovered, tagged and reportable rather than silently assumed.

**Prerequisite — product decision:** what happens when no sector size is available for a plain `.raw` file? The spec says degraded mode (refuse sector operations), which would disable `StorageTopologyProfiler` for the normal case here. **Recommended: proceed with `Assumed(512)` but surface the tag in `StorageTopology`, in reports, and as a `Finding`.** Decide before writing code (N-13).

**Scope:**
1. A geometry type: `bytes_per_sector` + provenance (5 levels), `total_bytes` (already measured) + provenance, derived `sector_count`, explicit `tail_bytes`, `conflicting_claims`.
2. Adopt the spec's corrected precedence: `OperatorDeclared > Measured > DecodedFromContainer > InferredFromExternalLog > Assumed`.
3. Replace `sector_size_override.unwrap_or(512)` (`topology.rs:59`) and `profile.layout.get("sector_size").unwrap_or(512)` (`honeywell/src/parser.rs:41`) with the tagged value (C-4, BC-5).
4. Validate `bytes_per_sector >= 512`; warn (do not reject) on non-power-of-two.
5. Optionally add `read_sectors` as a defaulted convenience over `read_at` requiring geometry — purely additive since nothing calls it today.

**Verification:** the spec's Phase 4.2 reconciliation cases adapted to the corrected precedence; conflicting claims retained; `tail_bytes` correct for a source whose length is not a sector multiple; property-based conversion round-trips across `{512, 520, 1024, 2048, 4096, 4160}` — the last confirming what `checked_sector_offset` already guarantees. Update `tests/tests/phase2_detection.rs:226` and `tests/tests/tplink_sample_raw_test.rs:33` expectations.

**Risk: MEDIUM.** Small code change, real behavioural implications, test expectations shift.

## 14.6 Stage 5 — Completeness cross-checks

**Goal:** never present a recording as complete when its bytes intersect a known gap.

1. Cross-check `Recording.source_offsets` against `Acquisition.bad_sector_ranges` and `unresolved_ranges` using Stage 1's `intersect`, and set `Recording.IntegrityFlag` accordingly (C-16, §11.5).
2. Extend `CoverageEstimate` toward the spec's named-set model (structural / claimed-intact / claimed-recovered / unreadable / unrecorded / carved) so coverage accounting can close over the device.
3. Wire `BoundedReader` to `PartitionCandidate` so partition-scoped reading is actually exercised (§11.7).

**Verification:** a recording whose regions intersect a bad-sector range must be flagged and must not be exportable as complete; coverage accounting closes — `structural ∪ claimed ∪ unreadable ∪ unaccounted == [0, len)`.

**Risk: LOW.** Additive, built on Stages 1 and 3.

## 14.7 Stage 6 — Recording fake gateway + address-space fix

**Goal:** make determinism testable, and fix the live parser-addressing defect.

1. Build a mock reader that **records every call** (offset, length, result) and can inject failures by offset, attempt number or call count (§11.11). This is the single highest-leverage test asset — it makes "no unrequested reads", determinism, partial-read paths and later retry all testable.
2. Add the no-unrequested-reads assertion for a full analysis pass.
3. Apply the **narrow** address-space fix (§11.8, C-9): distinguish whole-image from window readers at the reader/signature level so `recognize_candidate` cannot silently receive the wrong address space. **Do not** attempt the full typed-address-space model (N-4).

**Verification:** an analysis pass issues exactly the expected reads; a parser given a window cannot be handed to a whole-image-expecting signature.

**Risk: LOW** for the harness; **MEDIUM** for the addressing fix (touches the `Parser` trait and all seven implementations, though shallowly).

## 14.8 Stage 7 — Extent map / content addressing

**Goal:** read a fragmented recording as one stream.

Depends on Stage 2 (needs zero-fill reporting). Add `Extent` with kind and address space, a validated `ExtentMap`, and a reader over it. Sparse and uninitialised explicitly zero-filled **and reported**; unreadable makes the containing read `Partial`.

**Verification:** multi-extent maps including sparse and unreadable extents; reads straddling every extent boundary; byte-exactness against a concatenation oracle; explicit assertion that sparse regions are zeroed and reported.

**Risk: MEDIUM.** Purely additive but substantial new surface.

## 14.9 Stage 8 — Demand-driven capabilities (no fixed order)

Sequence by actual case requirements, not by the spec's ordering:

| Capability | Trigger | Notes |
|---|---|---|
| Windows physical-disk path + platform gateway (§11.9, C-12, C-13) | A case requires live-device acquisition on Windows | Adopt the spec's one-gateway design; narrowest share mode, recorded. Enables Stage 6's gateway to be shared. |
| GPT + EBR (§11.6) | A DVR image with GPT or logical partitions appears | If done, do it fully per spec §2.12 — CRCs, backup header, real entry count, GUIDs, UTF-16 names, no 12-entry cap. Needs a synthetic partition-structure builder. |
| All-schemes partition reporting (N-10, BC-4) | **After** GPT and EBR exist | Pointless before more than one scheme is detectable. Breaks `detectors/tplink.rs:41` and one test. |
| Retry policy (§11.12, N-11) | **After** a working physical-disk path | Needs the retryable/non-retryable error split from Stage 2. Iterative, bounded, policy-as-config. |
| Segmented raw images (§11.13) | A segmented acquisition appears | Validate every segment at open; integer-only selection; check every read; no 512-multiple rule. Needs a structured locator. |
| Sparse record-on-read capture (§11.14) | Failing-drive work becomes routine | Depends on Stage 2's `NotRecorded`. Decide read-original-format vs write-own-versioned-format. |
| E01 / EWF (§11.15, N-5) | A case delivers E01 evidence | Run the existing six-item OPEN-1 verification gate. **Do not hand-roll.** Independent of everything above. |
| Concurrent positional reads (C-14) | Detection throughput becomes a measured problem | Replaces `Mutex<File>` with platform positional reads. |

## 14.10 Dependency graph

```
Stage 0 (clarify docs) ─── independent, do immediately
                            │
Stage 1 (RangeSet) ─────────┼────────────┬──────────────┐
                            │            │              │
Stage 2 (read outcome) ─────┼────────┐   │              │
                            │        │   │              │
Stage 3 (findings + MBR) ───┘        │   │              │
        │                            │   │              │
Stage 4 (geometry) ──────────────────┘   │              │
        │                                │              │
Stage 5 (completeness cross-checks) ◄────┘              │
        │                                               │
Stage 6 (recording gateway + address fix) ◄─────────────┘
        │
Stage 7 (extent map)  ◄── needs Stage 2
        │
Stage 8 (demand-driven: Windows device, GPT/EBR, retry,
         segmented, sparse capture, E01)
```

## 14.11 Sequencing rationale, one line each

- **Stage 0 first** — a forensic type that implies an absent capability (`TopologyType::Gpt`) is a liability, and fixing docs costs nothing.
- **Stage 1 before 2** — partial reads must report *ranges*, so the range type should exist first; and it has zero dependencies.
- **Stage 2 before 4** — get the read contract right before any backend or geometry decision bakes an assumption into it. This is the spec's own Phase 19.6 advice, and it applies more strongly here because seven parsers already depend on the contract.
- **Stage 3 with or after 2** — findings and precise read outcomes are the same concern (stop discarding what you know) applied at two layers.
- **Stage 4 after 2 and 3** — geometry needs somewhere to record conflicting claims (findings) and benefits from the read contract being settled.
- **Stage 5 after 1 and 3** — the completeness cross-check is a set intersection over recorded gap ranges.
- **Stage 6 after 2** — the recording gateway is most valuable once there is a rich read outcome to assert against.
- **Stage 7 after 2** — extents cannot report sparse/unreadable regions without the outcome type.
- **Stage 8 last, demand-driven** — every item is either platform work, format work, or gated on external inputs. None should block Stages 1–7.

## 14.12 Cross-cutting rules for every stage

1. **Additive first.** New defaulted trait methods and new types beside old ones. A stage that requires changing `read_at`'s signature or `Region`'s semantics has been scoped wrong.
2. **All existing tests must pass unchanged**, except where a stage explicitly identifies an expectation to update (`error.rs:196-200`, `phase2_detection.rs:226`, `tplink_sample_raw_test.rs:33`). Unexpected test breakage means the change was not additive.
3. **`cargo check --workspace --all-targets` clean at every stage boundary** — the current baseline is exit 0 with warnings only.
4. **Never weaken an existing guarantee to match the spec.** The spec is silent on `WriteGuard`, `inspect_source`, OEM-facts-as-data and `DeterminismKey`; silence is not permission to remove them.
5. **Keep `Region` half-open and `read_exact_at` strict** throughout.
6. **Record each decision** in `docs/decisions/` following the `OPEN-1`/`OPEN-2` pattern, especially the Stage 4 product decision on missing sector size.

---

# 15. Risk Assessment

## 15.1 HIGH risks

### H-R1 — Substituted zeros are indistinguishable from recorded zeros
**What:** `read_at` returns only a byte count (`reader.rs:74`). A sparse file hole, a genuinely blank recorded region, and a region the OS returned short on produce identical bytes and no distinguishing signal. `raw.rs:126-144` has no sparse handling; `ScanReport.skipped_ranges` is declared (`scanner.rs:58`) but never populated (`:131`).
**Why HIGH:** in a DVR case these three have different evidentiary weight. This is the only current gap that can support a *wrong* conclusion rather than an incomplete one. Spec FI-04 calls it "the single most important forensic requirement."
**Mitigating factor:** the current code is silent about what it does not know rather than asserting completeness — `read_exact_at` errors instead of returning a partially-zeroed buffer, and `Acquisition` forces `Complete`→`Partial` when gaps are recorded (`acquisition.rs:110-127`). Materially safer than the original the spec describes, which reported success while returning fabricated zeros.
**Mitigation:** Stage 2 (§14.3).

### H-R2 — Introducing an inclusive `ByteRange` beside half-open `Region`
**What:** spec §13.7 specifies inclusive-inclusive ranges with `Length = End - Start + 1`. `Region` is half-open — `region.rs:41-47` (`contains` uses `< end`), `region.rs:141-147` (adjacent regions asserted non-overlapping), `region.rs:79-88` (`intersection` computes `end - start`, no `+1`).
**Why HIGH:** the error mode is a one-byte discrepancy that **compiles, passes tests, and produces plausible court-facing output**. Adjacency also changes meaning, so a `RangeSet` built on the wrong model would either over-merge or fail to merge. `Region` is load-bearing across ~20 crates.
**Mitigation:** do not do it (N-1). Build `RangeSet` on `Region` (Stage 1). Note the spec's own §9.2 marks the inclusivity as `[INFERRED]`, not confirmed — there is no evidence-based reason to prefer it.

### H-R3 — Loosening `read_exact_at` while "aligning with the spec"
**What:** `read_exact_at` currently converts a short read into `Err` (`reader.rs:78-86`). Seven parsers guard on `if let Ok(buf) = reader.read_exact_at(...)` — `dahua:111,149`; `uniview:78,84,121,164`; `hikvision:45`; `honeywell:45`.
**Why HIGH:** if a partial buffer became `Ok`, every one of those guards would admit partially-zeroed data and parse it as real. A well-intentioned "preserve the good prefix" change (which the spec does ask for) would silently convert a safe API into an unsafe one across all parsers.
**Mitigation:** N-3 — leave it strict. Add partial reporting on a new method (Stage 2).

### H-R4 — `TopologyType::Gpt` implying a capability that does not exist
**What:** declared at `topology.rs:23`, produced by no code path. `crates/detection/src/detectors/tplink.rs:41` branches on `== TopologyType::Mbr`, so a GPT-partitioned DVR image is classified `UnpartitionedRaw` and takes the fallback path.
**Why HIGH:** a forensic type that names a capability it lacks is a misrepresentation risk in a court-facing tool, and the mis-profiling is silent — no finding, no warning.
**Mitigation:** Stage 0 (document as reserved) immediately; Stage 8 (implement) when needed.

## 15.2 MEDIUM risks

### M-R1 — Parser address-space ambiguity
**What:** `recognize_candidate` always receives a `BoundedReader` (`levels.rs:225,258`; `validation.rs:51`) while parsers read absolute offsets (`uniview:78,84` read fixed 512 and 1024). `parsing/src/orchestrator.rs:67-84` passes the whole image to the other five methods. Nothing distinguishes them.
**Why MEDIUM not HIGH:** the failure direction is benign today — a window's offset 0 is mid-image, so absolute reads fail to match their magic and produce *false negatives* (candidate skipped), not wrong byte attribution. But it is safe by accident.
**Risk of escalation:** any parser that later reads a *relative* structure, or any change to `BoundedReader`'s offset base, flips this to false positives.
**Mitigation:** Stage 6 narrow fix (§11.8). **Do not** attempt the spec's full typed-address model (N-4, BC-2 = VERY HIGH).

### M-R2 — Silent assumed sector size
**What:** `topology.rs:59` (`sector_size_override.unwrap_or(512)`) and `honeywell/src/parser.rs:41` (`unwrap_or(512)`).
**Why MEDIUM:** on a 4Kn image every LBA→byte conversion in `StorageTopologyProfiler` is wrong by 8×, the MBR still parses, and nothing visibly fails. **Bounded blast radius today:** `total_bytes` is always a measured file length, and all parsers use absolute byte offsets, so the assumption only affects partition offset conversion. Spec's own H-3 admits it does not know whether 4Kn occurs in DVR evidence.
**Mitigation:** Stage 4 (§14.5), with the product decision recorded first.

### M-R3 — Structural anomalies silently discarded
**What:** out-of-range partitions dropped at `topology.rs:96`; no overlap detection despite `Region::overlaps` existing unused; zero-type/zero-length entries skipped without record (`topology.rs:82-89`); Dahua clamps a declared payload length without a finding (`dahua/src/parser.rs:193-196`).
**Why MEDIUM:** these are exactly the anomalies a forensic report should surface. The tool currently cannot report a tampered or corrupt partition table.
**Mitigation:** Stage 3 (§14.4). Low cost.

### M-R4 — Short read and out-of-range collapsed into one error
**What:** `read_exact_at` returns `out_of_bounds("short read", …)` (`reader.rs:78-86`); `RegionScanner` maps any `OutOfBounds` to `TerminationReason::Truncated` (`scanner.rs:172-176`), which `HashingService` turns into `Review` (`hashing/src/lib.rs:82-104`).
**Why MEDIUM:** a caller-side bounds bug is reported as evidence truncation — the exact "laundering" the spec criticises in §3.7. It corrupts the meaning of a validation state that appears in reports.
**Mitigation:** Stage 2 (C-5).

### M-R5 — Physical-disk support unreachable on the target platform
**What:** `RawReader::open_device` is `#[cfg(unix)]` (`raw.rs:79`); `ReadOnlyMmap` returns `UnsupportedFormat` on non-Unix (`mmap.rs:82-89`). Declared host is Windows.
**Why MEDIUM:** `SourceKind::PhysicalDisk` and `ImageFormat::PhysicalDisk` (`case.rs:63`) exist and cannot be constructed there. Capability claims and reality diverge.
**Mitigation:** Stage 0 document; Stage 8 implement.

### M-R6 — No evidence-layer test asserting reads are exactly those requested
**What:** determinism is a property of the code's structure (no timers, no random reads) rather than a tested assertion. Six mock readers exist; none records calls or injects failures.
**Why MEDIUM:** a future addition (a prefetch, a cache warm-up, a retry) could break determinism with no test failing.
**Mitigation:** Stage 6 recording gateway.

### M-R7 — Fragmented recordings cannot be read as one stream
**What:** recovery reads a single contiguous window per candidate, capped at 8 MiB (`levels.rs:35,42-54`).
**Why MEDIUM:** DVR recordings are routinely fragmented — a functional limitation for the core use case.
**Mitigating factor:** the cap is reported honestly as `Review` with the reason "bytes beyond the cap were not examined" (`levels.rs:169-183`). Incomplete, not misleading.
**Mitigation:** Stage 7.

### M-R8 — `Region`'s public fields bypass its overflow guard
**What:** `gaps.rs:157,166,175` construct `Region { offset, length }` as struct literals, skipping `Region::new`'s overflow check (`region.rs:23-31`).
**Why MEDIUM:** not currently reachable — inputs are pre-validated — but the pattern would not survive hostile input, and it undermines the invariant `Region::new` exists to enforce.
**Mitigation:** C-10 in Stage 1.

### M-R9 — Migration itself introducing regressions
**What:** ten identified breaking changes (§8.6); several touch `StorageTopology`'s shape and detection input.
**Why MEDIUM:** clamping previously-dropped partitions (Stage 3) changes what `detectors/tplink.rs:43-44` receives as candidate regions; geometry enforcement (Stage 4) changes test expectations.
**Mitigation:** §14.12 rules — additive-first, all existing tests pass unchanged except explicitly identified ones, `cargo check` clean at each boundary.

## 15.3 LOW risks

| # | Risk | Detail | Mitigation |
|---|---|---|---|
| L-R1 | `error.rs` variant-count assertion breaks on extension | `assert_eq!(errors.len(), 9, ...)` at `error.rs:196-200` | Mechanical update (C-17) |
| L-R2 | `ScanReport.skipped_ranges` permanently empty | Declared `scanner.rs:58`, initialised `:131`, never pushed. A public field structurally always empty | Populate or document (C-7) |
| L-R3 | Crate docs overstate sparse handling | `lib.rs:23` claims a distinction `raw.rs:126-144` cannot make | Correct or soften (C-8) |
| L-R4 | `Mutex<File>` serialises reads | `raw.rs:28,126-144`; trait advertises `Send + Sync` "for parallel detection" (`reader.rs:38`) but I/O is serialised. Correctness unaffected | Positional reads if throughput is measured as a problem (C-14) |
| L-R5 | `mmap.rs` `_file` underscore parameter | `map_region(_file: &File, …)` exists purely so the non-Unix branch compiles — a smell | Clean up with C-13 |
| L-R6 | Container kind from file extension | `raw.rs:63-71`. Transparent and deterministic; spec's objection targeted *encrypted* tests in the original | Revisit only when segmented/sparse containers arrive (C-15) |
| L-R7 | `unwrap()` on `try_into()` of bounds-checked slices | e.g. `dahua/src/parser.rs:152,322`. Safe — slices are length-verified — but relies on local reasoning | Lint policy |
| L-R8 | Retry absent | No live use case while physical disk is Unix-only on a Windows host | Stage 8, after device support |
| L-R9 | Adding a sampled fingerprint could be mistaken for integrity | Not present today; risk only if added | Do not add without an explicit non-integrity label (N-12) |
| L-R10 | No segmented / sparse / E01 support | Demand-driven capability gaps, each documented | Stage 8; E01 gate already documented |

## 15.4 Risks the spec raises that do NOT apply here

Recorded so mitigation effort is not misdirected. Each was verified absent.

| Spec risk | Why it does not apply |
|---|---|
| Arithmetic overflow unchecked project-wide | All ops via `checked_*` (`checked.rs:14-41`) |
| Mask/shift offsets wrong for non-power-of-two sectors | Multiplication only (`checked.rs:33-41`) |
| Floating-point address arithmetic | None; `f64` appears only in `coverage_ratio` (`gaps.rs:179-184`) and `ProgressInfo::fraction` (`progress.rs:70-78`) |
| Negative start sectors unchecked | `u64`; unrepresentable |
| Device handle never disposed | RAII; `File` on drop, `munmap` in `Drop` (`mmap.rs:120-127`) |
| DI container / decoder never disposed | No DI container exists |
| Random keep-alive breaking determinism | No keep-alive |
| Licence gate blocking evidence access | None |
| String-encryption runtime | None |
| Evidence layer depending on partition layer | `EvidenceReader` has no partition members; `detection` depends on `evidence-reader`, not the reverse |
| Public `retryAttemptNumber` letting callers start mid-ladder | No retry parameter on the trait |
| Three inconsistent range-merge predicates | One `merge_regions`, one call site (`gaps.rs:143`) |
| `GetMissingValues` materialising every 64-bit value | No value-enumerating API |
| `EntryCount` over-reporting due to deferred collapsing | No dual-index range tracker |
| Read+write share mode on the evidence device | No Windows device path yet; `File::open` is read-only |
| Recording target constructible from an evidence locator | No recording capability |
| Segmented image assuming all middle segments match the first | No segmented support |
| E01 read with no bounds check | E01 refused (`raw.rs:38-47`) |
| Unrecognised whole-disk volume discarded | Whole-device fallback is unconditional (`topology.rs:64-72,121-127`) |

---

# 16. Test Coverage Gap

Audit only — no tests were created. Verified by reading test files and running `cargo check --workspace --all-targets` (exit 0).

## 16.1 Test inventory

| Location | Scope |
|---|---|
| `crates/forensic-core/src/checked.rs:110-250` | Checked arithmetic: add/mul/sub normal, zero, overflow, underflow; sector offset incl. zero sector size and overflow; region bounds incl. boundary, beyond-source, zero-length at/beyond end; no-panic sweep over `{0, 1, u64::MAX/2, u64::MAX-1, u64::MAX}` |
| `crates/forensic-core/src/region.rs:103-198` | Serde round-trip, `end`, `contains`, empty-contains-nothing, overlap incl. adjacency, intersection, no-intersection, overflow rejection, display |
| `crates/forensic-core/src/error.rs:110-201` | Display context for Io/OutOfBounds/overflow; all 9 variants constructible |
| `crates/forensic-core/src/acquisition.rs:160-236` | Four statuses serde; default `Unknown`; **`Complete`→`Partial` downgrade for bad sectors and unresolved ranges**; complete-without-gaps; unknown-stays-unknown |
| `crates/forensic-core/src/provenance.rs:148-247` | Serde round-trips; completeness; incomplete-without-regions; profile fields; transformation ordering; validation state carried |
| `crates/forensic-core/src/write_guard.rs:108-177` | Write inside evidence dir denied + custody event; write in artifacts dir allowed |
| `crates/evidence-reader/src/reader.rs:95-120` | Documentation assertion that no write method exists; `Send + Sync` |
| `crates/evidence-reader/src/raw.rs:148-175` | Nonexistent file; **E01 rejected**; `Send + Sync` |
| `crates/evidence-reader/src/bounded.rs:103-166` | Window isolation, correct bytes, local out-of-bounds rejected, absolute-offset mapping |
| `crates/evidence-reader/src/scanner.rs:196-268` | Windowed reads equal full read (512-byte window over 5,000 bytes); cancellation with partial `searched_bytes` |
| `crates/evidence-reader/src/source_safety.rs:111-157` | ReadOnly accepted; ReadWrite rejected; Unknown accepted with warning; **Unknown never reported as ReadOnly**; serde; mounted blocks analysis |
| `crates/evidence-reader/src/config.rs:118-145` | Provisional default valid; out-of-range rejected; min>max rejected |
| `crates/evidence-reader/src/mmap.rs:130-152` | Unix mmap returns correct bytes for a 500-byte region at offset 100 |
| `crates/detection/src/topology.rs:129-183` | Unpartitioned raw; **one** valid MBR partition with correct start sector and byte region |
| `crates/hashing/src/lib.rs:145-265` | SHA-256 known vectors ("abc", empty); **hash identical across windows 4 KiB–64 KiB and equal to in-memory**; single-bit-flip and truncation produce distinct hashes; 512-byte-window large fixture |
| `crates/timeline/src/gaps.rs:~420-473` | Coverage merges overlapping regions; suppresses small holes; full coverage + continuity passes |
| `crates/recovery/tests/adversarial_recovery.rs:96-125` | Overflow offsets rejected safely; out-of-bounds offsets rejected safely |
| `crates/recovery/tests/integration.rs:154-200` | Engine truncation on byte limit and candidate limit |
| `crates/recovery/tests/uniview_recovery.rs:103` | Truncated evidence yields `Review` |
| `crates/parsers/*/tests/integration.rs` | Per-OEM: parse pipeline, adversarial wrong-offset, fixture-shape sweep |
| `tests/tests/phase1_foundational.rs` | Bounded memory scan over a sparse fixture; windowed reads equal full read; source-safety rejection; checked-arithmetic overflow |
| `tests/tests/phase2_detection.rs:203-228` | **`adversarial_non_512_sector_size_topology`** — profiles with `Some(4096)` and asserts `topo.sector_size == 4096` without panic |
| `tests/tests/phase3_parsing_contract.rs:58-90` | `checked_sector_offset(u64::MAX, 512)` overflow; region bounds validation |
| `tests/tests/regression_suite.rs:304-310` | `BoundedReader` isolation and absolute-offset translation |
| `tests/tests/tplink_sample_raw_test.rs:32-37` | Real sample: `TopologyType::Mbr`, 2 partitions, types `0x82`/`0x83` |
| `tests/tests/tplink_synthetic_dry_run.rs:30-95` | Mock reader synthesising an MBR at sector 0 with two entries |
| `tests/tests/corpus_suite.rs`, `tests/src/fixtures.rs` | Deterministic fixture generator: `FixtureShape::{Normal, Sparse, Truncated, Fragmented, WrongOffset, Partial}` |
| `tests/tests/workspace_layout.rs` | Workspace structural invariants (350 lines) |

## 16.2 Coverage against the spec's required test areas

| Spec-required area | Status | Evidence / gap |
|---|---|---|
| **Sector boundaries** | **NO TEST** | No test reads across a sector boundary as a sector boundary. No sector-addressed API exists to test. |
| **Byte boundaries** | **PARTIAL** | `checked.rs:184-194` covers region-at-boundary and beyond-source. `bounded.rs:131` tests local OOB. **Missing:** read at offset 0 of length 1; read ending exactly at `len`; read ending at `len+1`; read starting at `len-1`. |
| **Large offsets** | **PARTIAL** | `checked.rs:228-250` sweeps `u64` extremes for arithmetic; `recovery/tests/adversarial_recovery.rs:96` uses `u64::MAX - 10`. **Missing:** a reader-level test at a large offset against a real source. |
| **Overflow** | **GOOD** | `checked.rs:124-131,150-155,172-176`; `region.rs:186-190`; `phase1_foundational.rs:198-201`; `phase3_parsing_contract.rs:59-72`; `adversarial_recovery.rs:96`. |
| **Partial reads** | **WEAK** | `scanner.rs:221` proves windowed == full read on an *intact* source. `recovery/tests/uniview_recovery.rs:103` and `integration.rs:154-200` cover *window-cap* truncation. **Missing entirely:** a mock that returns fewer bytes than requested mid-source. No test injects a short read. |
| **Failed reads** | **WEAK** | `raw.rs:151` covers open failure. `adversarial_recovery.rs` has a `HostileReader` with a `fail_reads` flag, used with `fail_reads: false` in the two tests examined. **Missing:** a read that fails partway, and any assertion about what the caller observes. |
| **Truncated source** | **PARTIAL** | `FixtureShape::Truncated` exists and is exercised per-OEM; `uniview_recovery.rs:103` asserts `Review`. **Missing:** a source truncated *between* open and read; a test distinguishing truncation from an out-of-range request (the current conflation at `reader.rs:78-86` is untested either way). |
| **Partition boundaries** | **WEAK** | `topology.rs:165-182` tests **one** valid partition. `tplink_sample_raw_test.rs:33-37` tests two real partitions. **Missing:** an overrunning entry; overlapping entries; a partition reader asserting the last byte succeeds and the next fails; equivalence of `partition_reader.read_at(k)` with `device.read_at(start + k)`. |
| **GPT** | **NO TEST** | No GPT implementation, therefore no test. `TopologyType::Gpt` is never asserted anywhere. |
| **MBR** | **PARTIAL** | Valid-table paths only: `topology.rs:165-182`, `tplink_synthetic_dry_run.rs:35-49`, `tplink/src/parser.rs:339-344`. **Missing:** bad signature; garbage type bytes; absurd start/length; all-zero entry; `0x00` type entry; protective MBR. |
| **Extended partitions** | **NO TEST** | Not implemented (`for i in 0..4`), therefore untested. No cyclic-EBR test. |
| **Range merging** | **PARTIAL** | `gaps.rs:432-446` merges overlapping regions; `region.rs:130-160` covers pairwise overlap and adjacency. **Missing:** add-adjacent-left/right; add-fully-contained; add-fully-containing; random-order insertion equalling sorted insertion; canonical-invariant assertions. |
| **Range subtraction** | **NO TEST** | No subtraction operation exists. None of the spec's six subtraction shapes (disjoint, exact, covering, mid-split, left trim, right trim) is testable. |
| **Sparse images** | **MISLEADING** | `FixtureShape::Sparse` exists and `phase1_foundational.rs:67` uses it for a *bounded-memory* test, not a sparse-semantics test. **No test asserts that a sparse region is distinguishable from real zeros** — and no mechanism exists to make it so. The crate doc at `lib.rs:23` claims a property nothing tests. |
| **Segmented images** | **NO TEST** | Not implemented. |
| **Non-512 sector sizes** | **PARTIAL** | `phase2_detection.rs:203-228` profiles with `Some(4096)` and asserts `sector_size == 4096` without panic. **It does not assert that resulting partition byte offsets are correct at 4096.** No test at 520, 1024, 2048 or 4160. No property-based round-trip. |
| **Retry** | **NO TEST** | Not implemented. |
| **E01** | **TESTED AS REFUSED** | `raw.rs:154-163` asserts `UnsupportedFormat` for `.E01`. Correct for the current gate. |
| **Determinism** | **PARTIAL** | Hash proven window-independent (`hashing/src/lib.rs:203-225`); deterministic fixtures (`tests/src/fixtures.rs`). **Missing:** the spec's no-unrequested-reads assertion; a same-input-twice full-pipeline comparison; a cross-machine run. |
| **Read-only assurance** | **PARTIAL** | `reader.rs:99-107` is a documentation assertion, not a mechanical check. `write_guard.rs:111-152` tests path denial. **Missing:** a hash-before/hash-after assertion over a full analysis pass; a mock asserting no write call was ever attempted. |
| **Resource leaks** | **NO TEST — and unnecessary** | RAII makes leaks structurally impossible. The spec's handle-leak detector requirement does not apply. |
| **Concurrency** | **PARTIAL** | `Send + Sync` asserted at compile time (`reader.rs:113-119`, `raw.rs:171-174`). **Missing:** a multi-threaded disjoint/overlapping read test. |
| **Cancellation** | **GOOD** | `scanner.rs:246-268` asserts `Cancelled` with bounded `searched_bytes`; `progress.rs:95-110` asserts the error payload. Exceeds the spec, which has no cancellation requirement. |

## 16.3 The five most important missing tests

Ordered by forensic value relative to cost.

1. **Short-read injection at the reader level.** A mock returning fewer bytes than requested mid-source, asserting exactly what the caller observes from `read_at`, `read_exact_at`, `RegionScanner` and `recovery::read_bounded_window`. **Nothing currently tests this path**, and it is the path H-R1 and M-R4 live on. It is also the prerequisite test for Stage 2.
2. **Malformed MBR corpus.** Bad signature, garbage type bytes, absurd start/length, all-zero entry, an entry overrunning the image, two overlapping entries. Every current MBR test uses a well-formed table. This is the test that would have surfaced the silent-drop behaviour at `topology.rs:96`.
3. **Partition-reader boundary equivalence.** For a `BoundedReader` over `[start, start+len)`: the last byte succeeds, `start+len` fails, and `bounded.read_at(k)` equals `device.read_at(start + k)` for random `k`. `bounded.rs:120-140` covers the basics on a 16-byte buffer; this needs a realistic source and boundary emphasis.
4. **Non-512 correctness, not just non-panic.** `phase2_detection.rs:203-228` proves 4096 does not crash. What is untested is whether partition byte offsets are *correct* at 4096 — i.e. that `start_lba * 4096` is what lands in `PartitionCandidate.region.offset`. Extend to 520 and 4160 to exercise the non-power-of-two property `checked_sector_offset` already guarantees.
5. **Range-set property laws.** Once Stage 1 exists: `(A − B) ∪ (A ∩ B) == A`, `complement(complement(s, w), w) == s ∩ w`, canonical invariant after every operation, all six subtraction shapes, random-order insertion equalling sorted insertion.

## 16.4 Test infrastructure present vs required

| Spec-required tool | Status |
|---|---|
| Synthetic device generator with per-sector stamps | **PARTIAL** — `tests/src/fixtures.rs` generates OEM-shaped fixtures deterministically, but not LBA-stamped images. Stamping would make byte-exactness assertions trivial. |
| Partition-structure builder (valid + malformed MBR/GPT/hybrid) | **MISSING** — every MBR test hand-writes bytes inline (`topology.rs:167-174`, `tplink_synthetic_dry_run.rs:35-49`). A builder is the prerequisite for safely implementing GPT/EBR. |
| **Recording fake gateway** (records every call; injects failures by offset/attempt) | **MISSING** — six mocks exist (`bounded.rs:110-138`, `scanner.rs:216-243`, `topology.rs:135-152`, `hashing/src/lib.rs:152-176`, `recovery/tests/adversarial_recovery.rs`, `tplink_synthetic_dry_run.rs:30-95`); none records calls. **Highest-leverage missing asset** — it unlocks determinism, no-unrequested-reads, partial-read and future retry testing. |
| Byte-exactness harness against an oracle | **PARTIAL** — `scanner.rs:221` and `hashing/src/lib.rs:203` compare against in-memory oracles for their own paths. No general harness. |
| Property-based testing facility | **MISSING** — no `proptest`/`quickcheck` in `Cargo.toml`. All tests are example-based. |
| Handle/stream leak detector | **NOT NEEDED** — RAII. |
| Real-evidence smoke corpus | **PARTIAL** — `validation_corpus/`, `.fixture_build/` with real H.264/H.265 streams, and `tplink_sample_raw_test.rs` against a real sample. No 512e/4Kn device, no E01, no segmented set. |

## 16.5 Overall test posture

**Strong** on: checked arithmetic (the most thoroughly tested module in the workspace), error construction, acquisition invariants, provenance, source safety, write guarding, hash correctness and window-independence, cancellation, and per-OEM adversarial fixture shapes.

**Weak** on: anything involving a read that does not fully succeed. There is no short-read injection, no mid-read failure assertion, no malformed-partition-table corpus, no partition boundary equivalence, and no property-based testing at all.

The pattern is consistent and worth naming: **the codebase is well tested for hostile *inputs* (overflow, out-of-range offsets, wrong offsets, truncated fixtures) and untested for hostile *backends* (a source that reads short, fails partway, or has sparse holes).** That is precisely the axis the specification's FI-04 and Phase 16.3 target, and it aligns exactly with the audit's single highest-priority finding.

---

# 17. Final Verdict

## 1. Is `DATAIO_IMPLEMENTATION_SPEC.md` already implemented?

**No.** And it could not be, in the form written: the specification describes .NET interfaces (`IDisk`, `IRandomAccessReader`, `IBlockDevice`, `ReadResult`, `Span<byte>`, `IDisposable`, `IProperty<T>`) while the project is a Rust workspace (`Cargo.toml`, edition 2021, rust-version 1.82, 20 member crates). The specification was also never implemented anywhere — it is a Stage-2 design document derived from a decompiled assembly, with no corresponding code.

What exists instead is an independently built Rust evidence layer (`crates/evidence-reader`, 8 modules, ~1,100 lines) that arrives at several of the specification's conclusions by different means, and misses others entirely.

## 2. If not, approximately what percentage is implemented?

**≈34% fully implemented, ≈22% partially, ≈44% missing**, counting the 83 specification requirements that are applicable to this project — excluding .NET mechanics, excluding formats the specification itself says not to implement, and excluding "do not reproduce this defect" items that were never present.

That percentage understates the project's position. Roughly half the specification is a catalogue of the original assembly's defects with instructions not to repeat them. **This project never inherited those defects**, so a large share of the "missing" 44% is new capability (geometry provenance, segmented images, sparse capture, extent maps, range algebra) rather than broken behaviour needing repair. Weighted by forensic risk, the highest-risk specification requirements — overflow protection, bounds enforcement, read-only guarantees, deterministic disposal — are the ones already complete.

## 3. Which major parts are missing?

1. **A read-outcome type** — no `Complete`/`Partial`/`NotRecorded` discriminator and, critically, **no reporting of which ranges were substituted zeros** (`reader.rs:74`). The specification's FI-04, its most emphasised requirement.
2. **Any sector-geometry model** — no sector size, sector count, tail bytes, or provenance. Two silent `512` defaults (`topology.rs:59`, `honeywell/src/parser.rs:41`).
3. **GPT, extended/EBR partitions, and a findings model.** `TopologyType::Gpt` is declared at `topology.rs:23` and produced by no code path; `for i in 0..4` at `topology.rs:79` reads primaries only; out-of-range partitions are silently dropped at `topology.rs:96`.
4. **Reusable range-set algebra** — `merge_regions`/`estimate_coverage` (`gaps.rs:137-196`) compute union and complement once, inline. No subtraction, so the specification's forensically critical "does this recording intersect an unreadable range" check is unwritable.
5. **Extent map / content addressing** — recovery reads one contiguous window per candidate (`levels.rs:42-54`), so a fragmented DVR recording cannot be read as one stream.
6. **Retry policy** — none.
7. **Segmented raw images and sparse record-on-read capture** — neither exists.
8. **Windows physical-disk access** — `open_device` is `#[cfg(unix)]` (`raw.rs:79`) on a declared Windows host, so `SourceKind::PhysicalDisk` is unconstructible there.
9. **E01/EWF** — absent, but **deliberately and correctly gated** (`raw.rs:38-47`, `docs/decisions/OPEN-1-ewf-e01-dependency.md`). The specification confirms it has zero E01 format knowledge to offer (H-1).

## 4. Which parts of the current implementation are already good?

- **All offset arithmetic.** `crates/forensic-core/src/checked.rs` — integer-only, overflow-checked, and correct for non-power-of-two sector sizes. Fully satisfies FI-03 and FI-05. The specification's Phase 4 Q4 names non-power-of-two sectors "the failure mode most likely to produce plausible but wrong forensic output"; this project is immune.
- **Bounds enforcement.** Uniform across every implementation, `u64` making negative offsets unrepresentable, one shared validator (`checked.rs:64-89`), validated before allocation.
- **Read-only enforcement at four independent layers** plus a source-safety gate (`inspect_source`) the specification does not even require, including the rule that an undetermined state is never reported as read-only (`source_safety.rs:103-109`).
- **Resource management.** RAII eliminates the entire failure class behind FI-13 and specification §2.18. No work needed.
- **Byte-first read primitive.** Exactly what specification Phase 2.8 concludes is correct — and the specification had to *argue* for it because the original inverted it.
- **`BoundedReader`.** Satisfies both hard partition-reader invariants: every read bounded, parent device unreachable (`inner` private, no accessor).
- **Determinism.** No keep-alive, no background reads, no unrequested reads; plus `DeterminismKey` (`determinism.rs:23-74`), a concrete artifact the specification only gestures at.
- **`Acquisition` gap→`Partial` enforcement** (`acquisition.rs:110-127`) — the specification's "never present incomplete as complete" principle, enforced at the type level.
- **Provenance** richer than specified: profile version + hash, parser version, recovery level, ordered transformation history.
- **Unconditional whole-device fallback** (`topology.rs:64-72,121-127`) — the specification calls the original's discard-if-unrecognised behaviour "exactly backwards" for DVR evidence; this project already does the right thing.
- **The E01 gate and its decision record** — more rigorous than the specification's guidance.
- **OEM facts as versioned profile data, never Rust constants** — the specification never asks for this, and for a multi-vendor DVR tool it is more valuable than anything in specification Phase 13.

## 5. Which parts of the specification are materially better?

Four, in order:

1. **`ReadResult` with zero-filled-range reporting (FI-04).** Decisively better, and the only gap that can support a *wrong* forensic conclusion. A sparse hole, a blank recording and an unreadable sector are currently indistinguishable.
2. **Geometry with provenance (FI-07, §13.4).** Sector size as tagged, discovered data with the specification's corrected precedence (`OperatorDeclared > Measured > DecodedFromContainer > InferredFromExternalLog > Assumed`), plus explicit tail bytes.
3. **Partition-layer completeness (§13.5, §13.6).** Findings instead of silent dropping; clamp-with-record instead of discard; overlap detection; correct full GPT; EBR with depth and cycle limits.
4. **Range-set algebra and the recording×unreadable cross-check (§13.7, Phase 9.9).**

Also better, lower priority: retry policy (once physical-disk support exists), extent maps, the one-gateway platform isolation, and the recording fake gateway for tests.

**Where the specification is not better:** overflow and bounds safety, resource management, read-only enforcement, and determinism — the current implementation is ahead on all four. And its inclusive `ByteRange` is actively worse for this codebase than the existing half-open `Region`.

## 6. Is the specification compatible with the current project?

**PARTIALLY COMPATIBLE.**

- **Interfaces: incompatible.** They are C# types. There is nothing to coexist with.
- **Requirements: compatible, and mostly additively.** Rust's defaulted trait methods let geometry, sector reads and detailed read outcomes all be added without forcing any implementor to change. That is the single biggest factor making incremental adoption realistic.
- **One genuine type conflict:** the specification's inclusive `ByteRange` versus the project's half-open `Region` (`region.rs:41-47,79-88,141-147`). Mixing them produces one-byte errors that compile, pass tests, and reach court-facing output. Resolution: keep `Region`, reject the specification's inclusive model. The specification's own §9.2 marks that inclusivity as `[INFERRED]`, not confirmed.
- **One product decision required:** the specification's degraded mode would refuse sector operations when no sector size is available — which is every plain `.raw` file, the normal case here.

## 7. Would adopting it break existing parsers?

**Not if adopted additively. Yes, if adopted literally.**

All seven parsers use only `len()`, `read_at()` and `read_exact_at()`, and all read **image-absolute byte offsets** (`hikvision:45`; `uniview:45,78,84`; `dahua:111,149,258`; `honeywell:45`; `tplink:340`). So:

- **Safe (no parser changes):** read-outcome as a new defaulted method, geometry, `read_sectors`, findings, `RangeSet`, extent maps, retry, platform gateway.
- **Breaks all seven:** changing `read_at`'s signature directly (BC-1) — avoidable via the two-phase additive route. Full typed address spaces (BC-2) — VERY HIGH cost, avoidable via the narrow reader-level fix.
- **Dangerous if done carelessly:** loosening `read_exact_at` (BC-8). Parsers guard on `if let Ok(buf) = ...`; if a partial buffer became `Ok`, all seven would parse substituted zeros as real data. **Leave it strict.**
- **Breaks two parsers:** removing the `unwrap_or(512)` sector-size defaults (BC-5).
- **Breaks one detector and one test:** all-schemes partition reporting (BC-4) — `detectors/tplink.rs:41`, `tplink_sample_raw_test.rs:33`.

**A pre-existing defect worth naming:** `recognize_candidate` is always called with a `BoundedReader` (`levels.rs:225,258`; `validation.rs:51`) while parsers read absolute offsets. The specification does not cause this — it would **fix** it. Practical severity today is low because the mismatch yields false negatives rather than wrong attributions, but that is accident, not design.

## 8. Can it be introduced incrementally?

**Yes** — provided three rules hold: every change is additive-first (new defaulted trait methods, new types beside old ones); `read_exact_at` keeps its strict contract; and `Region` stays half-open.

Of ten identified breaking changes, five are LOW, four MEDIUM, and one VERY HIGH — and the VERY HIGH one (typed address spaces) is avoidable by a narrower fix that addresses the actual defect. **Option A — keep the current layer and import specification requirements in a deliberate order — is the recommended strategy.** Replacement (Option B) is rejected because it would require changing `read_at` and `Region` simultaneously across 9 crates and 7 parsers, and would risk losing capabilities the specification does not specify: `WriteGuard`, `inspect_source`, OEM-facts-as-data, `DeterminismKey`, and RAII safety.

## 9. What should be implemented first?

**Stage 0 (immediate, zero risk): make the documentation honest.** Mark `TopologyType::Gpt` as reserved-and-unimplemented (`topology.rs:23`), correct the sparse claim at `lib.rs:23` that `raw.rs:126-144` cannot deliver, mark `ScanReport.skipped_ranges` as reserved (`scanner.rs:58,131`), and record that physical-disk and mmap support are Unix-only. A forensic type must not imply a capability it lacks.

**Then Stage 1: the `RangeSet`** — immutable range-set algebra over `Region`'s existing half-open semantics. It is chosen first among code changes because it has zero dependencies, is purely additive, is fully specified (the specification gives complete pseudocode for every operation including all six subtraction shapes), and is needed by three later stages. The specification's own Phase 17 moved range tracking earlier for exactly this reason: cheap to build, expensive to retrofit.

**Then Stage 2: read-outcome reporting** as a new defaulted trait method — the central forensic fix.

## 10. What should NOT be touched yet?

- **`Region`'s half-open semantics.** Load-bearing across ~20 crates; introducing an inclusive `ByteRange` beside it creates silent one-byte errors. No benefit, serious risk.
- **`read_at`'s signature.** Use the additive defaulted-method route; retire the old method only after every caller has migrated.
- **`read_exact_at`'s strict contract.** Its all-or-nothing behaviour is a safety feature protecting all seven parsers.
- **Full typed address spaces.** VERY HIGH cost; the narrow reader-level fix addresses the real defect.
- **The E01 gate.** Correct, better-documented than the specification's guidance, and the specification has nothing to contribute (H-1).
- **RAII / resource management.** The specification's FI-13 disciplines are for a GC language.
- **The `checked` arithmetic helpers.** Already exceed the specification.
- **`inspect_source` / source-safety policy.** The specification is silent here, not permissive — do not weaken it while "aligning."
- **The OEM-facts-as-versioned-data architecture.** More valuable than any specification interface for this product.
- **All-schemes partition reporting.** Sequence it after GPT and EBR exist; reporting multiple schemes is useless while only one is detectable.
- **Retry.** No live use case while physical-disk support is Unix-only on a Windows host.
- **Sampled evidence fingerprint.** Adding a non-integrity hash creates exactly the confusion FI-11 warns about.
- **Degraded-mode refusal of sector operations.** Needs a product decision first — the specification's rule would disable `StorageTopologyProfiler` for every raw image.
- **Splitting `evidence-reader` into specification-shaped L0–L5 crates.** Let layering emerge as capabilities land.

## 17.1 Verdict in one paragraph

Current DataIO already provides a byte-first read-only evidence trait with no write method, universally checked integer offset arithmetic that is correct for non-power-of-two sector sizes, uniform bounds enforcement over `u64` offsets, RAII resource safety, a bounded window reader that cannot reach its parent, honest scan accounting with typed termination reasons, four-layer read-only enforcement plus a source-safety gate, byte-level provenance with profile and transformation history, acquisition-level completeness enforcement, an explicit determinism input model, and an unconditional whole-device partition fallback — several of which are stronger than the specification's own baseline, and none of which the specification would improve. The specification adds a read-outcome type that distinguishes substituted zeros from recorded zeros, sector geometry with provenance and explicit tail bytes, a complete partition layer with findings and correct GPT, reusable range-set algebra, extent-based content addressing, and a bounded retry policy. The two are compatible at the reader level and mostly additively so, because Rust's defaulted trait methods allow new capability without forcing implementor changes — but changing `read_at`'s signature would affect all seven DVR parsers, loosening `read_exact_at` would actively make them unsafe, and importing the specification's inclusive `ByteRange` beside the existing half-open `Region` would introduce silent one-byte errors across roughly twenty crates. Therefore the safest migration path is to keep the current evidence layer and import specification requirements additively in this order: first make the misleading declarations honest (notably `TopologyType::Gpt`), then build a `RangeSet` on the existing half-open `Region`, then add read-outcome reporting as a new defaulted method while leaving `read_exact_at` strict, then a findings model with MBR clamp-and-record, then provenance-tagged geometry — deferring GPT, EBR, retry, segmented images, sparse capture, Windows device access and E01 until a real case or platform requirement demands each one.

---

# Appendix A — Migration Difficulty Classification

Supplementary to §14. Classification per the audit brief's scale.

## A.1 LOW — add without changing existing APIs

| Change | Why LOW |
|---|---|
| `RangeSet` over `Region` (§11.4) | New type, zero dependencies, fully specified pseudocode. `estimate_coverage` reimplemented behind an unchanged signature. |
| Read-outcome as a **defaulted** trait method (§11.1 / Stage 2a) | Default wraps existing `read_at`. No implementor changes, no caller changes. |
| `Finding` type + `findings` field (§11.3) | All three `StorageTopology` construction sites are inside `topology.rs`. |
| MBR clamp-and-record instead of silent drop (C-1) | One conditional at `topology.rs:96-105`. |
| MBR overlap detection (C-2) | `Region::overlaps` already exists (`region.rs:63-77`), currently unused here. |
| Recording × bad-sector cross-check (§11.5, C-16) | Set intersection over existing data; `IntegrityFlag` already exists. |
| Wire `BoundedReader` to `PartitionCandidate` (§11.7) | One constructor call. |
| `Region::new` instead of struct literals in `gaps.rs` (C-10) | Three call sites. |
| Recording fake gateway (§11.11) | Test-only; trait is already trivially mockable. |
| Document `TopologyType::Gpt` as reserved (C-3) | Doc comment. |
| Document / soften the sparse claim (C-8) | Doc comment. |
| Document `skipped_ranges` as reserved (C-7) | Doc comment. |
| `ForensicError` new variants (BC-6) | Existing matches non-exhaustive (`scanner.rs:172-177`); one test assertion to update (`error.rs:196-200`). |
| `read_sectors` as a defaulted convenience | Nothing calls it today. |

## A.2 MEDIUM — introduce an adapter, or change a contained contract

| Change | Why MEDIUM |
|---|---|
| Geometry model + wiring (§11.2, C-4, BC-5) | New type is additive, but replacing `unwrap_or(512)` touches 4 call sites, 2 parsers, and test expectations at `phase2_detection.rs:226` / `tplink_sample_raw_test.rs:33`. Requires a product decision first. |
| Short-read vs out-of-range split (C-5) | Changes `TerminationReason` outcomes that `HashingService` maps to `Review`/`Pass` (`hashing/src/lib.rs:82-104`). |
| Override read-outcome in `RawReader`/`BoundedReader` (Stage 2b) | Two implementors plus migrating `RegionScanner` and `recovery::read_bounded_window`. |
| GPT implementation (§11.6) | Substantial new parsing (header validation, both CRC32s, backup header, GUIDs, UTF-16 names) plus a synthetic-structure test builder. Contained to `topology.rs`. |
| Extended/EBR chains (§11.6) | New recursion with depth and cycle limits. Contained. |
| All-schemes partition reporting (BC-4) | Breaks `detectors/tplink.rs:41` and `tplink_sample_raw_test.rs:33`. Softenable by keeping `topology_type` as the recommended scheme alongside a new `schemes` list. |
| Narrow address-space fix (§11.8, C-9) | Touches the `Parser` trait and all seven implementations, but shallowly. |
| Extent map / content addressing (§11.10) | Purely additive but substantial new surface; depends on Stage 2. |
| Retry policy (§11.12) | Needs the retryable/non-retryable split first; opt-in at construction. |
| Segmented raw images (§11.13) | New source type plus a structured locator (`source_path` is display-only). |
| `ReadOnlyMmap` Windows support (C-13) | Platform work confined to one module. |
| Positional reads replacing `Mutex<File>` (C-14) | Two platform paths; contained to `raw.rs`. |

## A.3 HIGH — change read semantics used by multiple parsers

| Change | Why HIGH |
|---|---|
| Changing `read_at`'s return type directly (BC-1) | 2 implementors, ~6 mocks, callers across 9 crates and 7 parsers, in one commit. **Avoidable** via A.1's defaulted-method route. |
| Loosening `read_exact_at` (BC-8) | Would silently convert a safe API into an unsafe one for all seven parsers. **Should not be done** (N-3). |
| Windows physical-disk path + platform gateway (§11.9, C-12) | New platform surface: device enumeration, handle open with narrowest sharing, geometry and length queries, positional reads, error-code propagation. HIGH by volume, not by blast radius — `RawReader`'s public API need not change. |
| Sparse record-on-read capture (§11.14) | New container format (read and write), a decorator, `NotRecorded` plumbing, and a format-compatibility decision. |

## A.4 VERY HIGH — replace a fundamental model

| Change | Why VERY HIGH |
|---|---|
| Full typed address spaces across all offsets (BC-2) | Would change `Region` or introduce parallel types across ~20 crates: provenance, acquisition, recovery candidates, recordings, timeline events, scan reports, partition candidates. **Avoid** — the narrow fix (A.2) addresses the real defect. |
| Introducing inclusive `ByteRange` beside half-open `Region` (BC-3) | MEDIUM to implement, VERY HIGH to make safe: errors compile, pass tests, and reach reports. **Do not do this** (N-1). |
| Replacing `evidence-reader` with a specification-shaped L0–L5 stack (Option B) | Two evidence abstractions in one workspace, doubled mocks, `Region`/`ByteRange` conversion at every seam, and a real risk of losing capabilities the specification does not specify. **Rejected** (§14.0). |

---

# Appendix B — Is the Specification Realistic?

Supplementary to §14. Specification requirements that cannot currently be implemented safely, classified per the audit brief.

## B.1 BLOCKED BY REVERSE ENGINEERING

| Requirement | Detail |
|---|---|
| **E01/EWF format support** | Specification H-1 states the original delegated E01 entirely to a third-party library, so the reverse engineering produced **zero** format knowledge: "Phase 5 cannot start from `DATAIO_REVERSE_ENGINEERING_RAW.md`." The project's own `docs/decisions/OPEN-1` reaches the same conclusion independently and prohibits hand-rolling a parser. **Aligned; no action.** |
| **Container detection from file extension** | Specification H-2: all string literals in the original were encrypted, so the extension→container mapping is `[UNKNOWN]` and cannot be reproduced. The project's transparent extension inference (`raw.rs:63-71`) is a reasonable substitute. |
| **GPT header field at +40; the 12-entry cap** | Specification H-5: semantics `[UNKNOWN]`. The specification's own resolution — implement the real GPT format instead — is correct, and it means results will differ from the original on some disks. That divergence is desirable and should be documented. |
| **Forensic-imager log parsing for geometry** | Specification M-11: all delimiters and field markers `[UNKNOWN]` across four imager dialects. Not implementable. Operator-declared geometry (§11.2) covers the need. |
| **Sparse format reserved field; version 1.0.1** | Specification M-6: the 16 `0xFF` bytes at header offset 48 have `[UNKNOWN]` meaning, and a `1.0.1` version constant appears in an uncalled member while the writer emits `1.0.0`. If a 1.0.1 variant exists in the wild, its layout is unknown. Argues for writing our own versioned format rather than the original's (§11.14). |
| **LVM2 extent arithmetic** | Specification L-15: the `8192` and `512` multipliers are unexplained and the parsed `Extent_size` is unused. The specification defers LVM2; agreed. |
| **`SdrImage` index format** | Specification L-16: all delimiters `[UNKNOWN]`. Specification says do not implement. |
| **Middle-segment validation behaviour** | Specification M-7: the original never verified that middle segments match the first, and whether irregular sets exist in practice is `[UNKNOWN]`. Validating them (the specification's recommendation) may reject images the original accepted — a deliberate, documentable divergence. |
| **Whether the original's silent zero-filling is depended upon** | Specification H-4: `[UNKNOWN]`. Not relevant here — this project has no upstream consumer of that behaviour to preserve. |

## B.2 BLOCKED BY CURRENT ARCHITECTURE

| Requirement | Detail |
|---|---|
| **All ten specification interfaces as declared** | They are C# interfaces using `Span<byte>`, `IDisposable`, `IProperty<T>` and DI-resolved factories. Structurally unimplementable in Rust as written. Their *requirements* are implementable; their *declarations* are not. |
| **Inclusive `ByteRange`** | Blocked by `Region`'s established half-open semantics across ~20 crates (`region.rs:41-47,79-88,141-147`). Implementable in principle; **should not be**, because the failure mode is silent (BC-3, H-R2). |
| **Degraded mode refusing sector operations when no sector size is known** | Would disable `StorageTopologyProfiler` for every plain `.raw` image — the normal input for this project, since a raw file carries no intrinsic sector size. The specification's rule assumes an operator-declared geometry workflow that does not exist here yet. **Needs a product decision, not a mechanical port** (N-13). |
| **`IDisposable` ownership flags on wrappers** | Rust borrowing (`BoundedReader<'a>` holding `&'a dyn EvidenceReader`) already expresses non-ownership. Implementing the specification's flags would add complexity for zero safety gain. |
| **`Failed` folded into the read outcome enum** | A C# idiom for a language without `Result`. Rust convention is `Result<Outcome, Error>`. Adopting the specification's shape literally would fight the language. |
| **Full typed address spaces** | Not blocked outright, but VERY HIGH cost against `Region`'s pervasiveness (BC-2). The narrow reader-level fix achieves the forensically important part. |

## B.3 BLOCKED BY EXTERNAL DEPENDENCY

| Requirement | Detail |
|---|---|
| **E01/EWF reader** | Requires either an independent EWF specification or a licensed library. `docs/decisions/OPEN-1` selects `ewf` 0.4.10 (Apache-2.0) as the preferred candidate, verifies its license, and **defers adoption** pending a six-item verification gate: write-surface API audit, segmented fixture, compressed fixture with the cache pinned to the OPEN-2 window budget, corrupt/truncated fixtures mapping onto `ForensicError`, differential hash check against libewf or The Sleuth Kit, and `error2` acquisition-error plumbing into `Acquisition.bad_sector_ranges`. Also noted: the crate is pre-1.0 with a single maintainer, and `ewf-image` was rejected because it can *write* E01. |
| **Windows physical-disk geometry queries** | Requires platform APIs the project does not currently call. Not blocked by anything external — just unimplemented (`raw.rs:79` is `#[cfg(unix)]`). |
| **Property-based testing** | No `proptest`/`quickcheck` in `Cargo.toml`. A dependency decision, trivially unblockable. |
| **Real-evidence smoke corpus (512e, 4Kn, E01, segmented set)** | Requires physical media the project does not have. `validation_corpus/` and `.fixture_build/` provide synthetic and real-codec coverage but no device-geometry variety. |

## B.4 SPECIFICATION GAP

Items where the specification does not say enough to implement from.

| Gap | Detail |
|---|---|
| **`ReadResult` zero-fill semantics at sub-sector granularity** | The specification requires `ZeroFilledRanges` but does not define behaviour when a zero-filled range partially overlaps a requested range within one sector, nor whether `BytesRead` counts substituted zeros. Given `Complete ⟺ BytesRead == requested && ZeroFilledRanges.IsEmpty`, the two fields can be made inconsistent. Must be pinned down before implementing (§11.1). |
| **Geometry precedence conflict resolution** | The specification defines the precedence order and requires conflicting claims be retained, but does not say whether a conflict should downgrade confidence, raise a finding severity, or block sector operations. Left to implementer judgement. |
| **`SectorSizeProvenance::Assumed` reporting obligation** | The specification says an `Assumed` value "must be visible in every report" but does not specify the mechanism or what a consumer should do with it. |
| **"All schemes" recommendation logic** | `PartitionTableSet.Recommended` must carry "the reason," but the specification does not define how to choose between a valid MBR and a valid GPT on a hybrid disk, which is precisely the case the feature exists for. |
| **Extent-map merge maximum** | The specification requires "one predicate… with a documented maximum merged length" but does not supply the maximum (it records the original's 1 GiB cap as a `[CONFIRMED]` observation, not a recommendation). |
| **Retry backoff schedule** | `IRetryPolicy.Delay(attempt)` is declared with no suggested schedule or bounds. `MaxAttempts` likewise unspecified (the original's 5 is recorded as observation, not recommendation). |
| **Recording-container format compatibility** | The specification documents the original's sparse format completely and recommends reading it while writing "our own versioned format that adds a per-block integrity hash and an explicit recorded-range index" — without specifying either addition. |
| **`Findings` severity model** | Findings are required throughout (geometry, partitions, extents) with no severity taxonomy, no codes, and no guidance on which findings should block an operation versus annotate it. |
| **Degraded-mode operation set** | The specification says sector-addressed and partition-level operations are "unavailable" in degraded mode but does not enumerate which operations those are, or whether whole-device byte analysis and carving remain available (they presumably should). |
| **Address-space tag representation** | `ByteOffset` is repeatedly described as "address-space tagged" with no definition of the tag set or how a partition identity is carried (§8.7 says a partition-relative offset "carries its partition identity"; §13 does not show how). |
| **`ComputeIdentity(IdentityMode)` sampled-mode parameters** | The specification documents the original's 11-tier stride ladder as observation and recommends offering a sampled mode, without specifying the stride policy to use. |

## B.5 Realism verdict

The specification is **realistic for the parts this audit recommends adopting first**. Stages 1–5 of the migration plan (§14) depend on nothing blocked: `RangeSet` is fully specified with complete pseudocode, the read-outcome type needs one semantic clarification (B.4 row 1) that is a local decision, the findings model needs a severity taxonomy this project can define, and the geometry model needs one product decision already identified.

The specification is **not realistic for E01** — and says so itself. It is **not directly usable for its interfaces**, which are .NET. And it contains **eleven identified specification gaps** where an implementer must decide something the document leaves open; none blocks the recommended early stages, but each should be resolved deliberately and recorded in `docs/decisions/` following the project's existing `OPEN-1`/`OPEN-2` pattern rather than settled implicitly in code.

One structural observation on the specification's own realism: it is a Stage-2 document whose Phase 12–19 content is tagged `[DESIGN]` throughout — the specification authors' own proposals, not reverse-engineered fact. Roughly half its volume documents defects in an assembly this project was never derived from. **Its highest value to this project is as a requirements checklist and a catalogue of known forensic failure modes, not as a blueprint to build against.** Used that way, it is realistic and useful. Used as an implementation plan, it would mandate a rewrite that the compatibility analysis in §8 does not support.
