# OPEN-2 — Maximum read-window / bounded-buffer default

| | |
|---|---|
| **Status** | Decided — **provisional engineering configuration** (not a validated forensic constant) |
| **Task** | tasks.md task 2 (OPEN-2). Consumed by task 17 (P1-013 — bounded `read_at` + `RegionScanner`) |
| **Requirements** | Req 8.2 (bounded buffers; never load the whole image), Req 8.3 (no allocation proportional to total image size) |
| **Design** | Cross-Cutting → bounded memory; Bounded Scanning; Component 1 (Evidence Reader); Open Items to Confirm item 2 |
| **Configuration** | `config/reader.toml` → `[read_window]` |

## Decision

| Key | Value | Allowed range | Meaning |
|---|---|---|---|
| `read_window.max_bytes` | **16 MiB** (`16777216`) | 8 MiB – 64 MiB (`8388608`–`67108864`) | Ceiling on any single evidence read buffer or scan window |
| `read_window.min_bytes` | 4 KiB (`4096`) | 512 B – 16 MiB | Floor for a caller-supplied window |

The value lives in the data file `config/reader.toml` (version `reader-1.0.0`, `status = "provisional"`).
It is **not** a Rust source constant, and it must not be duplicated as one — design.md is
explicit that no authoritative numeric constant is hard-coded in source. The allowed range
is stored alongside the value so the loader can reject out-of-range configuration rather
than clamping silently.

The 8–64 MiB range is not invented here: design.md Component 1 proposes it ("default e.g.
8–64 MiB"). This note picks a specific point inside that proposed range and records why.

## Why 16 MiB

1. **Cancellation latency is bounded by window size.** Progress and cancellation are honored
   at window boundaries (design: progress/cancel apply to long-running operations). At
   100–150 MB/s sustained HDD throughput a 16 MiB window is roughly 0.11–0.17 s, so a cancel
   request is observed quickly. A 64 MiB default pushes worst-case cancel latency past half a
   second on healthy media, and much further on a degraded drive with retries — which is
   exactly the media a forensic tool is pointed at.
2. **Peak memory is window × concurrency, not window.** Five OEM detectors run in parallel
   over one reader (Req 9.1) and `RegionScanner` is `Sync`-friendly so Rayon can scan
   disjoint regions concurrently. On an 8-worker workstation 16 MiB yields ~128 MiB of
   scan buffers; 64 MiB would yield ~512 MiB for no measured benefit.
3. **Large enough that syscall overhead stops mattering.** Sequential read cost is dominated
   by media transfer well before 16 MiB, so the top of the range buys throughput that the
   device cannot supply.
4. **Alignment-friendly.** 16 MiB is a whole multiple of 512 B (32768 sectors), 4 KiB
   (4096 pages), and of common DVR allocation granularities, so window boundaries can be
   aligned without partial-sector arithmetic.
5. **Headroom in both directions.** Sitting low-middle in the sanctioned range leaves room
   to tune up for large sequential sweeps or down for constrained hosts without leaving the
   documented range or amending this note.

## Why this is provisional engineering configuration, not a validated forensic constant

- **No measurement basis yet.** The rationale above is engineering reasoning about syscall
  cost, cancellation latency, and concurrency arithmetic on a workstation. No benchmark
  against real multi-terabyte DVR media has been run at the time of this decision. Calling
  16 MiB "correct" would assert something not yet measured.
- **It carries no forensic meaning.** The value describes how the platform reads, not what
  the evidence contains. It is not an OEM signature, offset, or structural fact, so it never
  enters an `OEM_Profile` and never carries an `Evidence_Status`.
- **Forensic results must be invariant to it.** The design's determinism key is: evidence
  bytes + `source_hash`, `OEM_Profile` version + hash, `ConfidenceConfig` version + hash,
  recovery configuration, and parser/component versions. Reader window configuration is
  deliberately **absent** from that key, so a `Forensic_Result` must be byte-identical for
  every value in the allowed range. If a detection, parse, or recovery result changes when
  the window changes, that is a reader/scanner defect — most likely mishandling of a
  structure that straddles a window boundary — and not a configuration matter.
- **Revisit when any of these happen:** benchmarking on real multi-TB media (task 19) shows
  a different sweet spot; profiling shows memory-mapped reads change the tradeoff; sustained
  scans on degraded media show cancellation latency is still too high; or parallel scanning
  concurrency grows enough that window × workers becomes the binding constraint. A revision
  updates `config/reader.toml`, bumps `config_version`, and amends this note.

## Where the configuration lives, and why there

`config/reader.toml`, with `config/README.md` describing the directory.

`config/` is a sibling of `profiles/` and carries the same "data, not code" rule, split by
what the data is about:

- `profiles/` — OEM-specific knowledge (signatures, offsets, structures, per-signature
  confidence weights), versioned per OEM.
- `config/` — uniform platform values applied identically across OEMs.

The design already requires this split for the Confidence_Engine, which reads OEM weights
from versioned `OEM_Profile` data and classification policy from versioned
`ConfidenceConfig` data. Reader bounds are the same kind of value: uniform, non-OEM,
versioned, and not a forensic fact. `design.md` → "Workspace Layout" does not yet list
`config/`; it should be read as extended by this note. OPEN-4's `ConfidenceConfig` and
`RecoveryBounds` values belong in the same directory as separate versioned files; this note
does not decide them.

## How task 17 (P1-013) consumes it

`RegionScanner` takes explicit `start`, `length`, `window_size`, `alignment`, cancellation,
progress, and candidate limits. The OPEN-2 configuration supplies the window bounds:

1. **Load, don't hard-code.** The reader reads `read_window.max_bytes` from
   `config/reader.toml`. No `const MAX_WINDOW` in Rust source, in the reader or in tests.
2. **`max_bytes` is a ceiling, applied per operation.** Every `read_at` buffer and every
   scan window must be `<= max_bytes`. Buffer size never derives from `reader.len()`
   (Req 8.3).
3. **A caller may request a smaller window.** An explicit `window_size` is valid when
   `min_bytes <= window_size <= max_bytes`. Values outside that range are rejected with a
   defined `ForensicError`, never silently clamped. Rejecting `0` is what keeps a scan
   terminating.
4. **Short regions allocate short.** A scan allocates `min(window_size, remaining_region_len)`,
   so small fixtures need no configuration change and no special-casing.
5. **Concurrency is the caller's budget.** The ceiling is per operation. Orchestration that
   runs N concurrent scans owns the N × window peak; the reader does not police it.
6. **Window exhaustion is not truncation.** Reaching the end of a window is ordinary
   iteration. A scan that stops before covering its requested range records the searched
   range, searched bytes, skipped ranges, and a termination reason, and its validation is
   `REVIEW` (Bounded Scanning) — separately from the sparse-hole versus end-of-source
   distinction in Req 8.10.
7. **Tests assert against the configured value, not against 16 MiB.** Property 2 (bounded
   memory) holds that peak memory stays under the configured cap regardless of image size,
   so the assertion must read the cap from configuration. That keeps the property valid for
   any in-range value and prevents this decision from being frozen into test code.

Streaming hashing (Req 5.7) and bounded recovery carving inherit the same ceiling; neither
introduces its own read-window default.

## Not decided here

Scan `alignment` defaults, candidate limits and other `RecoveryBounds` values (OPEN-4),
memory-map thresholds, and E01 handling (OPEN-1). This note decides the read-window bound
and its home, nothing else. No reader behavior is implemented by this task.
