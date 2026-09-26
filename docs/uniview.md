# Uniview storage format — implementation notes

What the platform's Uniview support reads, how, and how sure it is of each part.

- **Code:** `crates/parsers/uniview/` (parser), `crates/detection/src/detectors/uniview.rs` (detector)
- **Profile (all offsets and values as data):** `profiles/uniview/uniview-ubifs-v1.0.toml`, version 2.1.0.
  The profile id keeps its historical `ubifs` name; the storage family is `UNIVIEW_FS`. The format is a
  proprietary SUPER / UI / DI / DATA layout, **not** UBIFS.
- **Evidence base:** a clean-room analysis of the Uniview/H3C `disktool 1.4 2011/02/11` utility
  (ARM-32 ELF, Ghidra listing). disktool is the vendor's read/display tool, not the recorder firmware,
  so it does not show how the recorder writes, deletes or frames video.
- **Status:** `Partial` for parsing, reconstruction and validation (see `apps/api/src/capability_service.rs`).
  Everything has been tested against synthetic images built from this layout, and **not yet against
  a real Uniview disk image**.

## Confidence vocabulary

Every field the parser reports carries one of these labels (`layout::Confidence`):

| Label | Meaning |
|---|---|
| **CONFIRMED** | Location, width and use shown directly by disktool instructions or constants |
| **STRONG INFERENCE** | Several code paths agree; the meaning is well supported but not stated outright |
| **TENTATIVE** | Plausible, not corroborated; never drives authoritative output |
| **UNKNOWN** | Location known, meaning not; preserved raw and never interpreted |

## Disk layout

```text
0x00000000  SUPER     0x4000 bytes            both generations
0x00004000  UI        0x10000 bytes (OLD)     /  UI-CTL 0x10000 bytes (NEW)
0x00014000  unit 1    (OLD)                   /  UI-DATA, 0x10000 per UI-DATA unit n (NEW)
0x10014000  unit 2    (OLD)                   /  unit 1 (NEW)
            ... unit stride 0x10000000 (256 MiB) ...

unit_base(u) = gen_base + (u - 1) * 0x10000000     u is 1-based
gen_base     = 0x00014000 (OLD) | 0x10014000 (NEW)
```

All offset arithmetic is unsigned 64-bit and checked. An overflowing offset is reported as an error,
never wrapped.

## Detection and generation

| Check | Rule | Confidence |
|---|---|---|
| Primary signature | u32 LE at offset 0: `0x1367` = OLD, `0x1587` = NEW | CONFIRMED (the only test disktool applies) |
| SUPER completeness | Magic present but image shorter than 0x4000 → `Insufficient` | — |
| Corroboration 1 | UI / UI-CTL u16 rewrited flag ∈ {0, 1}, and the written-unit count is within bounds | STRONG INFERENCE |
| Corroboration 2 | Unit 1's DI record count ≤ 0x4000 | CONFIRMED (disktool's own check) |
| Corroboration 3 | Unit 1's DI record 1 has a calendar-valid timestamp and SPtoI ≥ 16 | STRONG INFERENCE |

Corroboration is **never required**. A passing check adds a non-exclusive evidence item. A failing
check adds a warning, and the evidence is reported as a *degraded* Uniview filesystem, never as
"not Uniview".

## Packed 5-byte timestamp (all structures)

```text
year   = b0 | ((b1 & 0x0F) << 8)        month  = b1 >> 4
day    = b2 & 0x1F                      hour   = ((b3 & 0x03) << 3) | (b2 >> 5)
minute = b3 >> 2                        second = b4 & 0x3F
```

- **CONFIRMED.** The value is recorder wall-clock time, **not** unix time.
- It is reported as native digits plus a UTC reading, with the timezone marked **Unknown**; no offset
  is stored anywhere on disk.
- Invalid values are reported as invalid, never adjusted. Values outside 2000–2100 are reported as
  *implausible*, never dropped.

## SUPER (0x0, 0x4000)

| Offset | Size | Field | Confidence |
|---|---|---|---|
| +0x00 | 4 | Magic (u32 LE) | CONFIRMED |
| +0x14 | 5 | "Last write super data time" | CONFIRMED |
| +0x1C | 5 | "Start storage time" | CONFIRMED |
| +0x2C | 0x40 | EcPortId: opaque bytes (e.g. `0@EC1001`), no format enforced | CONFIRMED location / UNKNOWN grammar |
| everything else | — | Not referenced by disktool | UNKNOWN |

## UI (OLD) and UI-CTL (NEW), at 0x4000, 0x10000 bytes

| | OLD UI | NEW UI-CTL | Confidence |
|---|---|---|---|
| +0x00 | u32 raw current-unit value | u32 raw current-unit value | CONFIRMED location |
| Written unit count | `raw − 1` | `raw + 1` | CONFIRMED (disktool FLOW) |
| +0x04 | u16, meaning unknown | u32 count base: UI-CTL entries = `(v >> 13) + 1` | UNKNOWN / CONFIRMED arithmetic |
| Rewrited flag | **u16** at +0x06 | **u16** at +0x0C | CONFIRMED (`ldrh`) |
| Entry table | Unit u's entry at `UI + (u + 1) * 8` | Entries from +0x10, numbered 0 .. count−1 | CONFIRMED addressing |

Raw values are always kept as stored. The ±1 adjustments are applied only where the vendor applies
them.

The rewrited flag means the storage ring has wrapped at least once. It does **not** say which
recordings were overwritten.

## UI-DATA (NEW only), at `0x14000 + n * 0x10000`

- Each UI-DATA unit holds 0x2000 8-byte entries; up to 4096 UI-DATA units fit before the NEW unit base.
- UI-DATA is one global array: storage unit u's entry is global index `u − 1`, i.e. UI-DATA unit
  `(u − 1) >> 13`, slot `(u − 1) & 0x1FFF`. **CONFIRMED** (disktool's export path).
- disktool's display caps the index at UI-CTL +0x04 and, when the rewrited flag is clear, also at the
  current-unit value. The arithmetic is confirmed; what the cap means is **TENTATIVE**.

## 8-byte time-index entry (UI, UI-CTL, UI-DATA)

```text
bytes 0..4  packed timestamp                                   CONFIRMED
lock        = (b5 << 2) | (b4 >> 6) | (b6 << 10) | (b7 << 18)  26 bits: extraction CONFIRMED, meaning UNKNOWN
```

Each storage unit has exactly one such entry, attached to the unit as `UnitRecord::time_index`.
**`lock` is not a channel number** and is never interpreted.

## DI, at the start of each unit, 0x40000 bytes of 16-byte records

| Record / offset | Field | Confidence |
|---|---|---|
| Record 0, +0x00 | u32 per-unit write-data byte count (FLOW input) | CONFIRMED |
| Record 0, +0x04 | u32 record count, **including record 0** | CONFIRMED (disktool loop) |
| Record 0, +0x08..+0x0F | Unknown | UNKNOWN |
| Records 1 .. count−1 | DI entries, at `DI + r * 0x10` | CONFIRMED |

- A count of **0x4000 is valid**: 0x4000 × 16 = 0x40000, the whole DI region.
- A count **above 0x4000** makes disktool print "data index head abnormal" and continue. The parser does
  the same: it reports `CountAbnormal`, reads every non-blank record the region holds, and marks the
  unit for review.

Each DI entry:

| Offset | Field | Confidence |
|---|---|---|
| +0x00..+0x04 | Packed timestamp | CONFIRMED |
| +0x05 + +0x06[1:0] | Field A = `b5 \| ((b6 & 3) << 8)`, 10 bits | CONFIRMED extraction / UNKNOWN meaning (never used as a channel) |
| +0x06[7:2] + +0x07 | **SPtoI** = `(b7 << 6) \| (b6 >> 2)`, 14 bits: a DATA **block index** | CONFIRMED |
| +0x08..+0x0E | Unknown | UNKNOWN |
| +0x0F | Printed by disktool, meaning unknown | UNKNOWN |

## SPtoI → DATA

```text
data_offset = unit_base(u) + SPtoI * 0x4000        16 KiB blocks, SPtoI < 0x4000
```

- **CONFIRMED** by two independent paths in disktool: extraction addressing, and the in-place re-basing
  of SPtoI when exporting.
- An SPtoI below 16 lands inside the DI region and is flagged as invalid.
- The extent of entry i is `[SPtoI(i), SPtoI(i+1))`, which is how disktool sizes its own extraction.
  It is labelled a storage-span inference, not a recording boundary.
- The last entry of a unit, a wraparound, a duplicate SPtoI or an unusable neighbour each claim only the
  single block their SPtoI selects, and the reason is recorded.

DATA is extracted as **raw bytes**: read-only, bounds-checked, at exact offsets, with SHA-256 per
region and over the whole. **No codec, container or framing is claimed.** The recovery engine's own
codec classifier is a separate signal.

## FLOW

There is no FLOW region on disk. Two figures are reported:

| Figure | Definition |
|---|---|
| **Vendor FLOW** (`vendor_flow`) | Exactly as disktool computes it: units 1..N, N from UI / UI-CTL (OLD `raw − 1`, NEW `raw + 1`); each DI +0x00 counter sign-extended from 32 bits and summed. **Refused when the rewrited flag is non-zero**. Stops at the first declared unit that is missing from the image. |
| **Scan total** (`scan_total_write_bytes`) | The sum of DI +0x00 over every unit found in the image. A filesystem-scan statistic, **not** the vendor result. |

## Recording index and recovery

- **Index.** One entry per storage unit, id `unv:u<unit>`, whose physical ranges are the merged DI spans.
  The index is **never authoritative**: DI has no checksum and extents are inferred, so absence from the
  index is not evidence of absence. The generic engine therefore never reports unreferenced DATA as
  *orphaned*.
- **Recovery.** Results are grouped by basis:

| Basis | What it is | Confidence |
|---|---|---|
| INDEXED | DI entry → SPtoI → DATA block(s) | Block: CONFIRMED; multi-block extent: STRONG INFERENCE |
| STRUCTURAL | DATA ranges in valid unit geometry that no DI entry references | Content UNKNOWN |
| HEURISTIC | Residual DI records beyond the declared count that still decode | TENTATIVE |

No Uniview deletion structure is known. Nothing is ever reported as *deleted*: unreferenced DATA is
*unreferenced*, and a residual record is *residue*.

## disktool `.h3crd` exports

disktool's `-r data` command writes a `.h3crd` file:

```text
0x00000  0x68-byte header: "iVS8000@huawei-3com" (20 bytes, NUL-terminated) at +0x00,
         constant 0x56B4C275 at +0x64
0x04000  UI copy: [+0x00] = 2, the unit's 8-byte time-index entry at +0x10
0x14000  DI copy: [+0x04] = number of copied entries; SPtoI re-based to start at 16
0x54000  the copied DATA blocks, contiguous
```

- The file is an OLD-shaped single-unit image, so it goes through the normal parser.
- The export tag is checked **only when no SUPER magic matches**, so raw-disk detection is unchanged.
- Two export-specific rules apply: the DI count is the number of copied entries, and the last entry's
  extent runs to the end of the copied DATA.
- Every report labels the source "Uniview disktool .h3crd export (normalized artifact, not an original
  physical disk layout)".
- The tag and constant are CONFIRMED. The constant's offset (+0x64) is a STRONG INFERENCE from the
  export routine's stack layout, so it is used only as corroboration.

## Known limitations (not resolved by the available evidence)

- How a time-index entry maps to an individual DI entry. Each unit's own entry is located, but index
  groups are per storage unit, not per recording.
- What `lock` means.
- What DI field A means. No channel is derived from any field.
- What the DI header and entry bytes +0x08..+0x0F mean.
- What the current-unit value and UI-CTL +0x04 mean beyond the vendor arithmetic.
- The DATA codec, container and framing.
- How the recorder deletes data, whether deletion clears metadata, and which recordings were
  overwritten when the disk wrapped.
- No SUPER, UI or DI checksum is known.

Resolving these needs the recorder or storage-service firmware (the write path), or real disk images.

## Next validation steps

1. Run the parser against a real OLD and a real NEW Uniview disk image. Confirm UI at 0x4000, DI at
   both bases, timestamps against known recordings, and the per-unit time-index entries.
2. Run it against a real disktool `.h3crd` export. Confirm the +0x64 constant offset and the DI count
   semantics.
3. Carve one real DATA block to identify the payload framing.
