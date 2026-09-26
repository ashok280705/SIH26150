# Universal parser architecture

How an OEM parser plugs into this platform, what the universal layer promises it, and what it
must promise back.

The short version: **the `Parser` trait was audited and kept.** It was found sufficient for
universal recovery, and a second interface would have been architecture for its own sake. What
was added is an executable definition of compliance.

---

## 1. The boundary

```text
      OEM-SPECIFIC                    │            UNIVERSAL
  ────────────────────────────────────┼──────────────────────────────────────
  filesystem interpretation           │  range algebra (RangeSet)
  storage geometry decoding           │  claimed vs unclaimed comparison
  index/table walking                 │  bounded reads, budgets, cancellation
  container framing                   │  codec classification from bytes
  timestamp encoding                  │  state classification
  chain reconstruction                │  fragment and temporal correlation
                                      │  provenance
  ────────────────────────────────────┼──────────────────────────────────────
  crates/parsers/<oem>                │  crates/recovery, crates/parsers-core
```

The contract between the two halves is four types in `parsers-core::storage`:
`StorageGeometry`, `RecordingIndex`, `IndexedRecording` and `ContainerRecord`. Every one is
plain data — `Region`s, `Option`s and `BTreeMap<String, String>` for anything OEM-specific.

**The generic layer never parses an OEM format**, and **the parser never decides a data
state**. That split is what makes the engine OEM-independent: `crates/recovery/src` contains no
OEM name at all, and adding an OEM adds no branch to it.

---

## 2. The trait, and why it was kept

`parsers_core::Parser` has eleven methods. Six are the original parsing surface
(`parse_filesystem`, `parse_metadata`, `parse_recordings`, `extract_timeline_events`,
`validate_structure`, `recognize_candidate`); three are the storage-interpretation surface the
recovery engine consumes (`storage_geometry`, `recording_index`,
`scan_region_for_candidates`); two are identity (`id`, `version`).

The audit asked whether the standardized output can represent each concept the universal layer
needs. It can:

| Concept | Where it lives | Unknown is expressible |
|---|---|---|
| `DeviceIdentity` | `StorageGeometry::oem_fields` (verbatim strings) | yes — absent key |
| `StorageGeometry` | `StorageGeometry` | yes — `Ok(None)`, or `None` per field |
| `FilesystemMetadata` | `StorageGeometry::metadata_region` + `oem_fields` | yes |
| `RecordingIndex` | `RecordingIndex` | yes — `Ok(None)` or `IndexAuthority::NotFound` |
| `RecordingMetadata` | `IndexedRecording` | yes — every field `Option` |
| `MediaReference` | `IndexedRecording::physical_regions` / `payload_regions` | yes — empty `payload_regions` |
| `Timestamp` | `start_time_unix` / `end_time_unix` | yes — `None` |
| `Channel` | `channel` | yes — `None`, never 0 |
| `Codec` | `codec_hint` | yes — `None`, never a guess |
| `Container` | `ContainerRecord::frame_type` + `oem_metadata` | yes |
| `DeletionState` | `AllocationEvidence` | yes — `Unknown` is a variant |
| `EvidenceReference` | absolute `Region`s + `ValidationState` on every structure | yes |

Three things were therefore **not** added, despite being on the candidate list:

* **`ParserCapabilities` as a trait method.** A parser declaring its own capabilities would be
  a statement of intent. What the engine needs is what the parser *actually established on this
  evidence*, which it can read from the parser's return values. Capability assessment is
  therefore derived at runtime in `recovery::capabilities`, not declared. A parser whose index
  region is destroyed on this particular disk correctly reports no index capability for this
  run, which a declared method could not express.
* **`NormalizedRecording`.** `IndexedRecording` already is one.
* **`RecoveryHints`.** Every hint considered was either already derivable from geometry and
  index, or would have been the parser telling the engine what to conclude — which is exactly
  the coupling the split exists to prevent.

---

## 3. Unknown, and the rule against fabrication

> Missing information must result in reduced evidence, never invented information.

Concretely, and enforced by the contract harness:

| Situation | Correct | Forbidden |
|---|---|---|
| No channel in the structure | `channel: None` | `Some(0)` |
| No timestamp in the structure | `start_time_unix: None` | `Some(0)` (the epoch) |
| No codec label | `codec_hint: None` | `Some("H264")` inferred from payload bytes |
| Framing not separable | `payload_regions: vec![]` | a guessed payload offset |
| No index reader | `Ok(None)` | an empty authoritative index |
| Index partly unreadable | `IndexAuthority::Partial { reason }` | `Authoritative` |
| No allocation marker | `AllocationEvidence::Unknown` | `Allocated` |
| Length field implausible | non-`Pass` evidence, or omit the record | truncate it to fit |

`codec_hint` deserves emphasis: it is the codec *as the OEM structure labels it*. Codec
identity derived from stream bytes is a separate downstream signal produced by
`VideoReconstructor::classify_codec`, and the two are never conflated — codec identity has
never been evidence of OEM identity.

---

## 4. The executable contract

`parsers_core::contract::run_parser_contract` is the single definition of compliance. Every
parser is run against the same checks on the same evidence shapes.

```text
  run_parser_contract(parser, reader, profile) -> ContractReport
     │
     ├─ identity      id and version are non-empty (a result must be tied to its code)
     │
     ├─ geometry      regions in bounds · size not overstated · no zero block/sector size
     │                · evidence state explained
     │
     ├─ index         regions in bounds · payload inside its record
     │                · no placeholder timestamps, no inverted intervals, no empty ids
     │                · authority explained, and never claims more than it read
     │                · accessible and unreferenced sets are disjoint
     │
     ├─ carver        records inside the requested range · non-zero length
     │                · no channel 0, no epoch clock · payload inside its record
     │                · deterministic across two passes
     │
     └─ determinism   a second parse of identical bytes is byte-for-byte identical
```

A check that cannot run because the parser does not supply its input is `NotApplicable`, **not
a failure**. A parser with no index reader is a valid parser; the engine degrades for it. The
contract governs the honesty and shape of whatever the parser does return.

The harness is run from `crates/recovery/tests/universal_parser_contract.rs` against every
parser in the workspace, on four evidence shapes:

| Evidence | What it proves |
|---|---|
| empty image | no parser invents structure out of nothing |
| 8 MiB of zeros | zeroed bytes are not mistaken for a volume |
| 8 MiB of pseudo-random noise (fixed seed) | noise is not mistaken for a container, a clock or a channel |
| a real Dahua DHFS 4.1 volume | the owning parser normalizes it honestly; **every other parser must decline it** |

The suite also contains a deliberately non-compliant parser and asserts the harness catches it,
because a harness that cannot fail proves nothing.

### Current results

All seven parsers — `dahua`, `hikvision`, `uniview`, `cpplus-ubs`, `honeywell`, `tplink`,
`unified` — pass every applicable check on all four shapes.

---

## 5. Capability tiers, observed not declared

What each parser actually returns today:

| Parser | `storage_geometry` | `recording_index` | `scan_region_for_candidates` | `recognize_candidate` |
|---|---|---|---|---|
| dahua | reads | reads | carves | inspects bytes |
| hikvision | reads | reads | carves | inspects bytes |
| uniview | reads | reads | carves | inspects bytes |
| unified | default `None` | default `None` | default empty | inspects bytes |
| cpplus-ubs | default `None` | default `None` | default empty | **always `true`** |
| honeywell | default `None` | default `None` | default empty | **always `true`** |
| tplink | default `None` | default `None` | default empty | **always `true`** |

The bottom four are **not** broken. `Ok(None)` is a supported answer, and the engine degrades
to a whole-window sweep whose findings can only reach `Unindexed` — never `Active`, never
`Orphaned`. That is the correct outcome for a parser that cannot yet establish an index.

The bold entries are finding **F8** in the audit: three parsers do not inspect bytes in
`recognize_candidate`, contrary to the trait's documentation. The signal is not load-bearing —
it cannot affect a data state — so this is recorded rather than patched, because fixing it
needs OEM format knowledge inside those parsers.

---

## 6. Adding an OEM

```text
1. crates/parsers/<oem>/          implement Parser
2. profiles/<oem>/<oem>-vN.toml   signatures, layout, weights — DATA, never constants
3. crates/recovery/Cargo.toml     add the crate to [dev-dependencies]
4. universal_parser_contract.rs   add one line to all_parsers()
```

Nothing else. No recovery algorithm, no fragmentation algorithm, no validation system, no
reconstruction system — those are universal and already written. A parser that returns
`Ok(None)` from every optional method is immediately usable at the raw-recovery tier, and every
capability it later gains upgrades it automatically because strategy selection reads
capabilities rather than names.
