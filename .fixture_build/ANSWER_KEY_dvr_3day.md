# ANSWER KEY — dvr_3day_sample.raw

> SPOILER: names the filesystem family. Read only after testing detection.

## Filesystem family
- **Dahua DHFS**: `DHFS` superblock @0, `DHAV` packets, `DIDX` index. Detection => Confirmed.
- Image 14,680,064 B (14 MiB), DIDX @ 0x00891E00 (30 entries).

## Recording model
- Each recording is a **10s** clip; cadence 10s (contiguous).
- 2 channels, 3 days, 5 present recordings/channel/day.
- One **50s gap**/channel/day (5 missing 10s slots), footage
  interleaved into the physical space between the straddling recordings.

## Expected counts
- ACTIVE recordings (clip list): **30** (15/channel).
- Sessions: **6**; GAPS: **6** (each 50s).

## Staged gap recovery (per gap, time order)
| slot time | content | level | outcome |
|-----------|---------|-------|---------|
| +0–10s  | clean stream          | L1 | Active, Recoverable |
| +10–20s | clean stream          | L1 | Active, Recoverable |
| +20–30s | NAL slice, no SPS/PPS  | L2 | Orphaned, Partial |
| +30–40s | zeros                  | —  | NOT recovered |
| +40–50s | start code + noise     | L3 | Corrupted, Partial |
- Net per 50s gap: 20s@L1 + 10s@L2 + 10s@L3 recovered, 10s not recovered.

## ACTIVE recordings
| # | channel | codec | recorder-native (IST) | offset | payload B |
|---|---------|-------|-----------------------|--------|-----------|
| 1 | CH01 | h264 | 2026-09-18 10:00:00 | 0x00000200 | 128,576 |
| 2 | CH01 | h264 | 2026-09-18 10:00:10 | 0x0001FA00 | 128,576 |
| 3 | CH01 | h264 | 2026-09-18 10:00:20 | 0x0003F200 | 128,576 |
| 4 | CH01 | h264 | 2026-09-18 10:01:20 | 0x00126A00 | 128,576 |
| 5 | CH01 | h264 | 2026-09-18 10:01:30 | 0x00146200 | 128,576 |
| 6 | CH01 | h264 | 2026-09-19 10:00:00 | 0x00165A00 | 128,576 |
| 7 | CH01 | h264 | 2026-09-19 10:00:10 | 0x00185200 | 128,576 |
| 8 | CH01 | h264 | 2026-09-19 10:00:20 | 0x001A4A00 | 128,576 |
| 9 | CH01 | h264 | 2026-09-19 10:01:20 | 0x0028C200 | 128,576 |
| 10 | CH01 | h264 | 2026-09-19 10:01:30 | 0x002ABA00 | 128,576 |
| 11 | CH01 | h264 | 2026-09-20 10:00:00 | 0x002CB200 | 128,576 |
| 12 | CH01 | h264 | 2026-09-20 10:00:10 | 0x002EAA00 | 128,576 |
| 13 | CH01 | h264 | 2026-09-20 10:00:20 | 0x0030A200 | 128,576 |
| 14 | CH01 | h264 | 2026-09-20 10:01:20 | 0x003F1A00 | 128,576 |
| 15 | CH01 | h264 | 2026-09-20 10:01:30 | 0x00411200 | 128,576 |
| 16 | CH02 | h265 | 2026-09-18 10:00:00 | 0x00430A00 | 141,974 |
| 17 | CH02 | h265 | 2026-09-18 10:00:10 | 0x00453600 | 141,974 |
| 18 | CH02 | h265 | 2026-09-18 10:00:20 | 0x00476200 | 141,974 |
| 19 | CH02 | h265 | 2026-09-18 10:01:20 | 0x00560E00 | 141,974 |
| 20 | CH02 | h265 | 2026-09-18 10:01:30 | 0x00583A00 | 141,974 |
| 21 | CH02 | h265 | 2026-09-19 10:00:00 | 0x005A6600 | 141,974 |
| 22 | CH02 | h265 | 2026-09-19 10:00:10 | 0x005C9200 | 141,974 |
| 23 | CH02 | h265 | 2026-09-19 10:00:20 | 0x005EBE00 | 141,974 |
| 24 | CH02 | h265 | 2026-09-19 10:01:20 | 0x006D6A00 | 141,974 |
| 25 | CH02 | h265 | 2026-09-19 10:01:30 | 0x006F9600 | 141,974 |
| 26 | CH02 | h265 | 2026-09-20 10:00:00 | 0x0071C200 | 141,974 |
| 27 | CH02 | h265 | 2026-09-20 10:00:10 | 0x0073EE00 | 141,974 |
| 28 | CH02 | h265 | 2026-09-20 10:00:20 | 0x00761A00 | 141,974 |
| 29 | CH02 | h265 | 2026-09-20 10:01:20 | 0x0084C600 | 141,974 |
| 30 | CH02 | h265 | 2026-09-20 10:01:30 | 0x0086F200 | 141,974 |

## Orphaned gap slots (recoverable footage)
| # | channel | slot | kind | recorder-native (IST) | offset |
|---|---------|------|------|-----------------------|--------|
| 1 | CH01 | 3 | clean | 2026-09-18 10:00:30 | 0x0005E884 |
| 2 | CH01 | 4 | clean | 2026-09-18 10:00:40 | 0x00086884 |
| 3 | CH01 | 5 | slice | 2026-09-18 10:00:50 | 0x000AE884 |
| 4 | CH01 | 6 | empty | 2026-09-18 10:01:00 | 0x000D6884 |
| 5 | CH01 | 7 | fragment | 2026-09-18 10:01:10 | 0x000FE884 |
| 6 | CH01 | 3 | clean | 2026-09-19 10:00:30 | 0x001C4084 |
| 7 | CH01 | 4 | clean | 2026-09-19 10:00:40 | 0x001EC084 |
| 8 | CH01 | 5 | slice | 2026-09-19 10:00:50 | 0x00214084 |
| 9 | CH01 | 6 | empty | 2026-09-19 10:01:00 | 0x0023C084 |
| 10 | CH01 | 7 | fragment | 2026-09-19 10:01:10 | 0x00264084 |
| 11 | CH01 | 3 | clean | 2026-09-20 10:00:30 | 0x00329884 |
| 12 | CH01 | 4 | clean | 2026-09-20 10:00:40 | 0x00351884 |
| 13 | CH01 | 5 | slice | 2026-09-20 10:00:50 | 0x00379884 |
| 14 | CH01 | 6 | empty | 2026-09-20 10:01:00 | 0x003A1884 |
| 15 | CH01 | 7 | fragment | 2026-09-20 10:01:10 | 0x003C9884 |
| 16 | CH02 | 3 | clean | 2026-09-18 10:00:30 | 0x00498CDA |
| 17 | CH02 | 4 | clean | 2026-09-18 10:00:40 | 0x004C0CDA |
| 18 | CH02 | 5 | slice | 2026-09-18 10:00:50 | 0x004E8CDA |
| 19 | CH02 | 6 | empty | 2026-09-18 10:01:00 | 0x00510CDA |
| 20 | CH02 | 7 | fragment | 2026-09-18 10:01:10 | 0x00538CDA |
| 21 | CH02 | 3 | clean | 2026-09-19 10:00:30 | 0x0060E8DA |
| 22 | CH02 | 4 | clean | 2026-09-19 10:00:40 | 0x006368DA |
| 23 | CH02 | 5 | slice | 2026-09-19 10:00:50 | 0x0065E8DA |
| 24 | CH02 | 6 | empty | 2026-09-19 10:01:00 | 0x006868DA |
| 25 | CH02 | 7 | fragment | 2026-09-19 10:01:10 | 0x006AE8DA |
| 26 | CH02 | 3 | clean | 2026-09-20 10:00:30 | 0x007844DA |
| 27 | CH02 | 4 | clean | 2026-09-20 10:00:40 | 0x007AC4DA |
| 28 | CH02 | 5 | slice | 2026-09-20 10:00:50 | 0x007D44DA |
| 29 | CH02 | 6 | empty | 2026-09-20 10:01:00 | 0x007FC4DA |
| 30 | CH02 | 7 | fragment | 2026-09-20 10:01:10 | 0x008244DA |

