# ANSWER KEY — dvr_3day_sample.raw

> SPOILER: names the filesystem family. Read only after testing detection.

## Filesystem family
- **Dahua DHFS**: `DHFS` superblock @0, `DHAV` packets, `DIDX` index.
  Detection => **Confirmed**. Model `NVR-8CH-2600`, volume `REC_VOLUME01`.
- Image 12,582,912 B (12 MiB), DIDX @ 0x00636200 (30 entries).

## Recording model
- Each recording is a **10-second** clip; cadence is 10s (contiguous).
- 2 channels, 3 days, 5 present 10s recordings per channel per day.
- One contiguous block of 3 missing slots per channel per day => a **30-second gap** per day.
- Start 2026-09-18T10:00:00 IST (UTC+05:30). Present slots [0, 1, 2, 6, 7], missing slots [3, 4, 5] (x10s).

## Expected counts (cross-check these)
- ACTIVE 10s recordings (indexed, appear as clips): **30** (15/channel).
- Per-channel/day recording sessions: **6** (one per channel per day), each with 5 segments.
- GAPS: **6** (one 30s gap per channel per day). Total missing = 180s.
- Measured cadence per channel = 10s, so each clip duration reads 10s.
- Session coverage = 50s recorded / 80s span.

## Recoverable gap footage (orphaned)
- 18 orphaned 10s clips (no DHAV framing / no DIDX entry) start at 0x003E1E00.
- Parser misses them (=> shown as gaps); pipeline recovery carves them by NAL
  signature. Each is an independently decodable clip (proven with ffprobe).

## ACTIVE recordings
| # | channel | codec | recorder-native (IST) | offset | payload B |
|---|---------|-------|-----------------------|--------|-----------|
| 1 | CH01 | h264 | 2026-09-18 10:00:00 | 0x00000200 | 128,576 |
| 2 | CH02 | h265 | 2026-09-18 10:00:00 | 0x0001FA00 | 141,974 |
| 3 | CH01 | h264 | 2026-09-18 10:00:10 | 0x00042600 | 128,576 |
| 4 | CH02 | h265 | 2026-09-18 10:00:10 | 0x00061E00 | 141,974 |
| 5 | CH01 | h264 | 2026-09-18 10:00:20 | 0x00084A00 | 128,576 |
| 6 | CH02 | h265 | 2026-09-18 10:00:20 | 0x000A4200 | 141,974 |
| 7 | CH01 | h264 | 2026-09-18 10:01:00 | 0x000C6E00 | 128,576 |
| 8 | CH02 | h265 | 2026-09-18 10:01:00 | 0x000E6600 | 141,974 |
| 9 | CH01 | h264 | 2026-09-18 10:01:10 | 0x00109200 | 128,576 |
| 10 | CH02 | h265 | 2026-09-18 10:01:10 | 0x00128A00 | 141,974 |
| 11 | CH01 | h264 | 2026-09-19 10:00:00 | 0x0014B600 | 128,576 |
| 12 | CH02 | h265 | 2026-09-19 10:00:00 | 0x0016AE00 | 141,974 |
| 13 | CH01 | h264 | 2026-09-19 10:00:10 | 0x0018DA00 | 128,576 |
| 14 | CH02 | h265 | 2026-09-19 10:00:10 | 0x001AD200 | 141,974 |
| 15 | CH01 | h264 | 2026-09-19 10:00:20 | 0x001CFE00 | 128,576 |
| 16 | CH02 | h265 | 2026-09-19 10:00:20 | 0x001EF600 | 141,974 |
| 17 | CH01 | h264 | 2026-09-19 10:01:00 | 0x00212200 | 128,576 |
| 18 | CH02 | h265 | 2026-09-19 10:01:00 | 0x00231A00 | 141,974 |
| 19 | CH01 | h264 | 2026-09-19 10:01:10 | 0x00254600 | 128,576 |
| 20 | CH02 | h265 | 2026-09-19 10:01:10 | 0x00273E00 | 141,974 |
| 21 | CH01 | h264 | 2026-09-20 10:00:00 | 0x00296A00 | 128,576 |
| 22 | CH02 | h265 | 2026-09-20 10:00:00 | 0x002B6200 | 141,974 |
| 23 | CH01 | h264 | 2026-09-20 10:00:10 | 0x002D8E00 | 128,576 |
| 24 | CH02 | h265 | 2026-09-20 10:00:10 | 0x002F8600 | 141,974 |
| 25 | CH01 | h264 | 2026-09-20 10:00:20 | 0x0031B200 | 128,576 |
| 26 | CH02 | h265 | 2026-09-20 10:00:20 | 0x0033AA00 | 141,974 |
| 27 | CH01 | h264 | 2026-09-20 10:01:00 | 0x0035D600 | 128,576 |
| 28 | CH02 | h265 | 2026-09-20 10:01:00 | 0x0037CE00 | 141,974 |
| 29 | CH01 | h264 | 2026-09-20 10:01:10 | 0x0039FA00 | 128,576 |
| 30 | CH02 | h265 | 2026-09-20 10:01:10 | 0x003BF200 | 141,974 |

## GAP (orphaned, recoverable) clips
| # | channel | codec | recorder-native (IST) | day | slot | orphan offset | bytes |
|---|---------|-------|-----------------------|-----|------|---------------|-------|
| 1 | CH01 | h264 | 2026-09-18 10:00:30 | 1 | 3 | 0x003E1E00 | 128,576 |
| 2 | CH02 | h265 | 2026-09-18 10:00:30 | 1 | 3 | 0x00401600 | 141,974 |
| 3 | CH01 | h264 | 2026-09-18 10:00:40 | 1 | 4 | 0x00424200 | 128,576 |
| 4 | CH02 | h265 | 2026-09-18 10:00:40 | 1 | 4 | 0x00443A00 | 141,974 |
| 5 | CH01 | h264 | 2026-09-18 10:00:50 | 1 | 5 | 0x00466600 | 128,576 |
| 6 | CH02 | h265 | 2026-09-18 10:00:50 | 1 | 5 | 0x00485E00 | 141,974 |
| 7 | CH01 | h264 | 2026-09-19 10:00:30 | 2 | 3 | 0x004A8A00 | 128,576 |
| 8 | CH02 | h265 | 2026-09-19 10:00:30 | 2 | 3 | 0x004C8200 | 141,974 |
| 9 | CH01 | h264 | 2026-09-19 10:00:40 | 2 | 4 | 0x004EAE00 | 128,576 |
| 10 | CH02 | h265 | 2026-09-19 10:00:40 | 2 | 4 | 0x0050A600 | 141,974 |
| 11 | CH01 | h264 | 2026-09-19 10:00:50 | 2 | 5 | 0x0052D200 | 128,576 |
| 12 | CH02 | h265 | 2026-09-19 10:00:50 | 2 | 5 | 0x0054CA00 | 141,974 |
| 13 | CH01 | h264 | 2026-09-20 10:00:30 | 3 | 3 | 0x0056F600 | 128,576 |
| 14 | CH02 | h265 | 2026-09-20 10:00:30 | 3 | 3 | 0x0058EE00 | 141,974 |
| 15 | CH01 | h264 | 2026-09-20 10:00:40 | 3 | 4 | 0x005B1A00 | 128,576 |
| 16 | CH02 | h265 | 2026-09-20 10:00:40 | 3 | 4 | 0x005D1200 | 141,974 |
| 17 | CH01 | h264 | 2026-09-20 10:00:50 | 3 | 5 | 0x005F3E00 | 128,576 |
| 18 | CH02 | h265 | 2026-09-20 10:00:50 | 3 | 5 | 0x00613600 | 141,974 |

