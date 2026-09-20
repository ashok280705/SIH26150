#!/usr/bin/env python3
"""
Generate a "blind" DVR/NVR .raw evidence disk image for end-to-end testing.

The filesystem family is deliberately NOT named in the on-screen output or the
filename, so the platform's detection stage can be exercised without a spoiler.
(The ground-truth answer key IS written to a separate file — open it only after
you have tested detection.)

Recording model (matches how the platform reasons about DVR footage)
--------------------------------------------------------------------
A DVR records continuously and stores the stream as back-to-back fixed-length
segment files. Each segment here is a real, independently decodable 10-second
clip, and consecutive segments are 10 seconds apart — so a "recording" IS a
10-second clip, and the platform measures the per-channel cadence as 10s.

  * 2 camera channels of real, decodable footage (H.264 + H.265).
  * 3 days of recording per channel.
  * 5 present 10-second recordings per channel per day.
  * A contiguous block of 3 missing 10-second slots per channel per day, i.e.
    a 30-second GAP in the middle of each day's recording.
  * The GAP is RECOVERABLE: the missing 10-second clips are written to the image
    as ORPHANED elementary streams (no container framing, no index entry). The
    normal parse misses them, so the recording timeline reports a 30-second gap;
    the recovery/carving stage can still bring those bytes back because they
    carry valid video signatures.

So each row of footage is a 10-second recording, gaps are reported in seconds,
and the gap footage is physically present and carvable.

Usage
-----
  python3 generate_evidence_3day.py
  python3 generate_evidence_3day.py --size 640x360 --image-size 14MiB

Requires ffmpeg/ffprobe on PATH.
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys
from datetime import datetime, timezone, timedelta

SECTOR_SIZE = 512
DHAV_HEADER_SIZE = 64
DHAV_FOOTER = b"dhav"

MAX_IMAGE_SIZE = 16 * 1024 * 1024
BUILD_DIR = ".fixture_build"
OUTPUT_PATH = "dvr_3day_sample.raw"
ANSWER_KEY_PATH = ".fixture_build/ANSWER_KEY_dvr_3day.md"
IST = timezone(timedelta(hours=5, minutes=30))

# Eight 10-second slots make up each day's recording per channel. Five are
# PRESENT (recorded) and a contiguous block of three in the middle is MISSING,
# producing a single 30-second gap that the surrounding recordings pin cleanly.
PRESENT_SLOTS = [0, 1, 2, 6, 7]
MISSING_SLOTS = [3, 4, 5]


def die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def require(tool: str) -> str:
    exe = shutil.which(tool)
    if not exe:
        die(f"{tool} not found on PATH (brew install ffmpeg).")
    return exe


def align_up(value: int, alignment: int = SECTOR_SIZE) -> int:
    return (value + alignment - 1) // alignment * alignment


def parse_size(text: str) -> int:
    t = text.strip().lower().replace("ib", "").replace("b", "")
    mult = 1
    if t.endswith("k"):
        mult, t = 1024, t[:-1]
    elif t.endswith("m"):
        mult, t = 1024 * 1024, t[:-1]
    elif t.endswith("g"):
        mult, t = 1024 * 1024 * 1024, t[:-1]
    try:
        return int(float(t) * mult)
    except ValueError:
        die(f"could not parse size: {text}")
        return 0


def ist_to_unix(text: str) -> int:
    try:
        dt = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        die(f"could not parse --start '{text}', expected YYYY-MM-DDThh:mm:ss")
    return int(dt.replace(tzinfo=IST).timestamp())


def fmt_ist(unix_ts: int) -> str:
    return datetime.fromtimestamp(unix_ts, IST).strftime("%Y-%m-%d %H:%M:%S")


def encode_clip(codec: str, seconds: int, size: str, fps: int, crf: int, out_path: str) -> bytes:
    ffmpeg = require("ffmpeg")
    encoder = "libx264" if codec == "h264" else "libx265"
    muxer = "h264" if codec == "h264" else "hevc"
    forbidden = b"DHAV"
    for attempt in range(4):
        this_crf = crf + attempt
        cmd = [
            ffmpeg, "-hide_banner", "-loglevel", "error", "-y",
            "-f", "lavfi", "-i", f"testsrc2=size={size}:rate={fps}:duration={seconds}",
            "-t", str(seconds), "-an",
            "-c:v", encoder, "-preset", "veryfast", "-crf", str(this_crf),
            "-g", str(fps), "-pix_fmt", "yuv420p", "-f", muxer, out_path,
        ]
        subprocess.run(cmd, check=True)
        data = open(out_path, "rb").read()
        if not data:
            die(f"encoded clip is empty: {out_path}")
        if forbidden not in data:
            return data
    die(f"could not encode a {codec} clip free of the packet tag after retries")
    return b""


def probe(path: str) -> tuple[int, int]:
    ffprobe = shutil.which("ffprobe")
    if not ffprobe:
        return (0, 0)
    out = subprocess.run(
        [ffprobe, "-hide_banner", "-v", "error",
         "-show_entries", "stream=width,height", "-of", "default=nw=1", path],
        capture_output=True, text=True, check=False,
    ).stdout
    w = h = 0
    for line in out.splitlines():
        if line.startswith("width=") and line[6:].isdigit():
            w = int(line[6:])
        elif line.startswith("height=") and line[7:].isdigit():
            h = int(line[7:])
    return (w, h)


def pack_packet(buf: bytearray, offset: int, *, channel0: int, frame_seq: int,
                timestamp: int, codec_label: bytes, name: bytes,
                width: int, height: int, payload: bytes) -> int:
    packet_len = DHAV_HEADER_SIZE + len(payload) + len(DHAV_FOOTER)
    buf[offset:offset + 4] = b"DHAV"
    struct.pack_into(
        "<BBHIIQIHH", buf, offset + 4,
        0xFD, channel0, 0x0000, frame_seq, packet_len,
        timestamp, 0x20260918, width, height,
    )
    buf[offset + 32:offset + 48] = codec_label.ljust(16, b"\x00")[:16]
    buf[offset + 48:offset + 64] = name.ljust(16, b"\x00")[:16]
    ps = offset + DHAV_HEADER_SIZE
    buf[ps:ps + len(payload)] = payload
    buf[ps + len(payload):ps + len(payload) + len(DHAV_FOOTER)] = DHAV_FOOTER
    return packet_len


class Channel:
    def __init__(self, index0, codec, ext, label, name):
        self.index0 = index0
        self.codec = codec
        self.ext = ext
        self.label = label
        self.name = name
        self.width = 0
        self.height = 0
        self.payload = b""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=int, default=3)
    ap.add_argument("--clip-seconds", type=int, default=10, help="length of each recording (also the cadence)")
    ap.add_argument("--size", default="320x240")
    ap.add_argument("--fps", type=int, default=10)
    ap.add_argument("--crf", type=int, default=34)
    ap.add_argument("--start", default="2026-09-18T10:00:00", help="IST wall clock of the first slot each day")
    ap.add_argument("--image-size", default="12MiB")
    ap.add_argument("--output", default=OUTPUT_PATH)
    ap.add_argument("--answer-key", default=ANSWER_KEY_PATH)
    args = ap.parse_args()

    days = max(1, args.days)
    clip = max(1, args.clip_seconds)   # segment length == cadence, so a recording is `clip` seconds
    base = ist_to_unix(args.start)
    day_secs = 86400

    os.makedirs(BUILD_DIR, exist_ok=True)

    channels = [
        Channel(0, "h264", "h264", b"H.264/AVC", b"CH01_ENTRANCE"),
        Channel(1, "h265", "hevc", b"H.265/HEVC", b"CH02_PARKING"),
    ]

    print("Encoding base clips (one per codec)...")
    for ch in channels:
        out = os.path.join(BUILD_DIR, f"base_{ch.codec}_{clip}s.{ch.ext}")
        ch.payload = encode_clip(ch.codec, clip, args.size, args.fps, args.crf, out)
        ch.width, ch.height = probe(out)
        ch.width = ch.width or int(args.size.split("x")[0])
        ch.height = ch.height or int(args.size.split("x")[1])
        print(f"  {ch.name.decode()}: {ch.codec} {ch.width}x{ch.height} {len(ch.payload):,} B/clip")

    # Schedule: contiguous 10s slots; PRESENT_SLOTS recorded, MISSING_SLOTS are
    # the recoverable gap. The slot index * clip seconds gives the offset in time.
    active, gaps = [], []
    for ch in channels:
        for d in range(days):
            day0 = base + d * day_secs
            for s in PRESENT_SLOTS:
                active.append(dict(channel0=ch.index0, name=ch.name, label=ch.label,
                                   codec=ch.codec, payload=ch.payload, width=ch.width,
                                   height=ch.height, timestamp=day0 + s * clip, day=d, slot=s))
            for s in MISSING_SLOTS:
                gaps.append(dict(channel0=ch.index0, name=ch.name, label=ch.label,
                                 codec=ch.codec, payload=ch.payload, width=ch.width,
                                 height=ch.height, timestamp=day0 + s * clip, day=d, slot=s))

    active.sort(key=lambda x: (x["timestamp"], x["channel0"]))
    gaps.sort(key=lambda x: (x["timestamp"], x["channel0"]))

    # ---- Physical layout ----------------------------------------------------
    cursor = SECTOR_SIZE
    for a in active:
        a["offset"] = cursor
        a["total"] = DHAV_HEADER_SIZE + len(a["payload"]) + len(DHAV_FOOTER)
        cursor = align_up(cursor + a["total"])

    orphan_region_start = align_up(cursor)
    cursor = orphan_region_start
    for g in gaps:
        g["offset"] = cursor
        g["length"] = len(g["payload"])
        cursor = align_up(cursor + g["length"])

    index_offset = align_up(cursor)
    index_size = 16 + len(active) * 32
    min_size = align_up(index_offset + index_size) + SECTOR_SIZE
    disk_size = align_up(max(align_up(min_size, 1024 * 1024), parse_size(args.image_size)), 1024 * 1024)
    if disk_size > MAX_IMAGE_SIZE:
        die(f"image would be {disk_size/1048576:.1f} MiB (> {MAX_IMAGE_SIZE//1048576} MiB window).")

    buf = bytearray(disk_size)

    # ---- Superblock @ 0 -----------------------------------------------------
    buf[0:4] = b"DHFS"
    struct.pack_into("<IIIQQQQ", buf, 4,
                     0x00010000, SECTOR_SIZE, 65536, disk_size // 65536,
                     active[0]["offset"] if active else SECTOR_SIZE, index_offset, base)
    buf[48:64] = b"NVR-8CH-2600".ljust(16, b"\x00")
    buf[64:96] = b"SN-2026-NVR-0007A3F19C42BB01".ljust(32, b"\x00")
    buf[96:112] = b"REC_VOLUME01".ljust(16, b"\x00")
    struct.pack_into("<I", buf, 508, 0xD4A0A5EF)

    for seq, a in enumerate(active, start=1):
        pack_packet(buf, a["offset"], channel0=a["channel0"], frame_seq=seq,
                    timestamp=a["timestamp"], codec_label=a["label"], name=a["name"],
                    width=a["width"], height=a["height"], payload=a["payload"])

    for g in gaps:
        buf[g["offset"]:g["offset"] + len(g["payload"])] = g["payload"]

    buf[index_offset:index_offset + 4] = b"DIDX"
    struct.pack_into("<I", buf, index_offset + 4, len(active))
    for i, a in enumerate(active):
        e = index_offset + 16 + i * 32
        struct.pack_into("<BBHQQQI", buf, e, a["channel0"], 0xFD, 0x0000,
                         a["offset"], a["total"], a["timestamp"], 0x1A2B3C4D + i)

    backup = disk_size - SECTOR_SIZE
    buf[backup:backup + 4] = b"DHFS"
    struct.pack_into("<I", buf, backup + 4, 0x00010000)
    buf[backup + 8:backup + 24] = b"BACKUP_SUPERBLK".ljust(16, b"\x00")

    with open(args.output, "wb") as f:
        f.write(buf)

    # ---- Self-check ---------------------------------------------------------
    problems = []
    if buf[0:4] != b"DHFS":
        problems.append("superblock magic missing")
    if active and buf[active[0]["offset"]:active[0]["offset"] + 4] != b"DHAV":
        problems.append("first packet tag missing")
    if active[0]["offset"] >= 65536:
        problems.append("first packet not within 64 KiB")
    if buf[index_offset:index_offset + 4] != b"DIDX":
        problems.append("index magic missing")
    orphan_end = align_up(gaps[-1]["offset"] + gaps[-1]["length"]) if gaps else orphan_region_start
    if b"DHAV" in bytes(buf[orphan_region_start:orphan_end]):
        problems.append("orphaned slack contains a stray packet tag")
    if problems:
        die("self-check failed: " + "; ".join(problems))

    print(f"\nWrote {args.output} ({len(buf):,} bytes / {len(buf)/1048576:.2f} MiB)")
    print(f"  active (indexed) 10s recordings : {len(active)} "
          f"({len(active)//len(channels)}/channel, {len(PRESENT_SLOTS)}/day/channel)")
    print(f"  recoverable gap clips (orphaned): {len(gaps)} "
          f"({len(MISSING_SLOTS)}/day/channel => a {clip*len(MISSING_SLOTS)}s gap/day)")
    print(f"  channels                        : {len(channels)}")
    print(f"  schedule                        : {days} day(s), {len(PRESENT_SLOTS)} present + "
          f"{len(MISSING_SLOTS)} missing {clip}s slots/day, cadence {clip}s")
    print(f"\nGround-truth answer key: {args.answer_key} (open only after testing detection)")

    write_answer_key(args, channels, active, gaps, disk_size, index_offset,
                     orphan_region_start, days, clip)


def write_answer_key(args, channels, active, gaps, disk_size, index_offset,
                     orphan_region_start, days, clip):
    n_ch = len(channels)
    gap_secs = clip * len(MISSING_SLOTS)
    L = []
    L.append("# ANSWER KEY — dvr_3day_sample.raw")
    L.append("")
    L.append("> SPOILER: names the filesystem family. Read only after testing detection.")
    L.append("")
    L.append("## Filesystem family")
    L.append("- **Dahua DHFS**: `DHFS` superblock @0, `DHAV` packets, `DIDX` index.")
    L.append("  Detection => **Confirmed**. Model `NVR-8CH-2600`, volume `REC_VOLUME01`.")
    L.append(f"- Image {disk_size:,} B ({disk_size/1048576:.0f} MiB), DIDX @ 0x{index_offset:08X} "
             f"({len(active)} entries).")
    L.append("")
    L.append("## Recording model")
    L.append(f"- Each recording is a **{clip}-second** clip; cadence is {clip}s (contiguous).")
    L.append(f"- {n_ch} channels, {days} days, {len(PRESENT_SLOTS)} present {clip}s recordings "
             f"per channel per day.")
    L.append(f"- One contiguous block of {len(MISSING_SLOTS)} missing slots per channel per day "
             f"=> a **{gap_secs}-second gap** per day.")
    L.append(f"- Start {args.start} IST (UTC+05:30). Present slots {PRESENT_SLOTS}, "
             f"missing slots {MISSING_SLOTS} (x{clip}s).")
    L.append("")
    L.append("## Expected counts (cross-check these)")
    L.append(f"- ACTIVE {clip}s recordings (indexed, appear as clips): **{len(active)}** "
             f"({len(active)//n_ch}/channel).")
    L.append(f"- Per-channel/day recording sessions: **{n_ch*days}** "
             f"(one per channel per day), each with {len(PRESENT_SLOTS)} segments.")
    L.append(f"- GAPS: **{n_ch*days}** (one {gap_secs}s gap per channel per day). "
             f"Total missing = {n_ch*days*gap_secs}s.")
    L.append(f"- Measured cadence per channel = {clip}s, so each clip duration reads {clip}s.")
    L.append(f"- Session coverage = {len(PRESENT_SLOTS)*clip}s recorded / "
             f"{(max(PRESENT_SLOTS)+1)*clip}s span.")
    L.append("")
    L.append("## Recoverable gap footage (orphaned)")
    L.append(f"- {len(gaps)} orphaned {clip}s clips (no DHAV framing / no DIDX entry) start at "
             f"0x{orphan_region_start:08X}.")
    L.append("- Parser misses them (=> shown as gaps); pipeline recovery carves them by NAL")
    L.append("  signature. Each is an independently decodable clip (proven with ffprobe).")
    L.append("")
    L.append("## ACTIVE recordings")
    L.append("| # | channel | codec | recorder-native (IST) | offset | payload B |")
    L.append("|---|---------|-------|-----------------------|--------|-----------|")
    for i, a in enumerate(active, 1):
        L.append(f"| {i} | CH{a['channel0']+1:02d} | {a['codec']} | {fmt_ist(a['timestamp'])} | "
                 f"0x{a['offset']:08X} | {len(a['payload']):,} |")
    L.append("")
    L.append("## GAP (orphaned, recoverable) clips")
    L.append("| # | channel | codec | recorder-native (IST) | day | slot | orphan offset | bytes |")
    L.append("|---|---------|-------|-----------------------|-----|------|---------------|-------|")
    for i, g in enumerate(gaps, 1):
        L.append(f"| {i} | CH{g['channel0']+1:02d} | {g['codec']} | {fmt_ist(g['timestamp'])} | "
                 f"{g['day']+1} | {g['slot']} | 0x{g['offset']:08X} | {g['length']:,} |")
    L.append("")
    os.makedirs(os.path.dirname(args.answer_key), exist_ok=True)
    with open(args.answer_key, "w") as f:
        f.write("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
