#!/usr/bin/env python3
"""
Generate a "blind" DVR/NVR .raw evidence disk image for end-to-end testing.

The filesystem family is deliberately NOT named on screen or in the filename, so
detection can be exercised without a spoiler. The ground-truth answer key is
written to a separate file — open it only after testing detection.

Recording model
---------------
Each recording is a real, independently decodable 10-second clip; consecutive
recordings are 10s apart (contiguous), so the platform measures the cadence as
10s and a "recording" IS a 10s clip.

  * 2 channels (H.264 + H.265), 3 days.
  * 5 present 10-second recordings per channel per day.
  * A 50-second GAP per channel per day (5 missing 10s slots), whose footage is
    written INTO the physical space between the two straddling recordings — this
    is where deleted footage would reside — so a byte scan of the gap can find it.

Graduated, recoverable gap (per gap, in time order)
---------------------------------------------------
The 5 missing slots are crafted so a staged L1 -> L2 -> L3 recovery produces a
mix of outcomes, demonstrating partial recovery:

  slot 3 (10s): clean elementary stream        -> L1 (Active,    Recoverable)
  slot 4 (10s): clean elementary stream        -> L1 (Active,    Recoverable)
  slot 5 (10s): NAL slice, no parameter sets   -> L2 (Orphaned,  Partial)
  slot 6 (10s): zeros                          -> not recovered
  slot 7 (10s): bare start code + noise        -> L3 (Corrupted, Partial)

So a 50s gap recovers as 20s@L1 + 10s@L2 + 10s@L3, with 10s not recovered.

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

# 10 scheduled 10s slots per channel per day: 5 present, a 5-slot gap in the middle.
PRESENT_SLOTS = [0, 1, 2, 8, 9]
MISSING_SLOTS = [3, 4, 5, 6, 7]
# Fixed byte size for each orphaned gap slot, so a proportional time->byte mapping
# over the gap region lands cleanly on each slot.
SLOT_BYTES = 160 * 1024
# Leading zero pad inside each orphan slot; keeps a slot's real content clear of the
# small boundary bleed from the proportional sub-slot mapping (max a few dozen bytes).
LEAD_PAD = 1024
# What each missing slot contains, driving the recovery level it resolves to.
CASCADE = {3: "clean", 4: "clean", 5: "slice", 6: "empty", 7: "fragment"}


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
        if forbidden not in data and len(data) + LEAD_PAD <= SLOT_BYTES:
            return data
    die(f"could not encode a {codec} clip that fits a slot and avoids the packet tag")
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


def orphan_content(kind: str, payload: bytes) -> bytes:
    """Build one SLOT_BYTES orphan slot whose bytes resolve to a specific level."""
    b = bytearray(SLOT_BYTES)  # zero-filled
    if kind == "clean":
        b[LEAD_PAD:LEAD_PAD + len(payload)] = payload            # valid stream -> L1
    elif kind == "slice":
        frag = b"\x00\x00\x01\x65" + b"\xBB" * 256               # one IDR slice, no SPS/PPS -> L2
        b[LEAD_PAD:LEAD_PAD + len(frag)] = frag
    elif kind == "fragment":
        frag = b"\x00\x00\x01\x01" + b"\xAA" * 256               # bare start code, non-scoring -> L3
        b[LEAD_PAD:LEAD_PAD + len(frag)] = frag
    elif kind == "empty":
        pass                                                     # all zeros -> not recovered
    else:
        die(f"unknown orphan kind: {kind}")
    return bytes(b)


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
    ap.add_argument("--image-size", default="14MiB")
    ap.add_argument("--output", default=OUTPUT_PATH)
    ap.add_argument("--answer-key", default=ANSWER_KEY_PATH)
    args = ap.parse_args()

    days = max(1, args.days)
    clip = max(1, args.clip_seconds)
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

    # ── Pass 1: plan the physical layout, interleaving each day's gap footage ──
    # Layout per (channel, day): [present slots 0,1,2][orphan gap slots 3..7][present 8,9]
    # The orphan slots occupy the physical space between the recordings that straddle
    # the gap, exactly where the recovery scan looks.
    active = []   # {offset, channel0, timestamp, payload, label, name, w, h}
    orphans = []  # {offset, content, channel0, timestamp, slot, kind}
    seq = 0
    cursor = SECTOR_SIZE

    def plan_active(ch, ts):
        nonlocal cursor, seq
        cursor = align_up(cursor)
        seq += 1
        payload = ch.payload
        active.append(dict(offset=cursor, channel0=ch.index0, timestamp=ts, payload=payload,
                           label=ch.label, name=ch.name, w=ch.width, h=ch.height, seq=seq))
        cursor += DHAV_HEADER_SIZE + len(payload) + len(DHAV_FOOTER)

    for ch in channels:
        for d in range(days):
            day0 = base + d * day_secs
            for s in [0, 1, 2]:
                plan_active(ch, day0 + s * clip)
            for s in MISSING_SLOTS:
                content = orphan_content(CASCADE[s], ch.payload)
                orphans.append(dict(offset=cursor, content=content, channel0=ch.index0,
                                    timestamp=day0 + s * clip, slot=s, kind=CASCADE[s]))
                cursor += SLOT_BYTES
            for s in [8, 9]:
                plan_active(ch, day0 + s * clip)  # placed right after orphans (no align)
            cursor = align_up(cursor)

    index_offset = align_up(cursor)
    index_size = 16 + len(active) * 32
    min_size = align_up(index_offset + index_size) + SECTOR_SIZE
    disk_size = align_up(max(align_up(min_size, 1024 * 1024), parse_size(args.image_size)), 1024 * 1024)
    if disk_size > MAX_IMAGE_SIZE:
        die(f"image would be {disk_size/1048576:.1f} MiB (> {MAX_IMAGE_SIZE//1048576} MiB window).")

    # ── Pass 2: write ──────────────────────────────────────────────────────────
    buf = bytearray(disk_size)
    buf[0:4] = b"DHFS"
    struct.pack_into("<IIIQQQQ", buf, 4,
                     0x00010000, SECTOR_SIZE, 65536, disk_size // 65536,
                     active[0]["offset"], index_offset, base)
    buf[48:64] = b"NVR-8CH-2600".ljust(16, b"\x00")
    buf[64:96] = b"SN-2026-NVR-0007A3F19C42BB01".ljust(32, b"\x00")
    buf[96:112] = b"REC_VOLUME01".ljust(16, b"\x00")
    struct.pack_into("<I", buf, 508, 0xD4A0A5EF)

    for a in active:
        pack_packet(buf, a["offset"], channel0=a["channel0"], frame_seq=a["seq"],
                    timestamp=a["timestamp"], codec_label=a["label"], name=a["name"],
                    width=a["w"], height=a["h"], payload=a["payload"])
    for o in orphans:
        buf[o["offset"]:o["offset"] + len(o["content"])] = o["content"]

    buf[index_offset:index_offset + 4] = b"DIDX"
    struct.pack_into("<I", buf, index_offset + 4, len(active))
    for i, a in enumerate(active):
        e = index_offset + 16 + i * 32
        struct.pack_into("<BBHQQQI", buf, e, a["channel0"], 0xFD, 0x0000,
                         a["offset"], DHAV_HEADER_SIZE + len(a["payload"]) + len(DHAV_FOOTER),
                         a["timestamp"], 0x1A2B3C4D + i)

    backup = disk_size - SECTOR_SIZE
    buf[backup:backup + 4] = b"DHFS"
    struct.pack_into("<I", buf, backup + 4, 0x00010000)
    buf[backup + 8:backup + 24] = b"BACKUP_SUPERBLK".ljust(16, b"\x00")

    with open(args.output, "wb") as f:
        f.write(buf)

    # ── Self-check ───────────────────────────────────────────────────────────
    problems = []
    if buf[0:4] != b"DHFS":
        problems.append("superblock magic missing")
    if buf[active[0]["offset"]:active[0]["offset"] + 4] != b"DHAV":
        problems.append("first packet tag missing")
    if active[0]["offset"] >= 65536:
        problems.append("first packet not within 64 KiB")
    if buf[index_offset:index_offset + 4] != b"DIDX":
        problems.append("index magic missing")
    for o in orphans:
        if b"DHAV" in o["content"]:
            problems.append(f"orphan slot {o['slot']} contains a stray packet tag")
            break
    if problems:
        die("self-check failed: " + "; ".join(problems))

    n_ch, n_gaps = len(channels), len(channels) * days
    print(f"\nWrote {args.output} ({len(buf):,} bytes / {len(buf)/1048576:.2f} MiB)")
    print(f"  active (indexed) 10s recordings : {len(active)} ({len(active)//n_ch}/channel, {len(PRESENT_SLOTS)}/day/channel)")
    print(f"  gaps                            : {n_gaps} (one {clip*len(MISSING_SLOTS)}s gap/channel/day)")
    print(f"  orphaned gap slots (recoverable): {len(orphans)} ({len(MISSING_SLOTS)}/gap: 2 clean, 1 slice, 1 empty, 1 fragment)")
    print(f"  channels                        : {n_ch}")
    print(f"\nGround-truth answer key: {args.answer_key} (open only after testing detection)")

    write_answer_key(args, channels, active, orphans, disk_size, index_offset, days, clip)


def write_answer_key(args, channels, active, orphans, disk_size, index_offset, days, clip):
    n_ch = len(channels)
    gap_secs = clip * len(MISSING_SLOTS)
    L = []
    L.append("# ANSWER KEY — dvr_3day_sample.raw")
    L.append("")
    L.append("> SPOILER: names the filesystem family. Read only after testing detection.")
    L.append("")
    L.append("## Filesystem family")
    L.append("- **Dahua DHFS**: `DHFS` superblock @0, `DHAV` packets, `DIDX` index. Detection => Confirmed.")
    L.append(f"- Image {disk_size:,} B ({disk_size/1048576:.0f} MiB), DIDX @ 0x{index_offset:08X} ({len(active)} entries).")
    L.append("")
    L.append("## Recording model")
    L.append(f"- Each recording is a **{clip}s** clip; cadence {clip}s (contiguous).")
    L.append(f"- {n_ch} channels, {days} days, {len(PRESENT_SLOTS)} present recordings/channel/day.")
    L.append(f"- One **{gap_secs}s gap**/channel/day ({len(MISSING_SLOTS)} missing {clip}s slots), footage")
    L.append("  interleaved into the physical space between the straddling recordings.")
    L.append("")
    L.append("## Expected counts")
    L.append(f"- ACTIVE recordings (clip list): **{len(active)}** ({len(active)//n_ch}/channel).")
    L.append(f"- Sessions: **{n_ch*days}**; GAPS: **{n_ch*days}** (each {gap_secs}s).")
    L.append("")
    L.append("## Staged gap recovery (per gap, time order)")
    L.append("| slot time | content | level | outcome |")
    L.append("|-----------|---------|-------|---------|")
    L.append("| +0–10s  | clean stream          | L1 | Active, Recoverable |")
    L.append("| +10–20s | clean stream          | L1 | Active, Recoverable |")
    L.append("| +20–30s | NAL slice, no SPS/PPS  | L2 | Orphaned, Partial |")
    L.append("| +30–40s | zeros                  | —  | NOT recovered |")
    L.append("| +40–50s | start code + noise     | L3 | Corrupted, Partial |")
    L.append(f"- Net per {gap_secs}s gap: 20s@L1 + 10s@L2 + 10s@L3 recovered, 10s not recovered.")
    L.append("")
    L.append("## ACTIVE recordings")
    L.append("| # | channel | codec | recorder-native (IST) | offset | payload B |")
    L.append("|---|---------|-------|-----------------------|--------|-----------|")
    for i, a in enumerate(active, 1):
        L.append(f"| {i} | CH{a['channel0']+1:02d} | {channels[a['channel0']].codec} | "
                 f"{fmt_ist(a['timestamp'])} | 0x{a['offset']:08X} | {len(a['payload']):,} |")
    L.append("")
    L.append("## Orphaned gap slots (recoverable footage)")
    L.append("| # | channel | slot | kind | recorder-native (IST) | offset |")
    L.append("|---|---------|------|------|-----------------------|--------|")
    for i, o in enumerate(orphans, 1):
        L.append(f"| {i} | CH{o['channel0']+1:02d} | {o['slot']} | {o['kind']} | "
                 f"{fmt_ist(o['timestamp'])} | 0x{o['offset']:08X} |")
    L.append("")
    os.makedirs(os.path.dirname(args.answer_key), exist_ok=True)
    with open(args.answer_key, "w") as f:
        f.write("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
