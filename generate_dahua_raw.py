#!/usr/bin/env python3
"""
Generate a Dahua **DHFS 4.1** DVR/NVR .raw evidence disk image containing REAL,
decodable video footage inside the real on-disk structures.

This writes the DHFS 4.1 structure set, not a flat "superblock + one index table"
stand-in:

    DHFS4.1 volume signature
      -> partition table            (0x3C00, identifier ........AA55AA55 at +304)
      -> partition information      (IndexStartSector / VideoStartSector / BlockCount)
      -> block table                (one 32-byte entry per 2 MiB video block)
      -> video blocks               (2 MiB each, linked by FirstBlock/NextBlock/PreviousBlock)
      -> DHII per-clip frame index  (inside selected blocks)
      -> DHAV frames                (24-byte header + TLV extra header + payload + trailer)

Usage
-----
  # Default: synthesise clips with FFmpeg (reproducible, no network needed)
  python3 generate_dahua_raw.py

  # Use your own footage (any format FFmpeg can read).
  # Channel 1 is encoded to H.264, channel 2 to H.265.
  python3 generate_dahua_raw.py --ch1 /path/to/cam1.mp4 --ch2 /path/to/cam2.mp4

  python3 generate_dahua_raw.py --clip-seconds 4 --size 1280x720 --segments 5

What the image contains, and why
--------------------------------
  * Accessible recordings: each active time slot becomes a block chain reached from a
    declared FirstBlock, so it classifies as Active.
  * One AVAILABLE recording: its blocks keep full metadata but no FirstBlock traversal
    reaches them. That is the real forensic situation of a recording the recorder no
    longer lists. It classifies as Orphaned — never as Deleted, because DHFS 4.1 carries
    no free/deallocated marker.
  * One loose DHAV frame in slack past the partition's video region: video no metadata
    describes at all, which classifies as Unindexed.
  * Deliberately skipped time slots, so the timeline reports missing footage.

Timestamps
----------
  DHAV and block-table times are written in Dahua's packed base-2000 encoding:

      bits 31..26 year-2000 | 25..22 month | 21..17 day | 16..12 hour | 11..6 min | 5..0 sec

  The recorder stores local wall-clock digits with **no** timezone. `--start` is read as
  those digits verbatim, and the report prints them the same way. No offset is applied
  anywhere, which is exactly what the parser does.

This is a synthetic image. It exercises the parser against the documented structures; it
is not evidence of compatibility with any particular Dahua firmware.
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys

SECTOR_SIZE = 512
VIDEO_BLOCK_SIZE = 2 * 1024 * 1024
BLOCK_ENTRY_SIZE = 32

DHFS41_SIGNATURE = b"DHFS4.1\x00"
PARTITION_TABLE_PRIMARY = 0x3C00
PARTITION_TABLE_IDENTIFIER_OFFSET = 304
PARTITION_ENTRY_STRIDE = 64
PARTITION_ID_GEN1 = bytes([0x01, 0x00, 0x00, 0x00, 0xAA, 0x55, 0xAA, 0x55])

# Partition internal layout, in sectors from the partition start.
PARTITION_START_SECTOR = 128
PARTITION_INFO_SECTOR = 1
INDEX_START_SECTOR = 2
VIDEO_START_SECTOR = 64

DHAV_FIXED_HEADER_SIZE = 24
DHAV_TRAILER_SIZE = 8
FRAME_TYPE_VIDEO_KEY = 0xFD

CODEC_H264 = 0x04
CODEC_H265 = 0x0C

DHII_TYPE_REFERENCE_FRAMES = 1
DHII_TYPE_JPEG_FRAMES = 3

TIMESTAMP_BASE_YEAR = 2000

BUILD_DIR = ".fixture_build"
OUTPUT_PATH = "dahua_dhfs_sample.raw"


def die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def require_ffmpeg() -> str:
    exe = shutil.which("ffmpeg")
    if not exe:
        die("ffmpeg not found on PATH. Install it (brew install ffmpeg) or pass "
            "pre-built .h264/.hevc elementary streams via --ch1/--ch2.")
    return exe


def align_up(value: int, alignment: int = SECTOR_SIZE) -> int:
    return (value + alignment - 1) // alignment * alignment


def parse_size(text: str) -> int:
    """Parse sizes like '32MiB', '8M', '512K', or a plain byte count."""
    t = text.strip().lower().replace("ib", "").replace("b", "")
    multiplier = 1
    if t.endswith("k"):
        multiplier, t = 1024, t[:-1]
    elif t.endswith("m"):
        multiplier, t = 1024 * 1024, t[:-1]
    elif t.endswith("g"):
        multiplier, t = 1024 * 1024 * 1024, t[:-1]
    try:
        return int(float(t) * multiplier)
    except ValueError:
        die(f"could not parse size: {text}")
        return 0  # unreachable; keeps type checkers happy


# ── Dahua packed timestamps ──────────────────────────────────────────────────

def pack_timestamp(year: int, month: int, day: int, hour: int, minute: int, second: int) -> int:
    """Encode wall-clock digits into Dahua's packed base-2000 field."""
    year_field = year - TIMESTAMP_BASE_YEAR
    if not 0 <= year_field <= 63:
        die(f"year {year} is outside the packed encoding's range ({TIMESTAMP_BASE_YEAR}..2063)")
    if not 1 <= month <= 15 or not 1 <= day <= 31 or hour > 31 or minute > 63 or second > 63:
        die(f"{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02} is not representable")
    return ((year_field << 26) | (month << 22) | (day << 17)
            | (hour << 12) | (minute << 6) | second)


def parse_wall_clock(text: str):
    """Parse `YYYY-MM-DDThh:mm:ss` as recorder wall-clock digits, with no timezone."""
    from datetime import datetime
    try:
        dt = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        die(f"could not parse --start '{text}', expected YYYY-MM-DDThh:mm:ss")
    return dt


def shift_wall_clock(dt, seconds: int):
    from datetime import timedelta
    return dt + timedelta(seconds=seconds)


def fmt_wall_clock(dt) -> str:
    """Print the recorder's own digits. No zone suffix, because none is recorded."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def packed_from_dt(dt) -> int:
    return pack_timestamp(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)


# ── Encoding source footage ──────────────────────────────────────────────────

def is_elementary_stream(path: str) -> bool:
    return path.lower().endswith((".h264", ".264", ".hevc", ".h265", ".265"))


def build_segment_clip(src, out_path: str, codec: str, clip_seconds: int,
                       size: str, seg_index: int) -> str:
    """Produce ONE independently decodable Annex-B clip at `out_path`.

    Every segment is encoded on its own, so it carries its own SPS/PPS and can be remuxed
    to a playable MP4 in isolation — which is what lets recovery reconstruct any single
    recording the timeline points at.
    """
    if src and is_elementary_stream(src):
        shutil.copyfile(src, out_path)
        return out_path

    ffmpeg = require_ffmpeg()
    encoder = "libx264" if codec == "h264" else "libx265"
    muxer = "h264" if codec == "h264" else "hevc"

    if src:
        if not os.path.isfile(src):
            die(f"input video not found: {src}")
        offset = seg_index * clip_seconds
        input_args = ["-stream_loop", "-1", "-i", src, "-ss", str(offset)]
    else:
        input_args = [
            "-f", "lavfi",
            "-i", f"testsrc2=size={size}:rate=15:duration={clip_seconds}",
        ]

    cmd = [
        ffmpeg, "-hide_banner", "-loglevel", "error", "-y",
        *input_args,
        "-t", str(clip_seconds),
        "-an",                      # no audio: the DHAV payload here is video only
        "-c:v", encoder,
        "-preset", "veryfast",
        "-crf", "30",
        "-g", "15",                 # frequent keyframes, typical of CCTV
        "-pix_fmt", "yuv420p",
        "-f", muxer,
        out_path,
    ]
    subprocess.run(cmd, check=True)
    return out_path


def probe_stream(path: str) -> dict:
    """Read real stream properties back out of the encoded elementary stream."""
    ffprobe = shutil.which("ffprobe")
    info = {"codec": "unknown", "width": 0, "height": 0, "frames": 0, "fps": 15}
    if not ffprobe:
        return info
    out = subprocess.run(
        [ffprobe, "-hide_banner", "-v", "error", "-count_frames",
         "-show_entries", "stream=codec_name,width,height,nb_read_frames,r_frame_rate",
         "-of", "default=nw=1", path],
        capture_output=True, text=True, check=False,
    ).stdout
    for line in out.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k == "codec_name":
            info["codec"] = v
        elif k == "width" and v.isdigit():
            info["width"] = int(v)
        elif k == "height" and v.isdigit():
            info["height"] = int(v)
        elif k == "nb_read_frames" and v.isdigit():
            info["frames"] = int(v)
        elif k == "r_frame_rate" and "/" in v:
            num, den = v.split("/", 1)
            try:
                if float(den) != 0:
                    info["fps"] = round(float(num) / float(den))
            except ValueError:
                pass
    return info


# ── Structure writers ────────────────────────────────────────────────────────

def build_dhav_frame(*, frame_type: int, channel_zero_based: int, frame_number: int,
                     packed_timestamp: int, codec_id: int, fps: int,
                     width: int, height: int, payload: bytes) -> bytes:
    """Serialize one DHAV frame with the real framing.

      +0   "DHAV"
      +4   u8  frame type          0xFD key, 0xFC delta, 0xF0 audio, 0xF1 info
      +5   u8  subtype
      +6   u16 channel             0-based
      +8   u32 frame number
      +12  i32 total length        DHAV .. trailer inclusive
      +16  u32 packed timestamp    base year 2000
      +20  u16 intra-second counter
      +22  u8  extra header length
      +23  u8  checksum
      +24      extra header        TLV records
      ...      elementary stream payload
      end-8    "dhav" + u32(total length - 8)
    """
    # Extra header: 0x82 exact resolution (8 bytes), then 0x81 codec + frame rate (4 bytes).
    extra = bytearray()
    extra += struct.pack("<BBBBHH", 0x82, 0, 0, 0, width, height)
    extra += struct.pack("<BBBB", 0x81, 0, codec_id, max(1, min(255, fps)))

    total = DHAV_FIXED_HEADER_SIZE + len(extra) + len(payload) + DHAV_TRAILER_SIZE
    out = bytearray()
    out += b"DHAV"
    out += struct.pack(
        "<BBHIIIHBB",
        frame_type,
        0x01,                       # subtype
        channel_zero_based,
        frame_number,
        total,
        packed_timestamp,
        0,                          # intra-second counter
        len(extra),
        0,                          # checksum
    )
    assert len(out) == DHAV_FIXED_HEADER_SIZE, len(out)
    out += extra
    out += payload
    out += b"dhav"
    out += struct.pack("<I", total - DHAV_TRAILER_SIZE)
    assert len(out) == total
    return bytes(out)


def build_dhii(arrays, base: int) -> bytes:
    """Serialize a DHII index destined for clip-relative offset `base`.

      +0   "DHII"
      +4   u32 index length
      +8   i32 header-entry count
      +12      header entries: u32 type, u32 clip-relative array offset, u32 array length
      entry:   u32 frame offset (clip-relative), i32 frame length, u32 packed timestamp
    """
    header_size, hdr_entry, entry = 12, 12, 12
    header_total = header_size + len(arrays) * hdr_entry
    arrays_total = sum(len(a["entries"]) * entry for a in arrays)
    index_length = header_total + arrays_total

    out = bytearray(index_length)
    out[0:4] = b"DHII"
    struct.pack_into("<Ii", out, 4, index_length, len(arrays))

    cursor = header_total
    for i, array in enumerate(arrays):
        h = header_size + i * hdr_entry
        length = len(array["entries"]) * entry
        struct.pack_into("<III", out, h, array["type"], base + cursor, length)
        for j, (off, ln, ts) in enumerate(array["entries"]):
            struct.pack_into("<IiI", out, cursor + j * entry, off, ln, ts)
        cursor += length
    return bytes(out)


def build_block_entry(*, type_byte: int, channel_1_based: int, start_ts: int, end_ts: int,
                      next_block: int, sector_count: int, previous_block: int,
                      first_block: int) -> bytes:
    """Serialize a 32-byte block-table entry.

      +0  u8  type              0xFE / 0x00 = empty
      +1  u8  legacy channel    (value & 0x0F) + 1
      +4  u32 start timestamp   packed
      +8  u32 end timestamp     packed
      +12 i32 NextBlock         -1 normalises to 0
      +16 i16 sectorCount       length of a LAST block, in 512-byte sectors
      +20 i32 PreviousBlock
      +24 i32 FirstBlock
      +29 u8  extended-channel flag (bit 0)
      +31 u8  extended channel
    """
    b = bytearray(32)
    b[0] = type_byte
    b[1] = (channel_1_based - 1) & 0x0F
    struct.pack_into("<II", b, 4, start_ts, end_ts)
    struct.pack_into("<ih", b, 12, next_block, sector_count)
    struct.pack_into("<ii", b, 20, previous_block, first_block)
    return bytes(b)


def build_partition_table(identifier: bytes, entries) -> bytes:
    """Serialize a 512-byte partition table: identifier at +304, entries every 64 bytes."""
    t = bytearray(512)
    t[PARTITION_TABLE_IDENTIFIER_OFFSET:PARTITION_TABLE_IDENTIFIER_OFFSET + 8] = identifier
    for slot, (info_sector, start_sector) in enumerate(entries):
        e = slot * PARTITION_ENTRY_STRIDE
        struct.pack_into("<i", t, e + 20, info_sector)
        struct.pack_into("<q", t, e + 48, start_sector)
    return bytes(t)


def parse_gap_slots(text: str) -> set:
    if not text:
        return set()
    slots = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            slots.add(int(part))
        except ValueError:
            die(f"invalid gap slot index: {part!r}")
    return slots


class ChannelPlan:
    def __init__(self, index0: int, codec: str, ext: str, codec_id: int, label: str,
                 gap_slots: set):
        self.index0 = index0
        self.codec = codec
        self.ext = ext
        self.codec_id = codec_id
        self.label = label
        self.gap_slots = gap_slots
        self.width = 0
        self.height = 0
        self.fps = 15


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ch1", help="source video for channel 1 (encoded to H.264)")
    ap.add_argument("--ch2", help="source video for channel 2 (encoded to H.265)")
    ap.add_argument("--clip-seconds", type=int, default=2,
                    help="length of each recorded segment clip, in seconds (default 2)")
    ap.add_argument("--duration", type=int, default=None,
                    help="alias for --clip-seconds (kept for backward compatibility)")
    ap.add_argument("--size", default="1280x720", help="frame size for synthesised clips")
    ap.add_argument("--segments", type=int, default=5,
                    help="number of time slots per channel (default 5)")
    ap.add_argument("--segment-interval", type=int, default=300,
                    help="seconds between consecutive slots (default 300 = 5 min)")
    ap.add_argument("--start", default="2026-09-20T10:00:00",
                    help="recorder wall clock of the first slot, with no timezone "
                         "(default 2026-09-20T10:00:00)")
    ap.add_argument("--ch1-gaps", default="3",
                    help="comma-separated slot indices channel 1 omits (default '3')")
    ap.add_argument("--ch2-gaps", default="2",
                    help="comma-separated slot indices channel 2 omits (default '2')")
    ap.add_argument("--output", default=OUTPUT_PATH, help=f"output image (default {OUTPUT_PATH})")
    ap.add_argument("--image-size", default="0",
                    help="minimum image size, e.g. 64MiB. The image is sized from the "
                         "structures it holds and grows past this if needed (default: exact)")
    ap.add_argument("--no-available-recording", action="store_true",
                    help="do not include an unreachable (available/orphaned) recording")
    ap.add_argument("--no-loose-frame", action="store_true",
                    help="do not place an unindexed DHAV frame in trailing slack")
    args = ap.parse_args()

    clip_seconds = max(1, args.duration if args.duration is not None else args.clip_seconds)
    num_slots = max(1, args.segments)
    interval = max(1, args.segment_interval)
    start_dt = parse_wall_clock(args.start)

    os.makedirs(BUILD_DIR, exist_ok=True)

    channels = [
        ChannelPlan(0, "h264", "h264", CODEC_H264, "H.264/AVC", parse_gap_slots(args.ch1_gaps)),
        ChannelPlan(1, "h265", "hevc", CODEC_H265, "H.265/HEVC", parse_gap_slots(args.ch2_gaps)),
    ]
    sources = {0: args.ch1, 1: args.ch2}

    # ── Encode one independent clip per active slot, per channel ─────────────
    print("Encoding recording segments (one independent clip per slot)...")
    segments = []
    for ch in channels:
        active = [k for k in range(num_slots) if k not in ch.gap_slots]
        for pos, slot in enumerate(active):
            out = os.path.join(BUILD_DIR, f"ch{ch.index0 + 1}_seg{slot}.{ch.ext}")
            build_segment_clip(sources[ch.index0], out, ch.codec, clip_seconds, args.size, pos)
            payload = open(out, "rb").read()
            if not payload:
                die(f"encoded segment came out empty: {out}")
            if ch.width == 0:
                info = probe_stream(out)
                ch.width = info["width"] or 1280
                ch.height = info["height"] or 720
                ch.fps = info["fps"] or 15
            if len(payload) + 4096 > VIDEO_BLOCK_SIZE:
                die(f"segment {out} is {len(payload):,} bytes, too large for one 2 MiB video "
                    f"block. Use a shorter --clip-seconds or a smaller --size.")
            segments.append({
                "channel0": ch.index0,
                "channel1": ch.index0 + 1,
                "codec_id": ch.codec_id,
                "label": ch.label,
                "fps": ch.fps,
                "dt": shift_wall_clock(start_dt, slot * interval),
                "end_dt": shift_wall_clock(start_dt, slot * interval + clip_seconds),
                "payload": payload,
                "width": ch.width,
                "height": ch.height,
                "slot": slot,
            })

    if not segments:
        die("no segments were produced (every slot was skipped?)")

    # The block table and the physical layout read cleaner in time order.
    segments.sort(key=lambda s: (s["dt"], s["channel0"]))

    # One recording is deliberately made unreachable: full block metadata, but no
    # FirstBlock traversal reaches it. That is the *available* case, and it is not deletion.
    available_index = None
    if not args.no_available_recording and len(segments) >= 3:
        available_index = len(segments) - 1

    # ── Plan the layout ──────────────────────────────────────────────────────
    partition_base = PARTITION_START_SECTOR * SECTOR_SIZE
    info_offset = partition_base + PARTITION_INFO_SECTOR * SECTOR_SIZE
    block_table_offset = partition_base + INDEX_START_SECTOR * SECTOR_SIZE
    video_base = partition_base + VIDEO_START_SECTOR * SECTOR_SIZE

    # Block 0 is left as an unused slot, so `FirstBlock > 0` stays meaningful: a zeroed
    # FirstBlock in block 0 must not look like the head of a recording.
    block_count = len(segments) + 1
    video_end = video_base + block_count * VIDEO_BLOCK_SIZE

    loose_offset = None
    disk_size = video_end
    if not args.no_loose_frame:
        loose_offset = video_end + 0x1000
        disk_size = loose_offset + VIDEO_BLOCK_SIZE // 16
    disk_size = align_up(disk_size + SECTOR_SIZE)
    disk_size = max(disk_size, align_up(parse_size(args.image_size)))

    buf = bytearray(disk_size)

    # ── Volume signature and descriptors ────────────────────────────────────
    buf[0:len(DHFS41_SIGNATURE)] = DHFS41_SIGNATURE
    buf[48:64] = b"DHI-XVR5216AN".ljust(16, b"\x00")
    buf[64:96] = b"DH-SN-2024-XVR-0007A3F19C42BB01".ljust(32, b"\x00")
    buf[96:112] = b"DVR_REC_VOL0".ljust(16, b"\x00")

    # ── Partition table, one partition ──────────────────────────────────────
    table = build_partition_table(PARTITION_ID_GEN1,
                                 [(PARTITION_INFO_SECTOR, PARTITION_START_SECTOR)])
    buf[PARTITION_TABLE_PRIMARY:PARTITION_TABLE_PRIMARY + len(table)] = table

    # ── Partition information ───────────────────────────────────────────────
    struct.pack_into("<iii", buf, info_offset + 68,
                     INDEX_START_SECTOR, VIDEO_START_SECTOR, block_count)

    # ── Video blocks, block table, and per-block DHII indexes ───────────────
    # Block 0 stays empty; segment i lives in block i+1.
    buf[block_table_offset:block_table_offset + BLOCK_ENTRY_SIZE] = build_block_entry(
        type_byte=0xFE, channel_1_based=1, start_ts=0, end_ts=0,
        next_block=0, sector_count=0, previous_block=0, first_block=0,
    )

    for i, seg in enumerate(segments):
        block_number = i + 1
        block_offset = video_base + block_number * VIDEO_BLOCK_SIZE
        packed = packed_from_dt(seg["dt"])
        packed_end = packed_from_dt(seg["end_dt"])

        frame = build_dhav_frame(
            frame_type=FRAME_TYPE_VIDEO_KEY,
            channel_zero_based=seg["channel0"],
            frame_number=i + 1,
            packed_timestamp=packed,
            codec_id=seg["codec_id"],
            fps=seg["fps"],
            width=seg["width"],
            height=seg["height"],
            payload=seg["payload"],
        )

        # Every second recording also gets a DHII reference-frame index, so both the
        # index-ordered and the container-walk reconstruction paths are exercised.
        if i % 2 == 0:
            index = build_dhii(
                [
                    {"type": DHII_TYPE_REFERENCE_FRAMES, "entries": []},
                    {"type": DHII_TYPE_JPEG_FRAMES, "entries": []},
                ],
                0,
            )
            frame_at = align_up(len(index), 512)
            index = build_dhii(
                [
                    {"type": DHII_TYPE_REFERENCE_FRAMES,
                     "entries": [(frame_at, len(frame), packed)]},
                    {"type": DHII_TYPE_JPEG_FRAMES, "entries": []},
                ],
                0,
            )
            buf[block_offset:block_offset + len(index)] = index
            seg["dhii_offset"] = block_offset
        else:
            frame_at = 0
            seg["dhii_offset"] = None

        frame_abs = block_offset + frame_at
        buf[frame_abs:frame_abs + len(frame)] = frame
        seg["block_number"] = block_number
        seg["block_offset"] = block_offset
        seg["frame_offset"] = frame_abs
        seg["frame_len"] = len(frame)

        # A single-block recording is both first and last: sectorCount gives its filled
        # length, and the whole occupied span must be covered so the frame sits inside it.
        filled = align_up(frame_at + len(frame), SECTOR_SIZE)
        sector_count = min(filled // SECTOR_SIZE, VIDEO_BLOCK_SIZE // SECTOR_SIZE)

        if i == available_index:
            # No FirstBlock, and a PreviousBlock pointing at a block outside any chain:
            # valid recording metadata that no traversal reaches.
            entry = build_block_entry(
                type_byte=0x01, channel_1_based=seg["channel1"],
                start_ts=packed, end_ts=packed_end,
                next_block=0, sector_count=sector_count,
                previous_block=block_count + 4, first_block=0,
            )
            seg["accessibility"] = "available"
        else:
            entry = build_block_entry(
                type_byte=0x01, channel_1_based=seg["channel1"],
                start_ts=packed, end_ts=packed_end,
                next_block=0, sector_count=sector_count,
                previous_block=0, first_block=block_number,
            )
            seg["accessibility"] = "accessible"

        at = block_table_offset + block_number * BLOCK_ENTRY_SIZE
        buf[at:at + BLOCK_ENTRY_SIZE] = entry

    # ── One loose frame in slack: video no metadata describes ───────────────
    if loose_offset is not None:
        loose = build_dhav_frame(
            frame_type=FRAME_TYPE_VIDEO_KEY,
            channel_zero_based=3,
            frame_number=1,
            packed_timestamp=packed_from_dt(shift_wall_clock(start_dt, -interval)),
            codec_id=CODEC_H264,
            fps=15,
            width=704, height=576,
            payload=segments[0]["payload"],
        )
        if loose_offset + len(loose) > len(buf):
            buf.extend(bytearray(loose_offset + len(loose) + SECTOR_SIZE - len(buf)))
        buf[loose_offset:loose_offset + len(loose)] = loose

    with open(args.output, "wb") as f:
        f.write(buf)

    # ── Report ──────────────────────────────────────────────────────────────
    print(f"\nWrote {args.output} ({len(buf):,} bytes / {len(buf) / 1048576:.2f} MiB)")
    print("\nDHFS 4.1 layout:")
    print(f"  0x{0:08X}  DHFS4.1 volume signature (model DHI-XVR5216AN, volume DVR_REC_VOL0)")
    print(f"  0x{PARTITION_TABLE_PRIMARY:08X}  partition table, identifier "
          f"{PARTITION_ID_GEN1.hex(' ').upper()} at +{PARTITION_TABLE_IDENTIFIER_OFFSET}")
    print(f"  0x{info_offset:08X}  partition information "
          f"(IndexStartSector={INDEX_START_SECTOR}, VideoStartSector={VIDEO_START_SECTOR}, "
          f"BlockCount={block_count})")
    print(f"  0x{block_table_offset:08X}  block table, {block_count} x {BLOCK_ENTRY_SIZE}B entries")
    print(f"  0x{video_base:08X}  video blocks, {VIDEO_BLOCK_SIZE // (1024 * 1024)} MiB each")
    print(f"             block 0: unused slot (not a deletion marker)")
    for seg in segments:
        dhii = f", DHII @0x{seg['dhii_offset']:08X}" if seg["dhii_offset"] else ""
        print(f"             block {seg['block_number']}: ch{seg['channel1']} {seg['label']} "
              f"{seg['width']}x{seg['height']}  {fmt_wall_clock(seg['dt'])}  "
              f"DHAV @0x{seg['frame_offset']:08X} ({seg['frame_len']:,} B)  "
              f"{seg['accessibility']}{dhii}")
    if loose_offset is not None:
        print(f"  0x{loose_offset:08X}  loose DHAV frame in slack (no metadata describes it)")

    print("\nExpected classification:")
    accessible = sum(1 for s in segments if s["accessibility"] == "accessible")
    available = sum(1 for s in segments if s["accessibility"] == "available")
    print(f"  Active     x{accessible}  block chains reached from a declared FirstBlock")
    print(f"  Orphaned   x{available}  surviving metadata the recorder no longer reaches "
          f"(available, NOT deleted)")
    if loose_offset is not None:
        print("  Unindexed  x1  video in slack that no metadata describes")
    print("  Deleted    x0  DHFS 4.1 carries no free/deallocated marker, so no deletion "
          "conclusion is available")

    print("\nRecording timeline (recorder wall clock, no timezone recorded):")
    for ch in channels:
        active = [k for k in range(num_slots) if k not in ch.gap_slots]
        if not active:
            continue
        first = shift_wall_clock(start_dt, active[0] * interval)
        last = shift_wall_clock(start_dt, active[-1] * interval)
        gaps = sorted(ch.gap_slots & set(range(num_slots)))
        gap_desc = ", ".join(
            fmt_wall_clock(shift_wall_clock(start_dt, g * interval))[11:] for g in gaps
        ) or "none"
        print(f"  ch{ch.index0 + 1} ({ch.label}): {fmt_wall_clock(first)} -> "
              f"{fmt_wall_clock(last)}  {len(active)} segment(s), missing slot(s) at {gap_desc}")

    print("\nEach recording is an independently decodable Annex-B clip inside real DHFS 4.1 "
          "structures, so any single recording the timeline points at can be reconstructed to a "
          "playable MP4. This image is synthetic: it exercises the parser against the documented "
          "structures and is not evidence of compatibility with any particular firmware.")


if __name__ == "__main__":
    main()
