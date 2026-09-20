#!/usr/bin/env python3
"""
Generate a realistic Dahua DHFS DVR/NVR .raw evidence disk image containing REAL,
decodable video footage.

Unlike a signature-only fixture, the DHAV packets in this image carry genuine
H.264 and H.265 Annex-B elementary streams, so the full pipeline can be exercised
end to end: detection -> parsing -> recovery -> elementary-stream extraction ->
FFmpeg remux -> playback in the UI.

Usage
-----
  # Default: synthesise two clips with FFmpeg (reproducible, no network needed)
  python3 generate_dahua_raw.py

  # Use your own footage (any format FFmpeg can read, e.g. a Pexels CCTV mp4).
  # Channel 1 is encoded to H.264, channel 2 to H.265.
  python3 generate_dahua_raw.py --ch1 /path/to/cam1.mp4 --ch2 /path/to/cam2.mp4

  # Control clip length / resolution of synthesised footage
  python3 generate_dahua_raw.py --duration 10 --size 1280x720

Layout produced
---------------
  0x000000  DHFS superblock (magic 'DHFS' at offset 0, dynamic index_offset)
  0x000200  DHAV packet, one per recorded SEGMENT  [64B header][Annex-B payload]['dhav']
  <aligned>   ... many segments, interleaved by time across channel 1 (H.264) and
  <aligned>       channel 2 (H.265). Each segment is its own decodable clip and carries
  <aligned>       its own recorder timestamp, spaced --segment-interval apart.
  <aligned> DIDX recording index (one entry per segment)
  last sec. DHFS backup superblock

Each channel records at a fixed cadence with one or more slots deliberately SKIPPED,
so the platform's Preliminary Timeline reports those slots as missing footage (gaps)
inside an otherwise continuous recording. Segments are date-sorted on disk.

What this drives
----------------
  * Detector  (crates/detection/src/detectors/dahua.rs)
      'DHFS' at exact offset 0        -> primary magic
      'DHAV' within first 64 KiB      -> corroborating tag
      both                            -> DetectionStatus::Confirmed
  * Parser    (crates/parsers/dahua/src/parser.rs)
      parse_filesystem  -> PASS from the superblock
      parse_metadata    -> PASS from the DIDX index
      parse_recordings  -> one Recording per packet, region = payload span only
      extract_timeline_events / validate_structure -> PASS
  * Recovery  (POST /api/evidence/:id/recovery)
      codec classified from the real NAL units in the payload
  * Reconstruct (POST .../reconstruct) -> FFmpeg stream-copy remux to playable MP4
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys

SECTOR_SIZE = 512
DHAV_HEADER_SIZE = 64
DHAV_FOOTER = b"dhav"

# The Dahua parser scans a bounded 16 MiB window for DHAV packets, so the image is
# kept inside that window to stay fully discoverable.
MAX_IMAGE_SIZE = 16 * 1024 * 1024

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
    """Parse sizes like '4MiB', '8M', '512K', or a plain byte count."""
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


def is_elementary_stream(path: str) -> bool:
    return path.lower().endswith((".h264", ".264", ".hevc", ".h265", ".265"))


def build_segment_clip(src: str | None, out_path: str, codec: str,
                       clip_seconds: int, size: str, seg_index: int) -> str:
    """Produce ONE independently decodable Annex-B clip at `out_path`.

    Every segment is encoded on its own, so it carries its own SPS/PPS and can be
    remuxed to a playable MP4 in isolation — which is what lets the recovery stage
    reconstruct any single recording segment the timeline points at.

    `src` None  -> synthesise a short test pattern with FFmpeg.
    `src` given -> transcode a distinct window of that file. Already-elementary inputs
                   are copied verbatim (a raw ES cannot be reliably sliced here).
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
        # Loop the source so short inputs still fill every segment, and take a distinct
        # window per segment so consecutive clips are not identical.
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
        "-an",                      # no audio: DHAV payload here is video only
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


def parse_local_ist_to_unix(text: str) -> int:
    """Interpret `text` (YYYY-MM-DDThh:mm:ss) as an IST (UTC+05:30) wall clock.

    The Dahua parser reconstructs the recorder-native wall clock as `UTC + 05:30`, so
    encoding the timestamps in IST here makes the parsed native time read back exactly
    as the wall-clock values printed in the layout summary.
    """
    from datetime import datetime, timezone, timedelta
    try:
        dt = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        die(f"could not parse --start '{text}', expected YYYY-MM-DDThh:mm:ss")
    ist = timezone(timedelta(hours=5, minutes=30))
    return int(dt.replace(tzinfo=ist).timestamp())


def parse_gap_slots(text: str) -> set[int]:
    """Parse a comma-separated list of slot indices to omit (e.g. '2,3')."""
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


def pack_dhav_packet(buf: bytearray, offset: int, *, channel_zero_based: int,
                     frame_type: int, frame_seq: int, timestamp: int,
                     codec_label: bytes, channel_name: bytes,
                     width: int, height: int, payload: bytes) -> int:
    """Write one DHAV packet. Returns the total packet length in bytes.

    Header layout (little-endian, no padding):
      [0..4]   b"DHAV"
      [4]      frame_type   (0xFD = I-frame / keyframe)
      [5]      channel      (0-based on disk)
      [6..8]   reserved
      [8..12]  frame_seq    u32
      [12..16] packet_len   u32  total bytes DHAV..dhav inclusive
      [16..24] timestamp    u64  unix seconds
      [24..28] date_bcd     u32  Dahua-style packed date
      [28..30] width        u16
      [30..32] height       u16
      [32..48] codec        16B ASCII
      [48..64] channel_name 16B ASCII
    """
    packet_len = DHAV_HEADER_SIZE + len(payload) + len(DHAV_FOOTER)

    buf[offset:offset + 4] = b"DHAV"
    struct.pack_into(
        "<BBHIIQIHH", buf, offset + 4,
        frame_type,
        channel_zero_based,
        0x0000,                 # reserved
        frame_seq,
        packet_len,
        timestamp,
        0x20240919,             # packed date, consistent with the timestamps below
        width, height,
    )
    buf[offset + 32:offset + 48] = codec_label.ljust(16, b"\x00")[:16]
    buf[offset + 48:offset + 64] = channel_name.ljust(16, b"\x00")[:16]

    payload_start = offset + DHAV_HEADER_SIZE
    buf[payload_start:payload_start + len(payload)] = payload
    footer_at = payload_start + len(payload)
    buf[footer_at:footer_at + len(DHAV_FOOTER)] = DHAV_FOOTER
    return packet_len


def fmt_ist(unix_ts: int) -> str:
    """Format a unix timestamp as its IST (UTC+05:30) wall clock, matching the parser."""
    from datetime import datetime, timezone, timedelta
    ist = timezone(timedelta(hours=5, minutes=30))
    return datetime.fromtimestamp(unix_ts, ist).strftime("%Y-%m-%d %H:%M:%S")


# One camera's plan: which codec, name, and time slots it records, and which it skips.
class ChannelPlan:
    def __init__(self, index0: int, codec: str, ext: str, codec_label: bytes,
                 name: bytes, gap_slots: set):
        self.index0 = index0            # 0-based channel index stored on disk
        self.codec = codec              # "h264" | "h265"
        self.ext = ext                  # elementary-stream file extension
        self.codec_label = codec_label  # ASCII label in the DHAV header
        self.name = name                # ASCII channel name in the DHAV header
        self.gap_slots = gap_slots      # slot indices deliberately omitted (missing footage)
        self.width = 0
        self.height = 0


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
    ap.add_argument("--segments", type=int, default=7,
                    help="number of time slots per channel (default 7)")
    ap.add_argument("--segment-interval", type=int, default=300,
                    help="seconds between consecutive slots (default 300 = 5 min)")
    ap.add_argument("--start", default="2026-09-20T10:00:00",
                    help="IST wall clock of the first slot (default 2026-09-20T10:00:00)")
    ap.add_argument("--ch1-gaps", default="3",
                    help="comma-separated slot indices channel 1 omits (default '3')")
    ap.add_argument("--ch2-gaps", default="2,3",
                    help="comma-separated slot indices channel 2 omits (default '2,3')")
    ap.add_argument("--output", default=OUTPUT_PATH, help=f"output image (default {OUTPUT_PATH})")
    ap.add_argument("--image-size", default="4MiB",
                    help="minimum image size, e.g. 4MiB. The image grows past this "
                         "if the footage needs more room (default 4MiB)")
    args = ap.parse_args()

    clip_seconds = max(1, args.duration if args.duration is not None else args.clip_seconds)
    num_slots = max(1, args.segments)
    interval = max(1, args.segment_interval)
    base_unix = parse_local_ist_to_unix(args.start)

    os.makedirs(BUILD_DIR, exist_ok=True)

    channels = [
        ChannelPlan(0, "h264", "h264", b"H.264/AVC", b"CH01_ENTRANCE", parse_gap_slots(args.ch1_gaps)),
        ChannelPlan(1, "h265", "hevc", b"H.265/HEVC", b"CH02_PARKING", parse_gap_slots(args.ch2_gaps)),
    ]
    sources = {0: args.ch1, 1: args.ch2}

    # ---- Encode one independent clip per active slot, per channel ------------
    # A "segment" is a single recorded clip located at one time slot. Skipped slots
    # are the deliberate gaps the timeline must surface as missing footage.
    print("Encoding recording segments (one independent clip per slot)...")
    segments = []  # each: dict(channel0, codec_label, name, timestamp, payload, width, height, slot)
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
            segments.append({
                "channel0": ch.index0,
                "codec_label": ch.codec_label,
                "name": ch.name,
                "timestamp": base_unix + slot * interval,
                "payload": payload,
                "width": ch.width,
                "height": ch.height,
                "slot": slot,
            })

    if not segments:
        die("no segments were produced (every slot was skipped?)")

    # DIDX and physical layout read cleaner when segments are stored in time order.
    segments.sort(key=lambda s: (s["timestamp"], s["channel0"]))

    # ---- Plan the layout so offsets are known before writing -----------------
    cursor = SECTOR_SIZE
    for seg in segments:
        seg["offset"] = cursor
        seg["total"] = DHAV_HEADER_SIZE + len(seg["payload"]) + len(DHAV_FOOTER)
        cursor = align_up(cursor + seg["total"])

    dhav_start = segments[0]["offset"]
    index_offset = align_up(cursor)
    index_size = 16 + len(segments) * 32

    # One spare sector for the backup superblock, then round the image to 1 MiB.
    # Padded up to --image-size so a previously registered evidence record whose
    # capacity was recorded at ingest stays consistent with the image on disk.
    min_size = align_up(index_offset + index_size) + SECTOR_SIZE
    disk_size = max(align_up(min_size, 1024 * 1024), parse_size(args.image_size))
    if disk_size > MAX_IMAGE_SIZE:
        die(f"image would be {disk_size / 1048576:.1f} MiB, beyond the parser's "
            f"{MAX_IMAGE_SIZE // 1048576} MiB scan window. Use fewer --segments, a shorter "
            f"--clip-seconds, or a smaller --size.")

    buf = bytearray(disk_size)

    # ---- DHFS superblock at offset 0 ----------------------------------------
    # [0..4] magic, [4..8] version, [8..12] sector_size, [12..16] block_size,
    # [16..24] total_blocks, [24..32] dhav_start, [32..40] index_offset,
    # [40..48] ctime, [48..64] model, [64..96] serial, [96..112] volume label
    buf[0:4] = b"DHFS"
    struct.pack_into(
        "<IIIQQQQ", buf, 4,
        0x00010000,                 # version 1.0
        SECTOR_SIZE,
        65536,                      # block size
        disk_size // 65536,         # total blocks
        dhav_start,                 # dhav_start
        index_offset,               # index_offset (read back by parse_metadata)
        base_unix,                  # filesystem creation time
    )
    buf[48:64] = b"DHI-XVR5216AN".ljust(16, b"\x00")
    buf[64:96] = b"DH-SN-2024-XVR-0007A3F19C42BB01".ljust(32, b"\x00")
    buf[96:112] = b"DVR_REC_VOL0".ljust(16, b"\x00")
    struct.pack_into("<I", buf, 508, 0xD4A0A5EF)   # superblock checksum placeholder

    # ---- DHAV packets: one per recorded segment -----------------------------
    for seq, seg in enumerate(segments, start=1):
        pack_dhav_packet(
            buf, seg["offset"],
            channel_zero_based=seg["channel0"], frame_type=0xFD, frame_seq=seq,
            timestamp=seg["timestamp"], codec_label=seg["codec_label"],
            channel_name=seg["name"], width=seg["width"], height=seg["height"],
            payload=seg["payload"],
        )

    # ---- DIDX recording index (one entry per segment) -----------------------
    # Header: [0..4] b"DIDX", [4..8] entry_count, [8..16] reserved
    # Entry (32B): [0] channel, [1] frame_type, [2..4] reserved,
    #              [4..12] offset, [12..20] length, [20..28] timestamp, [28..32] crc32
    buf[index_offset:index_offset + 4] = b"DIDX"
    struct.pack_into("<I", buf, index_offset + 4, len(segments))
    for i, seg in enumerate(segments):
        entry = index_offset + 16 + i * 32
        struct.pack_into("<BBHQQQI", buf, entry,
                         seg["channel0"], 0xFD, 0x0000,
                         seg["offset"], seg["total"], seg["timestamp"], 0x1A2B3C4D + i)

    # ---- Backup superblock in the last sector -------------------------------
    backup = disk_size - SECTOR_SIZE
    buf[backup:backup + 4] = b"DHFS"
    struct.pack_into("<I", buf, backup + 4, 0x00010000)
    buf[backup + 8:backup + 24] = b"BACKUP_SUPERBLK".ljust(16, b"\x00")

    with open(args.output, "wb") as f:
        f.write(buf)

    # ---- Report --------------------------------------------------------------
    print(f"\nWrote {args.output} ({len(buf):,} bytes / {len(buf) / 1048576:.2f} MiB)")
    print("\nLayout:")
    print(f"  0x{0:08X}  DHFS superblock (model DHI-XVR5216AN, volume DVR_REC_VOL0)")
    for seg in segments:
        label = seg["codec_label"].decode().strip("\x00")
        print(f"  0x{seg['offset']:08X}  DHAV ch{seg['channel0'] + 1}  {label}  "
              f"{seg['width']}x{seg['height']}  {fmt_ist(seg['timestamp'])} IST  "
              f"payload {len(seg['payload']):,} B")
    print(f"  0x{index_offset:08X}  DIDX index ({len(segments)} entries)")
    print(f"  0x{backup:08X}  DHFS backup superblock")

    print("\nRecording timeline (recorder-native IST wall clock):")
    for ch in channels:
        active = [k for k in range(num_slots) if k not in ch.gap_slots]
        first_ts = base_unix + active[0] * interval
        last_ts = base_unix + active[-1] * interval
        gaps = sorted(ch.gap_slots & set(range(num_slots)))
        gap_desc = ", ".join(fmt_ist(base_unix + g * interval)[11:] for g in gaps) or "none"
        print(f"  ch{ch.index0 + 1} ({ch.name.decode()}): "
              f"{fmt_ist(first_ts)} -> {fmt_ist(last_ts)}  "
              f"{len(active)} segment(s), missing slot(s) at {gap_desc}")

    print("\nEach segment is an independently decodable Annex-B clip, so any single "
          "recording the timeline points at can be reconstructed to a playable MP4. "
          "Skipped slots appear as missing footage (gaps) in the Preliminary Timeline.")


if __name__ == "__main__":
    main()
