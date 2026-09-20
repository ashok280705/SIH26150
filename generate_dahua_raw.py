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
  0x000200  DHAV packet, channel 1, H.264  [64B header][Annex-B payload]['dhav']
  <aligned> DHAV packet, channel 2, H.265  [64B header][Annex-B payload]['dhav']
  <aligned> DIDX recording index (one entry per packet)
  last sec. DHFS backup superblock

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


def build_annexb(src: str | None, out_path: str, codec: str, duration: int, size: str) -> str:
    """Produce an Annex-B elementary stream at `out_path`.

    `src` None  -> synthesise a test pattern with FFmpeg.
    `src` given -> transcode that file. Already-elementary inputs are copied as-is.
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
        input_args = ["-i", src]
    else:
        input_args = [
            "-f", "lavfi",
            "-i", f"testsrc2=size={size}:rate=15:duration={duration}",
        ]

    cmd = [
        ffmpeg, "-hide_banner", "-loglevel", "error", "-y",
        *input_args,
        "-t", str(duration),
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


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ch1", help="source video for channel 1 (encoded to H.264)")
    ap.add_argument("--ch2", help="source video for channel 2 (encoded to H.265)")
    ap.add_argument("--duration", type=int, default=8, help="clip length in seconds (default 8)")
    ap.add_argument("--size", default="1280x720", help="frame size for synthesised clips")
    ap.add_argument("--output", default=OUTPUT_PATH, help=f"output image (default {OUTPUT_PATH})")
    ap.add_argument("--image-size", default="4MiB",
                    help="minimum image size, e.g. 4MiB. The image grows past this "
                         "if the footage needs more room (default 4MiB)")
    args = ap.parse_args()

    os.makedirs(BUILD_DIR, exist_ok=True)
    ch1_es = os.path.join(BUILD_DIR, "ch1.h264")
    ch2_es = os.path.join(BUILD_DIR, "ch2.hevc")

    print("Preparing elementary streams...")
    build_annexb(args.ch1, ch1_es, "h264", args.duration, args.size)
    build_annexb(args.ch2, ch2_es, "h265", max(1, args.duration - 2), args.size)

    ch1_payload = open(ch1_es, "rb").read()
    ch2_payload = open(ch2_es, "rb").read()
    if not ch1_payload or not ch2_payload:
        die("an encoded elementary stream came out empty")

    ch1_info = probe_stream(ch1_es)
    ch2_info = probe_stream(ch2_es)

    # ---- Plan the layout so offsets are known before writing -----------------
    ch1_offset = SECTOR_SIZE
    ch1_total = DHAV_HEADER_SIZE + len(ch1_payload) + len(DHAV_FOOTER)
    ch2_offset = align_up(ch1_offset + ch1_total)
    ch2_total = DHAV_HEADER_SIZE + len(ch2_payload) + len(DHAV_FOOTER)
    index_offset = align_up(ch2_offset + ch2_total)
    index_size = 16 + 2 * 32

    # One spare sector for the backup superblock, then round the image to 1 MiB.
    # Padded up to --image-size so a previously registered evidence record whose
    # capacity was recorded at ingest stays consistent with the image on disk.
    min_size = align_up(index_offset + index_size) + SECTOR_SIZE
    disk_size = max(align_up(min_size, 1024 * 1024), parse_size(args.image_size))
    if disk_size > MAX_IMAGE_SIZE:
        die(f"image would be {disk_size / 1048576:.1f} MiB, beyond the parser's "
            f"{MAX_IMAGE_SIZE // 1048576} MiB scan window. Use a shorter --duration "
            f"or smaller --size.")

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
        ch1_offset,                 # dhav_start
        index_offset,               # index_offset (read back by parse_metadata)
        1726700000,                 # filesystem creation time
    )
    buf[48:64] = b"DHI-XVR5216AN".ljust(16, b"\x00")
    buf[64:96] = b"DH-SN-2024-XVR-0007A3F19C42BB01".ljust(32, b"\x00")
    buf[96:112] = b"DVR_REC_VOL0".ljust(16, b"\x00")
    struct.pack_into("<I", buf, 508, 0xD4A0A5EF)   # superblock checksum placeholder

    # ---- DHAV packets with real video ---------------------------------------
    ts1 = 1726700000
    ts2 = 1726703600
    pack_dhav_packet(
        buf, ch1_offset,
        channel_zero_based=0, frame_type=0xFD, frame_seq=1, timestamp=ts1,
        codec_label=b"H.264/AVC", channel_name=b"CH01_ENTRANCE",
        width=ch1_info["width"] or 1280, height=ch1_info["height"] or 720,
        payload=ch1_payload,
    )
    pack_dhav_packet(
        buf, ch2_offset,
        channel_zero_based=1, frame_type=0xFD, frame_seq=2, timestamp=ts2,
        codec_label=b"H.265/HEVC", channel_name=b"CH02_PARKING",
        width=ch2_info["width"] or 1280, height=ch2_info["height"] or 720,
        payload=ch2_payload,
    )

    # ---- DIDX recording index ----------------------------------------------
    # Header: [0..4] b"DIDX", [4..8] entry_count, [8..16] reserved
    # Entry (32B): [0] channel, [1] frame_type, [2..4] reserved,
    #              [4..12] offset, [12..20] length, [20..28] timestamp, [28..32] crc32
    buf[index_offset:index_offset + 4] = b"DIDX"
    struct.pack_into("<I", buf, index_offset + 4, 2)
    struct.pack_into("<BBHQQQI", buf, index_offset + 16,
                     0x00, 0xFD, 0x0000, ch1_offset, ch1_total, ts1, 0x1A2B3C4D)
    struct.pack_into("<BBHQQQI", buf, index_offset + 48,
                     0x01, 0xFD, 0x0000, ch2_offset, ch2_total, ts2, 0x5E6F7A8B)

    # ---- Backup superblock in the last sector -------------------------------
    backup = disk_size - SECTOR_SIZE
    buf[backup:backup + 4] = b"DHFS"
    struct.pack_into("<I", buf, backup + 4, 0x00010000)
    buf[backup + 8:backup + 24] = b"BACKUP_SUPERBLK".ljust(16, b"\x00")

    with open(args.output, "wb") as f:
        f.write(buf)

    print(f"\nWrote {args.output} ({len(buf):,} bytes / {len(buf) / 1048576:.2f} MiB)")
    print("\nLayout:")
    print(f"  0x{0:08X}  DHFS superblock (model DHI-XVR5216AN, volume DVR_REC_VOL0)")
    print(f"  0x{ch1_offset:08X}  DHAV ch1  {ch1_info['codec']} "
          f"{ch1_info['width']}x{ch1_info['height']} {ch1_info['frames']} frames, "
          f"payload {len(ch1_payload):,} B at 0x{ch1_offset + DHAV_HEADER_SIZE:08X}")
    print(f"  0x{ch2_offset:08X}  DHAV ch2  {ch2_info['codec']} "
          f"{ch2_info['width']}x{ch2_info['height']} {ch2_info['frames']} frames, "
          f"payload {len(ch2_payload):,} B at 0x{ch2_offset + DHAV_HEADER_SIZE:08X}")
    print(f"  0x{index_offset:08X}  DIDX index (2 entries)")
    print(f"  0x{backup:08X}  DHFS backup superblock")
    print("\nThe payloads are real Annex-B elementary streams, so reconstruction "
          "produces a playable MP4 via FFmpeg stream copy.")


if __name__ == "__main__":
    main()
