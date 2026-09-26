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
import glob
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone, timedelta

SECTOR_SIZE = 512
DHAV_HEADER_SIZE = 64
DHAV_FOOTER = b"dhav"

MAX_IMAGE_SIZE = 16 * 1024 * 1024
BUILD_DIR = ".fixture_build"
OUTPUT_PATH = "dvr_3day_sample.raw"
ANSWER_KEY_PATH = ".fixture_build/ANSWER_KEY_dvr_3day.md"
IST = timezone(timedelta(hours=5, minutes=30))

# Where dropped-in real source clips are looked for, and the video extensions we accept.
FOOTAGE_DIR = "footage"
VIDEO_EXTS = (".mp4", ".mov", ".mkv", ".m4v", ".webm", ".avi", ".ts")
# A desktop browser UA — the Pexels /download endpoint 302-redirects to the CDN mp4
# for a real request; it is not behind the JS challenge that guards the HTML pages.
PEXELS_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/125.0 Safari/537.36")

# A daily recording is SLOTS_PER_DAY consecutive segments at `seg` cadence, so the
# camera shows continuous footage for the whole day (e.g. 12 x 10s = 120s). Some interior
# segments are randomly "lost": their real bytes are written (unindexed) into the physical
# gap between the surrounding present segments, so a recovery scan can carve them back and
# the complete footage is restored.
SLOTS_PER_DAY = 12
# Fixed byte size for each lost (orphan) segment slot, a multiple of 512 so the recovery
# engine's proportional time->byte sub-slot mapping over a gap lands cleanly on each slot.
SLOT_BYTES = 160 * 1024
# Leading zero pad inside each orphan slot; keeps a slot's real content clear of the small
# boundary bleed from the proportional sub-slot mapping (a few hundred bytes at most).
LEAD_PAD = 1024
# Lost runs are made at least this many segments long so the missing span exceeds the
# pipeline's default in-recording gap threshold (30s at a 10s cadence => >=3 segments).
MIN_LOST_RUN = 3
MAX_LOST_RUN = 4


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


def download_pexels_video(video_id: str, out_path: str) -> str:
    """Fetch a Pexels stock video by id via the public /download endpoint.

    That endpoint 302-redirects to the CDN mp4 and — unlike the HTML search pages —
    is not behind the Cloudflare JS challenge, so a plain HTTP client can follow it.
    The numeric id is the trailing number in a Pexels video URL, e.g.
    https://www.pexels.com/video/<slug>-<ID>/ .
    """
    url = f"https://www.pexels.com/download/video/{video_id}/"
    req = urllib.request.Request(url, headers={"User-Agent": PEXELS_UA})
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:  # follows redirects
            ctype = resp.headers.get("Content-Type", "")
            if "video" not in ctype:
                die(f"Pexels id {video_id} did not resolve to a video (Content-Type "
                    f"'{ctype}'). Use the id from a /video/ page, not a photo.")
            data = resp.read()
    except urllib.error.URLError as e:
        die(f"could not download Pexels video {video_id}: {e}")
    if not data:
        die(f"Pexels video {video_id} download was empty")
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"    downloaded {len(data)/1048576:.1f} MiB from Pexels id {video_id}")
    return out_path


def resolve_source(ch_index: int, explicit_path, pexels_id, footage_dir: str, used: set) -> str | None:
    """Resolve the real source video for a channel, or None to fall back to testsrc2.

    Precedence: explicit --footage-chN path > --pexels-chN download > first unused
    video file dropped in `footage_dir`.
    """
    if explicit_path:
        if not os.path.exists(explicit_path):
            die(f"--footage-ch{ch_index + 1} file not found: {explicit_path}")
        return explicit_path
    if pexels_id:
        # Accept a bare id or a full pexels.com/video/... URL (use the trailing number).
        digits = re.findall(r"\d+", str(pexels_id))
        if not digits:
            die(f"--pexels-ch{ch_index + 1} '{pexels_id}' has no numeric video id")
        vid = digits[-1]
        out = os.path.join(BUILD_DIR, f"src_ch{ch_index + 1}.mp4")
        print(f"  CH0{ch_index + 1}: downloading Pexels video {vid} ...")
        return download_pexels_video(vid, out)
    if os.path.isdir(footage_dir):
        files = sorted(
            p for p in glob.glob(os.path.join(footage_dir, "*"))
            if p.lower().endswith(VIDEO_EXTS)
        )
        # Prefer a channel-specific name, else the first file not already claimed.
        preferred = [p for p in files if f"ch{ch_index + 1}" in os.path.basename(p).lower()]
        for cand in preferred + files:
            if cand not in used:
                used.add(cand)
                return cand
        if files:  # only one file for two channels — reuse it (a different window is sliced)
            return files[0]
    return None


def encode_clip(codec: str, seconds: int, size: str, fps: int, crf: int, out_path: str,
                *, source: str | None = None, start: int = 0) -> bytes:
    """Encode one 10s elementary-stream clip that fits a gap slot and carries no 'DHAV'.

    With `source`, a real video is sliced (`start`..`start+seconds`), scaled to `size`,
    and re-encoded to the channel's codec — this is the "real footage" path. Without a
    source, a synthetic testsrc2 pattern is used (the offline fallback). In both cases
    the retry loop raises CRF until the payload fits `SLOT_BYTES` and contains no stray
    packet tag, so the physical layout and recovery model are unchanged.
    """
    ffmpeg = require("ffmpeg")
    encoder = "libx264" if codec == "h264" else "libx265"
    muxer = "h264" if codec == "h264" else "hevc"
    width, height = size.split("x")
    forbidden = b"DHAV"
    for attempt in range(8):
        this_crf = crf + attempt * 3
        if source:
            # Loop the input so a short clip still yields a full `seconds` window, then
            # take a frame-accurate output-side slice and normalize to the DVR geometry.
            input_args = ["-stream_loop", "-1", "-i", source]
            vf = f"scale={width}:{height},fps={fps}"
        else:
            input_args = ["-f", "lavfi", "-i", f"testsrc2=size={size}:rate={fps}:duration={seconds}"]
            vf = f"fps={fps}"
        cmd = [
            ffmpeg, "-hide_banner", "-loglevel", "error", "-y",
            *input_args,
            "-ss", str(start), "-t", str(seconds), "-an",
            "-c:v", encoder, "-preset", "veryfast", "-crf", str(this_crf),
            "-g", str(fps), "-vf", vf, "-pix_fmt", "yuv420p", "-f", muxer, out_path,
        ]
        subprocess.run(cmd, check=True)
        data = open(out_path, "rb").read()
        if not data:
            die(f"encoded clip is empty: {out_path}")
        if forbidden not in data and len(data) + LEAD_PAD <= SLOT_BYTES:
            return data
    die(f"could not encode a {codec} clip that fits a slot and avoids the packet tag "
        f"(source={'real' if source else 'testsrc2'}); try a lower --fps or --size")
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


def probe_duration(path: str) -> float:
    """Duration of a media file in seconds (0.0 if it cannot be determined)."""
    ffprobe = shutil.which("ffprobe")
    if not ffprobe or not path or not os.path.exists(path):
        return 0.0
    out = subprocess.run(
        [ffprobe, "-hide_banner", "-v", "error",
         "-show_entries", "format=duration", "-of", "default=nw=1:nk=1", path],
        capture_output=True, text=True, check=False,
    ).stdout.strip()
    try:
        return float(out)
    except ValueError:
        return 0.0


def clean_orphan(payload: bytes) -> bytes:
    """Wrap a real decodable clip as one fixed-size lost-segment slot.

    The payload is a valid elementary stream (SPS/PPS + IDR + slices), placed after a
    short zero lead. A recovery scan over this slot classifies it as a clean L1 stream and
    carves it back — this is the "lost footage" the recovery engine restores.
    """
    if len(payload) + LEAD_PAD > SLOT_BYTES:
        die(f"segment payload {len(payload)}B does not fit a {SLOT_BYTES}B slot")
    b = bytearray(SLOT_BYTES)  # zero-filled
    b[LEAD_PAD:LEAD_PAD + len(payload)] = payload
    return bytes(b)


def choose_lost_slots(n_slots: int, rng: random.Random) -> tuple[list[int], list[list[int]]]:
    """Randomly pick interior segments to lose, grouped into runs of >= MIN_LOST_RUN.

    Runs never touch the first/last slot (so each gap is bounded by present segments) and
    are separated by at least one present segment (so they read as distinct gaps).

    Crucial invariant: present segments must stay the MAJORITY so the timeline's measured
    cadence (median spacing between present segments) equals the true `clip` cadence and
    the losses register as in-recording gaps. With G runs the present set splits into G+1
    contiguous groups, giving (present - G - 1) cadence-length deltas vs G gap deltas; we
    need cadence deltas to dominate, i.e. present > 2*G + 1. Two runs therefore use the
    minimum length so `present >= 6 > 5`; a single run may be a little longer.

    Returns (sorted lost slots, list of runs).
    """
    num_runs = rng.choice([1, 1, 2])  # usually one gap per day, sometimes two
    lost: set = set()
    runs: list[list[int]] = []
    attempts = 0
    while len(runs) < num_runs and attempts < 80:
        attempts += 1
        rlen = MIN_LOST_RUN if num_runs == 2 else rng.randint(MIN_LOST_RUN, min(5, n_slots - 3))
        if n_slots - 1 - rlen < 1:
            break
        start = rng.randint(1, n_slots - 1 - rlen)
        run = set(range(start, start + rlen))
        if 0 in run or (n_slots - 1) in run:
            continue
        buffer = set()
        for x in run:
            buffer.update({x - 1, x, x + 1})  # keep >=1 present segment around each run
        if buffer & lost:
            continue
        lost |= run
        runs.append(sorted(run))
    # Safety: never let losses reach the majority (would corrupt the measured cadence).
    while len(lost) > n_slots - (2 * len(runs) + 2) and runs:
        drop = runs[-1]
        if len(drop) <= MIN_LOST_RUN:
            break
        lost.discard(drop[-1])
        runs[-1] = drop[:-1]
    runs.sort()
    return sorted(lost), runs


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
    # ── Real-footage sources (instead of the synthetic testsrc2 pattern) ──────
    ap.add_argument("--footage-dir", default=FOOTAGE_DIR,
                    help="folder scanned for real source clips (default: ./footage). "
                         "Drop cctv_ch1.mp4 / cctv_ch2.mp4 (or any videos) here.")
    ap.add_argument("--footage-ch1", help="path to a real source video for CH01 (H.264)")
    ap.add_argument("--footage-ch2", help="path to a real source video for CH02 (H.265)")
    ap.add_argument("--pexels-ch1", help="Pexels video id to download + use for CH01 "
                                         "(trailing number of a pexels.com/video/... URL)")
    ap.add_argument("--pexels-ch2", help="Pexels video id to download + use for CH02")
    ap.add_argument("--clip-start-ch1", type=int, default=0,
                    help="seconds into the CH01 source to start the first segment")
    ap.add_argument("--clip-start-ch2", type=int, default=0,
                    help="seconds into the CH02 source to start the first segment")
    ap.add_argument("--slots-per-day", type=int, default=SLOTS_PER_DAY,
                    help="segments per daily recording (each --clip-seconds long)")
    ap.add_argument("--seed", type=int, default=20260918,
                    help="RNG seed for which segments are randomly lost (reproducible)")
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

    # Resolve a real source video per channel (explicit path > Pexels id > footage dir),
    # falling back to the synthetic pattern when nothing is supplied.
    print("Resolving per-channel footage...")
    used_sources: set = set()
    explicit = [args.footage_ch1, args.footage_ch2]
    pexels = [args.pexels_ch1, args.pexels_ch2]
    starts = [max(0, args.clip_start_ch1), max(0, args.clip_start_ch2)]
    sources = [resolve_source(i, explicit[i], pexels[i], args.footage_dir, used_sources)
               for i in range(len(channels))]
    # If both channels landed on the SAME single dropped-in file, slice a later window
    # for CH02 so the two cameras don't show identical footage.
    if sources[0] and sources[0] == sources[1] and starts[1] == 0:
        starts[1] = clip
    downloaded = [os.path.join(BUILD_DIR, f"src_ch{i + 1}.mp4") for i in range(len(channels))]

    n_slots = max(4, args.slots_per_day)
    rng = random.Random(args.seed)

    # Encode one decodable segment per (channel, slot). Consecutive slots slice successive
    # windows of the real footage, so playing a day's segments in order shows continuous
    # footage. Segments are cached per (channel, slot) and reused across the 3 days.
    print(f"Encoding {n_slots} segment(s)/day per channel (each {clip}s)...")
    seg_payloads: list[list[bytes]] = []
    for i, ch in enumerate(channels):
        src = sources[i]
        # Cycle the slice start within the clip so each segment is real footage and the
        # output-side seek stays small/fast; when there's no source this shifts testsrc2.
        dur = probe_duration(src) if src else 0.0
        span = max(1, int(dur) - clip) if dur > clip else 1
        out = os.path.join(BUILD_DIR, f"base_{ch.codec}.{ch.ext}")
        payloads: list[bytes] = []
        for slot in range(n_slots):
            start = (starts[i] + slot * clip) % span if src else (starts[i] + slot * clip)
            payloads.append(encode_clip(ch.codec, clip, args.size, args.fps, args.crf, out,
                                        source=src, start=start))
            if slot == 0:
                ch.width, ch.height = probe(out)
                ch.width = ch.width or int(args.size.split("x")[0])
                ch.height = ch.height or int(args.size.split("x")[1])
        seg_payloads.append(payloads)
        origin = f"REAL: {os.path.basename(src)}" if src else "synthetic testsrc2"
        avg = sum(len(p) for p in payloads) // len(payloads)
        print(f"  {ch.name.decode()}: {ch.codec} {ch.width}x{ch.height} "
              f"{n_slots} seg, ~{avg:,} B/seg  [{origin}]")

    # Reclaim disk: payloads are in memory, so drop any downloaded source mp4s.
    for d in downloaded:
        if os.path.exists(d):
            try:
                os.remove(d)
            except OSError:
                pass

    if not any(sources):
        print("  NOTE: no real footage supplied — used the synthetic testsrc2 pattern.")
        print("        Provide real footage via --footage-ch1/--footage-ch2, "
              "--pexels-ch1/--pexels-ch2, or by dropping clips in ./footage/.")

    # ── Pass 1: plan the physical layout ──────────────────────────────────────
    # Per (channel, day): SLOTS_PER_DAY segments at `clip`s cadence form one daily
    # recording. Present segments are indexed DHAV packets; randomly lost segments become
    # fixed-size orphan slots written into the physical gap between the surrounding present
    # packets, exactly where the recovery scan looks.
    active = []   # indexed present segments -> DHAV packets + DIDX entries
    orphans = []  # lost segments -> unindexed bytes in the gap (recoverable)
    schedule = {} # (channel0, day) -> (lost_slots, runs)
    seq = 0
    cursor = SECTOR_SIZE

    for i, ch in enumerate(channels):
        for d in range(days):
            day0 = base + d * day_secs
            lost, runs = choose_lost_slots(n_slots, rng)
            schedule[(ch.index0, d)] = (lost, runs)
            for slot in range(n_slots):
                ts = day0 + slot * clip
                payload = seg_payloads[i][slot]
                if slot in lost:
                    orphans.append(dict(offset=cursor, content=clean_orphan(payload),
                                        channel0=ch.index0, timestamp=ts, slot=slot, day=d,
                                        payload_len=len(payload)))
                    cursor += SLOT_BYTES
                else:
                    cursor = align_up(cursor)
                    seq += 1
                    active.append(dict(offset=cursor, channel0=ch.index0, timestamp=ts,
                                       payload=payload, label=ch.label, name=ch.name,
                                       w=ch.width, h=ch.height, seq=seq, slot=slot, day=d))
                    cursor += DHAV_HEADER_SIZE + len(payload) + len(DHAV_FOOTER)
            cursor = align_up(cursor)

    index_offset = align_up(cursor)
    index_size = 16 + len(active) * 32
    min_size = align_up(index_offset + index_size) + SECTOR_SIZE
    disk_size = align_up(max(align_up(min_size, 1024 * 1024), parse_size(args.image_size)), 1024 * 1024)
    if disk_size > MAX_IMAGE_SIZE:
        die(f"image would be {disk_size/1048576:.1f} MiB (> {MAX_IMAGE_SIZE//1048576} MiB "
            f"window). Reduce --slots-per-day (now {n_slots}) or --size.")

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

    n_ch = len(channels)
    n_gaps = sum(len(runs) for (_lost, runs) in schedule.values())
    print(f"\nWrote {args.output} ({len(buf):,} bytes / {len(buf)/1048576:.2f} MiB)")
    print(f"  daily recordings (sessions)      : {n_ch * days} ({days}/channel, one per day)")
    print(f"  segments/day/channel             : {n_slots} ({clip}s each => {n_slots*clip}s of footage/day)")
    print(f"  present (indexed) segments       : {len(active)}")
    print(f"  randomly lost segments (in gaps) : {len(orphans)} across {n_gaps} gap(s) — recoverable")
    print(f"  channels                         : {n_ch}")
    print(f"\nGround-truth answer key: {args.answer_key} (open only after testing detection)")

    write_answer_key(args, channels, active, orphans, schedule, disk_size, index_offset,
                     days, clip, n_slots)


def write_answer_key(args, channels, active, orphans, schedule, disk_size, index_offset,
                     days, clip, n_slots):
    n_ch = len(channels)
    day_secs_total = n_slots * clip
    n_gaps = sum(len(runs) for (_lost, runs) in schedule.values())
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
    L.append(f"- {n_ch} channels (CH01 H.264, CH02 H.265), {days} days.")
    L.append(f"- **One daily recording (session) per channel per day** = **{n_ch*days} sessions total**.")
    L.append(f"- Each daily recording is {n_slots} contiguous **{clip}s** segments = **{day_secs_total}s** of")
    L.append("  continuous footage, sliced from the real uploaded clip. Playing a day's present")
    L.append("  segments in order shows the whole footage.")
    L.append("- Some interior segments are **randomly lost** (RNG seed "
             f"{args.seed}) in runs of {MIN_LOST_RUN}-{MAX_LOST_RUN} segments; each lost segment's real")
    L.append("  bytes are written UNINDEXED into the physical gap between the surrounding present")
    L.append("  segments, so a recovery scan carves them back (clean L1) and the footage is completed.")
    L.append("")
    L.append("## Expected counts")
    L.append(f"- Present (indexed) segments : **{len(active)}**.")
    L.append(f"- Lost (recoverable) segments: **{len(orphans)}** across **{n_gaps}** in-recording gap(s).")
    L.append(f"- Sessions: **{n_ch*days}** ({days}/channel).")
    L.append("- Every lost segment is a clean, independently decodable stream => recovers at **L1**.")
    L.append("")
    L.append("## Per-day loss schedule (which segments were dropped)")
    L.append("| channel | day | present segments | lost segments (runs) |")
    L.append("|---------|-----|------------------|----------------------|")
    for (ch0, d) in sorted(schedule.keys()):
        lost, runs = schedule[(ch0, d)]
        present = [s for s in range(n_slots) if s not in lost]
        runs_str = "; ".join("-".join(str(x) for x in r) for r in runs) or "none"
        L.append(f"| CH{ch0+1:02d} | {d+1} | {present} | {runs_str} |")
    L.append("")
    L.append("## Present (indexed) segments")
    L.append("| # | channel | day | slot | codec | recorder-native (IST) | offset | payload B |")
    L.append("|---|---------|-----|------|-------|-----------------------|--------|-----------|")
    for i, a in enumerate(active, 1):
        L.append(f"| {i} | CH{a['channel0']+1:02d} | {a['day']+1} | {a['slot']} | "
                 f"{channels[a['channel0']].codec} | {fmt_ist(a['timestamp'])} | "
                 f"0x{a['offset']:08X} | {len(a['payload']):,} |")
    L.append("")
    L.append("## Lost segments (recoverable footage in gaps)")
    L.append("| # | channel | day | slot | recorder-native (IST) | offset | payload B | expected |")
    L.append("|---|---------|-----|------|-----------------------|--------|-----------|----------|")
    for i, o in enumerate(orphans, 1):
        L.append(f"| {i} | CH{o['channel0']+1:02d} | {o['day']+1} | {o['slot']} | "
                 f"{fmt_ist(o['timestamp'])} | 0x{o['offset']:08X} | {o['payload_len']:,} | L1 clean |")
    L.append("")
    os.makedirs(os.path.dirname(args.answer_key), exist_ok=True)
    with open(args.answer_key, "w") as f:
        f.write("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
