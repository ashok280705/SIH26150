#!/usr/bin/env python3
"""
Generate a realistic, forensically authentic TP-Link VIGI NVR .raw evidence disk image.
Size: 4 MiB (4,194,304 bytes)
"""
import struct
import os

OUTPUT_PATH = "tplink_vigi_nvr_sample.raw"
DISK_SIZE = 4 * 1024 * 1024  # 4 MiB
SECTOR_SIZE = 512

buf = bytearray(DISK_SIZE)

# ==============================================================================
# 1. Sector 0: MBR Partition Table (Sectors 0..512)
# ==============================================================================
buf[0:4] = b"\xEB\x48\x90\x00"

# Partition 1: Linux Swap (0x82)
# Starts at sector 2048 (1 MiB), count = 2048 sectors (1 MiB)
p1_offset = 446
struct.pack_into(
    "<B3sB3sII", buf, p1_offset,
    0x00,                  # Bootable flag (0 = no)
    b"\x00\x20\x21",       # Starting CHS
    0x82,                  # Partition Type: Linux Swap
    b"\x00\x40\x41",       # Ending CHS
    2048,                  # Starting LBA (Sector 2048 = 1 MiB)
    2048                   # Sector Count (2048 = 1 MiB)
)

# Partition 2: Linux EXT4 (0x83)
# Starts at sector 4096 (2 MiB), count = 4096 sectors (2 MiB)
p2_offset = 462
struct.pack_into(
    "<B3sB3sII", buf, p2_offset,
    0x00,                  # Bootable flag
    b"\x00\x40\x42",       # Starting CHS
    0x83,                  # Partition Type: Linux Native / EXT4
    b"\x00\x80\x82",       # Ending CHS
    4096,                  # Starting LBA (Sector 4096 = 2 MiB)
    4096                   # Sector Count (4096 = 2 MiB)
)

# MBR Signature at 510..512
buf[510] = 0x55
buf[511] = 0xAA

# ==============================================================================
# 2. TP-Link Proprietary rawDiskLayout Metadata (First 1-2 MiB)
# ==============================================================================
# Signature: tp_layout_magic ("TP" = 0x54, 0x50) at offset 8192 (0x2000)
buf[8192:8194] = b"TP"
struct.pack_into("<HHII", buf, 8194, 1, 0, 16, 1048576) # Version 1.0, 16 zones, 1MB blocks

# Signature: tp_metadata_string ("TP-Link Corporation Limited") at offset 16384 (0x4000)
meta_str = b"TP-Link Corporation Limited, VIGI NVR1008H(UN) 2.0, Firmware 1.1.3 Build 260727"
buf[16384:16384 + len(meta_str)] = meta_str

# Signature: sys_bin_sqlite ("SQLite format 3\0") at offset 32768 (0x8000)
sqlite_header = b"SQLite format 3\x00"
buf[32768:32768 + len(sqlite_header)] = sqlite_header
# Mock SQLite database page size 4096, write version 1, read version 1
struct.pack_into(">HBB", buf, 32768 + 16, 4096, 1, 1)

# ==============================================================================
# 3. Partition 1: Linux Swap Partition (Byte 1,048,576 / 0x100000)
# ==============================================================================
swap_offset = 1048576 + 4086
buf[swap_offset:swap_offset + 10] = b"SWAPSPACE2"

# ==============================================================================
# 4. Partition 2: Starts at 2,097,152 (0x200000)
# ==============================================================================

# 4A. TP-Link VIGI Channel 1 Recording Stream Container at 0x200000 (2,097,152)
# Header format:
# [0..7]:   b"TPREC\x01\x00\x01" (Magic TPREC, v1, channel 1)
# [8..15]:  uint64 start timestamp (1726700000)
# [16..31]: ASCII Codec string ("H.265 / HEVC    ")
# [32..35]: uint16 width (1920), uint16 height (1080)
# [36..39]: uint16 fps (25), uint16 stream_type (1 = main)
# [40..47]: uint64 frame_count (54000)
# [48..63]: Description ("FRONT_ENTRANCE_01")
ch1_offset = 2097152
buf[ch1_offset:ch1_offset + 8] = b"TPREC\x01\x00\x01"
struct.pack_into("<Q16sHHHHI16s", buf, ch1_offset + 8,
    1726700000,
    b"H.265 / HEVC\x00\x00\x00\x00",
    1920, 1080,
    25, 1,
    54000,
    b"FRONT_ENTRANCE_1"
)

# Followed immediately by H.265 video NAL units at offset ch1_offset + 64
vid1_offset = ch1_offset + 64
nal_start = b"\x00\x00\x00\x01"
# VPS NAL
buf[vid1_offset:vid1_offset + 4] = nal_start
buf[vid1_offset + 4:vid1_offset + 12] = b"\x40\x01\x0C\x01\xFF\xFF\x01\x60"
# SPS NAL
buf[vid1_offset + 16:vid1_offset + 20] = nal_start
buf[vid1_offset + 20:vid1_offset + 28] = b"\x42\x01\x01\x01\x60\x00\x00\x03"
# PPS NAL
buf[vid1_offset + 32:vid1_offset + 36] = nal_start
buf[vid1_offset + 36:vid1_offset + 44] = b"\x44\x01\xC0\xF3\xC0\x00\x00\x00"
# IDR Slice (I-Frame keyframe)
buf[vid1_offset + 48:vid1_offset + 52] = nal_start
buf[vid1_offset + 52:vid1_offset + 60] = b"\x26\x01\xAF\x00\x88\x12\x34\x56"
# Fill remainder of first 256 bytes with simulated video packet slice payload
for i in range(128, 256):
    buf[ch1_offset + i] = (i * 7 + 0x33) & 0xFF

# 4B. EXT4 Superblock at partition + 1024 (offset 2,098,176 / 0x200400)
ext4_sb_offset = 2097152 + 1024
ext4_magic_offset = ext4_sb_offset + 0x38
buf[ext4_magic_offset:ext4_magic_offset + 2] = b"\x53\xEF" # 0xEF53 little-endian
buf[ext4_sb_offset + 0x78:ext4_sb_offset + 0x78 + 15] = b"tplink_vigi_rec"

# Generic EXT4 probe offset
buf[51712:51714] = b"\x53\xEF"

# 4C. TP-Link VIGI Channel 2 Recording Stream Container at 0x220000 (2,228,224)
ch2_offset = 2228224
buf[ch2_offset:ch2_offset + 8] = b"TPREC\x01\x00\x02" # Magic TPREC, v1, channel 2
struct.pack_into("<Q16sHHHHI16s", buf, ch2_offset + 8,
    1726703600,
    b"H.264 / AVC\x00\x00\x00\x00\x00",
    1920, 1080,
    25, 1,
    36000,
    b"BACK_PARKING_002"
)

vid2_offset = ch2_offset + 64
# H.264 SPS
buf[vid2_offset:vid2_offset + 4] = nal_start
buf[vid2_offset + 4:vid2_offset + 12] = b"\x67\x42\x00\x1F\x96\x54\x05\x01"
# H.264 PPS
buf[vid2_offset + 16:vid2_offset + 20] = nal_start
buf[vid2_offset + 20:vid2_offset + 28] = b"\x68\xCE\x3C\x80\x00\x00\x00\x00"
# H.264 IDR Slice
buf[vid2_offset + 32:vid2_offset + 36] = nal_start
buf[vid2_offset + 36:vid2_offset + 44] = b"\x65\xB8\x00\x04\x00\x00\x00\x00"
for i in range(128, 256):
    buf[ch2_offset + i] = (i * 13 + 0x55) & 0xFF

with open(OUTPUT_PATH, "wb") as f:
    f.write(buf)

print(f"Successfully generated {OUTPUT_PATH} ({len(buf)} bytes)")
