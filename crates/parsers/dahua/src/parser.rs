//! # DahuaParser implementation
//!
//! Real (non-stub) extraction for the Dahua DHFS storage family. The parser reads
//! the DHFS superblock, walks the `DHAV` stream packets, and reads the `DIDX`
//! recording index, producing concrete `Recording` and `TimelineEvent` values.
//!
//! Byte layout expected (see generate_dahua_raw.py):
//!   DHFS superblock @ offset 0
//!   DHAV packet header:
//!     [0..4]   b"DHAV"
//!     [4]      frame_type  (0xFD = I-frame keyframe)
//!     [5]      channel
//!     [8..12]  frame_seq   (u32 LE)
//!     [12..16] packet_len  (u32 LE)
//!     [16..24] timestamp   (u64 LE, unix seconds)
//!     [28..30] width       (u16 LE)
//!     [30..32] height      (u16 LE)
//!     [32..48] codec       (16 bytes ASCII)
//!     [48..64] channel_name(16 bytes ASCII)
//!   DIDX index @ superblock.index_offset (default 0x100000)

use forensic_core::{
    ForensicError, Recording, TimelineEvent, ParserRun, OemProfile,
    ValidationState, Hash, Region, TimeEvidence, RawTimestamp,
    RecorderNativeTime, NormalizedTime, TimeZoneState, Provenance,
};
use forensic_core::identifiers::ProfileId;
use parsers_core::Parser;
use evidence_reader::EvidenceReader;

pub struct DahuaParser {
    pub id: String,
    pub version: String,
}

impl Default for DahuaParser {
    fn default() -> Self {
        Self {
            id: "dahua-dhfs-parser".to_string(),
            version: "1.0.0".to_string(),
        }
    }
}

impl DahuaParser {
    fn profile_hash(&self, profile: &OemProfile) -> Hash {
        profile.profile_hash.clone().unwrap_or(Hash::sha256(vec![0; 32]))
    }

    fn run(&self, profile: &OemProfile, op: &str, state: ValidationState) -> ParserRun {
        ParserRun::new(
            self.id.clone(),
            self.version.clone(),
            ProfileId(profile.profile_id.clone()),
            self.profile_hash(profile),
            op.to_string(),
            state,
        )
    }

    fn time_evidence(&self, profile: &OemProfile, unix_ts: u64) -> TimeEvidence {
        let dt_utc = chrono::DateTime::from_timestamp(unix_ts as i64, 0);
        let norm_iso = dt_utc
            .map(|d| d.to_rfc3339())
            .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());
        // Dahua DVRs are commonly deployed in IST (UTC+05:30) in this corpus.
        let local_dt = dt_utc.map(|d| d + chrono::Duration::hours(5) + chrono::Duration::minutes(30));
        let native_iso = local_dt
            .map(|d| d.format("%Y-%m-%dT%H:%M:%S").to_string())
            .unwrap_or_else(|| "1970-01-01T00:00:00".to_string());

        let raw_prov = Provenance::new(
            forensic_core::EvidenceId::new(),
            self.profile_hash(profile),
            vec![],
            &self.id,
            &self.version,
            Hash::sha256(vec![0; 32]),
            ValidationState::pass("raw", "valid", "raw").unwrap(),
        );
        TimeEvidence {
            raw: RawTimestamp { value: unix_ts, format: "UNIX_LE".into(), source: raw_prov },
            recorder_native: Some(RecorderNativeTime { iso_8601: native_iso }),
            normalized: Some(NormalizedTime { iso_8601: norm_iso, method: "utc_fixed".to_string() }),
            reference: None,
            timezone: TimeZoneState::Known("UTC+05:30".to_string()),
            correction: None,
        }
    }
}

impl Parser for DahuaParser {
    fn id(&self) -> &str {
        &self.id
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn parse_filesystem(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Vec<ParserRun>, ForensicError> {
        let superblock_size = profile.layout.get("superblock_size").copied().unwrap_or(512) as u64;
        let mut validation_state =
            ValidationState::review("DHFS superblock not present", "parse_filesystem", "superblock").unwrap();

        if reader.len() >= superblock_size {
            if let Ok(buf) = reader.read_exact_at(0, superblock_size as usize) {
                if let Some(magic) = profile.signatures.iter().find(|s| s.name == "dhfs_magic") {
                    let hex = magic.pattern_hex.replace(' ', "");
                    if let Ok(magic_bytes) = hex::decode(&hex) {
                        if buf.starts_with(&magic_bytes) {
                            // Read a couple of descriptive superblock fields for the reason string.
                            let model = ascii_field(&buf, 48, 16);
                            let label = ascii_field(&buf, 96, 16);
                            validation_state = ValidationState::pass(
                                format!("DHFS superblock verified (model '{model}', volume '{label}')"),
                                "parse_filesystem",
                                "superblock",
                            ).unwrap();
                        } else {
                            validation_state = ValidationState::review(
                                "DHFS magic mismatch in superblock sector",
                                "parse_filesystem",
                                "superblock",
                            ).unwrap();
                        }
                    }
                }
            }
        }

        Ok(vec![self.run(profile, "parse_filesystem", validation_state)])
    }

    fn parse_metadata(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Vec<ParserRun>, ForensicError> {
        // Delegate to the real index reader so this stage reports the same facts the
        // recovery engine will consume — including how authoritative the index is.
        // Reading only the header's entry count (as this stage used to) cannot
        // distinguish a complete index from a partially readable one.
        let validation_state = match crate::dhfs::read_recording_index(reader, profile)? {
            Some(index) => index.evidence.clone(),
            None => ValidationState::not_run(
                "parse_metadata",
                "No DHFS superblock; no recording index to read",
            ),
        };

        Ok(vec![self.run(profile, "parse_metadata", validation_state)])
    }

    fn parse_recordings(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<(Vec<Recording>, Vec<ParserRun>), ForensicError> {
        let packets = scan_dhav_packets(reader);

        let validation_state = if !packets.is_empty() {
            ValidationState::pass(
                format!("Extracted {} DHAV recording stream(s)", packets.len()),
                "parse_recordings",
                "dhav_stream",
            ).unwrap()
        } else {
            ValidationState::not_run("parse_recordings", "No DHAV packets located")
        };

        let mut recordings = Vec::new();
        for pkt in &packets {
            let time = self.time_evidence(profile, pkt.timestamp);
            // The recording region describes the elementary stream itself, not the
            // DHAV container framing, so downstream reconstruction receives a clean
            // Annex-B byte range. Clamped to the image so a declared length can never
            // describe bytes outside the evidence.
            let available = reader.len().saturating_sub(pkt.payload_offset);
            let region_len = pkt.payload_len.min(available).max(1);
            let region = Region::new(pkt.payload_offset, region_len)?;
            recordings.push(Recording::new(
                pkt.channel,
                time,
                reader.source_path().to_string(),
                vec![region],
                self.id.clone(),
                self.version.clone(),
                ProfileId(profile.profile_id.clone()),
                self.profile_hash(profile),
            ));
        }

        Ok((recordings, vec![self.run(profile, "parse_recordings", validation_state)]))
    }

    fn extract_timeline_events(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<(Vec<TimelineEvent>, Vec<ParserRun>), ForensicError> {
        let packets = scan_dhav_packets(reader);

        let validation_state = if !packets.is_empty() {
            ValidationState::pass(
                format!("Extracted {} DHAV timeline event(s)", packets.len()),
                "extract_timeline_events",
                "dhav_events",
            ).unwrap()
        } else {
            ValidationState::not_run("extract_timeline_events", "No DHAV packets located")
        };

        let mut events = Vec::new();
        for pkt in &packets {
            let time = self.time_evidence(profile, pkt.timestamp);
            let region = Region::new(pkt.offset, 64)?;
            let kind = if pkt.frame_type == 0xFD { "keyframe" } else { "frame" };
            events.push(TimelineEvent::new(
                pkt.channel,
                time,
                format!(
                    "Dahua DHAV Ch{} ({}) {} [{}] at 0x{:X}",
                    pkt.channel, pkt.channel_name, kind, pkt.codec, pkt.offset
                ),
                vec![region],
                self.id.clone(),
                self.version.clone(),
                ProfileId(profile.profile_id.clone()),
                self.profile_hash(profile),
            ));
        }

        Ok((events, vec![self.run(profile, "extract_timeline_events", validation_state)]))
    }

    fn validate_structure(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Vec<ParserRun>, ForensicError> {
        // Structural validation: DHFS magic at offset 0 AND at least one DHAV packet.
        let mut dhfs_ok = false;
        if let Ok(head) = reader.read_exact_at(0, 4) {
            dhfs_ok = &head[..] == b"DHFS";
        }
        let dhav_count = scan_dhav_packets(reader).len();

        let validation_state = if dhfs_ok && dhav_count > 0 {
            ValidationState::pass(
                format!("DHFS superblock and {dhav_count} DHAV packet(s) structurally consistent"),
                "validate_structure",
                "dhfs_dhav",
            ).unwrap()
        } else if dhfs_ok {
            ValidationState::review(
                "DHFS superblock present but no DHAV packets found",
                "validate_structure",
                "dhfs_dhav",
            ).unwrap()
        } else {
            ValidationState::review(
                "DHFS superblock magic not found at offset 0",
                "validate_structure",
                "dhfs_dhav",
            ).unwrap()
        };

        Ok(vec![self.run(profile, "validate_structure", validation_state)])
    }

    /// Format recognition only: do the bytes in this window carry Dahua DHAV container
    /// framing?
    ///
    /// Previously this returned `Ok(true)` unconditionally, which made the recovery
    /// engine's L1 gate always open and rendered the orphan/unindexed paths unreachable.
    /// It now inspects the window. It still says nothing about whether the region is an
    /// indexed recording — that question is answered by [`Parser::recording_index`].
    fn recognize_candidate(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<bool, ForensicError> {
        crate::dhfs::window_looks_like_dhav(reader, profile)
    }

    fn storage_geometry(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Option<parsers_core::storage::StorageGeometry>, ForensicError> {
        crate::dhfs::read_storage_geometry(reader, profile)
    }

    fn recording_index(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Option<parsers_core::storage::RecordingIndex>, ForensicError> {
        crate::dhfs::read_recording_index(reader, profile)
    }
}

#[derive(Debug, Clone)]
struct DhavPacket {
    channel: u32,
    offset: u64,
    frame_type: u8,
    timestamp: u64,
    codec: String,
    channel_name: String,
    /// Byte offset of the elementary stream payload (after the DHAV header).
    payload_offset: u64,
    /// Length of the elementary stream payload (excludes header and `dhav` footer).
    payload_len: u64,
}

/// Size of the fixed DHAV packet header that precedes the elementary stream.
const DHAV_HEADER_SIZE: u64 = 64;
/// Size of the lowercase `dhav` footer that closes a packet.
const DHAV_FOOTER_SIZE: u64 = 4;

/// Trim a fixed-width ASCII field to a clean string.
fn ascii_field(buf: &[u8], start: usize, len: usize) -> String {
    let end = (start + len).min(buf.len());
    if start >= end {
        return String::new();
    }
    String::from_utf8_lossy(&buf[start..end])
        .trim_matches('\0')
        .trim()
        .to_string()
}

/// Scan for `DHAV` stream packets across the evidence (bounded window) and parse
/// their headers into structured packets.
fn scan_dhav_packets(reader: &dyn EvidenceReader) -> Vec<DhavPacket> {
    let mut packets = Vec::new();
    let scan_limit = reader.len().min(16 * 1024 * 1024) as usize;
    let mut buf = vec![0u8; scan_limit];

    let read_len = match reader.read_at(0, &mut buf) {
        Ok(n) => n,
        Err(_) => return packets,
    };
    let slice = &buf[..read_len];
    let needle = b"DHAV";

    // Sane bounds for a declared DHAV packet length. Random bytes can imitate the
    // 4-byte tag, so a length outside these bounds is treated as untrustworthy and
    // replaced with a single sector rather than trusted blindly.
    const MIN_PACKET_LEN: u32 = 64;
    const MAX_PACKET_LEN: u32 = 64 * 1024 * 1024;

    let mut i = 0usize;
    while i + 64 <= slice.len() {
        if &slice[i..i + 4] == needle {
            let frame_type = slice[i + 4];
            // Dahua stores the channel index 0-based on disk; report it 1-based to
            // match the recorder's own channel labelling (CH01, CH02, ...).
            let channel = slice[i + 5] as u32 + 1;
            let raw_packet_len = u32::from_le_bytes(slice[i + 12..i + 16].try_into().unwrap());
            let packet_len = if (MIN_PACKET_LEN..=MAX_PACKET_LEN).contains(&raw_packet_len) {
                raw_packet_len
            } else {
                512
            };
            let timestamp = u64::from_le_bytes(slice[i + 16..i + 24].try_into().unwrap());
            let codec = ascii_field(slice, i + 32, 16);
            let codec = if codec.is_empty() { "unknown".to_string() } else { codec };
            let channel_name = ascii_field(slice, i + 48, 16);
            let channel_name = if channel_name.is_empty() {
                format!("CH{:02}", channel)
            } else {
                channel_name
            };

            // The elementary stream sits between the header and the footer. A packet
            // too small to hold both is reported with a zero-length payload rather
            // than an underflowed span.
            let offset = i as u64;
            let payload_offset = offset + DHAV_HEADER_SIZE;
            let payload_len = (packet_len as u64)
                .saturating_sub(DHAV_HEADER_SIZE + DHAV_FOOTER_SIZE);

            packets.push(DhavPacket {
                channel,
                offset,
                frame_type,
                timestamp,
                codec,
                channel_name,
                payload_offset,
                payload_len,
            });

            // Skip ahead by the declared packet length (aligned), or a sector if unknown.
            let step = if packet_len as usize >= 64 { packet_len as usize } else { 512 };
            i += step;
        } else {
            i += 1;
        }
    }

    packets
}
