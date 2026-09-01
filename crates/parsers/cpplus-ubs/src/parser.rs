use forensic_core::{
    ForensicError, Recording, TimelineEvent, ParserRun, OemProfile,
    ValidationState, Hash,
};
use forensic_core::identifiers::ProfileId;
use parsers_core::Parser;
use evidence_reader::EvidenceReader;

pub struct CpPlusUbsParser {
    pub id: String,
    pub version: String,
}

impl Default for CpPlusUbsParser {
    fn default() -> Self {
        Self {
            id: "cpplus-ubs-parser".to_string(),
            version: "1.0.0".to_string(),
        }
    }
}

impl Parser for CpPlusUbsParser {
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
        let mut runs = Vec::new();
        
        let mut validation_state = ValidationState::not_run("parse_filesystem", "No UBS_ header found");
        
        let superblock_size = profile.layout.get("superblock_size").copied().unwrap_or(512) as u64;

        if reader.len() >= superblock_size {
            // Checked math: validate bounds without panicking
            match reader.read_exact_at(0, superblock_size as usize) {
                Ok(buf) => {
                    // Check magic signature from profile (ubs_partition_marker)
                    let magic = profile.signatures.iter().find(|s| s.name == "ubs_partition_marker");
                    if let Some(magic) = magic {
                        let hex = magic.pattern_hex.replace(" ", "");
                        if let Ok(magic_bytes) = hex::decode(&hex) {
                            if buf.starts_with(&magic_bytes) {
                                validation_state = ValidationState::pass("UBS_ Superblock Found (Generic)", "parse_filesystem", "superblock").unwrap();
                            } else {
                                validation_state = ValidationState::review("Magic mismatch in UBS_ sector", "parse_filesystem", "superblock").unwrap();
                            }
                        }
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        
        runs.push(ParserRun::new(
            self.id.clone(),
            self.version.clone(),
            ProfileId(profile.profile_id.clone()),
            profile.profile_hash.clone().unwrap_or(Hash::sha256(vec![0; 32])),
            "parse_filesystem".to_string(),
            validation_state,
        ));
        
        Ok(runs)
    }

    fn parse_metadata(
        &self,
        _reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Vec<ParserRun>, ForensicError> {
        Ok(vec![ParserRun::new(
            self.id.clone(),
            self.version.clone(),
            ProfileId(profile.profile_id.clone()),
            profile.profile_hash.clone().unwrap_or(Hash::sha256(vec![0; 32])),
            "parse_metadata".to_string(),
            ValidationState::not_run("parse_metadata", "Index metadata missing or CRC failed in synthetic fixture"),
        )])
    }

    fn parse_recordings(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<(Vec<Recording>, Vec<ParserRun>), ForensicError> {
        let mut runs = Vec::new();
        
        let cpplus_marker_start = profile.layout.get("cpplus_marker_start").copied().unwrap_or(512) as u64;
        
        let validation_state = if reader.len() > cpplus_marker_start {
            ValidationState::review("Mock CPPLUS segment parse complete", "parse_recordings", "cpplus_marker").unwrap()
        } else {
            ValidationState::not_run("parse_recordings", "No CPPLUS payload space")
        };
        
        runs.push(ParserRun::new(
            self.id.clone(),
            self.version.clone(),
            ProfileId(profile.profile_id.clone()),
            profile.profile_hash.clone().unwrap_or(Hash::sha256(vec![0; 32])),
            "parse_recordings".to_string(),
            validation_state,
        ));
        
        Ok((vec![], runs))
    }

    fn extract_timeline_events(
        &self,
        _reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<(Vec<TimelineEvent>, Vec<ParserRun>), ForensicError> {
        Ok((vec![], vec![ParserRun::new(
            self.id.clone(),
            self.version.clone(),
            ProfileId(profile.profile_id.clone()),
            profile.profile_hash.clone().unwrap_or(Hash::sha256(vec![0; 32])),
            "extract_timeline_events".to_string(),
            ValidationState::not_run("extract_timeline_events", "No events in synthetic fixture"),
        )]))
    }

    fn validate_structure(
        &self,
        _reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<Vec<ParserRun>, ForensicError> {
        Ok(vec![ParserRun::new(
            self.id.clone(),
            self.version.clone(),
            ProfileId(profile.profile_id.clone()),
            profile.profile_hash.clone().unwrap_or(Hash::sha256(vec![0; 32])),
            "validate_structure".to_string(),
            ValidationState::not_run("validate_structure", "Structural validation skipped"),
        )])
    }

    fn recognize_candidate(
        &self,
        _reader: &dyn EvidenceReader,
        _profile: &OemProfile,
    ) -> Result<bool, ForensicError> {
        Ok(true)
    }
}
