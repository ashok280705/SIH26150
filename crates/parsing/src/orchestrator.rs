use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, ParserRun, Recording, TimelineEvent};
use parsers_core::Parser;

// Import all parsers
use parser_dahua::DahuaParser;
use parser_hikvision::HikvisionParser;
use parser_honeywell::HoneywellParser;
use parser_cpplus_ubs::CpPlusUbsParser;
use parser_uniview::UniviewParser;
use tplink::TplinkParser;

use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ParsingResult {
    pub parser_runs: Vec<ParserRun>,
    pub recordings: Vec<Recording>,
    pub timeline_events: Vec<TimelineEvent>,
}

pub struct ParsingOrchestrator {
    parsers: std::collections::HashMap<String, Box<dyn Parser>>,
}

impl ParsingOrchestrator {
    pub fn new() -> Self {
        let mut parsers: std::collections::HashMap<String, Box<dyn Parser>> = std::collections::HashMap::new();
        
        parsers.insert("dahua".to_string(), Box::new(DahuaParser::default()));
        parsers.insert("hikvision".to_string(), Box::new(HikvisionParser::default()));
        parsers.insert("honeywell".to_string(), Box::new(HoneywellParser::default()));
        parsers.insert("cpplus_ubs".to_string(), Box::new(CpPlusUbsParser::default()));
        parsers.insert("uniview".to_string(), Box::new(UniviewParser::default()));
        parsers.insert("tplink".to_string(), Box::new(TplinkParser::default()));
        
        Self { parsers }
    }

    pub fn run_parsing(
        &self,
        oem_key: &str,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<ParsingResult, ForensicError> {
        let parser = self.parsers.get(oem_key)
            .ok_or_else(|| ForensicError::corrupt("ParsingOrchestrator", format!("No parser registered for OEM key: {}", oem_key)))?;

        let mut parser_runs = Vec::new();

        // 1. Validate Structure
        let mut runs = parser.validate_structure(reader, profile)?;
        parser_runs.append(&mut runs);

        // 2. Parse Filesystem
        let mut runs = parser.parse_filesystem(reader, profile)?;
        parser_runs.append(&mut runs);

        // 3. Parse Metadata
        let mut runs = parser.parse_metadata(reader, profile)?;
        parser_runs.append(&mut runs);

        // 4. Parse Recordings
        let (recordings, mut runs) = parser.parse_recordings(reader, profile)?;
        parser_runs.append(&mut runs);

        // 5. Extract Timeline Events
        let (timeline_events, mut runs) = parser.extract_timeline_events(reader, profile)?;
        parser_runs.append(&mut runs);

        Ok(ParsingResult {
            parser_runs,
            recordings,
            timeline_events,
        })
    }
}
