use chrono::{DateTime, Utc};
use forensic_core::Region;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TplinkDataType {
    MainGop,
    SubGop,
    Audio,
    Picture,
    Unknown(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneState {
    Free,
    Active,
    Full,
    Done,
    Unknown(u32),
}

#[derive(Debug, Clone)]
pub struct RecordingEvent {
    pub event_id: u64,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub channel_id: u32,
    pub zone_id: u32,
    pub block_id: u32,
    pub event_type: u32,
    pub main_gop_length: u64,
    pub sub_gop_length: u64,
    pub audio_gop_length: u64,
    pub lock_flag: bool,
}

#[derive(Debug, Clone)]
pub struct ZoneRecord {
    pub zone_id: u32,
    pub block_id: u32,
    pub channel_id: u32,
    pub data_type: TplinkDataType,
    pub status: ZoneState,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub current_offset: u64,
    pub lock_flag: bool,
    pub write_times: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionStatus {
    Confirmed,
    NotConfirmed,
    Unknown,
}
