-- Add Phase 3 models (parser_runs, recordings, timeline_events)

CREATE TABLE IF NOT EXISTS parser_runs (
    id UUID PRIMARY KEY,
    evidence_id UUID NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    parser_id TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    profile_hash TEXT NOT NULL,
    operation_name TEXT NOT NULL,
    validation_state JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_parser_runs_evidence ON parser_runs(evidence_id);
CREATE INDEX idx_parser_runs_profile ON parser_runs(profile_id, profile_hash);

CREATE TABLE IF NOT EXISTS recordings (
    id UUID PRIMARY KEY,
    evidence_id UUID NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    parser_run_id UUID NOT NULL REFERENCES parser_runs(id) ON DELETE CASCADE,
    channel INTEGER NOT NULL,
    
    -- Time Evidence (Req 4.5, 4.6, 4.7)
    raw_ts JSONB NOT NULL,
    recorder_native_ts TIMESTAMPTZ,
    normalized_ts TIMESTAMPTZ,
    reference_ts TIMESTAMPTZ,
    timezone_state TEXT NOT NULL,
    normalization_method TEXT,
    clock_correction JSONB,
    
    -- Provenance and Integrity
    source_image TEXT NOT NULL,
    integrity JSONB NOT NULL,
    
    -- Export/Extraction payload (Req 12.2)
    exported_video_path TEXT,
    sha256 TEXT,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_recordings_evidence ON recordings(evidence_id);
CREATE INDEX idx_recordings_channel ON recordings(evidence_id, channel);
CREATE INDEX idx_recordings_time ON recordings(evidence_id, normalized_ts);

CREATE TABLE IF NOT EXISTS recording_source_regions (
    id UUID PRIMARY KEY,
    recording_id UUID NOT NULL REFERENCES recordings(id) ON DELETE CASCADE,
    offset_start BIGINT NOT NULL,
    length BIGINT NOT NULL
);

CREATE INDEX idx_recording_regions_rec ON recording_source_regions(recording_id);
CREATE INDEX idx_recording_regions_offset ON recording_source_regions(offset_start, length);

CREATE TABLE IF NOT EXISTS timeline_events (
    id UUID PRIMARY KEY,
    evidence_id UUID NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    parser_run_id UUID NOT NULL REFERENCES parser_runs(id) ON DELETE CASCADE,
    channel INTEGER NOT NULL,
    
    -- Time Evidence
    raw_ts JSONB NOT NULL,
    recorder_native_ts TIMESTAMPTZ,
    normalized_ts TIMESTAMPTZ,
    reference_ts TIMESTAMPTZ,
    timezone_state TEXT NOT NULL,
    normalization_method TEXT,
    clock_correction JSONB,
    
    description TEXT NOT NULL,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_timeline_events_evidence ON timeline_events(evidence_id);
CREATE INDEX idx_timeline_events_time ON timeline_events(evidence_id, normalized_ts);

CREATE TABLE IF NOT EXISTS timeline_event_source_regions (
    id UUID PRIMARY KEY,
    timeline_event_id UUID NOT NULL REFERENCES timeline_events(id) ON DELETE CASCADE,
    offset_start BIGINT NOT NULL,
    length BIGINT NOT NULL
);

CREATE INDEX idx_event_regions_event ON timeline_event_source_regions(timeline_event_id);
CREATE INDEX idx_event_regions_offset ON timeline_event_source_regions(offset_start, length);
