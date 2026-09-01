-- Phase 5: Timeline & Multi-Camera Correlation Tables

DROP TABLE IF EXISTS timeline_events;
CREATE TABLE IF NOT EXISTS timeline_events (
    id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    recording_id UUID REFERENCES recordings(id) ON DELETE SET NULL,
    channel INTEGER NOT NULL,
    event_time JSONB NOT NULL, -- TimeEvidence model
    description TEXT NOT NULL,
    source_offsets JSONB NOT NULL, -- List of Region
    parser_id TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    profile_hash TEXT NOT NULL,
    normalized_ts TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_timeline_events_case_norm ON timeline_events(case_id, normalized_ts);
CREATE INDEX IF NOT EXISTS idx_timeline_events_channel ON timeline_events(channel, normalized_ts);
CREATE INDEX IF NOT EXISTS idx_timeline_events_recording ON timeline_events(recording_id);

CREATE TABLE IF NOT EXISTS correlated_event_groups (
    id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    camera_channels TEXT NOT NULL,
    event_ids TEXT NOT NULL,
    has_timezone_uncertainty BOOLEAN NOT NULL DEFAULT FALSE,
    validation_state JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_correlated_groups_case ON correlated_event_groups(case_id);
CREATE INDEX IF NOT EXISTS idx_correlated_groups_window ON correlated_event_groups(window_start, window_end);
