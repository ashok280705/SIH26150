-- Phase 7: AI Analytics Findings & Boundaries Tables

CREATE TABLE IF NOT EXISTS ai_findings (
    id UUID PRIMARY KEY,
    recording_id UUID REFERENCES recordings(id) ON DELETE CASCADE,
    model_name TEXT NOT NULL,
    model_version TEXT NOT NULL,
    finding_type TEXT NOT NULL, -- 'ObjectDetection', 'LicensePlate', 'FacialFeature', etc.
    confidence DOUBLE PRECISION NOT NULL,
    bounding_box JSONB, -- [ymin, xmin, ymax, xmax]
    frame_offset BIGINT,
    timestamp_str TEXT,
    label_ai_assisted BOOLEAN NOT NULL DEFAULT TRUE,
    disclaimer TEXT NOT NULL,
    validation_state JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ai_findings_recording ON ai_findings(recording_id);
CREATE INDEX IF NOT EXISTS idx_ai_findings_type ON ai_findings(finding_type);
