-- Phase 2 Detection Metadata Schema (Req 2.6, 9.6, 11.2)

CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY,
    profile_id VARCHAR(255) NOT NULL,
    profile_version VARCHAR(100) NOT NULL,
    schema_version VARCHAR(50) NOT NULL,
    oem VARCHAR(100) NOT NULL,
    storage_family VARCHAR(100) NOT NULL,
    profile_hash BYTEA NOT NULL,
    loaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS evidence_items (
    id UUID PRIMARY KEY,
    evidence_id UUID NOT NULL REFERENCES evidence(id),
    kind VARCHAR(100) NOT NULL,
    offset_bytes BIGINT NOT NULL,
    length_bytes BIGINT NOT NULL,
    observed_snippet BYTEA NOT NULL,
    expected_snippet BYTEA NOT NULL,
    rule_match_status VARCHAR(50) NOT NULL,
    evidence_status VARCHAR(50) NOT NULL,
    score_contribution DOUBLE PRECISION NOT NULL,
    is_exclusive BOOLEAN NOT NULL DEFAULT FALSE,
    explanation TEXT NOT NULL,
    profile_version VARCHAR(100) NOT NULL,
    profile_hash BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS detection_results (
    id UUID PRIMARY KEY,
    evidence_id UUID NOT NULL REFERENCES evidence(id),
    top_candidate VARCHAR(100) NOT NULL,
    second_candidate VARCHAR(100),
    confidence DOUBLE PRECISION NOT NULL,
    margin DOUBLE PRECISION NOT NULL,
    evidence_quality DOUBLE PRECISION NOT NULL,
    classification VARCHAR(50) NOT NULL,
    attribution_status VARCHAR(50) NOT NULL,
    validation_state_id UUID REFERENCES validation_states(id),
    explanation TEXT NOT NULL,
    config_version VARCHAR(100) NOT NULL,
    config_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_detection_evidence ON detection_results(evidence_id);
CREATE INDEX IF NOT EXISTS idx_evidence_items_evidence ON evidence_items(evidence_id);
