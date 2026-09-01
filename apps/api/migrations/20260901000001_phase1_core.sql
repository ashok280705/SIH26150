-- Phase 1 Core Metadata Schema
-- strictly metadata only; no raw media blobs (Req 5.3, 5.4, 5.8, 5.9, 7.1, 7.2, 7.3, 7.7, 21.1, 22.1, 23.1, 23.2)

CREATE TABLE IF NOT EXISTS cases (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    examiner VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS acquisitions (
    id UUID PRIMARY KEY,
    evidence_id UUID NOT NULL,
    status VARCHAR(50) NOT NULL, -- 'complete', 'partial', 'failed', 'unknown'
    tool VARCHAR(255),
    tool_version VARCHAR(100),
    map_reference VARCHAR(1024),
    map_hash BYTEA,
    bad_sector_ranges JSONB NOT NULL DEFAULT '[]'::jsonb,
    unresolved_ranges JSONB NOT NULL DEFAULT '[]'::jsonb,
    verification_state VARCHAR(50) NOT NULL,
    verification_reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
    source_device VARCHAR(255) NOT NULL,
    acquisition_time TIMESTAMPTZ NOT NULL,
    capacity BIGINT NOT NULL,
    image_format VARCHAR(50) NOT NULL,
    responsible_examiner VARCHAR(255) NOT NULL,
    acquisition_tool VARCHAR(255),
    acquisition_tool_version VARCHAR(100),
    source_state VARCHAR(50) NOT NULL DEFAULT 'unknown', -- 'read_only', 'read_write', 'unknown'
    acquisition_id UUID REFERENCES acquisitions(id),
    path VARCHAR(4096) NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS source_safety_reports (
    id UUID PRIMARY KEY,
    evidence_id UUID NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    source_state VARCHAR(50) NOT NULL,
    decision VARCHAR(50) NOT NULL, -- 'accepted', 'rejected'
    reason TEXT NOT NULL,
    inspected_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS chain_of_custody (
    id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
    timestamp TIMESTAMPTZ NOT NULL,
    examiner VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    artifact_id UUID,
    result TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS validation_states (
    id UUID PRIMARY KEY,
    state VARCHAR(50) NOT NULL, -- 'PASS', 'REVIEW', 'FAIL', 'UNKNOWN'
    reason TEXT NOT NULL, -- NOT NULL constraint enforced: reason is mandatory (Req 22.2)
    operation VARCHAR(255) NOT NULL,
    subject VARCHAR(1024) NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS capability_stages (
    id UUID PRIMARY KEY,
    oem_key VARCHAR(100) NOT NULL,
    -- Five independent dimensions (Req 21.1)
    detection VARCHAR(50) NOT NULL DEFAULT 'not_implemented',
    profiling VARCHAR(50) NOT NULL DEFAULT 'not_implemented',
    parsing VARCHAR(50) NOT NULL DEFAULT 'not_implemented',
    reconstruction VARCHAR(50) NOT NULL DEFAULT 'not_implemented',
    validation VARCHAR(50) NOT NULL DEFAULT 'not_implemented',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS hashes (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL,
    algorithm VARCHAR(50) NOT NULL, -- 'sha256'
    value BYTEA NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL,
    validation_state_id UUID REFERENCES validation_states(id),
    duration_ms BIGINT NOT NULL,
    bytes_hashed BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS provenance (
    id UUID PRIMARY KEY,
    source_evidence_id UUID NOT NULL REFERENCES evidence(id),
    source_hash BYTEA NOT NULL,
    producing_component VARCHAR(255) NOT NULL,
    component_version VARCHAR(100) NOT NULL,
    profile_version VARCHAR(100),
    profile_hash BYTEA,
    parser_version VARCHAR(100),
    recovery_level VARCHAR(50),
    output_hash BYTEA NOT NULL,
    transformation_history JSONB NOT NULL DEFAULT '[]'::jsonb,
    validation_state_id UUID REFERENCES validation_states(id),
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS source_regions (
    id UUID PRIMARY KEY,
    provenance_id UUID NOT NULL REFERENCES provenance(id) ON DELETE CASCADE,
    evidence_id UUID NOT NULL REFERENCES evidence(id),
    offset_bytes BIGINT NOT NULL,
    length_bytes BIGINT NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS artifacts (
    id UUID PRIMARY KEY,
    kind VARCHAR(50) NOT NULL, -- 'native' or 'derived'
    evidence_id UUID NOT NULL REFERENCES evidence(id),
    provenance_id UUID REFERENCES provenance(id),
    output_path VARCHAR(4096),
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

-- Indices for forensic query performance
CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_custody_case ON chain_of_custody(case_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_evidence ON artifacts(evidence_id);
CREATE INDEX IF NOT EXISTS idx_source_regions_provenance ON source_regions(provenance_id);
