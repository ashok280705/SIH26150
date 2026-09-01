-- Add Phase 4 models (recovery_runs, recovery_candidates, recovery_source_regions)

CREATE TABLE IF NOT EXISTS recovery_runs (
    id UUID PRIMARY KEY,
    evidence_id UUID NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    searched_regions JSONB NOT NULL,
    searched_bytes BIGINT NOT NULL,
    skipped_ranges JSONB NOT NULL,
    candidate_count INTEGER NOT NULL,
    rejected INTEGER NOT NULL,
    accepted INTEGER NOT NULL,
    hypothesis_count INTEGER NOT NULL,
    truncated BOOLEAN NOT NULL DEFAULT FALSE,
    cancelled BOOLEAN NOT NULL DEFAULT FALSE,
    validation_state JSONB NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_recovery_runs_evidence ON recovery_runs(evidence_id);
CREATE INDEX idx_recovery_runs_truncated ON recovery_runs(truncated);

CREATE TABLE IF NOT EXISTS recovery_candidates (
    id UUID PRIMARY KEY,
    recovery_run_id UUID NOT NULL REFERENCES recovery_runs(id) ON DELETE CASCADE,
    evidence_id UUID NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    recovery_level TEXT NOT NULL, -- 'L1', 'L2', 'L3'
    data_state TEXT NOT NULL,     -- 'Active', 'Deleted', 'Orphaned', 'Corrupted', 'Overwritten' (Req 13.2)
    recovery_status TEXT NOT NULL,-- 'Recoverable', 'PartiallyRecoverable', 'Unrecoverable' (Req 13.6)
    validation JSONB NOT NULL,    -- FrameValidationReport
    sha256 TEXT,
    hypothesis_metadata JSONB,
    provenance_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_recovery_candidates_run ON recovery_candidates(recovery_run_id);
CREATE INDEX idx_recovery_candidates_evidence ON recovery_candidates(evidence_id);
CREATE INDEX idx_recovery_candidates_state ON recovery_candidates(data_state, recovery_status);

CREATE TABLE IF NOT EXISTS recovery_candidate_source_regions (
    id UUID PRIMARY KEY,
    candidate_id UUID NOT NULL REFERENCES recovery_candidates(id) ON DELETE CASCADE,
    offset_start BIGINT NOT NULL,
    length BIGINT NOT NULL
);

CREATE INDEX idx_recovery_region_cand ON recovery_candidate_source_regions(candidate_id);
CREATE INDEX idx_recovery_region_offsets ON recovery_candidate_source_regions(offset_start, length);
