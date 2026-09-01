-- Phase 6: Forensic Reporting and Artifact Export Tables

CREATE TABLE IF NOT EXISTS forensic_reports (
    id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    examiner TEXT NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL,
    evidence_summary JSONB NOT NULL,
    attribution_summary JSONB NOT NULL,
    capabilities_summary JSONB NOT NULL,
    validation_summary JSONB NOT NULL,
    recovery_summary JSONB NOT NULL,
    timeline_summary JSONB NOT NULL,
    artifacts_summary JSONB NOT NULL,
    custody_summary JSONB NOT NULL,
    stated_limitations JSONB NOT NULL,
    report_sha256 TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_reports_case ON forensic_reports(case_id);
CREATE INDEX IF NOT EXISTS idx_reports_sha256 ON forensic_reports(report_sha256);

CREATE TABLE IF NOT EXISTS report_artifacts (
    id UUID PRIMARY KEY,
    report_id UUID NOT NULL REFERENCES forensic_reports(id) ON DELETE CASCADE,
    export_format TEXT NOT NULL, -- 'json', 'csv', 'markdown', 'pdf'
    sha256 TEXT NOT NULL,
    byte_length BIGINT NOT NULL,
    output_path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_report_artifacts_report ON report_artifacts(report_id);
