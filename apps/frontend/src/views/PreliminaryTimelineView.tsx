import React, { useState, useEffect } from 'react';
import { ListTree, RefreshCw, HardDrive, CheckCircle2, AlertTriangle, ArrowRight } from 'lucide-react';
import { Evidence, PipelineRun } from '../types';
import { runFullPipeline } from '../services/api';
import { ContextHelp } from '../components/onboarding/ContextHelp';
import { WorkflowState } from '../workflow';

interface Props {
  evidence: Evidence | null;
  evidenceList?: Evidence[];
  onSelectEvidence?: (e: Evidence) => void;
  onNavigateToHex: (offset: number) => void;
  workflow?: WorkflowState;
  onWorkflow?: (patch: Partial<WorkflowState>) => void;
}

export const PreliminaryTimelineView: React.FC<Props> = ({ evidence, workflow, onWorkflow }) => {
  const [run, setRun] = useState<PipelineRun | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setRun(null);
    setError(null);
    if (evidence) build();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evidence?.id]);

  const build = async () => {
    if (!evidence) return;
    setLoading(true);
    setError(null);
    try {
      // The pipeline endpoint is the real source of the preliminary timeline and the
      // gap/coverage analysis (both computed by the Rust engine). We consume only its
      // preliminary-timeline and gap-analysis fields here; the analyst advances to
      // Recovery or Final Timeline via the sidebar once this result lands.
      const r = await runFullPipeline(evidence.id);
      setRun(r);
      if (onWorkflow) {
        onWorkflow({
          timelineBuilt: true,
          gapsPresent: r.gap_analysis?.gaps_present ?? false,
          coverageRatio: r.gap_analysis?.coverage.coverage_ratio ?? null,
          recoveryRequired: r.gap_analysis?.gaps_present ?? false,
        });
      }
    } catch (e: any) {
      setError(e?.message || 'Failed to build preliminary timeline');
    } finally {
      setLoading(false);
    }
  };

  if (!evidence) {
    return (
      <div className="view-container">
        <div className="view-header">
          <div>
            <h1 className="view-title">Preliminary Timeline Construction</h1>
            <p className="view-subtitle">Select an evidence target to build the preliminary timeline.</p>
          </div>
        </div>
        <div className="empty-state"><ListTree size={32} /><h3>No Evidence Selected</h3></div>
      </div>
    );
  }

  const gaps = run?.gap_analysis;
  const coveragePct = gaps ? (gaps.coverage.coverage_ratio * 100).toFixed(1) : null;
  const gapsPresent = gaps?.gaps_present ?? null;

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h1 className="view-title">Preliminary Timeline Construction</h1>
            <ContextHelp
              title="Preliminary Timeline"
              content="Builds a timeline from the extraction, normalizes timestamps, and detects temporal gaps and unaccounted image regions. Gaps route to the Recovery Engine; no gaps route straight to the Final Timeline."
            />
          </div>
          <p className="view-subtitle">Normalize timestamps · correlate events · detect gaps · estimate coverage</p>
        </div>
        <button className="btn btn-secondary" onClick={build} disabled={loading}>
          {loading ? <RefreshCw size={14} className="spin" /> : <RefreshCw size={14} />}
          <span>Rebuild</span>
        </button>
      </div>

      {/* Target bar */}
      <div className="panel" style={{ padding: '16px', marginBottom: '20px', backgroundColor: 'var(--surface)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <HardDrive size={18} style={{ color: 'var(--accent)' }} />
          <div>
            <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 600 }}>Active Target</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '2px' }}>
              <strong style={{ fontSize: '14px' }}>{evidence.source_device}</strong>
              <span className="badge badge-info">{evidence.image_format}</span>
              {workflow?.parserUsed && <span className="badge badge-pass">parser: {workflow.parserUsed}</span>}
            </div>
          </div>
        </div>
      </div>

      {error && (
        <div className="panel mb-4" style={{ borderLeft: '4px solid var(--danger)' }}>
          <strong>Failed to build timeline</strong>
          <div className="text-muted" style={{ fontSize: '13px', marginTop: '4px' }}>{error}</div>
        </div>
      )}

      {loading && !run && <div className="empty-state"><RefreshCw size={28} className="spin" /><h3>Building timeline…</h3></div>}

      {run && (
        <>
          {/* Gap verdict */}
          <div
            className="panel mb-4"
            style={{ borderLeft: `4px solid ${gapsPresent ? 'var(--warning)' : 'var(--success)'}` }}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
              {gapsPresent ? (
                <AlertTriangle size={22} style={{ color: 'var(--warning)', flexShrink: 0 }} />
              ) : (
                <CheckCircle2 size={22} style={{ color: 'var(--success)', flexShrink: 0 }} />
              )}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                  <strong style={{ fontSize: '15px' }}>Gap Analysis</strong>
                  <span className={gapsPresent ? 'badge badge-review' : 'badge badge-pass'}>
                    {gapsPresent ? 'GAPS PRESENT' : 'NO GAPS FOUND'}
                  </span>
                </div>
                <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '6px' }}>
                  {gaps?.validation.reason}
                </div>
                <div style={{ fontSize: '13px', marginTop: '8px', display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--accent)' }}>
                  <ArrowRight size={14} />
                  {gapsPresent
                    ? 'Proceed to the Recovery Engine (now unlocked) to recover the missing regions.'
                    : 'Proceed to the Final Timeline (now unlocked).'}
                </div>
              </div>
            </div>
          </div>

          {/* Metrics */}
          <div className="grid-4 mb-4">
            <div className="stat-card">
              <div className="stat-label">Preliminary Events</div>
              <div className="stat-value">{run.preliminary_timeline?.events.length ?? 0}</div>
              <div className="stat-sub">{run.correlation_groups.length} cross-camera group(s)</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Image Coverage</div>
              <div className="stat-value" style={{ fontSize: '16px' }}>{coveragePct}%</div>
              {gaps && (
                <div style={{ height: '6px', background: 'var(--surface-muted)', borderRadius: '3px', marginTop: '8px', overflow: 'hidden' }}>
                  <div style={{ width: `${gaps.coverage.coverage_ratio * 100}%`, height: '100%', background: 'var(--accent)' }} />
                </div>
              )}
            </div>
            <div className="stat-card">
              <div className="stat-label">Unaccounted</div>
              <div className="stat-value" style={{ fontSize: '16px' }}>
                {gaps ? `${(gaps.coverage.unaccounted_bytes / (1024 * 1024)).toFixed(2)} MB` : '—'}
              </div>
              <div className="stat-sub">not attributed to a recording</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Unknown Timezone</div>
              <div className="stat-value">{gaps?.events_with_unknown_timezone ?? 0}</div>
              <div className="stat-sub">events excluded from temporal maths</div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
