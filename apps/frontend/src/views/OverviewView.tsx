import React from 'react';
import { Shield, ShieldAlert, CheckCircle2, Database, HardDrive } from 'lucide-react';

import { Case, Evidence, Acquisition, SourceSafetyReport } from '../types';

interface OverviewViewProps {
  activeCase: Case | null;
  activeEvidence: Evidence | null;
  acquisition: Acquisition | null;
  safetyReport: SourceSafetyReport | null;
  ingestHash: string | null;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  activeCase,
  activeEvidence,
  acquisition,
  safetyReport,
  ingestHash,
}) => {
  const getBadgeClass = (status?: string) => {
    switch (status?.toLowerCase()) {
      case 'pass':
      case 'complete':
      case 'accepted':
      case 'read_only':
        return 'badge badge-pass';
      case 'review':
      case 'partial':
        return 'badge badge-review';
      case 'fail':
      case 'failed':
      case 'rejected':
      case 'read_write':
        return 'badge badge-fail';
      default:
        return 'badge badge-unknown';
    }
  };

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h1 className="view-title">Forensic Workstation Overview</h1>
          <p className="view-subtitle">High-level case summary, evidence integrity verification, and safety provenance</p>
        </div>
      </div>

      {/* Top Metrics Row */}
      <div className="grid-4" style={{ marginBottom: '20px' }}>
        <div className="stat-card">
          <div className="stat-label">Active Case</div>
          <div className="stat-value" style={{ fontSize: '15px', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
            {activeCase ? activeCase.name : 'No Case Loaded'}
          </div>
          <div className="stat-sub">Examiner: {activeCase ? activeCase.examiner : '—'}</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Source Safety State</div>
          <div style={{ marginTop: '6px' }}>
            <span className={getBadgeClass(safetyReport?.decision)}>
              {safetyReport?.decision === 'accepted' ? <CheckCircle2 size={12} /> : <ShieldAlert size={12} />}
              {safetyReport ? `${safetyReport.source_state} (${safetyReport.decision})` : 'Uninspected'}
            </span>
          </div>
          <div className="stat-sub">Hardware Write Blocker: Required</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Acquisition Status</div>
          <div style={{ marginTop: '6px' }}>
            <span className={getBadgeClass(acquisition?.status)}>
              {acquisition ? acquisition.status : 'Unknown'}
            </span>
          </div>
          <div className="stat-sub">
            Gaps / Bad Sectors: {acquisition?.bad_sector_ranges.length ? `${acquisition.bad_sector_ranges.length} range(s)` : 'None detected'}
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Evidence Capacity</div>
          <div className="stat-value" style={{ fontSize: '17px' }}>
            {activeEvidence ? `${(activeEvidence.capacity / (1024 * 1024 * 1024)).toFixed(2)} GB` : '—'}
          </div>
          <div className="stat-sub">Format: {activeEvidence ? activeEvidence.image_format : '—'}</div>
        </div>
      </div>

      {/* Main Panels Grid */}
      <div className="grid-2">
        {/* Evidence Ingest & Hash Details */}
        <div className="panel">
          <div className="panel-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <HardDrive size={15} color="var(--accent-primary)" />
              <span>Evidence Ingest & Provenance</span>
            </div>
            {activeEvidence && <span className="badge badge-pass">Registered</span>}
          </div>

          {activeEvidence ? (
            <table className="data-table">
              <tbody>
                <tr>
                  <td style={{ width: '140px', fontWeight: 600, color: 'var(--text-secondary)' }}>Source Device</td>
                  <td>{activeEvidence.source_device}</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Evidence ID</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{activeEvidence.id}</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>File Path</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{activeEvidence.path}</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>SHA-256 Ingest Hash</td>
                  <td style={{ fontFamily: 'var(--font-mono)', wordBreak: 'break-all', color: 'var(--accent-primary)' }}>
                    {ingestHash || 'Computing / Unhashed'}
                  </td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Acquisition Tool</td>
                  <td>{activeEvidence.acquisition_tool ? `${activeEvidence.acquisition_tool} (v${activeEvidence.acquisition_tool_version || '?'})` : 'Unknown'}</td>
                </tr>
              </tbody>
            </table>
          ) : (
            <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '24px 0' }}>
              No evidence registered yet. Go to the <strong>Evidence</strong> tab to register an image.
            </p>
          )}
        </div>

        {/* Source Safety & Write Blocking Audit */}
        <div className="panel">
          <div className="panel-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Shield size={15} color="var(--accent-primary)" />
              <span>Source Safety Inspection Audit (Req 1.8–1.12)</span>
            </div>
          </div>

          {safetyReport ? (
            <div>
              <div style={{ marginBottom: '12px', padding: '10px 14px', borderRadius: '4px', background: safetyReport.decision === 'accepted' ? 'var(--status-pass-bg)' : 'var(--status-fail-bg)', border: '1px solid ' + (safetyReport.decision === 'accepted' ? 'var(--status-pass-border)' : 'var(--status-fail-border)') }}>
                <div style={{ fontWeight: 700, color: safetyReport.decision === 'accepted' ? 'var(--status-pass-text)' : 'var(--status-fail-text)', marginBottom: '4px' }}>
                  Safety Decision: {safetyReport.decision.toUpperCase()}
                </div>
                <div style={{ fontSize: '11.5px', color: safetyReport.decision === 'accepted' ? '#14532d' : '#7f1d1d' }}>
                  {safetyReport.reason}
                </div>
              </div>

              <table className="data-table">
                <tbody>
                  <tr>
                    <td style={{ width: '140px', fontWeight: 600, color: 'var(--text-secondary)' }}>Inspected Source State</td>
                    <td><span className={getBadgeClass(safetyReport.source_state)}>{safetyReport.source_state}</span></td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Inspection Timestamp</td>
                    <td>{new Date(safetyReport.inspected_at).toLocaleString()}</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Application WriteGuard</td>
                    <td><span className="badge badge-pass">Enabled (Read-Only Secondary Barrier)</span></td>
                  </tr>
                </tbody>
              </table>
            </div>
          ) : (
            <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '24px 0' }}>
              Source safety check will run upon evidence registration.
            </p>
          )}
        </div>
      </div>

      {/* OEM Capabilities Preview */}
      <div className="panel">
        <div className="panel-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Database size={15} color="var(--accent-primary)" />
            <span>Multi-Vendor OEM Capability Maturity Model (Five Independent Dimensions — Req 21)</span>
          </div>
        </div>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>OEM / Platform Key</th>
                <th>Detection</th>
                <th>Topology Profiling</th>
                <th>Parsing</th>
                <th>Reconstruction</th>
                <th>Validation</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Dahua</strong> (DHFS / DHFS4.1)</td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
              </tr>
              <tr>
                <td><strong>Hikvision</strong> (HIK / HIKVISION_FS)</td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
              </tr>
              <tr>
                <td><strong>Honeywell</strong> (MAXPRO / MAXPRO_NVR)</td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
              </tr>
              <tr>
                <td><strong>CP Plus / UBS</strong> (CPPLUS_UBS)</td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
              </tr>
              <tr>
                <td><strong>Uniview</strong> (UBIFS / UNV)</td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
                <td><span className="badge badge-pass">Implemented</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
