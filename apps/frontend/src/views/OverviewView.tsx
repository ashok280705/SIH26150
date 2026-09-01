import React from 'react';
import { Shield, ShieldAlert, CheckCircle2, Database, HardDrive, ShieldCheck } from 'lucide-react';

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
      <div className="grid-4 mb-4">
        <div className="stat-card">
          <div className="stat-label">Active Case</div>
          <div className="stat-value" style={{ textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
            {activeCase ? activeCase.name : 'No Case Loaded'}
          </div>
          <div className="stat-sub">Examiner: {activeCase ? activeCase.examiner : '—'}</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Source Safety State</div>
          <div className="mt-4">
            <span className={getBadgeClass(safetyReport?.decision)}>
              {safetyReport?.decision === 'accepted' ? <CheckCircle2 size={12} /> : <ShieldAlert size={12} />}
              {safetyReport ? `${safetyReport.source_state} (${safetyReport.decision})` : 'Uninspected'}
            </span>
          </div>
          <div className="stat-sub">Hardware Write Blocker: Required</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Acquisition Status</div>
          <div className="mt-4">
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
          <div className="stat-value">
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
            <div className="flex items-center gap-2">
              <HardDrive size={15} style={{ color: 'var(--accent)' }} />
              <span>Evidence Ingest & Provenance</span>
            </div>
            {activeEvidence && <span className="badge badge-pass">Registered</span>}
          </div>

          {activeEvidence ? (
            <div className="table-container">
              <table className="data-table">
                <tbody>
                  <tr>
                    <td style={{ width: '150px' }}><strong>Source Device</strong></td>
                    <td>{activeEvidence.source_device}</td>
                  </tr>
                  <tr>
                    <td><strong>Evidence ID</strong></td>
                    <td className="mono">{activeEvidence.id}</td>
                  </tr>
                  <tr>
                    <td><strong>File Path</strong></td>
                    <td className="mono">{activeEvidence.path}</td>
                  </tr>
                  <tr>
                    <td><strong>SHA-256 Ingest Hash</strong></td>
                    <td className="mono" style={{ wordBreak: 'break-all', color: 'var(--accent)' }}>
                      {ingestHash || 'Computing / Unhashed'}
                    </td>
                  </tr>
                  <tr>
                    <td><strong>Acquisition Tool</strong></td>
                    <td>{activeEvidence.acquisition_tool ? `${activeEvidence.acquisition_tool} (v${activeEvidence.acquisition_tool_version || '?'})` : 'Unknown'}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <HardDrive size={32} />
              <h3>No Evidence Selected</h3>
              <p>Go to the Evidence tab to register or select a raw evidence image.</p>
            </div>
          )}
        </div>

        {/* Source Safety & Write Blocking Audit */}
        <div className="panel">
          <div className="panel-header">
            <div className="flex items-center gap-2">
              <Shield size={15} style={{ color: 'var(--accent)' }} />
              <span>Source Safety Inspection Audit (Req 1.8–1.12)</span>
            </div>
          </div>

          {safetyReport ? (
            <div>
              {safetyReport.decision === 'accepted' ? (
                <div className="alert alert-success">
                  <ShieldCheck size={18} />
                  <div>
                    <strong>Safety Decision: {safetyReport.decision.toUpperCase()}</strong>
                    <div className="text-muted" style={{ fontSize: '11px', marginTop: '2px' }}>{safetyReport.reason}</div>
                  </div>
                </div>
              ) : (
                <div className="alert alert-error">
                  <ShieldAlert size={18} />
                  <div>
                    <strong>Safety Decision: {safetyReport.decision.toUpperCase()}</strong>
                    <div className="text-muted" style={{ fontSize: '11px', marginTop: '2px' }}>{safetyReport.reason}</div>
                  </div>
                </div>
              )}

              <div className="table-container">
                <table className="data-table">
                  <tbody>
                    <tr>
                      <td style={{ width: '160px' }}><strong>Inspected Source State</strong></td>
                      <td><span className={getBadgeClass(safetyReport.source_state)}>{safetyReport.source_state}</span></td>
                    </tr>
                    <tr>
                      <td><strong>Inspection Timestamp</strong></td>
                      <td>{new Date(safetyReport.inspected_at).toLocaleString()}</td>
                    </tr>
                    <tr>
                      <td><strong>Application WriteGuard</strong></td>
                      <td><span className="badge badge-pass">Enabled (Read-Only Barrier)</span></td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="empty-state">
              <Shield size={32} />
              <h3>Pending Inspection</h3>
              <p>Source safety check will run upon evidence registration.</p>
            </div>
          )}
        </div>
      </div>

      {/* OEM Capabilities Preview */}
      <div className="panel">
        <div className="panel-header">
          <div className="flex items-center gap-2">
            <Database size={15} style={{ color: 'var(--accent)' }} />
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
