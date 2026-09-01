import React from 'react';
import { Video } from 'lucide-react';
import { Evidence, RecoveryCandidateUI, RecoveryRunUI } from '../types';

interface RecoveryViewProps {
  evidence: Evidence | null;
  onNavigateToHex: (offset: number) => void;
}

export const RecoveryView: React.FC<RecoveryViewProps> = ({ evidence, onNavigateToHex }) => {
  if (!evidence) {
    return (
      <div className="view-container">
        <div className="view-header">
          <div>
            <h1 className="view-title">Deep Recovery & Video Reconstruction</h1>
            <p className="view-subtitle">Select an evidence target to execute recovery and reconstruction.</p>
          </div>
        </div>
        <div className="empty-state">
          <Video size={32} />
          <h3>No Evidence Selected</h3>
          <p>Select a DVR/NVR evidence item from the active case to begin analysis.</p>
        </div>
      </div>
    );
  }

  // Mock Recovery Run representing bounded multi-level search extent
  const mockRun: RecoveryRunUI = {
    searched_bytes: 4 * 1024 * 1024 * 1024, // 4 GB
    total_bytes: 8 * 1024 * 1024 * 1024,    // 8 GB
    skipped_bytes: 1024 * 1024 * 1024,     // 1 GB skipped
    candidate_count: 8,
    accepted: 6,
    rejected: 2,
    truncated: true, // Bounded search truncated → REVIEW
    validation_state: {
      state: 'REVIEW',
      reason: 'Bounded scan limit reached (4 GB); full storage extent not exhaustively searched',
      operation: 'execute_recovery',
      subject: 'RecoveryRun',
    },
  };

  const mockCandidates: RecoveryCandidateUI[] = [
    {
      id: 'cand-001',
      channel: 1,
      time_native: '2026-09-01 14:00:00',
      duration_sec: 1800,
      data_state: 'Active',
      recovery_status: 'Recoverable',
      recovery_level: 'L1',
      source_offset: 0x00100000,
      source_length: 250 * 1024 * 1024,
      integrity_status: 'Intact Index',
      codec: 'H.264',
      validation: { state: 'PASS', reason: 'Verified GOP structure and decoded keyframes', operation: 'reconstruct', subject: 'cand-001' },
      has_native_artifact: true,
      has_derived_artifact: true,
    },
    {
      id: 'cand-002',
      channel: 2,
      time_native: '2026-09-01 14:30:00',
      duration_sec: 1200,
      data_state: 'Deleted',
      recovery_status: 'Recoverable',
      recovery_level: 'L2',
      source_offset: 0x01500000,
      source_length: 180 * 1024 * 1024,
      integrity_status: 'Unlinked Block Table',
      codec: 'H.265',
      validation: { state: 'PASS', reason: 'Recovered via orphan payload scan; GOP sequence validated', operation: 'reconstruct', subject: 'cand-002' },
      has_native_artifact: true,
      has_derived_artifact: true,
    },
    {
      id: 'cand-003',
      channel: 1,
      time_native: '2026-09-01 12:15:00',
      duration_sec: 450,
      data_state: 'Orphaned',
      recovery_status: 'PartiallyRecoverable',
      recovery_level: 'L3',
      source_offset: 0x02800000,
      source_length: 64 * 1024 * 1024,
      integrity_status: 'Fragmented Frames',
      codec: 'H.264',
      validation: { state: 'REVIEW', reason: 'Missing frames between GOP #4 and #5; marked 1 gap', operation: 'reconstruct', subject: 'cand-003' },
      has_native_artifact: true,
      has_derived_artifact: true,
    },
    {
      id: 'cand-004',
      channel: 3,
      time_native: '2026-09-01 10:00:00',
      duration_sec: 900,
      data_state: 'Corrupted',
      recovery_status: 'PartiallyRecoverable',
      recovery_level: 'L3',
      source_offset: 0x03C00000,
      source_length: 90 * 1024 * 1024,
      integrity_status: 'CRC Mismatch (Payload Intact)',
      codec: 'H.264',
      validation: { state: 'REVIEW', reason: 'Corrupted block headers but video NAL payload recoverable', operation: 'reconstruct', subject: 'cand-004' },
      has_native_artifact: true,
      has_derived_artifact: false,
    },
    {
      id: 'cand-005',
      channel: 4,
      time_native: '2026-08-31 23:00:00',
      duration_sec: 0,
      data_state: 'Overwritten',
      recovery_status: 'Unrecoverable',
      recovery_level: 'L2',
      source_offset: 0x05000000,
      source_length: 128 * 1024 * 1024,
      integrity_status: 'Overwritten by Circular Wrap',
      codec: 'Unknown',
      validation: { state: 'FAIL', reason: 'Physical sectors confirmed overwritten by new camera data', operation: 'reconstruct', subject: 'cand-005' },
      has_native_artifact: true,
      has_derived_artifact: false,
    },
  ];

  const getValidationBadge = (state: string) => {
    switch (state) {
      case 'PASS': return 'badge badge-pass';
      case 'REVIEW': return 'badge badge-review';
      case 'FAIL': return 'badge badge-fail';
      default: return 'badge badge-unknown';
    }
  };

  const getDataStateBadge = (state: string) => {
    switch (state) {
      case 'Active': return 'badge badge-pass';
      case 'Deleted': return 'badge badge-fail';
      case 'Orphaned': return 'badge badge-review';
      default: return 'badge badge-unknown'; // For Corrupted, Overwritten etc.
    }
  };

  const getRecoveryStatusBadge = (status: string) => {
    switch (status) {
      case 'Recoverable': return 'badge badge-pass';
      case 'PartiallyRecoverable': return 'badge badge-review';
      case 'Unrecoverable': return 'badge badge-fail';
      default: return 'badge badge-unknown';
    }
  };

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h1 className="view-title">Deep Recovery & Video Reconstruction</h1>
          <p className="view-subtitle">Multi-level indexed, orphan/slack, and raw carving reconstruction (Phase 4 / Req 13, 14)</p>
        </div>
      </div>

      {/* Metrics & Bounds Banner */}
      <div className="grid-4 mb-4">
        <div className="stat-card">
          <div className="stat-label">Recovery Run Extent</div>
          <div className="stat-value">
            {(mockRun.searched_bytes / (1024 * 1024 * 1024)).toFixed(1)} GB / {(mockRun.total_bytes / (1024 * 1024 * 1024)).toFixed(1)} GB
          </div>
          <div className="stat-sub mt-4">
            {mockRun.truncated ? (
              <span className="badge badge-review">⚠️ Bounded (Truncated)</span>
            ) : (
              <span className="badge badge-pass">Exhaustive Scan</span>
            )}
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Recovery Validation State</div>
          <div className="mt-4">
             <span className={getValidationBadge(mockRun.validation_state.state)}>
                {mockRun.validation_state.state}
             </span>
          </div>
          <div className="stat-sub mt-4" style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {mockRun.validation_state.reason}
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Candidates Accepted / Total</div>
          <div className="stat-value" style={{ color: 'var(--success)' }}>
            {mockRun.accepted} / {mockRun.candidate_count}
          </div>
          <div className="stat-sub">{mockRun.rejected} rejected by media QC</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Artifact Classification</div>
          <div className="stat-value" style={{ fontSize: '18px' }}>Native + Derived</div>
          <div className="stat-sub" style={{ color: 'var(--accent)' }}>Strict Lineage Separation (Req 5.9)</div>
        </div>
      </div>

      {/* Main Table */}
      <div className="panel" style={{ padding: '0', overflow: 'hidden' }}>
        <div className="panel-header" style={{ margin: 0, padding: '16px' }}>
          <h3 style={{ margin: 0, fontSize: '14px' }}>Reconstructed Recording Candidates</h3>
        </div>
        <div className="table-container" style={{ border: 'none', borderTop: '1px solid var(--border)', borderRadius: '0' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Candidate / Channel</th>
                <th>Timestamp & Duration</th>
                <th>DataState (Physical)</th>
                <th>RecoveryStatus</th>
                <th>Level</th>
                <th>Artifacts</th>
                <th>Validation</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {mockCandidates.map(cand => (
                <tr key={cand.id}>
                  <td>
                    <div style={{ fontWeight: 600 }}>{cand.id}</div>
                    <div className="text-muted" style={{ fontSize: '11px' }}>CH {cand.channel} | {cand.codec}</div>
                  </td>
                  <td>
                    <div>{cand.time_native}</div>
                    <div className="text-muted" style={{ fontSize: '11px' }}>{cand.duration_sec > 0 ? `${Math.floor(cand.duration_sec / 60)} min` : 'N/A'}</div>
                  </td>
                  <td>
                    <span className={getDataStateBadge(cand.data_state)}>
                      {cand.data_state}
                    </span>
                  </td>
                  <td>
                    <span className={getRecoveryStatusBadge(cand.recovery_status)}>
                      {cand.recovery_status}
                    </span>
                  </td>
                  <td>
                    <span className="badge badge-info">
                      {cand.recovery_level}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: '4px', flexDirection: 'column' }}>
                      {cand.has_native_artifact && (
                        <span className="badge badge-info" style={{ fontSize: '9px', padding: '1px 4px' }}>
                          [Native]
                        </span>
                      )}
                      {cand.has_derived_artifact && (
                        <span className="badge badge-unknown" style={{ fontSize: '9px', padding: '1px 4px' }}>
                          [Derived Remux]
                        </span>
                      )}
                    </div>
                  </td>
                  <td>
                    <span className={getValidationBadge(cand.validation.state)}>
                      {cand.validation.state}
                    </span>
                    <div className="text-muted" style={{ fontSize: '11px', marginTop: '4px', maxWidth: '200px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {cand.validation.reason}
                    </div>
                  </td>
                  <td>
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={() => onNavigateToHex(cand.source_offset)}
                    >
                      Hex (<span className="mono">0x{cand.source_offset.toString(16).toUpperCase()}</span>)
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
