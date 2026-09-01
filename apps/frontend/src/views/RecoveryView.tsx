import React from 'react';
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
          <h1 className="view-title">Deep Recovery & Video Reconstruction</h1>
          <p className="view-subtitle">Select an evidence target to execute recovery and reconstruction.</p>
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

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h1 className="view-title">Deep Recovery & Video Reconstruction</h1>
          <p className="view-subtitle">Multi-level indexed, orphan/slack, and raw carving reconstruction (Phase 4 / Req 13, 14)</p>
        </div>
      </div>

      {/* Metrics & Bounds Banner */}
      <div className="metrics-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '24px' }}>
        <div className="metric-card" style={{ padding: '16px', backgroundColor: '#1e1e1e', borderRadius: '8px', border: '1px solid #333' }}>
          <div className="metric-label" style={{ fontSize: '12px', color: '#888', marginBottom: '4px' }}>Recovery Run Extent</div>
          <div className="metric-value" style={{ fontSize: '18px', fontWeight: 'bold' }}>
            {(mockRun.searched_bytes / (1024 * 1024 * 1024)).toFixed(1)} GB / {(mockRun.total_bytes / (1024 * 1024 * 1024)).toFixed(1)} GB
          </div>
          <div className="metric-subtext" style={{ fontSize: '12px', color: '#ff9800' }}>
            {mockRun.truncated ? '⚠️ Bounded (Truncated)' : 'Exhaustive Scan'}
          </div>
        </div>

        <div className="metric-card" style={{ padding: '16px', backgroundColor: '#1e1e1e', borderRadius: '8px', border: '1px solid #333' }}>
          <div className="metric-label" style={{ fontSize: '12px', color: '#888', marginBottom: '4px' }}>Recovery Validation State</div>
          <div className="metric-value" style={{ fontSize: '18px', fontWeight: 'bold', color: mockRun.validation_state.state === 'REVIEW' ? '#ff9800' : '#4caf50' }}>
            {mockRun.validation_state.state}
          </div>
          <div className="metric-subtext" style={{ fontSize: '11px', color: '#aaa', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {mockRun.validation_state.reason}
          </div>
        </div>

        <div className="metric-card" style={{ padding: '16px', backgroundColor: '#1e1e1e', borderRadius: '8px', border: '1px solid #333' }}>
          <div className="metric-label" style={{ fontSize: '12px', color: '#888', marginBottom: '4px' }}>Candidates Accepted / Total</div>
          <div className="metric-value" style={{ fontSize: '24px', fontWeight: 'bold', color: '#4caf50' }}>
            {mockRun.accepted} / {mockRun.candidate_count}
          </div>
          <div className="metric-subtext" style={{ fontSize: '12px', color: '#aaa' }}>{mockRun.rejected} rejected by media QC</div>
        </div>

        <div className="metric-card" style={{ padding: '16px', backgroundColor: '#1e1e1e', borderRadius: '8px', border: '1px solid #333' }}>
          <div className="metric-label" style={{ fontSize: '12px', color: '#888', marginBottom: '4px' }}>Artifact Classification</div>
          <div className="metric-value" style={{ fontSize: '16px', fontWeight: 'bold' }}>Native + Derived</div>
          <div className="metric-subtext" style={{ fontSize: '12px', color: '#2196f3' }}>Strict Lineage Separation (Req 5.9)</div>
        </div>
      </div>

      {/* Main Table */}
      <div className="data-panel" style={{ backgroundColor: '#1e1e1e', borderRadius: '8px', border: '1px solid #333', overflow: 'hidden' }}>
        <div className="panel-header" style={{ padding: '16px', borderBottom: '1px solid #333', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ margin: 0, fontSize: '16px' }}>Reconstructed Recording Candidates</h3>
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr style={{ backgroundColor: '#252525', textAlign: 'left' }}>
              <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Candidate / Channel</th>
              <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Timestamp & Duration</th>
              <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>DataState (Physical)</th>
              <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>RecoveryStatus</th>
              <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Level</th>
              <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Artifacts</th>
              <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Validation</th>
              <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {mockCandidates.map(cand => (
              <tr key={cand.id} style={{ borderBottom: '1px solid #333' }}>
                <td style={{ padding: '12px 16px' }}>
                  <div style={{ fontWeight: 'bold' }}>{cand.id}</div>
                  <div style={{ color: '#888' }}>CH {cand.channel} | {cand.codec}</div>
                </td>
                <td style={{ padding: '12px 16px' }}>
                  <div>{cand.time_native}</div>
                  <div style={{ color: '#888', fontSize: '11px' }}>{cand.duration_sec > 0 ? `${Math.floor(cand.duration_sec / 60)} min` : 'N/A'}</div>
                </td>
                <td style={{ padding: '12px 16px' }}>
                  <span style={{
                    padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold',
                    backgroundColor: cand.data_state === 'Active' ? '#2e7d3233' : cand.data_state === 'Deleted' ? '#c6282833' : cand.data_state === 'Orphaned' ? '#ef6c0033' : '#6a1b9a33',
                    color: cand.data_state === 'Active' ? '#81c784' : cand.data_state === 'Deleted' ? '#e57373' : cand.data_state === 'Orphaned' ? '#ffb74d' : '#ba68c8',
                  }}>
                    {cand.data_state}
                  </span>
                </td>
                <td style={{ padding: '12px 16px' }}>
                  <span style={{
                    padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold',
                    backgroundColor: cand.recovery_status === 'Recoverable' ? '#1b5e2033' : cand.recovery_status === 'PartiallyRecoverable' ? '#e6510033' : '#b71c1c33',
                    color: cand.recovery_status === 'Recoverable' ? '#a5d6a7' : cand.recovery_status === 'PartiallyRecoverable' ? '#ffcc80' : '#ef9a9a',
                  }}>
                    {cand.recovery_status}
                  </span>
                </td>
                <td style={{ padding: '12px 16px' }}>
                  <span style={{ padding: '2px 6px', borderRadius: '4px', fontSize: '11px', backgroundColor: '#333', color: '#eee' }}>
                    {cand.recovery_level}
                  </span>
                </td>
                <td style={{ padding: '12px 16px' }}>
                  <div style={{ display: 'flex', gap: '4px', flexDirection: 'column' }}>
                    {cand.has_native_artifact && (
                      <span style={{ fontSize: '10px', padding: '1px 4px', borderRadius: '2px', backgroundColor: '#0d47a1', color: '#90caf9' }}>
                        [Native]
                      </span>
                    )}
                    {cand.has_derived_artifact && (
                      <span style={{ fontSize: '10px', padding: '1px 4px', borderRadius: '2px', backgroundColor: '#4a148c', color: '#ce93d8' }}>
                        [Derived Remux]
                      </span>
                    )}
                  </div>
                </td>
                <td style={{ padding: '12px 16px' }}>
                  <span style={{
                    padding: '2px 6px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold',
                    backgroundColor: cand.validation.state === 'PASS' ? '#4caf5033' : cand.validation.state === 'REVIEW' ? '#ff980033' : '#f4433633',
                    color: cand.validation.state === 'PASS' ? '#81c784' : cand.validation.state === 'REVIEW' ? '#ffb74d' : '#e57373',
                  }}>
                    {cand.validation.state}
                  </span>
                  <div style={{ fontSize: '11px', color: '#777', marginTop: '2px', maxWidth: '200px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {cand.validation.reason}
                  </div>
                </td>
                <td style={{ padding: '12px 16px' }}>
                  <button
                    onClick={() => onNavigateToHex(cand.source_offset)}
                    style={{ background: '#2196f3', color: 'white', border: 'none', padding: '4px 8px', borderRadius: '4px', cursor: 'pointer', fontSize: '11px' }}
                  >
                    View Hex (0x{cand.source_offset.toString(16)})
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
