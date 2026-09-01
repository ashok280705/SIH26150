import React from 'react';
import { Evidence, ParserRun, Recording, DeletedCandidate, TimeEvidence } from '../types';

interface ParsingViewProps {
  evidence: Evidence | null;
  onNavigateToHex: (offset: number) => void;
}

export const ParsingView: React.FC<ParsingViewProps> = ({ evidence, onNavigateToHex }) => {
  if (!evidence) {
    return (
      <div className="view-container">
        <div className="view-header">
          <h1 className="view-title">Storage & Recording Parsers</h1>
          <p className="view-subtitle">Select an evidence item to view parsed data.</p>
        </div>
      </div>
    );
  }

  // Mock data for Phase 3 UI evaluation
  const mockApplicability = {
    oem: 'DAHUA',
    storageFamily: 'DAHUA_DHFS',
    profileVersion: '1.0.0',
    confidence: 'Confirmed (1.10)'
  };

  const mockParserRuns: ParserRun[] = [
    {
      id: 'run-1', evidence_id: evidence.id, parser_id: 'dahua-dhfs', parser_version: '1.0.0',
      operation_name: 'parse_filesystem', started_at: new Date().toISOString(), completed_at: new Date().toISOString(),
      validation: { state: 'PASS', reason: 'Valid DHFS Superblock found', operation: 'parse_filesystem', subject: 'superblock' }
    },
    {
      id: 'run-2', evidence_id: evidence.id, parser_id: 'dahua-dhfs', parser_version: '1.0.0',
      operation_name: 'parse_metadata', started_at: new Date().toISOString(), completed_at: new Date().toISOString(),
      validation: { state: 'PASS', reason: 'Index blocks fully mapped', operation: 'parse_metadata', subject: 'index' }
    },
    {
      id: 'run-3', evidence_id: evidence.id, parser_id: 'dahua-dhfs', parser_version: '1.0.0',
      operation_name: 'parse_recordings', started_at: new Date().toISOString(), completed_at: new Date().toISOString(),
      validation: { state: 'REVIEW', reason: 'Found 3 fragmented/deleted recordings', operation: 'parse_recordings', subject: 'recordings' }
    }
  ];

  const mockTime = (raw: number, native: string, utc: string | null, ref: string | null, tz: 'known' | 'unknown' | 'inferred'): TimeEvidence => ({
    raw_value: raw,
    recorder_native: native,
    normalized_utc: utc,
    reference_time: ref,
    timezone_state: tz
  });

  const mockRecordings: Recording[] = [
    { id: 'rec-1', evidence_id: evidence.id, channel_id: 1, codec: 'H.264', frame_count: 1500, offset_start: 1048576, offset_end: 2097152, is_deleted: false, is_fragmented: false,
      start_time: mockTime(1672531200, '2023-01-01 00:00:00', '2023-01-01T00:00:00Z', '2023-01-01T00:00:00Z', 'known'),
      end_time: mockTime(1672534800, '2023-01-01 01:00:00', '2023-01-01T01:00:00Z', '2023-01-01T01:00:00Z', 'known') },
    { id: 'rec-2', evidence_id: evidence.id, channel_id: 2, codec: 'H.265', frame_count: 3200, offset_start: 3145728, offset_end: 5192837, is_deleted: false, is_fragmented: false,
      start_time: mockTime(1672617600, '2023-01-02 00:00:00', null, null, 'unknown'),
      end_time: mockTime(1672621200, '2023-01-02 01:00:00', null, null, 'unknown') }
  ];

  const mockDeleted: DeletedCandidate[] = [
    { id: 'del-1', offset_start: 8388608, reason: 'Orphaned DATA marker detected (no index entry)', validation: { state: 'REVIEW', reason: 'Possible unlinked fragment', operation: 'parse_recordings', subject: 'deleted' } },
    { id: 'del-2', offset_start: 9437184, reason: 'Overwritten frame boundaries', validation: { state: 'UNKNOWN', reason: 'Partial payload only', operation: 'parse_recordings', subject: 'deleted' } }
  ];

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h1 className="view-title">Storage & Recording Parsers</h1>
          <p className="view-subtitle">High-speed extraction of recordings and video index tables</p>
        </div>
      </div>
      
      <div className="metrics-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '24px' }}>
        <div className="metric-card" style={{ padding: '16px', backgroundColor: '#1e1e1e', borderRadius: '8px', border: '1px solid #333' }}>
          <div className="metric-label" style={{ fontSize: '12px', color: '#888', marginBottom: '4px' }}>Applicability & Profile</div>
          <div className="metric-value" style={{ fontSize: '18px', fontWeight: 'bold' }}>{mockApplicability.oem} {mockApplicability.storageFamily}</div>
          <div className="metric-subtext" style={{ fontSize: '12px', color: '#4caf50' }}>{mockApplicability.confidence} (v{mockApplicability.profileVersion})</div>
        </div>
        <div className="metric-card" style={{ padding: '16px', backgroundColor: '#1e1e1e', borderRadius: '8px', border: '1px solid #333' }}>
          <div className="metric-label" style={{ fontSize: '12px', color: '#888', marginBottom: '4px' }}>Recordings Extracted</div>
          <div className="metric-value" style={{ fontSize: '24px', fontWeight: 'bold' }}>{mockRecordings.length}</div>
          <div className="metric-subtext" style={{ fontSize: '12px', color: '#aaa' }}>Across 2 channels</div>
        </div>
        <div className="metric-card" style={{ padding: '16px', backgroundColor: '#1e1e1e', borderRadius: '8px', border: '1px solid #333' }}>
          <div className="metric-label" style={{ fontSize: '12px', color: '#888', marginBottom: '4px' }}>Deleted Candidates</div>
          <div className="metric-value" style={{ fontSize: '24px', fontWeight: 'bold', color: '#f44336' }}>{mockDeleted.length}</div>
          <div className="metric-subtext" style={{ fontSize: '12px', color: '#aaa' }}>Recoverable fragments</div>
        </div>
        <div className="metric-card" style={{ padding: '16px', backgroundColor: '#1e1e1e', borderRadius: '8px', border: '1px solid #333' }}>
          <div className="metric-label" style={{ fontSize: '12px', color: '#888', marginBottom: '4px' }}>Date Range</div>
          <div className="metric-value" style={{ fontSize: '16px', fontWeight: 'bold' }}>2023-01-01</div>
          <div className="metric-subtext" style={{ fontSize: '12px', color: '#aaa' }}>to 2023-01-02</div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '24px' }}>
        {/* Main Content Area */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '24px' }}>
          
          <div className="data-panel" style={{ backgroundColor: '#1e1e1e', borderRadius: '8px', border: '1px solid #333', overflow: 'hidden' }}>
            <div className="panel-header" style={{ padding: '16px', borderBottom: '1px solid #333', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ margin: 0, fontSize: '16px' }}>Parsed Recordings</h3>
            </div>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
              <thead>
                <tr style={{ backgroundColor: '#252525', textAlign: 'left' }}>
                  <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>ID / CH</th>
                  <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Start Time (TimeEvidence)</th>
                  <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>End Time (TimeEvidence)</th>
                  <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Location (Hex)</th>
                </tr>
              </thead>
              <tbody>
                {mockRecordings.map(rec => (
                  <tr key={rec.id} style={{ borderBottom: '1px solid #333' }}>
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ fontWeight: 'bold' }}>{rec.id}</div>
                      <div style={{ color: '#888' }}>CH {rec.channel_id} | {rec.codec} ({rec.frame_count} frames)</div>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <div>Native: <span style={{ color: '#fff' }}>{rec.start_time.recorder_native}</span></div>
                      <div style={{ color: '#888', marginTop: '2px' }}>
                        {rec.start_time.timezone_state === 'unknown' ? (
                          <span style={{ color: '#ff9800' }}>⚠️ Timezone Unknown</span>
                        ) : (
                          <span>UTC: {rec.start_time.normalized_utc}</span>
                        )}
                      </div>
                      <div style={{ color: '#555', fontSize: '11px', marginTop: '2px' }}>Raw: {rec.start_time.raw_value}</div>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <div>Native: <span style={{ color: '#fff' }}>{rec.end_time.recorder_native}</span></div>
                      <div style={{ color: '#888', marginTop: '2px' }}>
                        {rec.end_time.timezone_state === 'unknown' ? (
                          <span style={{ color: '#ff9800' }}>⚠️ Timezone Unknown</span>
                        ) : (
                          <span>UTC: {rec.end_time.normalized_utc}</span>
                        )}
                      </div>
                      <div style={{ color: '#555', fontSize: '11px', marginTop: '2px' }}>Raw: {rec.end_time.raw_value}</div>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ fontFamily: 'monospace', marginBottom: '4px' }}>0x{rec.offset_start.toString(16)}</div>
                      <button 
                        onClick={() => onNavigateToHex(rec.offset_start)}
                        style={{ background: '#2196f3', color: 'white', border: 'none', padding: '4px 8px', borderRadius: '4px', cursor: 'pointer', fontSize: '11px' }}>
                        Inspect Hex
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="data-panel" style={{ backgroundColor: '#1e1e1e', borderRadius: '8px', border: '1px solid #333', overflow: 'hidden' }}>
            <div className="panel-header" style={{ padding: '16px', borderBottom: '1px solid #333' }}>
              <h3 style={{ margin: 0, fontSize: '16px' }}>Deleted Candidates & Fragments</h3>
            </div>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
              <thead>
                <tr style={{ backgroundColor: '#252525', textAlign: 'left' }}>
                  <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Offset</th>
                  <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Reason</th>
                  <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Validation</th>
                  <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {mockDeleted.map(del => (
                  <tr key={del.id} style={{ borderBottom: '1px solid #333' }}>
                    <td style={{ padding: '12px 16px', fontFamily: 'monospace' }}>0x{del.offset_start.toString(16)}</td>
                    <td style={{ padding: '12px 16px' }}>{del.reason}</td>
                    <td style={{ padding: '12px 16px' }}>
                       <span style={{ 
                        padding: '2px 6px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold',
                        backgroundColor: del.validation.state === 'REVIEW' ? '#ff980033' : '#9c27b033',
                        color: del.validation.state === 'REVIEW' ? '#ffb74d' : '#ce93d8'
                      }}>
                        {del.validation.state}
                      </span>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <button 
                        onClick={() => onNavigateToHex(del.offset_start)}
                        style={{ background: '#333', color: 'white', border: '1px solid #444', padding: '4px 8px', borderRadius: '4px', cursor: 'pointer', fontSize: '11px' }}>
                        Inspect Hex
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

        </div>

        {/* Sidebar Panel */}
        <div style={{ width: '320px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div className="data-panel" style={{ backgroundColor: '#1e1e1e', borderRadius: '8px', border: '1px solid #333', overflow: 'hidden' }}>
             <div className="panel-header" style={{ padding: '16px', borderBottom: '1px solid #333' }}>
                <h3 style={{ margin: 0, fontSize: '16px' }}>Parser Status</h3>
             </div>
             <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {mockParserRuns.map(run => (
                  <div key={run.id} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '13px', fontWeight: 'bold' }}>{run.operation_name}</span>
                      <span style={{ 
                        padding: '2px 6px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold',
                        backgroundColor: run.validation.state === 'PASS' ? '#4caf5033' : run.validation.state === 'REVIEW' ? '#ff980033' : '#f4433633',
                        color: run.validation.state === 'PASS' ? '#81c784' : run.validation.state === 'REVIEW' ? '#ffb74d' : '#e57373'
                      }}>
                        {run.validation.state}
                      </span>
                    </div>
                    <div style={{ fontSize: '12px', color: '#888' }}>{run.validation.reason}</div>
                  </div>
                ))}
             </div>
          </div>
        </div>

      </div>
    </div>
  );
};
