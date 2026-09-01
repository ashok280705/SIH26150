import React from 'react';
import { FileCheck2, AlertTriangle, CheckCircle2, XCircle, HelpCircle } from 'lucide-react';
import { Acquisition } from '../types';

interface AcquisitionViewProps {
  acquisition: Acquisition | null;
}

export const AcquisitionView: React.FC<AcquisitionViewProps> = ({ acquisition }) => {
  const renderStatusBadge = (status?: string) => {
    switch (status?.toLowerCase()) {
      case 'complete':
        return <span className="badge badge-pass"><CheckCircle2 size={12} /> Complete</span>;
      case 'partial':
        return <span className="badge badge-review"><AlertTriangle size={12} /> Partial</span>;
      case 'failed':
        return <span className="badge badge-fail"><XCircle size={12} /> Failed</span>;
      default:
        return <span className="badge badge-unknown"><HelpCircle size={12} /> Unknown</span>;
    }
  };

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h1 className="view-title">Acquisition Verification & Gaps Audit</h1>
          <p className="view-subtitle">Detailed imaging completeness, bad sector accounting, and verification validation state (Req 7.7–7.9, 23.1–23.4)</p>
        </div>
      </div>

      {!acquisition ? (
        <div className="panel" style={{ textAlign: 'center', padding: '32px' }}>
          <HelpCircle size={28} color="#64748b" style={{ margin: '0 auto 10px', display: 'block' }} />
          <h3 style={{ marginBottom: '6px' }}>No Acquisition Data Available</h3>
          <p style={{ color: 'var(--text-muted)' }}>Register evidence to generate or verify acquisition metadata.</p>
        </div>
      ) : (
        <div className="grid-2">
          {/* Acquisition Metadata */}
          <div className="panel">
            <div className="panel-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <FileCheck2 size={15} color="var(--accent-primary)" />
                <span>Acquisition Metadata</span>
              </div>
              {renderStatusBadge(acquisition.status)}
            </div>

            <table className="data-table">
              <tbody>
                <tr>
                  <td style={{ width: '150px', fontWeight: 600, color: 'var(--text-secondary)' }}>Acquisition Status</td>
                  <td>{renderStatusBadge(acquisition.status)}</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Acquisition Tool</td>
                  <td>{acquisition.tool ? `${acquisition.tool} (v${acquisition.tool_version || '?'})` : 'Unknown'}</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Map / Receipt Ref</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{acquisition.map_reference || 'None provided'}</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Recorded At</td>
                  <td>{new Date(acquisition.created_at).toLocaleString()}</td>
                </tr>
              </tbody>
            </table>
          </div>

          {/* Verification Validation State */}
          <div className="panel">
            <div className="panel-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span>Validation State (Req 22)</span>
              </div>
            </div>

            <table className="data-table">
              <tbody>
                <tr>
                  <td style={{ width: '130px', fontWeight: 600, color: 'var(--text-secondary)' }}>Outcome State</td>
                  <td><span className={`badge badge-${acquisition.verification.state.toLowerCase()}`}>{acquisition.verification.state}</span></td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Operation</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{acquisition.verification.operation}</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Mandatory Reason</td>
                  <td>{acquisition.verification.reason}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
