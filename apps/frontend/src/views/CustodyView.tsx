import React, { useEffect, useState } from 'react';
import { ScrollText, ShieldCheck, AlertCircle, RefreshCw } from 'lucide-react';
import { getCustodyLog } from '../services/api';
import { CustodyEvent } from '../types';

interface CustodyViewProps {
  caseId: string | null;
}

export const CustodyView: React.FC<CustodyViewProps> = ({ caseId }) => {
  const [events, setEvents] = useState<CustodyEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchLog = async () => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await getCustodyLog(caseId);
      setEvents(data);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch chain of custody log');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLog();
  }, [caseId]);

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h1 className="view-title">Append-Only Chain of Custody Audit Log</h1>
          <p className="view-subtitle">Immutable chronological audit trail of all forensic operations, ingest actions, and write-denials (Req 5.3, 5.5)</p>
        </div>
        {caseId && (
          <button className="btn btn-secondary" onClick={fetchLog} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'spin' : ''} />
            <span>Refresh Log</span>
          </button>
        )}
      </div>

      {!caseId ? (
        <div className="panel" style={{ textAlign: 'center', padding: '32px' }}>
          <AlertCircle size={28} color="#64748b" style={{ margin: '0 auto 10px', display: 'block' }} />
          <h3 style={{ marginBottom: '6px' }}>No Active Case Selected</h3>
          <p style={{ color: 'var(--text-muted)' }}>Select or create a case to view its forensic chain of custody.</p>
        </div>
      ) : (
        <div className="panel">
          <div className="panel-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <ScrollText size={15} color="var(--accent-primary)" />
              <span>Custody Event Log ({events.length} events recorded)</span>
            </div>
            <span className="badge badge-pass"><ShieldCheck size={12} /> Append-Only Guaranteed</span>
          </div>

          {error && (
            <div style={{ color: '#991b1b', background: '#fee2e2', padding: '10px', borderRadius: '4px', marginBottom: '14px' }}>
              {error}
            </div>
          )}

          {events.length === 0 ? (
            <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '24px 0' }}>
              No custody events recorded for this case yet.
            </p>
          ) : (
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp (UTC)</th>
                    <th>Action</th>
                    <th>Examiner</th>
                    <th>Result / Details</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((ev, idx) => (
                    <tr key={idx}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', whiteSpace: 'nowrap' }}>
                        {new Date(ev.timestamp).toLocaleString()}
                      </td>
                      <td>
                        <span className={ev.action === 'write_denied' ? 'badge badge-fail' : 'badge badge-pass'}>
                          {ev.action}
                        </span>
                      </td>
                      <td style={{ fontWeight: 600 }}>{ev.examiner}</td>
                      <td>{ev.result}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
