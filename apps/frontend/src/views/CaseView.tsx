import React, { useState } from 'react';
import { FolderPlus, FolderCheck, AlertCircle, CheckCircle2 } from 'lucide-react';
import { createCase } from '../services/api';
import { Case } from '../types';

interface CaseViewProps {
  activeCase: Case | null;
  onCaseCreated: (c: Case) => void;
}

export const CaseView: React.FC<CaseViewProps> = ({ activeCase, onCaseCreated }) => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [examiner, setExaminer] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (!name.trim()) {
      setError("Field 'name' is required.");
      return;
    }
    if (!examiner.trim()) {
      setError("Field 'examiner' is required.");
      return;
    }

    setLoading(true);
    try {
      const created = await createCase({ name, description, examiner });
      onCaseCreated(created);
      setSuccess(`Case '${created.name}' created successfully.`);
      setName('');
      setDescription('');
    } catch (err: any) {
      setError(err.message || 'Failed to create case');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h1 className="view-title">Forensic Case Management</h1>
          <p className="view-subtitle">Register new investigative cases, assign examiners, and manage forensic scopes (Req 7.1–7.6)</p>
        </div>
      </div>

      <div className="grid-2">
        {/* Case Creation Form */}
        <div className="panel">
          <div className="panel-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <FolderPlus size={15} color="var(--accent-primary)" />
              <span>Create New Case</span>
            </div>
          </div>

          {error && (
            <div style={{ color: '#991b1b', background: '#fee2e2', padding: '10px', borderRadius: '4px', marginBottom: '14px', display: 'flex', gap: '6px', alignItems: 'center' }}>
              <AlertCircle size={14} />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div style={{ color: '#166534', background: '#dcfce7', padding: '10px', borderRadius: '4px', marginBottom: '14px', display: 'flex', gap: '6px', alignItems: 'center' }}>
              <CheckCircle2 size={14} />
              <span>{success}</span>
            </div>
          )}

          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label">Case Name / Identifier *</label>
              <input
                type="text"
                className="form-input"
                placeholder="e.g. CR-2026-8942 Burglary CCTV"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Responsible Examiner ID / Name *</label>
              <input
                type="text"
                className="form-input"
                placeholder="e.g. Det. Sarah Jenkins (Badge #4012)"
                value={examiner}
                onChange={(e) => setExaminer(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Case Description & Notes</label>
              <textarea
                className="form-textarea"
                placeholder="Incident details, seizure location, DVR make/model notes..."
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>

            <button type="submit" className="btn btn-primary" disabled={loading}>
              <FolderPlus size={14} />
              <span>{loading ? 'Registering...' : 'Create Case'}</span>
            </button>
          </form>
        </div>

        {/* Current Active Case Card */}
        <div className="panel">
          <div className="panel-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <FolderCheck size={15} color="var(--accent-primary)" />
              <span>Active Case Context</span>
            </div>
            {activeCase && <span className="badge badge-pass">Loaded</span>}
          </div>

          {activeCase ? (
            <table className="data-table">
              <tbody>
                <tr>
                  <td style={{ width: '130px', fontWeight: 600, color: 'var(--text-secondary)' }}>Case Name</td>
                  <td><strong>{activeCase.name}</strong></td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Case ID</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{activeCase.id}</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Examiner</td>
                  <td>{activeCase.examiner}</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Created At</td>
                  <td>{new Date(activeCase.created_at).toLocaleString()}</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Description</td>
                  <td>{activeCase.description || 'No description provided.'}</td>
                </tr>
              </tbody>
            </table>
          ) : (
            <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '24px 0' }}>
              No active case loaded. Create a case using the form on the left.
            </p>
          )}
        </div>
      </div>
    </div>
  );
};
