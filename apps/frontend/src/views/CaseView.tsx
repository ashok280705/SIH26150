import React, { useState, useEffect } from 'react';
import { FolderPlus, FolderCheck, AlertCircle, CheckCircle2, List } from 'lucide-react';
import { createCase, listCases } from '../services/api';
import { Case } from '../types';

import { loadStorage, saveStorage, removeStorage } from '../utils/storage';

interface CaseViewProps {
  activeCase: Case | null;
  onCaseSelected?: (c: Case) => void;
  onCaseCreated?: (c: Case) => void;
  onCaseUnloaded?: () => void;
}

export const CaseView: React.FC<CaseViewProps> = ({ activeCase, onCaseSelected, onCaseCreated, onCaseUnloaded }) => {
  const [name, setName] = useState(() => loadStorage('forensic_draft_case_name', ''));
  const [description, setDescription] = useState(() => loadStorage('forensic_draft_case_desc', ''));
  const [examiner, setExaminer] = useState(() => loadStorage('forensic_draft_case_examiner', ''));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [cases, setCases] = useState<Case[]>([]);

  useEffect(() => {
    saveStorage('forensic_draft_case_name', name);
  }, [name]);

  useEffect(() => {
    saveStorage('forensic_draft_case_desc', description);
  }, [description]);

  useEffect(() => {
    saveStorage('forensic_draft_case_examiner', examiner);
  }, [examiner]);

  useEffect(() => {
    fetchCases();
  }, []);

  const fetchCases = async () => {
    try {
      const data = await listCases();
      setCases(data);
    } catch (err) {
      console.error('Failed to load cases:', err);
    }
  };

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
      setCases(prev => [created, ...prev]);
      const selectCallback = onCaseSelected || onCaseCreated;
      if (selectCallback) {
        selectCallback(created);
      }
      setSuccess(`Case '${created.name}' created successfully.`);
      setName('');
      setDescription('');
      removeStorage('forensic_draft_case_name');
      removeStorage('forensic_draft_case_desc');
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
          <p className="view-subtitle">Register new investigative cases, assign examiners, and manage forensic scopes</p>
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

        {/* Current Active Case Card & Case List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div className="panel">
            <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <FolderCheck size={15} color="var(--accent-primary)" />
                <span>Active Case Context</span>
                {activeCase && <span className="badge badge-pass" style={{ marginLeft: '6px' }}>Loaded</span>}
              </div>
              {activeCase && onCaseUnloaded && (
                <button
                  onClick={onCaseUnloaded}
                  className="btn btn-secondary"
                  style={{ padding: '2px 8px', fontSize: '0.8rem' }}
                >
                  Unload Case
                </button>
              )}
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
                No active case loaded. Create a case or select one below.
              </p>
            )}
          </div>

          <div className="panel">
            <div className="panel-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <List size={15} color="var(--text-secondary)" />
                <span>Existing Cases</span>
              </div>
            </div>
            
            {cases.length === 0 ? (
              <p style={{ color: 'var(--text-muted)', padding: '16px', textAlign: 'center' }}>
                No cases found in database.
              </p>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Created</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {cases.map((c) => (
                    <tr key={c.id}>
                      <td><strong>{c.name}</strong></td>
                      <td>{new Date(c.created_at).toLocaleDateString()}</td>
                      <td>
                        <button 
                          className="btn btn-secondary" 
                          style={{ padding: '4px 8px', fontSize: '0.8rem' }}
                          onClick={() => {
                            const selectCallback = onCaseSelected || onCaseCreated;
                            if (selectCallback) selectCallback(c);
                          }}
                          disabled={activeCase?.id === c.id}
                        >
                          {activeCase?.id === c.id ? 'Active' : 'Load'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
