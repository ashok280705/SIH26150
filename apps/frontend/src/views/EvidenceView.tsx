import React, { useState, useEffect } from 'react';
import { HardDriveDownload, AlertCircle, CheckCircle2, FileWarning, List, Clock, Globe, X } from 'lucide-react';
import { registerEvidence, listCaseEvidence, setEvidenceTimezone, clearEvidenceTimezone } from '../services/api';
import { Case, Evidence, Acquisition } from '../types';
import { ContextHelp } from '../components/onboarding/ContextHelp';
import { loadStorage, saveStorage, removeStorage } from '../utils/storage';

interface EvidenceViewProps {
  activeCase: Case | null;
  onEvidenceRegistered: (data: { evidence: Evidence; acquisition?: Acquisition; ingest_hash: string }) => void;
  onEvidenceSelected: (evidence: Evidence) => void;
  activeEvidence: Evidence | null;
}

export const EvidenceView: React.FC<EvidenceViewProps> = ({ activeCase, activeEvidence, onEvidenceRegistered, onEvidenceSelected }) => {
  const [sourceDevice, setSourceDevice] = useState(() => loadStorage('forensic_draft_ev_device', ''));
  const [capacityValue, setCapacityValue] = useState<string>(() => loadStorage('forensic_draft_ev_cap_val', '1'));
  const [capacityUnit, setCapacityUnit] = useState<'B' | 'MB' | 'GB' | 'TB'>(() => loadStorage('forensic_draft_ev_cap_unit', 'GB'));
  const [imageFormat, setImageFormat] = useState(() => loadStorage('forensic_draft_ev_format', 'raw'));
  const [examiner, setExaminer] = useState(() => loadStorage('forensic_draft_ev_examiner', ''));
  const [acquisitionTool, setAcquisitionTool] = useState(() => loadStorage('forensic_draft_ev_tool', 'dd'));

  const [acquisitionToolVer, setAcquisitionToolVer] = useState(() => loadStorage('forensic_draft_ev_tool_ver', '8.32'));
  const [path, setPath] = useState(() => loadStorage('forensic_draft_ev_path', ''));
  const [sourceState, setSourceState] = useState<'read_only' | 'read_write' | 'unknown'>(() => loadStorage('forensic_draft_ev_state', 'read_only'));
  const [acquisitionStatus, setAcquisitionStatus] = useState<'complete' | 'partial' | 'unknown'>(() => loadStorage('forensic_draft_ev_status', 'complete'));

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Examiner-established timezone fields (never prefilled from browser/OS)
  const [examinerTz, setExaminerTz] = useState('');
  const [examinerTzSource, setExaminerTzSource] = useState('');
  const [examinerTzNotes, setExaminerTzNotes] = useState('');

  // Editing timezone modal
  const [editingEvidence, setEditingEvidence] = useState<Evidence | null>(null);
  const [modalTz, setModalTz] = useState('');
  const [modalSource, setModalSource] = useState('');
  const [modalNotes, setModalNotes] = useState('');
  const [modalLoading, setModalLoading] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);

  const [evidenceList, setEvidenceList] = useState<Evidence[]>([]);

  useEffect(() => {
    saveStorage('forensic_draft_ev_device', sourceDevice);
  }, [sourceDevice]);

  useEffect(() => {
    saveStorage('forensic_draft_ev_cap_val', capacityValue);
  }, [capacityValue]);

  useEffect(() => {
    saveStorage('forensic_draft_ev_cap_unit', capacityUnit);
  }, [capacityUnit]);

  useEffect(() => {
    saveStorage('forensic_draft_ev_format', imageFormat);
  }, [imageFormat]);

  useEffect(() => {
    saveStorage('forensic_draft_ev_examiner', examiner);
  }, [examiner]);

  useEffect(() => {
    saveStorage('forensic_draft_ev_tool', acquisitionTool);
  }, [acquisitionTool]);

  useEffect(() => {
    saveStorage('forensic_draft_ev_tool_ver', acquisitionToolVer);
  }, [acquisitionToolVer]);

  useEffect(() => {
    saveStorage('forensic_draft_ev_path', path);
  }, [path]);

  useEffect(() => {
    saveStorage('forensic_draft_ev_state', sourceState);
  }, [sourceState]);

  useEffect(() => {
    saveStorage('forensic_draft_ev_status', acquisitionStatus);
  }, [acquisitionStatus]);

  useEffect(() => {
    if (activeCase) {
      if (!examiner) {
        setExaminer(activeCase.examiner);
      }
      fetchEvidence();
    } else {
      setEvidenceList([]);
    }
  }, [activeCase]);

  const fetchEvidence = async () => {
    if (!activeCase) return;
    try {
      const data = await listCaseEvidence(activeCase.id);
      setEvidenceList(data);
    } catch (err) {
      console.error('Failed to load case evidence:', err);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeCase) {
      setError('Please create or select an active case first.');
      return;
    }

    setError(null);
    setSuccess(null);
    setLoading(true);

    const multipliers: Record<string, number> = {
      B: 1,
      MB: 1024 * 1024,
      GB: 1024 * 1024 * 1024,
      TB: 1024 * 1024 * 1024 * 1024,
    };
    const computedBytes = Math.floor((parseFloat(capacityValue) || 1) * (multipliers[capacityUnit] || 1));

    try {
      const payload = {
        source_device: sourceDevice,
        acquisition_time: new Date().toISOString(),
        capacity: computedBytes,
        image_format: imageFormat,
        responsible_examiner: examiner || activeCase.examiner,
        acquisition_tool: acquisitionTool || null,
        acquisition_tool_version: acquisitionToolVer || null,
        path,
        acquisition_status: acquisitionStatus,
        bad_sector_ranges: [],
        unresolved_ranges: [],
        source_state: sourceState,
        examiner_timezone: examinerTz.trim()
          ? {
              timezone: examinerTz.trim(),
              source: examinerTzSource.trim() || 'Documented during evidence ingest',
              established_by: examiner || activeCase.examiner,
              notes: examinerTzNotes.trim() || null,
              established_at: new Date().toISOString(),
            }
          : null,
      };

      const result = await registerEvidence(activeCase.id, payload);
      setEvidenceList(prev => [...prev, result.evidence]);
      onEvidenceRegistered(result);
      setSuccess(`Evidence '${result.evidence.source_device}' registered successfully.`);
      
      // Reset form
      setSourceDevice('');
      setPath('');
      setExaminerTz('');
      setExaminerTzSource('');
      setExaminerTzNotes('');
      removeStorage('forensic_draft_ev_device');
      removeStorage('forensic_draft_ev_path');
    } catch (err: any) {
      setError(err.message || 'Failed to register evidence');
    } finally {
      setLoading(false);
    }
  };

  const openTimezoneModal = (e: Evidence) => {
    setEditingEvidence(e);
    setModalTz(e.examiner_timezone?.timezone || '');
    setModalSource(e.examiner_timezone?.source || '');
    setModalNotes(e.examiner_timezone?.notes || '');
    setModalError(null);
  };

  const handleSaveModalTz = async () => {
    if (!editingEvidence) return;
    if (!modalTz.trim()) {
      setModalError('Please specify a timezone or UTC offset (e.g. Asia/Kolkata, UTC+05:30)');
      return;
    }
    if (!modalSource.trim()) {
      setModalError('Please document the evidentiary source/basis (e.g. DVR Setup Menu Photo)');
      return;
    }
    setModalLoading(true);
    setModalError(null);
    try {
      const res = await setEvidenceTimezone(editingEvidence.id, {
        timezone: modalTz.trim(),
        source: modalSource.trim(),
        notes: modalNotes.trim() || undefined,
        examiner: activeCase?.examiner,
      });
      const updatedList = evidenceList.map((e) =>
        e.id === editingEvidence.id ? { ...e, examiner_timezone: res } : e
      );
      setEvidenceList(updatedList);
      if (activeEvidence?.id === editingEvidence.id) {
        onEvidenceSelected({ ...editingEvidence, examiner_timezone: res });
      }
      setSuccess(`Examiner timezone for '${editingEvidence.source_device}' established as ${res.timezone}.`);
      setEditingEvidence(null);
    } catch (err: any) {
      setModalError(err.message || 'Failed to save timezone');
    } finally {
      setModalLoading(false);
    }
  };

  const handleClearModalTz = async () => {
    if (!editingEvidence) return;
    setModalLoading(true);
    setModalError(null);
    try {
      await clearEvidenceTimezone(editingEvidence.id);
      const updatedList = evidenceList.map((e) =>
        e.id === editingEvidence.id ? { ...e, examiner_timezone: null } : e
      );
      setEvidenceList(updatedList);
      if (activeEvidence?.id === editingEvidence.id) {
        onEvidenceSelected({ ...editingEvidence, examiner_timezone: null });
      }
      setSuccess(`Examiner timezone removed for '${editingEvidence.source_device}'. Reverted to filesystem facts.`);
      setEditingEvidence(null);
    } catch (err: any) {
      setModalError(err.message || 'Failed to remove timezone');
    } finally {
      setModalLoading(false);
    }
  };

  if (!activeCase) {
    return (
      <div className="view-container" data-tour="evidence-view-panel">
        <div className="view-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h1 className="view-title">Evidence Ingest & Registration</h1>
              <ContextHelp
                title="Evidence Source"
                content="Evidence represents the DVR/NVR storage media being examined. Multiple evidence sources can be registered under a single case."
              />
            </div>
            <p className="view-subtitle">Register raw forensic images and perform source-safety inspection</p>
          </div>
        </div>
        <div className="panel" style={{ textAlign: 'center', padding: '32px' }}>
          <FileWarning size={28} color="#d97706" style={{ margin: '0 auto 10px', display: 'block' }} />
          <h3 style={{ marginBottom: '6px' }}>No Active Case Selected</h3>
          <p style={{ color: 'var(--text-muted)' }}>Evidence must be registered under an existing case scope. Please create or load a case first.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="view-container" data-tour="evidence-view-panel">
      <div className="view-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h1 className="view-title">Evidence Ingest & Registration</h1>
            <ContextHelp
              title="Evidence Source"
              content="Evidence represents the DVR/NVR storage media being examined. Multiple evidence sources (.raw, .dd, .img) can be registered under a single case."
            />
          </div>
          <p className="view-subtitle">Register raw forensic images, compute initial cryptographic hash, and perform source-safety inspection (Req 1.8–1.12, 7.1–7.9)</p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(460px, 520px) 1fr', gap: '24px', alignItems: 'start' }}>
        {/* Left Form Panel */}
        <div className="panel">
          <div className="panel-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <HardDriveDownload size={15} color="var(--accent-primary)" />
              <span>Register Evidence Image for: <strong>{activeCase.name}</strong></span>
            </div>
          </div>

          {error && (
            <div style={{ color: '#991b1b', background: '#fee2e2', padding: '10px 14px', borderRadius: '6px', marginBottom: '16px', display: 'flex', gap: '8px', alignItems: 'center', fontSize: '12.5px' }}>
              <AlertCircle size={15} style={{ flexShrink: 0 }} />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div style={{ color: '#166534', background: '#dcfce7', padding: '10px 14px', borderRadius: '6px', marginBottom: '16px', display: 'flex', gap: '8px', alignItems: 'center', fontSize: '12.5px' }}>
              <CheckCircle2 size={15} style={{ flexShrink: 0 }} />
              <span>{success}</span>
            </div>
          )}

          <form onSubmit={handleRegister} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div className="form-group" style={{ margin: 0 }}>
              <label className="form-label">Source Device / Model Name *</label>
              <input
                type="text"
                className="form-input"
                placeholder="e.g. Western Digital 2TB WD20PURX (Evidence Tag #1042)"
                value={sourceDevice}
                onChange={(e) => setSourceDevice(e.target.value)}
                required
              />
            </div>

            <div className="form-group" style={{ margin: 0 }}>
              <label className="form-label">Evidence File Path (Local Server Path) *</label>
              <input
                type="text"
                className="form-input"
                placeholder="e.g. /Users/anuj/Downloads/sih2026/evidence_samples/dahua_dhfs_sample.raw"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                required
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
              <div className="form-group" style={{ margin: 0 }}>
                <label className="form-label">Storage Capacity</label>
                <div style={{ display: 'flex', gap: '6px' }}>
                  <input
                    type="number"
                    step="any"
                    min="0.001"
                    className="form-input"
                    style={{ flex: 1 }}
                    placeholder="e.g. 1"
                    value={capacityValue}
                    onChange={(e) => setCapacityValue(e.target.value)}
                    required
                  />
                  <select
                    className="form-select"
                    style={{ width: '80px', flexShrink: 0 }}
                    value={capacityUnit}
                    onChange={(e) => setCapacityUnit(e.target.value as any)}
                  >
                    <option value="TB">TB</option>
                    <option value="GB">GB</option>
                    <option value="MB">MB</option>
                    <option value="B">Bytes</option>
                  </select>
                </div>
              </div>

              <div className="form-group" style={{ margin: 0 }}>
                <label className="form-label">Image Format</label>
                <select className="form-select" value={imageFormat} onChange={(e) => setImageFormat(e.target.value)}>
                  <option value="raw">Raw Binary (.raw)</option>
                  <option value="dd">dd Image (.dd)</option>
                  <option value="img">Disk Image (.img)</option>
                  <option value="physical_disk">Physical Block Device</option>
                </select>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
              <div className="form-group" style={{ margin: 0 }}>
                <label className="form-label">Source Safety (Req 1.8)</label>
                <select className="form-select" value={sourceState} onChange={(e) => setSourceState(e.target.value as any)}>
                  <option value="read_only">Read-Only (Write Blocker)</option>
                  <option value="unknown">Unknown / Unverified</option>
                  <option value="read_write">Read-Write (Rejected)</option>
                </select>
              </div>

              <div className="form-group" style={{ margin: 0 }}>
                <label className="form-label">Acquisition Status (Req 7.8)</label>
                <select className="form-select" value={acquisitionStatus} onChange={(e) => setAcquisitionStatus(e.target.value as any)}>
                  <option value="complete">Complete (Clean)</option>
                  <option value="partial">Partial (Bad Blocks)</option>
                  <option value="unknown">Unknown</option>
                </select>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
              <div className="form-group" style={{ margin: 0 }}>
                <label className="form-label">Acquisition Tool</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. dd, FTK Imager"
                  value={acquisitionTool}
                  onChange={(e) => setAcquisitionTool(e.target.value)}
                />
              </div>

              <div className="form-group" style={{ margin: 0 }}>
                <label className="form-label">Tool Version</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. 8.32"
                  value={acquisitionToolVer}
                  onChange={(e) => setAcquisitionToolVer(e.target.value)}
                />
              </div>
            </div>

            {/* Examiner-Established Timezone (External Evidence) */}
            <div style={{ border: '1px solid var(--border)', borderRadius: '6px', padding: '12px', background: 'var(--surface-muted)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Clock size={14} style={{ color: 'var(--accent)' }} />
                  <span style={{ fontSize: '12.5px', fontWeight: 600 }}>Examiner-Established Timezone (Optional)</span>
                </div>
                <ContextHelp
                  title="Examiner-Established Timezone"
                  content="Forensic Principle: Timezone is NEVER detected from disk for OEM recorder formats like Dahua and must NEVER be assumed to be UTC or inferred from the browser/OS. Specify only if you have documented external evidence (e.g. DVR on-screen setup menu photo, site dispatch log, or camera configuration sheet)."
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                <div className="form-group" style={{ margin: 0 }}>
                  <label className="form-label" style={{ fontSize: '11px' }}>Timezone / Offset</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="e.g. Asia/Kolkata, UTC+05:30, -05:00"
                    value={examinerTz}
                    onChange={(e) => setExaminerTz(e.target.value)}
                  />
                </div>

                <div className="form-group" style={{ margin: 0 }}>
                  <label className="form-label" style={{ fontSize: '11px' }}>Documented Source / Basis</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="e.g. DVR Setup Menu Photo (Item #1042)"
                    value={examinerTzSource}
                    onChange={(e) => setExaminerTzSource(e.target.value)}
                  />
                </div>
              </div>

              <div className="form-group" style={{ margin: '8px 0 0 0' }}>
                <label className="form-label" style={{ fontSize: '11px' }}>Investigative Notes / Justification</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. Verified DVR system configuration page showed Indian Standard Time"
                  value={examinerTzNotes}
                  onChange={(e) => setExaminerTzNotes(e.target.value)}
                />
              </div>
            </div>

            <div style={{ marginTop: '8px' }}>
              <button type="submit" className="btn btn-primary" style={{ width: '100%', padding: '10px' }} disabled={loading}>
                <HardDriveDownload size={15} />
                <span>{loading ? 'Streaming SHA-256 Hash & Ingesting...' : 'Register Forensic Evidence'}</span>
              </button>
            </div>
          </form>
        </div>

        {/* Right Registered Evidence Panel */}
        <div className="panel">
          <div className="panel-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <List size={15} color="var(--text-secondary)" />
              <span>Registered Evidence ({evidenceList.length})</span>
            </div>
          </div>
          
          {evidenceList.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '36px 16px', color: 'var(--text-muted)' }}>
              <p>No evidence registered under case <strong>{activeCase.name}</strong> yet.</p>
              <p style={{ fontSize: '12px', marginTop: '4px' }}>Use the form on the left to register a raw forensic disk image.</p>
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Device / Path</th>
                  <th>Format</th>
                  <th>Capacity</th>
                  <th>Status</th>
                  <th>Timezone</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {evidenceList.map((e) => {
                  const isLoaded = activeEvidence?.id === e.id;
                  const hasExaminerTz = Boolean(e.examiner_timezone);
                  return (
                    <tr key={e.id} style={{ backgroundColor: isLoaded ? 'var(--accent-light)' : undefined }}>
                      <td>
                        <div style={{ fontWeight: 600 }}>{e.source_device}</div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '2px', wordBreak: 'break-all' }}>
                          {e.path}
                        </div>
                      </td>
                      <td><span className="badge badge-info">{e.image_format}</span></td>
                      <td style={{ fontSize: '0.8rem', whiteSpace: 'nowrap' }}>
                        {(e.capacity / (1024 * 1024)).toFixed(2)} MB
                      </td>
                      <td>
                        <span className={`badge ${e.source_state === 'read_only' ? 'badge-pass' : 'badge-warning'}`}>
                          {e.source_state.replace('_', '-')}
                        </span>
                      </td>
                      <td>
                        {hasExaminerTz ? (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                            <span className="badge badge-info" title={`Basis: ${e.examiner_timezone?.source} | Established by: ${e.examiner_timezone?.established_by}`}>
                              {e.examiner_timezone?.timezone} (Examiner)
                            </span>
                            <span style={{ fontSize: '10px', color: 'var(--text-muted)', maxWidth: '140px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={e.examiner_timezone?.source}>
                              {e.examiner_timezone?.source}
                            </span>
                          </div>
                        ) : (
                          <span className="badge badge-secondary" title="Filesystem timezone is Unknown; local wall-clock retained without assuming UTC">
                            Filesystem (Unknown)
                          </span>
                        )}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '6px' }}>
                          <button 
                            className={`btn ${isLoaded ? 'btn-primary' : 'btn-secondary'}`}
                            style={{ padding: '4px 10px', fontSize: '0.8rem', whiteSpace: 'nowrap' }}
                            onClick={() => onEvidenceSelected(e)}
                            disabled={isLoaded}
                          >
                            {isLoaded ? 'Active' : 'Load'}
                          </button>
                          <button
                            className="btn btn-secondary"
                            style={{ padding: '4px 8px', fontSize: '0.8rem', whiteSpace: 'nowrap' }}
                            onClick={() => openTimezoneModal(e)}
                            title="Establish, edit, or remove examiner timezone"
                          >
                            <Clock size={12} />
                            <span>TZ</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Examiner Timezone Modal */}
      {editingEvidence && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '16px' }}>
          <div className="panel" style={{ width: '100%', maxWidth: '520px', margin: 0, padding: 0, overflow: 'hidden' }}>
            <div className="panel-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Globe size={16} style={{ color: 'var(--accent)' }} />
                <h3 style={{ margin: 0, fontSize: '15px' }}>Examiner Timezone Assertion</h3>
              </div>
              <button className="btn btn-secondary btn-sm" onClick={() => setEditingEvidence(null)} style={{ padding: '4px' }}>
                <X size={16} />
              </button>
            </div>

            <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div style={{ background: 'var(--surface-muted)', padding: '10px 12px', borderRadius: '6px', fontSize: '12px' }}>
                <div><strong>Target Evidence:</strong> {editingEvidence.source_device}</div>
                <div style={{ marginTop: '4px', color: 'var(--text-muted)' }}>
                  Filesystem Timezone: <strong>Unknown (from disk bytes)</strong>
                </div>
                {editingEvidence.examiner_timezone && (
                  <div style={{ marginTop: '4px', color: 'var(--accent)' }}>
                    Current Assertion: <strong>{editingEvidence.examiner_timezone.timezone}</strong> (Source: {editingEvidence.examiner_timezone.source})
                  </div>
                )}
              </div>

              {modalError && (
                <div style={{ color: '#991b1b', background: '#fee2e2', padding: '8px 12px', borderRadius: '6px', fontSize: '12px', display: 'flex', gap: '6px', alignItems: 'center' }}>
                  <AlertCircle size={14} style={{ flexShrink: 0 }} />
                  <span>{modalError}</span>
                </div>
              )}

              <div className="form-group" style={{ margin: 0 }}>
                <label className="form-label">Timezone or UTC Offset *</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. Asia/Kolkata, UTC+05:30, +05:30, -05:00"
                  value={modalTz}
                  onChange={(e) => setModalTz(e.target.value)}
                />
                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  Accepts IANA names (e.g. Asia/Kolkata, America/New_York) or numerical offsets (+05:30, -05:00).
                </span>
              </div>

              <div className="form-group" style={{ margin: 0 }}>
                <label className="form-label">Evidentiary Documentation Basis *</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. DVR Setup Menu Photo (Item #1042), Station Log Sheet"
                  value={modalSource}
                  onChange={(e) => setModalSource(e.target.value)}
                />
                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  Forensic audit requires documenting the external basis for this assertion.
                </span>
              </div>

              <div className="form-group" style={{ margin: 0 }}>
                <label className="form-label">Notes & Justification</label>
                <textarea
                  className="form-input"
                  rows={2}
                  placeholder="e.g. Confirmed camera clock matched local IST dispatch broadcast"
                  value={modalNotes}
                  onChange={(e) => setModalNotes(e.target.value)}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '8px' }}>
                {editingEvidence.examiner_timezone ? (
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={handleClearModalTz}
                    disabled={modalLoading}
                    style={{ color: 'var(--danger)' }}
                    title="Remove examiner assertion and revert to filesystem facts"
                  >
                    Clear Assertion
                  </button>
                ) : <div />}

                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => setEditingEvidence(null)}
                    disabled={modalLoading}
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={handleSaveModalTz}
                    disabled={modalLoading}
                  >
                    {modalLoading ? 'Saving...' : 'Establish Timezone'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
