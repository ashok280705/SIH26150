import React, { useState } from 'react';
import { HardDriveDownload, AlertCircle, CheckCircle2, FileWarning } from 'lucide-react';
import { registerEvidence } from '../services/api';
import { Case, Evidence, Acquisition } from '../types';

interface EvidenceViewProps {
  activeCase: Case | null;
  onEvidenceRegistered: (data: { evidence: Evidence; acquisition?: Acquisition; ingest_hash: string }) => void;
}

export const EvidenceView: React.FC<EvidenceViewProps> = ({ activeCase, onEvidenceRegistered }) => {
  const [sourceDevice, setSourceDevice] = useState('');
  const [capacity, setCapacity] = useState<number>(1073741824); // 1 GB default
  const [imageFormat, setImageFormat] = useState('raw');
  const [examiner] = useState(activeCase?.examiner || 'Examiner');
  const [acquisitionTool, setAcquisitionTool] = useState('dd');

  const [acquisitionToolVer, setAcquisitionToolVer] = useState('8.32');
  const [path, setPath] = useState('');
  const [sourceState, setSourceState] = useState<'read_only' | 'read_write' | 'unknown'>('read_only');
  const [acquisitionStatus, setAcquisitionStatus] = useState<'complete' | 'partial' | 'unknown'>('complete');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeCase) {
      setError('Please create or select an active case first.');
      return;
    }

    setError(null);
    setSuccess(null);
    setLoading(true);

    try {
      const payload = {
        source_device: sourceDevice,
        acquisition_time: new Date().toISOString(),
        capacity: Number(capacity),
        image_format: imageFormat,
        responsible_examiner: examiner || activeCase.examiner,
        acquisition_tool: acquisitionTool || null,
        acquisition_tool_version: acquisitionToolVer || null,
        path,
        acquisition_status: acquisitionStatus,
        bad_sector_ranges: [],
        unresolved_ranges: [],
        source_state: sourceState,
      };

      const result = await registerEvidence(activeCase.id, payload);
      onEvidenceRegistered(result);
      setSuccess(`Evidence '${result.evidence.source_device}' registered successfully.`);
    } catch (err: any) {
      setError(err.message || 'Failed to register evidence');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h1 className="view-title">Evidence Ingest & Registration</h1>
          <p className="view-subtitle">Register raw forensic images, compute initial cryptographic hash, and perform source-safety inspection (Req 1.8–1.12, 7.1–7.9)</p>
        </div>
      </div>

      {!activeCase ? (
        <div className="panel" style={{ textAlign: 'center', padding: '32px' }}>
          <FileWarning size={28} color="#d97706" style={{ margin: '0 auto 10px', display: 'block' }} />
          <h3 style={{ marginBottom: '6px' }}>No Active Case Selected</h3>
          <p style={{ color: 'var(--text-muted)' }}>Evidence must be registered under an existing case scope. Please create or load a case first.</p>
        </div>
      ) : (
        <div className="panel">
          <div className="panel-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <HardDriveDownload size={15} color="var(--accent-primary)" />
              <span>Register Evidence Image for Case: <strong>{activeCase.name}</strong></span>
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

          <form onSubmit={handleRegister}>
            <div className="grid-2">
              <div className="form-group">
                <label className="form-label">Source Device / Model Name *</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. Dahua DH-XVR5108HS or Western Digital 2TB"
                  value={sourceDevice}
                  onChange={(e) => setSourceDevice(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Evidence File Path (Local Server Path) *</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. /evidence/dahua_disk.raw"
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Capacity (Bytes)</label>
                <input
                  type="number"
                  className="form-input"
                  value={capacity}
                  onChange={(e) => setCapacity(parseInt(e.target.value) || 0)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Image Format</label>
                <select className="form-select" value={imageFormat} onChange={(e) => setImageFormat(e.target.value)}>
                  <option value="raw">Raw Binary Image (.raw)</option>
                  <option value="dd">dd Raw Image (.dd)</option>
                  <option value="img">Disk Image (.img)</option>
                  <option value="physical_disk">Physical Block Device</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Source Safety Inspection State (Req 1.8)</label>
                <select className="form-select" value={sourceState} onChange={(e) => setSourceState(e.target.value as any)}>
                  <option value="read_only">Read-Only (Hardware Write-Blocker Attached)</option>
                  <option value="unknown">Unknown / Unverified (Defaults to Unknown)</option>
                  <option value="read_write">Read-Write (Will be rejected by safety audit)</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Acquisition Status (Honest Reporting — Req 7.8, 7.9)</label>
                <select className="form-select" value={acquisitionStatus} onChange={(e) => setAcquisitionStatus(e.target.value as any)}>
                  <option value="complete">Complete (No bad sectors or gaps)</option>
                  <option value="partial">Partial (Contains bad sectors / truncated)</option>
                  <option value="unknown">Unknown (Missing imaging receipt)</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Acquisition Tool</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. FTK Imager, dd, Atola Insight"
                  value={acquisitionTool}
                  onChange={(e) => setAcquisitionTool(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label className="form-label">Acquisition Tool Version</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. 4.7.1"
                  value={acquisitionToolVer}
                  onChange={(e) => setAcquisitionToolVer(e.target.value)}
                />
              </div>
            </div>

            <div style={{ marginTop: '10px' }}>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                <HardDriveDownload size={14} />
                <span>{loading ? 'Streaming SHA-256 Hash & Ingesting...' : 'Register Evidence'}</span>
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
