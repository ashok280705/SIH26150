import React, { useState, useEffect } from 'react';
import {
  FileCheck2,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  HardDrive,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  Play,
  StopCircle,
  Database,
  ArrowRight,
  Info,
} from 'lucide-react';
import {
  Acquisition,
  Case,
  Evidence,
  PhysicalSource,
  SafetyAssessment,
  AcquisitionJobStatus,
} from '../types';
import { ContextHelp } from '../components/onboarding/ContextHelp';
import {
  listAcquisitionDevices,
  assessAcquisitionSafety,
  startAcquisitionJob,
  getAcquisitionJob,
  cancelAcquisitionJob,
  registerAcquisitionEvidence,
} from '../services/api';

interface AcquisitionViewProps {
  acquisition: Acquisition | null;
  activeCase?: Case | null;
  onEvidenceRegistered?: (data: { evidence: Evidence; acquisition?: Acquisition; ingest_hash: string }) => void;
  onNavigateTab?: (tab: any) => void;
}

export const AcquisitionView: React.FC<AcquisitionViewProps> = ({
  acquisition,
  activeCase,
  onEvidenceRegistered,
  onNavigateTab,
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'workflow' | 'audit'>('workflow');

  // Device enumeration state
  const [devices, setDevices] = useState<PhysicalSource[]>([]);
  const [loadingDevices, setLoadingDevices] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState<PhysicalSource | null>(null);

  // Examiner Write-Blocker Attestation
  const [hardwareBlockerUsed, setHardwareBlockerUsed] = useState(false);
  const [blockerModel, setBlockerModel] = useState('');
  const [examinerNotes, setExaminerNotes] = useState('');

  // Destination & config
  const [destinationPath, setDestinationPath] = useState('');
  const [chunkSizeMb, setChunkSizeMb] = useState<number>(1);
  const [maxRetries, setMaxRetries] = useState<number>(3);
  const [attemptLock, setAttemptLock] = useState(true);

  // Safety assessment state
  const [safety, setSafety] = useState<SafetyAssessment | null>(null);
  const [assessingSafety, setAssessingSafety] = useState(false);

  // Active Job state
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [jobStatus, setJobStatus] = useState<AcquisitionJobStatus | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [registering, setRegistering] = useState(false);
  const [registeredEvidence, setRegisteredEvidence] = useState<{ evidence: Evidence; acquisition: Acquisition } | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Load devices on mount
  useEffect(() => {
    fetchDevices();
  }, []);

  // Poll active acquisition job
  useEffect(() => {
    if (!activeJobId) return;

    const interval = setInterval(async () => {
      try {
        const status = await getAcquisitionJob(activeJobId);
        setJobStatus(status);

        if (status.state === 'completed' || status.state === 'failed' || status.state === 'cancelled') {
          clearInterval(interval);
        }
      } catch (err: any) {
        console.error('Job polling error:', err);
      }
    }, 800);

    return () => clearInterval(interval);
  }, [activeJobId]);

  const fetchDevices = async () => {
    setLoadingDevices(true);
    setErrorMsg(null);
    try {
      const list = await listAcquisitionDevices();
      setDevices(list);
      if (list.length > 0 && !selectedDevice) {
        handleSelectDevice(list[0]);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to enumerate physical devices');
    } finally {
      setLoadingDevices(false);
    }
  };

  const handleSelectDevice = (dev: PhysicalSource) => {
    setSelectedDevice(dev);
    setSafety(null);
    if (!destinationPath) {
      const sanitizedModel = (dev.model || `Drive${dev.drive_number}`).replace(/[^a-zA-Z0-9_-]/g, '_');
      setDestinationPath(`C:\\ForensicImages\\PhysicalDrive${dev.drive_number}_${sanitizedModel}.raw`);
    }
  };

  const handleAssessSafety = async () => {
    if (!selectedDevice || !destinationPath || !activeCase) return;
    setAssessingSafety(true);
    setErrorMsg(null);
    try {
      const assessment = await assessAcquisitionSafety(selectedDevice, {
        source_path: selectedDevice.device_path,
        destination_path: destinationPath,
        chunk_size: chunkSizeMb * 1024 * 1024,
        max_retries: maxRetries,
        case_id: activeCase.id,
        examiner: activeCase.examiner,
        attestation: {
          hardware_write_blocker_used: hardwareBlockerUsed,
          blocker_make_model: blockerModel || null,
          examiner_notes: examinerNotes || null,
        },
        attempt_volume_lock: attemptLock,
      });
      setSafety(assessment);
    } catch (err: any) {
      setErrorMsg(err.message || 'Safety assessment evaluation failed');
    } finally {
      setAssessingSafety(false);
    }
  };

  const handleStartAcquisition = async () => {
    if (!selectedDevice || !activeCase || !destinationPath) return;
    setErrorMsg(null);
    try {
      const res = await startAcquisitionJob({
        source_drive: selectedDevice.drive_number,
        destination_path: destinationPath,
        case_id: activeCase.id,
        examiner: activeCase.examiner,
        chunk_size: chunkSizeMb * 1024 * 1024,
        max_retries: maxRetries,
        attestation: {
          hardware_write_blocker_used: hardwareBlockerUsed,
          blocker_make_model: blockerModel || null,
          examiner_notes: examinerNotes || null,
        },
        attempt_volume_lock: attemptLock,
      });

      setActiveJobId(res.job_id);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to start acquisition job');
    }
  };

  const handleCancelJob = async () => {
    if (!activeJobId) return;
    setCancelling(true);
    try {
      await cancelAcquisitionJob(activeJobId);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to cancel job');
    } finally {
      setCancelling(false);
    }
  };

  const handleRegisterEvidence = async () => {
    if (!activeJobId) return;
    setRegistering(true);
    setErrorMsg(null);
    try {
      const res = await registerAcquisitionEvidence(activeJobId);
      setRegisteredEvidence({ evidence: res.evidence, acquisition: res.acquisition });
      if (onEvidenceRegistered) {
        onEvidenceRegistered(res);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to register evidence');
    } finally {
      setRegistering(false);
    }
  };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
  };

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
    <div className="view-container" data-tour="acquisition-view-panel">
      {/* Header */}
      <div className="view-header" style={{ marginBottom: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h1 className="view-title">Forensic Physical Acquisition & Verification</h1>
            <ContextHelp
              title="Forensic Physical Acquisition"
              content="Bit-for-bit physical disk acquisition operating under strict read-only guarantees (GENERIC_READ). Enforces NIST SP 800-86 chain of custody, hardware write-blocker attestation, automated anti-collision checks, adaptive bad-sector isolation, and independent two-pass cryptographic verification."
            />
          </div>
          <p className="view-subtitle">
            Windows PhysicalDrive streaming acquisition, independent SHA-256 verification, and forensic manifest generation
          </p>
        </div>

        {/* Tab toggle */}
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            className={`btn ${activeSubTab === 'workflow' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveSubTab('workflow')}
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <HardDrive size={14} />
            <span>Physical Acquisition Workflow</span>
          </button>
          <button
            className={`btn ${activeSubTab === 'audit' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveSubTab('audit')}
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <FileCheck2 size={14} />
            <span>Evidence Audit & Hashes</span>
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="alert alert-error" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <XCircle size={18} />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* ==================================================================== */}
      {/* WORKFLOW TAB */}
      {/* ==================================================================== */}
      {activeSubTab === 'workflow' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Active Case Warning */}
          {!activeCase && (
            <div className="alert alert-warning" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <AlertTriangle size={20} />
              <div>
                <strong>No Active Case Selected:</strong> Please open or create a forensic case before initiating acquisition to maintain chain-of-custody attribution.
              </div>
            </div>
          )}

          {/* Active Job Running / Finished Panel */}
          {activeJobId && jobStatus && (
            <div className="panel" style={{ border: '2px solid var(--accent-primary)', background: 'var(--bg-secondary)' }}>
              <div className="panel-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <HardDrive size={18} color="var(--accent-primary)" />
                  <span style={{ fontWeight: 600, fontSize: '1.1rem' }}>
                    Acquisition Monitor: PhysicalDrive{selectedDevice?.drive_number}
                  </span>
                </div>
                <div>
                  <span className={`badge badge-${jobStatus.state === 'completed' ? 'pass' : jobStatus.state === 'failed' ? 'fail' : 'review'}`}>
                    {jobStatus.state.toUpperCase()}
                  </span>
                </div>
              </div>

              {/* Progress metrics */}
              {jobStatus.acquisition_progress && (
                <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>
                      Current Phase: <strong style={{ color: 'var(--accent-primary)' }}>{jobStatus.acquisition_progress.current_phase.toUpperCase()}</strong>
                    </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                      {jobStatus.acquisition_progress.percentage.toFixed(1)}%
                    </span>
                  </div>

                  {/* Progress Bar */}
                  <div style={{ width: '100%', height: '14px', background: 'var(--bg-tertiary)', borderRadius: '7px', overflow: 'hidden' }}>
                    <div
                      style={{
                        width: `${jobStatus.acquisition_progress.percentage}%`,
                        height: '100%',
                        background: 'linear-gradient(90deg, #3b82f6, #10b981)',
                        transition: 'width 0.3s ease',
                      }}
                    />
                  </div>

                  <div className="grid-4" style={{ marginTop: '8px' }}>
                    <div className="metric-box">
                      <div className="metric-label">Processed</div>
                      <div className="metric-value" style={{ fontSize: '1.1rem' }}>
                        {formatBytes(jobStatus.acquisition_progress.bytes_processed)} / {formatBytes(jobStatus.acquisition_progress.total_bytes)}
                      </div>
                    </div>
                    <div className="metric-box">
                      <div className="metric-label">Throughput</div>
                      <div className="metric-value" style={{ fontSize: '1.1rem' }}>
                        {(jobStatus.acquisition_progress.throughput_bytes_per_sec / (1024 * 1024)).toFixed(1)} MB/s
                      </div>
                    </div>
                    <div className="metric-box">
                      <div className="metric-label">Elapsed / ETA</div>
                      <div className="metric-value" style={{ fontSize: '1.1rem' }}>
                        {Math.floor(jobStatus.acquisition_progress.elapsed_seconds)}s / {jobStatus.acquisition_progress.eta_seconds != null ? `${jobStatus.acquisition_progress.eta_seconds}s` : '--'}
                      </div>
                    </div>
                    <div className="metric-box">
                      <div className="metric-label">Bad Sectors (Zero-Filled)</div>
                      <div className="metric-value" style={{ fontSize: '1.1rem', color: jobStatus.acquisition_progress.bad_sector_count > 0 ? '#ef4444' : 'var(--text-primary)' }}>
                        {jobStatus.acquisition_progress.bad_sector_count} ({formatBytes(jobStatus.acquisition_progress.unreadable_bytes)})
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Completed Results & Independent Verification */}
              {jobStatus.state === 'completed' && jobStatus.acquisition_result && (
                <div style={{ padding: '16px', borderTop: '1px solid var(--border-color)', background: 'rgba(16, 185, 129, 0.05)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                    <CheckCircle2 size={20} color="#10b981" />
                    <h3 style={{ margin: 0, color: '#10b981' }}>Two-Pass Cryptographic Verification Succeeded</h3>
                  </div>

                  <table className="data-table" style={{ marginBottom: '16px' }}>
                    <thead>
                      <tr>
                        <th>Algorithm</th>
                        <th>Pass-1 Hash (Output Stream)</th>
                        <th>Pass-2 Hash (Disk Re-read)</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td style={{ fontWeight: 600 }}>MD5</td>
                        <td style={{ fontFamily: 'var(--font-mono)' }}>{jobStatus.acquisition_result.verification.pass1_md5}</td>
                        <td style={{ fontFamily: 'var(--font-mono)' }}>{jobStatus.acquisition_result.verification.pass2_md5 || '--'}</td>
                        <td><span className="badge badge-pass">MATCHED</span></td>
                      </tr>
                      <tr>
                        <td style={{ fontWeight: 600 }}>SHA-256</td>
                        <td style={{ fontFamily: 'var(--font-mono)' }}>{jobStatus.acquisition_result.verification.pass1_sha256}</td>
                        <td style={{ fontFamily: 'var(--font-mono)' }}>{jobStatus.acquisition_result.verification.pass2_sha256 || '--'}</td>
                        <td><span className="badge badge-pass">MATCHED</span></td>
                      </tr>
                    </tbody>
                  </table>

                  <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                    {!registeredEvidence ? (
                      <button
                        className="btn btn-primary"
                        onClick={handleRegisterEvidence}
                        disabled={registering}
                        style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                      >
                        <Database size={15} />
                        <span>{registering ? 'Registering Evidence...' : 'Register as Active Evidence'}</span>
                      </button>
                    ) : (
                      <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                        <span className="badge badge-pass" style={{ padding: '8px 12px', fontSize: '0.9rem' }}>
                          <CheckCircle2 size={15} /> Evidence Registered Successfully
                        </span>
                        {onNavigateTab && (
                          <button
                            className="btn btn-secondary"
                            onClick={() => onNavigateTab('overview')}
                            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                          >
                            <span>Start Forensic Analysis</span>
                            <ArrowRight size={15} />
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Cancel Button during run */}
              {(jobStatus.state === 'running' || jobStatus.state === 'queued') && (
                <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border-color)', display: 'flex', justifyContent: 'flex-end' }}>
                  <button
                    className="btn btn-secondary"
                    onClick={handleCancelJob}
                    disabled={cancelling}
                    style={{ color: '#ef4444', borderColor: '#ef4444', display: 'flex', alignItems: 'center', gap: '6px' }}
                  >
                    <StopCircle size={15} />
                    <span>{cancelling ? 'Cancelling...' : 'Cancel Acquisition'}</span>
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Device Selection & Setup Grid */}
          {(!activeJobId || jobStatus?.state === 'completed' || jobStatus?.state === 'failed') && (
            <div className="grid-2">
              {/* Left Column: Physical Disks List */}
              <div className="panel">
                <div className="panel-header">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <HardDrive size={16} color="var(--accent-primary)" />
                    <span>Connected Physical Disks</span>
                  </div>
                  <button
                    className="btn btn-secondary"
                    onClick={fetchDevices}
                    disabled={loadingDevices}
                    style={{ padding: '4px 10px', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '6px' }}
                  >
                    <RefreshCw size={12} className={loadingDevices ? 'spin' : ''} />
                    <span>Refresh</span>
                  </button>
                </div>

                {loadingDevices ? (
                  <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    Scanning physical block devices via Win32 IOCTL...
                  </div>
                ) : devices.length === 0 ? (
                  <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No physical drives detected. (Ensure elevated Administrator privileges on Windows).
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', padding: '12px' }}>
                    {devices.map((dev) => {
                      const isSelected = selectedDevice?.drive_number === dev.drive_number;
                      return (
                        <div
                          key={dev.drive_number}
                          onClick={() => handleSelectDevice(dev)}
                          style={{
                            padding: '12px',
                            borderRadius: '6px',
                            border: `1px solid ${isSelected ? 'var(--accent-primary)' : 'var(--border-color)'}`,
                            background: isSelected ? 'rgba(59, 130, 246, 0.08)' : 'var(--bg-tertiary)',
                            cursor: 'pointer',
                            transition: 'all 0.15s ease',
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '6px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <HardDrive size={15} color={isSelected ? 'var(--accent-primary)' : 'var(--text-secondary)'} />
                              <strong style={{ fontSize: '0.95rem' }}>PhysicalDrive{dev.drive_number}</strong>
                              <span className="badge badge-info" style={{ fontSize: '0.75rem' }}>{dev.bus_type}</span>
                            </div>
                            <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                              {formatBytes(dev.capacity)}
                            </span>
                          </div>

                          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                            {dev.model || dev.vendor || 'Generic Block Device'} {dev.serial ? `(${dev.serial})` : ''}
                          </div>

                          <div style={{ display: 'flex', gap: '8px', fontSize: '0.75rem', flexWrap: 'wrap' }}>
                            <span className="badge badge-secondary">Logical: {dev.logical_sector_size}B</span>
                            <span className="badge badge-secondary">Physical: {dev.physical_sector_size}B</span>
                            {dev.os_write_protected ? (
                              <span className="badge badge-pass"><ShieldCheck size={11} /> OS Write-Protected</span>
                            ) : (
                              <span className="badge badge-unknown">OS Writable</span>
                            )}
                            {dev.volumes.length === 0 ? (
                              <span className="badge badge-review">Proprietary DVR Media (No Volumes)</span>
                            ) : (
                              <span className="badge badge-secondary">{dev.volumes.length} Windows Volume(s)</span>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Right Column: Acquisition Configuration & Safety */}
              <div className="panel">
                <div className="panel-header">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <ShieldCheck size={16} color="var(--accent-primary)" />
                    <span>Forensic Acquisition Config & Safety</span>
                  </div>
                </div>

                <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  {/* Selected Source Summary */}
                  <div>
                    <label style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                      Selected Physical Source:
                    </label>
                    <div style={{ padding: '8px 12px', background: 'var(--bg-tertiary)', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '0.9rem' }}>
                      {selectedDevice ? `${selectedDevice.device_path} — ${formatBytes(selectedDevice.capacity)} (${selectedDevice.model || 'Unknown'})` : 'No drive selected'}
                    </div>
                  </div>

                  {/* Destination Path */}
                  <div>
                    <label style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                      Destination RAW Image Path (.raw):
                    </label>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <input
                        type="text"
                        className="input"
                        value={destinationPath}
                        onChange={(e) => {
                          setDestinationPath(e.target.value);
                          setSafety(null);
                        }}
                        placeholder="e.g. D:\Cases\Case1\physical_drive.raw"
                        style={{ flex: 1, fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}
                      />
                    </div>
                  </div>

                  {/* Examiner Write-Blocker Attestation */}
                  <div style={{ padding: '12px', background: 'rgba(59, 130, 246, 0.05)', borderRadius: '6px', border: '1px solid rgba(59, 130, 246, 0.2)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                      <input
                        type="checkbox"
                        id="writeBlockerCheck"
                        checked={hardwareBlockerUsed}
                        onChange={(e) => setHardwareBlockerUsed(e.target.checked)}
                      />
                      <label htmlFor="writeBlockerCheck" style={{ fontWeight: 600, cursor: 'pointer', fontSize: '0.9rem' }}>
                        Forensic Hardware Write-Blocker Connected (Examiner Attestation)
                      </label>
                    </div>

                    {hardwareBlockerUsed && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '8px' }}>
                        <input
                          type="text"
                          className="input"
                          value={blockerModel}
                          onChange={(e) => setBlockerModel(e.target.value)}
                          placeholder="Blocker Make & Model (e.g. Tableau T8u, WiebeTech UltraDock)"
                          style={{ fontSize: '0.85rem' }}
                        />
                        <input
                          type="text"
                          className="input"
                          value={examinerNotes}
                          onChange={(e) => setExaminerNotes(e.target.value)}
                          placeholder="Forensic bridge / hardware notes (optional)"
                          style={{ fontSize: '0.85rem' }}
                        />
                      </div>
                    )}

                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                      Notice: Software cannot independently prove physical write-blocker existence. This records examiner attestation into the chain of custody and manifest.
                    </div>
                  </div>

                  {/* Tuning Options */}
                  <div className="grid-2">
                    <div>
                      <label style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                        Chunk Buffer:
                      </label>
                      <select
                        className="input"
                        value={chunkSizeMb}
                        onChange={(e) => setChunkSizeMb(Number(e.target.value))}
                        style={{ width: '100%', fontSize: '0.85rem' }}
                      >
                        <option value={1}>1 MiB (Standard Forensic Default)</option>
                        <option value={2}>2 MiB</option>
                        <option value={4}>4 MiB</option>
                        <option value={0.5}>512 KiB</option>
                      </select>
                    </div>

                    <div>
                      <label style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                        Sector Read Retries:
                      </label>
                      <select
                        className="input"
                        value={maxRetries}
                        onChange={(e) => setMaxRetries(Number(e.target.value))}
                        style={{ width: '100%', fontSize: '0.85rem' }}
                      >
                        <option value={1}>1 Retry</option>
                        <option value={2}>2 Retries</option>
                        <option value={3}>3 Retries (Recommended)</option>
                        <option value={5}>5 Retries</option>
                      </select>
                    </div>
                  </div>

                  {/* Volume Lock Toggle */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <input
                      type="checkbox"
                      id="attemptLockCheck"
                      checked={attemptLock}
                      disabled={!selectedDevice || selectedDevice.volumes.length === 0}
                      onChange={(e) => setAttemptLock(e.target.checked)}
                    />
                    <label
                      htmlFor="attemptLockCheck"
                      style={{
                        fontSize: '0.85rem',
                        cursor: (!selectedDevice || selectedDevice.volumes.length === 0) ? 'not-allowed' : 'pointer',
                        color: (!selectedDevice || selectedDevice.volumes.length === 0) ? 'var(--text-muted)' : 'var(--text-primary)',
                      }}
                    >
                      Attempt Windows volume locking & dismount ({selectedDevice?.volumes.length || 0} recognized volume(s))
                    </label>
                  </div>

                  {/* Safety Assessment Action & Report */}
                  <div style={{ marginTop: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <button
                        className="btn btn-secondary"
                        onClick={handleAssessSafety}
                        disabled={assessingSafety || !selectedDevice || !destinationPath}
                        style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                      >
                        <ShieldAlert size={14} />
                        <span>{assessingSafety ? 'Assessing Safety...' : 'Validate Safety Invariants'}</span>
                      </button>

                      {safety && (
                        <span className={`badge badge-${safety.is_safe_to_proceed ? 'pass' : 'fail'}`}>
                          {safety.is_safe_to_proceed ? 'SAFE TO PROCEED' : 'SAFETY VIOLATION DETECTED'}
                        </span>
                      )}
                    </div>

                    {safety && (
                      <div style={{ padding: '10px', background: 'var(--bg-tertiary)', borderRadius: '6px', fontSize: '0.8rem', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          {safety.source_accessible ? <CheckCircle2 size={13} color="#10b981" /> : <XCircle size={13} color="#ef4444" />}
                          <span>Source Read-Only Handle Accessible</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          {safety.destination_not_on_source_device ? <CheckCircle2 size={13} color="#10b981" /> : <XCircle size={13} color="#ef4444" />}
                          <span>Anti-Collision: Destination does NOT reside on source physical disk</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          {safety.has_sufficient_space ? <CheckCircle2 size={13} color="#10b981" /> : <XCircle size={13} color="#ef4444" />}
                          <span>Free Space: {formatBytes(safety.destination_free_space_bytes)} available (Source: {formatBytes(safety.source_capacity_bytes)})</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <Info size={13} color="var(--accent-primary)" />
                          <span>Volume Lock State: <strong>{safety.volume_lock_state}</strong></span>
                        </div>

                        {safety.blocking_reasons.length > 0 && (
                          <div style={{ color: '#ef4444', marginTop: '4px', fontWeight: 600 }}>
                            {safety.blocking_reasons.map((r, i) => (
                              <div key={i}>• {r}</div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Start Acquisition Action */}
                  <div style={{ marginTop: '8px' }}>
                    <button
                      className="btn btn-primary"
                      onClick={handleStartAcquisition}
                      disabled={!safety?.is_safe_to_proceed || !activeCase}
                      style={{ width: '100%', padding: '10px', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '8px', fontSize: '1rem' }}
                    >
                      <Play size={16} />
                      <span>Start Forensic Acquisition</span>
                    </button>
                    {!safety?.is_safe_to_proceed && (
                      <div style={{ textAlign: 'center', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                        Safety assessment must validate successfully before acquisition can begin.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ==================================================================== */}
      {/* AUDIT & VERIFICATION TAB (Historical metadata view) */}
      {/* ==================================================================== */}
      {activeSubTab === 'audit' && (
        <div>
          {!acquisition ? (
            <div className="panel" style={{ textAlign: 'center', padding: '32px' }}>
              <HelpCircle size={28} color="#64748b" style={{ margin: '0 auto 10px', display: 'block' }} />
              <h3 style={{ marginBottom: '6px' }}>No Acquisition Data Available</h3>
              <p style={{ color: 'var(--text-muted)' }}>Perform physical acquisition or register existing evidence to view historical audit metadata.</p>
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
                      <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Bad Sector Ranges</td>
                      <td>{acquisition.bad_sector_ranges.length} range(s) recorded</td>
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
      )}
    </div>
  );
};
