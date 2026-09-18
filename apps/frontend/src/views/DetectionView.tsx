import React, { useEffect, useState } from 'react';
import { Search, Activity, Shield, CheckCircle, AlertCircle, HardDrive, Cpu, AlignLeft } from 'lucide-react';
import { Evidence, ClassifiedDetectionResult, CapabilityStages, StorageTopology } from '../types';
import { runDetection, getCapabilities, getTopology } from '../services/api';
import { loadStorage, saveStorage } from '../utils/storage';

interface DetectionViewProps {
  evidence: Evidence | null;
  evidenceList?: Evidence[];
  onSelectEvidence?: (e: Evidence) => void;
}

export const DetectionView: React.FC<DetectionViewProps> = ({ 
  evidence, 
  evidenceList = [], 
  onSelectEvidence 
}) => {
  const [capabilities, setCapabilities] = useState<Record<string, CapabilityStages>>({});
  const [results, setResults] = useState<ClassifiedDetectionResult[]>([]);
  const [topology, setTopology] = useState<StorageTopology | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchCapabilities();
  }, []);

  useEffect(() => {
    if (evidence) {
      const savedRes = loadStorage<ClassifiedDetectionResult[]>(`forensic_det_results_${evidence.id}`, []);
      const savedTop = loadStorage<StorageTopology | null>(`forensic_det_topology_${evidence.id}`, null);
      setResults(savedRes);
      setTopology(savedTop);
    } else {
      setResults([]);
      setTopology(null);
    }
  }, [evidence?.id]);

  const fetchCapabilities = async () => {
    try {
      const caps = await getCapabilities();
      setCapabilities(caps);
    } catch (err) {
      console.error('Failed to fetch capabilities', err);
    }
  };

  const handleRunDetection = async () => {
    if (!evidence) return;
    setLoading(true);
    setError(null);
    try {
      const [topRes, detRes] = await Promise.all([
        getTopology(evidence.id),
        runDetection(evidence.id)
      ]);
      setTopology(topRes);
      setResults(detRes);
      saveStorage(`forensic_det_topology_${evidence.id}`, topRes);
      saveStorage(`forensic_det_results_${evidence.id}`, detRes);
    } catch (err: any) {
      setError(err.message || 'Detection failed');
    } finally {
      setLoading(false);
    }
  };

  const getAttributionColor = (status: string) => {
    switch (status) {
      case 'Confirmed': return '#10b981'; // green
      case 'CompatibleCandidate': return '#3b82f6'; // blue
      case 'Ambiguous': return '#f59e0b'; // yellow
      case 'Unknown': return '#6b7280'; // gray
      case 'Insufficient': return '#ef4444'; // red
      default: return '#6b7280';
    }
  };

  const renderCapabilityPill = (stage: string) => {
    if (stage === 'IMPLEMENTED') {
      return <span className="status-badge success"><CheckCircle size={12}/> {stage}</span>;
    } else if (stage === 'PARTIAL') {
      return <span className="status-badge warning"><Activity size={12}/> {stage}</span>;
    }
    return <span className="status-badge unknown">{stage}</span>;
  };

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h1 className="view-title">Multi-Vendor Storage Detection</h1>
          <p className="view-subtitle">Parallel deterministic orchestration, topology profiling, and confidence-scored attribution</p>
        </div>
      </div>

      {/* Target Evidence Selector Bar */}
      <div className="panel" style={{ padding: '16px', marginBottom: '20px', backgroundColor: 'var(--surface)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <HardDrive size={18} style={{ color: 'var(--accent)' }} />
            <div>
              <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 600 }}>
                Active Target Evidence
              </div>
              {evidence ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '2px' }}>
                  <strong style={{ fontSize: '14px' }}>{evidence.source_device}</strong>
                  <span className="badge badge-info">{evidence.image_format}</span>
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    ({(evidence.capacity / (1024 * 1024)).toFixed(2)} MB)
                  </span>
                </div>
              ) : (
                <div style={{ color: 'var(--text-muted)', fontStyle: 'italic', marginTop: '2px' }}>
                  No evidence selected. Please register or select an evidence target.
                </div>
              )}
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {evidenceList && evidenceList.length > 1 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                  Switch Target:
                </label>
                <select
                  className="form-select"
                  style={{ width: '220px', padding: '6px 10px', fontSize: '12px' }}
                  value={evidence?.id || ''}
                  onChange={(e) => {
                    const found = evidenceList.find((item) => item.id === e.target.value);
                    if (found && onSelectEvidence) onSelectEvidence(found);
                  }}
                >
                  {evidenceList.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.source_device} ({(item.capacity / (1024 * 1024)).toFixed(0)}MB)
                    </option>
                  ))}
                </select>
              </div>
            )}

            <button 
              className="btn btn-primary" 
              onClick={handleRunDetection} 
              disabled={!evidence || loading}
              style={{ padding: '8px 16px' }}
            >
              {loading ? <Activity size={16} className="spin" /> : <Search size={16} />}
              <span>{loading ? 'Running Analysis...' : 'Run Detection & Profiling'}</span>
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div style={{ color: '#991b1b', background: '#fee2e2', padding: '12px 16px', borderRadius: '6px', marginBottom: '20px', display: 'flex', gap: '8px', alignItems: 'center' }}>
          <AlertCircle size={16} style={{ flexShrink: 0 }} />
          <span>{error}</span>
        </div>
      )}

      {/* Capability Matrix (Req 3.6, 21.2) */}
      <div className="panel mb-4">
        <div className="panel-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Shield size={16} color="var(--accent-primary)" />
            <span>OEM Capability Matrix (Derived from implementation)</span>
          </div>
        </div>
        <div className="panel-content" style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '14px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-color)', textAlign: 'left', color: 'var(--text-muted)' }}>
                <th style={{ padding: '8px' }}>OEM Key</th>
                <th style={{ padding: '8px' }}>Detection</th>
                <th style={{ padding: '8px' }}>Profiling</th>
                <th style={{ padding: '8px' }}>Parsing</th>
                <th style={{ padding: '8px' }}>Reconstruction</th>
                <th style={{ padding: '8px' }}>Validation</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(capabilities).map(([oem, stages]) => (
                <tr key={oem} style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <td style={{ padding: '12px 8px', fontWeight: '500', textTransform: 'capitalize' }}>{oem.replace('_', ' ')}</td>
                  <td style={{ padding: '12px 8px' }}>{renderCapabilityPill(stages.detection)}</td>
                  <td style={{ padding: '12px 8px' }}>{renderCapabilityPill(stages.profiling)}</td>
                  <td style={{ padding: '12px 8px' }}>{renderCapabilityPill(stages.parsing)}</td>
                  <td style={{ padding: '12px 8px' }}>{renderCapabilityPill(stages.reconstruction)}</td>
                  <td style={{ padding: '12px 8px' }}>{renderCapabilityPill(stages.validation)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {error && (
        <div style={{ color: '#991b1b', background: '#fee2e2', padding: '12px', borderRadius: '6px', marginBottom: '24px' }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* Storage Topology */}
      {topology && (
        <div className="panel mb-4">
          <div className="panel-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <HardDrive size={16} color="var(--accent-primary)" />
              <span>Storage Topology Profiler</span>
            </div>
            <span className="status-badge success">{String(topology.topology_type || 'RAW').toUpperCase()}</span>
          </div>
          <div className="panel-content">
            <h4 style={{ marginBottom: '8px', color: 'var(--text-muted)' }}>Partitions & Regions</h4>
            {(!topology.partitions || topology.partitions.length === 0) ? (
              <div style={{ padding: '12px', background: 'var(--bg-secondary)', borderRadius: '6px', fontSize: '13px' }}>
                Raw disk geometry / Unpartitioned space only (Sector size: {topology.sector_size || 512} bytes).
                {topology.unpartitioned_regions && topology.unpartitioned_regions.length > 0 && (
                  <div style={{ marginTop: '6px', color: 'var(--text-muted)' }}>
                    Total unpartitioned capacity: {((topology.unpartitioned_regions[0]?.length || 0) / (1024 * 1024)).toFixed(2)} MB
                  </div>
                )}
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {topology.partitions.map((part, idx) => (
                  <div key={`part-${idx}`} style={{ display: 'flex', justifyContent: 'space-between', padding: '12px', background: 'var(--bg-secondary)', borderRadius: '6px', borderLeft: '3px solid var(--accent-primary)' }}>
                    <div>
                      <div style={{ fontWeight: '500', marginBottom: '4px' }}>Partition #{part.index}: {part.partition_type}</div>
                      <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Sector {part.start_sector} ({part.sector_count} sectors, {part.sector_size} B/sector)</div>
                    </div>
                    <div style={{ textAlign: 'right', fontSize: '12px', color: 'var(--text-muted)' }}>
                      Offset: 0x{part.region?.offset?.toString(16).toUpperCase() || '0'}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Detection Results */}
      {results.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <h3 style={{ margin: '16px 0 8px', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
            Multi-Vendor Candidate Attribution Leaderboard
          </h3>

          {/* Multi-Vendor Comparison Matrix */}
          <div className="panel mb-3">
            <div className="panel-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Activity size={16} color="var(--accent-primary)" />
                <span>Candidate Confidence Scores & Evaluated Margins</span>
              </div>
            </div>
            <div className="panel-content" style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-color)', textAlign: 'left', color: 'var(--text-muted)' }}>
                    <th style={{ padding: '8px' }}>Rank</th>
                    <th style={{ padding: '8px' }}>OEM Candidate</th>
                    <th style={{ padding: '8px' }}>Confidence Score</th>
                    <th style={{ padding: '8px' }}>Attribution Status</th>
                    <th style={{ padding: '8px' }}>Quality</th>
                    <th style={{ padding: '8px' }}>Matched Signatures</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((cand, idx) => (
                    <tr key={idx} style={{ borderBottom: '1px solid var(--border-color)', background: idx === 0 ? 'rgba(59, 130, 246, 0.05)' : 'transparent' }}>
                      <td style={{ padding: '10px 8px', fontWeight: idx === 0 ? 'bold' : 'normal' }}>#{idx + 1}</td>
                      <td style={{ padding: '10px 8px', fontWeight: '600', textTransform: 'capitalize' }}>
                        {cand.oem_key.replace('_', ' ')}
                        {idx === 0 && <span style={{ marginLeft: '6px', fontSize: '11px', color: 'var(--accent-primary)', fontWeight: 'bold' }}>(Top Candidate)</span>}
                      </td>
                      <td style={{ padding: '10px 8px', minWidth: '160px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <div style={{ flex: 1, height: '8px', background: 'var(--bg-secondary)', borderRadius: '4px', overflow: 'hidden' }}>
                            <div style={{ width: `${(cand.confidence_score * 100).toFixed(0)}%`, height: '100%', background: cand.confidence_score > 0 ? getAttributionColor(cand.attribution_status) : '#9ca3af' }} />
                          </div>
                          <span style={{ fontWeight: 'bold', minWidth: '45px' }}>{(cand.confidence_score * 100).toFixed(1)}%</span>
                        </div>
                      </td>
                      <td style={{ padding: '10px 8px' }}>
                        <span className="status-badge" style={{ backgroundColor: getAttributionColor(cand.attribution_status), color: 'white', fontSize: '11px' }}>
                          {cand.attribution_status}
                        </span>
                      </td>
                      <td style={{ padding: '10px 8px' }}>{(cand.quality_score * 100).toFixed(0)}%</td>
                      <td style={{ padding: '10px 8px' }}>
                        {(() => {
                          const matchedCount = cand.evidence_items.filter(item => item.rule_match_status === 'MATCH').length;
                          return matchedCount > 0 ? (
                            <span style={{ color: '#10b981', fontWeight: 'bold' }}>{matchedCount} signature(s) matched</span>
                          ) : (
                            <span style={{ color: 'var(--text-muted)' }}>0 matches</span>
                          );
                        })()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <h3 style={{ margin: '16px 0 8px', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
            Detailed Evidence & Engine Classifications
          </h3>

          {results.filter(r => r.confidence_score > 0 || r.evidence_items.length > 0).map((res, idx) => (
            <div key={idx} className="panel">
              <div className="panel-header" style={{ borderBottom: `2px solid ${getAttributionColor(res.attribution_status)}` }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Cpu size={16} />
                  <span style={{ fontWeight: '600', fontSize: '16px', textTransform: 'capitalize' }}>{(res.oem_key || 'Unknown').replace('_', ' ')}</span>
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <span className="status-badge" style={{ backgroundColor: getAttributionColor(res.attribution_status), color: 'white' }}>
                    {res.attribution_status}
                  </span>
                  <span className="status-badge" style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
                    Class: {res.classification}
                  </span>
                </div>
              </div>
              
              <div className="panel-content">
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '16px', paddingBottom: '16px', borderBottom: '1px dashed var(--border-color)' }}>
                  <div>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>Confidence Score</div>
                    <div style={{ fontSize: '24px', fontWeight: 'bold' }}>{((res.confidence_score || 0) * 100).toFixed(1)}%</div>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>Margin to next: {((res.margin || 0) * 100).toFixed(1)}% | Quality: {((res.quality_score || 0) * 100).toFixed(1)}%</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>Engine Configuration</div>
                    <div style={{ fontSize: '13px', fontFamily: 'monospace' }}>
                      Profile: {res.profile_version || '1.0.0'} ({typeof res.profile_hash === 'object' && (res.profile_hash as any)?.value ? String((res.profile_hash as any).value).substring(0, 8) : String(res.profile_hash || '').substring(0, 8) || 'N/A'})
                    </div>
                    <div style={{ fontSize: '13px', fontFamily: 'monospace', marginTop: '4px' }}>
                      Config: {res.config_version || '1.0.0'} ({typeof res.config_hash === 'object' && (res.config_hash as any)?.value ? String((res.config_hash as any).value).substring(0, 8) : String(res.config_hash || '').substring(0, 8) || 'N/A'})
                    </div>
                  </div>
                </div>

                {res.warnings && res.warnings.length > 0 && (
                  <div style={{ background: '#fffbeb', color: '#92400e', padding: '12px', borderRadius: '6px', marginBottom: '16px', fontSize: '13px', display: 'flex', alignItems: 'flex-start', gap: '8px' }}>
                    <AlertCircle size={16} style={{ flexShrink: 0, marginTop: '2px' }} />
                    <ul style={{ margin: 0, paddingLeft: '16px' }}>
                      {res.warnings.map((w, i) => <li key={i}>{w}</li>)}
                    </ul>
                  </div>
                )}

                <h4 style={{ marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-muted)' }}>
                  <AlignLeft size={14} /> Corroborating Evidence Items
                </h4>
                {(!res.evidence_items || res.evidence_items.length === 0) ? (
                  <div style={{ fontSize: '13px', color: 'var(--text-muted)', fontStyle: 'italic' }}>No evidence matching this OEM profile found.</div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {res.evidence_items.map((item, i) => (
                      <div key={i} style={{ padding: '10px 14px', background: 'var(--bg-secondary)', borderRadius: '6px', fontSize: '13px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                          <span style={{ fontWeight: '500' }}>{item.description}</span>
                          <span style={{ color: 'var(--text-muted)' }}>{item.offset_start !== undefined ? `0x${item.offset_start.toString(16).toUpperCase()}` : ''}</span>
                        </div>
                        <div style={{ display: 'flex', gap: '8px', fontSize: '11px' }}>
                          <span className={`status-badge ${item.evidence_status === 'VALIDATED' ? 'success' : 'warning'}`}>
                            {(item.evidence_status || '').replace('_', ' ')}
                          </span>
                          <span className="status-badge">
                            {item.rule_match_status}
                          </span>
                          {item.is_exclusive && (
                            <span className="status-badge" style={{ backgroundColor: '#e0e7ff', color: '#4f46e5' }}>EXCLUSIVE</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
