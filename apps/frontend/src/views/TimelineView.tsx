import React, { useState } from 'react';
import { Clock } from 'lucide-react';
import { Evidence } from '../types';

interface TimelineViewProps {
  evidence: Evidence | null;
  onNavigateToHex: (offset: number) => void;
}

type OrderingMode = 'Normalized' | 'RecorderNative' | 'Physical';

interface TimelineEventUI {
  id: string;
  channel: number;
  description: string;
  raw_timestamp: number;
  raw_format: string;
  native_time: string;
  normalized_time: string;
  timezone_state: 'Known' | 'Unknown';
  timezone_label: string;
  source_offset: number;
  source_length: number;
  provenance: {
    producing_component: string;
    component_version: string;
    profile_id: string;
    profile_hash: string;
    output_hash: string;
    transformations: string[];
    is_native: boolean;
  };
}

export const TimelineView: React.FC<TimelineViewProps> = ({ evidence, onNavigateToHex }) => {
  const [ordering, setOrdering] = useState<OrderingMode>('Normalized');
  const [selectedEvent, setSelectedEvent] = useState<TimelineEventUI | null>(null);

  if (!evidence) {
    return (
      <div className="view-container">
        <div className="view-header">
          <div>
            <h1 className="view-title">Forensic Timeline & Provenance</h1>
            <p className="view-subtitle">Select an evidence target to view unified cross-camera timeline.</p>
          </div>
        </div>
        <div className="empty-state">
          <Clock size={32} />
          <h3>No Evidence Selected</h3>
          <p>Select a DVR/NVR evidence item from the active case to begin analysis.</p>
        </div>
      </div>
    );
  }

  const mockEvents: TimelineEventUI[] = [
    {
      id: 'evt-001',
      channel: 1,
      description: 'Vehicle entered gate (Camera 1)',
      raw_timestamp: 0x20260901140000,
      raw_format: 'BCD 64-bit',
      native_time: '2026-09-01 14:00:00',
      normalized_time: '2026-09-01 14:00:00 UTC',
      timezone_state: 'Known',
      timezone_label: 'UTC+0',
      source_offset: 0x00100000,
      source_length: 512,
      provenance: {
        producing_component: 'Parser-Dahua',
        component_version: '1.0.0',
        profile_id: 'dahua-dhfs-v1.0',
        profile_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        output_hash: 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e',
        transformations: ['Indexed Frame Parse', 'UTC Normalization'],
        is_native: true,
      },
    },
    {
      id: 'evt-002',
      channel: 2,
      description: 'Person detected at lobby entrance (Camera 2)',
      raw_timestamp: 0x20260901140015,
      raw_format: 'BCD 64-bit',
      native_time: '2026-09-01 14:00:15',
      normalized_time: '2026-09-01 14:00:15 UTC',
      timezone_state: 'Known',
      timezone_label: 'UTC+0',
      source_offset: 0x00250000,
      source_length: 512,
      provenance: {
        producing_component: 'Parser-Hikvision',
        component_version: '1.0.0',
        profile_id: 'hikvision-hikbtfs-v1.0',
        profile_hash: 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2',
        output_hash: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
        transformations: ['Master Sector Index Parse', 'UTC Normalization'],
        is_native: true,
      },
    },
    {
      id: 'evt-003',
      channel: 3,
      description: 'Side corridor motion detected (Camera 3)',
      raw_timestamp: 0x66D46850,
      raw_format: 'UNIX Epoch Seconds (LE)',
      native_time: '2026-09-01 14:00:30',
      normalized_time: '2026-09-01 14:00:30 UTC',
      timezone_state: 'Unknown',
      timezone_label: 'Unknown Timezone (Unadjusted)',
      source_offset: 0x00080000,
      source_length: 512,
      provenance: {
        producing_component: 'Parser-Uniview',
        component_version: '1.0.0',
        profile_id: 'uniview-ubifs-v1.0',
        profile_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        output_hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
        transformations: ['EC1001 Marker Carve', 'Epoch Parsing'],
        is_native: true,
      },
    },
  ];

  // Sort events based on selected ordering
  const sortedEvents = [...mockEvents].sort((a, b) => {
    if (ordering === 'Physical') {
      return a.source_offset - b.source_offset;
    } else if (ordering === 'RecorderNative') {
      return a.native_time.localeCompare(b.native_time);
    } else {
      return a.normalized_time.localeCompare(b.normalized_time);
    }
  });

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h1 className="view-title">Unified Forensic Timeline & Lineage</h1>
          <p className="view-subtitle">Cross-camera temporal correlation with full provenance and raw timestamp preservation (Phase 5 / Req 15, 4)</p>
        </div>
      </div>

      {/* Controls Bar */}
      <div className="panel" style={{ padding: '12px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span className="text-muted" style={{ fontSize: '13px', fontWeight: 600 }}>Timeline Ordering Mode:</span>
          <div style={{ display: 'flex', gap: '8px' }}>
            {(['Normalized', 'RecorderNative', 'Physical'] as OrderingMode[]).map(mode => (
              <button
                key={mode}
                onClick={() => setOrdering(mode)}
                style={{
                  padding: '6px 12px',
                  borderRadius: '4px',
                  border: '1px solid',
                  borderColor: ordering === mode ? 'var(--accent)' : 'var(--border)',
                  backgroundColor: ordering === mode ? 'var(--accent-light)' : 'var(--surface)',
                  color: ordering === mode ? 'var(--accent)' : 'var(--text-secondary)',
                  fontWeight: ordering === mode ? 600 : 500,
                  cursor: 'pointer',
                  fontSize: '12px',
                  transition: 'all 0.15s ease'
                }}
              >
                {mode === 'Normalized' && '🕒 Normalized (UTC Chronological)'}
                {mode === 'RecorderNative' && '📼 Recorder-Native Time'}
                {mode === 'Physical' && '💾 Physical Disk Offset'}
              </button>
            ))}
          </div>
        </div>
        <div className="text-muted" style={{ fontSize: '12px' }}>
          {ordering === 'Physical' && '⚠️ Note: Physical disk order does NOT imply chronological order (Req 15.6)'}
          {ordering === 'Normalized' && '✓ UTC Normalized timeline with correlation window'}
          {ordering === 'RecorderNative' && '📼 Raw native DVR clock without external adjustment'}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: selectedEvent ? '1fr 380px' : '1fr', gap: '16px' }}>
        {/* Timeline Event Stream */}
        <div className="panel" style={{ padding: '0', overflow: 'hidden' }}>
          <div className="panel-header" style={{ margin: 0, padding: '16px' }}>
            <h3 style={{ margin: 0, fontSize: '14px' }}>
              Correlated Event Stream ({sortedEvents.length} events)
            </h3>
          </div>
          <div className="table-container" style={{ border: 'none', borderTop: '1px solid var(--border)', borderRadius: '0' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Camera</th>
                  <th>Normalized Time (UTC)</th>
                  <th>Recorder-Native & Raw</th>
                  <th>Description</th>
                  <th>Physical Offset</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sortedEvents.map(evt => (
                  <tr
                    key={evt.id}
                    onClick={() => setSelectedEvent(evt)}
                    style={{
                      backgroundColor: selectedEvent?.id === evt.id ? 'var(--accent-light)' : 'transparent',
                      cursor: 'pointer',
                      transition: 'background-color 0.1s',
                    }}
                  >
                    <td>
                      <span className="badge" style={{
                        backgroundColor: evt.channel === 1 ? '#e0f2fe' : evt.channel === 2 ? '#dcfce7' : '#ffedd5',
                        color: evt.channel === 1 ? '#0369a1' : evt.channel === 2 ? '#15803d' : '#c2410c',
                        border: '1px solid',
                        borderColor: evt.channel === 1 ? '#bae6fd' : evt.channel === 2 ? '#bbf7d0' : '#fed7aa',
                      }}>
                        CH {evt.channel}
                      </span>
                    </td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{evt.normalized_time}</div>
                      {evt.timezone_state === 'Unknown' && (
                        <div className="mt-4"><span className="badge badge-review" style={{ fontSize: '9px' }}>
                          ⚠️ Unknown TZ
                        </span></div>
                      )}
                    </td>
                    <td>
                      <div>{evt.native_time}</div>
                      <div className="text-muted mono" style={{ fontSize: '11px', marginTop: '2px' }}>
                        Raw: 0x{evt.raw_timestamp.toString(16).toUpperCase()} ({evt.raw_format})
                      </div>
                    </td>
                    <td>{evt.description}</td>
                    <td className="mono" style={{ color: 'var(--accent)' }}>
                      0x{evt.source_offset.toString(16).padStart(8, '0').toUpperCase()}
                    </td>
                    <td>
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          onNavigateToHex(evt.source_offset);
                        }}
                      >
                        Hex
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Provenance Detail Inspector Panel */}
        {selectedEvent && (
          <div className="panel">
            <div className="panel-header no-border">
              <h3 style={{ margin: 0, fontSize: '14px' }}>Lineage & Provenance</h3>
              <button
                onClick={() => setSelectedEvent(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '14px' }}
              >
                ✕
              </button>
            </div>

            <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '16px', fontSize: '12px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div>
                <div className="text-muted" style={{ fontWeight: 600, marginBottom: '2px' }}>Event Target</div>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{selectedEvent.description} (CH {selectedEvent.channel})</div>
              </div>

              <div>
                <div className="text-muted" style={{ fontWeight: 600, marginBottom: '2px' }}>Producing Parser Component</div>
                <div>{selectedEvent.provenance.producing_component} (v{selectedEvent.provenance.component_version})</div>
              </div>

              <div>
                <div className="text-muted" style={{ fontWeight: 600, marginBottom: '2px' }}>Applied OEM Profile</div>
                <div>{selectedEvent.provenance.profile_id}</div>
                <div className="mono text-muted" style={{ fontSize: '10px', wordBreak: 'break-all', marginTop: '2px' }}>
                  Hash: {selectedEvent.provenance.profile_hash}
                </div>
              </div>

              <div>
                <div className="text-muted" style={{ fontWeight: 600, marginBottom: '2px' }}>Physical Evidence Region</div>
                <div>Offset: <span className="mono">0x{selectedEvent.source_offset.toString(16).toUpperCase()}</span> ({selectedEvent.source_length} bytes)</div>
              </div>

              <div>
                <div className="text-muted" style={{ fontWeight: 600, marginBottom: '2px' }}>Transformation Steps Applied</div>
                <ul style={{ margin: '4px 0 0 16px', padding: 0, color: 'var(--text-primary)' }}>
                  {selectedEvent.provenance.transformations.map((t, idx) => (
                    <li key={idx}>{t}</li>
                  ))}
                </ul>
              </div>

              <div>
                <div className="text-muted" style={{ fontWeight: 600, marginBottom: '4px' }}>Artifact Classification</div>
                {selectedEvent.provenance.is_native ? (
                  <span className="badge badge-info">Native Original Evidence</span>
                ) : (
                  <span className="badge badge-unknown">Derived</span>
                )}
              </div>

              <div style={{ marginTop: '8px', paddingTop: '16px', borderTop: '1px solid var(--border-subtle)' }}>
                <button
                  onClick={() => onNavigateToHex(selectedEvent.source_offset)}
                  className="btn btn-primary"
                  style={{ width: '100%' }}
                >
                  Inspect in Hex Viewer
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
