import React, { useState } from 'react';
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
          <h1 className="view-title">Forensic Timeline & Provenance</h1>
          <p className="view-subtitle">Select an evidence target to view unified cross-camera timeline.</p>
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
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', backgroundColor: '#1e1e1e', padding: '12px 16px', borderRadius: '8px', border: '1px solid #333' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ fontSize: '13px', color: '#aaa', fontWeight: 'bold' }}>Timeline Ordering Mode:</span>
          {(['Normalized', 'RecorderNative', 'Physical'] as OrderingMode[]).map(mode => (
            <button
              key={mode}
              onClick={() => setOrdering(mode)}
              style={{
                padding: '6px 12px',
                borderRadius: '4px',
                border: '1px solid',
                borderColor: ordering === mode ? '#2196f3' : '#444',
                backgroundColor: ordering === mode ? '#1976d233' : '#252525',
                color: ordering === mode ? '#90caf9' : '#ccc',
                fontWeight: ordering === mode ? 'bold' : 'normal',
                cursor: 'pointer',
                fontSize: '12px',
              }}
            >
              {mode === 'Normalized' && '🕒 Normalized (UTC Chronological)'}
              {mode === 'RecorderNative' && '📼 Recorder-Native Time'}
              {mode === 'Physical' && '💾 Physical Disk Offset'}
            </button>
          ))}
        </div>
        <div style={{ fontSize: '12px', color: '#888' }}>
          {ordering === 'Physical' && '⚠️ Note: Physical disk order does NOT imply chronological order (Req 15.6)'}
          {ordering === 'Normalized' && '✓ UTC Normalized timeline with correlation window'}
          {ordering === 'RecorderNative' && '📼 Raw native DVR clock without external adjustment'}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: selectedEvent ? '1fr 380px' : '1fr', gap: '16px' }}>
        {/* Timeline Event Stream */}
        <div className="data-panel" style={{ backgroundColor: '#1e1e1e', borderRadius: '8px', border: '1px solid #333', overflow: 'hidden' }}>
          <div className="panel-header" style={{ padding: '16px', borderBottom: '1px solid #333' }}>
            <h3 style={{ margin: 0, fontSize: '16px' }}>
              Correlated Event Stream ({sortedEvents.length} events)
            </h3>
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
            <thead>
              <tr style={{ backgroundColor: '#252525', textAlign: 'left' }}>
                <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Camera</th>
                <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Normalized Time (UTC)</th>
                <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Recorder-Native & Raw</th>
                <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Description</th>
                <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Physical Offset</th>
                <th style={{ padding: '12px 16px', borderBottom: '1px solid #333' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {sortedEvents.map(evt => (
                <tr
                  key={evt.id}
                  onClick={() => setSelectedEvent(evt)}
                  style={{
                    borderBottom: '1px solid #333',
                    backgroundColor: selectedEvent?.id === evt.id ? '#1e3a5f33' : 'transparent',
                    cursor: 'pointer',
                  }}
                >
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{
                      padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold',
                      backgroundColor: evt.channel === 1 ? '#1565c0' : evt.channel === 2 ? '#2e7d32' : '#e65100',
                      color: 'white',
                    }}>
                      CH {evt.channel}
                    </span>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <div style={{ fontWeight: 'bold' }}>{evt.normalized_time}</div>
                    {evt.timezone_state === 'Unknown' && (
                      <span style={{ fontSize: '10px', color: '#ff9800', backgroundColor: '#ff980022', padding: '1px 4px', borderRadius: '2px' }}>
                        ⚠️ Unknown TZ
                      </span>
                    )}
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <div>{evt.native_time}</div>
                    <div style={{ color: '#888', fontSize: '11px', fontFamily: 'monospace' }}>
                      Raw: 0x{evt.raw_timestamp.toString(16)} ({evt.raw_format})
                    </div>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    {evt.description}
                  </td>
                  <td style={{ padding: '12px 16px', fontFamily: 'monospace', color: '#90caf9' }}>
                    0x{evt.source_offset.toString(16).padStart(8, '0')}
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onNavigateToHex(evt.source_offset);
                      }}
                      style={{ background: '#2196f3', color: 'white', border: 'none', padding: '4px 8px', borderRadius: '4px', cursor: 'pointer', fontSize: '11px' }}
                    >
                      Hex
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Provenance Detail Inspector Panel */}
        {selectedEvent && (
          <div style={{ backgroundColor: '#1e1e1e', borderRadius: '8px', border: '1px solid #333', padding: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', borderBottom: '1px solid #333', paddingBottom: '8px' }}>
              <h3 style={{ margin: 0, fontSize: '15px' }}>Lineage & Provenance</h3>
              <button
                onClick={() => setSelectedEvent(null)}
                style={{ background: 'transparent', border: 'none', color: '#aaa', cursor: 'pointer', fontSize: '14px' }}
              >
                ✕
              </button>
            </div>

            <div style={{ fontSize: '12px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div>
                <div style={{ color: '#888', marginBottom: '2px' }}>Event Target</div>
                <div style={{ fontWeight: 'bold' }}>{selectedEvent.description} (CH {selectedEvent.channel})</div>
              </div>

              <div>
                <div style={{ color: '#888', marginBottom: '2px' }}>Producing Parser Component</div>
                <div>{selectedEvent.provenance.producing_component} (v{selectedEvent.provenance.component_version})</div>
              </div>

              <div>
                <div style={{ color: '#888', marginBottom: '2px' }}>Applied OEM Profile</div>
                <div>{selectedEvent.provenance.profile_id}</div>
                <div style={{ fontFamily: 'monospace', fontSize: '10px', color: '#aaa', wordBreak: 'break-all' }}>
                  Hash: {selectedEvent.provenance.profile_hash}
                </div>
              </div>

              <div>
                <div style={{ color: '#888', marginBottom: '2px' }}>Physical Evidence Region</div>
                <div>Offset: 0x{selectedEvent.source_offset.toString(16)} ({selectedEvent.source_length} bytes)</div>
              </div>

              <div>
                <div style={{ color: '#888', marginBottom: '2px' }}>Transformation Steps Applied</div>
                <ul style={{ margin: '4px 0 0 16px', padding: 0 }}>
                  {selectedEvent.provenance.transformations.map((t, idx) => (
                    <li key={idx} style={{ color: '#90caf9' }}>{t}</li>
                  ))}
                </ul>
              </div>

              <div>
                <div style={{ color: '#888', marginBottom: '2px' }}>Artifact Classification</div>
                <span style={{ fontSize: '10px', padding: '2px 6px', borderRadius: '3px', backgroundColor: '#0d47a1', color: '#90caf9' }}>
                  {selectedEvent.provenance.is_native ? 'Native Original Evidence' : 'Derived'}
                </span>
              </div>

              <div style={{ marginTop: '8px', paddingTop: '8px', borderTop: '1px solid #333' }}>
                <button
                  onClick={() => onNavigateToHex(selectedEvent.source_offset)}
                  style={{ width: '100%', background: '#1976d2', color: 'white', border: 'none', padding: '8px', borderRadius: '4px', cursor: 'pointer', fontSize: '12px', fontWeight: 'bold' }}
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
