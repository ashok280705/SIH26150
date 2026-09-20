import React, { useState, useEffect } from 'react';
import { Clock, Layers, ShieldCheck, HardDrive, RefreshCw } from 'lucide-react';
import { Evidence, OrderingMode, TimelineEventApi, ValidationState, hashHex } from '../types';
import { getTimeline } from '../services/api';
import { ContextHelp } from '../components/onboarding/ContextHelp';
import { WorkflowState } from '../workflow';

interface TimelineViewProps {
  evidence: Evidence | null;
  evidenceList?: Evidence[];
  onSelectEvidence?: (e: Evidence) => void;
  onNavigateToHex: (offset: number) => void;
  onWorkflow?: (patch: Partial<WorkflowState>) => void;
}

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
    /** `null` when no output hash has been computed for this event. */
    output_hash: string | null;
    transformations: string[];
    is_native: boolean;
  };
}

/** Maps a backend TimelineEvent onto the view model without inventing values. */
function toEventUI(e: TimelineEventApi, idx: number): TimelineEventUI {
  const region = e.source_offsets?.[0] ?? { offset: 0, length: 0 };
  const tzKnown = typeof e.time.timezone === 'object' && e.time.timezone !== null;
  const tzLabel = tzKnown
    ? (e.time.timezone as { Known: string }).Known
    : 'Unknown Timezone (Unadjusted)';

  const transformations: string[] = [`Parsed by ${e.parser_id} v${e.parser_version}`];
  if (e.time.normalized) {
    transformations.push(`Normalization: ${e.time.normalized.method}`);
  } else {
    transformations.push('No normalization applied');
  }

  return {
    id: `evt-${idx + 1}-ch${e.channel}-0x${region.offset.toString(16).toUpperCase()}`,
    channel: e.channel,
    description: e.description,
    raw_timestamp: e.time.raw?.value ?? 0,
    raw_format: e.time.raw?.format ?? 'Unknown',
    native_time: e.time.recorder_native?.iso_8601 ?? 'Unknown',
    normalized_time: e.time.normalized?.iso_8601 ?? 'Unknown',
    timezone_state: tzKnown ? 'Known' : 'Unknown',
    timezone_label: tzLabel,
    source_offset: region.offset,
    source_length: region.length,
    provenance: {
      producing_component: e.parser_id,
      component_version: e.parser_version,
      profile_id: e.profile_id,
      // The backend sends a Hash object ({algorithm, value}); flatten it to the hex
      // digest so JSX renders text rather than an object.
      profile_hash: hashHex(e.profile_hash) ?? 'Unavailable',
      output_hash: null,
      transformations,
      is_native: true,
    },
  };
}

export const TimelineView: React.FC<TimelineViewProps> = ({ 
  evidence, 
  evidenceList = [], 
  onSelectEvidence, 
  onNavigateToHex,
  onWorkflow,
}) => {
  const [ordering, setOrdering] = useState<OrderingMode>('Normalized');
  const [selectedEvent, setSelectedEvent] = useState<TimelineEventUI | null>(null);
  const [events, setEvents] = useState<TimelineEventUI[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [timelineValidation, setTimelineValidation] = useState<ValidationState | null>(null);
  const [hasUnknownTimezones, setHasUnknownTimezones] = useState(false);

  // Re-fetch when the ordering mode changes so the backend stays authoritative.
  useEffect(() => {
    if (evidence) {
      loadTimelineEvents();
    } else {
      setEvents([]);
      setSelectedEvent(null);
      setError(null);
      setTimelineValidation(null);
    }
  }, [evidence?.id, ordering]);

  const loadTimelineEvents = async () => {
    if (!evidence) return;
    setLoading(true);
    setError(null);
    try {
      // Ordering is applied server-side by TimelineEngine, which owns the
      // deterministic tie-break rules for each mode.
      const res = await getTimeline(evidence.id, ordering);
      const mapped = res.events.map(toEventUI);
      setEvents(mapped);
      setTimelineValidation(res.validation);
      setHasUnknownTimezones(res.has_unknown_timezones);
      setSelectedEvent(mapped[0] ?? null);
      // The final timeline is now built — unlock the Video Player and Reports.
      if (onWorkflow) onWorkflow({ finalTimelineBuilt: true });
    } catch (err: any) {
      console.error('Failed to load timeline events', err);
      setError(err?.message || 'Timeline correlation failed');
      setEvents([]);
      setSelectedEvent(null);
      setTimelineValidation(null);
      setHasUnknownTimezones(false);
    } finally {
      setLoading(false);
    }
  };

  if (!evidence) {
    return (
      <div className="view-container" data-tour="timeline-view-panel">
        <div className="view-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h1 className="view-title">Forensic Timeline & Provenance</h1>
              <ContextHelp
                title="Forensic Timeline"
                content="The timeline aligns multi-channel recordings chronologically with ordering modes (Normalized UTC, Native, Physical offset) and explicit timezone state flags."
              />
            </div>
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

  const capacityMb = (evidence.capacity / (1024 * 1024)).toFixed(2);

  // Already ordered by TimelineEngine on the backend for the selected mode;
  // re-sorting here would risk diverging from the authoritative tie-break rules.
  const sortedEvents = events;

  return (
    <div className="view-container" data-tour="timeline-view-panel">
      <div className="view-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h1 className="view-title">Unified Forensic Timeline & Lineage</h1>
            <ContextHelp
              title="Forensic Timeline"
              content="The timeline aligns multi-channel recordings chronologically with ordering modes (Normalized UTC, Native, Physical offset) and explicit timezone state flags."
            />
          </div>
          <p className="view-subtitle">Cross-camera temporal correlation with full provenance and raw timestamp preservation (Phase 5 / Req 15, 4)</p>
        </div>
        <div>
          <button className="btn btn-secondary" onClick={loadTimelineEvents} disabled={loading}>
            {loading ? <RefreshCw size={14} className="spin" /> : <Clock size={14} />}
            <span>{loading ? 'Correlating...' : 'Re-correlate Events'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="panel mb-4" style={{ borderLeft: '4px solid var(--danger)' }}>
          <strong>Timeline correlation failed</strong>
          <div className="text-muted" style={{ fontSize: '13px', marginTop: '4px' }}>{error}</div>
        </div>
      )}

      {timelineValidation && (
        <div className="panel mb-4" style={{ padding: '12px 16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <span className={
              timelineValidation.state === 'PASS' ? 'badge badge-pass'
              : timelineValidation.state === 'REVIEW' ? 'badge badge-review'
              : timelineValidation.state === 'FAIL' ? 'badge badge-fail'
              : 'badge badge-unknown'
            }>
              {timelineValidation.state}
            </span>
            <span style={{ fontSize: '13px' }}>{timelineValidation.reason}</span>
            {hasUnknownTimezones && (
              <span className="badge badge-review">Contains Unknown timezone events</span>
            )}
          </div>
        </div>
      )}

      {/* Target Evidence Selector Bar */}
      <div className="panel" style={{ padding: '16px', marginBottom: '20px', backgroundColor: 'var(--surface)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <HardDrive size={18} style={{ color: 'var(--accent)' }} />
            <div>
              <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 600 }}>
                Active Target Evidence
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '2px' }}>
                <strong style={{ fontSize: '14px' }}>{evidence.source_device}</strong>
                <span className="badge badge-info">{evidence.image_format}</span>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  ({capacityMb} MB)
                </span>
              </div>
            </div>
          </div>

          {evidenceList && evidenceList.length > 1 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                Switch Target:
              </label>
              <select
                className="form-select"
                style={{ width: '220px', padding: '6px 10px', fontSize: '12px' }}
                value={evidence.id}
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
        </div>
      </div>

      {/* Controls Bar */}
      <div className="panel" style={{ padding: '12px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span className="text-muted" style={{ fontSize: '13px', fontWeight: 600 }}>Timeline Ordering Mode:</span>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              className={`btn btn-sm ${ordering === 'Normalized' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setOrdering('Normalized')}
            >
              Normalized UTC (Req 15.3)
            </button>
            <button
              className={`btn btn-sm ${ordering === 'RecorderNative' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setOrdering('RecorderNative')}
            >
              Recorder-Native Time
            </button>
            <button
              className={`btn btn-sm ${ordering === 'Physical' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setOrdering('Physical')}
            >
              Physical Disk Offset
            </button>
          </div>
        </div>

        <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          Showing <strong>{sortedEvents.length}</strong> temporal events across active channels
        </div>
      </div>

      {/* Main Grid: Timeline Flow & Provenance Inspector */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: '20px' }}>
        
        {/* Left: Event List */}
        <div className="panel" style={{ padding: '0', overflow: 'hidden' }}>
          <div className="panel-header" style={{ margin: 0, padding: '16px' }}>
            <h3 style={{ margin: 0, fontSize: '14px' }}>Chronological Event Stream</h3>
          </div>
          <div className="table-container" style={{ border: 'none', borderTop: '1px solid var(--border)', borderRadius: '0' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Channel</th>
                  <th>Description</th>
                  <th>Timestamp (Ordered)</th>
                  <th>Physical Sector</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {sortedEvents.map(evt => {
                  const isSelected = selectedEvent?.id === evt.id;
                  return (
                    <tr
                      key={evt.id}
                      onClick={() => setSelectedEvent(evt)}
                      style={{
                        cursor: 'pointer',
                        backgroundColor: isSelected ? 'rgba(59, 130, 246, 0.08)' : undefined,
                        borderLeft: isSelected ? '3px solid var(--accent)' : '3px solid transparent',
                      }}
                    >
                      <td>
                        <span className="badge badge-info">CH {evt.channel}</span>
                      </td>
                      <td>
                        <div style={{ fontWeight: 600, fontSize: '13px' }}>{evt.description}</div>
                        <div className="text-muted" style={{ fontSize: '11px', marginTop: '2px' }}>
                          Native: <span className="mono">{evt.native_time}</span>
                        </div>
                      </td>
                      <td>
                        {ordering === 'Normalized' ? (
                          <div>
                            <div className="mono" style={{ fontWeight: 600 }}>{evt.normalized_time}</div>
                            {evt.timezone_state === 'Unknown' && (
                              <span style={{ color: 'var(--warning)', fontSize: '11px' }}>⚠ Unknown TZ (Not Shifted)</span>
                            )}
                          </div>
                        ) : ordering === 'RecorderNative' ? (
                          <div className="mono" style={{ fontWeight: 600 }}>{evt.native_time}</div>
                        ) : (
                          <div className="mono" style={{ fontWeight: 600 }}>0x{evt.source_offset.toString(16).toUpperCase()}</div>
                        )}
                      </td>
                      <td>
                        <span className="mono" style={{ fontSize: '12px' }}>0x{evt.source_offset.toString(16).toUpperCase()}</span>
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
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: Provenance Inspector Panel (Req 4) */}
        <div>
          {selectedEvent ? (
            <div className="panel">
              <div className="panel-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <ShieldCheck size={18} style={{ color: 'var(--accent)' }} />
                  <h3 style={{ margin: 0, fontSize: '14px' }}>Event Provenance & Lineage</h3>
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div>
                  <div className="text-muted" style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Event ID & Channel</div>
                  <div style={{ fontWeight: 600, fontSize: '13px', marginTop: '2px' }}>
                    {selectedEvent.id} (Channel {selectedEvent.channel})
                  </div>
                </div>

                <div>
                  <div className="text-muted" style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Raw Binary Timestamp (Preserved)</div>
                  <div className="mono" style={{ fontSize: '12px', background: 'var(--surface-muted)', padding: '6px 8px', borderRadius: '4px', marginTop: '2px' }}>
                    0x{selectedEvent.raw_timestamp.toString(16).toUpperCase()} ({selectedEvent.raw_format})
                  </div>
                </div>

                <div>
                  <div className="text-muted" style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Physical Disk Extent</div>
                  <div className="mono" style={{ fontSize: '12px', marginTop: '2px' }}>
                    Offset: 0x{selectedEvent.source_offset.toString(16).toUpperCase()} ({selectedEvent.source_length} bytes)
                  </div>
                </div>

                <div>
                  <div className="text-muted" style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Producing Engine Component</div>
                  <div style={{ fontSize: '12px', marginTop: '2px' }}>
                    <strong>{selectedEvent.provenance.producing_component}</strong> (v{selectedEvent.provenance.component_version})
                  </div>
                </div>

                <div>
                  <div className="text-muted" style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Oem Profile Hash (Req 4.3)</div>
                  <div className="mono" style={{ fontSize: '10.5px', wordBreak: 'break-all', marginTop: '2px' }}>
                    {selectedEvent.provenance.profile_hash}
                  </div>
                </div>

                <div>
                  <div className="text-muted" style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Output Signature Hash</div>
                  <div className="mono" style={{ fontSize: '10.5px', wordBreak: 'break-all', marginTop: '2px' }}>
                    {selectedEvent.provenance.output_hash ?? 'Not computed for timeline events'}
                  </div>
                </div>

                <div>
                  <div className="text-muted" style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Transformation Chain</div>
                  <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginTop: '4px' }}>
                    {selectedEvent.provenance.transformations.map((t, idx) => (
                      <span key={idx} className="badge badge-info" style={{ fontSize: '10.5px' }}>
                        {t}
                      </span>
                    ))}
                  </div>
                </div>

                <div style={{ paddingTop: '8px', borderTop: '1px solid var(--border)' }}>
                  <button
                    className="btn btn-primary"
                    style={{ width: '100%', justifyContent: 'center' }}
                    onClick={() => onNavigateToHex(selectedEvent.source_offset)}
                  >
                    Inspect Physical Sector in Hex Viewer
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="panel" style={{ textAlign: 'center', padding: '32px' }}>
              <Layers size={28} className="text-muted" />
              <p className="text-muted" style={{ fontSize: '13px', marginTop: '8px' }}>
                Select an event from the timeline stream to view its cryptographic provenance and raw binary lineage.
              </p>
            </div>
          )}
        </div>

      </div>
    </div>
  );
};
