import React, { useState } from 'react';
import { 
  X, 
  HelpCircle, 
  RotateCcw, 
  GitCommit, 
  Keyboard, 
  ShieldCheck, 
  ArrowRight, 
  CheckCircle2,
  FolderPlus,
  HardDriveDownload,
  FileCheck2,
  ScanSearch,
  Binary,
  FileCode2,
  Video,
  Clock,
  ScrollText,
  FileSpreadsheet
} from 'lucide-react';
import { WORKFLOW_STAGES } from '../../utils/onboarding';
import { ActiveTab, WorkflowStage } from '../../types/onboarding';

interface HelpModalProps {
  isOpen: boolean;
  onClose: () => void;
  onRestartTour: () => void;
  onNavigateTab: (tab: ActiveTab) => void;
}

type HelpTab = 'tour' | 'workflow' | 'shortcuts' | 'about';

export const HelpModal: React.FC<HelpModalProps> = ({
  isOpen,
  onClose,
  onRestartTour,
  onNavigateTab,
}) => {
  const [activeHelpTab, setActiveHelpTab] = useState<HelpTab>('workflow');
  const [selectedStage, setSelectedStage] = useState<WorkflowStage>(WORKFLOW_STAGES[0]);

  if (!isOpen) return null;

  const getStageIcon = (id: string) => {
    switch (id) {
      case 'cases': return <FolderPlus size={15} />;
      case 'evidence': return <HardDriveDownload size={15} />;
      case 'acquisition': return <FileCheck2 size={15} />;
      case 'detection': return <ScanSearch size={15} />;
      case 'hex_viewer': return <Binary size={15} />;
      case 'parsing': return <FileCode2 size={15} />;
      case 'recovery': return <Video size={15} />;
      case 'timeline': return <Clock size={15} />;
      case 'custody': return <ScrollText size={15} />;
      case 'reports': return <FileSpreadsheet size={15} />;
      default: return <GitCommit size={15} />;
    }
  };

  return (
    <div 
      className="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="help-modal-title"
    >
      <div className="help-modal-card">
        {/* Header */}
        <div className="help-modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div className="help-icon-badge">
              <HelpCircle size={20} color="var(--accent)" />
            </div>
            <div>
              <h2 id="help-modal-title" className="help-title">
                Help & Forensic Investigator Guide
              </h2>
              <p className="help-subtitle">
                Interactive workflow documentation, guided onboarding, and workstation references
              </p>
            </div>
          </div>
          <button
            type="button"
            className="modal-close-btn"
            onClick={onClose}
            aria-label="Close help modal"
          >
            <X size={18} />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="help-tab-bar">
          <button
            type="button"
            className={`help-tab-btn ${activeHelpTab === 'workflow' ? 'active' : ''}`}
            onClick={() => setActiveHelpTab('workflow')}
          >
            <GitCommit size={15} />
            <span>Forensic Workflow</span>
          </button>
          <button
            type="button"
            className={`help-tab-btn ${activeHelpTab === 'tour' ? 'active' : ''}`}
            onClick={() => setActiveHelpTab('tour')}
          >
            <RotateCcw size={15} />
            <span>Guided Tour</span>
          </button>
          <button
            type="button"
            className={`help-tab-btn ${activeHelpTab === 'shortcuts' ? 'active' : ''}`}
            onClick={() => setActiveHelpTab('shortcuts')}
          >
            <Keyboard size={15} />
            <span>Shortcuts</span>
          </button>
          <button
            type="button"
            className={`help-tab-btn ${activeHelpTab === 'about' ? 'active' : ''}`}
            onClick={() => setActiveHelpTab('about')}
          >
            <ShieldCheck size={15} />
            <span>Forensic Guarantees</span>
          </button>
        </div>

        {/* Tab Contents */}
        <div className="help-modal-content">
          {/* TAB 1: WORKFLOW VISUALIZER */}
          {activeHelpTab === 'workflow' && (
            <div className="workflow-view-grid">
              {/* Left Column: Visual Flow Diagram */}
              <div className="workflow-diagram-column">
                <div className="workflow-column-title">10-Stage Investigation Pipeline</div>
                <div className="workflow-nodes-container">
                  {WORKFLOW_STAGES.map((stage, index) => {
                    const isSelected = selectedStage.id === stage.id;
                    return (
                      <React.Fragment key={stage.id}>
                        <button
                          type="button"
                          className={`workflow-node-btn ${isSelected ? 'selected' : ''}`}
                          onClick={() => setSelectedStage(stage)}
                        >
                          <div className="workflow-node-badge">
                            {index + 1}
                          </div>
                          <div className="workflow-node-icon">
                            {getStageIcon(stage.id)}
                          </div>
                          <div className="workflow-node-text">
                            <span className="workflow-node-label">{stage.label}</span>
                            <span className="workflow-node-status">
                              <CheckCircle2 size={10} color="var(--success)" />
                              <span>Implemented</span>
                            </span>
                          </div>
                        </button>
                        {index < WORKFLOW_STAGES.length - 1 && (
                          <div className="workflow-node-arrow" aria-hidden="true">
                            ↓
                          </div>
                        )}
                      </React.Fragment>
                    );
                  })}
                </div>
              </div>

              {/* Right Column: Selected Stage Details */}
              <div className="workflow-detail-column">
                <div className="workflow-detail-header">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {getStageIcon(selectedStage.id)}
                    <h3 className="workflow-detail-title">{selectedStage.label}</h3>
                  </div>
                  <span className="badge badge-pass">Implemented</span>
                </div>

                <div className="workflow-detail-section">
                  <div className="workflow-section-label">What happens here?</div>
                  <p className="workflow-section-text">{selectedStage.whatHappens}</p>
                </div>

                <div className="workflow-detail-section">
                  <div className="workflow-section-label">Why does this stage matter?</div>
                  <p className="workflow-section-text">{selectedStage.whyItMatters}</p>
                </div>

                <div className="workflow-detail-section">
                  <div className="workflow-section-label">Key Technical Properties</div>
                  <ul className="workflow-properties-list">
                    {selectedStage.details.map((item, idx) => (
                      <li key={idx}>
                        <CheckCircle2 size={13} color="var(--success)" style={{ flexShrink: 0, marginTop: '2px' }} />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="workflow-detail-actions">
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => {
                      onClose();
                      onNavigateTab(selectedStage.tab);
                    }}
                  >
                    <span>Go to {selectedStage.label}</span>
                    <ArrowRight size={14} />
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: GUIDED TOUR */}
          {activeHelpTab === 'tour' && (
            <div className="help-tour-tab">
              <div className="panel" style={{ padding: '24px', backgroundColor: 'var(--surface)' }}>
                <h3 style={{ fontSize: '16px', fontWeight: 600, marginBottom: '8px', color: 'var(--text-primary)' }}>
                  Interactive First-Time Investigator Tour
                </h3>
                <p style={{ color: 'var(--text-secondary)', marginBottom: '16px', lineHeight: '1.6' }}>
                  The guided tour walks investigators through all 10 stages of the DVR/NVR analysis workflow directly on the live interface. It explains case establishment, multi-device attachment, read-only acquisition checks, OEM detection, byte inspection, proprietary parsing, timeline alignment, and forensic documentation.
                </p>

                <div className="help-tour-features">
                  <div className="help-feature-card">
                    <strong>100% Observational:</strong> The tour will never create test cases, alter evidence, or trigger heavy backend processing.
                  </div>
                  <div className="help-feature-card">
                    <strong>Context Aware:</strong> Dynamically detects if an investigation or evidence item is already loaded.
                  </div>
                  <div className="help-feature-card">
                    <strong>Interactive Spotlight:</strong> Automatically scrolls to and highlights actual working workstation controls.
                  </div>
                </div>

                <div style={{ marginTop: '20px' }}>
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => {
                      onClose();
                      onRestartTour();
                    }}
                    style={{ padding: '10px 18px', fontSize: '13px' }}
                  >
                    <RotateCcw size={15} />
                    <span>Restart Guided Tour</span>
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: KEYBOARD SHORTCUTS */}
          {activeHelpTab === 'shortcuts' && (
            <div className="help-shortcuts-tab">
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{ width: '180px' }}>Key / Shortcut</th>
                    <th>Action</th>
                    <th>Context</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td><kbd className="help-kbd">?</kbd></td>
                    <td>Open / Close this Help & Guide dialog</td>
                    <td>Global (outside text inputs)</td>
                  </tr>
                  <tr>
                    <td><kbd className="help-kbd">Esc</kbd></td>
                    <td>Close modal / Dismiss Guided Tour</td>
                    <td>Any dialog or active tour</td>
                  </tr>
                  <tr>
                    <td><kbd className="help-kbd">Enter</kbd> or <kbd className="help-kbd">→</kbd></td>
                    <td>Advance to next step in guided tour</td>
                    <td>Active guided tour</td>
                  </tr>
                  <tr>
                    <td><kbd className="help-kbd">←</kbd></td>
                    <td>Go back to previous step in guided tour</td>
                    <td>Active guided tour</td>
                  </tr>
                  <tr>
                    <td><kbd className="help-kbd">Tab</kbd> / <kbd className="help-kbd">Shift + Tab</kbd></td>
                    <td>Accessible focus navigation across controls</td>
                    <td>Workstation interface</td>
                  </tr>
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 4: FORENSIC GUARANTEES */}
          {activeHelpTab === 'about' && (
            <div className="help-about-tab">
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div className="help-guarantee-card">
                  <div className="help-guarantee-header">
                    <ShieldCheck size={18} color="var(--success)" />
                    <strong>Read-Only Source Guarantee</strong>
                  </div>
                  <p>
                    All evidence operations, byte inspections, and parser runs execute strictly in read-only mode through the backend EvidenceReader. Write operations to evidence sources are blocked and audited.
                  </p>
                </div>

                <div className="help-guarantee-card">
                  <div className="help-guarantee-header">
                    <ShieldCheck size={18} color="var(--success)" />
                    <strong>Cryptographic Ingest Hashing</strong>
                  </div>
                  <p>
                    Evidence files are cryptographically hashed using SHA-256 immediately upon ingest. All exported documentation preserves lineage hashes to verify that the examined media has remained pristine.
                  </p>
                </div>

                <div className="help-guarantee-card">
                  <div className="help-guarantee-header">
                    <ShieldCheck size={18} color="var(--success)" />
                    <strong>Append-Only Chain of Custody</strong>
                  </div>
                  <p>
                    Examiner actions, ingest events, validation checks, and write denials are recorded to an append-only database audit log. Records cannot be deleted or retroactively altered.
                  </p>
                </div>

                <div className="help-guarantee-card">
                  <div className="help-guarantee-header">
                    <ShieldCheck size={18} color="var(--success)" />
                    <strong>Deterministic Candidate Attribution</strong>
                  </div>
                  <p>
                    OEM detection evaluates storage geometry and superblock magic rules deterministically. Attribution is reported with candidate confidence margins rather than assumed certainty.
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="help-modal-footer">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={onClose}
          >
            Close Guide
          </button>
        </div>
      </div>
    </div>
  );
};
