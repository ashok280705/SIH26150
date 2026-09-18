import React, { useState } from 'react';
import { Compass, X, Shield, ArrowRight } from 'lucide-react';

interface WelcomeModalProps {
  isOpen: boolean;
  onStartTour: () => void;
  onSkipTour: (dontShowAgain: boolean) => void;
}

export const WelcomeModal: React.FC<WelcomeModalProps> = ({
  isOpen,
  onStartTour,
  onSkipTour,
}) => {
  const [dontShowAgain, setDontShowAgain] = useState(false);

  if (!isOpen) return null;

  return (
    <div 
      className="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="welcome-modal-title"
    >
      <div className="welcome-modal-card">
        <button
          type="button"
          className="modal-close-btn"
          onClick={() => onSkipTour(dontShowAgain)}
          aria-label="Close welcome dialog"
        >
          <X size={18} />
        </button>

        <div className="welcome-modal-header">
          <div className="welcome-icon-badge">
            <Compass size={24} color="var(--accent)" />
          </div>
          <div>
            <h2 id="welcome-modal-title" className="welcome-title">
              Welcome to the DVR/NVR Forensic Workbench
            </h2>
            <p className="welcome-subtitle">
              Let's take a quick tour of the forensic workflow.
            </p>
          </div>
        </div>

        <div className="welcome-body">
          <p className="welcome-text">
            This workspace helps investigators acquire, identify, parse, recover, analyze, and document evidence from DVR/NVR storage media while preserving forensic traceability.
          </p>

          <div className="welcome-highlights">
            <div className="welcome-highlight-item">
              <Shield size={14} className="welcome-highlight-icon" />
              <span><strong>Strict Read-Only:</strong> Non-destructive analysis; evidence is never modified.</span>
            </div>
            <div className="welcome-highlight-item">
              <Shield size={14} className="welcome-highlight-icon" />
              <span><strong>Audit Traceability:</strong> Every action and verification outcome is immutably logged.</span>
            </div>
          </div>

          <div className="welcome-checkbox-row">
            <label className="welcome-checkbox-label">
              <input
                type="checkbox"
                checked={dontShowAgain}
                onChange={(e) => setDontShowAgain(e.target.checked)}
                className="welcome-checkbox"
              />
              <span>Don't show this welcome message again</span>
            </label>
          </div>
        </div>

        <div className="welcome-actions">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => onSkipTour(dontShowAgain)}
          >
            Skip for Now
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={onStartTour}
            autoFocus
          >
            <Compass size={15} />
            <span>Start Guided Tour</span>
            <ArrowRight size={14} />
          </button>
        </div>
      </div>
    </div>
  );
};
