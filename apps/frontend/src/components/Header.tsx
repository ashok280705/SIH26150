import React from 'react';
import { ShieldCheck, ShieldAlert, HardDrive, Terminal, HelpCircle } from 'lucide-react';

import { Case, Evidence } from '../types';

interface HeaderProps {
  activeCase: Case | null;
  activeEvidence: Evidence | null;
  evidenceList?: Evidence[];
  onSelectEvidence?: (e: Evidence) => void;
  onUnloadCase?: () => void;
  onOpenHelp?: () => void;
}

export const Header: React.FC<HeaderProps> = ({ 
  activeCase, 
  activeEvidence, 
  evidenceList = [], 
  onSelectEvidence, 
  onUnloadCase,
  onOpenHelp
}) => {
  const isSourceSafe = activeEvidence?.source_state === 'read_only';

  return (
    <header className="top-header">
      <div className="logo-section">
        <span className="logo-badge">SIH-2026</span>
        <span className="app-title">Multi-Vendor DVR/NVR Forensic Platform</span>
      </div>

      <div className="header-status" data-tour="header-status">
        <div className="header-context-item">
          {activeEvidence ? (
            isSourceSafe ? (
              <>
                <ShieldCheck size={15} className="text-success" style={{ color: 'var(--success)' }} />
                <span className="header-context-label" style={{ color: 'var(--success)' }}>Source Safety: Active</span>
              </>
            ) : (
              <>
                <ShieldAlert size={15} className="text-danger" style={{ color: 'var(--danger)' }} />
                <span className="header-context-label" style={{ color: 'var(--danger)' }}>Source Safety: Inactive</span>
              </>
            )
          ) : (
            <>
              <ShieldCheck size={15} style={{ color: 'var(--unknown)' }} />
              <span className="header-context-label" style={{ color: 'var(--unknown)' }}>Source Safety: N/A</span>
            </>
          )}
        </div>

        <div className="header-context-item" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Terminal size={14} />
          <span className="header-context-label">Case:</span>
          <span className="header-context-value">{activeCase ? activeCase.name : 'None'}</span>
          {activeCase && onUnloadCase && (
            <button
              onClick={onUnloadCase}
              className="btn btn-secondary"
              style={{ padding: '2px 6px', fontSize: '0.75rem', height: 'auto', marginLeft: '4px' }}
              title="Unload / Close Case"
            >
              Close
            </button>
          )}
        </div>

        <div className="header-context-item" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <HardDrive size={14} />
          <span className="header-context-label">Evidence:</span>
          {evidenceList && evidenceList.length > 1 ? (
            <select
              className="form-select"
              style={{ padding: '2px 8px', fontSize: '0.75rem', height: '24px', fontWeight: 600, maxWidth: '200px' }}
              value={activeEvidence?.id || ''}
              onChange={(e) => {
                const found = evidenceList.find((item) => item.id === e.target.value);
                if (found && onSelectEvidence) onSelectEvidence(found);
              }}
            >
              {evidenceList.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.source_device}
                </option>
              ))}
            </select>
          ) : (
            <span className="header-context-value">{activeEvidence ? activeEvidence.source_device : 'None'}</span>
          )}
        </div>

        {onOpenHelp && (
          <button
            type="button"
            className="btn btn-secondary"
            onClick={onOpenHelp}
            data-tour="help-center-btn"
            style={{ display: 'flex', alignItems: 'center', gap: '5px', padding: '4px 10px', fontSize: '12px', height: '28px' }}
            title="Help & Guide (?)"
          >
            <HelpCircle size={14} color="var(--accent)" />
            <span>Help & Guide</span>
            <span style={{ fontSize: '10px', opacity: 0.7, border: '1px solid var(--border)', borderRadius: '3px', padding: '0 3px' }}>?</span>
          </button>
        )}
      </div>
    </header>
  );
};
