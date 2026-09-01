import React from 'react';
import { ShieldCheck, ShieldAlert, HardDrive, Terminal } from 'lucide-react';

import { Case, Evidence } from '../types';

interface HeaderProps {
  activeCase: Case | null;
  activeEvidence: Evidence | null;
}

export const Header: React.FC<HeaderProps> = ({ activeCase, activeEvidence }) => {
  const isSourceSafe = activeEvidence?.source_state === 'read_only';

  return (
    <header className="top-header">
      <div className="logo-section">
        <span className="logo-badge">SIH-2026</span>
        <span className="app-title">Multi-Vendor DVR/NVR Forensic Platform</span>
      </div>

      <div className="header-status">
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

        <div className="header-context-item">
          <Terminal size={14} />
          <span className="header-context-label">Case:</span>
          <span className="header-context-value">{activeCase ? activeCase.name : 'None'}</span>
        </div>

        <div className="header-context-item">
          <HardDrive size={14} />
          <span className="header-context-label">Evidence:</span>
          <span className="header-context-value">{activeEvidence ? activeEvidence.source_device : 'None'}</span>
        </div>
      </div>
    </header>
  );
};
