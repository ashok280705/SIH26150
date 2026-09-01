import React from 'react';
import { ShieldCheck, HardDrive, Terminal } from 'lucide-react';

import { Case, Evidence } from '../types';

interface HeaderProps {
  activeCase: Case | null;
  activeEvidence: Evidence | null;
}

export const Header: React.FC<HeaderProps> = ({ activeCase, activeEvidence }) => {
  return (
    <header className="top-header">
      <div className="logo-section">
        <span className="logo-badge">SIH-2026</span>
        <span className="app-title">Multi-Vendor DVR/NVR Forensic Platform</span>
      </div>

      <div className="header-status">
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}>
          <ShieldCheck size={15} color="#166534" />
          <span style={{ color: '#166534', fontWeight: 600 }}>Source Safety: Active</span>
        </div>

        {activeCase && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--text-secondary)' }}>
            <Terminal size={14} />
            <span>Case: <strong>{activeCase.name}</strong></span>
          </div>
        )}

        {activeEvidence && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--text-secondary)' }}>
            <HardDrive size={14} />
            <span>Target: <strong>{activeEvidence.source_device}</strong></span>
          </div>
        )}
      </div>
    </header>
  );
};
