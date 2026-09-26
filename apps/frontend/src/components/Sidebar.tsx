import React from 'react';
import {
  LayoutDashboard,
  FolderPlus,
  HardDriveDownload,
  FileCheck2,
  ScanSearch,
  FileCode2,
  Video,
  Clock,
  FileSpreadsheet,
  Binary,
  ScrollText,
  ListTree,
  MonitorPlay,
  Lock,
} from 'lucide-react';
import type { StageAccess } from '../workflow';

export type ActiveTab =
  | 'overview'
  | 'cases'
  | 'evidence'
  | 'acquisition'
  | 'hex_viewer'
  | 'detection'
  | 'parsing'
  | 'preliminary_timeline'
  | 'recovery'
  | 'timeline'
  | 'video'
  | 'custody'
  | 'reports';

interface SidebarProps {
  activeTab: ActiveTab;
  onSelectTab: (tab: ActiveTab) => void;
  onOpenHelp?: () => void;
  /** Per-tab lock state; locked analysis stages are disabled with a reason. */
  access?: Partial<Record<ActiveTab, StageAccess>>;
}

interface NavDef {
  tab: ActiveTab;
  label: string;
  icon: React.ReactNode;
  badge?: string;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, onSelectTab, onOpenHelp, access = {} }) => {
  const core: NavDef[] = [
    { tab: 'overview', label: 'Overview', icon: <LayoutDashboard size={16} /> },
    { tab: 'cases', label: 'Cases', icon: <FolderPlus size={16} /> },
    { tab: 'evidence', label: 'Evidence', icon: <HardDriveDownload size={16} /> },
    { tab: 'acquisition', label: 'Acquisition', icon: <FileCheck2 size={16} /> },
    { tab: 'hex_viewer', label: 'Byte Inspector', icon: <Binary size={16} />, badge: 'P1' },
    { tab: 'custody', label: 'Chain of Custody', icon: <ScrollText size={16} /> },
  ];

  // Ordered to match the investigation flow.
  const pipeline: NavDef[] = [
    { tab: 'detection', label: 'Detection & Confidence', icon: <ScanSearch size={16} />, badge: 'P2' },
    { tab: 'parsing', label: 'Parsing & Extraction', icon: <FileCode2 size={16} />, badge: 'P3' },
    { tab: 'preliminary_timeline', label: 'Preliminary Timeline', icon: <ListTree size={16} /> },
    { tab: 'recovery', label: 'Recovery Engine', icon: <Video size={16} />, badge: 'P4' },
    { tab: 'timeline', label: 'Final Timeline', icon: <Clock size={16} />, badge: 'P5' },
    { tab: 'video', label: 'Video Player', icon: <MonitorPlay size={16} /> },
    { tab: 'reports', label: 'Forensic Reports', icon: <FileSpreadsheet size={16} />, badge: 'P6' },
  ];

  const renderItem = (def: NavDef) => {
    const acc = access[def.tab];
    const locked = acc?.locked ?? false;
    return (
      <li key={def.tab}>
        <div
          className={`nav-item ${activeTab === def.tab ? 'active' : ''} ${locked ? 'nav-item-locked' : ''}`}
          onClick={() => {
            if (!locked) onSelectTab(def.tab);
          }}
          data-tour={`nav-${def.tab}`}
          title={locked ? acc?.reason : undefined}
          style={locked ? { opacity: 0.5, cursor: 'not-allowed' } : undefined}
          aria-disabled={locked}
        >
          {def.icon}
          <span>{def.label}</span>
          {locked ? (
            <Lock size={12} style={{ marginLeft: 'auto', color: 'var(--text-muted)' }} />
          ) : (
            def.badge && <span className="nav-badge">{def.badge}</span>
          )}
        </div>
      </li>
    );
  };

  return (
    <aside className="sidebar">
      <div className="nav-section-title">Core &amp; Ingest</div>
      <ul className="nav-list">{core.map(renderItem)}</ul>

      <div className="nav-section-title">Analysis Pipeline</div>
      <ul className="nav-list">{pipeline.map(renderItem)}</ul>

      {onOpenHelp && (
        <div style={{ marginTop: 'auto', padding: '12px 8px', borderTop: '1px solid var(--border-subtle)' }}>
          <div className="nav-item" onClick={onOpenHelp} data-tour="nav-help" style={{ color: 'var(--accent)' }}>
            <ScrollText size={16} />
            <span>Help &amp; Guide</span>
            <span className="nav-badge" style={{ backgroundColor: 'var(--accent-light)', color: 'var(--accent)' }}>?</span>
          </div>
        </div>
      )}
    </aside>
  );
};
