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
  ScrollText
} from 'lucide-react';

export type ActiveTab =
  | 'overview'
  | 'cases'
  | 'evidence'
  | 'acquisition'
  | 'hex_viewer'
  | 'detection'
  | 'parsing'
  | 'recovery'
  | 'timeline'
  | 'custody'
  | 'reports';

interface SidebarProps {
  activeTab: ActiveTab;
  onSelectTab: (tab: ActiveTab) => void;
  onOpenHelp?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, onSelectTab, onOpenHelp }) => {
  return (
    <aside className="sidebar">
      <div className="nav-section-title">Core & Ingest</div>
      <ul className="nav-list">
        <li>
          <div
            className={`nav-item ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => onSelectTab('overview')}
            data-tour="nav-overview"
          >
            <LayoutDashboard size={16} />
            <span>Overview</span>
          </div>
        </li>
        <li>
          <div
            className={`nav-item ${activeTab === 'cases' ? 'active' : ''}`}
            onClick={() => onSelectTab('cases')}
            data-tour="nav-cases"
          >
            <FolderPlus size={16} />
            <span>Cases</span>
          </div>
        </li>
        <li>
          <div
            className={`nav-item ${activeTab === 'evidence' ? 'active' : ''}`}
            onClick={() => onSelectTab('evidence')}
            data-tour="nav-evidence"
          >
            <HardDriveDownload size={16} />
            <span>Evidence</span>
          </div>
        </li>
        <li>
          <div
            className={`nav-item ${activeTab === 'acquisition' ? 'active' : ''}`}
            onClick={() => onSelectTab('acquisition')}
            data-tour="nav-acquisition"
          >
            <FileCheck2 size={16} />
            <span>Acquisition</span>
          </div>
        </li>
        <li>
          <div
            className={`nav-item ${activeTab === 'hex_viewer' ? 'active' : ''}`}
            onClick={() => onSelectTab('hex_viewer')}
            data-tour="nav-hex_viewer"
          >
            <Binary size={16} />
            <span>Byte Inspector</span>
            <span className="nav-badge">P1</span>
          </div>
        </li>
        <li>
          <div
            className={`nav-item ${activeTab === 'custody' ? 'active' : ''}`}
            onClick={() => onSelectTab('custody')}
            data-tour="nav-custody"
          >
            <ScrollText size={16} />
            <span>Chain of Custody</span>
          </div>
        </li>
      </ul>

      <div className="nav-section-title">Analysis Pipeline</div>
      <ul className="nav-list">
        <li>
          <div
            className={`nav-item ${activeTab === 'detection' ? 'active' : ''}`}
            onClick={() => onSelectTab('detection')}
            data-tour="nav-detection"
          >
            <ScanSearch size={16} />
            <span>Detection</span>
            <span className="nav-badge">P2</span>
          </div>
        </li>
        <li>
          <div
            className={`nav-item ${activeTab === 'parsing' ? 'active' : ''}`}
            onClick={() => onSelectTab('parsing')}
            data-tour="nav-parsing"
          >
            <FileCode2 size={16} />
            <span>Parsing</span>
            <span className="nav-badge">P3</span>
          </div>
        </li>
        <li>
          <div
            className={`nav-item ${activeTab === 'recovery' ? 'active' : ''}`}
            onClick={() => onSelectTab('recovery')}
            data-tour="nav-recovery"
          >
            <Video size={16} />
            <span>Recovery & Video</span>
            <span className="nav-badge">P4</span>
          </div>
        </li>
        <li>
          <div
            className={`nav-item ${activeTab === 'timeline' ? 'active' : ''}`}
            onClick={() => onSelectTab('timeline')}
            data-tour="nav-timeline"
          >
            <Clock size={16} />
            <span>Timeline</span>
            <span className="nav-badge">P5</span>
          </div>
        </li>
        <li>
          <div
            className={`nav-item ${activeTab === 'reports' ? 'active' : ''}`}
            onClick={() => onSelectTab('reports')}
            data-tour="nav-reports"
          >
            <FileSpreadsheet size={16} />
            <span>Forensic Reports</span>
            <span className="nav-badge">P6</span>
          </div>
        </li>
      </ul>

      {onOpenHelp && (
        <div style={{ marginTop: 'auto', padding: '12px 8px', borderTop: '1px solid var(--border-subtle)' }}>
          <div
            className="nav-item"
            onClick={onOpenHelp}
            data-tour="nav-help"
            style={{ color: 'var(--accent)' }}
          >
            <ScrollText size={16} />
            <span>Help & Guide</span>
            <span className="nav-badge" style={{ backgroundColor: 'var(--accent-light)', color: 'var(--accent)' }}>?</span>
          </div>
        </div>
      )}
    </aside>
  );
};
