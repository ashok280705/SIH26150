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
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, onSelectTab }) => {
  return (
    <aside className="sidebar">
      <div className="nav-section-title">Core & Ingest</div>
      <ul className="nav-list">
        <li>
          <div
            className={`nav-item ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => onSelectTab('overview')}
          >
            <LayoutDashboard size={16} />
            <span>Overview</span>
          </div>
        </li>
        <li>
          <div
            className={`nav-item ${activeTab === 'cases' ? 'active' : ''}`}
            onClick={() => onSelectTab('cases')}
          >
            <FolderPlus size={16} />
            <span>Cases</span>
          </div>
        </li>
        <li>
          <div
            className={`nav-item ${activeTab === 'evidence' ? 'active' : ''}`}
            onClick={() => onSelectTab('evidence')}
          >
            <HardDriveDownload size={16} />
            <span>Evidence</span>
          </div>
        </li>
        <li>
          <div
            className={`nav-item ${activeTab === 'acquisition' ? 'active' : ''}`}
            onClick={() => onSelectTab('acquisition')}
          >
            <FileCheck2 size={16} />
            <span>Acquisition</span>
          </div>
        </li>
        <li>
          <div
            className={`nav-item ${activeTab === 'hex_viewer' ? 'active' : ''}`}
            onClick={() => onSelectTab('hex_viewer')}
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
          >
            <ScrollText size={16} />
            <span>Chain of Custody</span>
          </div>
        </li>
      </ul>

      <div className="nav-section-title" style={{ marginTop: '12px' }}>Analysis Pipeline</div>
      <ul className="nav-list">
        <li>
          <div
            className={`nav-item ${activeTab === 'detection' ? 'active' : ''}`}
            onClick={() => onSelectTab('detection')}
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
          >
            <FileSpreadsheet size={16} />
            <span>Forensic Reports</span>
            <span className="nav-badge">P6</span>
          </div>
        </li>
      </ul>
    </aside>
  );
};
