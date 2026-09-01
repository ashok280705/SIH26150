import React from 'react';
import { ScanSearch, FileCode2, Video, Clock, FileSpreadsheet } from 'lucide-react';


interface PhasePlaceholderProps {
  phaseNumber: number;
  title: string;
  description: string;
  features: string[];
}

export const PhasePlaceholderView: React.FC<PhasePlaceholderProps> = ({
  phaseNumber,
  title,
  description,
  features,
}) => {
  const getIcon = () => {
    switch (phaseNumber) {
      case 2: return <ScanSearch size={32} color="var(--accent-primary)" />;
      case 3: return <FileCode2 size={32} color="var(--accent-primary)" />;
      case 4: return <Video size={32} color="var(--accent-primary)" />;
      case 5: return <Clock size={32} color="var(--accent-primary)" />;
      default: return <FileSpreadsheet size={32} color="var(--accent-primary)" />;
    }
  };

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h1 className="view-title">Phase {phaseNumber}: {title}</h1>
          <p className="view-subtitle">{description}</p>
        </div>
        <span className="badge badge-review">Phase {phaseNumber} Pipeline</span>
      </div>

      <div className="panel" style={{ padding: '36px 28px' }}>
        <div style={{ display: 'flex', gap: '20px', alignItems: 'flex-start' }}>
          <div style={{ background: 'var(--bg-tertiary)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            {getIcon()}
          </div>
          <div>
            <h2 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '6px' }}>{title} Implementation Ready</h2>
            <p style={{ color: 'var(--text-secondary)', marginBottom: '18px', maxWidth: '650px' }}>
              Phase 1 Core domain types, checked arithmetic, read-only reader, and streaming hash infrastructure are fully active.
            </p>

            <h3 style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '10px' }}>
              Upcoming Capabilities for Phase {phaseNumber}:
            </h3>
            <ul style={{ listStyle: 'disc', paddingLeft: '20px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {features.map((f, idx) => (
                <li key={idx}><strong>{f}</strong></li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
