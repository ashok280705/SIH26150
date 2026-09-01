import React, { useState } from 'react';
import { Header } from './components/Header';
import { Sidebar, ActiveTab } from './components/Sidebar';
import { OverviewView } from './views/OverviewView';
import { CaseView } from './views/CaseView';
import { EvidenceView } from './views/EvidenceView';
import { AcquisitionView } from './views/AcquisitionView';
import { CustodyView } from './views/CustodyView';
import { PhasePlaceholderView } from './views/PhasePlaceholderView';
import { DetectionView } from './views/DetectionView';
import { ParsingView } from './views/ParsingView';
import { HexViewer } from './components/HexViewer';
import { Case, Evidence, Acquisition, SourceSafetyReport } from './types';
import { getSourceSafety } from './services/api';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [activeCase, setActiveCase] = useState<Case | null>(null);
  const [activeEvidence, setActiveEvidence] = useState<Evidence | null>(null);
  const [acquisition, setAcquisition] = useState<Acquisition | null>(null);
  const [safetyReport, setSafetyReport] = useState<SourceSafetyReport | null>(null);
  const [ingestHash, setIngestHash] = useState<string | null>(null);
  const [hexOffset, setHexOffset] = useState<number | undefined>(undefined);

  const handleCaseCreated = (c: Case) => {
    setActiveCase(c);
    setActiveTab('evidence');
  };

  const handleEvidenceRegistered = async (data: { evidence: Evidence; acquisition?: Acquisition; ingest_hash: string }) => {
    setActiveEvidence(data.evidence);
    setIngestHash(data.ingest_hash);
    if (data.acquisition) {
      setAcquisition(data.acquisition);
    }
    try {
      const report = await getSourceSafety(data.evidence.id);
      setSafetyReport(report);
    } catch {
      // Fallback
    }
    setActiveTab('overview');
  };

  const handleNavigateToHex = (offset: number) => {
    setHexOffset(offset);
    setActiveTab('hex_viewer');
  };

  return (
    <div className="app-container">
      <Sidebar activeTab={activeTab} onSelectTab={setActiveTab} />
      
      <div className="main-content">
        <Header activeCase={activeCase} activeEvidence={activeEvidence} />

        {activeTab === 'overview' && (
          <OverviewView
            activeCase={activeCase}
            activeEvidence={activeEvidence}
            acquisition={acquisition}
            safetyReport={safetyReport}
            ingestHash={ingestHash}
          />
        )}

        {activeTab === 'cases' && (
          <CaseView activeCase={activeCase} onCaseCreated={handleCaseCreated} />
        )}

        {activeTab === 'evidence' && (
          <EvidenceView activeCase={activeCase} onEvidenceRegistered={handleEvidenceRegistered} />
        )}

        {activeTab === 'acquisition' && (
          <AcquisitionView acquisition={acquisition} />
        )}

        {activeTab === 'hex_viewer' && (
          <div className="view-container">
            <div className="view-header">
              <div>
                <h1 className="view-title">Raw Byte & Offset Inspector</h1>
                <p className="view-subtitle">Interactive positioned byte reader streaming chunks strictly through the read-only EvidenceReader (Req 18.8)</p>
              </div>
            </div>
            <HexViewer evidenceId={activeEvidence?.id || null} initialOffset={hexOffset} />
          </div>
        )}

        {activeTab === 'custody' && (
          <CustodyView caseId={activeCase?.id || null} />
        )}

        {activeTab === 'detection' && (
          <DetectionView evidence={activeEvidence} />
        )}

        {activeTab === 'parsing' && (
          <ParsingView evidence={activeEvidence} onNavigateToHex={handleNavigateToHex} />
        )}

        {activeTab === 'recovery' && (
          <PhasePlaceholderView
            phaseNumber={4}
            title="Deep Recovery & Video Reconstruction"
            description="L1 Header Carving, L2 Index Reconstruction, and L3 Fragment Stitching with Video Reconstruction"
            features={[
              "Independent DataState & RecoveryStatus tracking",
              "Bounded Candidate Hypotheses & Search Extents",
              "H.264/H.265 Elementary Stream validation & Remuxing",
              "Native vs Derived Artifact lineage preservation",
            ]}
          />
        )}

        {activeTab === 'timeline' && (
          <PhasePlaceholderView
            phaseNumber={5}
            title="Forensic Timeline Engine"
            description="Multi-camera timestamp correlation, clock-drift calibration, and gap visualization"
            features={[
              "Deterministic TimelineEvent extraction",
              "Recorder Clock Calibration with delta adjustments",
              "Gap Analysis and non-overwritten evidence interval validation",
            ]}
          />
        )}

        {activeTab === 'reports' && (
          <PhasePlaceholderView
            phaseNumber={6}
            title="Court-Admissible Forensic Reporting"
            description="Comprehensive PDF, JSON, and CSV export with full cryptographic provenance and validation states"
            features={[
              "Complete Derivation Lineage & SHA-256 Hashes",
              "Independent Capability Maturity Matrix display",
              "Per-operation ValidationState (Pass / Review / Fail / Unknown) with mandatory explanations",
            ]}
          />
        )}
      </div>
    </div>
  );
};
