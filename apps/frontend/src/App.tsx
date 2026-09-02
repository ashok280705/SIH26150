import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Sidebar, ActiveTab } from './components/Sidebar';
import { OverviewView } from './views/OverviewView';
import { CaseView } from './views/CaseView';
import { EvidenceView } from './views/EvidenceView';
import { AcquisitionView } from './views/AcquisitionView';
import { CustodyView } from './views/CustodyView';
import { DetectionView } from './views/DetectionView';
import { ParsingView } from './views/ParsingView';
import { RecoveryView } from './views/RecoveryView';
import { TimelineView } from './views/TimelineView';
import { ReportsView } from './views/ReportsView';
import { HexViewer } from './components/HexViewer';
import { Case, Evidence, Acquisition, SourceSafetyReport } from './types';
import { getSourceSafety } from './services/api';
import { loadStorage, saveStorage } from './utils/storage';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>(() => loadStorage('forensic_active_tab', 'overview'));
  const [activeCase, setActiveCase] = useState<Case | null>(() => loadStorage('forensic_active_case', null));
  const [activeEvidence, setActiveEvidence] = useState<Evidence | null>(() => loadStorage('forensic_active_evidence', null));
  const [acquisition, setAcquisition] = useState<Acquisition | null>(() => loadStorage('forensic_acquisition', null));
  const [safetyReport, setSafetyReport] = useState<SourceSafetyReport | null>(() => loadStorage('forensic_safety_report', null));
  const [ingestHash, setIngestHash] = useState<string | null>(() => loadStorage('forensic_ingest_hash', null));
  const [hexOffset, setHexOffset] = useState<number | undefined>(() => loadStorage('forensic_hex_offset', undefined));

  useEffect(() => {
    saveStorage('forensic_active_tab', activeTab);
  }, [activeTab]);

  useEffect(() => {
    saveStorage('forensic_active_case', activeCase);
  }, [activeCase]);

  useEffect(() => {
    saveStorage('forensic_active_evidence', activeEvidence);
  }, [activeEvidence]);

  useEffect(() => {
    saveStorage('forensic_acquisition', acquisition);
  }, [acquisition]);

  useEffect(() => {
    saveStorage('forensic_safety_report', safetyReport);
  }, [safetyReport]);

  useEffect(() => {
    saveStorage('forensic_ingest_hash', ingestHash);
  }, [ingestHash]);

  useEffect(() => {
    saveStorage('forensic_hex_offset', hexOffset);
  }, [hexOffset]);

  const handleCaseSelected = (c: Case) => {
    setActiveCase(c);
    setActiveEvidence(null);
    setAcquisition(null);
    setSafetyReport(null);
    setIngestHash(null);
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

  const handleEvidenceSelected = async (e: Evidence) => {
    setActiveEvidence(e);
    setAcquisition(null);
    setIngestHash(null);
    try {
      const report = await getSourceSafety(e.id);
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
          <CaseView activeCase={activeCase} onCaseSelected={handleCaseSelected} />
        )}

        {activeTab === 'evidence' && (
          <EvidenceView 
            activeCase={activeCase} 
            activeEvidence={activeEvidence}
            onEvidenceRegistered={handleEvidenceRegistered} 
            onEvidenceSelected={handleEvidenceSelected}
          />
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
          <RecoveryView evidence={activeEvidence} onNavigateToHex={handleNavigateToHex} />
        )}

        {activeTab === 'timeline' && (
          <TimelineView evidence={activeEvidence} onNavigateToHex={handleNavigateToHex} />
        )}

        {activeTab === 'reports' && (
          <ReportsView evidence={activeEvidence} />
        )}
      </div>
    </div>
  );
};
