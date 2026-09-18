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
import { WelcomeModal } from './components/onboarding/WelcomeModal';
import { TourOverlay } from './components/onboarding/TourOverlay';
import { HelpModal } from './components/onboarding/HelpModal';
import { Case, Evidence, Acquisition, SourceSafetyReport } from './types';
import { OnboardingState, TourContext } from './types/onboarding';
import { getSourceSafety, getCase, listCaseEvidence } from './services/api';
import { loadStorage, saveStorage, removeStorage } from './utils/storage';
import { 
  getOnboardingState, 
  setOnboardingState, 
  getOnboardingStep, 
  setOnboardingStep, 
  resetOnboarding, 
  TOUR_STEPS 
} from './utils/onboarding';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>(() => loadStorage('forensic_active_tab', 'overview'));
  const [activeCase, setActiveCase] = useState<Case | null>(() => loadStorage('forensic_active_case', null));
  const [activeEvidence, setActiveEvidence] = useState<Evidence | null>(() => loadStorage('forensic_active_evidence', null));
  const [caseEvidenceList, setCaseEvidenceList] = useState<Evidence[]>([]);
  const [acquisition, setAcquisition] = useState<Acquisition | null>(() => loadStorage('forensic_acquisition', null));
  const [safetyReport, setSafetyReport] = useState<SourceSafetyReport | null>(() => loadStorage('forensic_safety_report', null));
  const [ingestHash, setIngestHash] = useState<string | null>(() => loadStorage('forensic_ingest_hash', null));
  const [hexOffset, setHexOffset] = useState<number | undefined>(() => loadStorage('forensic_hex_offset', undefined));

  // Onboarding state management
  const [onboardingState, setOnboardingStateLocal] = useState<OnboardingState>(() => getOnboardingState());
  const [onboardingStepIndex, setOnboardingStepIndexLocal] = useState<number>(() => getOnboardingStep());
  const [isHelpOpen, setIsHelpOpen] = useState(false);

  const handleUnloadCase = () => {
    setActiveCase(null);
    setActiveEvidence(null);
    setCaseEvidenceList([]);
    setAcquisition(null);
    setSafetyReport(null);
    setIngestHash(null);
    setHexOffset(undefined);
    removeStorage('forensic_active_case');
    removeStorage('forensic_active_evidence');
    removeStorage('forensic_acquisition');
    removeStorage('forensic_safety_report');
    removeStorage('forensic_ingest_hash');
    removeStorage('forensic_hex_offset');
    setActiveTab('cases');
  };

  useEffect(() => {
    if (activeCase?.id) {
      getCase(activeCase.id).catch(() => {
        handleUnloadCase();
      });

      listCaseEvidence(activeCase.id)
        .then((list) => {
          setCaseEvidenceList(list);
          if (list.length > 0 && (!activeEvidence || !list.some((e) => e.id === activeEvidence.id))) {
            setActiveEvidence(list[0]);
          }
        })
        .catch(() => setCaseEvidenceList([]));
    } else {
      setCaseEvidenceList([]);
    }
  }, [activeCase?.id]);

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

  // Global keyboard shortcuts
  useEffect(() => {
    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      const activeTag = (document.activeElement?.tagName || '').toLowerCase();
      if (activeTag === 'input' || activeTag === 'textarea' || activeTag === 'select') {
        return;
      }

      if (e.key === '?' && !e.ctrlKey && !e.metaKey) {
        e.preventDefault();
        setIsHelpOpen((prev) => !prev);
      }
    };

    window.addEventListener('keydown', handleGlobalKeyDown);
    return () => window.removeEventListener('keydown', handleGlobalKeyDown);
  }, []);

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
    setCaseEvidenceList((prev) => [...prev.filter((e) => e.id !== data.evidence.id), data.evidence]);
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
  };

  const handleNavigateToHex = (offset: number) => {
    setHexOffset(offset);
    setActiveTab('hex_viewer');
  };

  // Onboarding handlers
  const handleStartTour = () => {
    setOnboardingState('onboarding_in_progress');
    setOnboardingStep(0);
    setOnboardingStateLocal('onboarding_in_progress');
    setOnboardingStepIndexLocal(0);
    setActiveTab(TOUR_STEPS[0].tab);
  };

  const handleSkipTour = (dontShowAgain: boolean) => {
    const nextState = dontShowAgain ? 'onboarding_dismissed' : 'onboarding_dismissed';
    setOnboardingState(nextState);
    setOnboardingStateLocal(nextState);
  };

  const handleNextTourStep = () => {
    const nextIndex = onboardingStepIndex + 1;
    if (nextIndex < TOUR_STEPS.length) {
      setOnboardingStep(nextIndex);
      setOnboardingStepIndexLocal(nextIndex);
      setActiveTab(TOUR_STEPS[nextIndex].tab);
    } else {
      handleFinishTour();
    }
  };

  const handlePrevTourStep = () => {
    const prevIndex = onboardingStepIndex - 1;
    if (prevIndex >= 0) {
      setOnboardingStep(prevIndex);
      setOnboardingStepIndexLocal(prevIndex);
      setActiveTab(TOUR_STEPS[prevIndex].tab);
    }
  };

  const handleFinishTour = () => {
    setOnboardingState('onboarding_completed');
    setOnboardingStateLocal('onboarding_completed');
  };

  const handleRestartTour = () => {
    resetOnboarding();
    setOnboardingStateLocal('onboarding_in_progress');
    setOnboardingStepIndexLocal(0);
    setActiveTab(TOUR_STEPS[0].tab);
    setIsHelpOpen(false);
  };

  const tourContext: TourContext = {
    activeCase,
    activeEvidence,
    evidenceList: caseEvidenceList,
  };

  const currentTourStep = TOUR_STEPS[onboardingStepIndex] || TOUR_STEPS[0];

  return (
    <div className="app-container">
      <Sidebar 
        activeTab={activeTab} 
        onSelectTab={setActiveTab}
        onOpenHelp={() => setIsHelpOpen(true)}
      />
      
      <div className="main-content">
        <Header 
          activeCase={activeCase} 
          activeEvidence={activeEvidence} 
          evidenceList={caseEvidenceList}
          onSelectEvidence={handleEvidenceSelected}
          onUnloadCase={handleUnloadCase}
          onOpenHelp={() => setIsHelpOpen(true)}
        />

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
          <CaseView activeCase={activeCase} onCaseSelected={handleCaseSelected} onCaseUnloaded={handleUnloadCase} />
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
          <div className="view-container" data-tour="hex-viewer-panel">
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
          <DetectionView 
            evidence={activeEvidence} 
            evidenceList={caseEvidenceList}
            onSelectEvidence={handleEvidenceSelected}
          />
        )}

        {activeTab === 'parsing' && (
          <ParsingView 
            evidence={activeEvidence} 
            evidenceList={caseEvidenceList}
            onSelectEvidence={handleEvidenceSelected}
            onNavigateToHex={handleNavigateToHex} 
          />
        )}

        {activeTab === 'recovery' && (
          <RecoveryView 
            evidence={activeEvidence} 
            evidenceList={caseEvidenceList}
            onSelectEvidence={handleEvidenceSelected}
            onNavigateToHex={handleNavigateToHex} 
          />
        )}

        {activeTab === 'timeline' && (
          <TimelineView 
            evidence={activeEvidence} 
            evidenceList={caseEvidenceList}
            onSelectEvidence={handleEvidenceSelected}
            onNavigateToHex={handleNavigateToHex} 
          />
        )}

        {activeTab === 'reports' && (
          <ReportsView 
            evidence={activeEvidence} 
            evidenceList={caseEvidenceList}
            onSelectEvidence={handleEvidenceSelected}
          />
        )}
      </div>

      {/* First-Time User Welcome Modal */}
      <WelcomeModal
        isOpen={onboardingState === 'onboarding_not_started'}
        onStartTour={handleStartTour}
        onSkipTour={handleSkipTour}
      />

      {/* Guided Tour Interactive Spotlight Overlay */}
      {onboardingState === 'onboarding_in_progress' && (
        <TourOverlay
          step={currentTourStep}
          context={tourContext}
          onNext={handleNextTourStep}
          onPrev={handlePrevTourStep}
          onSkip={() => handleSkipTour(true)}
          onFinish={handleFinishTour}
        />
      )}

      {/* Persistent Help & Guide Center */}
      <HelpModal
        isOpen={isHelpOpen}
        onClose={() => setIsHelpOpen(false)}
        onRestartTour={handleRestartTour}
        onNavigateTab={(tab) => {
          setActiveTab(tab);
          setIsHelpOpen(false);
        }}
      />
    </div>
  );
};
