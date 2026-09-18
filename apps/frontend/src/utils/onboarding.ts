import { loadStorage, saveStorage } from './storage';
import { OnboardingState, TourStep, WorkflowStage } from '../types/onboarding';

export const ONBOARDING_STATE_KEY = 'forensic_onboarding_state';
export const ONBOARDING_STEP_KEY = 'forensic_onboarding_step';

export function getOnboardingState(): OnboardingState {
  return loadStorage<OnboardingState>(ONBOARDING_STATE_KEY, 'onboarding_not_started');
}

export function setOnboardingState(state: OnboardingState): void {
  saveStorage(ONBOARDING_STATE_KEY, state);
}

export function getOnboardingStep(): number {
  return loadStorage<number>(ONBOARDING_STEP_KEY, 0);
}

export function setOnboardingStep(step: number): void {
  saveStorage(ONBOARDING_STEP_KEY, step);
}

export function resetOnboarding(): void {
  setOnboardingState('onboarding_in_progress');
  setOnboardingStep(0);
}

export const TOUR_STEPS: TourStep[] = [
  {
    id: 'case-management',
    stepNumber: 1,
    totalSteps: 10,
    title: 'Case Management',
    tab: 'cases',
    targetSelector: '[data-tour="case-view-panel"]',
    fallbackSelector: '[data-tour="nav-cases"]',
    preferredPlacement: 'right',
    explanation: 'Cases organize the investigation. Case metadata establishes the context in which evidence, analysis findings, and examination records are documented.',
    importance: 'Every forensic examination begins by registering a case scope with a unique case identifier, assigned examiner name, and investigative notes.',
    whatNext: 'Next, we attach one or more DVR/NVR storage sources to this case.',
    getStateAwareExplanation: (ctx) => {
      if (ctx.activeCase) {
        return `Active Case Loaded: "${ctx.activeCase.name}" (Examiner: ${ctx.activeCase.examiner}). You can examine evidence under this active scope or switch cases at any time.`;
      }
      return 'No case is currently loaded. Create a new case or load an existing one from the database list on the right.';
    }
  },
  {
    id: 'evidence-device',
    stepNumber: 2,
    totalSteps: 10,
    title: 'Evidence / Device Ingest',
    tab: 'evidence',
    targetSelector: '[data-tour="evidence-view-panel"]',
    fallbackSelector: '[data-tour="nav-evidence"]',
    preferredPlacement: 'right',
    explanation: 'Evidence represents the DVR/NVR storage source being examined. An investigation can include multiple devices or storage media examined independently under the same case.',
    importance: 'Supports Raw Binary (.raw), dd Images (.dd), Disk Images (.img), and Physical Block Devices, tracking source paths and device capacities.',
    whatNext: 'Next, we verify the source safety state and compute integrity hashes.',
    getStateAwareExplanation: (ctx) => {
      if (ctx.activeEvidence) {
        return `Active Evidence: "${ctx.activeEvidence.source_device}" (${(ctx.activeEvidence.capacity / (1024 * 1024)).toFixed(0)} MB, format: ${ctx.activeEvidence.image_format}). Case currently contains ${ctx.evidenceList.length} evidence source(s).`;
      }
      return ctx.activeCase 
        ? `Register a forensic image under "${ctx.activeCase.name}" or select an existing evidence item from the list.`
        : 'Register a forensic disk image once a case is loaded.';
    }
  },
  {
    id: 'acquisition',
    stepNumber: 3,
    totalSteps: 10,
    title: 'Acquisition & Integrity',
    tab: 'acquisition',
    targetSelector: '[data-tour="acquisition-view-panel"]',
    fallbackSelector: '[data-tour="nav-acquisition"]',
    preferredPlacement: 'bottom',
    explanation: 'The original evidence is treated as strictly read-only. Acquisition verification accounts for imaging completeness, bad sector gaps, and SHA-256 cryptographic ingest hashes.',
    importance: 'Source-safety checks verify that write-blocker protection is active (read-only kernel mode). Any attempted write operation is denied and logged.',
    whatNext: 'Next, the storage structure is profiled to identify the OEM manufacturer signature.',
    getStateAwareExplanation: (ctx) => {
      if (!ctx.activeEvidence) {
        return 'Select or register an evidence item to view its acquisition verification details and bad sector accounting.';
      }
      return `Monitoring integrity for evidence "${ctx.activeEvidence.source_device}". Verified state: ${ctx.activeEvidence.source_state.replace('_', '-')}.`;
    }
  },
  {
    id: 'oem-detection',
    stepNumber: 4,
    totalSteps: 10,
    title: 'OEM & Storage Detection',
    tab: 'detection',
    targetSelector: '[data-tour="detection-view-panel"]',
    fallbackSelector: '[data-tour="nav-detection"]',
    preferredPlacement: 'bottom',
    explanation: 'Analyzes storage characteristics, geometry, superblocks, and magic signatures to identify the DVR/NVR vendor ecosystem (e.g. Dahua, Hikvision, TP-Link VIGI, CP Plus / UBS, Honeywell, Uniview).',
    importance: 'Detection outputs a confidence-scored attribution leaderboard. It is an analytical result to guide parsing and should be verified against raw bytes rather than blindly assumed.',
    whatNext: 'Next, inspect raw byte offsets directly using the built-in Byte Inspector.',
    getStateAwareExplanation: (ctx) => {
      if (!ctx.activeEvidence) {
        return 'Detection runs deterministically against selected evidence images to profile partition geometry and identify storage structures.';
      }
      return `Target evidence: "${ctx.activeEvidence.source_device}". Analysis evaluates candidate margins, profile versions, and corroborated byte offsets.`;
    }
  },
  {
    id: 'hex-viewer',
    stepNumber: 5,
    totalSteps: 10,
    title: 'Byte Inspector (Hex Viewer)',
    tab: 'hex_viewer',
    targetSelector: '[data-tour="hex-viewer-panel"]',
    fallbackSelector: '[data-tour="nav-hex_viewer"]',
    preferredPlacement: 'bottom',
    explanation: 'The Byte Inspector exposes underlying evidence bytes, hex offsets, and ASCII interpretations directly. It includes 64-bit offset positioning and forward pattern searching up to 1 GB.',
    importance: 'Strictly observational: all byte reads stream through the read-only EvidenceReader. Inspecting bytes never modifies or touches the source disk.',
    whatNext: 'Next, structured parsers interpret proprietary video indices.',
    getStateAwareExplanation: (ctx) => {
      if (!ctx.activeEvidence) {
        return 'Load an evidence item to stream chunks from any decimal or hexadecimal byte offset.';
      }
      return `Streaming read-only byte chunks for "${ctx.activeEvidence.source_device}". Use this to validate partition headers and parser findings.`;
    }
  },
  {
    id: 'parser',
    stepNumber: 6,
    totalSteps: 10,
    title: 'Proprietary Parsing',
    tab: 'parsing',
    targetSelector: '[data-tour="parsing-view-panel"]',
    fallbackSelector: '[data-tour="nav-parsing"]',
    preferredPlacement: 'bottom',
    explanation: 'After the storage format is identified, vendor-specific parsers interpret proprietary filesystem structures (e.g., DHFS, HIKVISION_FS, UBIFS) to extract recording indices and metadata.',
    importance: 'Converts low-level disk structures into structured records with channels, timestamps, and sector extents while recording validation results for each step.',
    whatNext: 'Next, examine video recovery and candidate reconstruction.',
    getStateAwareExplanation: (ctx) => {
      if (!ctx.activeEvidence) {
        return 'Parsing executes vendor-specific extraction routines against the active evidence target.';
      }
      return `Extracted recordings and parsed sector ranges for "${ctx.activeEvidence.source_device}" will appear here with direct links back to raw byte offsets.`;
    }
  },
  {
    id: 'video-recovery',
    stepNumber: 7,
    totalSteps: 10,
    title: 'Video Recovery & Extraction',
    tab: 'recovery',
    targetSelector: '[data-tour="recovery-view-panel"]',
    fallbackSelector: '[data-tour="nav-recovery"]',
    preferredPlacement: 'bottom',
    explanation: 'Reconstructs video streams from detected structures, frame sequences, and GOP headers. Distinguishes active recordings from orphaned or carved unallocated fragments.',
    importance: 'Exposes actual technical properties: channels, native timestamps, duration, data state (Active vs Orphaned), recovery levels (L1, L2), and independent validation status with technical reasons.',
    whatNext: 'Next, align multi-channel sequences chronologically on the timeline.',
    getStateAwareExplanation: (ctx) => {
      if (!ctx.activeEvidence) {
        return 'Recovery candidates display reconstructed media segments, codec verification (H.264/H.265), and validation state.';
      }
      return `Recovery status for "${ctx.activeEvidence.source_device}". Each candidate details start offset, byte length, and validation outcome.`;
    }
  },
  {
    id: 'timeline',
    stepNumber: 8,
    totalSteps: 10,
    title: 'Forensic Timeline',
    tab: 'timeline',
    targetSelector: '[data-tour="timeline-view-panel"]',
    fallbackSelector: '[data-tour="nav-timeline"]',
    preferredPlacement: 'bottom',
    explanation: 'Organizes recovered events and video recordings chronologically across all camera channels. Supports ordering by Normalized UTC, Recorder Native, or Physical byte offset.',
    importance: 'Clearly flags timezone states (known vs unadjusted raw recorder clocks) so investigators understand whether clock skew or DST offsets affect chronological correlation.',
    whatNext: 'Next, audit the immutable chain of custody and investigative findings.',
    getStateAwareExplanation: (ctx) => {
      if (!ctx.activeEvidence) {
        return 'The timeline provides multi-channel chronological alignment and provenance tracking for recovered events.';
      }
      return `Timeline view for "${ctx.activeEvidence.source_device}". Inspect producing components, profile hashes, and transformations for any event.`;
    }
  },
  {
    id: 'custody',
    stepNumber: 9,
    totalSteps: 10,
    title: 'Chain of Custody & Findings',
    tab: 'custody',
    targetSelector: '[data-tour="custody-view-panel"]',
    fallbackSelector: '[data-tour="nav-custody"]',
    preferredPlacement: 'bottom',
    explanation: 'An append-only audit trail that automatically logs every forensic action, evidence ingest, examiner identity, and write-denial event in chronological sequence.',
    importance: 'Establishes forensic traceability: observations and examiner actions are recorded immutably with timestamps, linking findings directly to case evidence.',
    whatNext: 'Finally, export comprehensive forensic documentation.',
    getStateAwareExplanation: (ctx) => {
      if (!ctx.activeCase) {
        return 'The chain of custody is tied to the active case scope, guaranteeing an append-only verifiable audit record.';
      }
      return `Displaying immutable custody log for case "${ctx.activeCase.name}". All actions by examiner "${ctx.activeCase.examiner}" are audited here.`;
    }
  },
  {
    id: 'reports',
    stepNumber: 10,
    totalSteps: 10,
    title: 'Forensic Reports & Documentation',
    tab: 'reports',
    targetSelector: '[data-tour="reports-view-panel"]',
    fallbackSelector: '[data-tour="nav-reports"]',
    preferredPlacement: 'bottom',
    explanation: 'Generates comprehensive forensic examination reports in PDF/Markdown, JSON, and CSV formats for documentation and technical review.',
    importance: 'Details case metadata, evidence parameters, SHA-256 derivation hashes, validation operations with technical reasons, and explicit stated forensic limitations (non-destructive analysis, read-only bounds).',
    whatNext: 'You have completed the forensic workflow overview!',
    getStateAwareExplanation: (ctx) => {
      if (!ctx.activeEvidence) {
        return 'Select an evidence item to generate and export formatted forensic examination documentation.';
      }
      return `Ready to export documentation for evidence "${ctx.activeEvidence.source_device}". Export includes cryptographic lineage references and validation logs.`;
    }
  }
];

export const WORKFLOW_STAGES: WorkflowStage[] = [
  {
    id: 'cases',
    label: 'Case Management',
    tab: 'cases',
    whatHappens: 'Register investigation identifier, assigned examiner, and case description to define the forensic boundary.',
    whyItMatters: 'Isolates evidence and analysis records within a distinct, persistent investigative scope.',
    status: 'implemented',
    details: ['Case identifier & examiner tracking', 'Scope isolation', 'Database persistence']
  },
  {
    id: 'evidence',
    label: 'Evidence Ingest',
    tab: 'evidence',
    whatHappens: 'Attach forensic disk images (.raw, .dd, .img) or block devices and record hardware write-blocker state.',
    whyItMatters: 'Supports multi-device investigations while locking evidence sources into strict read-only mode.',
    status: 'implemented',
    details: ['Multiple devices per case', 'Format classification (.raw, .dd, .img)', 'Capacity accounting']
  },
  {
    id: 'acquisition',
    label: 'Acquisition Verification',
    tab: 'acquisition',
    whatHappens: 'Verify imaging completeness, log bad sectors, and compute initial SHA-256 cryptographic hash.',
    whyItMatters: 'Provides an integrity baseline confirming the forensic working image has not been altered.',
    status: 'implemented',
    details: ['SHA-256 ingest hash', 'Bad sector gap accounting', 'Verification state logging']
  },
  {
    id: 'detection',
    label: 'OEM Detection',
    tab: 'detection',
    whatHappens: 'Analyze storage geometry, superblocks, and signatures to score candidate vendor profiles.',
    whyItMatters: 'Determines the appropriate parser without guessing; candidate margins highlight attribution certainty.',
    status: 'implemented',
    details: ['Hikvision, Dahua, TP-Link, CP Plus, Honeywell, Uniview', 'Deterministic signature matching', 'Storage topology profiler']
  },
  {
    id: 'hex_viewer',
    label: 'Byte Inspector',
    tab: 'hex_viewer',
    whatHappens: 'Stream positioned byte chunks and inspect raw hex and ASCII representations strictly read-only.',
    whyItMatters: 'Allows direct verification of parser findings and investigation of unallocated slack space.',
    status: 'implemented',
    details: ['64-bit offset positioning', '1 GB forward search', 'Read-only EvidenceReader guarantee']
  },
  {
    id: 'parsing',
    label: 'Proprietary Parsing',
    tab: 'parsing',
    whatHappens: 'Execute vendor-specific parsers (DHFS, HIKVISION_FS, UBIFS) to decode index tables and video headers.',
    whyItMatters: 'Extracts recording records, channels, and frame boundaries from proprietary disk structures.',
    status: 'implemented',
    details: ['Structure-aware index extraction', 'Independent validation outcomes', 'Direct offset jump links']
  },
  {
    id: 'recovery',
    label: 'Video Recovery',
    tab: 'recovery',
    whatHappens: 'Reconstruct playable video streams and identify active vs orphaned vs carved unallocated segments.',
    whyItMatters: 'Recovers video sequences with codec verification (H.264/H.265) and validation status records.',
    status: 'implemented',
    details: ['Active and orphaned candidates', 'H.264 / H.265 stream verification', 'Validation state & reasons']
  },
  {
    id: 'timeline',
    label: 'Forensic Timeline',
    tab: 'timeline',
    whatHappens: 'Correlate events across multiple cameras chronologically with ordering modes and timezone awareness.',
    whyItMatters: 'Clarifies sequence relationships and distinguishes known timezones from unadjusted recorder clocks.',
    status: 'implemented',
    details: ['Normalized UTC & native clock ordering', 'Timezone state flags', 'Component provenance lineage']
  },
  {
    id: 'custody',
    label: 'Chain of Custody',
    tab: 'custody',
    whatHappens: 'Append-only chronological audit log records all examiner actions, ingest hashes, and write denials.',
    whyItMatters: 'Guarantees forensic traceability and provides an unalterable record of all investigative operations.',
    status: 'implemented',
    details: ['Append-only database guarantee', 'Write-denial event logging', 'Examiner action tracking']
  },
  {
    id: 'reports',
    label: 'Forensic Reporting',
    tab: 'reports',
    whatHappens: 'Export structured examination documentation in PDF, JSON, and CSV with validation reasons and limitations.',
    whyItMatters: 'Produces comprehensive forensic documentation allowing technical peer review of findings.',
    status: 'implemented',
    details: ['PDF, JSON, CSV export formats', 'SHA-256 derivation reference', 'Stated forensic limitations']
  }
];
