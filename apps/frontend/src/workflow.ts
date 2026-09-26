// Sequential investigation workflow state.
//
// Each analysis sidebar stage is gated on the result of the previous one. This
// module owns the shared state and computes which stages are unlocked, so a stage
// can never be entered before the result it depends on exists.
//
// Flow (matches the investigation diagram):
//   Detection (+confidence)  →  verdict: confirmed | ambiguous | unresolved
//     confirmed   → Parsing auto-attaches the confirmed OEM parser
//     ambiguous   → analyst reviews extracted evidence in the Byte Inspector,
//                   then manually selects a parser in Parsing
//   Parsing (extraction, recording locations)
//     → Preliminary Timeline (build + gap detection)
//        no gaps  → Final Timeline
//        gaps     → Recovery Engine
//                     recovered/partial → Final Timeline
//                     nothing recovered → analyst decides whether to continue
//     → Final Timeline → Video Player + Reports

import type { ActiveTab } from './components/Sidebar';

export type DetectionVerdict = 'confirmed' | 'ambiguous' | 'unresolved';
export type RecoveryOutcome = 'recovered' | 'partial' | 'not_recovered';

export interface WorkflowState {
  // Detection + confidence
  detectionDone: boolean;
  verdict: DetectionVerdict | null;
  attributedOem: string | null; // set only when confirmed
  confidence: number | null;

  // Parsing / extraction
  parsingDone: boolean;
  parserUsed: string | null;
  recordingCount: number;

  // Preliminary timeline + gaps
  timelineBuilt: boolean;
  gapsPresent: boolean | null;
  coverageRatio: number | null;

  // Recovery
  recoveryDone: boolean;
  recoveryRequired: boolean;
  recoveryOutcome: RecoveryOutcome | null;
  analystApproved: boolean; // continue despite nothing recovered

  // Final timeline
  finalTimelineBuilt: boolean;
}

export const EMPTY_WORKFLOW: WorkflowState = {
  detectionDone: false,
  verdict: null,
  attributedOem: null,
  confidence: null,
  parsingDone: false,
  parserUsed: null,
  recordingCount: 0,
  timelineBuilt: false,
  gapsPresent: null,
  coverageRatio: null,
  recoveryDone: false,
  recoveryRequired: false,
  recoveryOutcome: null,
  analystApproved: false,
  finalTimelineBuilt: false,
};

const KEY_PREFIX = 'forensic_workflow_';

export function loadWorkflow(evidenceId: string | null): WorkflowState {
  if (!evidenceId) return { ...EMPTY_WORKFLOW };
  try {
    const raw = localStorage.getItem(KEY_PREFIX + evidenceId.replace('evidence-', ''));
    if (raw) return { ...EMPTY_WORKFLOW, ...JSON.parse(raw) };
  } catch {
    /* ignore corrupt state */
  }
  return { ...EMPTY_WORKFLOW };
}

export function saveWorkflow(evidenceId: string | null, state: WorkflowState): void {
  if (!evidenceId) return;
  try {
    localStorage.setItem(KEY_PREFIX + evidenceId.replace('evidence-', ''), JSON.stringify(state));
  } catch {
    /* storage full / unavailable — non-fatal */
  }
}

export interface StageAccess {
  locked: boolean;
  reason: string;
}

/**
 * Whether the final timeline is reachable given the current state.
 * Reachable when there were no gaps, or recovery ran with a usable outcome, or the
 * analyst explicitly chose to continue after nothing was recovered.
 */
export function finalTimelineReachable(w: WorkflowState): boolean {
  if (w.timelineBuilt && w.gapsPresent === false) return true;
  if (w.recoveryDone && (w.recoveryOutcome === 'recovered' || w.recoveryOutcome === 'partial')) return true;
  if (w.recoveryDone && w.analystApproved) return true;
  return false;
}

/**
 * Compute lock state + reason for every gated analysis tab. Non-analysis tabs
 * (overview, cases, evidence, acquisition, hex, custody) are always available.
 */
export function computeAccess(evidenceLoaded: boolean, w: WorkflowState): Record<ActiveTab, StageAccess> {
  const open: StageAccess = { locked: false, reason: '' };
  const need = (reason: string): StageAccess => ({ locked: true, reason });

  const detection: StageAccess = evidenceLoaded ? open : need('Select an evidence target first');

  const parsing: StageAccess = !w.detectionDone
    ? need('Run Detection & Confidence first')
    : w.verdict === null
    ? need('Awaiting a detection verdict')
    : open;

  const preliminary: StageAccess = w.parsingDone
    ? open
    : need('Complete Parsing & Extraction first');

  const recovery: StageAccess = !w.timelineBuilt
    ? need('Build the Preliminary Timeline first')
    : w.gapsPresent === true
    ? open
    : need('No gaps were found — recovery is not required');

  const finalReachable = finalTimelineReachable(w);
  const timeline: StageAccess = finalReachable
    ? open
    : w.timelineBuilt && w.gapsPresent === true
    ? need('Resolve gaps in Recovery first')
    : need('Build the Preliminary Timeline first');

  const video: StageAccess = w.finalTimelineBuilt || (w.recoveryDone && w.analystApproved)
    ? open
    : need('Available after the Final Timeline is built');

  const reports: StageAccess = w.finalTimelineBuilt
    ? open
    : need('Available after the Final Timeline is built');

  return {
    overview: open,
    cases: open,
    evidence: open,
    acquisition: open,
    hex_viewer: open,
    custody: open,
    detection,
    parsing,
    preliminary_timeline: preliminary,
    recovery,
    timeline,
    video: video,
    reports,
  };
}
