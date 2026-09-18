import { Case, Evidence } from './index';

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

export type OnboardingState = 
  | 'onboarding_not_started'
  | 'onboarding_in_progress'
  | 'onboarding_completed'
  | 'onboarding_dismissed';

export interface TourContext {
  activeCase: Case | null;
  activeEvidence: Evidence | null;
  evidenceList: Evidence[];
}

export interface TourStep {
  id: string;
  stepNumber: number;
  totalSteps: number;
  title: string;
  tab: ActiveTab;
  targetSelector: string;
  fallbackSelector?: string;
  explanation: string;
  importance: string;
  whatNext?: string;
  preferredPlacement?: 'top' | 'bottom' | 'left' | 'right' | 'auto';
  getStateAwareExplanation?: (ctx: TourContext) => string | null;
  isAvailable?: (ctx: TourContext) => boolean;
}

export interface WorkflowStage {
  id: string;
  label: string;
  tab: ActiveTab;
  whatHappens: string;
  whyItMatters: string;
  status: 'implemented' | 'partial' | 'planned';
  details: string[];
}
