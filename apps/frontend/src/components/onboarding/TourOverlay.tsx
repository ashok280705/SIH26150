import React, { useState, useEffect, useRef, useCallback } from 'react';
import { ChevronLeft, ChevronRight, X, Compass, CheckCircle2, AlertCircle, Info } from 'lucide-react';
import { TourStep, TourContext } from '../../types/onboarding';

interface TourOverlayProps {
  step: TourStep;
  context: TourContext;
  onNext: () => void;
  onPrev: () => void;
  onSkip: () => void;
  onFinish: () => void;
}

interface TargetRect {
  top: number;
  left: number;
  width: number;
  height: number;
}

export const TourOverlay: React.FC<TourOverlayProps> = ({
  step,
  context,
  onNext,
  onPrev,
  onSkip,
  onFinish,
}) => {
  const [targetRect, setTargetRect] = useState<TargetRect | null>(null);
  const [targetFound, setTargetFound] = useState<boolean>(true);
  const [windowSize, setWindowSize] = useState({ width: window.innerWidth, height: window.innerHeight });
  const popoverRef = useRef<HTMLDivElement>(null);
  const isFinalStep = step.stepNumber === step.totalSteps;

  const updateTargetPosition = useCallback(() => {
    let el = document.querySelector(step.targetSelector) as HTMLElement | null;
    if (!el && step.fallbackSelector) {
      el = document.querySelector(step.fallbackSelector) as HTMLElement | null;
    }

    if (el) {
      const rect = el.getBoundingClientRect();
      // Scroll into view if outside viewport boundaries
      const isOffscreen = 
        rect.top < 0 || 
        rect.left < 0 || 
        rect.bottom > window.innerHeight || 
        rect.right > window.innerWidth;

      if (isOffscreen) {
        el.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' });
      }

      // Re-read rect after potential scroll adjustment
      const updatedRect = el.getBoundingClientRect();
      setTargetRect({
        top: Math.max(0, updatedRect.top),
        left: Math.max(0, updatedRect.left),
        width: Math.max(20, updatedRect.width),
        height: Math.max(20, updatedRect.height),
      });
      setTargetFound(true);
    } else {
      setTargetRect(null);
      setTargetFound(false);
    }
  }, [step.targetSelector, step.fallbackSelector]);

  // Initial and reactive position calculation
  useEffect(() => {
    // Slight delay to allow tab component to mount / transition
    const timer = setTimeout(() => {
      updateTargetPosition();
    }, 150);

    const retryTimer = setTimeout(() => {
      updateTargetPosition();
    }, 450);

    const handleResize = () => {
      setWindowSize({ width: window.innerWidth, height: window.innerHeight });
      updateTargetPosition();
    };

    window.addEventListener('resize', handleResize);
    window.addEventListener('scroll', updateTargetPosition, true);

    return () => {
      clearTimeout(timer);
      clearTimeout(retryTimer);
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('scroll', updateTargetPosition, true);
    };
  }, [step.tab, step.id, updateTargetPosition]);

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't intercept if user is typing into an input or textarea
      const activeTag = (document.activeElement?.tagName || '').toLowerCase();
      if (activeTag === 'input' || activeTag === 'textarea' || activeTag === 'select') {
        return;
      }

      if (e.key === 'Escape') {
        e.preventDefault();
        onSkip();
      } else if (e.key === 'ArrowRight' || e.key === 'Enter') {
        e.preventDefault();
        if (isFinalStep) {
          onFinish();
        } else {
          onNext();
        }
      } else if (e.key === 'ArrowLeft') {
        e.preventDefault();
        if (step.stepNumber > 1) {
          onPrev();
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onNext, onPrev, onSkip, onFinish, isFinalStep, step.stepNumber]);

  // Focus management: focus the popover when step changes
  useEffect(() => {
    if (popoverRef.current) {
      popoverRef.current.focus();
    }
  }, [step.id]);

  // Compute popover coordinates relative to the target element
  const getPopoverStyle = (): React.CSSProperties => {
    const isMobile = windowSize.width < 768;
    if (isMobile || !targetRect || !targetFound) {
      // Bottom sheet or centered modal for mobile or missing element
      return {
        position: 'fixed',
        bottom: isMobile ? '16px' : 'auto',
        left: isMobile ? '16px' : '50%',
        right: isMobile ? '16px' : 'auto',
        top: isMobile ? 'auto' : '50%',
        transform: isMobile ? 'none' : 'translate(-50%, -50%)',
        maxWidth: isMobile ? 'calc(100vw - 32px)' : '480px',
        width: '100%',
        zIndex: 10001,
      };
    }

    const popoverWidth = 440;
    const padding = 14;
    const viewportWidth = windowSize.width;
    const viewportHeight = windowSize.height;

    let left = targetRect.left;
    let top = targetRect.top + targetRect.height + padding;

    // Check preferred placement
    const preferred = step.preferredPlacement || 'bottom';

    if (preferred === 'right' && targetRect.left + targetRect.width + popoverWidth + padding < viewportWidth) {
      left = targetRect.left + targetRect.width + padding;
      top = targetRect.top;
    } else if (preferred === 'left' && targetRect.left - popoverWidth - padding > 0) {
      left = targetRect.left - popoverWidth - padding;
      top = targetRect.top;
    } else if (preferred === 'top' && targetRect.top - 280 > 0) {
      top = targetRect.top - 260 - padding;
      left = targetRect.left;
    } else {
      // Default: below target
      top = targetRect.top + targetRect.height + padding;
      left = targetRect.left;
    }

    // Keep within horizontal bounds
    if (left + popoverWidth > viewportWidth - 20) {
      left = viewportWidth - popoverWidth - 20;
    }
    if (left < 20) left = 20;

    // Keep within vertical bounds
    if (top + 280 > viewportHeight - 20) {
      // If overflowing bottom, flip to above target if space exists
      if (targetRect.top - 280 > 20) {
        top = targetRect.top - 270;
      } else {
        top = Math.max(20, viewportHeight - 320);
      }
    }
    if (top < 20) top = 20;

    return {
      position: 'fixed',
      top: `${top}px`,
      left: `${left}px`,
      width: `${popoverWidth}px`,
      maxWidth: 'calc(100vw - 40px)',
      zIndex: 10001,
    };
  };

  const stateAwareMsg = step.getStateAwareExplanation ? step.getStateAwareExplanation(context) : null;

  return (
    <div 
      className="tour-overlay-container" 
      role="dialog" 
      aria-modal="true" 
      aria-label={`Tour Step ${step.stepNumber} of ${step.totalSteps}: ${step.title}`}
    >
      {/* SVG Darkened Backdrop with Spotlight Cutout */}
      <svg 
        className="tour-backdrop-svg"
        width={windowSize.width}
        height={windowSize.height}
        aria-hidden="true"
      >
        <defs>
          <mask id="tour-spotlight-mask">
            {/* White covers everything (visible) */}
            <rect x="0" y="0" width={windowSize.width} height={windowSize.height} fill="white" />
            {/* Black cuts out the spotlight hole (transparent) */}
            {targetRect && (
              <rect
                x={Math.max(0, targetRect.left - 6)}
                y={Math.max(0, targetRect.top - 6)}
                width={targetRect.width + 12}
                height={targetRect.height + 12}
                rx="6"
                ry="6"
                fill="black"
              />
            )}
          </mask>
        </defs>
        {/* Darkened backdrop overlay with cutout mask */}
        <rect
          x="0"
          y="0"
          width={windowSize.width}
          height={windowSize.height}
          fill="rgba(15, 23, 42, 0.72)"
          mask="url(#tour-spotlight-mask)"
        />
      </svg>

      {/* Spotlight Ring around target */}
      {targetRect && (
        <div
          className="tour-spotlight-ring"
          style={{
            top: `${Math.max(0, targetRect.top - 6)}px`,
            left: `${Math.max(0, targetRect.left - 6)}px`,
            width: `${targetRect.width + 12}px`,
            height: `${targetRect.height + 12}px`,
          }}
          aria-hidden="true"
        />
      )}

      {/* Anchored / Positioned Popover Card */}
      <div
        ref={popoverRef}
        tabIndex={-1}
        className="tour-popover-card"
        style={getPopoverStyle()}
      >
        {/* Popover Header */}
        <div className="tour-popover-header">
          <div className="tour-step-badge">
            <Compass size={13} style={{ marginRight: '5px' }} />
            <span>Step {step.stepNumber} of {step.totalSteps}</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button
              type="button"
              className="tour-skip-btn"
              onClick={onSkip}
              title="Exit Guided Tour (Esc)"
            >
              Skip Tour
            </button>
            <button
              type="button"
              className="tour-close-btn"
              onClick={onSkip}
              aria-label="Close tour"
            >
              <X size={15} />
            </button>
          </div>
        </div>

        {/* Title */}
        <h3 className="tour-title">{step.title}</h3>

        {/* Missing Target Fallback Notice */}
        {!targetFound && (
          <div className="tour-missing-banner">
            <AlertCircle size={14} style={{ flexShrink: 0 }} />
            <span>This section is not currently available or visible in the workspace.</span>
          </div>
        )}

        {/* Core Explanation */}
        <p className="tour-explanation">{step.explanation}</p>

        {/* State-aware contextual note */}
        {stateAwareMsg && (
          <div className="tour-state-banner">
            <Info size={14} style={{ flexShrink: 0, marginTop: '1px' }} />
            <div>{stateAwareMsg}</div>
          </div>
        )}

        {/* Why It Matters */}
        <div className="tour-importance-box">
          <span className="tour-importance-label">Forensic Importance:</span>{' '}
          <span className="tour-importance-text">{step.importance}</span>
        </div>

        {/* Final step celebration message */}
        {isFinalStep && (
          <div className="tour-complete-banner">
            <CheckCircle2 size={16} color="var(--success)" style={{ flexShrink: 0 }} />
            <div>
              <strong>You're ready to investigate.</strong>
              <div style={{ fontSize: '12px', marginTop: '2px', color: 'var(--text-secondary)' }}>
                You can revisit this guided tour or view the forensic workflow anytime from <strong>Help & Guide</strong>.
              </div>
            </div>
          </div>
        )}

        {/* Popover Footer: Progress Dots & Action Buttons */}
        <div className="tour-popover-footer">
          {/* Progress dots indicator */}
          <div className="tour-dots-indicator" aria-hidden="true">
            {Array.from({ length: step.totalSteps }).map((_, idx) => (
              <span
                key={idx}
                className={`tour-dot ${idx + 1 === step.stepNumber ? 'active' : ''} ${idx + 1 < step.stepNumber ? 'passed' : ''}`}
                title={`Step ${idx + 1}`}
              />
            ))}
          </div>

          {/* Navigation buttons */}
          <div className="tour-footer-buttons">
            {step.stepNumber > 1 && (
              <button
                type="button"
                className="btn btn-secondary tour-btn"
                onClick={onPrev}
                title="Previous step (Left Arrow)"
              >
                <ChevronLeft size={14} />
                <span>Previous</span>
              </button>
            )}

            {!isFinalStep ? (
              <button
                type="button"
                className="btn btn-primary tour-btn"
                onClick={onNext}
                title="Next step (Enter or Right Arrow)"
                autoFocus
              >
                <span>Next</span>
                <ChevronRight size={14} />
              </button>
            ) : (
              <button
                type="button"
                className="btn btn-primary tour-btn"
                onClick={onFinish}
                style={{ backgroundColor: 'var(--success)' }}
                autoFocus
              >
                <CheckCircle2 size={14} />
                <span>Finish Tour</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
