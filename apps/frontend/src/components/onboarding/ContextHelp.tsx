import React, { useState, useRef, useEffect } from 'react';
import { HelpCircle, X } from 'lucide-react';

interface ContextHelpProps {
  title: string;
  content: string;
  placement?: 'top' | 'bottom' | 'left' | 'right';
  className?: string;
}

export const ContextHelp: React.FC<ContextHelpProps> = ({
  title,
  content,
  placement = 'top',
  className = '',
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleOutsideClick = (e: MouseEvent) => {
      if (
        popoverRef.current &&
        !popoverRef.current.contains(e.target as Node) &&
        triggerRef.current &&
        !triggerRef.current.contains(e.target as Node)
      ) {
        setIsOpen(false);
      }
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        setIsOpen(false);
        triggerRef.current?.focus();
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleOutsideClick);
      document.addEventListener('keydown', handleKeyDown);
    }

    return () => {
      document.removeEventListener('mousedown', handleOutsideClick);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen]);

  return (
    <div className={`context-help-wrapper ${className}`} style={{ display: 'inline-flex', position: 'relative' }}>
      <button
        ref={triggerRef}
        type="button"
        className="context-help-btn"
        onClick={() => setIsOpen(!isOpen)}
        onMouseEnter={() => setIsOpen(true)}
        aria-label={`Help on ${title}`}
        aria-expanded={isOpen}
      >
        <HelpCircle size={13} />
      </button>

      {isOpen && (
        <div 
          ref={popoverRef}
          className={`context-help-popover placement-${placement}`}
          role="tooltip"
          onMouseLeave={() => setIsOpen(false)}
        >
          <div className="context-help-header">
            <span className="context-help-title">{title}</span>
            <button
              type="button"
              className="context-help-close"
              onClick={(e) => {
                e.stopPropagation();
                setIsOpen(false);
              }}
              aria-label="Dismiss tooltip"
            >
              <X size={12} />
            </button>
          </div>
          <p className="context-help-body">{content}</p>
        </div>
      )}
    </div>
  );
};
