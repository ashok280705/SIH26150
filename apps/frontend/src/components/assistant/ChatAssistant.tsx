import React, { useState, useRef, useEffect } from 'react';
import {
  Bot, Send, X, Settings, RefreshCw, AlertTriangle, Eye, Trash2, Sparkles, ShieldAlert,
} from 'lucide-react';
import {
  streamChat, getBase, DEFAULT_MODEL,
} from '../../services/assistant';
import { sendAiChat } from '../../services/api';

interface Props {
  /** The active view/tab, injected into the assistant's context. */
  activeTab: string;
  /** The active evidence name, if any. */
  evidenceName?: string | null;
}

interface UiMessage {
  role: 'user' | 'assistant';
  content: string;
  provider?: string;
  model?: string;
}

/** Read the visible content of the main app area (the current screen), so the assistant
 *  can explain whatever the examiner is looking at — hex bytes, timelines, findings, etc. */
function readScreen(): string {
  const el = document.querySelector('.main-content') as HTMLElement | null;
  let text = el?.innerText ?? '';
  text = text.replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
  const LIMIT = 6000;
  if (text.length > LIMIT) text = text.slice(0, LIMIT) + '\n…[screen content truncated]';
  return text;
}

const NAL_H264: Record<number, string> = {
  1: 'non-IDR slice (P/B frame)',
  5: 'IDR slice (keyframe)',
  6: 'SEI (supplemental info, often encoder metadata)',
  7: 'SPS (sequence parameter set)',
  8: 'PPS (picture parameter set)',
  9: 'access unit delimiter',
};

/** Decode the hex bytes actually shown in the Byte Inspector into concrete facts, so a
 *  small model has no room to invent structure. Returns null when no hex is on screen. */
function extractHexFacts(): string | null {
  const box = document.querySelector('.hex-viewer-box') as HTMLElement | null;
  if (!box) return null;
  const rows = Array.from(box.querySelectorAll('.hex-row'));
  if (rows.length === 0) return null;

  const bytes: number[] = [];
  let firstOffset = '';
  let lastOffset = '';
  for (const r of rows) {
    const off = (r.querySelector('.hex-offset') as HTMLElement | null)?.innerText.trim() ?? '';
    const hx = (r.querySelector('.hex-bytes') as HTMLElement | null)?.innerText.trim() ?? '';
    if (off && !firstOffset) firstOffset = off;
    if (off) lastOffset = off;
    for (const tok of hx.split(/\s+/)) {
      if (/^[0-9A-Fa-f]{2}$/.test(tok)) bytes.push(parseInt(tok, 16));
    }
  }
  if (bytes.length === 0) return null;

  // Printable ASCII runs (>= 4 chars) — these carry the real meaning in codec headers.
  const strings: string[] = [];
  let cur = '';
  for (const b of bytes) {
    if (b >= 0x20 && b <= 0x7e) cur += String.fromCharCode(b);
    else { if (cur.length >= 4) strings.push(cur); cur = ''; }
  }
  if (cur.length >= 4) strings.push(cur);

  // Annex-B start codes + the NAL type that follows a 4-byte start code.
  let sc3 = 0;
  let sc4 = 0;
  const nalNames: string[] = [];
  for (let i = 0; i + 2 < bytes.length; i++) {
    if (bytes[i] === 0 && bytes[i + 1] === 0 && bytes[i + 2] === 1 && ((bytes[i + 3] ?? 0) & 0x80) === 0) {
      const fourByte = i > 0 && bytes[i - 1] === 0;
      if (fourByte) sc4++; else sc3++;
      const h = bytes[i + 3];
      if (h !== undefined) {
        const t = h & 0x1f;
        nalNames.push(NAL_H264[t] ?? `NAL type ${t}`);
      }
    }
  }

  const joined = strings.join(' ');
  const sigs: string[] = [];
  if (/x264/i.test(joined)) sigs.push('the x264 encoder configuration string → this is an H.264/AVC video elementary stream');
  if (/x265|hevc/i.test(joined)) sigs.push('x265/HEVC markers → H.265 video');
  if (/videolan/i.test(joined)) sigs.push('VideoLAN/x264 metadata');
  if (/DHAV|DHFS/.test(joined)) sigs.push('Dahua DHAV/DHFS container markers');
  if (/HIKVISION@HANGZHOU/.test(joined)) sigs.push('the Hikvision boot identifier HIKVISION@HANGZHOU (boot structure +16)');
  if (/HIKBTREE/.test(joined)) sigs.push('a Hikvision HIKBTREE index page header');
  if (/OFNI/.test(joined)) sigs.push('a Hikvision OFNI information part inside an MPEG-PS clip');
  {
    let packs = 0;
    for (let i = 0; i + 3 < bytes.length; i++) {
      if (bytes[i] === 0 && bytes[i + 1] === 0 && bytes[i + 2] === 1 && bytes[i + 3] === 0xba) packs++;
    }
    if (packs > 0) sigs.push(`${packs}× MPEG-PS pack header (00 00 01 BA) — container framing (as in Hikvision clips), not a NAL unit`);
  }
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) sigs.push('JPEG SOI marker (FF D8 FF) → MJPEG frame');

  const lines: string[] = [];
  lines.push(`The Byte Inspector is showing ${bytes.length} bytes, offsets ${firstOffset} to ${lastOffset}. Each row is one 16-byte line; the left column is that line's byte ADDRESS (offset), not a separate "chunk".`);
  if (sc4 + sc3 > 0) {
    lines.push(`Annex-B NAL start codes found: ${sc4}× four-byte (00 00 00 01) and ${sc3}× three-byte (00 00 01). Start codes mark the boundaries of NAL units in a raw H.264/H.265 stream.`);
  }
  if (nalNames.length) {
    lines.push(`NAL unit types after the start codes, in order: ${nalNames.slice(0, 10).join(', ')}.`);
  }
  if (strings.length) {
    lines.push(`Readable ASCII text in these bytes: ${strings.slice(0, 8).map((s) => `"${s}"`).join(', ')}.`);
  }
  if (sigs.length) {
    lines.push(`Signatures detected: ${sigs.join('; ')}.`);
  }
  return lines.join('\n');
}

function buildSystemPrompt(
  screen: string,
  hexFacts: string | null,
  tab: string,
  evidence?: string | null,
): string {
  const parts: string[] = [
    'You are VidForge\'s AI Forensic Analysis Assistant, integrated into a multi-vendor DVR/NVR forensic analysis platform.',
    'You operate strictly as an ADVISORY INTERPRETATION LAYER. You are not an independent source of forensic truth.',
    'Explain what is on the current screen and how to interpret it: the hex/byte inspector, the preliminary and final timelines, coverage bars, gaps, the staged recovery levels (L1 indexed/active, L2 orphan carve, L3 raw carve), detection & confidence, and provenance/hashes.',
    '',
    'STRICT FORENSIC DIRECTIVES:',
    '- Base every statement strictly on the DECODED FACTS and SCREEN CONTENT provided below. NEVER invent structure, offsets, hashes, timestamps, codecs, or camera events.',
    '- In the hex view, each row is a 16-byte line and the left value (e.g. 0x00146240) is that line\'s byte OFFSET/address — it is NOT a separate chunk.',
    '- If the facts do not tell you something, explicitly state: "The available forensic data does not establish this."',
    '- Distinguish verified deterministic facts from AI interpretations.',
    '- Never recommend modifying original evidence.',
    '',
    `Current Active Tab: ${tab}`,
    `Active Evidence: ${evidence || 'none selected'}`,
  ];
  if (hexFacts) {
    parts.push(
      '',
      '=== DECODED FACTS ABOUT THE HEX ON SCREEN (authoritative — build your answer from these) ===',
      hexFacts,
      '=== END DECODED FACTS ===',
    );
  }
  parts.push(
    '',
    '=== CURRENT SCREEN TEXT (verbatim, from VidForge interface) ===',
    screen || '(the screen appears to be empty)',
    '=== END SCREEN TEXT ===',
  );
  return parts.join('\n');
}

const QUICK_PROMPTS = [
  'Summarize the forensic findings in this investigation.',
  'Explain the current recovery results.',
  'Explain the timeline gaps and anomalies.',
  'Explain the detected filesystem on this disk.',
  'Explain the bytes shown in the Byte Inspector.',
];

const PROVIDER_KEY = 'vidforge_ai_provider';
const API_KEY_KEY = 'vidforge_ai_key';
const MODEL_KEY = 'vidforge_ai_model';

export const ChatAssistant: React.FC<Props> = ({ activeTab, evidenceName }) => {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<UiMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  
  const [provider, setProvider] = useState<string>(() => localStorage.getItem(PROVIDER_KEY) || 'gemini');
  const [apiKey, setApiKey] = useState<string>(() => localStorage.getItem(API_KEY_KEY) || '');
  const [model, setModel] = useState<string>(() => localStorage.getItem(MODEL_KEY) || '');
  const [error, setError] = useState<string | null>(null);

  const scrollRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' });
  }, [messages, loading]);

  const saveSettings = () => {
    localStorage.setItem(PROVIDER_KEY, provider);
    localStorage.setItem(API_KEY_KEY, apiKey);
    localStorage.setItem(MODEL_KEY, model);
    setShowSettings(false);
    setError(null);
  };

  const send = async (text: string) => {
    const q = text.trim();
    if (!q || loading) return;
    setError(null);

    const screen = readScreen();
    const hexFacts = extractHexFacts();
    const systemPrompt = buildSystemPrompt(screen, hexFacts, activeTab, evidenceName);

    const historyPayload = messages.slice(-6).map((m) => ({ role: m.role, content: m.content }));
    const payload = [
      { role: 'system' as const, content: systemPrompt },
      ...historyPayload,
      { role: 'user' as const, content: q },
    ];

    setMessages((prev) => [...prev, { role: 'user', content: q }]);
    setInput('');
    setLoading(true);

    try {
      if (provider === 'ollama') {
        // Fallback to local Ollama if selected
        let streamedResponse = '';
        setMessages((prev) => [...prev, { role: 'assistant', content: '', provider: 'ollama' }]);
        await streamChat(
          payload,
          (delta) => {
            streamedResponse += delta;
            setMessages((prev) => {
              const copy = [...prev];
              const last = copy[copy.length - 1];
              if (last && last.role === 'assistant') {
                copy[copy.length - 1] = { ...last, content: streamedResponse };
              }
              return copy;
            });
          },
          { model: model || DEFAULT_MODEL, base: getBase() },
        );
      } else {
        // Route through Axum AI Gateway
        const res = await sendAiChat({
          messages: payload,
          provider,
          api_key: apiKey || undefined,
          model: model || undefined,
        });

        setMessages((prev) => [
          ...prev,
          {
            role: 'assistant',
            content: res.message,
            provider: res.provider,
            model: res.model,
          },
        ]);
      }
    } catch (e: any) {
      setError(e?.message || 'AI Copilot request failed');
    } finally {
      setLoading(false);
    }
  };

  const getProviderBadge = () => {
    switch (provider) {
      case 'gemini': return 'Gemini 3.8 Flash';
      case 'groq': return 'Groq Qwen 3.8';
      case 'openai': return 'OpenAI GPT-4o-mini';
      case 'ollama': return 'Local Ollama';
      default: return provider;
    }
  };

  return (
    <>
      {/* Floating launcher */}
      {!open && (
        <button
          onClick={() => setOpen(true)}
          title="Open AI Forensic Copilot"
          style={{
            position: 'fixed', right: '22px', bottom: '22px', zIndex: 1000,
            width: '54px', height: '54px', borderRadius: '50%',
            background: 'linear-gradient(135deg, #134074 0%, #0B2545 100%)',
            color: '#fff', border: '1px solid rgba(255,255,255,0.2)', cursor: 'pointer',
            boxShadow: '0 8px 24px rgba(11, 37, 69, 0.45)', display: 'flex', alignItems: 'center', justifyContent: 'center',
            transition: 'transform 0.2s ease',
          }}
        >
          <Bot size={26} />
        </button>
      )}

      {open && (
        <div
          style={{
            position: 'fixed', right: '22px', bottom: '22px', zIndex: 1000,
            width: '420px', maxWidth: 'calc(100vw - 44px)', height: '620px', maxHeight: 'calc(100vh - 44px)',
            background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '14px',
            boxShadow: '0 16px 48px rgba(0,0,0,0.45)', display: 'flex', flexDirection: 'column', overflow: 'hidden',
          }}
        >
          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '12px 14px', borderBottom: '1px solid var(--border)', background: 'var(--surface-muted)' }}>
            <Sparkles size={18} style={{ color: 'var(--accent)' }} />
            <div style={{ display: 'flex', flexDirection: 'column', lineHeight: 1.15 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <strong style={{ fontSize: '13.5px' }}>AI Forensic Copilot</strong>
                <span style={{ fontSize: '10px', padding: '1px 6px', borderRadius: '10px', background: 'rgba(46, 125, 50, 0.15)', color: 'var(--success)', border: '1px solid rgba(46, 125, 50, 0.3)', fontWeight: 600 }}>
                  {getProviderBadge()}
                </span>
              </div>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Advisory interpretation · strictly grounded in deterministic facts</span>
            </div>
            <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '4px' }}>
              <button className="btn btn-icon btn-sm" title="Settings" onClick={() => setShowSettings((s) => !s)} style={{ color: showSettings ? 'var(--accent)' : 'var(--text-secondary)' }}>
                <Settings size={15} />
              </button>
              <button className="btn btn-icon btn-sm" title="Clear chat" onClick={() => setMessages([])} style={{ color: 'var(--text-secondary)' }}>
                <Trash2 size={15} />
              </button>
              <button className="btn btn-icon btn-sm" title="Close" onClick={() => setOpen(false)} style={{ color: 'var(--text-secondary)' }}>
                <X size={16} />
              </button>
            </div>
          </div>

          {/* Settings Drawer */}
          {showSettings && (
            <div style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', background: 'var(--surface-sunken)', fontSize: '12px' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '5px' }}>
                  <Settings size={13} /> AI Provider Configuration
                </div>
                
                <label style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>AI Engine Provider</span>
                  <select
                    className="form-select"
                    style={{ fontSize: '12px', padding: '6px 8px' }}
                    value={provider}
                    onChange={(e) => setProvider(e.target.value)}
                  >
                    <option value="gemini">Google Gemini (Recommended - Fast & Large Context)</option>
                    <option value="groq">Groq Cloud (Ultra-Fast Qwen / LLaMA)</option>
                    <option value="openai">OpenAI (GPT-4o-mini)</option>
                    <option value="ollama">Local Offline Ollama</option>
                  </select>
                </label>

                {provider !== 'ollama' && (
                  <label style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>API Key (Optional override)</span>
                    <input
                      type="password"
                      className="form-input"
                      style={{ fontSize: '12px', padding: '6px 8px' }}
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                      placeholder="Leave blank to use server environment key"
                    />
                    <span style={{ color: 'var(--text-muted)', fontSize: '10.5px' }}>
                      Keys are stored locally in your browser session only.
                    </span>
                  </label>
                )}

                <label style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Model Identifier (Optional)</span>
                  <input
                    className="form-input"
                    style={{ fontSize: '12px', padding: '6px 8px' }}
                    value={model}
                    onChange={(e) => setModel(e.target.value)}
                    placeholder={
                      provider === 'gemini' ? 'gemini-3.8-flash' :
                      provider === 'groq' ? 'qwen/qwen3.8-27b' :
                      provider === 'openai' ? 'gpt-4o-mini' : DEFAULT_MODEL
                    }
                  />
                </label>

                <div style={{ display: 'flex', gap: '8px', marginTop: '4px' }}>
                  <button className="btn btn-primary btn-sm" onClick={saveSettings}>Save Settings</button>
                  <button className="btn btn-secondary btn-sm" onClick={() => setShowSettings(false)}>Cancel</button>
                </div>
              </div>
            </div>
          )}

          {/* Messages Body */}
          <div ref={scrollRef} style={{ flex: 1, overflowY: 'auto', padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {messages.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: '12.5px', lineHeight: 1.55 }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', marginBottom: '10px', background: 'var(--surface-sunken)', padding: '10px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                  <Eye size={15} style={{ color: 'var(--accent)', marginTop: '2px', flexShrink: 0 }} />
                  <span>
                    I read the current view automatically (<strong>{activeTab.replace(/_/g, ' ')}</strong>).
                    In the Byte Inspector, I extract real structural indicators, NAL types, and OEM magic bytes so answers stay grounded.
                  </span>
                </div>
                <div style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Suggested Investigative Queries:
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {QUICK_PROMPTS.map((p) => (
                    <button key={p} className="btn btn-secondary btn-sm" style={{ justifyContent: 'flex-start', textAlign: 'left', fontSize: '12px' }} onClick={() => send(p)}>
                      {p}
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              messages.map((m, i) => (
                <div
                  key={i}
                  style={{
                    alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start',
                    maxWidth: '92%',
                    background: m.role === 'user' ? 'linear-gradient(135deg, #134074 0%, #0B2545 100%)' : 'var(--surface-muted)',
                    color: m.role === 'user' ? '#fff' : 'var(--text-primary)',
                    border: m.role === 'user' ? 'none' : '1px solid var(--border)',
                    borderRadius: '10px', padding: '9px 12px',
                    fontSize: '12.5px', lineHeight: 1.52, whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                  }}
                >
                  {m.role === 'assistant' && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px', fontSize: '10.5px', color: 'var(--text-muted)', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '4px' }}>
                      <Sparkles size={11} style={{ color: 'var(--accent)' }} />
                      <span>VidForge AI Advisory</span>
                      {m.provider && <span style={{ marginLeft: 'auto', opacity: 0.8 }}>[{m.provider}]</span>}
                    </div>
                  )}
                  {m.content}
                </div>
              ))
            )}

            {loading && (
              <div style={{ alignSelf: 'flex-start', background: 'var(--surface-muted)', padding: '8px 12px', borderRadius: '10px', border: '1px solid var(--border)', fontSize: '12px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <RefreshCw size={13} className="spin" style={{ color: 'var(--accent)' }} />
                <span>Analyzing deterministic forensic facts...</span>
              </div>
            )}

            {error && (
              <div style={{ fontSize: '12px', color: 'var(--danger)', background: 'rgba(179, 38, 30, 0.1)', border: '1px solid var(--danger)', padding: '8px 10px', borderRadius: '8px', display: 'flex', alignItems: 'flex-start', gap: '8px' }}>
                <AlertTriangle size={15} style={{ flexShrink: 0, marginTop: '2px' }} />
                <span>{error}</span>
              </div>
            )}
          </div>

          {/* Legal Disclaimer Bar */}
          <div style={{ padding: '4px 12px', background: 'var(--surface-sunken)', borderTop: '1px solid var(--border-subtle)', fontSize: '10px', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <ShieldAlert size={12} style={{ flexShrink: 0 }} />
            <span>AI-Assisted Interpretation. Does not alter original evidence.</span>
          </div>

          {/* Composer */}
          <div style={{ borderTop: '1px solid var(--border)', padding: '10px 12px', display: 'flex', gap: '8px', alignItems: 'flex-end', background: 'var(--surface)' }}>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(input); }
              }}
              placeholder="Ask about recovery results, timeline gaps, or hex bytes…"
              rows={1}
              style={{
                flex: 1, resize: 'none', maxHeight: '96px', minHeight: '38px',
                padding: '9px 10px', fontSize: '12.5px', borderRadius: '8px',
                border: '1px solid var(--border)', background: 'var(--surface-sunken)', color: 'var(--text-primary)',
              }}
            />
            <button className="btn btn-primary" onClick={() => send(input)} disabled={!input.trim() || loading} title="Send query" style={{ height: '38px', minWidth: '42px' }}>
              <Send size={15} />
            </button>
          </div>
        </div>
      )}
    </>
  );
};
