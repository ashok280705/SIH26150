import React, { useState, useRef, useEffect, useCallback } from 'react';
import {
  Bot, Send, X, Settings, RefreshCw, AlertTriangle, Eye, Trash2, Cpu,
} from 'lucide-react';
import {
  streamChat, checkOllama, getModel, setModel as persistModel,
  getBase, setBase as persistBase, ChatMessage, OllamaStatus, DEFAULT_MODEL,
} from '../../services/assistant';

interface Props {
  /** The active view/tab, injected into the assistant's context. */
  activeTab: string;
  /** The active evidence name, if any. */
  evidenceName?: string | null;
}

interface UiMessage {
  role: 'user' | 'assistant';
  content: string;
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
    // A NAL header has its forbidden bit clear; 00 00 01 BA/BB/E0... are MPEG system start
    // codes (container framing) and are reported separately below.
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
    // 00 00 01 BA is an MPEG-PS pack header, not a NAL start code: Hikvision clips are framed this way.
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
    lines.push(`Annex-B NAL start codes found: ${sc4}× four-byte (00 00 00 01) and ${sc3}× three-byte (00 00 01). Start codes mark the boundaries of NAL units in a raw H.264/H.265 stream — they do NOT alternate audio/video.`);
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
    'You are the offline forensic assistant built into the Multi-Vendor DVR/NVR Forensic Analysis tool. You run locally via Ollama; nothing leaves this machine.',
    'Explain what is on the current screen and how to use the tool: the hex/byte inspector, the preliminary and final timelines, coverage bars, gaps, the staged recovery levels (L1 indexed/active, L2 orphan carve, L3 raw carve, "recording lost"), detection & confidence, and provenance/hashes.',
    '',
    'STRICT RULES:',
    '- Base every statement on the DECODED FACTS and SCREEN CONTENT below. Do NOT invent structure, offsets, hashes, timestamps, codecs, or "audio/audio-video chunks".',
    '- In the hex view, each row is a 16-byte line and the left value (e.g. 0x00146240) is that line\'s byte OFFSET/address — it is NOT a separate chunk and rows do NOT alternate between audio and video.',
    '- 00 00 00 01 and 00 00 01 are H.264/H.265 Annex-B NAL start codes.',
    '- If the facts do not tell you something, say "that is not visible on screen" instead of guessing. Be concise (a few sentences).',
    '',
    `Current tab: ${tab}`,
    `Active evidence: ${evidence || 'none'}`,
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
    '=== CURRENT SCREEN TEXT (verbatim, may be truncated) ===',
    screen || '(the screen appears to be empty)',
    '=== END SCREEN TEXT ===',
  );
  return parts.join('\n');
}

const QUICK_PROMPTS = [
  'Explain the bytes shown in the Byte Inspector.',
  'Are there any H.264 start codes on screen, and what do they mean?',
  'What does the readable text in these bytes tell us?',
  'What should I do next?',
];

export const ChatAssistant: React.FC<Props> = ({ activeTab, evidenceName }) => {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<UiMessage[]>([]);
  const [input, setInput] = useState('');
  const [streaming, setStreaming] = useState(false);
  const [status, setStatus] = useState<OllamaStatus | null>(null);
  const [checking, setChecking] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [model, setModelState] = useState(getModel());
  const [base, setBaseState] = useState(getBase());
  const [error, setError] = useState<string | null>(null);

  const abortRef = useRef<AbortController | null>(null);
  const scrollRef = useRef<HTMLDivElement | null>(null);

  const runCheck = useCallback(async () => {
    setChecking(true);
    const s = await checkOllama();
    setStatus(s);
    // If the configured model isn't installed but others are, switch to one that is.
    if (s.ok && s.models.length > 0 && !s.models.includes(getModel())) {
      persistModel(s.models[0]);
      setModelState(s.models[0]);
    }
    setChecking(false);
  }, []);

  useEffect(() => {
    if (open && status === null) runCheck();
  }, [open, status, runCheck]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' });
  }, [messages, streaming]);

  const stop = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setStreaming(false);
  };

  const send = async (text: string) => {
    const q = text.trim();
    if (!q || streaming) return;
    setError(null);

    const history: ChatMessage[] = messages.slice(-8).map((m) => ({ role: m.role, content: m.content }));
    const screen = readScreen();
    const hexFacts = extractHexFacts();
    const system = buildSystemPrompt(screen, hexFacts, activeTab, evidenceName);
    const payload: ChatMessage[] = [
      { role: 'system', content: system },
      ...history,
      { role: 'user', content: q },
    ];

    setMessages((prev) => [...prev, { role: 'user', content: q }, { role: 'assistant', content: '' }]);
    setInput('');
    setStreaming(true);

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      await streamChat(
        payload,
        (delta) => {
          setMessages((prev) => {
            const copy = [...prev];
            const last = copy[copy.length - 1];
            if (last && last.role === 'assistant') copy[copy.length - 1] = { ...last, content: last.content + delta };
            return copy;
          });
        },
        { signal: controller.signal, model, base },
      );
    } catch (e: any) {
      if (e?.name !== 'AbortError') {
        setError(e?.message || 'Assistant request failed');
        // Drop the empty assistant bubble on hard failure.
        setMessages((prev) => {
          const copy = [...prev];
          const last = copy[copy.length - 1];
          if (last && last.role === 'assistant' && last.content === '') copy.pop();
          return copy;
        });
        // Re-check connectivity so the setup panel can appear.
        runCheck();
      }
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  };

  const saveSettings = async () => {
    persistModel(model);
    persistBase(base);
    setShowSettings(false);
    setStatus(null);
    await runCheck();
  };

  const offline = status !== null && !status.ok;

  return (
    <>
      {/* Floating launcher */}
      {!open && (
        <button
          onClick={() => setOpen(true)}
          title="Open the offline assistant"
          style={{
            position: 'fixed', right: '22px', bottom: '22px', zIndex: 1000,
            width: '52px', height: '52px', borderRadius: '50%',
            background: 'var(--accent)', color: '#fff', border: 'none', cursor: 'pointer',
            boxShadow: '0 6px 20px rgba(0,0,0,0.35)', display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}
        >
          <Bot size={24} />
        </button>
      )}

      {open && (
        <div
          style={{
            position: 'fixed', right: '22px', bottom: '22px', zIndex: 1000,
            width: '380px', maxWidth: 'calc(100vw - 44px)', height: '560px', maxHeight: 'calc(100vh - 44px)',
            background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '12px',
            boxShadow: '0 12px 40px rgba(0,0,0,0.4)', display: 'flex', flexDirection: 'column', overflow: 'hidden',
          }}
        >
          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 12px', borderBottom: '1px solid var(--border)', background: 'var(--surface-muted)' }}>
            <Bot size={18} style={{ color: 'var(--accent)' }} />
            <div style={{ display: 'flex', flexDirection: 'column', lineHeight: 1.1 }}>
              <strong style={{ fontSize: '13px' }}>Forensic Assistant</strong>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Offline · Ollama · reads the current screen</span>
            </div>
            <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '4px' }}>
              <span
                title={status?.ok ? `Connected · model ${model}` : 'Ollama not reachable'}
                style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '10px', color: status?.ok ? 'var(--success)' : 'var(--text-muted)' }}
              >
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: status?.ok ? 'var(--success)' : 'var(--text-muted)' }} />
              </span>
              <button className="btn btn-icon btn-sm" title="Settings" onClick={() => setShowSettings((s) => !s)} style={{ color: 'var(--text-secondary)' }}>
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

          {/* Settings */}
          {showSettings && (
            <div style={{ padding: '12px', borderBottom: '1px solid var(--border)', background: 'var(--surface-sunken)', fontSize: '12px' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <label style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Model</span>
                  {status?.ok && status.models.length > 0 ? (
                    <select className="form-select" style={{ fontSize: '12px', padding: '5px 8px' }} value={model} onChange={(e) => setModelState(e.target.value)}>
                      {status.models.map((m) => (<option key={m} value={m}>{m}</option>))}
                    </select>
                  ) : (
                    <input className="form-input" style={{ fontSize: '12px', padding: '5px 8px' }} value={model} onChange={(e) => setModelState(e.target.value)} placeholder={DEFAULT_MODEL} />
                  )}
                </label>
                <label style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Ollama base URL</span>
                  <input className="form-input" style={{ fontSize: '12px', padding: '5px 8px' }} value={base} onChange={(e) => setBaseState(e.target.value)} placeholder="/ollama" />
                  <span style={{ color: 'var(--text-muted)', fontSize: '10.5px' }}>Default <code>/ollama</code> is proxied to http://127.0.0.1:11434 in dev.</span>
                </label>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button className="btn btn-primary btn-sm" onClick={saveSettings}>Save &amp; reconnect</button>
                  <button className="btn btn-secondary btn-sm" onClick={runCheck} disabled={checking}>
                    {checking ? <RefreshCw size={12} className="spin" /> : <Cpu size={12} />}<span>Test</span>
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Body */}
          <div ref={scrollRef} style={{ flex: 1, overflowY: 'auto', padding: '12px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {offline ? (
              <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--warning)', fontWeight: 600, marginBottom: '6px' }}>
                  <AlertTriangle size={15} /> Ollama isn’t reachable
                </div>
                <p style={{ margin: '0 0 8px' }}>The assistant runs fully offline through a local Ollama server. To enable it:</p>
                <ol style={{ margin: '0 0 8px', paddingLeft: '18px' }}>
                  <li>Install Ollama (ollama.com), then start it: <code>ollama serve</code></li>
                  <li>Pull a small quantized model: <code>ollama pull {DEFAULT_MODEL}</code></li>
                  <li>Click <strong>Retry</strong> below.</li>
                </ol>
                {status?.error && <div style={{ color: 'var(--text-muted)', fontSize: '11px' }}>Details: {status.error}</div>}
                <button className="btn btn-primary btn-sm" style={{ marginTop: '8px' }} onClick={runCheck} disabled={checking}>
                  {checking ? <RefreshCw size={12} className="spin" /> : <RefreshCw size={12} />}<span>Retry</span>
                </button>
              </div>
            ) : messages.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: '12.5px', lineHeight: 1.55 }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '6px', marginBottom: '8px' }}>
                  <Eye size={14} style={{ color: 'var(--accent)', marginTop: '2px', flexShrink: 0 }} />
                  <span>
                    I read the current screen automatically (<strong>{activeTab.replace(/_/g, ' ')}</strong>) — no screenshot needed.
                    On the Byte Inspector I also decode the actual bytes (start codes, NAL types, text) so answers stay accurate.
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {QUICK_PROMPTS.map((p) => (
                    <button key={p} className="btn btn-secondary btn-sm" style={{ justifyContent: 'flex-start', textAlign: 'left' }} onClick={() => send(p)}>
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
                    maxWidth: '88%',
                    background: m.role === 'user' ? 'var(--accent)' : 'var(--surface-muted)',
                    color: m.role === 'user' ? '#fff' : 'var(--text-primary)',
                    border: m.role === 'user' ? 'none' : '1px solid var(--border-subtle)',
                    borderRadius: '10px', padding: '8px 10px',
                    fontSize: '12.5px', lineHeight: 1.5, whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                  }}
                >
                  {m.content || (streaming && i === messages.length - 1 ? <span style={{ color: 'var(--text-muted)' }}>▍</span> : '')}
                </div>
              ))
            )}
            {error && !offline && (
              <div style={{ fontSize: '11.5px', color: 'var(--danger)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <AlertTriangle size={13} /> {error}
              </div>
            )}
          </div>

          {/* Composer */}
          {!offline && (
            <div style={{ borderTop: '1px solid var(--border)', padding: '10px', display: 'flex', gap: '8px', alignItems: 'flex-end' }}>
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(input); }
                }}
                placeholder="Ask about the hex view, timeline, or anything on screen…"
                rows={1}
                style={{
                  flex: 1, resize: 'none', maxHeight: '96px', minHeight: '38px',
                  padding: '9px 10px', fontSize: '12.5px', borderRadius: '8px',
                  border: '1px solid var(--border)', background: 'var(--surface-sunken)', color: 'var(--text-primary)',
                }}
              />
              {streaming ? (
                <button className="btn btn-secondary" onClick={stop} title="Stop" style={{ height: '38px' }}>Stop</button>
              ) : (
                <button className="btn btn-primary" onClick={() => send(input)} disabled={!input.trim()} title="Send" style={{ height: '38px' }}>
                  <Send size={15} />
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </>
  );
};
