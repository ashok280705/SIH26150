// ── Offline assistant service (local Ollama) ─────────────────────────────────
//
// Talks to a locally running Ollama server. In dev the browser calls the same-origin
// path `/ollama/...`, which Vite proxies to http://127.0.0.1:11434 (see vite.config.ts),
// so there is no CORS setup to do. The base URL can be overridden (persisted in
// localStorage) if the operator runs Ollama elsewhere — note a direct cross-origin URL
// requires setting OLLAMA_ORIGINS on the Ollama side.
//
// Everything here is local: no data leaves the machine.

const BASE_KEY = 'assistant_ollama_base';
const MODEL_KEY = 'assistant_ollama_model';

/** Default small, quantized instruct model bundled with the project. The assistant
 *  also auto-selects whatever model is actually installed if this one is absent. */
export const DEFAULT_MODEL = 'qwen2.5:0.5b';
export const DEFAULT_BASE = '/ollama';

export function getBase(): string {
  return (localStorage.getItem(BASE_KEY) || DEFAULT_BASE).replace(/\/+$/, '');
}
export function setBase(v: string) {
  localStorage.setItem(BASE_KEY, v.trim());
}
export function getModel(): string {
  return localStorage.getItem(MODEL_KEY) || DEFAULT_MODEL;
}
export function setModel(v: string) {
  localStorage.setItem(MODEL_KEY, v.trim());
}

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface OllamaStatus {
  ok: boolean;
  models: string[];
  error?: string;
}

/** Verify Ollama is reachable and list installed models. */
export async function checkOllama(base = getBase()): Promise<OllamaStatus> {
  try {
    const res = await fetch(`${base}/api/tags`, { method: 'GET' });
    if (!res.ok) return { ok: false, models: [], error: `Ollama responded ${res.status}` };
    const data = await res.json();
    const models: string[] = Array.isArray(data?.models) ? data.models.map((m: any) => m.name).filter(Boolean) : [];
    return { ok: true, models };
  } catch (e: any) {
    return { ok: false, models: [], error: e?.message || 'Could not reach Ollama' };
  }
}

/**
 * Stream a chat completion from Ollama, invoking `onToken` for each incremental
 * content chunk. Resolves when the stream completes. `signal` cancels the request.
 */
export async function streamChat(
  messages: ChatMessage[],
  onToken: (delta: string) => void,
  opts: { model?: string; base?: string; signal?: AbortSignal } = {},
): Promise<void> {
  const base = opts.base ?? getBase();
  const model = opts.model ?? getModel();

  const res = await fetch(`${base}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model,
      messages,
      stream: true,
      // Low temperature: keep the small local model grounded and non-inventive.
      options: { temperature: 0.1, top_p: 0.9 },
    }),
    signal: opts.signal,
  });

  if (!res.ok) {
    let detail = `Ollama error ${res.status}`;
    try {
      const j = await res.json();
      if (j?.error) detail = j.error;
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  if (!res.body) throw new Error('Ollama returned no response body');

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  // Ollama streams newline-delimited JSON objects.
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let nl: number;
    while ((nl = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (!line) continue;
      try {
        const obj = JSON.parse(line);
        const delta: string | undefined = obj?.message?.content;
        if (delta) onToken(delta);
        if (obj?.error) throw new Error(obj.error);
      } catch (e) {
        // A malformed partial line can occur at chunk boundaries; ignore unless it's a
        // real thrown error above.
        if (e instanceof Error && e.message && !e.message.startsWith('Unexpected')) throw e;
      }
    }
  }
}
