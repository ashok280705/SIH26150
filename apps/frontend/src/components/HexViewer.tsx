import React, { useState, useEffect } from 'react';
import { Binary, ArrowRight, RefreshCw, AlertCircle } from 'lucide-react';
import { readEvidenceBytes } from '../services/api';
import { HexChunkResponse } from '../types';

interface HexViewerProps {
  evidenceId: string | null;
  initialOffset?: number;
}

export const HexViewer: React.FC<HexViewerProps> = ({ evidenceId, initialOffset }) => {
  const [offset, setOffset] = useState<number>(initialOffset || 0);
  const [length, setLength] = useState<number>(256);
  const [chunk, setChunk] = useState<HexChunkResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (initialOffset !== undefined) {
      setOffset(initialOffset);
      if (evidenceId) {
        // Automatically fetch when initialOffset changes
        handleFetchBytesForOffset(initialOffset);
      }
    }
  }, [initialOffset, evidenceId]);

  const handleFetchBytesForOffset = async (targetOffset: number) => {
    setLoading(true);
    setError(null);
    try {
      const data = await readEvidenceBytes(evidenceId!, targetOffset, length);
      setChunk(data);
    } catch (err: any) {
      setError(err.message || 'Failed to read evidence bytes');
    } finally {
      setLoading(false);
    }
  };

  const handleFetchBytes = () => {
    if (!evidenceId) return;
    handleFetchBytesForOffset(offset);
  };

  const renderFormattedHex = (hexStr: string, startOffset: number) => {
    const bytes: string[] = [];
    for (let i = 0; i < hexStr.length; i += 2) {
      bytes.push(hexStr.substring(i, i + 2));
    }

    const rows: { offsetStr: string; hexStr: string; asciiStr: string }[] = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const slice = bytes.slice(i, i + 16);
      const rowOffset = startOffset + i;
      const offsetStr = '0x' + rowOffset.toString(16).padStart(8, '0').toUpperCase();
      
      const hexParts = slice.join(' ').toUpperCase();
      const padding = '   '.repeat(16 - slice.length);
      
      const asciiParts = slice
        .map((b) => {
          const code = parseInt(b, 16);
          return code >= 32 && code <= 126 ? String.fromCharCode(code) : '.';
        })
        .join('');

      rows.push({
        offsetStr,
        hexStr: hexParts + padding,
        asciiStr: asciiParts,
      });
    }

    return (
      <div className="hex-viewer-box">
        {rows.map((r, idx) => (
          <div key={idx} className="hex-row">
            <span className="hex-offset">{r.offsetStr}</span>
            <span className="hex-bytes">{r.hexStr}</span>
            <span className="hex-ascii">{r.asciiStr}</span>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Binary size={16} color="var(--accent-primary)" />
          <span>Evidence Byte Inspector (Read-Only via EvidenceReader)</span>
        </div>
        {chunk && (
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Source Length: {(chunk.total_source_len / (1024 * 1024)).toFixed(2)} MB ({chunk.total_source_len} B)
          </span>
        )}
      </div>

      {!evidenceId ? (
        <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
          <AlertCircle size={24} style={{ margin: '0 auto 8px', display: 'block' }} />
          <span>No evidence selected. Please register or select an evidence target first.</span>
        </div>
      ) : (
        <>
          <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-end', marginBottom: '16px' }}>
            <div style={{ width: '160px' }}>
              <label className="form-label">Offset (Bytes / 0xHex)</label>
              <input
                type="number"
                className="form-input"
                value={offset}
                onChange={(e) => setOffset(Math.max(0, parseInt(e.target.value) || 0))}
              />
            </div>
            <div style={{ width: '140px' }}>
              <label className="form-label">Length (Max 64KB)</label>
              <input
                type="number"
                className="form-input"
                value={length}
                onChange={(e) => setLength(Math.min(65536, Math.max(16, parseInt(e.target.value) || 16)))}
              />
            </div>
            <button className="btn btn-primary" onClick={handleFetchBytes} disabled={loading}>
              {loading ? <RefreshCw size={14} className="spin" /> : <ArrowRight size={14} />}
              <span>Inspect Chunk</span>
            </button>
          </div>

          {error && (
            <div style={{ color: '#991b1b', background: '#fee2e2', padding: '10px', borderRadius: '4px', marginBottom: '14px' }}>
              <strong>Error:</strong> {error}
            </div>
          )}

          {chunk && renderFormattedHex(chunk.hex, chunk.offset)}
        </>
      )}
    </div>
  );
};
