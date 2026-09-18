import React, { useState, useEffect } from 'react';
import { Binary, ArrowRight, RefreshCw, AlertCircle, Search } from 'lucide-react';
import { readEvidenceBytes, searchEvidence } from '../services/api';
import { HexChunkResponse } from '../types';
import { ContextHelp } from './onboarding/ContextHelp';

interface HexViewerProps {
  evidenceId: string | null;
  initialOffset?: number;
}

export const HexViewer: React.FC<HexViewerProps> = ({ evidenceId, initialOffset }) => {
  // Using string for offset to avoid precision loss on large 64-bit integers in JS
  const [offsetStr, setOffsetStr] = useState<string>(initialOffset ? initialOffset.toString() : '0');
  const [length, setLength] = useState<number>(256);
  
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [searchType, setSearchType] = useState<'hex' | 'ascii'>('ascii');
  const [isSearching, setIsSearching] = useState(false);

  const [chunk, setChunk] = useState<HexChunkResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (initialOffset !== undefined) {
      setOffsetStr(initialOffset.toString());
      if (evidenceId) {
        handleFetchBytesForOffset(initialOffset.toString());
      }
    }
  }, [initialOffset, evidenceId]);

  const handleFetchBytesForOffset = async (targetOffsetStr: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await readEvidenceBytes(evidenceId!, parseInt(targetOffsetStr) || 0, length);
      setChunk(data);
    } catch (err: any) {
      setError(err.message || 'Failed to read evidence bytes');
    } finally {
      setLoading(false);
    }
  };

  const handleFetchBytes = () => {
    if (!evidenceId) return;
    handleFetchBytesForOffset(offsetStr);
  };

  const handleSearch = async () => {
    if (!evidenceId || !searchTerm) return;
    setIsSearching(true);
    setError(null);
    try {
      const data = await searchEvidence(evidenceId, offsetStr, searchTerm, searchType);
      if (data.found_offset !== null) {
        setOffsetStr(data.found_offset.toString());
        await handleFetchBytesForOffset(data.found_offset.toString());
      } else {
        setError('Pattern not found within the 1GB search limit from the current offset.');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to search evidence');
    } finally {
      setIsSearching(false);
    }
  };

  const renderFormattedHex = (hexStr: string, startOffsetNum: number) => {
    const bytes: string[] = [];
    for (let i = 0; i < hexStr.length; i += 2) {
      bytes.push(hexStr.substring(i, i + 2));
    }

    const rows: { offsetStr: string; hexStr: string; asciiStr: string }[] = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const slice = bytes.slice(i, i + 16);
      const rowOffset = startOffsetNum + i;
      const offsetHex = '0x' + rowOffset.toString(16).padStart(8, '0').toUpperCase();
      
      const hexParts = slice.join(' ').toUpperCase();
      const padding = '   '.repeat(16 - slice.length);
      
      const asciiParts = slice
        .map((b) => {
          const code = parseInt(b, 16);
          return code >= 32 && code <= 126 ? String.fromCharCode(code) : '.';
        })
        .join('');

      rows.push({
        offsetStr: offsetHex,
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
    <div className="panel" data-tour="hex-viewer-panel">
      <div className="panel-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Binary size={16} style={{ color: 'var(--accent)' }} />
          <span>Evidence Byte Inspector (Read-Only via EvidenceReader)</span>
          <ContextHelp
            title="Read-Only Byte Inspector"
            content="Inspect raw evidence bytes and hex offsets directly. Reads stream strictly through the EvidenceReader without touching or modifying source media."
          />
        </div>
        {chunk && (
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Source Length: {(chunk.total_source_len / (1024 * 1024)).toFixed(2)} MB ({chunk.total_source_len} B)
          </span>
        )}
      </div>

      {!evidenceId ? (
        <div className="empty-state">
          <Binary size={32} />
          <h3>No Evidence Selected</h3>
          <p>Please register or select an evidence target first.</p>
        </div>
      ) : (
        <>
          <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-end', marginBottom: '16px' }}>
            <div style={{ width: '180px' }}>
              <label className="form-label">Offset (Decimal)</label>
              <input
                type="text"
                className="form-input"
                value={offsetStr}
                onChange={(e) => setOffsetStr(e.target.value.replace(/\D/g, ''))}
                placeholder="0"
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

          <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-end', marginBottom: '16px', background: 'var(--surface-muted)', padding: '12px', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
            <div style={{ width: '120px' }}>
              <label className="form-label">Search Type</label>
              <select className="form-select" value={searchType} onChange={(e) => setSearchType(e.target.value as any)}>
                <option value="ascii">ASCII</option>
                <option value="hex">Hex (e.g. FFD8)</option>
              </select>
            </div>
            <div style={{ flex: 1 }}>
              <label className="form-label">Search Pattern (scans forward up to 1GB)</label>
              <input
                type="text"
                className="form-input"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder={searchType === 'hex' ? 'e.g. FFD8FFE0' : 'e.g. password'}
              />
            </div>
            <button className="btn btn-secondary" onClick={handleSearch} disabled={isSearching || !searchTerm}>
              {isSearching ? <RefreshCw size={14} className="spin" /> : <Search size={14} />}
              <span>{isSearching ? 'Searching...' : 'Search Forward'}</span>
            </button>
          </div>

          {error && (
            <div className="alert alert-error">
              <AlertCircle size={16} />
              <div><strong>Error:</strong> {error}</div>
            </div>
          )}

          {chunk && renderFormattedHex(chunk.hex, chunk.offset)}
        </>
      )}
    </div>
  );
};
