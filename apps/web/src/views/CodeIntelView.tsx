import React, { useState } from 'react';
import { Terminal, Search, Code, FileCode } from 'lucide-react';
import { aegisApi } from '../api/endpoints';
import type { CodeSymbol } from '../types';

export const CodeIntelView: React.FC = () => {
  const [query, setQuery] = useState<string>('order');
  const [results, setResults] = useState<CodeSymbol[]>([]);
  const [loading, setLoading] = useState<boolean>(false);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query) return;
    try {
      setLoading(true);
      const res = await aegisApi.searchCodeSymbols(query);
      setResults(res.code_matches || []);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <div>
          <h1 style={styles.heading}>Code Intelligence</h1>
          <p style={styles.subheading}>
            AST Symbol Extraction, Function Call Graphs & Deterministic Provenance
          </p>
        </div>
      </div>

      <form onSubmit={handleSearch} style={styles.searchBar}>
        <Search size={16} color="var(--text-muted)" />
        <input
          style={styles.searchInput}
          placeholder="Search symbols (e.g. order, user, payment, database)..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <button type="submit" className="btn btn-sm btn-primary" disabled={loading}>
          {loading ? 'Searching...' : 'Search'}
        </button>
      </form>

      <div style={styles.resultsCard}>
        <div style={styles.cardHeader}>
          <h2 style={styles.cardTitle}>Indexed Symbols ({results.length})</h2>
        </div>
        <div style={styles.cardBody}>
          {results.length === 0 ? (
            <div style={styles.emptyNotice}>
              <Code size={24} color="var(--text-muted)" />
              <p>Search AST symbols across the repository codebase.</p>
            </div>
          ) : (
            results.map((sym, i) => (
              <div key={i} style={styles.symbolRow}>
                <div style={styles.symHeader}>
                  <span className="badge badge-info">{sym.symbol_type}</span>
                  <span style={styles.symName}>{sym.name}</span>
                  <span style={styles.symPath}>
                    {sym.file_path}:{sym.line_number}
                  </span>
                </div>
                {sym.signature && <div style={styles.symSig}>{sym.signature}</div>}
                {sym.docstring && <div style={styles.symDoc}>{sym.docstring}</div>}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  container: {
    padding: '1.75rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '1.25rem',
    height: '100%',
    overflowY: 'auto',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  heading: {
    fontSize: '1.4rem',
    fontWeight: 700,
    color: 'var(--text-primary)',
  },
  subheading: {
    fontSize: '0.825rem',
    color: 'var(--text-secondary)',
    marginTop: '0.2rem',
  },
  searchBar: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-color)',
    borderRadius: '8px',
    padding: '0.6rem 1rem',
  },
  searchInput: {
    flex: 1,
    background: 'transparent',
    border: 'none',
    color: 'var(--text-primary)',
    fontSize: '0.85rem',
    outline: 'none',
  },
  resultsCard: {
    backgroundColor: 'var(--bg-card)',
    backdropFilter: 'blur(10px)',
    border: '1px solid var(--border-color)',
    borderRadius: '10px',
    overflow: 'hidden',
  },
  cardHeader: {
    padding: '1rem 1.25rem',
    borderBottom: '1px solid var(--border-color)',
    background: 'var(--bg-elevated)',
  },
  cardTitle: {
    fontSize: '0.925rem',
    fontWeight: 600,
    color: 'var(--text-primary)',
  },
  cardBody: {
    padding: '1.25rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.75rem',
  },
  symbolRow: {
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.75rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.35rem',
  },
  symHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.65rem',
  },
  symName: {
    fontSize: '0.875rem',
    fontWeight: 600,
    color: 'var(--text-primary)',
    fontFamily: 'monospace',
  },
  symPath: {
    marginLeft: 'auto',
    fontSize: '0.72rem',
    color: 'var(--text-muted)',
    fontFamily: 'monospace',
  },
  symSig: {
    fontSize: '0.775rem',
    color: 'var(--accent-cyan)',
    fontFamily: 'monospace',
  },
  symDoc: {
    fontSize: '0.75rem',
    color: 'var(--text-secondary)',
  },
  emptyNotice: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '3rem 1rem',
    color: 'var(--text-muted)',
    gap: '0.75rem',
  },
};
