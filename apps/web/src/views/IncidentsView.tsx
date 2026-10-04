import React, { useState } from 'react';
import { AlertTriangle, Filter, Search, ArrowRight, ShieldCheck } from 'lucide-react';
import type { Incident } from '../types';

interface IncidentsViewProps {
  incidents: Incident[];
  onSelectIncident: (id: string) => void;
}

export const IncidentsView: React.FC<IncidentsViewProps> = ({ incidents, onSelectIncident }) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filtered = incidents.filter((inc) => {
    if (filterSeverity !== 'ALL' && inc.severity !== filterSeverity) return false;
    if (filterStatus !== 'ALL' && inc.status !== filterStatus) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        (inc.title || '').toLowerCase().includes(q) ||
        (inc.service_name || '').toLowerCase().includes(q) ||
        (inc.id || '').toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div style={styles.container}>
      {/* Title */}
      <div style={styles.header}>
        <div>
          <h1 style={styles.heading}>Incident Center</h1>
          <p style={styles.subheading}>
            Autonomous Ingestion, Signal Correlation & Root Cause Investigations
          </p>
        </div>
      </div>

      {/* Filters Toolbar */}
      <div style={styles.toolbar}>
        <div style={styles.searchBox}>
          <Search size={14} color="var(--text-muted)" />
          <input
            style={styles.searchInput}
            placeholder="Search by title, service, or incident ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <div style={styles.filterGroup}>
          <select
            style={styles.select}
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
          >
            <option value="ALL">Severity: All</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            style={styles.select}
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
          >
            <option value="ALL">Status: All</option>
            <option value="DETECTED">Detected</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="REASONING">Reasoning</option>
            <option value="REMEDIATING">Remediating</option>
            <option value="RESOLVED">Resolved</option>
          </select>
        </div>
      </div>

      {/* Table Card */}
      <div style={styles.card}>
        <table style={styles.table}>
          <thead>
            <tr style={styles.thRow}>
              <th style={styles.th}>Incident ID</th>
              <th style={styles.th}>Title</th>
              <th style={styles.th}>Service</th>
              <th style={styles.th}>Severity</th>
              <th style={styles.th}>Status</th>
              <th style={styles.th}>Detected At</th>
              <th style={styles.th}>Action</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} style={styles.emptyTd}>
                  No matching incidents found.
                </td>
              </tr>
            ) : (
              filtered.map((inc) => (
                <tr key={inc.id} style={styles.tr} onClick={() => onSelectIncident(inc.id)}>
                  <td style={styles.tdId}>{inc.id.slice(0, 8)}...</td>
                  <td style={styles.tdTitle}>
                    <div style={{ fontWeight: 600 }}>{inc.title}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {inc.description}
                    </div>
                  </td>
                  <td style={styles.tdService}>{inc.service_name}</td>
                  <td style={styles.td}>
                    <span
                      className={`badge ${
                        inc.severity === 'CRITICAL'
                          ? 'badge-danger'
                          : inc.severity === 'HIGH'
                          ? 'badge-warning'
                          : 'badge-info'
                      }`}
                    >
                      {inc.severity}
                    </span>
                  </td>
                  <td style={styles.td}>
                    <span
                      className={`badge ${
                        inc.status === 'RESOLVED' ? 'badge-success' : 'badge-neutral'
                      }`}
                    >
                      {inc.status}
                    </span>
                  </td>
                  <td style={styles.tdTime}>
                    {new Date(inc.detected_at).toLocaleTimeString()}
                  </td>
                  <td style={styles.tdAction}>
                    <button className="btn btn-sm btn-primary">
                      Open <ArrowRight size={12} />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
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
  toolbar: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: '1rem',
  },
  searchBox: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.4rem 0.75rem',
    width: '380px',
  },
  searchInput: {
    background: 'transparent',
    border: 'none',
    color: 'var(--text-primary)',
    fontSize: '0.825rem',
    outline: 'none',
    width: '100%',
  },
  filterGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
  },
  select: {
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    color: 'var(--text-primary)',
    padding: '0.4rem 0.75rem',
    fontSize: '0.825rem',
    outline: 'none',
  },
  card: {
    backgroundColor: 'var(--bg-card)',
    backdropFilter: 'blur(10px)',
    border: '1px solid var(--border-color)',
    borderRadius: '10px',
    overflow: 'hidden',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    textAlign: 'left',
    fontSize: '0.825rem',
  },
  thRow: {
    borderBottom: '1px solid var(--border-color)',
    background: 'var(--bg-elevated)',
  },
  th: {
    padding: '0.85rem 1rem',
    color: 'var(--text-secondary)',
    fontWeight: 600,
    textTransform: 'uppercase',
    fontSize: '0.7rem',
    letterSpacing: '0.04em',
  },
  tr: {
    borderBottom: '1px solid var(--border-color)',
    cursor: 'pointer',
    transition: 'background 0.1s ease',
  },
  td: {
    padding: '0.85rem 1rem',
    verticalAlign: 'middle',
  },
  tdId: {
    padding: '0.85rem 1rem',
    fontFamily: 'monospace',
    color: 'var(--accent-cyan)',
    fontSize: '0.75rem',
  },
  tdTitle: {
    padding: '0.85rem 1rem',
    maxWidth: '300px',
  },
  tdService: {
    padding: '0.85rem 1rem',
    fontFamily: 'monospace',
    color: 'var(--text-secondary)',
  },
  tdTime: {
    padding: '0.85rem 1rem',
    color: 'var(--text-muted)',
    fontSize: '0.75rem',
  },
  tdAction: {
    padding: '0.85rem 1rem',
    textAlign: 'right',
  },
  emptyTd: {
    padding: '3rem 1rem',
    textAlign: 'center',
    color: 'var(--text-muted)',
  },
};
