import React from 'react';
import { FileText, Shield, User, Clock, Hash, Download } from 'lucide-react';
import type { AuditEvent } from '../types';

interface AuditViewProps {
  auditEvents: AuditEvent[];
}

export const AuditView: React.FC<AuditViewProps> = ({ auditEvents }) => {
  const exportAsJSON = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(auditEvents, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `aegis_audit_trail_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const exportAsCSV = () => {
    if (auditEvents.length === 0) return;
    const headers = ['id', 'created_at', 'actor_user_id', 'action', 'resource_type', 'resource_id', 'request_id'];
    const rows = auditEvents.map((e) => [
      e.id,
      e.created_at,
      e.actor_user_id,
      e.action,
      e.resource_type,
      e.resource_id,
      e.request_id || '',
    ]);
    const csvContent =
      'data:text/csv;charset=utf-8,' +
      [headers.join(','), ...rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(','))].join('\n');
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', encodeURI(csvContent));
    downloadAnchor.setAttribute('download', `aegis_audit_trail_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <div>
          <h1 style={styles.heading}>Immutable Audit Trail</h1>
          <p style={styles.subheading}>
            Append-Only Cryptographic Log of Tenant Actions, AI Invocations & Remediation Executions
          </p>
        </div>
        <div style={styles.exportGroup}>
          <button className="btn btn-sm" onClick={exportAsCSV} title="Export audit log to CSV for compliance auditors">
            <Download size={13} /> Export CSV
          </button>
          <button className="btn btn-sm btn-primary" onClick={exportAsJSON} title="Export full JSON payload">
            <Download size={13} /> Export JSON
          </button>
        </div>
      </div>

      <div style={styles.card}>
        <table style={styles.table}>
          <thead>
            <tr style={styles.thRow}>
              <th style={styles.th}>Timestamp</th>
              <th style={styles.th}>Actor</th>
              <th style={styles.th}>Action</th>
              <th style={styles.th}>Resource</th>
              <th style={styles.th}>Request ID</th>
              <th style={styles.th}>Details</th>
            </tr>
          </thead>
          <tbody>
            {auditEvents.length === 0 ? (
              <tr>
                <td colSpan={6} style={styles.emptyTd}>
                  No audit events recorded yet.
                </td>
              </tr>
            ) : (
              auditEvents.map((evt) => (
                <tr key={evt.id} style={styles.tr}>
                  <td style={styles.tdTime}>
                    {new Date(evt.created_at).toLocaleString()}
                  </td>
                  <td style={styles.tdActor}>
                    <span style={styles.actorChip}>
                      <User size={12} /> {evt.actor_user_id}
                    </span>
                  </td>
                  <td style={styles.tdAction}>
                    <span className="badge badge-info">{evt.action}</span>
                  </td>
                  <td style={styles.tdResource}>
                    {evt.resource_type}: {evt.resource_id.slice(0, 8)}...
                  </td>
                  <td style={styles.tdReqId}>{evt.request_id?.slice(0, 8) || 'system'}</td>
                  <td style={styles.tdMeta}>
                    <pre style={styles.metaJson}>{JSON.stringify(evt.event_metadata)}</pre>
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
  exportGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.65rem',
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
  },
  tdTime: {
    padding: '0.85rem 1rem',
    color: 'var(--text-muted)',
    fontSize: '0.75rem',
    fontFamily: 'monospace',
    whiteSpace: 'nowrap',
  },
  tdActor: {
    padding: '0.85rem 1rem',
  },
  actorChip: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.35rem',
    fontSize: '0.75rem',
    color: 'var(--text-primary)',
    fontFamily: 'monospace',
  },
  tdAction: {
    padding: '0.85rem 1rem',
  },
  tdResource: {
    padding: '0.85rem 1rem',
    fontSize: '0.75rem',
    color: 'var(--text-secondary)',
    fontFamily: 'monospace',
  },
  tdReqId: {
    padding: '0.85rem 1rem',
    fontSize: '0.72rem',
    color: 'var(--accent-cyan)',
    fontFamily: 'monospace',
  },
  tdMeta: {
    padding: '0.85rem 1rem',
    maxWidth: '280px',
  },
  metaJson: {
    fontFamily: 'monospace',
    fontSize: '0.7rem',
    color: 'var(--text-muted)',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  emptyTd: {
    padding: '3rem 1rem',
    textAlign: 'center',
    color: 'var(--text-muted)',
  },
};
