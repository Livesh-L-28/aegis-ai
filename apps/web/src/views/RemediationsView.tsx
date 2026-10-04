import React, { useState } from 'react';
import { Zap, Check, X, Play, ShieldAlert, AlertTriangle, Layers } from 'lucide-react';
import { aegisApi } from '../api/endpoints';
import type { RemediationProposal } from '../types';

interface RemediationsViewProps {
  remediations: RemediationProposal[];
  onRefresh: () => void;
}

export const RemediationsView: React.FC<RemediationsViewProps> = ({
  remediations,
  onRefresh,
}) => {
  const [actingId, setActingId] = useState<string | null>(null);

  const handleApprove = async (id: string) => {
    try {
      setActingId(id);
      await aegisApi.approveRemediation(id);
      onRefresh();
    } catch (err) {
      alert(`Approval error: ${err}`);
    } finally {
      setActingId(null);
    }
  };

  const handleReject = async (id: string) => {
    try {
      setActingId(id);
      await aegisApi.rejectRemediation(id);
      onRefresh();
    } catch (err) {
      alert(`Rejection error: ${err}`);
    } finally {
      setActingId(null);
    }
  };

  const handleExecute = async (id: string) => {
    try {
      setActingId(id);
      await aegisApi.executeRemediation(id);
      onRefresh();
    } catch (err) {
      alert(`Execution error: ${err}`);
    } finally {
      setActingId(null);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <div>
          <h1 style={styles.heading}>Remediation Center</h1>
          <p style={styles.subheading}>
            Typed Actions, Blast Radius Bounds, Preflights & Human Approval Gates
          </p>
        </div>
      </div>

      <div style={styles.grid}>
        {remediations.length === 0 ? (
          <div style={styles.emptyCard}>
            <Layers size={32} color="var(--text-muted)" />
            <p>No active remediation proposals in the system.</p>
          </div>
        ) : (
          remediations.map((rem) => (
            <div key={rem.id} style={styles.remCard}>
              <div style={styles.cardTop}>
                <div>
                  <div style={styles.actionType}>{rem.title || rem.action_type || 'Automated Remediation'}</div>
                  <div style={styles.targetService}>Target: {rem.service_name || rem.target_service || 'System'}</div>
                </div>
                <span
                  className={`badge ${
                    rem.status === 'SUCCEEDED'
                      ? 'badge-success'
                      : rem.status === 'PENDING_APPROVAL' || rem.status === 'PROPOSED'
                      ? 'badge-warning'
                      : rem.status === 'APPROVED'
                      ? 'badge-info'
                      : 'badge-neutral'
                  }`}
                >
                  {rem.status}
                </span>
              </div>

              <div style={styles.summaryBox}>{rem.description || rem.plan_summary || 'Targeted autonomous remediation plan.'}</div>

              <div style={styles.metricsRow}>
                <div>
                  <span style={styles.metaLabel}>Risk Level:</span>
                  <span
                    className={`badge ${
                      rem.risk_level === 'CRITICAL'
                        ? 'badge-danger'
                        : rem.risk_level === 'HIGH'
                        ? 'badge-warning'
                        : 'badge-neutral'
                    }`}
                  >
                    {rem.risk_level}
                  </span>
                </div>
                <div>
                  <span style={styles.metaLabel}>Blast Radius:</span>
                  <span style={styles.metaVal}>{rem.blast_radius?.affected_services?.join(', ') || rem.blast_radius_services?.join(', ') || rem.service_name || '1 service'}</span>
                </div>
              </div>

              {rem.rollback_strategy && (
                <div style={styles.rollbackBox}>
                  <span style={styles.metaLabel}>Rollback Strategy:</span>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                    {rem.rollback_strategy}
                  </span>
                </div>
              )}

              {/* Action Buttons */}
              <div style={styles.actionRow}>
                {rem.status === 'PENDING_APPROVAL' && (
                  <div style={styles.btnGroup}>
                    <button
                      className="btn btn-sm btn-danger"
                      onClick={() => handleReject(rem.id)}
                      disabled={actingId === rem.id}
                    >
                      <X size={12} /> Reject
                    </button>
                    <button
                      className="btn btn-sm btn-primary"
                      onClick={() => handleApprove(rem.id)}
                      disabled={actingId === rem.id}
                    >
                      <Check size={12} /> Human Approve
                    </button>
                  </div>
                )}

                {rem.status === 'APPROVED' && (
                  <button
                    className="btn btn-sm btn-primary"
                    onClick={() => handleExecute(rem.id)}
                    disabled={actingId === rem.id}
                  >
                    <Play size={12} /> Execute in Sandbox
                  </button>
                )}

                {rem.status === 'SUCCEEDED' && (
                  <span style={{ fontSize: '0.75rem', color: '#10b981', fontWeight: 600 }}>
                    ✓ Remediation validated & verified
                  </span>
                )}
              </div>
            </div>
          ))
        )}
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
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(380px, 1fr))',
    gap: '1.25rem',
  },
  remCard: {
    backgroundColor: 'var(--bg-card)',
    backdropFilter: 'blur(10px)',
    border: '1px solid var(--border-color)',
    borderRadius: '10px',
    padding: '1.25rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.85rem',
  },
  cardTop: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
  },
  actionType: {
    fontSize: '1rem',
    fontWeight: 600,
    color: 'var(--text-primary)',
  },
  targetService: {
    fontSize: '0.75rem',
    color: 'var(--accent-cyan)',
    fontFamily: 'monospace',
  },
  summaryBox: {
    fontSize: '0.8rem',
    color: 'var(--text-secondary)',
    lineHeight: 1.4,
  },
  metricsRow: {
    display: 'flex',
    justifyContent: 'space-between',
    fontSize: '0.75rem',
    borderTop: '1px solid var(--border-color)',
    paddingTop: '0.65rem',
  },
  metaLabel: {
    color: 'var(--text-muted)',
    marginRight: '0.4rem',
  },
  metaVal: {
    color: 'var(--text-primary)',
    fontWeight: 500,
  },
  rollbackBox: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.2rem',
  },
  actionRow: {
    display: 'flex',
    justifyContent: 'flex-end',
    borderTop: '1px solid var(--border-color)',
    paddingTop: '0.75rem',
  },
  btnGroup: {
    display: 'flex',
    gap: '0.5rem',
  },
  emptyCard: {
    gridColumn: '1 / -1',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '4rem 1rem',
    gap: '1rem',
    color: 'var(--text-muted)',
  },
};
