import React, { useEffect, useState } from 'react';
import {
  ArrowLeft,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Layers,
  HelpCircle,
  Brain,
  Shield,
  Play,
  RotateCcw,
  Check,
  RefreshCw,
} from 'lucide-react';
import { aegisApi } from '../api/endpoints';
import type {
  Incident,
  Investigation,
  EvidenceItem,
  Hypothesis,
  ReasoningResult,
  TimelineEntry,
  RemediationProposal,
} from '../types';

interface IncidentDetailViewProps {
  incidentId: string;
  onBack: () => void;
  onNavigateTab: (tab: any) => void;
}

export const IncidentDetailView: React.FC<IncidentDetailViewProps> = ({
  incidentId,
  onBack,
  onNavigateTab,
}) => {
  const [incident, setIncident] = useState<Incident | null>(null);
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [hypotheses, setHypotheses] = useState<Hypothesis[]>([]);
  const [reasoning, setReasoning] = useState<ReasoningResult | null>(null);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [remediations, setRemediations] = useState<RemediationProposal[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const fetchIncidentData = async () => {
    try {
      setLoading(true);
      const inc = await aegisApi.getIncident(incidentId);
      setIncident(inc);

      // Check if investigation exists or create one
      let invId = inc.investigations?.[0]?.id;
      if (!invId) {
        try {
          const existingInvs = await aegisApi.listIncidentInvestigations(incidentId);
          if (existingInvs && existingInvs.length > 0) {
            invId = existingInvs[0].id;
            setInvestigation(existingInvs[0]);
          }
        } catch {
          // ignore error
        }
      }

      if (!invId) {
        try {
          const newInv = await aegisApi.createInvestigation(incidentId);
          invId = newInv.id;
          setInvestigation(newInv);
        } catch {
          // might already exist
        }
      } else if (!investigation) {
        const inv = await aegisApi.getInvestigation(invId);
        setInvestigation(inv);
      }

      if (invId) {
        const [evList, hypList, resResult, timeList] = await Promise.all([
          aegisApi.getEvidence(invId).catch(() => []),
          aegisApi.getHypotheses(invId).catch(() => []),
          aegisApi.getReasoningResult(invId).catch(() => null),
          aegisApi.getTimeline(invId).catch(() => []),
        ]);
        setEvidence(evList);
        setHypotheses(hypList);
        setReasoning(resResult);
        setTimeline(timeList);
      }

      // Load associated remediations
      const allRem = await aegisApi.listRemediations().catch(() => []);
      setRemediations(allRem.filter((r) => r.incident_id === incidentId));
    } catch (err) {
      console.error('Failed to load incident detail:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidentData();
  }, [incidentId]);

  const handleRunInvestigation = async () => {
    if (!investigation) return;
    try {
      setActionLoading('investigating');
      await aegisApi.runInvestigation(investigation.id);
      await fetchIncidentData();
    } catch (err) {
      alert(`Investigation failed: ${err}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleProposeRemediation = async () => {
    try {
      setActionLoading('remediating');
      await aegisApi.createRemediation(incidentId);
      await fetchIncidentData();
    } catch (err) {
      alert(`Remediation proposal failed: ${err}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleApproveRemediation = async (remId: string) => {
    try {
      setActionLoading(remId);
      await aegisApi.approveRemediation(remId);
      await fetchIncidentData();
    } catch (err) {
      alert(`Approval error: ${err}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleExecuteRemediation = async (remId: string) => {
    try {
      setActionLoading(remId);
      await aegisApi.executeRemediation(remId);
      await fetchIncidentData();
    } catch (err) {
      alert(`Execution error: ${err}`);
    } finally {
      setActionLoading(null);
    }
  };

  if (loading && !incident) {
    return (
      <div style={styles.centerNotice}>
        <RefreshCw size={24} className="spin" color="var(--accent-cyan)" />
        <p>Loading Incident & AI Investigation Plane...</p>
      </div>
    );
  }

  if (!incident) {
    return (
      <div style={styles.centerNotice}>
        <p>Incident not found.</p>
        <button className="btn btn-sm" onClick={onBack}>
          Return to Incidents
        </button>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      {/* Back button & Title Bar */}
      <div style={styles.header}>
        <button className="btn btn-sm" onClick={onBack}>
          <ArrowLeft size={14} /> Back to Incidents
        </button>

        <div style={styles.headerMeta}>
          <span className={`badge ${incident.severity === 'CRITICAL' ? 'badge-danger' : 'badge-warning'}`}>
            {incident.severity}
          </span>
          <span className="badge badge-info">{incident.status}</span>
          {incident.service_name && <span style={styles.serviceBadge}>{incident.service_name}</span>}
        </div>
      </div>

      {/* Incident Title & Action Header */}
      <div style={styles.titleCard}>
        <div>
          <h1 style={styles.incidentTitle}>{incident.title}</h1>
          <p style={styles.incidentDesc}>{incident.description}</p>
        </div>

        <div style={styles.topActions}>
          {(!reasoning || reasoning.confidence === 0) && (
            <button
              className="btn btn-primary"
              onClick={handleRunInvestigation}
              disabled={actionLoading === 'investigating'}
            >
              {actionLoading === 'investigating' ? (
                <RefreshCw size={14} className="spin" />
              ) : (
                <Brain size={14} />
              )}
              Run AI Investigation
            </button>
          )}

          {reasoning && reasoning.confidence > 0 && remediations.length === 0 && (
            <button
              className="btn btn-primary"
              onClick={handleProposeRemediation}
              disabled={actionLoading === 'remediating'}
            >
              {actionLoading === 'remediating' ? (
                <RefreshCw size={14} className="spin" />
              ) : (
                <Play size={14} />
              )}
              Propose AI Remediation
            </button>
          )}
        </div>
      </div>

      {/* Structured Investigation Pipeline Sections */}
      <div style={styles.sectionsGrid}>
        {/* 1. Root Cause & AI Reasoning Engine */}
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <div style={styles.cardTitle}>
              <Brain size={16} color="var(--accent-cyan)" /> AI Root Cause & Reasoning
            </div>
            {reasoning && (
              <span className="badge badge-success">
                Confidence: {Math.round(reasoning.confidence * 100)}%
              </span>
            )}
          </div>

          <div style={styles.cardBody}>
            {reasoning ? (
              <div style={styles.reasoningContent}>
                <div style={styles.rcBox}>
                  <div style={styles.label}>Determined Root Cause</div>
                  <div style={styles.rcText}>{reasoning.root_cause}</div>
                </div>

                <div style={styles.label}>Summary</div>
                <p style={styles.summaryText}>{reasoning.summary}</p>

                {reasoning.recommended_actions?.length > 0 && (
                  <div>
                    <div style={styles.label}>Recommended Action</div>
                    <ul style={styles.recList}>
                      {reasoning.recommended_actions.map((act, i) => (
                        <li key={i}>{act}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ) : (
              <div style={styles.emptyNotice}>
                <HelpCircle size={20} color="var(--text-muted)" />
                <p>No causal diagnosis generated yet. Click "Run AI Investigation" above to execute.</p>
              </div>
            )}
          </div>
        </div>

        {/* 2. Remediation Proposals & Human Approval Boundary */}
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <div style={styles.cardTitle}>
              <Shield size={16} color="#10b981" /> Remediation & Policy Boundary
            </div>
          </div>

          <div style={styles.cardBody}>
            {remediations.length === 0 ? (
              <div style={styles.emptyNotice}>
                <p>No remediation proposals generated for this incident.</p>
              </div>
            ) : (
              remediations.map((rem) => (
                <div key={rem.id} style={styles.remItem}>
                  <div style={styles.remHead}>
                    <div>
                      <div style={styles.remActionName}>{rem.title || rem.action_type || 'Automated Remediation'}</div>
                      <div style={styles.remTarget}>Target: {rem.service_name || rem.target_service || 'System'}</div>
                    </div>
                    <span
                      className={`badge ${
                        rem.status === 'SUCCEEDED'
                          ? 'badge-success'
                          : rem.status === 'PENDING_APPROVAL' || rem.status === 'PROPOSED'
                          ? 'badge-warning'
                          : 'badge-info'
                      }`}
                    >
                      {rem.status}
                    </span>
                  </div>

                  <p style={styles.remSummary}>{rem.description || rem.plan_summary || 'Targeted autonomous remediation plan.'}</p>

                  <div style={styles.remMetadata}>
                    <span>Risk: <strong>{rem.risk_level}</strong></span>
                    <span>Blast Radius: <strong>{rem.blast_radius?.affected_services?.join(', ') || rem.blast_radius_services?.join(', ') || rem.service_name || '1 service'}</strong></span>
                  </div>

                  {/* Policy and Actions */}
                  <div style={styles.remActionRow}>
                    {rem.status === 'PENDING_APPROVAL' && (
                      <button
                        className="btn btn-sm btn-primary"
                        onClick={() => handleApproveRemediation(rem.id)}
                        disabled={actionLoading === rem.id}
                      >
                        <Check size={12} /> Approve Action
                      </button>
                    )}

                    {rem.status === 'APPROVED' && (
                      <button
                        className="btn btn-sm btn-primary"
                        onClick={() => handleExecuteRemediation(rem.id)}
                        disabled={actionLoading === rem.id}
                      >
                        <Play size={12} /> Execute in Sandbox
                      </button>
                    )}

                    {rem.status === 'SUCCEEDED' && (
                      <span className="badge badge-success">
                        <CheckCircle2 size={12} /> Validated & Resolved
                      </span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Timeline & Evidence Columns */}
      <div style={styles.sectionsGrid}>
        {/* Timeline */}
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <div style={styles.cardTitle}>
              <Clock size={16} color="var(--accent-cyan)" /> Incident & Evidence Timeline
            </div>
          </div>
          <div style={styles.cardBody}>
            {timeline.length === 0 ? (
              <div style={styles.emptyNotice}>No timeline events registered.</div>
            ) : (
              <div style={styles.timelineList}>
                {timeline.map((entry, idx) => (
                  <div key={idx} style={styles.timelineItem}>
                    <div style={styles.timelineDot}></div>
                    <div>
                      <div style={styles.timelineTime}>
                        {new Date(entry.timestamp).toLocaleTimeString()}
                      </div>
                      <div style={styles.timelineTitle}>{entry.title}</div>
                      <div style={styles.timelineDetails}>{entry.description || entry.details}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Evidence Items */}
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <div style={styles.cardTitle}>
              <Layers size={16} color="#a855f7" /> Collected Signals & Evidence ({evidence.length})
            </div>
          </div>
          <div style={styles.cardBody}>
            {evidence.length === 0 ? (
              <div style={styles.emptyNotice}>No evidence collected.</div>
            ) : (
              <div style={styles.evidenceList}>
                {evidence.map((ev) => (
                  <div key={ev.id} style={styles.evidenceRow}>
                    <div style={styles.evHead}>
                      <span className="badge badge-neutral">{ev.evidence_type}</span>
                      <span style={styles.evSource}>{ev.source}</span>
                      <span style={styles.evConf}>Score: {ev.relevance_score}</span>
                    </div>
                    <div style={styles.evContent}>{ev.content}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
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
  headerMeta: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.65rem',
  },
  serviceBadge: {
    fontSize: '0.75rem',
    fontFamily: 'monospace',
    color: 'var(--accent-cyan)',
    backgroundColor: 'var(--bg-card)',
    padding: '0.2rem 0.5rem',
    borderRadius: '4px',
    border: '1px solid var(--border-color)',
  },
  titleCard: {
    backgroundColor: 'var(--bg-card)',
    backdropFilter: 'blur(10px)',
    border: '1px solid var(--border-color)',
    borderRadius: '10px',
    padding: '1.25rem',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    gap: '1rem',
  },
  incidentTitle: {
    fontSize: '1.35rem',
    fontWeight: 700,
    color: 'var(--text-primary)',
  },
  incidentDesc: {
    fontSize: '0.85rem',
    color: 'var(--text-secondary)',
    marginTop: '0.35rem',
    lineHeight: 1.4,
  },
  topActions: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
  },
  sectionsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))',
    gap: '1.25rem',
  },
  card: {
    backgroundColor: 'var(--bg-card)',
    backdropFilter: 'blur(10px)',
    border: '1px solid var(--border-color)',
    borderRadius: '10px',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  },
  cardHeader: {
    padding: '0.9rem 1.15rem',
    borderBottom: '1px solid var(--border-color)',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    background: 'var(--bg-elevated)',
  },
  cardTitle: {
    fontSize: '0.875rem',
    fontWeight: 600,
    color: 'var(--text-primary)',
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
  },
  cardBody: {
    padding: '1.15rem',
    flex: 1,
    overflowY: 'auto',
  },
  reasoningContent: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.85rem',
  },
  label: {
    fontSize: '0.7rem',
    textTransform: 'uppercase',
    color: 'var(--text-muted)',
    fontWeight: 700,
    letterSpacing: '0.04em',
    marginBottom: '0.2rem',
  },
  rcBox: {
    backgroundColor: 'rgba(56, 189, 248, 0.08)',
    border: '1px solid rgba(56, 189, 248, 0.3)',
    borderRadius: '6px',
    padding: '0.75rem',
  },
  rcText: {
    fontSize: '0.9rem',
    fontWeight: 600,
    color: 'var(--accent-cyan)',
  },
  summaryText: {
    fontSize: '0.825rem',
    color: 'var(--text-secondary)',
    lineHeight: 1.4,
  },
  recList: {
    paddingLeft: '1.2rem',
    fontSize: '0.825rem',
    color: 'var(--text-primary)',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem',
  },
  emptyNotice: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '2rem 1rem',
    color: 'var(--text-muted)',
    fontSize: '0.825rem',
    textAlign: 'center',
  },
  remItem: {
    backgroundColor: 'var(--bg-elevated)',
    border: '1px solid var(--border-color)',
    borderRadius: '8px',
    padding: '0.85rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem',
  },
  remHead: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
  },
  remActionName: {
    fontSize: '0.85rem',
    fontWeight: 600,
    color: 'var(--text-primary)',
  },
  remTarget: {
    fontSize: '0.75rem',
    color: 'var(--accent-cyan)',
    fontFamily: 'monospace',
  },
  remSummary: {
    fontSize: '0.775rem',
    color: 'var(--text-secondary)',
  },
  remMetadata: {
    display: 'flex',
    gap: '1rem',
    fontSize: '0.72rem',
    color: 'var(--text-muted)',
  },
  remActionRow: {
    display: 'flex',
    justifyContent: 'flex-end',
    marginTop: '0.35rem',
  },
  timelineList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.75rem',
  },
  timelineItem: {
    display: 'flex',
    gap: '0.75rem',
    alignItems: 'flex-start',
  },
  timelineDot: {
    width: '8px',
    height: '8px',
    borderRadius: '50%',
    backgroundColor: 'var(--accent-cyan)',
    marginTop: '0.3rem',
    flexShrink: 0,
  },
  timelineTime: {
    fontSize: '0.7rem',
    color: 'var(--text-muted)',
    fontFamily: 'monospace',
  },
  timelineTitle: {
    fontSize: '0.8rem',
    fontWeight: 600,
    color: 'var(--text-primary)',
  },
  timelineDetails: {
    fontSize: '0.75rem',
    color: 'var(--text-secondary)',
    marginTop: '0.15rem',
    lineHeight: 1.4,
  },
  evidenceList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.65rem',
  },
  evidenceRow: {
    backgroundColor: 'var(--bg-elevated)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.65rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem',
  },
  evHead: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
  },
  evSource: {
    fontSize: '0.72rem',
    color: 'var(--text-muted)',
    fontFamily: 'monospace',
  },
  evConf: {
    marginLeft: 'auto',
    fontSize: '0.7rem',
    color: 'var(--accent-cyan)',
  },
  evContent: {
    fontSize: '0.75rem',
    color: 'var(--text-secondary)',
    fontFamily: 'monospace',
    whiteSpace: 'pre-wrap',
    lineHeight: 1.4,
  },
  centerNotice: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100%',
    gap: '1rem',
    color: 'var(--text-secondary)',
  },
};
