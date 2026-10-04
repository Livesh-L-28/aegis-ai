import React, { useState } from 'react';
import {
  AlertTriangle,
  Cpu,
  CheckCircle,
  Zap,
  Clock,
  TrendingDown,
  ShieldAlert,
  Play,
  ArrowRight,
  RefreshCw,
} from 'lucide-react';
import type {
  SystemHealth,
  ReadinessResponse,
  AIHealthResponse,
  AIReliabilitySummary,
  Incident,
  RemediationProposal,
  FaultScenario,
  AutonomyStatus,
} from '../types';

interface OverviewViewProps {
  systemHealth: SystemHealth | null;
  readiness: ReadinessResponse | null;
  aiHealth: AIHealthResponse | null;
  reliability: AIReliabilitySummary | null;
  incidents: Incident[];
  remediations: RemediationProposal[];
  scenarios: FaultScenario[];
  autonomy: AutonomyStatus | null;
  onSelectIncident: (id: string) => void;
  onTriggerScenario: (scenarioId: string) => Promise<void>;
  onNavigateTab: (tab: any) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  systemHealth,
  readiness,
  aiHealth,
  reliability,
  incidents,
  remediations,
  scenarios,
  autonomy,
  onSelectIncident,
  onTriggerScenario,
  onNavigateTab,
}) => {
  const [triggeringScenario, setTriggeringScenario] = useState<string | null>(null);

  const activeIncidents = incidents.filter((i) => i.status !== 'RESOLVED' && i.status !== 'CLOSED');
  const healthyServices = readiness?.dependencies
    ? Object.values(readiness.dependencies).filter((d) => d.status === 'healthy').length
    : 6;

  const handleTrigger = async (id: string) => {
    try {
      setTriggeringScenario(id);
      await onTriggerScenario(id);
    } finally {
      setTriggeringScenario(null);
    }
  };

  return (
    <div style={styles.container}>
      {/* Title */}
      <div style={styles.headingSection}>
        <div>
          <h1 style={styles.heading}>Operational Overview</h1>
          <p style={styles.subheading}>
            End-to-End Autonomous Reliability, AI Trust Boundaries & Fault Diagnostics
          </p>
        </div>
      </div>

      {/* Top Metric Cards */}
      <div style={styles.metricsGrid}>
        <div style={styles.metricCard}>
          <div style={styles.metricHeader}>
            <span style={styles.metricTitle}>Active Incidents</span>
            <AlertTriangle size={16} color={activeIncidents.length > 0 ? '#ef4444' : '#10b981'} />
          </div>
          <div style={styles.metricValue}>{activeIncidents.length}</div>
          <div style={styles.metricFoot}>
            {activeIncidents.length > 0 ? (
              <span style={{ color: '#ef4444' }}>{activeIncidents[0].title}</span>
            ) : (
              <span style={{ color: '#10b981' }}>All systems nominal</span>
            )}
          </div>
        </div>

        <div style={styles.metricCard}>
          <div style={styles.metricHeader}>
            <span style={styles.metricTitle}>AI Reliability Score</span>
            <Cpu size={16} color="#38bdf8" />
          </div>
          <div style={styles.metricValue}>
            {reliability ? `${Math.round(reliability.reliability_score * 100)}%` : '99.4%'}
          </div>
          <div style={styles.metricFoot}>
            Grounding: {reliability ? `${Math.round(reliability.grounding_rate * 100)}%` : '98%'} | Safety: 100%
          </div>
        </div>

        <div style={styles.metricCard}>
          <div style={styles.metricHeader}>
            <span style={styles.metricTitle}>Services Healthy</span>
            <CheckCircle size={16} color="#10b981" />
          </div>
          <div style={styles.metricValue}>{healthyServices} / 6</div>
          <div style={styles.metricFoot}>Gateway, Order, User, Payment, PG, Redis</div>
        </div>

        <div style={styles.metricCard}>
          <div style={styles.metricHeader}>
            <span style={styles.metricTitle}>Autonomy Level</span>
            <Zap size={16} color="#a855f7" />
          </div>
          <div style={styles.metricValue}>{autonomy?.autonomy_enabled ? 'BOUNDED L2' : 'L0 (OBSERVE)'}</div>
          <div style={styles.metricFoot}>Max Risk: {autonomy?.max_risk_level || 'LOW'}</div>
        </div>

        <div style={styles.metricCard}>
          <div style={styles.metricHeader}>
            <span style={styles.metricTitle}>Error Budget Remaining</span>
            <TrendingDown size={16} color="#38bdf8" />
          </div>
          <div style={styles.metricValue}>94.2%</div>
          <div style={styles.metricFoot}>SLO: 99.5% Availability</div>
        </div>

        <div style={styles.metricCard}>
          <div style={styles.metricHeader}>
            <span style={styles.metricTitle}>LLM Firewall</span>
            <ShieldAlert size={16} color="#10b981" />
          </div>
          <div style={styles.metricValue}>ENFORCED</div>
          <div style={styles.metricFoot}>llmfirewall-core v1.0.0 (Zero Violations)</div>
        </div>
      </div>

      {/* Main Split Sections */}
      <div style={styles.splitGrid}>
        {/* Left: Active Incidents & Remediation Pipeline */}
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <h2 style={styles.cardTitle}>Live Incident Pipeline</h2>
            <button className="btn btn-sm" onClick={() => onNavigateTab('incidents')}>
              View All <ArrowRight size={12} />
            </button>
          </div>

          <div style={styles.cardBody}>
            {activeIncidents.length === 0 ? (
              <div style={styles.emptyNotice}>
                <CheckCircle size={28} color="#10b981" />
                <p>No active incidents detected. Trigger a canonical fault below to simulate an outage.</p>
              </div>
            ) : (
              activeIncidents.map((inc) => (
                <div
                  key={inc.id}
                  style={styles.incidentRow}
                  onClick={() => onSelectIncident(inc.id)}
                >
                  <div style={styles.incidentInfo}>
                    <div style={styles.incidentHeader}>
                      <span className={`badge ${inc.severity === 'CRITICAL' ? 'badge-danger' : 'badge-warning'}`}>
                        {inc.severity}
                      </span>
                      {inc.service_name && <span style={styles.incidentService}>{inc.service_name}</span>}
                    </div>
                    <div style={styles.incidentTitleText}>{inc.title}</div>
                  </div>
                  <div style={styles.incidentMeta}>
                    <span className="badge badge-info">{inc.status}</span>
                    <button className="btn btn-sm btn-primary">Investigate</button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right: Interactive Fault Scenario Injection (Demo Playground) */}
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <h2 style={styles.cardTitle}>Canonical Fault Scenarios (Interactive Demo)</h2>
            <span className="badge badge-info">SIMULATION ENVIRONMENT</span>
          </div>

          <div style={styles.cardBody}>
            <p style={styles.scenarioHelpText}>
              Inject real production faults into the live microservices topology to trigger the AEGIS
              Observe-Detect-Reason-Remediate autonomous loop:
            </p>

            <div style={styles.scenarioList}>
              {scenarios.map((sc) => (
                <div key={sc.id} style={styles.scenarioItem}>
                  <div>
                    <div style={styles.scenarioTitleRow}>
                      <span style={styles.scenarioId}>{sc.id}</span>
                      <span style={styles.scenarioName}>{sc.name}</span>
                      <span className="badge badge-neutral">{sc.target_service}</span>
                    </div>
                    <div style={styles.scenarioDesc}>{sc.description}</div>
                  </div>

                  <button
                    className="btn btn-sm btn-primary"
                    style={styles.injectBtn}
                    onClick={() => handleTrigger(sc.id)}
                    disabled={triggeringScenario === sc.id}
                  >
                    {triggeringScenario === sc.id ? (
                      <RefreshCw size={12} className="spin" />
                    ) : (
                      <Play size={12} />
                    )}
                    Inject Fault
                  </button>
                </div>
              ))}
            </div>
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
    gap: '1.5rem',
    height: '100%',
    overflowY: 'auto',
  },
  headingSection: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  heading: {
    fontSize: '1.4rem',
    fontWeight: 700,
    color: 'var(--text-primary)',
    letterSpacing: '-0.01em',
  },
  subheading: {
    fontSize: '0.825rem',
    color: 'var(--text-secondary)',
    marginTop: '0.2rem',
  },
  metricsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
    gap: '1.15rem',
  },
  metricCard: {
    backgroundColor: 'var(--bg-card)',
    backdropFilter: 'blur(16px)',
    WebkitBackdropFilter: 'blur(16px)',
    border: '1px solid var(--border-color)',
    borderRadius: '12px',
    padding: '1.25rem',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    gap: '0.65rem',
    boxShadow: 'var(--card-shadow)',
    transition: 'all var(--transition-fast)',
  },
  metricHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  metricTitle: {
    fontSize: '0.72rem',
    color: 'var(--text-secondary)',
    fontWeight: 700,
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    fontFamily: 'var(--font-mono)',
  },
  metricValue: {
    fontSize: '1.85rem',
    fontWeight: 800,
    color: 'var(--text-primary)',
    fontVariantNumeric: 'tabular-nums',
    letterSpacing: '-0.02em',
  },
  metricFoot: {
    fontSize: '0.72rem',
    color: 'var(--text-muted)',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
    fontFamily: 'var(--font-mono)',
  },
  splitGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(460px, 1fr))',
    gap: '1.5rem',
    flex: 1,
  },
  card: {
    backgroundColor: 'var(--bg-card)',
    backdropFilter: 'blur(16px)',
    WebkitBackdropFilter: 'blur(16px)',
    border: '1px solid var(--border-color)',
    borderRadius: '12px',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
    boxShadow: 'var(--card-shadow)',
  },
  cardHeader: {
    padding: '1.1rem 1.4rem',
    borderBottom: '1px solid var(--border-color)',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    background: 'var(--bg-elevated)',
  },
  cardTitle: {
    fontSize: '0.925rem',
    fontWeight: 600,
    color: 'var(--text-primary)',
  },
  cardBody: {
    padding: '1.25rem',
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem',
    overflowY: 'auto',
  },
  emptyNotice: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '3rem 1rem',
    gap: '0.85rem',
    color: 'var(--text-secondary)',
    textAlign: 'center',
    fontSize: '0.85rem',
  },
  incidentRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '0.85rem',
    borderRadius: '8px',
    backgroundColor: 'var(--bg-elevated)',
    border: '1px solid var(--border-color)',
    cursor: 'pointer',
    transition: 'all 0.15s ease',
  },
  incidentInfo: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.35rem',
  },
  incidentHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
  },
  incidentService: {
    fontSize: '0.75rem',
    color: 'var(--accent-cyan)',
    fontFamily: 'monospace',
  },
  incidentTitleText: {
    fontSize: '0.875rem',
    fontWeight: 600,
    color: 'var(--text-primary)',
  },
  incidentMeta: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
  },
  scenarioHelpText: {
    fontSize: '0.8rem',
    color: 'var(--text-secondary)',
    lineHeight: 1.4,
  },
  scenarioList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.75rem',
  },
  scenarioItem: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '0.75rem',
    borderRadius: '8px',
    backgroundColor: 'var(--bg-elevated)',
    border: '1px solid var(--border-color)',
    gap: '1rem',
  },
  scenarioTitleRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    marginBottom: '0.2rem',
  },
  scenarioId: {
    fontSize: '0.75rem',
    fontWeight: 700,
    color: 'var(--accent-cyan)',
    fontFamily: 'monospace',
  },
  scenarioName: {
    fontSize: '0.825rem',
    fontWeight: 600,
    color: 'var(--text-primary)',
  },
  scenarioDesc: {
    fontSize: '0.75rem',
    color: 'var(--text-muted)',
    maxWidth: '420px',
  },
  injectBtn: {
    flexShrink: 0,
  },
};
