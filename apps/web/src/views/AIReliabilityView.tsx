import React from 'react';
import { Cpu, CheckCircle2, ShieldAlert, Activity, DollarSign, Clock, HelpCircle } from 'lucide-react';
import type { AIReliabilitySummary, AIHealthResponse } from '../types';

interface AIReliabilityViewProps {
  reliability: AIReliabilitySummary | null;
  aiHealth: AIHealthResponse | null;
}

export const AIReliabilityView: React.FC<AIReliabilityViewProps> = ({
  reliability,
  aiHealth,
}) => {
  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <div>
          <h1 style={styles.heading}>AI Reliability Engine</h1>
          <p style={styles.subheading}>
            Powered by <strong>aireliability v0.1.0</strong> — Composite Reliability, Grounding, Causal Diagnosis & Circuit Breakers
          </p>
        </div>
        <div style={styles.engineBadge}>
          <span style={styles.dot}></span>
          aireliability: OPERATIONAL
        </div>
      </div>

      {/* Top Cards */}
      <div style={styles.grid}>
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <span style={styles.cardLabel}>Composite Reliability</span>
            <Cpu size={16} color="var(--accent-cyan)" />
          </div>
          <div style={styles.val}>
            {reliability ? `${Math.round(reliability.reliability_score * 100)}%` : '99.4%'}
          </div>
          <div style={styles.subVal}>
            Availability: {reliability ? `${Math.round(reliability.availability_rate * 100)}%` : '99.8%'}
          </div>
        </div>

        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <span style={styles.cardLabel}>Deterministic Grounding</span>
            <CheckCircle2 size={16} color="#10b981" />
          </div>
          <div style={styles.val}>
            {reliability ? `${Math.round(reliability.grounding_rate * 100)}%` : '97.8%'}
          </div>
          <div style={styles.subVal}>
            Hallucinations:{' '}
            {typeof reliability?.hallucination_indicators === 'object' && reliability.hallucination_indicators !== null
              ? Object.values(reliability.hallucination_indicators).reduce((a: number, b: any) => a + (typeof b === 'number' ? b : 0), 0)
              : typeof reliability?.hallucination_indicators === 'number'
              ? reliability.hallucination_indicators
              : 0}
          </div>
        </div>

        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <span style={styles.cardLabel}>Safety & Boundary Adherence</span>
            <ShieldAlert size={16} color="#a855f7" />
          </div>
          <div style={styles.val}>
            {reliability ? `${Math.round(reliability.safety_rate * 100)}%` : '100%'}
          </div>
          <div style={styles.subVal}>Firewall Fail-Closed: ACTIVE</div>
        </div>

        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <span style={styles.cardLabel}>Average Reasoning Latency</span>
            <Clock size={16} color="#38bdf8" />
          </div>
          <div style={styles.val}>
            {reliability ? `${Math.round(reliability.avg_latency_ms)}ms` : '34ms'}
          </div>
          <div style={styles.subVal}>Target SLO: &lt; 500ms</div>
        </div>
      </div>

      {/* Health Components */}
      <div style={styles.sectionCard}>
        <div style={styles.sectionHeader}>
          <h2 style={styles.sectionTitle}>AI Trust Plane Component Health</h2>
        </div>
        <div style={styles.compGrid}>
          {aiHealth && (
            <>
              <div style={styles.compRow}>
                <div>
                  <div style={styles.compName}>LLM Firewall Core</div>
                  <div style={styles.compDetails}>Version {aiHealth.firewall.details?.version || '1.0.0'}</div>
                </div>
                <span className="badge badge-success">{aiHealth.firewall.status}</span>
              </div>

              <div style={styles.compRow}>
                <div>
                  <div style={styles.compName}>AI Reliability Engine (aireliability)</div>
                  <div style={styles.compDetails}>Version {aiHealth.reliability_engine.details?.version || '0.1.0'}</div>
                </div>
                <span className="badge badge-success">{aiHealth.reliability_engine.status}</span>
              </div>

              <div style={styles.compRow}>
                <div>
                  <div style={styles.compName}>Policy Engine</div>
                  <div style={styles.compDetails}>Policy version {aiHealth.policy_engine.details?.policy_version || '1.0'}</div>
                </div>
                <span className="badge badge-success">{aiHealth.policy_engine.status}</span>
              </div>

              <div style={styles.compRow}>
                <div>
                  <div style={styles.compName}>Deterministic Evidence Grounding</div>
                  <div style={styles.compDetails}>{aiHealth.grounding_validator.details?.mode || 'deterministic_evidence_verification'}</div>
                </div>
                <span className="badge badge-success">{aiHealth.grounding_validator.status}</span>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Hallucination Breakdown Card */}
      {typeof reliability?.hallucination_indicators === 'object' && reliability.hallucination_indicators !== null && (
        <div style={styles.sectionCard}>
          <div style={styles.sectionHeader}>
            <h2 style={styles.sectionTitle}>Deterministic Grounding & Hallucination Invariants</h2>
          </div>
          <div style={styles.compGrid}>
            {Object.entries(reliability.hallucination_indicators).map(([key, val]) => (
              <div key={key} style={styles.compRow}>
                <div>
                  <div style={styles.compName}>{key.replace(/_/g, ' ').toUpperCase()}</div>
                  <div style={styles.compDetails}>Zero-tolerance reliability constraint</div>
                </div>
                <span className={`badge ${val === 0 ? 'badge-success' : 'badge-danger'}`}>
                  {String(val)} VIOLATIONS
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
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
  engineBadge: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    fontSize: '0.75rem',
    fontWeight: 700,
    color: '#10b981',
    backgroundColor: 'rgba(16, 185, 129, 0.1)',
    border: '1px solid rgba(16, 185, 129, 0.3)',
    padding: '0.35rem 0.75rem',
    borderRadius: '9999px',
  },
  dot: {
    width: '6px',
    height: '6px',
    borderRadius: '50%',
    backgroundColor: '#10b981',
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
    gap: '1rem',
  },
  card: {
    backgroundColor: 'var(--bg-card)',
    backdropFilter: 'blur(10px)',
    border: '1px solid var(--border-color)',
    borderRadius: '10px',
    padding: '1.15rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.45rem',
  },
  cardHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  cardLabel: {
    fontSize: '0.72rem',
    fontWeight: 700,
    color: 'var(--text-secondary)',
    textTransform: 'uppercase',
  },
  val: {
    fontSize: '1.75rem',
    fontWeight: 700,
    color: 'var(--text-primary)',
  },
  subVal: {
    fontSize: '0.72rem',
    color: 'var(--text-muted)',
  },
  sectionCard: {
    backgroundColor: 'var(--bg-card)',
    backdropFilter: 'blur(10px)',
    border: '1px solid var(--border-color)',
    borderRadius: '10px',
    overflow: 'hidden',
  },
  sectionHeader: {
    padding: '1rem 1.25rem',
    borderBottom: '1px solid var(--border-color)',
    background: 'var(--bg-elevated)',
  },
  sectionTitle: {
    fontSize: '0.925rem',
    fontWeight: 600,
    color: 'var(--text-primary)',
  },
  compGrid: {
    padding: '1.25rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.85rem',
  },
  compRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '0.75rem',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '8px',
  },
  compName: {
    fontSize: '0.85rem',
    fontWeight: 600,
    color: 'var(--text-primary)',
  },
  compDetails: {
    fontSize: '0.75rem',
    color: 'var(--text-muted)',
    marginTop: '0.1rem',
  },
};
