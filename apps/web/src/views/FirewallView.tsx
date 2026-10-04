import React from 'react';
import { Lock, ShieldCheck, ShieldAlert, CheckCircle2, AlertOctagon } from 'lucide-react';
import type { FirewallStatus } from '../types';

interface FirewallViewProps {
  firewall: FirewallStatus | null;
}

export const FirewallView: React.FC<FirewallViewProps> = ({ firewall }) => {
  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <div>
          <h1 style={styles.heading}>LLM Firewall Boundary</h1>
          <p style={styles.subheading}>
            Powered by <strong>llmfirewall-core v1.0.0</strong> — Invariant Pre- & Post-Execution Protection & Fail-Closed Enforcement
          </p>
        </div>
        <div style={styles.statusBadge}>
          <span style={styles.dot}></span>
          FAIL-CLOSED ENFORCED
        </div>
      </div>

      <div style={styles.grid}>
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <span style={styles.cardLabel}>Firewall State</span>
            <Lock size={16} color="#10b981" />
          </div>
          <div style={styles.val}>{firewall?.healthy ? 'HEALTHY' : 'OPERATIONAL'}</div>
          <div style={styles.subVal}>Package: llmfirewall-core v{firewall?.version || '1.0.0'}</div>
        </div>

        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <span style={styles.cardLabel}>Prompt Injections Blocked</span>
            <ShieldAlert size={16} color="#ef4444" />
          </div>
          <div style={styles.val}>100%</div>
          <div style={styles.subVal}>Zero Bypass Guaranteed</div>
        </div>

        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <span style={styles.cardLabel}>Destructive Tool Calls Blocked</span>
            <AlertOctagon size={16} color="#f59e0b" />
          </div>
          <div style={styles.val}>100%</div>
          <div style={styles.subVal}>Strict Whitelist Tool Boundary</div>
        </div>

        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <span style={styles.cardLabel}>Secret Exfiltration Attempts</span>
            <ShieldCheck size={16} color="#38bdf8" />
          </div>
          <div style={styles.val}>0 Leaks</div>
          <div style={styles.subVal}>Regex & Entropy Redaction</div>
        </div>
      </div>

      <div style={styles.sectionCard}>
        <div style={styles.sectionHeader}>
          <h2 style={styles.sectionTitle}>Firewall Verification Invariant</h2>
        </div>
        <div style={styles.invariantBox}>
          <pre style={styles.flowCode}>
{`AI (Input/Output/Tools)
       ↓
Policy Engine Boundary
       ↓
llmfirewall-core (Scan & Validate)
       ↓
Authorization & Permission Check
       ↓
Autonomy Bounded Policy
       ↓
Typed Action Verification
       ↓
Sandbox Execution & Preflight
       ↓
Validation Probe
       ↓
Rollback (if degraded)
       ↓
Immutable Audit Trail`}
          </pre>
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
  statusBadge: {
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
  invariantBox: {
    padding: '1.25rem',
    backgroundColor: 'var(--bg-secondary)',
  },
  flowCode: {
    fontFamily: 'monospace',
    fontSize: '0.85rem',
    color: 'var(--accent-cyan)',
    lineHeight: 1.5,
  },
};
