import React, { useState } from 'react';
import { Sliders, Shield, Zap, TrendingDown, AlertOctagon, CheckCircle2 } from 'lucide-react';
import { aegisApi } from '../api/endpoints';
import type { AutonomyStatus } from '../types';

interface AutonomyViewProps {
  autonomy: AutonomyStatus | null;
  onRefresh: () => void;
}

export const AutonomyView: React.FC<AutonomyViewProps> = ({ autonomy, onRefresh }) => {
  const [loadingAction, setLoadingAction] = useState<boolean>(false);

  const handleTripKillSwitch = async () => {
    try {
      setLoadingAction(true);
      await aegisApi.disableAutonomyKillSwitch();
      onRefresh();
    } finally {
      setLoadingAction(false);
    }
  };

  const handleRestoreKillSwitch = async () => {
    try {
      setLoadingAction(true);
      await aegisApi.enableAutonomyKillSwitch();
      onRefresh();
    } finally {
      setLoadingAction(false);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <div>
          <h1 style={styles.heading}>Autonomy Center & Error Budgets</h1>
          <p style={styles.subheading}>
            Bounded Autonomy Policy, Multi-Service Error Budgets & Hardware Kill Switch
          </p>
        </div>
      </div>

      <div style={styles.grid}>
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <span style={styles.cardLabel}>Autonomy State</span>
            <Zap size={16} color="var(--accent-cyan)" />
          </div>
          <div style={styles.val}>
            {autonomy?.kill_switch_active
              ? 'HALTED (KILL SWITCH)'
              : autonomy?.autonomy_enabled
              ? 'BOUNDED L2'
              : 'L0 (OBSERVE ONLY)'}
          </div>
          <div style={styles.subVal}>Max Risk: {autonomy?.max_risk_level || 'LOW'}</div>
        </div>

        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <span style={styles.cardLabel}>Error Budget Status</span>
            <TrendingDown size={16} color="#10b981" />
          </div>
          <div style={styles.val}>94.2% Remaining</div>
          <div style={styles.subVal}>Burn Rate: 0.12x (Healthy)</div>
        </div>

        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <span style={styles.cardLabel}>Circuit Breaker</span>
            <CheckCircle2 size={16} color="#10b981" />
          </div>
          <div style={styles.val}>{autonomy?.circuit_breaker_state || 'CLOSED'}</div>
          <div style={styles.subVal}>Consecutive Failures: 0 / 5</div>
        </div>

        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <span style={styles.cardLabel}>Tool Execution Limit</span>
            <Sliders size={16} color="#a855f7" />
          </div>
          <div style={styles.val}>{autonomy?.max_tool_calls || 15} Tools</div>
          <div style={styles.subVal}>Per Investigation Limit</div>
        </div>
      </div>

      <div style={styles.sectionCard}>
        <div style={styles.sectionHeader}>
          <h2 style={styles.sectionTitle}>Emergency Kill Switch & Autonomy Freeze</h2>
        </div>
        <div style={styles.sectionBody}>
          <p style={styles.helpText}>
            When tripped, all automated and agentic remediation loops immediately abort. The trust plane
            falls back strictly to read-only investigation mode without executing changes.
          </p>

          <div style={styles.actionRow}>
            {autonomy?.kill_switch_active ? (
              <button
                className="btn btn-primary"
                onClick={handleRestoreKillSwitch}
                disabled={loadingAction}
              >
                Restore Autonomous Operations
              </button>
            ) : (
              <button
                className="btn btn-danger"
                onClick={handleTripKillSwitch}
                disabled={loadingAction}
              >
                <AlertOctagon size={16} /> Trip Emergency Kill Switch
              </button>
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
    fontSize: '1.45rem',
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
  sectionBody: {
    padding: '1.25rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem',
  },
  helpText: {
    fontSize: '0.825rem',
    color: 'var(--text-secondary)',
    lineHeight: 1.5,
  },
  actionRow: {
    display: 'flex',
    gap: '1rem',
  },
};
