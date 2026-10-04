import React from 'react';
import { Shield, RefreshCw, AlertCircle, CheckCircle2, Radio, Building2, Sun, Moon } from 'lucide-react';
import type { SystemHealth, ReadinessResponse, AutonomyStatus } from '../types';

export interface TenantOption {
  id: string;
  name: string;
}

export const AVAILABLE_TENANTS: TenantOption[] = [
  { id: '088adce9-4d52-4a3d-9ceb-bccba54b3d2f', name: 'Default Enterprise (Cluster A)' },
  { id: '11111111-2222-3333-4444-555555555555', name: 'Staging E-Commerce (Cluster B)' },
  { id: '99999999-8888-7777-6666-555555555555', name: 'Global Payment Gateway (Prod-EU)' },
];

interface HeaderProps {
  systemHealth: SystemHealth | null;
  readiness: ReadinessResponse | null;
  autonomyStatus: AutonomyStatus | null;
  loading: boolean;
  sseConnected: boolean;
  selectedTenant: string;
  theme?: 'dark' | 'light';
  onToggleTheme?: () => void;
  onTenantChange: (tenantId: string) => void;
  onRefresh: () => void;
  onOpenConnectModal?: () => void;
  onTripKillSwitch?: () => void;
  onRestoreKillSwitch?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  systemHealth,
  readiness,
  autonomyStatus,
  loading,
  sseConnected,
  selectedTenant,
  theme = 'dark',
  onToggleTheme,
  onTenantChange,
  onRefresh,
  onOpenConnectModal,
  onTripKillSwitch,
  onRestoreKillSwitch,
}) => {
  const isHealthy = readiness?.status === 'ready' && systemHealth?.status === 'ok';
  const killSwitchActive = autonomyStatus?.kill_switch_active;

  return (
    <header style={styles.header}>
      {/* Left: Environment Badge, Tenant Switcher & Topology Breadcrumb */}
      <div style={styles.left}>
        <div style={styles.envTag}>
          <span style={styles.envPulse}></span>
          ENV: SIMULATION
        </div>

        {/* Tenant Switcher */}
        <div style={styles.tenantContainer}>
          <Building2 size={13} color="var(--accent-cyan)" />
          <select
            style={styles.tenantSelect}
            value={selectedTenant}
            onChange={(e) => onTenantChange(e.target.value)}
            title="Switch Enterprise Tenant Context"
          >
            {AVAILABLE_TENANTS.map((t) => (
              <option key={t.id} value={t.id} style={styles.selectOption}>
                {t.name}
              </option>
            ))}
          </select>
        </div>

        <div style={styles.divider}></div>
        <div style={styles.systemStatus}>
          {isHealthy ? (
            <span className="badge badge-success">
              <CheckCircle2 size={12} /> ALL SYSTEMS OPERATIONAL
            </span>
          ) : (
            <span className="badge badge-warning">
              <AlertCircle size={12} /> CHECKING STATUS
            </span>
          )}
        </div>

        {/* Live SSE Stream Pulse */}
        <div style={styles.sseStatus} title={sseConnected ? 'Real-time SSE event pipeline connected' : 'Connecting to real-time event pipeline'}>
          <Radio size={12} color={sseConnected ? '#10b981' : '#f59e0b'} className={sseConnected ? 'pulse' : ''} />
          <span style={{ color: sseConnected ? '#10b981' : '#f59e0b', fontSize: '0.72rem', fontWeight: 600 }}>
            {sseConnected ? 'LIVE SSE STREAM' : 'SSE CONNECTING'}
          </span>
        </div>
      </div>

      {/* Right: Actions, Kill Switch & Live Indicators */}
      <div style={styles.right}>
        {onToggleTheme && (
          <button
            className="btn btn-sm"
            onClick={onToggleTheme}
            title={theme === 'dark' ? 'Switch to Professional Light Mode' : 'Switch to Executive Dark Mode'}
          >
            {theme === 'dark' ? <Sun size={13} color="#f59e0b" /> : <Moon size={13} color="#6366f1" />}
            {theme === 'dark' ? 'Light' : 'Dark'}
          </button>
        )}

        {onOpenConnectModal && (
          <button
            className="btn btn-sm btn-primary"
            onClick={onOpenConnectModal}
            title="Connect your service or AI application in 1 click"
            style={styles.connectBtn}
          >
            <Radio size={12} /> + Connect Product
          </button>
        )}

        {killSwitchActive ? (
          <div style={styles.killSwitchAlert}>
            <span style={styles.killDot}></span>
            AUTONOMOUS KILL SWITCH ACTIVE
            {onRestoreKillSwitch && (
              <button className="btn btn-sm" style={styles.restoreBtn} onClick={onRestoreKillSwitch}>
                Restore Autonomy
              </button>
            )}
          </div>
        ) : (
          onTripKillSwitch && (
            <button className="btn btn-sm btn-danger" onClick={onTripKillSwitch} title="Emergency stop autonomous remediations">
              <Shield size={12} /> EMERGENCY KILL SWITCH
            </button>
          )
        )}

        <button className="btn btn-sm" onClick={onRefresh} disabled={loading} title="Refresh active telemetry">
          <RefreshCw size={12} className={loading ? 'spin' : ''} />
          {loading ? 'Syncing...' : 'Sync'}
        </button>
      </div>
    </header>
  );
};

const styles: Record<string, React.CSSProperties> = {
  header: {
    height: 'var(--header-height)',
    borderBottom: '1px solid var(--border-color)',
    backgroundColor: 'var(--bg-glass)',
    backdropFilter: 'blur(16px)',
    WebkitBackdropFilter: 'blur(16px)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0 1.75rem',
    zIndex: 20,
    boxShadow: 'var(--glass-shadow)',
  },
  left: {
    display: 'flex',
    alignItems: 'center',
    gap: '1.2rem',
  },
  envTag: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.55rem',
    padding: '0.3rem 0.75rem',
    borderRadius: '6px',
    backgroundColor: 'rgba(56, 189, 248, 0.08)',
    border: '1px solid rgba(56, 189, 248, 0.25)',
    color: 'var(--accent-cyan)',
    fontSize: '0.72rem',
    fontWeight: 700,
    letterSpacing: '0.08em',
    fontFamily: 'var(--font-mono)',
  },
  envPulse: {
    width: '7px',
    height: '7px',
    borderRadius: '50%',
    backgroundColor: 'var(--accent-cyan)',
    boxShadow: '0 0 6px var(--accent-cyan)',
  },
  divider: {
    width: '1px',
    height: '20px',
    backgroundColor: 'var(--border-color)',
  },
  systemStatus: {
    display: 'flex',
    alignItems: 'center',
  },
  right: {
    display: 'flex',
    alignItems: 'center',
    gap: '1rem',
  },
  killSwitchAlert: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.65rem',
    padding: '0.32rem 0.85rem',
    borderRadius: '6px',
    backgroundColor: 'rgba(239, 68, 68, 0.18)',
    border: '1px solid rgba(239, 68, 68, 0.55)',
    color: '#fca5a5',
    fontSize: '0.75rem',
    fontWeight: 700,
    letterSpacing: '0.06em',
    boxShadow: '0 0 14px rgba(239, 68, 68, 0.25)',
  },
  killDot: {
    width: '8px',
    height: '8px',
    borderRadius: '50%',
    backgroundColor: '#ef4444',
    boxShadow: '0 0 8px #ef4444',
  },
  restoreBtn: {
    marginLeft: '0.5rem',
    padding: '0.2rem 0.55rem',
    fontSize: '0.7rem',
    background: '#1e293b',
    border: '1px solid rgba(255, 255, 255, 0.15)',
  },
  tenantContainer: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.45rem',
    padding: '0.2rem 0.55rem',
    borderRadius: '6px',
    backgroundColor: 'rgba(255, 255, 255, 0.04)',
    border: '1px solid var(--border-color)',
  },
  tenantSelect: {
    backgroundColor: 'transparent',
    border: 'none',
    color: 'var(--text-primary)',
    fontSize: '0.74rem',
    fontFamily: 'var(--font-sans)',
    outline: 'none',
    cursor: 'pointer',
    fontWeight: 500,
  },
  selectOption: {
    backgroundColor: 'var(--bg-card)',
    color: 'var(--text-primary)',
  },
  sseStatus: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.45rem',
    padding: '0.25rem 0.6rem',
    borderRadius: '6px',
    backgroundColor: 'rgba(16, 185, 129, 0.06)',
    border: '1px solid rgba(16, 185, 129, 0.2)',
  },
  connectBtn: {
    fontWeight: 600,
    gap: '0.45rem',
  },
};
