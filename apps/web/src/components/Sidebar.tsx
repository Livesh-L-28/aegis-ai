import React from 'react';
import {
  Activity,
  AlertTriangle,
  Shield,
  Cpu,
  GitBranch,
  Search,
  BookOpen,
  Terminal,
  Zap,
  Sliders,
  CheckCircle2,
  FileText,
  BarChart2,
  Lock,
} from 'lucide-react';

export type NavItem =
  | 'overview'
  | 'incidents'
  | 'incident-detail'
  | 'remediations'
  | 'ai-reliability'
  | 'firewall'
  | 'dependencies'
  | 'autonomy'
  | 'code-intel'
  | 'knowledge'
  | 'evaluation'
  | 'audit';

interface SidebarProps {
  currentTab: NavItem;
  onSelectTab: (tab: NavItem) => void;
  activeIncidentId: string | null;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab, activeIncidentId }) => {
  return (
    <aside style={styles.sidebar}>
      {/* Brand Header */}
      <div style={styles.brand}>
        <div style={styles.logoBadge}>
          <Shield size={18} color="#38bdf8" />
        </div>
        <div>
          <div style={styles.brandTitle}>AEGIS AI</div>
          <div style={styles.brandSubtitle}>COMMAND CENTER</div>
        </div>
      </div>

      {/* Nav List */}
      <nav style={styles.nav}>
        <div style={styles.sectionLabel}>MONITORING</div>
        <button
          style={currentTab === 'overview' ? styles.navItemActive : styles.navItem}
          onClick={() => onSelectTab('overview')}
        >
          <Activity size={16} /> Overview
        </button>
        <button
          style={currentTab === 'incidents' ? styles.navItemActive : styles.navItem}
          onClick={() => onSelectTab('incidents')}
        >
          <AlertTriangle size={16} /> Incidents
        </button>
        {activeIncidentId && (
          <button
            style={currentTab === 'incident-detail' ? styles.navItemActiveSub : styles.navItemSub}
            onClick={() => onSelectTab('incident-detail')}
          >
            ↳ Investigation Detail
          </button>
        )}
        <button
          style={currentTab === 'dependencies' ? styles.navItemActive : styles.navItem}
          onClick={() => onSelectTab('dependencies')}
        >
          <GitBranch size={16} /> Dependency Graph
        </button>

        <div style={styles.sectionLabel}>AI TRUST PLANE</div>
        <button
          style={currentTab === 'ai-reliability' ? styles.navItemActive : styles.navItem}
          onClick={() => onSelectTab('ai-reliability')}
        >
          <Cpu size={16} /> AI Reliability
        </button>
        <button
          style={currentTab === 'firewall' ? styles.navItemActive : styles.navItem}
          onClick={() => onSelectTab('firewall')}
        >
          <Lock size={16} /> LLM Firewall
        </button>
        <button
          style={currentTab === 'evaluation' ? styles.navItemActive : styles.navItem}
          onClick={() => onSelectTab('evaluation')}
        >
          <BarChart2 size={16} /> Continuous Eval
        </button>

        <div style={styles.sectionLabel}>ACTION & AUTONOMY</div>
        <button
          style={currentTab === 'remediations' ? styles.navItemActive : styles.navItem}
          onClick={() => onSelectTab('remediations')}
        >
          <Zap size={16} /> Remediation Center
        </button>
        <button
          style={currentTab === 'autonomy' ? styles.navItemActive : styles.navItem}
          onClick={() => onSelectTab('autonomy')}
        >
          <Sliders size={16} /> Autonomy & SLO
        </button>

        <div style={styles.sectionLabel}>INTELLIGENCE & AUDIT</div>
        <button
          style={currentTab === 'code-intel' ? styles.navItemActive : styles.navItem}
          onClick={() => onSelectTab('code-intel')}
        >
          <Terminal size={16} /> Code Intelligence
        </button>
        <button
          style={currentTab === 'knowledge' ? styles.navItemActive : styles.navItem}
          onClick={() => onSelectTab('knowledge')}
        >
          <BookOpen size={16} /> Knowledge & Docs
        </button>
        <button
          style={currentTab === 'audit' ? styles.navItemActive : styles.navItem}
          onClick={() => onSelectTab('audit')}
        >
          <FileText size={16} /> Audit Trail
        </button>
      </nav>

      {/* Footer Info */}
      <div style={styles.footer}>
        <div style={styles.engineTag}>
          <span style={styles.dot}></span> llmfirewall-core 1.0.0
        </div>
        <div style={styles.engineTag}>
          <span style={styles.dot}></span> aireliability 0.1.0
        </div>
      </div>
    </aside>
  );
};

const styles: Record<string, React.CSSProperties> = {
  sidebar: {
    width: 'var(--sidebar-width)',
    height: '100%',
    backgroundColor: 'var(--bg-secondary)',
    borderRight: '1px solid var(--border-color)',
    display: 'flex',
    flexDirection: 'column',
    userSelect: 'none',
    boxShadow: '4px 0 24px rgba(0, 0, 0, 0.4)',
    zIndex: 30,
  },
  brand: {
    padding: '1.25rem 1.4rem',
    display: 'flex',
    alignItems: 'center',
    gap: '0.85rem',
    borderBottom: '1px solid var(--border-color)',
    background: 'linear-gradient(180deg, rgba(6, 182, 212, 0.05) 0%, transparent 100%)',
  },
  logoBadge: {
    width: '36px',
    height: '36px',
    borderRadius: '10px',
    backgroundColor: 'rgba(56, 189, 248, 0.12)',
    border: '1px solid rgba(56, 189, 248, 0.4)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    boxShadow: '0 0 16px rgba(56, 189, 248, 0.25)',
  },
  brandTitle: {
    fontWeight: 800,
    fontSize: '1.05rem',
    letterSpacing: '0.08em',
    color: 'var(--text-primary)',
  },
  brandSubtitle: {
    fontSize: '0.62rem',
    color: 'var(--accent-cyan)',
    fontWeight: 700,
    letterSpacing: '0.14em',
    fontFamily: 'var(--font-mono)',
  },
  nav: {
    flex: 1,
    overflowY: 'auto',
    padding: '1rem 0.85rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem',
  },
  sectionLabel: {
    fontSize: '0.62rem',
    fontWeight: 800,
    color: 'var(--text-muted)',
    letterSpacing: '0.12em',
    marginTop: '1.1rem',
    marginBottom: '0.4rem',
    paddingLeft: '0.65rem',
    fontFamily: 'var(--font-mono)',
  },
  navItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.65rem',
    padding: '0.55rem 0.75rem',
    borderRadius: '7px',
    fontSize: '0.825rem',
    color: 'var(--text-secondary)',
    background: 'transparent',
    border: 'none',
    cursor: 'pointer',
    textAlign: 'left',
    transition: 'all var(--transition-fast)',
    fontWeight: 500,
  },
  navItemActive: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.65rem',
    padding: '0.55rem 0.75rem',
    borderRadius: '6px',
    fontSize: '0.825rem',
    color: 'var(--text-primary)',
    backgroundColor: 'rgba(56, 189, 248, 0.08)',
    borderLeft: '3px solid var(--accent-cyan)',
    borderTop: '1px solid rgba(56, 189, 248, 0.15)',
    borderRight: '1px solid rgba(56, 189, 248, 0.15)',
    borderBottom: '1px solid rgba(56, 189, 248, 0.15)',
    cursor: 'pointer',
    textAlign: 'left',
    fontWeight: 600,
  },
  navItemSub: {
    paddingLeft: '2rem',
    paddingTop: '0.35rem',
    paddingBottom: '0.35rem',
    fontSize: '0.75rem',
    color: 'var(--accent-cyan)',
    background: 'transparent',
    border: 'none',
    cursor: 'pointer',
    textAlign: 'left',
  },
  navItemActiveSub: {
    paddingLeft: '2rem',
    paddingTop: '0.35rem',
    paddingBottom: '0.35rem',
    fontSize: '0.75rem',
    color: 'var(--text-primary)',
    background: 'rgba(56, 189, 248, 0.15)',
    border: 'none',
    fontWeight: 600,
    cursor: 'pointer',
    textAlign: 'left',
  },
  footer: {
    padding: '0.85rem 1.15rem',
    borderTop: '1px solid var(--border-color)',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.4rem',
    background: 'rgba(9, 13, 22, 0.7)',
  },
  engineTag: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    fontSize: '0.7rem',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-mono)',
  },
  dot: {
    width: '6px',
    height: '6px',
    borderRadius: '50%',
    backgroundColor: 'var(--status-success)',
    boxShadow: '0 0 6px var(--status-success)',
  },
};
