import React, { useEffect, useState, useRef } from 'react';
import { Sidebar, type NavItem } from './components/Sidebar';
import { Header, AVAILABLE_TENANTS } from './components/Header';
import { ConnectProductModal } from './components/ConnectProductModal';
import { ViewErrorBoundary } from './components/ViewErrorBoundary';
import { OverviewView } from './views/OverviewView';
import { IncidentsView } from './views/IncidentsView';
import { IncidentDetailView } from './views/IncidentDetailView';
import { RemediationsView } from './views/RemediationsView';
import { AIReliabilityView } from './views/AIReliabilityView';
import { FirewallView } from './views/FirewallView';
import { DependenciesView } from './views/DependenciesView';
import { AutonomyView } from './views/AutonomyView';
import { CodeIntelView } from './views/CodeIntelView';
import { KnowledgeView } from './views/KnowledgeView';
import { EvaluationView } from './views/EvaluationView';
import { AuditView } from './views/AuditView';
import { aegisApi } from './api/endpoints';
import { setActiveOrgId, DEFAULT_ORG_ID, API_BASE } from './api/client';
import type {
  SystemHealth,
  ReadinessResponse,
  AIHealthResponse,
  AIReliabilitySummary,
  FirewallStatus,
  Incident,
  RemediationProposal,
  SystemDependencyGraph,
  AutonomyStatus,
  FaultScenario,
  AuditEvent,
} from './types';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<NavItem>('overview');
  const [activeIncidentId, setActiveIncidentId] = useState<string | null>(null);
  const [selectedTenant, setSelectedTenant] = useState<string>(DEFAULT_ORG_ID);
  const [sseConnected, setSseConnected] = useState<boolean>(false);
  const [connectModalOpen, setConnectModalOpen] = useState<boolean>(false);
  const [theme, setTheme] = useState<'dark' | 'light'>('light');

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  const handleToggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  // Global Platform State
  const [systemHealth, setSystemHealth] = useState<SystemHealth | null>(null);
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);
  const [aiHealth, setAIHealth] = useState<AIHealthResponse | null>(null);
  const [reliability, setReliability] = useState<AIReliabilitySummary | null>(null);
  const [firewall, setFirewall] = useState<FirewallStatus | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [remediations, setRemediations] = useState<RemediationProposal[]>([]);
  const [dependencyGraph, setDependencyGraph] = useState<SystemDependencyGraph | null>(null);
  const [autonomy, setAutonomy] = useState<AutonomyStatus | null>(null);
  const [scenarios, setScenarios] = useState<FaultScenario[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchAllData = async () => {
    try {
      setLoading(true);
      const [
        healthRes,
        readyRes,
        aiHealthRes,
        relRes,
        fwRes,
        incList,
        remList,
        depGraph,
        autStatus,
        scenList,
        audList,
      ] = await Promise.all([
        aegisApi.getHealth().catch(() => null),
        aegisApi.getReadiness().catch(() => null),
        aegisApi.getAIHealth().catch(() => null),
        aegisApi.getAIReliability().catch(() => null),
        aegisApi.getFirewallStatus().catch(() => null),
        aegisApi.listIncidents().catch(() => []),
        aegisApi.listRemediations().catch(() => []),
        aegisApi.getDependencyGraph().catch(() => null),
        aegisApi.getAutonomyStatus().catch(() => null),
        aegisApi.listScenarios().catch(() => []),
        aegisApi.listAuditEvents(50).catch(() => []),
      ]);

      setSystemHealth(healthRes);
      setReadiness(readyRes);
      setAIHealth(aiHealthRes);
      setReliability(relRes);
      setFirewall(fwRes);
      setIncidents(incList);
      setRemediations(remList);
      setDependencyGraph(depGraph);
      setAutonomy(autStatus);
      setScenarios(scenList);
      setAuditEvents(audList);
    } catch (err) {
      console.error('Error syncing platform state:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleTenantChange = (tenantId: string) => {
    setSelectedTenant(tenantId);
    setActiveOrgId(tenantId);
    fetchAllData();
  };

  // Real-Time SSE Stream Hookup
  useEffect(() => {
    fetchAllData();
    const interval = setInterval(fetchAllData, 15000); // Background sync fallback

    // Establish SSE event connection
    let eventSource: EventSource | null = null;
    try {
      eventSource = new EventSource(`${API_BASE}/events/stream`);
      eventSource.onopen = () => {
        setSseConnected(true);
      };
      eventSource.addEventListener('ping', () => {
        setSseConnected(true);
      });
      eventSource.onerror = () => {
        setSseConnected(false);
      };
    } catch (err) {
      console.warn('SSE stream not supported or blocked:', err);
      setSseConnected(false);
    }

    return () => {
      clearInterval(interval);
      if (eventSource) {
        eventSource.close();
      }
    };
  }, [selectedTenant]);

  const handleSelectIncident = (id: string) => {
    setActiveIncidentId(id);
    setCurrentTab('incident-detail');
  };

  const handleTriggerScenario = async (scenarioId: string) => {
    try {
      await aegisApi.activateScenario(scenarioId);
      // Find or create matching incident in API
      const matching = scenarios.find((s) => s.id === scenarioId);
      if (matching) {
        const createdInc = await aegisApi.createIncident({
          title: matching.name,
          description: matching.description,
          severity: (matching.risk_level || 'MEDIUM') as any,
          service_name: matching.target_service,
          source: 'SIMULATION',
        });
        
        // Auto-create investigation for seamless lifecycle progression
        try {
          await aegisApi.createInvestigation(createdInc.id);
        } catch (invErr) {
          console.warn('Investigation already initiated:', invErr);
        }

        setActiveIncidentId(createdInc.id);
        setCurrentTab('incident-detail');
      }
    } catch (err) {
      console.error('Failed to trigger scenario:', err);
    } finally {
      await fetchAllData();
    }
  };

  const handleTripKillSwitch = async () => {
    await aegisApi.disableAutonomyKillSwitch();
    await fetchAllData();
  };

  const handleRestoreKillSwitch = async () => {
    await aegisApi.enableAutonomyKillSwitch();
    await fetchAllData();
  };

  return (
    <div style={styles.appRoot}>
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        activeIncidentId={activeIncidentId}
      />

      <div style={styles.mainWrapper}>
        <Header
          systemHealth={systemHealth}
          readiness={readiness}
          autonomyStatus={autonomy}
          loading={loading}
          sseConnected={sseConnected}
          selectedTenant={selectedTenant}
          theme={theme}
          onToggleTheme={handleToggleTheme}
          onTenantChange={handleTenantChange}
          onRefresh={fetchAllData}
          onOpenConnectModal={() => setConnectModalOpen(true)}
          onTripKillSwitch={handleTripKillSwitch}
          onRestoreKillSwitch={handleRestoreKillSwitch}
        />

        <ConnectProductModal
          isOpen={connectModalOpen}
          onClose={() => setConnectModalOpen(false)}
          onProductConnected={fetchAllData}
        />

        <main style={styles.contentArea}>
          <ViewErrorBoundary tabName={currentTab}>
            {currentTab === 'overview' && (
              <OverviewView
                systemHealth={systemHealth}
                readiness={readiness}
                aiHealth={aiHealth}
                reliability={reliability}
                incidents={incidents}
                remediations={remediations}
                scenarios={scenarios}
                autonomy={autonomy}
                onSelectIncident={handleSelectIncident}
                onTriggerScenario={handleTriggerScenario}
                onNavigateTab={setCurrentTab}
              />
            )}

            {currentTab === 'incidents' && (
              <IncidentsView incidents={incidents} onSelectIncident={handleSelectIncident} />
            )}

            {currentTab === 'incident-detail' && activeIncidentId && (
              <IncidentDetailView
                incidentId={activeIncidentId}
                onBack={() => setCurrentTab('incidents')}
                onNavigateTab={setCurrentTab}
              />
            )}

            {currentTab === 'remediations' && (
              <RemediationsView remediations={remediations} onRefresh={fetchAllData} />
            )}

            {currentTab === 'ai-reliability' && (
              <AIReliabilityView reliability={reliability} aiHealth={aiHealth} />
            )}

            {currentTab === 'firewall' && <FirewallView firewall={firewall} />}

            {currentTab === 'dependencies' && <DependenciesView graph={dependencyGraph} />}

            {currentTab === 'autonomy' && (
              <AutonomyView autonomy={autonomy} onRefresh={fetchAllData} />
            )}

            {currentTab === 'code-intel' && <CodeIntelView />}

            {currentTab === 'knowledge' && <KnowledgeView />}

            {currentTab === 'evaluation' && <EvaluationView />}

            {currentTab === 'audit' && <AuditView auditEvents={auditEvents} />}
          </ViewErrorBoundary>
        </main>
      </div>
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  appRoot: {
    display: 'flex',
    width: '100vw',
    height: '100vh',
    overflow: 'hidden',
    backgroundColor: 'var(--bg-primary)',
  },
  mainWrapper: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    overflow: 'hidden',
  },
  contentArea: {
    flex: 1,
    overflowY: 'auto',
    position: 'relative',
  },
};

export default App;
