import { apiRequest } from './client';
import type {
  SystemHealth,
  ReadinessResponse,
  AIHealthResponse,
  AIReliabilitySummary,
  FirewallStatus,
  Incident,
  Investigation,
  EvidenceItem,
  Hypothesis,
  ReasoningResult,
  TimelineEntry,
  RemediationProposal,
  SystemDependencyGraph,
  AutonomyStatus,
  FaultScenario,
  AuditEvent,
  CodeSymbol,
} from '../types';

export const aegisApi = {
  // Health & Readiness
  getHealth: () => apiRequest<SystemHealth>('/health'),
  getReadiness: () => apiRequest<ReadinessResponse>('/ready'),

  // AI Plane
  getAIHealth: () => apiRequest<AIHealthResponse>('/ai/health'),
  getAIReliability: () => apiRequest<AIReliabilitySummary>('/ai/reliability'),
  getFirewallStatus: () => apiRequest<FirewallStatus>('/ai/firewall/status'),
  getAIModels: () => apiRequest<any[]>('/ai/models'),

  // Incidents
  listIncidents: () => apiRequest<Incident[]>('/incidents'),
  getIncident: (id: string) => apiRequest<Incident>(`/incidents/${id}`),
  createIncident: (payload: { title: string; description: string; severity: string; service_name: string; source: string }) =>
    apiRequest<Incident>('/incidents', { method: 'POST', body: JSON.stringify(payload) }),

  // Investigations & Evidence
  createInvestigation: (incidentId: string) =>
    apiRequest<Investigation>(`/incidents/${incidentId}/investigations`, { method: 'POST', body: JSON.stringify({}) }),
  listIncidentInvestigations: (incidentId: string) =>
    apiRequest<Investigation[]>(`/incidents/${incidentId}/investigations`),
  getInvestigation: (id: string) => apiRequest<Investigation>(`/investigations/${id}`),
  runInvestigation: (id: string) => apiRequest<Investigation>(`/investigations/${id}/run`, { method: 'POST' }),
  getEvidence: (investigationId: string) => apiRequest<EvidenceItem[]>(`/investigations/${investigationId}/evidence`),
  getHypotheses: (investigationId: string) => apiRequest<Hypothesis[]>(`/investigations/${investigationId}/hypotheses`),
  getReasoningResult: (investigationId: string) => apiRequest<ReasoningResult>(`/investigations/${investigationId}/result`),
  getTimeline: (investigationId: string) => apiRequest<TimelineEntry[]>(`/investigations/${investigationId}/timeline`),

  // Remediation
  listRemediations: () => apiRequest<RemediationProposal[]>('/remediations'),
  createRemediation: (incidentId: string, environment = 'production-sim') =>
    apiRequest<RemediationProposal>(`/incidents/${incidentId}/remediations`, {
      method: 'POST',
      body: JSON.stringify({ target_environment: environment }),
    }),
  approveRemediation: (id: string, notes = 'Approved from AEGIS Command Center') =>
    apiRequest<any>(`/remediations/${id}/approve`, {
      method: 'POST',
      body: JSON.stringify({ notes }),
    }),
  rejectRemediation: (id: string, reason = 'Rejected from AEGIS Command Center') =>
    apiRequest<any>(`/remediations/${id}/reject`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),
  executeRemediation: (id: string, environment = 'production-sim') =>
    apiRequest<any>(`/remediations/${id}/execute`, {
      method: 'POST',
      body: JSON.stringify({ environment }),
    }),

  // Intelligence
  getDependencyGraph: () => apiRequest<SystemDependencyGraph>('/intelligence/dependency-graph'),
  searchCodeSymbols: (query: string) => apiRequest<{ code_matches: CodeSymbol[] }>(`/intelligence/search`, {
    method: 'POST',
    body: JSON.stringify({ query, limit: 10 }),
  }),
  searchKnowledge: (query: string) => apiRequest<{ knowledge_matches: any[] }>(`/intelligence/search`, {
    method: 'POST',
    body: JSON.stringify({ query, limit: 10 }),
  }),
  ingestKnowledgeDocument: (data: { title: string; content: string; source_type?: string; source_uri?: string }) =>
    apiRequest<any>('/intelligence/knowledge/documents', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // Autonomy & Kill Switch
  getAutonomyStatus: () => apiRequest<AutonomyStatus>('/autonomy/status'),
  disableAutonomyKillSwitch: () => apiRequest<AutonomyStatus>('/autonomy/kill-switch/disable', { method: 'POST' }),
  enableAutonomyKillSwitch: () => apiRequest<AutonomyStatus>('/autonomy/kill-switch/enable', { method: 'POST' }),
  getServiceSLO: (serviceName: string) => apiRequest<any>(`/autonomy/slo/${serviceName}`),
  runEvaluation: () => apiRequest<any>('/autonomy/evaluations/run', { method: 'POST' }),

  // Simulation
  listScenarios: () => apiRequest<FaultScenario[]>('/simulation/scenarios'),
  activateScenario: (scenarioId: string) =>
    apiRequest<FaultScenario>(`/simulation/scenarios/${scenarioId}/activate`, { method: 'POST' }),
  deactivateScenario: (scenarioId: string) =>
    apiRequest<FaultScenario>(`/simulation/scenarios/${scenarioId}/deactivate`, { method: 'POST' }),

  // Audit
  listAuditEvents: (limit = 50) => apiRequest<AuditEvent[]>(`/audit?limit=${limit}`),

  // Client Onboarding (1-Click Connect)
  connectProduct: (payload: any) =>
    apiRequest<any>('/onboarding/connect', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
};


