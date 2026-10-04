export interface SystemHealth {
  status: string;
  service: string;
  version: string;
}

export interface DependencyStatus {
  status: 'healthy' | 'unhealthy' | 'degraded';
  latency_ms?: number | null;
  error?: string | null;
}

export interface ReadinessResponse {
  status: string;
  dependencies: Record<string, DependencyStatus>;
}

export interface AIHealthResponse {
  status: string;
  api: { status: string; details: Record<string, any> };
  firewall: { status: string; details: Record<string, any> };
  policy_engine: { status: string; details: Record<string, any> };
  model_router: { status: string; details: Record<string, any> };
  grounding_validator: { status: string; details: Record<string, any> };
  reliability_engine: { status: string; details: Record<string, any> };
}

export interface AIReliabilitySummary {
  total_requests: number;
  successful_requests: number;
  failed_requests: number;
  availability_rate: number;
  grounding_rate: number;
  safety_rate: number;
  reliability_score: number;
  avg_latency_ms: number;
  total_input_tokens: number;
  total_output_tokens: number;
  total_cost_usd: number;
  hallucination_indicators?: number | {
    unsupported_claims?: number;
    invalid_evidence_references?: number;
    schema_violations?: number;
    missing_citations?: number;
    [key: string]: any;
  };
  score_breakdown: Record<string, number>;
}

export interface FirewallStatus {
  enabled: boolean;
  healthy: boolean;
  version: string;
  policy_version: string;
}

export interface Incident {
  id: string;
  organization_id: string;
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'DETECTED' | 'INVESTIGATING' | 'REASONING' | 'REMEDIATING' | 'VALIDATING' | 'RESOLVED' | 'CLOSED';
  service_name: string;
  source: string;
  detected_at: string;
  resolved_at?: string | null;
  actor_id?: string | null;
  metadata?: Record<string, any>;
  investigations?: Investigation[];
}

export interface Investigation {
  id: string;
  incident_id: string;
  organization_id: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  started_at: string;
  completed_at?: string | null;
  created_by?: string | null;
  metadata?: Record<string, any>;
}

export interface EvidenceItem {
  id: string;
  organization_id: string;
  investigation_id: string;
  evidence_type: string;
  source: string;
  service_name: string;
  signal: string;
  observed_at: string;
  severity: string;
  content: string;
  structured_data: Record<string, any>;
  confidence: number;
  relevance_score: number;
  provenance: Record<string, any>;
}

export interface Hypothesis {
  id: string;
  investigation_id: string;
  statement: string;
  probability: number;
  status: 'SUPPORTED' | 'REFUTED' | 'INCONCLUSIVE';
  created_at: string;
}

export interface ReasoningResult {
  id: string;
  investigation_id: string;
  root_cause: string;
  confidence: number;
  supporting_evidence_ids: string[];
  refuting_evidence_ids: string[];
  recommended_actions: string[];
  summary: string;
}

export interface TimelineEntry {
  id?: string;
  timestamp: string;
  title: string;
  description?: string;
  details?: string;
  service_name?: string;
  service?: string;
  severity?: string;
  event_type?: string;
  evidence_ids?: string[];
}

export interface RemediationProposal {
  id: string;
  incident_id: string;
  organization_id: string;
  service_name?: string;
  title?: string;
  description?: string;
  root_cause_reference?: string;
  evidence_ids?: string[];
  action_type?: string;
  target_service?: string;
  target_environment?: string;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: string;
  actions?: any[];
  blast_radius?: {
    affected_services?: string[];
    affected_dependencies?: string[];
    affected_environments?: string[];
    estimated_impact_description?: string;
  };
  blast_radius_services?: string[];
  validation_plan?: any;
  rollback_plan?: any;
  preconditions?: string[];
  validation_criteria?: Record<string, any>;
  rollback_strategy?: string | null;
  parameters?: Record<string, any>;
  plan_summary?: string;
  remediation_hash?: string;
  created_by?: string;
  created_at: string;
  expires_at?: string;
}

export interface DependencyNode {
  id: string;
  name: string;
  type: string;
  environment: string;
  status: string;
  version: string;
  metadata: Record<string, any>;
}

export interface DependencyEdge {
  source: string;
  target: string;
  dependency_type: string;
  protocol: string;
}

export interface SystemDependencyGraph {
  nodes: DependencyNode[];
  edges: DependencyEdge[];
}

export interface AutonomyStatus {
  autonomy_enabled: boolean;
  production_enabled: boolean;
  kill_switch_active: boolean;
  change_freeze_active: boolean;
  circuit_breaker_state: string;
  max_risk_level: string;
  max_tool_calls: number;
}

export interface FaultScenario {
  id: string;
  name: string;
  description: string;
  fault_type: string;
  target_service: string;
  risk_level: string;
  enabled: boolean;
  duration_seconds: number;
  parameters: Record<string, any>;
  expected_telemetry: string;
  expected_impact: string;
}

export interface AuditEvent {
  id: string;
  organization_id: string;
  actor_user_id: string;
  action: string;
  resource_type: string;
  resource_id: string;
  request_id: string;
  event_metadata: Record<string, any>;
  created_at: string;
}

export interface CodeSymbol {
  name: string;
  symbol_type: string;
  file_path: string;
  line_number: number;
  signature?: string;
  docstring?: string;
}

export interface ConnectProductPayload {
  product_name: string;
  product_type: 'microservice' | 'ai_application' | 'api_gateway' | 'database';
  endpoint_url?: string;
  environment?: string;
  probe_health?: boolean;
}

export interface ConnectProductResponse {
  status: 'connected' | 'degraded' | 'pending';
  product_id: string;
  product_name: string;
  product_type: string;
  environment: string;
  connection_token: string;
  proxy_endpoint: string;
  health_checked: boolean;
  message: string;
}

