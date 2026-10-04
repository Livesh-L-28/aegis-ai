# AEGIS AI — Phase 5 Architecture: AI Trust + Reliability

## 1. Overview
Phase 5 introduces the dedicated **Trust Plane** around the Phase 4 AI Reasoning engine. It establishes an impenetrable security perimeter around all AI invocations, tool requests, model routing, and execution telemetry.

No AI reasoning operation, context interpolation, or tool execution ever bypasses the Trust Plane.

```text
                    AI REQUEST
                        │
                        ▼
                 INPUT SECURITY (llmfirewall-core)
                        │
                        ▼
               CONTEXT VALIDATION (Redaction & PII)
                        │
                        ▼
                 MODEL ROUTER (Circuit Breaker & Fallback)
                        │
                        ▼
                LLM / REASONING
                        │
                        ▼
                OUTPUT VALIDATION (llmfirewall-core)
                        │
                        ▼
                 TRUST POLICY (AIPolicyEngine)
                        │
                        ▼
               TOOL-CALL GATEWAY (Deny-by-Default)
                        │
                        ▼
                 SAFE EXECUTION (Read-only tools)
                        │
                        ▼
                     AUDIT & RELIABILITY METRICS
```

---

## 2. Core Pillars of Phase 5

### A. First-Class `llmfirewall-core` Integration
- Packaged adapter `packages/security/llm_firewall/adapter.py` connecting directly to `llmfirewall-core`.
- **Fails Closed**: If the firewall engine is uninitialized or errors, the pipeline defaults to `BLOCK`.
- Intercepts and mitigates:
  - Prompt injections and jailbreaks
  - Unauthorized system prompt overrides
  - Secret leakage and PII exposure
  - Malicious tool execution commands (`rm -rf /`, unauthorized scripts)

### B. Programmatic AI Policy Engine (`AIPolicyEngine`)
- Enforces strict risk levels: `READ_ONLY`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- Phase 5 boundary permits strictly `READ_ONLY` operations. High and Critical risk operations are denied by default.
- Data classification levels: `PUBLIC`, `INTERNAL`, `SENSITIVE`, `SECRET`.
- Sensitive tenant data is strictly restricted to policy-approved model providers.

### C. Health-Aware Model Router (`ModelRouter`)
- Decouples reasoning from raw model endpoints.
- Circuit breaker with states: `CLOSED`, `OPEN`, `HALF_OPEN`.
- Configurable per-call timeouts and bounded retry policies.
- Failover to approved fallback models while maintaining the exact same security, firewall, grounding, and audit gates.

### D. AI Reliability Engine (`AIReliabilityService`)
- Real-time tracking of:
  - Latency breakdown (queue, input validation, model, output verification)
  - Token consumption (input, output, total)
  - Estimated cost calculation based on pricing metadata
  - Grounding rate (supported vs total claims)
  - Hallucination indicators (invalid evidence IDs, unsupported claims, missing citations)
  - Transparent composite AI reliability score (`40% Availability + 35% Grounding + 25% Safety`)

### E. Deny-by-Default Tool Gateway (`ToolGateway`)
- Governed execution gateway for AI actions.
- Unknown tools: `DENY`.
- Missing schemas or parameters: `DENY`.
- Mutating/write tools: `DENY` (Phase 5 permits safe read-only metadata tools only).
- Every tool execution attempt is audited with actor, organization, risk level, and duration.
