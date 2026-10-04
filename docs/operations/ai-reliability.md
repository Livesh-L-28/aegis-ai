# AI Reliability & Telemetry Operations

## Overview
The `AIReliabilityService` tracks the operational efficiency, safety, and correctness of all AI operations in AEGIS.

## Tracked Metrics

### 1. Latency Breakdown
- `queue_duration_ms`: Duration waiting in execution queue.
- `firewall_scan_duration_ms`: Latency of `llmfirewall-core` prompt scan.
- `model_duration_ms`: Time spent during LLM generation.
- `output_validation_duration_ms`: Verification of output schema, grounding, and output firewall.
- `total_ai_latency_ms`: Complete lifecycle execution duration.

### 2. Token & Cost Accounting
- Real-time aggregation of `input_tokens` and `output_tokens`.
- Dynamic pricing models configured per model metadata (e.g., `$0.0015 / 1k input`, `$0.0020 / 1k output`).
- Records stored in PostgreSQL table `ai_usage_records`.

### 3. Grounding & Hallucination Indicators
- `grounding_rate`: Proportion of claimed evidence verified by `GroundingValidator`.
- `invalid_evidence_references`: Number of hallucinated IDs rejected by grounding validation.
- `unsupported_claims`: Conclusions lacking direct evidence citations.
- `schema_violations`: Rejected malformed structured JSON responses.

### 4. Transparent Reliability Score
AEGIS computes a decomposable composite reliability score rather than an opaque rating:

$$\text{Reliability Score} = 0.40 \times \text{Availability} + 0.35 \times \text{Grounding} + 0.25 \times \text{Safety}$$

- **Availability Rate**: Proportion of AI requests completing without infrastructure or provider timeouts.
- **Grounding Rate**: Proportion of substantiated claims backed by verified evidence.
- **Safety Rate**: Proportion of clean requests with no prompt injection or policy violations.

## Integration with Standalone Packages

AEGIS AI integrates two external foundational engines through clean adapter boundaries:
1. **`llmfirewall-core 1.0.0`**: Provides pre-execution prompt injection, secret leakage, and destructive tool-call prevention at the AI Security boundary (`packages/security/llm_firewall/`).
2. **`aireliability 0.1.0`**: Provides deep execution trace analysis, causal root cause diagnosis (`RootCauseAnalyzer`), and declarative expectation evaluations (`MaxLatency`, `OutputContains`) at the AI Reliability engine boundary (`packages/reliability/`).

### Canonical Architecture
```text
                         AEGIS AI
                            │
       ┌────────────────────┼────────────────────┐
       │                    │                    │
       ↓                    ↓                    ↓
  AI Security          AI Reliability        AI Control
       │                    │                    │
       ↓                    ↓                    ↓
llmfirewall-core      aireliability       Policy Engine
(v1.0.0 adapter)     (v0.1.0 adapter)            │
       │                    │               Autonomy
       │                    │                    │
       └──────────────┬─────┴────────────────────┘
                      ↓
                AI Reasoning
                      ↓
                 Evidence
                      ↓
                 Remediation
                      ↓
                  Validation
                      ↓
                   Audit
                      ↓
                Evaluation
```

## Telemetry APIs
- `GET /api/v1/ai/reliability`: Aggregated tenant reliability score and component breakdown.
- `GET /api/v1/ai/usage`: Historical token usage and financial cost accounting.
- `GET /api/v1/ai/health`: Real-time operational health across API, Firewall, Policy Engine, Model Router, Grounding Validator, and AI Reliability Engine (`aireliability`).
