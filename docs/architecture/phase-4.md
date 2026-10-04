# Phase 4 Architecture — Evidence + AI Reasoning

## Overview

Phase 4 bridges observational signals (Phase 2) and structural intelligence (Phase 3) through a deterministic Evidence Engine and structured LLM Reasoning pipeline:

```text
                 INCIDENT
                    │
                    ▼
             EVIDENCE ENGINE
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
    Telemetry      Code       Knowledge
       │            │            │
       └────────────┼────────────┘
                    ▼
              CORRELATION
                    │
                    ▼
              TIMELINE
                    │
                    ▼
             HYPOTHESES
                    │
                    ▼
          EVIDENCE VERIFICATION
                    │
                    ▼
             AI REASONING
                    │
                    ▼
           STRUCTURED RCA
```

## Fundamental Architectural Rule

> **Evidence first. Reasoning second.**
> **The LLM must reason over evidence, not invent evidence.**

If LLM inference providers are unavailable or offline, the deterministic evidence collection, correlation, timeline construction, and rule-based hypothesis scoring layers continue to operate with zero degradation.

## Components

1. **Incident Representation**:
   - Tenant-scoped model tracking title, severity, status, source, detected_at, and resolution.
2. **Investigation Lifecycle**:
   - States: `CREATED` -> `COLLECTING_EVIDENCE` -> `ANALYZING` -> `REASONING` -> `COMPLETED` / `FAILED`.
   - Guaranteed idempotency guarding against concurrent runs.
3. **Evidence Engine**:
   - Multi-source provider abstraction (`TelemetryEvidenceProvider`, `DeploymentEvidenceProvider`, `SystemEvidenceProvider`, `CodeEvidenceProvider`, `KnowledgeEvidenceProvider`).
   - Normalization into canonical `EvidenceItem` schema with immutable provenance.
   - Deduplication and deterministic ranking factoring severity, signal type, and service affinity.
4. **Hypothesis Engine**:
   - Rule-based generation across telemetry degradation, cache/Redis breakdowns, and deployment regressions.
   - Scoring with explicit contradictive evidence discovery and penalties.
5. **Bounded Reasoning Context**:
   - Top-K evidence limit and context token budgeting.
   - Deterministic SHA-256 context hashing for evaluation reproducibility.
6. **Reasoning Provider Abstraction**:
   - `ReasoningModelProvider` with `MockReasoningProvider` for deterministic CI and extension points for local Ollama / OpenAI-compatible backends.
7. **Grounding Validation & Hallucination Defense**:
   - Validates that every evidence ID cited in the output exists in the investigation packet. Fabricated IDs trigger immediate rejection.
   - Uncertainty awareness: If evidence is insufficient, root cause is reported as `UNKNOWN` with low confidence.
