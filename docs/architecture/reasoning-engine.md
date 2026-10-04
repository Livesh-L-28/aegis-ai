# AI Reasoning Engine Architecture

The Reasoning Engine receives a bounded evidence packet and generates structured, grounded root-cause analyses (RCA).

## Bounded Reasoning Context

Input context is bounded to prevent token explosion:
- Top-K evidence items (max 15 items ranked by relevance score).
- Chronological incident timeline.
- Top candidate hypotheses and contradiction evaluations.
- Service topology propagation summary.
- Deterministic `context_hash` (SHA-256) computed over evidence and hypotheses IDs for evaluation reproducibility.

## System Prompt Boundary & Untrusted Data

Logs, trace attributes, code diffs, and knowledge documents are explicitly designated as **DATA** in prompt templates.
Instructions embedded inside logs or runbooks are treated strictly as passive data and never executed.

## Structured Output & Grounding

The reasoning provider must return a validated JSON payload:

```json
{
  "summary": "Order Service experiencing cascading timeouts due to PostgreSQL query latency",
  "root_cause": "Database Query Latency Degradation",
  "confidence": 0.88,
  "affected_services": ["order-service", "gateway"],
  "supporting_evidence_ids": ["uuid-1", "uuid-2"],
  "contradicting_evidence_ids": [],
  "reasoning_steps": [
    {"type": "OBSERVED FACT", "statement": "...", "evidence_id": "uuid-1"},
    {"type": "INFERRED RELATIONSHIP", "statement": "...", "evidence_id": "uuid-2"},
    {"type": "CONCLUSION", "statement": "...", "evidence_id": "uuid-1"},
    {"type": "UNCERTAINTY", "statement": "...", "evidence_id": null}
  ]
}
```

## Validation & Confidence

1. **Grounding Validation**:
   - `GroundingValidator.validate_groundedness()` asserts that every cited ID exists in the investigation packet. Fabricated IDs raise `GroundingValidationError` and mark the investigation as `FAILED`.
2. **Confidence Adjustment**:
   - Incorporates model confidence, average supporting evidence quality, and penalties for contradictory signals.
   - Low or insufficient evidence results in `root_cause="UNKNOWN"` and `confidence <= 0.3`.
