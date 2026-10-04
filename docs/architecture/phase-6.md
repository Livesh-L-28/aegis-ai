# AEGIS AI — Phase 6: AI Remediation + Human Approval + Deployment

## 1. Architectural Overview

Phase 6 introduces **controlled remediation**, transitioning AEGIS from an AI platform that diagnoses incidents into a governed reliability platform that safely proposes, approves, executes, and validates operational remedies.

```text
                     INCIDENT
                        │
                        ▼
                 INVESTIGATION
                        │
                        ▼
                 ROOT CAUSE
                        │
                        ▼
              REMEDIATION PLANNER
                        │
                        ▼
              REMEDIATION PROPOSAL
                        │
                        ▼
                 RISK ENGINE
                        │
                        ▼
                POLICY ENGINE
                        │
                ┌───────┴────────┐
                │                │
             DENIED            APPROVAL
                │                │
                ▼                ▼
              AUDIT         HUMAN REVIEW
                                 │
                          ┌──────┴──────┐
                          │             │
                       REJECT        APPROVE
                          │             │
                          ▼             ▼
                        AUDIT       PREFLIGHT
                                       │
                                       ▼
                                    SANDBOX
                                       │
                                       ▼
                                    VALIDATE
                                       │
                                       ▼
                                   DEPLOYMENT
                                       │
                                       ▼
                              POST-DEPLOYMENT
                                  VALIDATION
                                       │
                              ┌────────┴────────┐
                              │                 │
                           SUCCESS           FAILURE
                              │                 │
                              ▼                 ▼
                            AUDIT            ROLLBACK
```

## 2. Invariants & Guardrails

1. **AI Proposes, Policy Governs, Human Authorizes**: The LLM suggests intent; the server-side risk engine calculates risk independent of AI declarations.
2. **Zero Arbitrary Shell**: `subprocess(shell=True)` and string command execution are strictly prohibited.
3. **Cryptographic Binding**: Human approval cryptographically binds to the deterministic SHA256 hash of the proposal. Any plan change invalidates previous approval.
4. **Separation of Duties**: The author of a remediation proposal cannot approve their own high-risk proposal.
5. **Preflight & Dry-Run**: Targets, service existence, action schemas, rollback feasibility, and hash integrity must pass before any execution commences.
6. **Post-Remediation Verification & Rollback**: Automatic or guided rollback triggers immediately if operational validation fails.
