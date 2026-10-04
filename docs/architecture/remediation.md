# Remediation Domain & Lifecycle

## 1. Domain Entities & Status Transitions

Remediation proposals advance through explicit states:

```text
DRAFT -> PROPOSED -> PENDING_APPROVAL -> APPROVED -> PREFLIGHT -> EXECUTING -> VALIDATING -> SUCCEEDED
                           │                                                       │
                           ├─────────> REJECTED                                    ├─────────> FAILED -> ROLLING_BACK -> ROLLED_BACK
                           │                                                       │
                           └─────────> EXPIRED                                     └─────────> CANCELLED
```

## 2. Action Registry & Type Safety

Only explicitly registered action types are permitted:

- `SERVICE_RESTART`: Graceful service restarts.
- `CONFIG_CHANGE`: Typed key-value modifications with schema validation.
- `CACHE_INVALIDATION`: Targeted key or pattern-based cache evictions.
- `SCALING`: Horizontal or vertical capacity adjustments.
- `CODE_PATCH`: Isolated Git branch modifications via pull request.
- `DEPLOYMENT`: Version rollouts using safe deployment strategies.
- `ROLLBACK`: Restorations to previous known-good deployment versions.

## 3. Server-Side Risk Escalation

The platform evaluates:

$$\text{Proposal Risk} = \max(\text{Risk}(\text{Action}_i))$$

The AI cannot downgrade the calculated risk level. Destructive operations (such as table truncation or database drops) escalate unconditionally to `CRITICAL` risk and are denied by default policy.
