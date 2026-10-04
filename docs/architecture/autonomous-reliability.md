# Autonomous Reliability Engine

## 1. Decision Engine Logic

The `AutonomyDecisionEngine` consumes:
- Incident severity and root cause hypothesis
- Remediator action risk and calculated architectural blast radius
- Environment policy configuration and action allowlists
- System health and error budget status
- Circuit breaker and kill switch states

It outputs one of:
- `AUTONOMOUSLY_EXECUTE`: Action is strictly allowlisted, risk is low, blast radius <= 1, no freeze or kill switch active.
- `REQUIRE_APPROVAL`: Risk exceeds low, or action is outside auto-allowlist, or circuit breaker is tripped.
- `RECOMMEND_ONLY`: Active change freeze halts mutations while permitting advisory output.
- `DENY`: Critical risk, missing rollback plan, or kill switch engaged.

## 2. Bounded Agent State Machine

```text
CREATED -> INVESTIGATING -> REASONING -> PROPOSING -> AWAITING_APPROVAL -> EXECUTING -> VALIDATING -> COMPLETED
                                                           │                              │
                                                           └─────────> FAILED             └─────────> ESCALATING -> ROLLED_BACK
```

## 3. Runaway Agent Safeguards

Every autonomous workflow enforces hard bounds:
- `max_iterations`: Default 10
- `max_tool_calls`: Default 15
- `max_cost_usd`: Default $2.00
- `max_duration_seconds`: Default 120s

Exceeding any boundary immediately aborts execution and logs an escalation event.
