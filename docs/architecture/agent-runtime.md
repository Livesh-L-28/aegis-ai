# Bounded Reliability Agent Runtime

## 1. Loop Orchestration

The `ReliabilityAgent` executes a deterministic reliability loop for an active incident:

```text
Incident Detected
   ↓
Collect Telemetry & Logs
   ↓
Correlate Evidence
   ↓
Isolate Root Cause
   ↓
Plan Remediation & Rollback
   ↓
Evaluate Autonomy Policy
   ↓
[Auto-Execute OR Wait Human Approval]
   ↓
Preflight Verification
   ↓
Sandbox Execution
   ↓
Post-Remediation Verification
   ↓
[Succeeded -> Learn Operationally | Failed -> Auto-Rollback]
```

## 2. Evidence & Tool Budgets

Agent runtime tools are strictly mediated:
- Only registered tools can be invoked via `ToolGateway`.
- Tool calls are budgeted and deduplicated to prevent repetitive loops.
- Shell and raw OS commands remain completely blocked.
