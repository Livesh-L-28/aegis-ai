# FDE Python SDK Reference

The Forward Deployment Engineering (FDE) programmatic API is exposed directly through the `logicfalcon` top-level package namespace.

---

## 1. Primary SDK Entry Points

```python
from pathlib import Path
from logicfalcon import (
    fde_inspect,
    fde_preflight,
    fde_plan,
    fde_generate_runbook,
    fde_run_mission,
    DeploymentInventory,
    FdeMission,
    FdeStep,
    MissionOrchestrator,
    PolicyGateway,
    OperationCategory,
    MissionStatus,
)
```

---

## 2. Functions

### `fde_inspect(repo_root: Path | str) -> DeploymentInventory`
Discovers deployment configuration, services, frameworks, and databases in the given repository path.

```python
inventory = fde_inspect(Path("/path/to/repo"))
print(f"Frameworks: {inventory.frameworks}")
print(f"Declared Ports: {inventory.declared_ports}")
print(f"Databases: {inventory.database_types}")
```

---

### `fde_preflight(repo_root: Path | str, check_ports: bool = True, check_docker: bool = False) -> PreflightReport`
Executes non-destructive preflight environmental health probes.

```python
report = fde_preflight(Path("/path/to/repo"), check_ports=True)
print(f"Overall Preflight: {report.status}")
for finding in report.findings:
    print(f"[{finding.severity}] {finding.title}: {finding.message}")
```

---

### `fde_plan(repo_root: Path | str = ".") -> FdeMission`
Constructs a validated DAG mission plan from repository inspection.

```python
mission = fde_plan(Path("/path/to/repo"))
print(f"Mission ID: {mission.id}")
for step in mission.steps:
    print(f"Step {step.id}: {step.target_adapter} -> {step.operation} (Risk: {step.risk_level})")
```

---

### `fde_generate_runbook(mission: FdeMission, inventory: DeploymentInventory | None = None, execution_report: MissionExecutionReport | None = None) -> Runbook`
Generates an operational handover runbook model from a planned mission and inventory.

```python
runbook = fde_generate_runbook(mission, inventory=inventory)
print(f"Instructions count: {len(runbook.ordered_instructions)}")
Path("HANDOVER_RUNBOOK.json").write_text(runbook.to_json())
```

---

### `fde_run_mission(mission: FdeMission, registry: AdapterRegistry | None = None, approval_tokens: dict[str, str] | None = None) -> MissionExecutionReport`
Executes an authorized FDE mission DAG through the policy gateway with postcondition verification.

```python
# Dry-run execution
report = fde_run_mission(mission)
print(f"Execution status: {report.status}")

# Approved execution with approval tokens
token = policy_gateway.generate_approval_token(step_id="step-1", target_adapter="system", operation="deploy")
live_report = fde_run_mission(mission, approval_tokens={"step-1": token})
```

---

## 3. Data Models

### `FdeStep`
Represents an individual step in a mission DAG:
- `id`: Unique identifier (string).
- `name`: Human-readable step name.
- `description`: Detailed step action description.
- `operation_category`: `OperationCategory` (`READ_ONLY`, `CONTAINED_WRITE`, `EXTERNAL_MUTATING`, `DANGEROUS`).
- `risk_level`: `StepRiskLevel` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `target_adapter`: Target adapter identifier (`system`, `http`, `docker`, `postgres`, `mcp`, `aws`).
- `operation`: Specific adapter operation to invoke.
- `target`: Target endpoint, host, or resource identifier.
- `parameters`: Dictionary of parameters passed to the adapter.
- `dependencies`: List of `StepDependency` objects.
- `expected_postconditions`: List of postcondition assertion definitions.

### `FdeMission`
Represents the complete mission DAG:
- `id`: Unique mission identifier (UUID string).
- `name`: Mission title.
- `objective`: Operational deployment objective.
- `steps`: Ordered list of `FdeStep` definitions.
- `created_at`: UTC timestamp of mission creation.
- `policy_context`: Execution policy metadata dictionary.
