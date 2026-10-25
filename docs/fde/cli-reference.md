# FDE CLI Reference

The Forward Deployment Engineering (FDE) capabilities are accessible via the `logicfalcon fde` CLI subcommand.

---

## 1. `logicfalcon fde inspect`

Scans a repository to discover deployment topologies, frameworks, ports, and databases.

### Usage
```bash
logicfalcon fde inspect [OPTIONS]
```

### Options
- `--repo PATH`: Path to the target repository root (default: current directory `.`).
- `--format {text,json}`: Output format (default: `text`).

### Example
```bash
logicfalcon fde inspect --repo . --format json
```

### Output Fields (JSON)
- `services`: List of detected services, framework type, entry points, and configured ports.
- `databases`: List of discovered databases, engine type, and configuration keys.
- `docker_compose_files`: Discovered compose files and service mappings.
- `limitations`: Any paths skipped or unparsed during inspection.

---

## 2. `logicfalcon fde preflight`

Executes non-destructive environmental health checks.

### Usage
```bash
logicfalcon fde preflight [OPTIONS]
```

### Options
- `--repo PATH`: Target repository path (default: `.`).
- `--format {text,json}`: Output format (default: `text`).
- `--check-ports`: Verify port availability for discovered services.
- `--check-docker`: Verify Docker daemon connectivity and status.

### Example
```bash
logicfalcon fde preflight --repo . --format text
```

---

## 3. `logicfalcon fde plan`

Generates an executable or dry-run DAG mission plan for a deployment operation.

### Usage
```bash
logicfalcon fde plan [OPTIONS]
```

### Options
- `--repo PATH`: Target repository path (default: `.`).
- `--operation {deploy,migrate,rollback,verify}`: Target operation category.
- `--output PATH`: File path to save the generated mission plan JSON.
- `--format {text,json}`: Output format (default: `text`).

### Example
```bash
logicfalcon fde plan --repo . --operation deploy --output plan.json
```

---

## 4. `logicfalcon fde runbook`

Generates an operational handover runbook from a mission plan.

### Usage
```bash
logicfalcon fde runbook [OPTIONS]
```

### Options
- `--mission-file PATH`: Path to the mission plan JSON file (required).
- `--output-format {markdown,json}`: Runbook format (default: `markdown`).
- `--output-file PATH`: Optional path to write runbook output.

### Example
```bash
logicfalcon fde runbook --mission-file plan.json --output-format markdown --output-file RUNBOOK.md
```

---

## 5. `logicfalcon fde run`

Executes a planned mission with strict policy and approval enforcement.

### Usage
```bash
logicfalcon fde run [OPTIONS]
```

### Options
- `--mission-file PATH`: Path to the mission plan JSON file (required).
- `--dry-run`: Execute in simulation mode without applying external mutating side effects.
- `--approved`: Confirm explicit execution approval.
- `--approval-token TOKEN`: Cryptographic HMAC-SHA256 parameter-bound approval token for mutating operations.
- `--checkpoint-dir PATH`: Directory to store mission state checkpoints (default: `.fde_checkpoints`).
- `--format {text,json}`: Output format (default: `text`).

### Examples
```bash
# Dry-run execution (safe simulation)
logicfalcon fde run --mission-file plan.json --dry-run

# Approved execution
logicfalcon fde run --mission-file plan.json --approved --approval-token <TOKEN>
```

### Exit Codes
- `0`: Execution completed successfully; all postconditions verified.
- `1`: Step execution failed, postcondition violated, or approval denied.
- `2`: Invalid CLI arguments or malformed mission file.
