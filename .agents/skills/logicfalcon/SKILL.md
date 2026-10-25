---
name: logicfalcon
description: Automated, deterministic software engineering intelligence and code review powered by LogicFalcon (AEGIS AI). Use to review code changes, detect security and quality flaws, explain findings, and safely apply proposed remediations.
---

# LogicFalcon Engineering Intelligence Skill

LogicFalcon provides deterministic code review, AST static analysis, and safe remediation proposals across Python, TypeScript, and JavaScript codebases.

## When to Use

Activate this skill when:
- Reviewing pull requests, git diffs, or individual files for quality and security defects.
- Detecting AST-level vulnerabilities (e.g., dynamic `eval()`, SQL injections, mutable default arguments, shell injections).
- Verifying whether a code fix introduces regressions or syntax errors.
- Running non-destructive capability diagnostics.

## Available Workflows

### 1. Reviewing a Single File
To review a target file:
```bash
python3 -m logicfalcon.cli review --file <path/to/file.py> --format json
```
Or when reviewing an in-memory or unsaved buffer:
```bash
cat << 'EOF' | python3 -m logicfalcon.cli review --file <file.py> --stdin --format json
<buffer content>
EOF
```

### 2. Reviewing Workspace Git Changes
To inspect uncommitted working tree changes:
```bash
python3 -m logicfalcon.cli review --unstaged --format json
```
To inspect staged changes:
```bash
python3 -m logicfalcon.cli review --staged --format json
```
To compare against a base branch:
```bash
python3 -m logicfalcon.cli review --base origin/main --format json
```

### 3. Applying Automated Fixes
When a finding provides a `proposed_fix`, inspect the preview first:
```bash
python3 -m logicfalcon.cli apply-fix --fix '<json_fix_payload>' --dry-run
```
To apply the change to disk with syntax verification and automated `.bak` backup:
```bash
python3 -m logicfalcon.cli apply-fix --fix '<json_fix_payload>' --approved
```

### 4. Running Capability Doctor
```bash
python3 -m logicfalcon.cli doctor --format json
```

### 5. Forward Deployment Engineering (FDE)
Use FDE commands to assess deployment topology, execute non-destructive preflight checks, plan missions, generate operational handover runbooks, and run controlled execution:

- **Deployment Discovery**:
  ```bash
  python3 -m logicfalcon.cli fde inspect --repo . --format json
  ```
- **Environmental Preflight Probes**:
  ```bash
  python3 -m logicfalcon.cli fde preflight --repo . --format json
  ```
- **Mission Planning (Dry-run)**:
  ```bash
  python3 -m logicfalcon.cli fde plan --repo . --operation deploy --output plan.json
  ```
- **Operational Runbook Generation**:
  ```bash
  python3 -m logicfalcon.cli fde runbook --mission-file plan.json --output-format markdown
  ```
- **Controlled Execution**:
  ```bash
  # Simulation / dry-run mode (read-only):
  python3 -m logicfalcon.cli fde run --mission-file plan.json --dry-run
  # Approved execution with parameter-bound cryptographic approval token:
  python3 -m logicfalcon.cli fde run --mission-file plan.json --approved --approval-token <TOKEN>
  ```

## Best Practices
- Never apply fixes or execute mutating FDE steps without explicit human approval.
- Always run preflight health probes before initiating a mission plan.
- Checkpoints are saved with `0o600` permissions and recursive credential redaction.
- Keep all analysis local, bounded, and deterministic.
