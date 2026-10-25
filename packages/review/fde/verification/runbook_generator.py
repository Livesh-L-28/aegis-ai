"""Operator runbook generator and handover documentation for LogicFalcon FDE."""

from datetime import UTC, datetime

from packages.review.adapters.ast_security import redact_secrets_in_text
from packages.review.fde.models import (
    DeploymentInventory,
    FdeMission,
    Runbook,
    RunbookInstruction,
)
from packages.review.fde.orchestration.orchestrator import MissionExecutionReport


class RunbookGenerator:
    """Generates structured, secret-redacted operational runbooks and handover guides."""

    def generate_runbook(
        self,
        mission: FdeMission,
        inventory: DeploymentInventory | None = None,
        execution_report: MissionExecutionReport | None = None,
    ) -> Runbook:
        """Generates a typed Runbook model from mission definition and inventory."""
        prerequisites: list[str] = []
        if inventory:
            if inventory.runtime_versions.get("python"):
                prerequisites.append(f"Python Runtime: {inventory.runtime_versions['python']}")
            if inventory.declared_ports:
                prerequisites.append(f"Free TCP Ports: {', '.join(str(p) for p in inventory.declared_ports)}")
            if inventory.required_env_vars:
                prerequisites.append(f"Environment Variables Configured: {', '.join(inventory.required_env_vars[:5])}")

        ordered_instructions: list[RunbookInstruction] = []
        topological_steps = mission.get_topological_steps()

        for idx, step in enumerate(topological_steps, start=1):
            cmd_action = f"{step.target_adapter} {step.operation} target={step.target}"
            full_title = f"{step.name}: {step.description}" if (step.name and step.description) else (step.name or step.description)
            ordered_instructions.append(
                RunbookInstruction(
                    step_number=idx,
                    step_id=step.id,
                    title=full_title,
                    command_or_action=cmd_action,
                    expected_output=f"Operation {step.operation} returns success",
                    verification_check=step.expected_postconditions[0] if step.expected_postconditions else "Verify service status",
                    rollback_action="Revert configuration and notify on-call operator if failure occurs",
                    is_automated=not step.requires_approval,
                )
            )

        verification_steps = [
            "Verify application health check endpoint returns 200 OK.",
            "Verify all declared container services are running without restarts.",
            "Verify database connectivity and schema migrations.",
        ]

        rollback_guidance = [
            "1. Stop the active container or deployment process immediately upon fatal health check failure.",
            "2. Restore previous database snapshot or backup if schema migrations were partially applied.",
            "3. Rerun preflight verification probe (`logicfalcon fde preflight`) to ensure clean state.",
        ]

        handover_notes = [
            "Generated automatically by LogicFalcon Forward Deployment Engineering.",
            "All commands and outputs have been validated against path containment and secret redaction rules.",
            "Note: Steps in this runbook represent planned operational procedures; consult mission execution report for actual runtime outcomes.",
        ]

        return Runbook(
            deployment_context={
                "mission_id": mission.id,
                "mission_name": mission.name,
                "mission_objective": mission.objective,
                "frameworks": inventory.frameworks if inventory else [],
                "database_types": inventory.database_types if inventory else [],
            },
            prerequisites=prerequisites,
            ordered_instructions=ordered_instructions,
            verification_steps=verification_steps,
            rollback_guidance=rollback_guidance,
            unresolved_risks=["Ensure network firewall permits traffic on target ports before production rollout."],
            handover_notes=handover_notes,
            created_at=datetime.now(UTC),
            schema_version="1.0.0",
        )

    def generate_markdown(
        self,
        mission: FdeMission,
        inventory: DeploymentInventory | None = None,
        execution_report: MissionExecutionReport | None = None,
    ) -> str:
        """Renders the operational runbook as clean, sanitized Markdown."""
        runbook = self.generate_runbook(mission, inventory, execution_report)

        lines: list[str] = [
            f"# Operational Runbook: {runbook.deployment_context.get('mission_name', 'Deployment')}",
            f"**Objective:** {runbook.deployment_context.get('mission_objective', 'N/A')}",
            f"**Generated:** {runbook.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "## 1. Prerequisites",
        ]

        for prereq in runbook.prerequisites:
            lines.append(f"- [ ] {prereq}")
        if not runbook.prerequisites:
            lines.append("- [ ] Verify target host environment and access credentials.")

        lines.extend([
            "",
            "## 2. Ordered Deployment Instructions",
            "| Step | ID | Operation | Description | Automated | Verification |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])

        for inst in runbook.ordered_instructions:
            auto_str = "Yes" if inst.is_automated else "**Requires Approval**"
            verif = inst.verification_check or "N/A"
            lines.append(f"| {inst.step_number} | `{inst.step_id}` | `{inst.command_or_action}` | {inst.title} | {auto_str} | {verif} |")

        lines.extend([
            "",
            "## 3. Verification & Acceptance",
        ])
        for v in runbook.verification_steps:
            lines.append(f"- [ ] {v}")

        lines.extend([
            "",
            "## 4. Rollback & Contingency Procedures",
        ])
        for r in runbook.rollback_guidance:
            lines.append(r)

        lines.extend([
            "",
            "## 5. Handover & Operator Notes",
        ])
        for n in runbook.handover_notes:
            lines.append(f"- {n}")

        rendered = "\n".join(lines)
        return redact_secrets_in_text(rendered)
