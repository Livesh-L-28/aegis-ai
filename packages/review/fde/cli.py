"""Command-line interface for LogicFalcon Forward Deployment Engineering (FDE)."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from packages.review.fde.adapters import (
    AdapterRegistry,
    AwsAdapter,
    DockerAdapter,
    HttpAdapter,
    McpAdapter,
    PostgresAdapter,
    SystemAdapter,
)
from packages.review.fde.discovery import DeploymentDiscoveryEngine
from packages.review.fde.models import (
    FdeMission,
    FdeStep,
    OperationCategory,
    PreflightStatus,
    StepRiskLevel,
)
from packages.review.fde.orchestration import (
    MissionOrchestrator,
    MissionStatus,
    PolicyGateway,
)
from packages.review.fde.preflight import PreflightRunner
from packages.review.fde.verification import (
    FdeCheckpointStore,
    RunbookGenerator,
)


def _build_default_registry() -> AdapterRegistry:
    """Constructs an AdapterRegistry with all standard FDE adapters registered."""
    registry = AdapterRegistry()
    registry.register(SystemAdapter())
    registry.register(HttpAdapter())
    registry.register(DockerAdapter())
    registry.register(PostgresAdapter())
    registry.register(McpAdapter())
    registry.register(AwsAdapter())
    return registry


def run_inspect(args: argparse.Namespace) -> int:
    """Statically inspects repository topography and deployment requirements."""
    repo_path = Path(args.repo).resolve()
    engine = DeploymentDiscoveryEngine(repo_root=repo_path)
    inventory = engine.discover()

    if args.json:
        sys.stdout.write(inventory.model_dump_json(indent=2) + "\n")
        return 0

    sys.stdout.write(f"🦅  LogicFalcon FDE — Deployment Topography Inspection: {repo_path.name}\n")
    sys.stdout.write("=" * 65 + "\n")
    sys.stdout.write(f"Frameworks Detected: {', '.join(inventory.frameworks) or 'None'}\n")
    sys.stdout.write(f"Declared Ports: {', '.join(str(p) for p in inventory.declared_ports) or 'None'}\n")
    sys.stdout.write(f"Database Services: {', '.join(inventory.database_types) or 'None'}\n")
    sys.stdout.write(f"Container Definitions: {', '.join(inventory.container_definitions) or 'None'}\n")
    sys.stdout.write(f"Required Environment Variables ({len(inventory.required_env_vars)}):\n")
    for v in inventory.required_env_vars[:10]:
        sys.stdout.write(f"  - {v}\n")
    if len(inventory.required_env_vars) > 10:
        sys.stdout.write(f"  ... and {len(inventory.required_env_vars) - 10} more\n")
    sys.stdout.write("=" * 65 + "\n")
    return 0


def run_preflight(args: argparse.Namespace) -> int:
    """Runs bounded, non-mutating preflight readiness verification probes."""
    repo_path = Path(args.repo).resolve()
    runner = PreflightRunner(
        repo_root=repo_path,
        check_ports=not args.no_ports,
        check_env_vars=not args.no_env,
        check_docker=args.docker,
        check_dns=args.dns,
        http_health_url=args.health_url,
    )
    report = runner.run_preflight()

    if args.json:
        sys.stdout.write(report.to_json(indent=2) + "\n")
    else:
        sys.stdout.write("🦅  LogicFalcon FDE — Environment Preflight Readiness Probe\n")
        sys.stdout.write("=" * 65 + "\n")
        sys.stdout.write(f"Preflight Status: {report.status.value}\n")
        sys.stdout.write(f"Findings: {len(report.findings)} | Observed Evidence: {len(report.observed_evidence)}\n")
        for f in report.findings:
            sys.stdout.write(f"[{f.severity.value}] {f.title}: {f.message}\n")
            if f.remediation:
                sys.stdout.write(f"       Action: {f.remediation}\n")
        sys.stdout.write("=" * 65 + "\n")

    if report.status == PreflightStatus.BLOCKED:
        return 2
    elif report.status == PreflightStatus.FAILED:
        return 1
    return 0


def run_capabilities(args: argparse.Namespace) -> int:
    """Lists registered adapters, declared capabilities, risk levels, and health status."""
    registry = _build_default_registry()
    health_reports = registry.check_all_health()

    payload: dict[str, Any] = {"adapters": {}}
    for adapter_id in registry.list_adapters():
        adapter = registry.get(adapter_id)
        if not adapter:
            continue
        h = health_reports.get(adapter_id)
        payload["adapters"][adapter_id] = {
            "version": adapter.version,
            "health": h.status.value if h else "UNKNOWN",
            "message": h.message if h else "",
            "capabilities": [
                {
                    "name": cap.name,
                    "description": cap.description,
                    "category": cap.operation_category.value,
                    "risk": cap.risk_level.value,
                    "requires_approval": cap.requires_approval,
                }
                for cap in adapter.capabilities
            ],
        }

    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 0

    sys.stdout.write("🦅  LogicFalcon FDE — Registered Adapter Capabilities\n")
    sys.stdout.write("=" * 65 + "\n")
    for ad_id, ad_data in payload["adapters"].items():
        sys.stdout.write(f"Adapter: {ad_id} (Health: {ad_data['health']})\n")
        for cap in ad_data["capabilities"]:
            approval_str = "[APPROVAL REQUIRED]" if cap["requires_approval"] else "[AUTO]"
            sys.stdout.write(f"  - {cap['name']} ({cap['category']}, {cap['risk']}) {approval_str}\n")
    sys.stdout.write("=" * 65 + "\n")
    return 0


def run_plan(args: argparse.Namespace) -> int:
    """Plans a deployment verification mission without executing operations."""
    repo_path = Path(args.repo).resolve()
    engine = DeploymentDiscoveryEngine(repo_root=repo_path)
    inventory = engine.discover()

    steps: list[FdeStep] = []
    # Plan step 1: Environment probe
    steps.append(
        FdeStep(
            id="plan-1-runtime-probe",
            name="Verify Runtime Compatibility",
            description="Verify active Python environment meets requirements",
            target_adapter="system",
            operation="check_runtime",
            target="python",
            operation_category=OperationCategory.READ_ONLY,
            risk_level=StepRiskLevel.LOW,
        )
    )

    # Plan step 2: Declared ports verification
    for port in inventory.declared_ports[:3]:
        steps.append(
            FdeStep(
                id=f"plan-port-{port}",
                name=f"Verify Port {port}",
                description=f"Verify localhost binding availability for port {port}",
                target_adapter="system",
                operation="verify_port",
                target=f"localhost:{port}",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
            )
        )

    mission = FdeMission(
        name=f"Deployment Mission: {repo_path.name}",
        objective="Inspect and verify deployment prerequisites and service endpoints",
        steps=steps,
    )

    if args.json:
        sys.stdout.write(mission.to_json(indent=2) + "\n")
    else:
        sys.stdout.write(f"🦅  LogicFalcon FDE — Mission Plan: {mission.name}\n")
        sys.stdout.write(f"Objective: {mission.objective}\n")
        sys.stdout.write("=" * 65 + "\n")
        for s in mission.get_topological_steps():
            sys.stdout.write(f"Step '{s.id}': {s.name} ({s.operation_category.value})\n")
        sys.stdout.write("=" * 65 + "\n")
        sys.stdout.write("Note: Plan generated statically. No infrastructure operations executed.\n")
    return 0


def run_runbook(args: argparse.Namespace) -> int:
    """Generates an operator runbook from a mission JSON file."""
    mission_file = Path(args.mission_file).resolve()
    if not mission_file.is_file():
        sys.stderr.write(f"Error: Mission file '{args.mission_file}' not found.\n")
        return 1

    try:
        content = mission_file.read_text(encoding="utf-8")
        data = json.loads(content)
        mission = FdeMission.model_validate(data)
    except Exception as e:
        sys.stderr.write(f"Error parsing mission file: {e}\n")
        return 1

    generator = RunbookGenerator()
    if args.json:
        runbook = generator.generate_runbook(mission)
        sys.stdout.write(runbook.to_json(indent=2) + "\n")
    else:
        md = generator.generate_markdown(mission)
        sys.stdout.write(md + "\n")
    return 0


def run_mission_cli(args: argparse.Namespace) -> int:
    """Executes a mission definition file with policy enforcement."""
    mission_file = Path(args.mission_file).resolve()
    if not mission_file.is_file():
        sys.stderr.write(f"Error: Mission file '{args.mission_file}' not found.\n")
        return 1

    try:
        content = mission_file.read_text(encoding="utf-8")
        data = json.loads(content)
        mission = FdeMission.model_validate(data)
    except Exception as e:
        sys.stderr.write(f"Error parsing mission file: {e}\n")
        return 1

    registry = _build_default_registry()
    policy_gateway = PolicyGateway(registry)

    tokens: dict[str, str] = {}
    if args.approve_token:
        # e.g. step_id:token or global token
        for t_spec in args.approve_token:
            if ":" in t_spec:
                s_id, tok = t_spec.split(":", 1)
                tokens[s_id.strip()] = tok.strip()
            else:
                for s in mission.steps:
                    tokens[s.id] = t_spec.strip()

    orchestrator = MissionOrchestrator(registry, policy_gateway)
    report = orchestrator.run_mission(mission, approval_tokens=tokens)

    if args.save_checkpoint:
        store = FdeCheckpointStore()
        saved = store.save_checkpoint(report)
        sys.stderr.write(f"Checkpoint saved to {saved}\n")

    if args.json:
        sys.stdout.write(json.dumps(report.to_dict(), indent=2) + "\n")
    else:
        sys.stdout.write(f"🦅  LogicFalcon FDE — Mission Execution: {mission.name}\n")
        sys.stdout.write(f"Status: {report.status.value}\n")
        sys.stdout.write(
            f"Steps: {report.total_steps} (Succeeded: {report.succeeded_steps}, "
            f"Failed: {report.failed_steps}, Blocked: {report.blocked_steps})\n"
        )
        for summary in report.step_summaries:
            status_indicator = "✓" if summary.success else "✗"
            sys.stdout.write(f"  [{status_indicator}] {summary.step_id}: {summary.status.value}")
            if summary.error:
                sys.stdout.write(f" - {summary.error}")
            sys.stdout.write("\n")

    return 0 if report.status == MissionStatus.SUCCEEDED else 1


def build_fde_parser() -> argparse.ArgumentParser:
    """Builds the argument parser for logicfalcon fde subcommands."""
    parser = argparse.ArgumentParser(
        prog="logicfalcon fde",
        description="LogicFalcon Forward Deployment Engineering (FDE) CLI",
    )
    subparsers = parser.add_subparsers(dest="fde_subcommand", help="FDE action to perform")

    # inspect
    inspect_p = subparsers.add_parser("inspect", help="Statically discover deployment topography")
    inspect_p.add_argument("repo", nargs="?", default=".", help="Repository root path")
    inspect_p.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # preflight
    preflight_p = subparsers.add_parser("preflight", help="Execute bounded preflight readiness probes")
    preflight_p.add_argument("repo", nargs="?", default=".", help="Repository root path")
    preflight_p.add_argument("--docker", action="store_true", help="Enable Docker daemon probe")
    preflight_p.add_argument("--dns", action="store_true", help="Enable DNS resolution probes")
    preflight_p.add_argument("--health-url", type=str, default=None, help="Probe an explicit HTTP health endpoint")
    preflight_p.add_argument("--no-ports", action="store_true", help="Disable port binding availability checks")
    preflight_p.add_argument("--no-env", action="store_true", help="Disable environment variable checks")
    preflight_p.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # capabilities
    cap_p = subparsers.add_parser("capabilities", help="List registered adapter capabilities and health")
    cap_p.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # plan
    plan_p = subparsers.add_parser("plan", help="Generate deployment mission plan without executing")
    plan_p.add_argument("repo", nargs="?", default=".", help="Repository root path")
    plan_p.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # runbook
    runbook_p = subparsers.add_parser("runbook", help="Generate operator runbook from mission file")
    runbook_p.add_argument("mission_file", help="Path to mission JSON definition file")
    runbook_p.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # run
    run_p = subparsers.add_parser("run", help="Execute mission workflow with policy enforcement")
    run_p.add_argument("mission_file", help="Path to mission JSON definition file")
    run_p.add_argument(
        "--approve-token",
        action="append",
        help="Approval token for consequential mutations (format: token or step_id:token)",
    )
    run_p.add_argument("--save-checkpoint", action="store_true", help="Save execution checkpoint on completion")
    run_p.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    return parser


def run_fde_cli(argv: list[str]) -> int:
    """Dispatches logicfalcon fde CLI subcommands."""
    parser = build_fde_parser()
    if not argv or argv[0] in ("-h", "--help"):
        parser.print_help()
        return 0

    args = parser.parse_args(argv)
    if args.fde_subcommand == "inspect":
        return run_inspect(args)
    elif args.fde_subcommand == "preflight":
        return run_preflight(args)
    elif args.fde_subcommand == "capabilities":
        return run_capabilities(args)
    elif args.fde_subcommand == "plan":
        return run_plan(args)
    elif args.fde_subcommand == "runbook":
        return run_runbook(args)
    elif args.fde_subcommand == "run":
        return run_mission_cli(args)

    parser.print_help()
    return 0
