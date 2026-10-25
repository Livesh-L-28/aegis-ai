"""Architecture, modularity, and boundary analyzer for LogicFalcon."""

from pathlib import Path
from typing import Any

from packages.review.analyzer.dependency_graph import DependencyGraph
from packages.review.domain.models import (
    ArchitecturePolicy,
    ArchitectureReport,
    BoundaryViolation,
    CycleGroup,
    DependencyCycle,
    FindingCategory,
    FindingOrigin,
    FindingSeverity,
    LayerDefinition,
    ModuleMetric,
    ReviewFinding,
    RuleException,
    SourceLocation,
)

DEFAULT_BOUNDARY_RULES: list[dict[str, str]] = [
    {
        "name": "domain_layer_isolation",
        "source_pattern": "*domain*",
        "forbidden_pattern": "*adapters*",
        "description": "Domain entities must not depend on external infrastructure adapters.",
    },
    {
        "name": "domain_cli_isolation",
        "source_pattern": "*domain*",
        "forbidden_pattern": "*cli*",
        "description": "Domain layer must not depend on CLI or presentation layer.",
    },
]


class ArchitectureAnalyzer:
    """Evaluates repository modularity, dependency cycles, boundary conformance, and health."""

    def __init__(
        self,
        repo_root: str | Path,
        boundary_rules: list[dict[str, str]] | None = None,
        policy: ArchitecturePolicy | None = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.policy = policy
        if policy is not None and policy.rules:
            self.boundary_rules = [r.model_dump() for r in policy.rules]
        elif boundary_rules is not None:
            self.boundary_rules = boundary_rules
        else:
            self.boundary_rules = DEFAULT_BOUNDARY_RULES
        self.dep_graph = DependencyGraph(self.repo_root)

    def analyze(self, files: list[str] | None = None) -> ArchitectureReport:
        """Executes full architecture inspection across the repository or specified files."""
        self.dep_graph.build_graph(files=files)

        cycles: list[DependencyCycle] = self.dep_graph.find_cycles()
        cycle_groups: list[CycleGroup] = self.dep_graph.find_strongly_connected_components()

        exceptions: list[RuleException] | None = self.policy.exceptions if self.policy else None
        layers: list[LayerDefinition] | None = self.policy.layers if self.policy else None
        boundary_violations: list[BoundaryViolation] = self.dep_graph.check_boundaries(
            rules=self.boundary_rules,
            exceptions=exceptions,
            layers=layers,
        )
        coupling_data = self.dep_graph.get_module_coupling()

        module_metrics: list[ModuleMetric] = []
        for mod_name, data in coupling_data.items():
            module_metrics.append(
                ModuleMetric(
                    module_name=mod_name,
                    file_path=data["file_path"],
                    afferent_coupling=data["afferent_coupling"],
                    efferent_coupling=data["efferent_coupling"],
                    instability=data["instability"],
                    is_hotspot=data["is_hotspot"],
                )
            )

        # Explainable Health Scoring
        base_score = 100.0
        cycle_deductions = min(len(cycles) * 15.0, 45.0)
        boundary_deductions = min(len(boundary_violations) * 10.0, 30.0)
        hotspots = [m for m in module_metrics if m.is_hotspot]
        hotspot_deductions = min(len(hotspots) * 5.0, 25.0)

        final_score = max(0.0, base_score - cycle_deductions - boundary_deductions - hotspot_deductions)

        scoring_breakdown: dict[str, Any] = {
            "base_score": base_score,
            "deductions": {
                "circular_dependencies": {
                    "count": len(cycles),
                    "deducted": cycle_deductions,
                    "explanation": f"{len(cycles)} cycles detected (-15 pts each, max -45 pts)",
                },
                "boundary_violations": {
                    "count": len(boundary_violations),
                    "deducted": boundary_deductions,
                    "explanation": f"{len(boundary_violations)} boundary violations (-10 pts each, max -30 pts)",
                },
                "coupling_hotspots": {
                    "count": len(hotspots),
                    "deducted": hotspot_deductions,
                    "explanation": f"{len(hotspots)} high-coupling hotspot modules (-5 pts each, max -25 pts)",
                },
            },
            "final_score": round(final_score, 1),
        }

        if final_score >= 90:
            summary = "Excellent: Highly decoupled architecture with clear modular boundaries."
        elif final_score >= 75:
            summary = "Good: Minor coupling or boundary issues that should be addressed."
        elif final_score >= 50:
            summary = "Moderate Debt: Notable circular dependencies or boundary leakage detected."
        else:
            summary = "High Debt: Critical architectural coupling and circular dependencies require refactoring."

        total_internal_deps = sum(len(targets) for targets in self.dep_graph.internal_import_graph.values())

        return ArchitectureReport(
            total_modules=len(self.dep_graph.module_to_file),
            total_internal_dependencies=total_internal_deps,
            cycles=cycles,
            cycle_groups=cycle_groups,
            boundary_violations=boundary_violations,
            module_metrics=module_metrics,
            layers=layers or [],
            health_score=round(final_score, 1),
            health_summary=summary,
            scoring_breakdown=scoring_breakdown,
        )

    def generate_findings(self, report: ArchitectureReport) -> list[ReviewFinding]:
        """Translates architectural violations and cycles into standardized ReviewFinding objects."""
        findings: list[ReviewFinding] = []

        # 1. Circular Dependencies (ARCH-001)
        for cycle in report.cycles:
            primary_mod = cycle.modules[0]
            file_path = self.dep_graph.module_to_file.get(primary_mod, primary_mod.replace(".", "/") + ".py")
            findings.append(
                ReviewFinding(
                    rule_id="ARCH-001",
                    title="Circular Dependency Detected",
                    message=f"Circular dependency cycle detected: {cycle.display_path}",
                    severity=FindingSeverity.ERROR,
                    category=FindingCategory.ARCHITECTURE,
                    origin=FindingOrigin.STATIC_ANALYSIS,
                    location=SourceLocation(
                        file_path=file_path,
                        start_line=1,
                        symbol_name=primary_mod,
                    ),
                    suggestion=(
                        "Refactor the shared dependency into a separate common interface or module "
                        "to break the import cycle."
                    ),
                    why_it_matters="Circular dependencies complicate testing, break module isolation, and cause runtime import errors.",
                    tool_name="architecture_analyzer",
                    confidence=1.0,
                    metadata={"cycle": cycle.modules, "length": cycle.length},
                )
            )

        # 2. Boundary Violations (ARCH-002)
        for violation in report.boundary_violations:
            path_str = " -> ".join(violation.dependency_path) if violation.dependency_path else f"{violation.source_module} -> {violation.target_module}"
            findings.append(
                ReviewFinding(
                    rule_id="ARCH-002",
                    title=f"Architectural Boundary Violation: {violation.rule_name}",
                    message=f"{violation.description} (Path: {path_str})",
                    severity=FindingSeverity.WARNING,
                    category=FindingCategory.ARCHITECTURE,
                    origin=FindingOrigin.STATIC_ANALYSIS,
                    location=SourceLocation(
                        file_path=violation.source_file,
                        start_line=1,
                        symbol_name=violation.source_module,
                    ),
                    suggestion="Invert the dependency using dependency injection or interfaces.",
                    why_it_matters="Violating architectural layers causes coupling leaks between domain logic and infrastructure.",
                    tool_name="architecture_analyzer",
                    confidence=1.0,
                    metadata={
                        "source_module": violation.source_module,
                        "target_module": violation.target_module,
                        "rule_name": violation.rule_name,
                        "rule_type": violation.rule_type,
                        "dependency_path": violation.dependency_path,
                        "is_transitive": violation.is_transitive,
                    },
                )
            )

        # 3. Coupling Hotspots (ARCH-003)
        for mod in report.module_metrics:
            if mod.is_hotspot:
                findings.append(
                    ReviewFinding(
                        rule_id="ARCH-003",
                        title="High Coupling Architecture Hotspot",
                        message=(
                            f"Module '{mod.module_name}' exhibits excessive coupling "
                            f"(Afferent: {mod.afferent_coupling}, Efferent: {mod.efferent_coupling}, "
                            f"Instability: {mod.instability})."
                        ),
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.ARCHITECTURE,
                        origin=FindingOrigin.STATIC_ANALYSIS,
                        location=SourceLocation(
                            file_path=mod.file_path,
                            start_line=1,
                            symbol_name=mod.module_name,
                        ),
                        suggestion="Consider decomposing this module into smaller cohesive submodules.",
                        why_it_matters="God modules and high-coupling hotspots create change bottlenecks and fragile codebases.",
                        tool_name="architecture_analyzer",
                        confidence=0.85,
                    )
                )

        return findings
