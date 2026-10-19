"""Change-impact analysis and intelligent test selection engine for AEGIS AI.

Correlates diff deltas to affected AST symbols, reverse dependency paths,
impacted test suites, API contracts, and rule-based risk classifications.
"""

from collections.abc import Sequence
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field

from apps.api.app.services.evidence_graph import EvidenceGraphService


class ImpactRiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ChangeImpactReport(BaseModel):
    """Deterministic, revision-scoped change impact report."""

    repository_id: UUID
    commit_sha: str
    changed_files: list[str]
    affected_symbols: list[str] = Field(default_factory=list)
    affected_tests: list[str] = Field(default_factory=list)
    affected_api_endpoints: list[str] = Field(default_factory=list)
    affected_database_models: list[str] = Field(default_factory=list)
    risk_level: ImpactRiskLevel = ImpactRiskLevel.LOW
    risk_reasons: list[str] = Field(default_factory=list)
    selection_explanations: dict[str, str] = Field(default_factory=dict)
    unresolved_dependencies: list[str] = Field(default_factory=list)
    confidence: float = 1.0


class ChangeImpactAnalyzer:
    """Evaluates cross-language dependency blast radius and test candidate selection."""

    def __init__(self, service: EvidenceGraphService) -> None:
        self.service = service

    async def analyze_impact(
        self,
        organization_id: UUID,
        repository_id: UUID,
        commit_sha: str,
        changed_files: Sequence[str],
        max_depth: int = 3,
    ) -> ChangeImpactReport:
        clean_files = [f.strip().lstrip("/") for f in changed_files if f.strip()]
        if not clean_files:
            return ChangeImpactReport(
                repository_id=repository_id,
                commit_sha=commit_sha,
                changed_files=[],
                risk_level=ImpactRiskLevel.LOW,
                risk_reasons=["No changed files specified."],
            )

        affected_symbols: list[str] = []
        unresolved_deps: list[str] = []
        affected_endpoints: list[str] = []
        affected_models: list[str] = []
        explanations: dict[str, str] = {}

        # 1. Query directly affected symbols for each changed file
        for cf in clean_files:
            syms, _ = await self.service.get_symbols_for_revision(
                organization_id=organization_id,
                repository_id=repository_id,
                commit_sha=commit_sha,
                file_path=cf,
                limit=100,
            )
            for s in syms:
                affected_symbols.append(f"{cf}::{s.qualified_name}")

            # Detect API or DB model files
            lower = cf.lower()
            if "endpoint" in lower or "api" in lower or "router" in lower:
                affected_endpoints.append(cf)
            if "model" in lower or "entities" in lower or "migration" in lower or "schema" in lower:
                affected_models.append(cf)

        # 2. Discover transitively affected tests via reverse dependency graph
        affected_tests = await self.service.get_affected_tests(
            organization_id=organization_id,
            repository_id=repository_id,
            commit_sha=commit_sha,
            changed_files=clean_files,
            max_depth=max_depth,
        )

        for t in affected_tests:
            explanations[t] = f"Candidate test selected via reverse dependency graph within {max_depth} hops of modified files."

        # 3. Rule-based Risk Classification
        risk_reasons: list[str] = []
        has_migrations = any("migration" in f.lower() or "alembic" in f.lower() for f in clean_files)
        has_security = any("security" in f.lower() or "auth" in f.lower() or "rbac" in f.lower() for f in clean_files)
        has_api_change = bool(affected_endpoints)

        if has_migrations:
            risk_reasons.append("Database migration or schema definition modified.")
        if has_security:
            risk_reasons.append("Security or authorization control components modified.")
        if has_api_change:
            risk_reasons.append(f"Public API endpoint handlers modified ({len(affected_endpoints)} file(s)).")
        if len(affected_tests) > 5:
            risk_reasons.append(f"Broad downstream blast radius ({len(affected_tests)} affected tests).")
        if len(affected_tests) == 0 and any(f.endswith((".py", ".ts", ".tsx", ".js")) for f in clean_files):
            risk_reasons.append("No automated test coverage discovered for modified source files.")

        # Assign risk level based on transparent rules
        if has_migrations and has_security:
            level = ImpactRiskLevel.CRITICAL
        elif has_migrations or has_security or has_api_change:
            level = ImpactRiskLevel.HIGH
        elif len(affected_tests) > 3 or (len(affected_tests) == 0 and affected_symbols):
            level = ImpactRiskLevel.MEDIUM
        else:
            level = ImpactRiskLevel.LOW

        if not risk_reasons:
            risk_reasons.append("Localized change with covered tests and no sensitive boundary impact.")

        return ChangeImpactReport(
            repository_id=repository_id,
            commit_sha=commit_sha,
            changed_files=clean_files,
            affected_symbols=affected_symbols,
            affected_tests=affected_tests,
            affected_api_endpoints=affected_endpoints,
            affected_database_models=affected_models,
            risk_level=level,
            risk_reasons=risk_reasons,
            selection_explanations=explanations,
            unresolved_dependencies=unresolved_deps,
            confidence=0.95 if affected_tests else 0.75,
        )
