"""Explainable, deterministic impact scoring and risk classification."""

from packages.review.domain.models import ReviewFinding
from packages.review.impact.models import (
    ChangeSet,
    ImpactedEntity,
    ImpactRiskLevel,
)


class ImpactScorer:
    """Scores impacted entities and classifies change-set risk based on transparent, documented factors."""

    def score_entities(
        self,
        entities: list[ImpactedEntity],
        findings_by_file: dict[str, list[ReviewFinding]] | None = None,
    ) -> None:
        """Assigns explainable 0.0-100.0 impact scores to each impacted entity in-place."""
        findings_map = findings_by_file or {}

        for entity in entities:
            score = 0.0
            reasons = list(entity.impact_reasons)

            # Factor 1: Proximity / Dependency Depth (max 30 pts)
            if entity.depth == 1:
                score += 30.0
            elif entity.depth == 2:
                score += 18.0
            elif entity.depth == 3:
                score += 10.0
            else:
                score += 5.0

            # Factor 2: Entry-point / API route exposure (max 25 pts)
            if entity.affected_entry_points:
                score += 25.0
                reasons.append(f"Exposes top-level entry point: {entity.affected_entry_points[0]}")
            elif entity.associated_routes:
                score += 20.0
                reasons.append(f"Directly powers {len(entity.associated_routes)} API route(s)")

            # Factor 3: Core Data Model / Database impact (max 20 pts)
            if entity.associated_models:
                score += 20.0
                reasons.append(f"Contains {len(entity.associated_models)} schema-critical model(s)")

            # Factor 4: Architectural boundary crossing (max 15 pts)
            if any("architectural boundary" in r.lower() for r in entity.impact_reasons):
                score += 15.0

            # Factor 5: Pre-existing findings in target module (max 10 pts)
            f_list = findings_map.get(entity.file_path, [])
            if f_list:
                score += min(len(f_list) * 3.0, 10.0)
                reasons.append(f"Target module contains {len(f_list)} active review finding(s)")
                entity.relevant_findings = [
                    {
                        "rule_id": f.rule_id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "line": f.location.start_line,
                    }
                    for f in f_list[:5]
                ]

            entity.impact_score = min(round(score, 1), 100.0)
            entity.impact_reasons = sorted(set(reasons))

    def evaluate_change_risk(
        self,
        change_set: ChangeSet,
        entities: list[ImpactedEntity],
    ) -> tuple[ImpactRiskLevel, float, list[str]]:
        """Evaluates overall change-set risk level and returns (risk_level, score, reasons)."""
        reasons: list[str] = []
        score = 0.0

        all_changed_paths = set(change_set.modified_paths + change_set.added_paths + change_set.deleted_paths)
        if not all_changed_paths and not entities:
            return ImpactRiskLevel.LOW, 0.0, ["No changed files detected."]

        # 1. Check for database migrations
        has_migration = any(
            "alembic" in p.lower() or "migration" in p.lower() or "schema.sql" in p.lower()
            for p in all_changed_paths
        )
        if has_migration:
            score += 40.0
            reasons.append("Change set modifies database migrations or schema definitions.")

        # 2. Check for security/auth/crypto components
        has_security = any(
            any(k in p.lower() for k in ("security", "auth", "rbac", "token", "crypto", "firewall"))
            for p in all_changed_paths
        )
        if has_security:
            score += 35.0
            reasons.append("Change set modifies security, authentication, or access control modules.")

        # 3. Blast radius from impacted entities
        total_dependents = len(entities)
        if total_dependents > 25:
            score += 30.0
            reasons.append(f"Very wide blast radius: {total_dependents} dependent files impacted.")
        elif total_dependents > 8:
            score += 20.0
            reasons.append(f"Moderate blast radius: {total_dependents} dependent files impacted.")
        elif total_dependents > 0:
            score += 10.0
            reasons.append(f"Localized blast radius: {total_dependents} dependent file(s) impacted.")

        # 4. Entry point and API reachability
        all_routes = sum(len(e.associated_routes) for e in entities)
        all_eps = sum(len(e.affected_entry_points) for e in entities)
        if all_eps > 0:
            score += 20.0
            reasons.append(f"Reachability to {all_eps} application entry point(s).")
        if all_routes > 0:
            score += 15.0
            reasons.append(f"Reachability to {all_routes} external API route(s).")

        # 5. Core model modifications
        all_models = sum(len(e.associated_models) for e in entities)
        if all_models > 0:
            score += 15.0
            reasons.append(f"Reachability to {all_models} data models.")

        # Aggregate normalized score (0.0 - 100.0)
        norm_score = min(round(score, 1), 100.0)

        # Risk Classification
        if (has_migration and has_security) or norm_score >= 75.0 or (has_security and total_dependents >= 10):
            risk_level = ImpactRiskLevel.CRITICAL
        elif norm_score >= 50.0 or has_migration or has_security or total_dependents >= 15:
            risk_level = ImpactRiskLevel.HIGH
        elif norm_score >= 25.0 or total_dependents >= 3:
            risk_level = ImpactRiskLevel.MEDIUM
        else:
            risk_level = ImpactRiskLevel.LOW

        if not reasons:
            reasons.append("Low-complexity change with localized reverse dependencies.")

        return risk_level, norm_score, reasons
