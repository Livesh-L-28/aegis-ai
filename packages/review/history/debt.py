"""Technical debt estimation and breakdown based on static findings and modularity health."""

from collections import defaultdict

from packages.review.history.models import (
    RepositoryMetrics,
    SnapshotFinding,
    TechnicalDebtEstimate,
)

# Standard remediation effort point weights
SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 20.0,
    "ERROR": 8.0,
    "HIGH": 8.0,
    "WARNING": 3.0,
    "MEDIUM": 3.0,
    "INFO": 1.0,
    "LOW": 1.0,
}

CYCLE_PENALTY: float = 5.0
BOUNDARY_PENALTY: float = 4.0
HOTSPOT_PENALTY: float = 2.5


class TechnicalDebtEstimator:
    """Computes transparent, explainable technical debt points without fabricated monetary units."""

    @classmethod
    def estimate(
        cls,
        findings: list[SnapshotFinding],
        metrics: RepositoryMetrics | None = None,
    ) -> TechnicalDebtEstimate:
        """Calculates aggregate technical debt points and multi-dimensional breakdowns."""
        sev_breakdown: dict[str, float] = defaultdict(float)
        cat_breakdown: dict[str, float] = defaultdict(float)
        file_debt: dict[str, float] = defaultdict(float)

        finding_points = 0.0
        for f in findings:
            weight = SEVERITY_WEIGHTS.get(f.severity.upper(), 2.0)
            finding_points += weight
            sev_breakdown[f.severity.upper()] += weight
            cat_breakdown[f.category.upper()] += weight
            file_debt[f.file_path] += weight

        arch_points = 0.0
        assumptions: list[str] = [
            "Technical debt is measured in normalized effort points (not arbitrary currency).",
            f"Weights: CRITICAL={SEVERITY_WEIGHTS['CRITICAL']}pts, HIGH/ERROR={SEVERITY_WEIGHTS['HIGH']}pts, "
            f"MEDIUM/WARNING={SEVERITY_WEIGHTS['MEDIUM']}pts, LOW/INFO={SEVERITY_WEIGHTS['LOW']}pt.",
        ]

        if metrics is not None:
            cycle_pts = metrics.cycle_count * CYCLE_PENALTY
            boundary_pts = metrics.boundary_violations_count * BOUNDARY_PENALTY
            hotspot_pts = metrics.hotspot_count * HOTSPOT_PENALTY
            arch_points = cycle_pts + boundary_pts + hotspot_pts

            if cycle_pts > 0:
                cat_breakdown["ARCHITECTURE_CYCLES"] = cycle_pts
            if boundary_pts > 0:
                cat_breakdown["BOUNDARY_VIOLATIONS"] = boundary_pts
            if hotspot_pts > 0:
                cat_breakdown["COUPLING_HOTSPOTS"] = hotspot_pts

            assumptions.append(
                f"Modularity debt penalties: {CYCLE_PENALTY}pts/cycle, {BOUNDARY_PENALTY}pts/boundary violation, "
                f"{HOTSPOT_PENALTY}pts/coupling hotspot."
            )

        total_points = round(finding_points + arch_points, 1)

        # Top debt files (top 10)
        sorted_files = sorted(file_debt.items(), key=lambda x: x[1], reverse=True)[:10]
        top_files = [(f, round(pts, 1)) for f, pts in sorted_files]

        return TechnicalDebtEstimate(
            total_points=total_points,
            severity_breakdown={k: round(v, 1) for k, v in sev_breakdown.items()},
            category_breakdown={k: round(v, 1) for k, v in cat_breakdown.items()},
            top_debt_files=top_files,
            assumptions=assumptions,
        )
