"""Historical engineering trend analytics across snapshot series for LogicFalcon."""

from collections import Counter

from packages.review.history.models import (
    EngineeringTrendReport,
    RepositorySnapshot,
    TrendDirection,
    TrendPoint,
)


class TrendAnalyzer:
    """Analyzes longitudinal repository health, technical debt, and defect recurrence."""

    @classmethod
    def analyze(cls, snapshots: list[RepositorySnapshot]) -> EngineeringTrendReport:
        """Computes engineering trend metrics across a chronological sequence of snapshots."""
        if not snapshots:
            return EngineeringTrendReport(
                repository_name="unknown",
                sample_count=0,
                time_span_days=0.0,
                health_direction=TrendDirection.INSUFFICIENT_DATA,
                debt_direction=TrendDirection.INSUFFICIENT_DATA,
                summary_commentary=["No historical snapshots available for trend analysis."],
            )

        # Sort chronologically
        sorted_snaps = sorted(snapshots, key=lambda s: s.metadata.created_at)
        repo_name = sorted_snaps[-1].metadata.repo_name or "repository"

        trend_points: list[TrendPoint] = []
        rule_counts: Counter[str] = Counter()

        for s in sorted_snaps:
            sev_counts: dict[str, int] = Counter(f.severity for f in s.findings)
            for f in s.findings:
                rule_counts[f.rule_id] += 1

            trend_points.append(
                TrendPoint(
                    snapshot_id=str(s.id),
                    timestamp=s.metadata.created_at,
                    revision=s.metadata.revision,
                    health_score=round(s.metrics.health_score, 2),
                    tech_debt_points=round(s.metrics.tech_debt_points, 2),
                    total_findings=len(s.findings),
                    severity_counts=dict(sev_counts),
                    cycle_count=s.metrics.cycle_count,
                    boundary_violations_count=s.metrics.boundary_violations_count,
                    file_count=s.metrics.file_count,
                )
            )

        sample_count = len(sorted_snaps)
        first = sorted_snaps[0]
        last = sorted_snaps[-1]

        t_diff = (last.metadata.created_at - first.metadata.created_at).total_seconds()
        time_span_days = round(max(0.0, t_diff / 86400.0), 2)

        if sample_count < 2:
            return EngineeringTrendReport(
                repository_name=repo_name,
                sample_count=sample_count,
                time_span_days=time_span_days,
                trend_points=trend_points,
                health_direction=TrendDirection.INSUFFICIENT_DATA,
                debt_direction=TrendDirection.INSUFFICIENT_DATA,
                summary_commentary=["At least 2 snapshots are required to determine health trajectory."],
            )

        # Health direction calculation
        health_delta = last.metrics.health_score - first.metrics.health_score
        if health_delta >= 2.5:
            health_dir = TrendDirection.IMPROVING
        elif health_delta <= -2.5:
            health_dir = TrendDirection.DETERIORATING
        else:
            health_dir = TrendDirection.STABLE

        # Tech debt direction calculation (lower debt is IMPROVING)
        debt_delta = last.metrics.tech_debt_points - first.metrics.tech_debt_points
        if debt_delta <= -5.0:
            debt_dir = TrendDirection.IMPROVING
        elif debt_delta >= 5.0:
            debt_dir = TrendDirection.DETERIORATING
        else:
            debt_dir = TrendDirection.STABLE

        # Velocity: points delta per snapshot step
        debt_velocity = round(debt_delta / max(1, sample_count - 1), 2)
        net_findings_delta = len(last.findings) - len(first.findings)

        # Recurring rules appearing in multiple snapshots
        recurring = sorted(rule_counts.most_common(5), key=lambda x: x[1], reverse=True)

        commentary: list[str] = []
        commentary.append(
            f"Over {sample_count} snapshots ({time_span_days} days), repository health trajectory is {health_dir.value} "
            f"(Score: {first.metrics.health_score:.1f} -> {last.metrics.health_score:.1f})."
        )
        commentary.append(
            f"Technical debt trajectory is {debt_dir.value} with velocity of {debt_velocity:+.1f} pts/snapshot "
            f"(Debt: {first.metrics.tech_debt_points:.1f} -> {last.metrics.tech_debt_points:.1f})."
        )
        if recurring:
            commentary.append(
                "Most recurring active rules: " + ", ".join(f"{r} ({c}x)" for r, c in recurring) + "."
            )

        return EngineeringTrendReport(
            repository_name=repo_name,
            sample_count=sample_count,
            time_span_days=time_span_days,
            trend_points=trend_points,
            health_direction=health_dir,
            debt_direction=debt_dir,
            debt_velocity=debt_velocity,
            recurring_rule_ids=recurring,
            net_findings_delta=net_findings_delta,
            summary_commentary=commentary,
        )
