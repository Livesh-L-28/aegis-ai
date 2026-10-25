"""Deterministic revision comparison and regression intelligence for LogicFalcon."""

from uuid import uuid4

from packages.review.history.lifecycle import FindingLifecycleTracker
from packages.review.history.models import (
    FindingLifecycleState,
    RepositorySnapshot,
    SnapshotComparison,
    SnapshotFinding,
)


class SnapshotComparator:
    """Compares two repository snapshots to detect regressions, lifecycle shifts, and health deltas."""

    @classmethod
    def compare(
        cls,
        base_snapshot: RepositorySnapshot,
        target_snapshot: RepositorySnapshot,
        historical_resolved_fps: set[str] | None = None,
    ) -> SnapshotComparison:
        """Executes evidence-backed comparison between base and target snapshots."""
        comparability_notes: list[str] = []
        is_comparable = True

        # 1. Comparability validation
        if base_snapshot.metadata.schema_version != target_snapshot.metadata.schema_version:
            comparability_notes.append(
                f"Schema version difference: base={base_snapshot.metadata.schema_version}, "
                f"target={target_snapshot.metadata.schema_version}. Comparison may have minor schema gaps."
            )

        if (
            base_snapshot.metadata.config_fingerprint
            and target_snapshot.metadata.config_fingerprint
            and base_snapshot.metadata.config_fingerprint != target_snapshot.metadata.config_fingerprint
        ):
            comparability_notes.append(
                "Analysis configuration differs between snapshots. Metric changes may reflect config adjustments."
            )

        if base_snapshot.metadata.scan_coverage > 0:
            cov_ratio = target_snapshot.metadata.scan_coverage / max(0.01, base_snapshot.metadata.scan_coverage)
            if cov_ratio < 0.7:
                is_comparable = False
                comparability_notes.append(
                    f"Target scan coverage ({target_snapshot.metadata.scan_coverage:.1%}) is significantly lower "
                    f"than base ({base_snapshot.metadata.scan_coverage:.1%}). Direct resolution comparison is unsafe."
                )

        # 2. Extract parsed and skipped files from target
        # If target has findings or explicit parsed files, extract file paths
        target_parsed_files: set[str] = {f.file_path for f in target_snapshot.findings}
        target_meta = target_snapshot.metadata.metadata or {}
        if "parsed_files_list" in target_meta:
            target_parsed_files.update(target_meta["parsed_files_list"])
        elif target_snapshot.metadata.parsed_files > 0:
            # If explicit list is absent, assume files in findings + discovered were parsed unless skipped
            target_parsed_files.update({f.file_path for f in target_snapshot.findings})

        target_skipped_files: set[str] = set(target_meta.get("skipped_files_list", []))

        # 3. Compute lifecycle transitions
        _, transitions = FindingLifecycleTracker.compute_lifecycle(
            prior_findings=base_snapshot.findings,
            current_findings=target_snapshot.findings,
            current_parsed_files=target_parsed_files,
            current_skipped_files=target_skipped_files,
            historical_resolved_fingerprints=historical_resolved_fps,
        )

        # 4. Partition findings by lifecycle state
        new_findings: list[SnapshotFinding] = []
        resolved_findings: list[SnapshotFinding] = []
        persistent_findings: list[SnapshotFinding] = []
        reopened_findings: list[SnapshotFinding] = []
        changed_findings: list[SnapshotFinding] = []
        uncertain_findings: list[SnapshotFinding] = []

        target_by_fp = {f.fingerprint: f for f in target_snapshot.findings}
        base_by_fp = {f.fingerprint: f for f in base_snapshot.findings}

        for tr in transitions:
            if tr.current_state == FindingLifecycleState.NEW and tr.fingerprint in target_by_fp:
                new_findings.append(target_by_fp[tr.fingerprint])
            elif tr.current_state == FindingLifecycleState.REOPENED and tr.fingerprint in target_by_fp:
                reopened_findings.append(target_by_fp[tr.fingerprint])
            elif tr.current_state == FindingLifecycleState.UNCHANGED and tr.fingerprint in target_by_fp:
                persistent_findings.append(target_by_fp[tr.fingerprint])
            elif tr.current_state == FindingLifecycleState.CHANGED and tr.fingerprint in target_by_fp:
                changed_findings.append(target_by_fp[tr.fingerprint])
            elif tr.current_state == FindingLifecycleState.RESOLVED and tr.fingerprint in base_by_fp:
                resolved_findings.append(base_by_fp[tr.fingerprint])
            elif tr.current_state == FindingLifecycleState.UNCERTAIN and tr.fingerprint in base_by_fp:
                uncertain_findings.append(base_by_fp[tr.fingerprint])

        # 5. Calculate metric deltas
        bm = base_snapshot.metrics
        tm = target_snapshot.metrics

        metric_deltas: dict[str, float] = {
            "file_count": float(tm.file_count - bm.file_count),
            "symbol_count": float(tm.symbol_count - bm.symbol_count),
            "total_findings": float(len(target_snapshot.findings) - len(base_snapshot.findings)),
            "cycle_count": float(tm.cycle_count - bm.cycle_count),
            "boundary_violations": float(tm.boundary_violations_count - bm.boundary_violations_count),
            "health_score": round(tm.health_score - bm.health_score, 2),
            "tech_debt_points": round(tm.tech_debt_points - bm.tech_debt_points, 2),
            "avg_instability": round(tm.avg_instability - bm.avg_instability, 4),
            "hotspot_count": float(tm.hotspot_count - bm.hotspot_count),
        }

        health_score_delta = round(tm.health_score - bm.health_score, 2)
        tech_debt_delta = round(tm.tech_debt_points - bm.tech_debt_points, 2)

        # 6. Identify detected regressions
        detected_regressions: list[str] = []
        critical_new = [f for f in new_findings if f.severity in ("CRITICAL", "ERROR")]
        if critical_new:
            detected_regressions.append(
                f"{len(critical_new)} new HIGH/CRITICAL finding(s) introduced: "
                + ", ".join(f"{f.rule_id} in {f.file_path}:{f.start_line}" for f in critical_new[:3])
            )

        if reopened_findings:
            detected_regressions.append(
                f"{len(reopened_findings)} previously resolved finding(s) reopened: "
                + ", ".join(f.rule_id for f in reopened_findings[:3])
            )

        if metric_deltas["cycle_count"] > 0:
            detected_regressions.append(
                f"{int(metric_deltas['cycle_count'])} new circular dependency cycle(s) detected."
            )

        if metric_deltas["boundary_violations"] > 0:
            detected_regressions.append(
                f"{int(metric_deltas['boundary_violations'])} new architectural boundary violation(s) detected."
            )

        if health_score_delta <= -5.0:
            detected_regressions.append(
                f"Repository health score dropped by {abs(health_score_delta):.1f} points "
                f"({bm.health_score:.1f} -> {tm.health_score:.1f})."
            )

        if tech_debt_delta >= 15.0:
            detected_regressions.append(
                f"Technical debt expanded by {tech_debt_delta:.1f} points "
                f"({bm.tech_debt_points:.1f} -> {tm.tech_debt_points:.1f})."
            )

        # 7. Aggregate limitations
        limitations: list[str] = list(target_snapshot.limitations)
        if uncertain_findings:
            limitations.append(
                f"{len(uncertain_findings)} finding(s) marked UNCERTAIN because their source files were skipped or unparsed."
            )

        return SnapshotComparison(
            id=uuid4(),
            from_snapshot_id=str(base_snapshot.id),
            to_snapshot_id=str(target_snapshot.id),
            from_revision=base_snapshot.metadata.revision,
            to_revision=target_snapshot.metadata.revision,
            from_timestamp=base_snapshot.metadata.created_at,
            to_timestamp=target_snapshot.metadata.created_at,
            is_comparable=is_comparable,
            comparability_notes=comparability_notes,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            persistent_findings=persistent_findings,
            reopened_findings=reopened_findings,
            changed_findings=changed_findings,
            uncertain_findings=uncertain_findings,
            metric_deltas=metric_deltas,
            health_score_delta=health_score_delta,
            tech_debt_delta=tech_debt_delta,
            detected_regressions=detected_regressions,
            limitations=limitations,
        )
