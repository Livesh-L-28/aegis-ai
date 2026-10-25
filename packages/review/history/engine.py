"""Historical engineering intelligence engine orchestrating snapshots, comparisons, and policy gates."""

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from packages.review.analyzer.architecture import ArchitectureAnalyzer
from packages.review.domain.models import ReviewFinding
from packages.review.engine import LocalReviewEngine, ReviewConfig
from packages.review.history.comparator import SnapshotComparator
from packages.review.history.debt import TechnicalDebtEstimator
from packages.review.history.models import (
    EngineeringTrendReport,
    FindingLifecycleState,
    GitState,
    PolicyEvaluationResult,
    RepositoryMetrics,
    RepositorySnapshot,
    SnapshotComparison,
    SnapshotFinding,
    SnapshotMetadata,
    TechnicalDebtEstimate,
)
from packages.review.history.policy import EngineeringPolicyEvaluator
from packages.review.history.storage import HistoryStorage
from packages.review.history.trends import TrendAnalyzer


class HistoricalIntelligenceEngine:
    """Orchestrates snapshot collection, persistence, trend analytics, and policy gate evaluation."""

    def __init__(
        self,
        repo_root: str | Path = ".",
        storage: HistoryStorage | None = None,
        db_path: str | Path | None = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        if storage is not None:
            self.storage = storage
        elif db_path is not None:
            self.storage = HistoryStorage(db_path=db_path)
        else:
            default_db = self.repo_root / ".logicfalcon" / "history.db"
            self.storage = HistoryStorage(db_path=default_db)

    def capture_snapshot(
        self,
        revision: str | None = None,
        git_state: GitState | str = GitState.UNKNOWN,
        save: bool = True,
        max_files: int = 500,
        custom_findings: list[ReviewFinding] | None = None,
    ) -> RepositorySnapshot:
        """Collects a complete repository snapshot with review findings, architecture health, and metrics."""
        limitations: list[str] = []
        discovered_files: list[str] = []
        parsed_files: list[str] = []
        skipped_files: list[str] = []

        # 1. Discover target files within repository
        for ext in (".py", ".ts", ".js", ".tsx", ".jsx"):
            for p in self.repo_root.rglob(f"*{ext}"):
                if p.is_file():
                    try:
                        rel = str(p.relative_to(self.repo_root))
                        if not any(part.startswith(".") for part in p.parts if part != ".logicfalcon"):
                            discovered_files.append(rel)
                    except ValueError:
                        continue

        # Sort deterministically
        discovered_files.sort()
        target_files = discovered_files[:max_files]
        if len(discovered_files) > max_files:
            limitations.append(
                f"Discovered {len(discovered_files)} files; analysis bounded to first {max_files} files."
            )
            skipped_files.extend(discovered_files[max_files:])

        # 2. Collect static review findings
        findings_to_process: list[ReviewFinding] = []
        if custom_findings is not None:
            findings_to_process = custom_findings
            parsed_files = list(target_files)
        else:
            engine = LocalReviewEngine(
                repo_root=self.repo_root,
                config=ReviewConfig(max_file_size_bytes=500_000, per_file_timeout_seconds=5.0),
            )
            for rel_path in target_files:
                full_p = self.repo_root / rel_path
                try:
                    content = full_p.read_text(encoding="utf-8")
                    file_report = engine.review_file(file_path=rel_path, content=content)
                    findings_to_process.extend(file_report.findings)
                    parsed_files.append(rel_path)
                except Exception as e:
                    skipped_files.append(rel_path)
                    limitations.append(f"Failed to parse '{rel_path}': {e}")

        # 3. Analyze architecture & modularity health
        arch_analyzer = ArchitectureAnalyzer(repo_root=self.repo_root)
        try:
            arch_report = arch_analyzer.analyze(files=parsed_files if parsed_files else None)
        except Exception as e:
            limitations.append(f"Architecture inspection encountered warning: {e}")
            from packages.review.domain.models import ArchitectureReport

            arch_report = ArchitectureReport()

        # 4. Optional Reverse Engineering integration
        api_count = 0
        model_count = 0
        entry_point_count = 0
        try:
            from packages.review.reverse_engineering.engine import ReverseEngineeringEngine

            re_engine = ReverseEngineeringEngine(repo_root=self.repo_root, max_files=max_files)
            re_rep = re_engine.analyze()
            api_count = re_rep.api_inventory.total_routes
            model_count = re_rep.data_model_inventory.total_models
            entry_point_count = sum(
                1 for n in re_rep.call_graph.nodes if any(k in n.lower() for k in ("main", "cli", "run", "entry"))
            )
        except Exception:
            # Graceful fallback: reverse engineering is optional
            pass

        # 5. Normalize findings into SnapshotFinding models
        snapshot_findings: list[SnapshotFinding] = []
        sev_dist: dict[str, int] = {}
        cat_dist: dict[str, int] = {}

        for rf in findings_to_process:
            sev_str = rf.severity.value if hasattr(rf.severity, "value") else str(rf.severity)
            cat_str = rf.category.value if hasattr(rf.category, "value") else str(rf.category)

            sev_dist[sev_str] = sev_dist.get(sev_str, 0) + 1
            cat_dist[cat_str] = cat_dist.get(cat_str, 0) + 1

            snapshot_findings.append(
                SnapshotFinding(
                    fingerprint=rf.deduplication_hash,
                    rule_id=rf.rule_id,
                    category=cat_str,
                    severity=sev_str,
                    file_path=rf.location.file_path,
                    start_line=rf.location.start_line,
                    end_line=rf.location.end_line,
                    symbol_name=rf.location.symbol_name,
                    title=rf.title,
                    message=rf.message,
                    evidence_snippet=rf.technical_evidence,
                    confidence=rf.confidence,
                    resolution_state=FindingLifecycleState.NEW,
                )
            )

        # 6. Estimate technical debt
        debt_estimate = TechnicalDebtEstimator.estimate(
            findings=snapshot_findings,
            metrics=None,  # Will merge after computing metrics
        )

        # Calculate average instability
        instabilities = [m.instability for m in arch_report.module_metrics]
        avg_instability = round(sum(instabilities) / max(1, len(instabilities)), 4)
        hotspot_count = sum(1 for m in arch_report.module_metrics if m.is_hotspot)

        metrics = RepositoryMetrics(
            file_count=len(discovered_files),
            symbol_count=sum(len(m.modules) for m in arch_report.cycles) if arch_report.cycles else 0,
            graph_nodes=arch_report.total_modules,
            graph_edges=arch_report.total_internal_dependencies,
            scc_count=len(arch_report.cycle_groups),
            cycle_count=len(arch_report.cycles),
            boundary_violations_count=len(arch_report.boundary_violations),
            avg_instability=avg_instability,
            hotspot_count=hotspot_count,
            health_score=round(arch_report.health_score, 1),
            api_route_count=api_count,
            data_model_count=model_count,
            entry_point_count=entry_point_count,
            tech_debt_points=debt_estimate.total_points,
            severity_distribution=sev_dist,
            category_distribution=cat_dist,
        )

        # Re-compute debt with architecture penalties included
        debt_with_arch = TechnicalDebtEstimator.estimate(
            findings=snapshot_findings,
            metrics=metrics,
        )
        metrics.tech_debt_points = debt_with_arch.total_points

        # Privacy-conscious repository identity hash
        repo_hash = hashlib.sha256(str(self.repo_root).encode("utf-8")).hexdigest()[:16]
        scan_coverage = round(len(parsed_files) / max(1, len(discovered_files)), 3)

        metadata = SnapshotMetadata(
            schema_version="1.0",
            logicfalcon_version="0.1.2",
            created_at=datetime.now(UTC),
            repo_name=self.repo_root.name,
            repo_path_hash=repo_hash,
            revision=revision,
            git_state=GitState(git_state) if isinstance(git_state, str) else git_state,
            analyzer_versions={"ast_security": "1.0", "architecture": "1.0"},
            enabled_analyzers=["ast_security", "architecture"],
            config_fingerprint=f"max_files={max_files}",
            discovered_files=len(discovered_files),
            parsed_files=len(parsed_files),
            skipped_files=len(skipped_files),
            scan_coverage=scan_coverage,
            limitations=limitations,
            metadata={
                "parsed_files_list": parsed_files,
                "skipped_files_list": skipped_files,
            },
        )

        snapshot = RepositorySnapshot(
            id=uuid4(),
            metadata=metadata,
            metrics=metrics,
            findings=snapshot_findings,
            limitations=limitations,
        )

        if save:
            self.storage.save_snapshot(snapshot)

        return snapshot

    def compare_snapshots(
        self,
        from_id_or_rev: str,
        to_id_or_rev: str,
    ) -> SnapshotComparison:
        """Compares two historical snapshots identified by ID or Git revision."""
        # Try resolving from_id_or_rev
        base = self.storage.get_snapshot(from_id_or_rev)
        if base is None:
            base = self.storage.get_snapshot_by_revision(from_id_or_rev)
        if base is None:
            raise ValueError(f"Base snapshot '{from_id_or_rev}' could not be found in history storage.")

        target = self.storage.get_snapshot(to_id_or_rev)
        if target is None:
            target = self.storage.get_snapshot_by_revision(to_id_or_rev)
        if target is None:
            raise ValueError(f"Target snapshot '{to_id_or_rev}' could not be found in history storage.")

        return SnapshotComparator.compare(base_snapshot=base, target_snapshot=target)

    def analyze_trends(self, limit: int = 20) -> EngineeringTrendReport:
        """Extracts recent snapshots and computes longitudinal engineering trend indicators."""
        snapshots = self.storage.get_recent_snapshots(limit=limit)
        return TrendAnalyzer.analyze(snapshots)

    def estimate_debt(self, snapshot_id: str | None = None) -> TechnicalDebtEstimate:
        """Computes technical debt estimate for a specified snapshot or the latest repository state."""
        if snapshot_id is not None:
            snap = self.storage.get_snapshot(snapshot_id)
            if snap is None:
                snap = self.storage.get_snapshot_by_revision(snapshot_id)
            if snap is None:
                raise ValueError(f"Snapshot '{snapshot_id}' not found.")
        else:
            snap = self.storage.get_latest_snapshot()
            if snap is None:
                return TechnicalDebtEstimate(
                    total_points=0.0,
                    assumptions=["No historical snapshots found in storage."],
                )

        return TechnicalDebtEstimator.estimate(findings=snap.findings, metrics=snap.metrics)

    def evaluate_policy(
        self,
        config_path: str | Path | None = None,
        comparison: SnapshotComparison | None = None,
        snapshot: RepositorySnapshot | None = None,
    ) -> PolicyEvaluationResult:
        """Evaluates engineering policy rules against a revision comparison or absolute snapshot."""
        if config_path is not None:
            evaluator = EngineeringPolicyEvaluator.from_config_file(config_path)
        else:
            evaluator = EngineeringPolicyEvaluator()

        if comparison is not None:
            return evaluator.evaluate_comparison(comparison)
        elif snapshot is not None:
            return evaluator.evaluate_snapshot(snapshot)
        else:
            latest = self.storage.get_latest_snapshot()
            if latest is None:
                raise ValueError("No snapshot available for policy evaluation.")
            return evaluator.evaluate_snapshot(latest)
