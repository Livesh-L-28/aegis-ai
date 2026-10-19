"""Local code review engine orchestrating diff parsing, symbol mapping, static analysis, and AI review."""

import asyncio
import json
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from packages.intelligence.evidence.graph_models import (
    EvidenceRecord,
    ProvenanceTag,
)
from packages.intelligence.evidence.graph_models import (
    ValidationStatus as EvidenceValidationStatus,
)
from packages.logging.logger import get_logger
from packages.review.adapters.ast_security import ASTSecurityAdapter
from packages.review.adapters.base import StaticAnalysisAdapter
from packages.review.adapters.ruff_adapter import RuffAnalysisAdapter
from packages.review.adapters.runner import execute_adapter_with_enforceable_timeout
from packages.review.ai.context_builder import ContextBuilder
from packages.review.ai.reviewer import AIReviewEngine
from packages.review.analyzer.dependency_graph import DependencyGraph
from packages.review.analyzer.symbol_mapper import SymbolMapper
from packages.review.domain.models import (
    AffectedArtifacts,
    ChangedSymbol,
    DiffChangeType,
    FindingCategory,
    FindingOrigin,
    FindingSeverity,
    GitDiffSummary,
    ReviewFinding,
    ReviewReport,
    SourceLocation,
)
from packages.review.git.diff_parser import GitDiffParser
from packages.review.security.path_validation import validate_contained_path

logger = get_logger("aegis.review.engine")


class ReviewCancelledException(Exception):
    """Raised when review execution is cooperatively cancelled mid-flight."""
    pass


class ReviewConfig(BaseModel):
    """Configuration and resource boundaries for the code review engine."""

    max_file_size_bytes: int = 1_000_000  # 1 MB
    per_file_timeout_seconds: float = 10.0
    max_diff_bytes: int = 10_000_000  # 10 MB
    enable_external_tools: bool = False  # Disabled by default for process safety
    enable_ai_review: bool = False  # Optional AI review integration
    repository_id: UUID | None = None
    commit_sha: str | None = None
    organization_id: UUID | None = None
    ignored_patterns: list[str] = Field(
        default_factory=lambda: [
            ".git",
            ".venv",
            "venv",
            "__pycache__",
            ".ruff_cache",
            ".mypy_cache",
            ".pytest_cache",
            "node_modules",
            "dist",
            "build",
            ".DS_Store",
        ]
    )

    @classmethod
    def load_config(cls, config_path: Path | str | None = None, repo_root: Path | str = ".") -> "ReviewConfig":
        """Loads configuration from an explicit path or repository files (.logicfalcon.json, .logicfalcon.yml)."""
        root = Path(repo_root).resolve()
        candidate: Path | None = None

        if config_path:
            candidate = Path(config_path) if Path(config_path).is_absolute() else root / config_path
            if not candidate.is_file():
                logger.warning(f"Specified config file '{config_path}' not found; using default config.")
                return cls()
        else:
            for name in (".logicfalcon.json", ".logicfalcon.yaml", ".logicfalcon.yml", ".aegis.yml", ".aegis.yaml"):
                p = root / name
                if p.is_file():
                    candidate = p
                    break

        if candidate and candidate.is_file():
            try:
                raw_text = candidate.read_text(encoding="utf-8")
                if candidate.suffix == ".json":
                    data = json.loads(raw_text)
                    return cls.model_validate(data)
                elif candidate.suffix in (".yaml", ".yml"):
                    import yaml
                    data = yaml.safe_load(raw_text) or {}
                    return cls.model_validate(data)
            except Exception as e:
                logger.warning(f"Failed to parse config file '{candidate}': {e}; using default config.")

        return cls()


class LocalReviewEngine:
    """Orchestrates secure, read-only local code review on unified diffs or repositories."""

    def __init__(
        self,
        repo_root: str | Path,
        config: ReviewConfig | None = None,
        custom_adapters: list[StaticAnalysisAdapter] | None = None,
        ai_reviewer: AIReviewEngine | None = None,
        evidence_service: Any = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.config = config or ReviewConfig()
        self.evidence_service = evidence_service
        self.diff_parser = GitDiffParser(max_diff_bytes=self.config.max_diff_bytes)
        self.symbol_mapper = SymbolMapper()
        self.dependency_graph = DependencyGraph(self.repo_root)
        self.context_builder = ContextBuilder()
        self.ai_reviewer = ai_reviewer or AIReviewEngine()

        # Register default adapters
        self.adapters: list[StaticAnalysisAdapter] = []
        if custom_adapters is not None:
            self.adapters = custom_adapters
        else:
            self.adapters.append(ASTSecurityAdapter())
            if self.config.enable_external_tools:
                self.adapters.append(RuffAnalysisAdapter(default_timeout_seconds=5.0))

    def _is_ignored(self, file_path: str) -> bool:
        return any(pat in file_path for pat in self.config.ignored_patterns)

    def review_diff(self, diff_text: str, cancellation_token: Callable[[], bool] | None = None) -> ReviewReport:
        """Synchronously performs a complete review on raw unified Git diff text."""
        return asyncio.run(
            self.review_diff_async(
                diff_text=diff_text,
                enable_ai=self.config.enable_ai_review,
                cancellation_token=cancellation_token,
            )
        )

    async def review_diff_async(
        self,
        diff_text: str,
        enable_ai: bool = False,
        cancellation_token: Callable[[], bool] | None = None,
        repository_id: UUID | None = None,
        commit_sha: str | None = None,
        organization_id: UUID | None = None,
    ) -> ReviewReport:
        """Asynchronously executes review with optional AI hypothesis evaluation."""
        start_time = time.perf_counter()
        errors: list[str] = []
        findings: list[ReviewFinding] = []
        files_reviewed: list[str] = []
        changed_symbols_all: list[ChangedSymbol] = []
        changed_files_list: list[str] = []

        if cancellation_token and cancellation_token():
            raise ReviewCancelledException("Review cancelled before processing.")

        diff_summary: GitDiffSummary = self.diff_parser.parse(diff_text)
        if diff_summary.warnings:
            errors.extend(diff_summary.warnings)

        for cf in diff_summary.files:
            if cancellation_token and cancellation_token():
                raise ReviewCancelledException("Review cancelled during file analysis.")

            target_path = cf.new_path or cf.old_path
            if not target_path:
                continue

            if self._is_ignored(target_path):
                continue

            # Strict Path Traversal Defense (SEC-01):
            # Validate containment of both old and new paths relative to repo root
            is_new_contained = validate_contained_path(self.repo_root, cf.new_path) if cf.new_path else None
            is_old_contained = validate_contained_path(self.repo_root, cf.old_path) if cf.old_path else None

            if cf.new_path and is_new_contained is None:
                errors.append(f"Rejected path outside repository boundary: {target_path}")
                continue
            if cf.old_path and is_old_contained is None:
                errors.append(f"Rejected path outside repository boundary: {target_path}")
                continue

            changed_files_list.append(target_path)

            if cf.is_binary:
                continue

            if cf.change_type == DiffChangeType.DELETED:
                continue

            # Check file size limit if contained file exists on disk
            full_disk_path = is_new_contained or is_old_contained
            content: str | None = None
            if full_disk_path is not None and full_disk_path.is_file():
                try:
                    file_size = full_disk_path.stat().st_size
                    if file_size > self.config.max_file_size_bytes:
                        findings.append(
                            ReviewFinding(
                                rule_id="RESOURCE-LIMIT",
                                title="File Exceeds Size Limit",
                                message=(
                                    f"File '{target_path}' ({file_size} bytes) exceeds limit "
                                    f"of {self.config.max_file_size_bytes} bytes; skipping static analysis."
                                ),
                                severity=FindingSeverity.INFO,
                                category=FindingCategory.QUALITY,
                                origin=FindingOrigin.STATIC_ANALYSIS,
                                location=SourceLocation(file_path=target_path, start_line=1),
                                tool_name="local_review_engine",
                                confidence=1.0,
                            )
                        )
                        continue
                    content = full_disk_path.read_text(encoding="utf-8", errors="ignore")
                except OSError as e:
                    errors.append(f"Failed to read '{target_path}': {e}")
                    continue

            # If not on disk, reconstruct from hunk additions
            if content is None:
                added_chunks: list[str] = []
                for hunk in cf.hunks:
                    for line in hunk.lines:
                        if line.startswith("+") and not line.startswith("+++"):
                            added_chunks.append(line[1:])
                content = chr(10).join(added_chunks)

            files_reviewed.append(target_path)

            # Map changed symbols
            file_symbols = self.symbol_mapper.map_file_symbols(
                changed_file=cf,
                source_content=content,
                repo_root=self.repo_root,
            )
            changed_symbols_all.extend(file_symbols)

            # Execute static analysis adapters with bounded timeout enforcement
            for adapter in self.adapters:
                if not adapter.is_available():
                    continue

                if cancellation_token and cancellation_token():
                    raise ReviewCancelledException("Review cancelled during adapter execution.")

                adapter_findings = self._run_adapter_with_timeout(
                    adapter=adapter,
                    file_path=target_path,
                    content=content,
                    timeout_seconds=self.config.per_file_timeout_seconds,
                )
                findings.extend(adapter_findings)

        if cancellation_token and cancellation_token():
            raise ReviewCancelledException("Review cancelled before dependency graph analysis.")

        eff_repo_id = repository_id or self.config.repository_id
        eff_commit_sha = commit_sha or self.config.commit_sha or diff_summary.head_commit
        eff_org_id = organization_id or self.config.organization_id

        # Build dependency graph and discover affected tests
        try:
            if files_reviewed:
                self.dependency_graph.build_graph(files=files_reviewed)
                affected_artifacts = self.dependency_graph.find_affected_artifacts(
                    changed_symbols=changed_symbols_all,
                    changed_files=changed_files_list,
                )
            else:
                affected_artifacts = AffectedArtifacts(changed_symbols=changed_symbols_all)
        except Exception as e:
            errors.append(f"Dependency graph analysis warning: {e}")
            affected_artifacts = AffectedArtifacts(
                changed_symbols=changed_symbols_all,
                discovery_warnings=[f"Failed to build full dependency graph: {e}"],
            )

        # Consult persisted evidence graph if available
        if self.evidence_service and eff_repo_id and eff_commit_sha and eff_org_id:
            try:
                persisted_tests = await self.evidence_service.get_affected_tests(
                    organization_id=eff_org_id,
                    repository_id=eff_repo_id,
                    commit_sha=eff_commit_sha,
                    changed_files=changed_files_list,
                )
                if persisted_tests:
                    combined = set(affected_artifacts.affected_tests).union(persisted_tests)
                    affected_artifacts.affected_tests = sorted(combined)
            except Exception as e:
                logger.info("Persisted evidence graph test lookup fallback: %s", e)

        if cancellation_token and cancellation_token():
            raise ReviewCancelledException("Review cancelled before AI review.")

        # Optional AI review execution
        if enable_ai or self.config.enable_ai_review:
            try:
                bounded_context = self.context_builder.build_context(
                    repository_name=self.repo_root.name,
                    changed_files=diff_summary.files,
                    affected_artifacts=affected_artifacts,
                    static_findings=findings,
                    base_commit=diff_summary.base_commit,
                    head_commit=diff_summary.head_commit,
                )
                ai_findings, _, ai_errors = await self.ai_reviewer.review(context=bounded_context)
                findings.extend(ai_findings)
                errors.extend(ai_errors)
            except Exception as e:
                errors.append(f"AI review execution error: {e}")

        # Record findings as evidence in persistent graph if service is available
        if self.evidence_service and eff_org_id and eff_repo_id:
            for f in findings:
                try:
                    ev_status = EvidenceValidationStatus.VALIDATED
                    if f.validation_status.value == "REJECTED_LOCATION":
                        ev_status = EvidenceValidationStatus.REJECTED_LOCATION
                    elif f.validation_status.value == "REJECTED_CONTRADICTED":
                        ev_status = EvidenceValidationStatus.REJECTED_CONTRADICTED
                    elif f.validation_status.value == "UNVERIFIED":
                        ev_status = EvidenceValidationStatus.UNVERIFIED

                    ev_rec = EvidenceRecord(
                        id=f.id,
                        evidence_type=f.origin.value,
                        provenance=ProvenanceTag(
                            source=f.tool_name or "local_review_engine",
                            tool_version="1.0",
                        ),
                        file_path=f.location.file_path,
                        start_line=f.location.start_line,
                        end_line=f.location.end_line,
                        symbol_name=f.location.symbol_name,
                        content=f.message,
                        structured_payload={
                            "rule_id": f.rule_id,
                            "title": f.title,
                            "severity": f.severity.value,
                            "category": f.category.value,
                        },
                        confidence=f.confidence,
                        validation_status=ev_status,
                    )
                    await self.evidence_service.record_evidence(
                        organization_id=eff_org_id,
                        record=ev_rec,
                        repository_id=eff_repo_id,
                        commit_sha=eff_commit_sha,
                    )
                except Exception as exc:
                    logger.debug("Evidence record persistence omitted: %s", exc)

        elapsed = time.perf_counter() - start_time
        return ReviewReport(
            repository_path=str(self.repo_root),
            base_commit=diff_summary.base_commit,
            head_commit=diff_summary.head_commit,
            diff_summary=diff_summary,
            affected_artifacts=affected_artifacts,
            findings=findings,
            files_reviewed=files_reviewed,
            execution_time_seconds=round(elapsed, 4),
            is_clean=len(findings) == 0,
            errors=errors,
        )

    def _run_adapter_with_timeout(
        self,
        adapter: StaticAnalysisAdapter,
        file_path: str,
        content: str,
        timeout_seconds: float,
    ) -> list[ReviewFinding]:
        options: dict[str, Any] = {
            "enabled": self.config.enable_external_tools,
            "timeout_seconds": timeout_seconds,
        }
        return execute_adapter_with_enforceable_timeout(
            adapter=adapter,
            file_path=file_path,
            content=content,
            options=options,
            timeout_seconds=timeout_seconds,
        )

    def review_local_git_diff(
        self,
        base_ref: str | None = None,
        staged: bool = False,
        unstaged: bool = False,
    ) -> ReviewReport:
        """Extracts local unified Git diff safely without shell=True and performs review.

        Supports:
        - Staged changes (`staged=True` -> `git diff --cached`)
        - Unstaged changes (`unstaged=True` -> `git diff`)
        - Base branch or commit comparison (`base_ref` -> `git diff base_ref...HEAD` with fallback)
        - Working tree changes (default: `git diff HEAD`, falling back to `git diff` for fresh repos)
        """
        cmd: list[str] = ["git", "diff"]
        if staged:
            cmd.append("--cached")
        elif unstaged:
            pass  # git diff default is unstaged
        elif base_ref:
            cmd.extend([f"{base_ref}...HEAD"])
        else:
            cmd.append("HEAD")

        try:
            res = subprocess.run(
                cmd,
                cwd=str(self.repo_root),
                capture_output=True,
                check=False,
                timeout=15.0,
            )
            raw_diff = res.stdout.decode("utf-8", errors="ignore")
            # If base_ref...HEAD failed (e.g. no merge base or shallow clone), fallback to base_ref..HEAD
            if res.returncode != 0 and base_ref:
                fallback_cmd = ["git", "diff", f"{base_ref}..HEAD"]
                fallback_res = subprocess.run(
                    fallback_cmd,
                    cwd=str(self.repo_root),
                    capture_output=True,
                    check=False,
                    timeout=15.0,
                )
                if fallback_res.returncode == 0:
                    raw_diff = fallback_res.stdout.decode("utf-8", errors="ignore")
                else:
                    err_msg = res.stderr.decode("utf-8", errors="ignore").strip()
                    empty_summary = GitDiffSummary(
                        warnings=[f"Git diff error comparing against '{base_ref}': {err_msg}"]
                    )
                    return ReviewReport(
                        repository_path=str(self.repo_root),
                        diff_summary=empty_summary,
                        affected_artifacts=AffectedArtifacts(),
                        errors=[f"Git comparison against '{base_ref}' failed: {err_msg}"],
                    )
            # If git diff HEAD failed (e.g. initial repository with no commits yet)
            elif res.returncode != 0 and not base_ref and not staged and not unstaged:
                unstaged_res = subprocess.run(
                    ["git", "diff"],
                    cwd=str(self.repo_root),
                    capture_output=True,
                    check=False,
                    timeout=15.0,
                )
                if unstaged_res.returncode == 0:
                    raw_diff = unstaged_res.stdout.decode("utf-8", errors="ignore")
        except (subprocess.TimeoutExpired, OSError) as e:
            empty_summary = GitDiffSummary(warnings=[f"Failed to generate git diff: {e}"])
            return ReviewReport(
                repository_path=str(self.repo_root),
                diff_summary=empty_summary,
                affected_artifacts=AffectedArtifacts(),
                errors=[f"Git diff extraction failure: {e}"],
            )

        return self.review_diff(raw_diff)
