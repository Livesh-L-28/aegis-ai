"""Finding validator and grounding verification engine for LogicFalcon (AEGIS AI).

Provides multi-pass verification of review findings to eliminate hallucinations,
verify code locations, assert factual evidence, and deduplicate findings.
"""

from dataclasses import dataclass
from pathlib import Path

from packages.logging.logger import get_logger
from packages.review.domain.models import (
    GitDiffSummary,
    ReviewFinding,
    ValidationStatus,
)
from packages.review.security.path_validation import validate_contained_path

logger = get_logger("logicfalcon.review.validator")


@dataclass
class ValidationStats:
    """Statistics collected during findings validation."""

    total_inspected: int = 0
    validated: int = 0
    unverified: int = 0
    rejected_location: int = 0
    rejected_contradicted: int = 0
    deduplicated_dropped: int = 0


class FindingValidator:
    """Verifies review findings against filesystem and git diff evidence."""

    def __init__(
        self,
        repo_root: Path | None = None,
        min_confidence: float = 0.6,
        reject_ungrounded: bool = True,
    ) -> None:
        self.repo_root = repo_root.resolve() if repo_root else None
        self.min_confidence = min_confidence
        self.reject_ungrounded = reject_ungrounded

    def validate(
        self,
        findings: list[ReviewFinding],
        repo_root: Path | None = None,
        diff_summary: GitDiffSummary | None = None,
        override_contents: dict[str, str] | None = None,
    ) -> tuple[list[ReviewFinding], ValidationStats]:
        """Validates, filters, and deduplicates a collection of findings."""
        root = (repo_root.resolve() if repo_root else self.repo_root) or Path.cwd().resolve()
        stats = ValidationStats(total_inspected=len(findings))
        overrides = override_contents or {}

        # 1. Deduplicate findings while preserving the highest confidence finding
        deduped_map: dict[str, ReviewFinding] = {}
        for f in findings:
            fp = f.deduplication_hash or f"{f.location.file_path}:{f.location.start_line}:{f.rule_id}"
            if fp in deduped_map:
                existing = deduped_map[fp]
                stats.deduplicated_dropped += 1
                if f.confidence > existing.confidence:
                    deduped_map[fp] = f
            else:
                deduped_map[fp] = f

        # Build lookup of diff files and added lines if diff_summary is available
        diff_lines_map: dict[str, set[int]] = {}
        if diff_summary:
            for cf in diff_summary.files:
                path = cf.new_path or cf.old_path
                if path:
                    lines: set[int] = set()
                    for hunk in cf.hunks:
                        lines.update(hunk.added_lines)
                    diff_lines_map[path] = lines

        verified_findings: list[ReviewFinding] = []

        for finding in deduped_map.values():
            file_path = finding.location.file_path
            start_line = finding.location.start_line
            end_line = finding.location.end_line or start_line

            # Check 1: Path Traversal and File Containment
            resolved_file = validate_contained_path(root, file_path)
            if not resolved_file:
                finding.validation_status = ValidationStatus.REJECTED_LOCATION
                finding.is_uncertain = True
                stats.rejected_location += 1
                if not self.reject_ungrounded:
                    verified_findings.append(finding)
                continue

            # Check 2: File exists on disk or in diff or in override contents
            has_override = file_path in overrides or str(resolved_file) in overrides
            file_exists = resolved_file.is_file() or has_override
            in_diff = file_path in diff_lines_map

            if not file_exists and not in_diff:
                finding.validation_status = ValidationStatus.REJECTED_LOCATION
                finding.is_uncertain = True
                stats.rejected_location += 1
                if not self.reject_ungrounded:
                    verified_findings.append(finding)
                continue

            # Check 3: Line bounds verification
            if file_exists:
                try:
                    if has_override:
                        file_text = overrides.get(file_path, overrides.get(str(resolved_file), ""))
                    else:
                        file_text = resolved_file.read_text(encoding="utf-8", errors="ignore")
                    file_lines = file_text.splitlines()
                    total_lines = len(file_lines)

                    if start_line < 1 or start_line > max(1, total_lines):
                        finding.validation_status = ValidationStatus.REJECTED_LOCATION
                        finding.is_uncertain = True
                        stats.rejected_location += 1
                        if not self.reject_ungrounded:
                            verified_findings.append(finding)
                        continue

                    # Check 4: Grounding / Factuality Check
                    # If technical evidence is provided, check if evidence relates to target lines
                    evidence = (finding.technical_evidence or "").strip()
                    if evidence and total_lines > 0:
                        # Extract context window around start_line (start_line - 2 to end_line + 2)
                        ctx_start = max(0, start_line - 3)
                        ctx_end = min(total_lines, end_line + 3)
                        context_snippet = "\n".join(file_lines[ctx_start:ctx_end])

                        # If technical evidence looks like an exact code snippet, test if present
                        ev_first_line = evidence.splitlines()[0].strip() if evidence else ""
                        if len(ev_first_line) > 5:
                            is_grounded = ev_first_line in context_snippet or ev_first_line in file_text
                            if not is_grounded and "[REDACTED_SECRET]" in ev_first_line:
                                from packages.review.adapters.ast_security import (
                                    redact_secrets_in_text,
                                )

                                is_grounded = (
                                    ev_first_line in redact_secrets_in_text(context_snippet)
                                    or ev_first_line in redact_secrets_in_text(file_text)
                                )

                            if not is_grounded:
                                finding.validation_status = ValidationStatus.REJECTED_CONTRADICTED
                                finding.is_uncertain = True
                                stats.rejected_contradicted += 1
                                if not self.reject_ungrounded:
                                    verified_findings.append(finding)
                                continue

                except Exception as e:
                    logger.debug(f"File reading error during validation of {file_path}: {e}")

            # Check 5: Confidence threshold
            if finding.confidence < self.min_confidence:
                finding.validation_status = ValidationStatus.UNVERIFIED
                finding.is_uncertain = True
                stats.unverified += 1
                if not self.reject_ungrounded:
                    verified_findings.append(finding)
                continue

            finding.validation_status = ValidationStatus.VALIDATED
            stats.validated += 1
            verified_findings.append(finding)

        return verified_findings, stats
