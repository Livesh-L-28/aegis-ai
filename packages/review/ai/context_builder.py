"""Bounded repository context builder for AI code review."""

from typing import Any

from pydantic import BaseModel, Field

from packages.review.domain.models import (
    AffectedArtifacts,
    ChangedFile,
    ReviewFinding,
)


class BoundedReviewContext(BaseModel):
    """Encapsulates strictly bounded repository context for LLM code review prompts."""

    repository_name: str
    base_commit: str | None = None
    head_commit: str | None = None
    changed_files: list[str] = Field(default_factory=list)
    diff_snippets: list[dict[str, Any]] = Field(default_factory=list)
    changed_symbols: list[dict[str, Any]] = Field(default_factory=list)
    dependencies: dict[str, list[str]] = Field(default_factory=dict)
    affected_tests: list[str] = Field(default_factory=list)
    static_findings_summary: list[dict[str, Any]] = Field(default_factory=list)
    missing_context_notes: list[str] = Field(default_factory=list)
    total_character_count: int = 0
    is_truncated: bool = False


class ContextBuilder:
    """Constructs bounded, sanitized prompt context to prevent context-window overflow and ReDoS."""

    def __init__(
        self,
        max_total_chars: int = 24_000,
        max_hunk_lines_per_file: int = 200,
        max_symbols_per_file: int = 20,
        max_affected_tests: int = 20,
    ) -> None:
        self.max_total_chars = max_total_chars
        self.max_hunk_lines_per_file = max_hunk_lines_per_file
        self.max_symbols_per_file = max_symbols_per_file
        self.max_affected_tests = max_affected_tests

    def build_context(
        self,
        repository_name: str,
        changed_files: list[ChangedFile],
        affected_artifacts: AffectedArtifacts,
        static_findings: list[ReviewFinding],
        base_commit: str | None = None,
        head_commit: str | None = None,
    ) -> BoundedReviewContext:
        """Assembles a bounded context packet ready for LLM code review."""
        missing_notes: list[str] = list(affected_artifacts.discovery_warnings)
        diff_snippets: list[dict[str, Any]] = []
        chars_used = 0
        truncated = False

        file_names = [f.new_path or f.old_path or "unknown" for f in changed_files]

        for cf in changed_files:
            file_path = cf.new_path or cf.old_path or "unknown"
            if cf.is_binary:
                missing_notes.append(f"Binary file '{file_path}' excluded from AI review context.")
                continue

            hunk_texts: list[str] = []
            line_count = 0
            for hunk in cf.hunks:
                if line_count >= self.max_hunk_lines_per_file:
                    hunk_texts.append("... [Hunks truncated due to line limits] ...")
                    truncated = True
                    break
                for line in hunk.lines:
                    if line_count >= self.max_hunk_lines_per_file:
                        hunk_texts.append("... [Hunks truncated due to line limits] ...")
                        truncated = True
                        break
                    hunk_texts.append(line)
                    line_count += 1

            raw_content = "\n".join(hunk_texts)
            snippet_chars = len(raw_content)

            if chars_used + snippet_chars > self.max_total_chars:
                missing_notes.append(
                    f"Diff content for '{file_path}' partially omitted to stay within character budget."
                )
                truncated = True
                remaining = max(0, self.max_total_chars - chars_used)
                raw_content = raw_content[:remaining] + "\n... [Context truncated]"
                diff_snippets.append(
                    {
                        "file_path": file_path,
                        "change_type": cf.change_type.value,
                        "added_lines": cf.added_lines_count,
                        "deleted_lines": cf.deleted_lines_count,
                        "content": raw_content,
                    }
                )
                chars_used += len(raw_content)
                break

            diff_snippets.append(
                {
                    "file_path": file_path,
                    "change_type": cf.change_type.value,
                    "added_lines": cf.added_lines_count,
                    "deleted_lines": cf.deleted_lines_count,
                    "content": raw_content,
                }
            )
            chars_used += snippet_chars

        # Map changed symbols
        symbol_data: list[dict[str, Any]] = []
        for cs in affected_artifacts.changed_symbols[: self.max_symbols_per_file * 5]:
            item = {
                "file_path": cs.file_path,
                "name": cs.symbol.name,
                "qualified_name": cs.symbol.qualified_name,
                "symbol_type": cs.symbol.symbol_type.value,
                "start_line": cs.symbol.start_line,
                "end_line": cs.symbol.end_line,
                "signature": cs.symbol.signature,
                "docstring": cs.symbol.docstring,
            }
            symbol_data.append(item)

        # Summarize static findings
        findings_summary = [
            {
                "rule_id": f.rule_id,
                "file_path": f.location.file_path,
                "start_line": f.location.start_line,
                "severity": f.severity.value,
                "message": f.message,
                "origin": f.origin.value,
            }
            for f in static_findings
        ]

        return BoundedReviewContext(
            repository_name=repository_name,
            base_commit=base_commit,
            head_commit=head_commit,
            changed_files=file_names,
            diff_snippets=diff_snippets,
            changed_symbols=symbol_data,
            dependencies=affected_artifacts.reverse_dependencies,
            affected_tests=affected_artifacts.affected_tests[: self.max_affected_tests],
            static_findings_summary=findings_summary,
            missing_context_notes=missing_notes,
            total_character_count=chars_used,
            is_truncated=truncated,
        )
