"""Failure localization subsystem: correlates stack frames with revision source and AST symbols."""

from uuid import UUID

from apps.api.app.services.evidence_graph import EvidenceGraphService
from packages.intelligence.debugging.models import FrameOriginType, StackTraceFrame

PROTECTED_FILENAMES = {"render_schema.json"}


class FailureLocalizer:
    """Matches stack frames against indexed repository revisions, resolving symbols and failure sites."""

    def __init__(self, service: EvidenceGraphService) -> None:
        self.service = service

    async def localize_frames(
        self,
        organization_id: UUID,
        repository_id: UUID | None,
        commit_sha: str | None,
        frames: list[StackTraceFrame],
    ) -> list[StackTraceFrame]:
        """Validates each frame against the revision Evidence Graph, resolving AST symbols."""
        localized: list[StackTraceFrame] = []

        for frame in frames:
            # 1. Protected file check
            if frame.is_protected_file or any(p in PROTECTED_FILENAMES for p in frame.file_path.split("/")):
                f_copy = frame.model_copy()
                f_copy.file_path = "[PROTECTED_FILE_REDACTED]"
                f_copy.is_resolved = False
                f_copy.is_protected_file = True
                f_copy.resolution_note = "Access to protected file denied by security policy."
                localized.append(f_copy)
                continue

            # 2. External library check
            if frame.origin == FrameOriginType.EXTERNAL_LIBRARY:
                f_copy = frame.model_copy()
                f_copy.is_resolved = False
                f_copy.resolution_note = "External third-party or runtime library frame."
                localized.append(f_copy)
                continue

            # 3. Missing revision check
            if not repository_id or not commit_sha:
                f_copy = frame.model_copy()
                f_copy.is_resolved = False
                f_copy.resolution_note = "Cannot resolve frame without repository_id and commit_sha."
                localized.append(f_copy)
                continue

            # 4. Safe relative path normalization
            rel_path = self._normalize_relative_path(frame.file_path)
            if not rel_path or ".." in rel_path.split("/"):
                f_copy = frame.model_copy()
                f_copy.is_resolved = False
                f_copy.resolution_note = "Path traversal or malformed path rejected."
                localized.append(f_copy)
                continue

            # 5. Query Evidence Graph for symbols in this file
            symbols, _total = await self.service.get_symbols_for_revision(
                organization_id=organization_id,
                repository_id=repository_id,
                commit_sha=commit_sha,
                file_path=rel_path,
                limit=100,
            )

            f_copy = frame.model_copy()
            f_copy.file_path = rel_path

            if not symbols:
                # Check if file exists without symbols (e.g. empty or test without classes)
                f_copy.is_resolved = False
                f_copy.resolution_note = "File or symbols not found in indexed revision."
            else:
                # Find enclosing symbol by line range
                enclosing = [
                    s for s in symbols
                    if s.start_line <= frame.line_number <= s.end_line
                ]
                if enclosing:
                    # Choose innermost symbol (smallest line range)
                    best_match = min(enclosing, key=lambda s: s.end_line - s.start_line)
                    f_copy.matched_symbol = best_match.qualified_name
                    f_copy.is_resolved = True
                    f_copy.origin = FrameOriginType.INTERNAL if frame.origin != FrameOriginType.TEST_FRAME else FrameOriginType.TEST_FRAME
                    f_copy.resolution_note = f"Resolved to symbol '{best_match.qualified_name}' (L{best_match.start_line}-L{best_match.end_line})"
                else:
                    # File exists in revision, but line is outside symbols
                    f_copy.is_resolved = True
                    f_copy.origin = FrameOriginType.INTERNAL if frame.origin != FrameOriginType.TEST_FRAME else FrameOriginType.TEST_FRAME
                    f_copy.resolution_note = f"File matched in revision (line {frame.line_number} outside defined symbol boundaries)"

            localized.append(f_copy)

        return localized

    @staticmethod
    def _normalize_relative_path(path: str) -> str:
        """Strips common prefix working directories to find the relative repository path."""
        norm = path.replace("\\", "/").strip().lstrip("/")
        # If absolute path like /app/src/index.ts or /workspace/pkg/calc.py
        for prefix in ("app/", "workspace/", "src/", "var/task/"):
            if norm.startswith(prefix) and not prefix.startswith("src/"):
                norm = norm[len(prefix):]
        return norm
