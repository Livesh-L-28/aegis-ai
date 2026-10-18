"""Maps Git diff hunks to code symbols extracted via AST parsing."""

from pathlib import Path

from packages.intelligence.code.indexer import (
    PythonASTParser,
    sanitize_source_content,
)
from packages.review.domain.models import ChangedFile, ChangedSymbol, DiffChangeType
from packages.review.security.path_validation import validate_contained_path


class SymbolMapper:
    """Correlates Git diff line changes with concrete Python AST symbols."""

    def map_file_symbols(
        self,
        changed_file: ChangedFile,
        source_content: str | None = None,
        repo_root: Path | None = None,
    ) -> list[ChangedSymbol]:
        """Extracts symbols from the modified file and maps changed lines to symbols."""
        if changed_file.is_binary or changed_file.change_type == DiffChangeType.DELETED:
            return []

        rel_path = changed_file.new_path or changed_file.old_path
        if not rel_path or not rel_path.endswith(".py"):
            return []

        content = source_content
        if content is None and repo_root is not None:
            safe_path = validate_contained_path(repo_root, rel_path)
            if safe_path is not None and safe_path.is_file():
                try:
                    content = safe_path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    content = None

        if not content:
            return []

        # Sanitize source content as defense-in-depth prior to AST processing
        sanitized_content = sanitize_source_content(content)

        symbols, _ = PythonASTParser.parse_source(rel_path, sanitized_content)
        if not symbols:
            return []

        # Collect all 1-indexed line numbers modified or added in the new file
        changed_lines: set[int] = set()
        for hunk in changed_file.hunks:
            changed_lines.update(hunk.added_lines)

        if not changed_lines:
            return []

        changed_symbols: list[ChangedSymbol] = []
        for sym in symbols:
            # Check overlap between symbol range [start_line, end_line] and changed_lines
            matching_lines = [
                line for line in changed_lines if sym.start_line <= line <= sym.end_line
            ]
            if matching_lines:
                # Group into continuous ranges
                matching_lines.sort()
                ranges: list[tuple[int, int]] = []
                start = matching_lines[0]
                end = matching_lines[0]
                for line in matching_lines[1:]:
                    if line == end + 1:
                        end = line
                    else:
                        ranges.append((start, end))
                        start = line
                        end = line
                ranges.append((start, end))

                change_type = (
                    "ADDED" if changed_file.change_type == DiffChangeType.ADDED else "MODIFIED"
                )
                changed_symbols.append(
                    ChangedSymbol(
                        symbol=sym,
                        file_path=rel_path,
                        change_type=change_type,
                        changed_line_ranges=ranges,
                    )
                )

        return changed_symbols
