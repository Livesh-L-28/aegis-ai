"""Secure unified Git diff parser for AEGIS AI Code Review."""

import contextlib
import re

from packages.review.domain.models import (
    ChangedFile,
    DiffChangeType,
    DiffHunk,
    GitDiffSummary,
)

HUNK_HEADER_PATTERN = re.compile(
    r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(?:\s*(.*))?$"
)
INDEX_PATTERN = re.compile(r"^index\s+([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)")
COMMIT_PATTERN = re.compile(r"^commit\s+([0-9a-fA-F]{7,40})")


def _clean_git_path(raw: str) -> str:
    """Cleans Git diff path prefixes and unquotes C-style escapes if present."""
    p = raw.strip()
    if p.startswith('"') and p.endswith('"') and len(p) >= 2:
        p = p[1:-1]
        with contextlib.suppress(Exception):
            p = p.encode("utf-8").decode("unicode_escape")
    if p.startswith("a/") or p.startswith("b/"):
        p = p[2:]
    return p


class GitDiffParser:
    """Parses unified Git diffs safely in pure Python without executing shell commands."""

    def __init__(self, max_diff_bytes: int = 10_000_000) -> None:
        self.max_diff_bytes = max_diff_bytes

    def parse(self, diff_text: str) -> GitDiffSummary:
        """Parses a unified diff string into a structured GitDiffSummary."""
        warnings: list[str] = []
        is_truncated = False

        if not diff_text:
            return GitDiffSummary()

        if len(diff_text.encode("utf-8", errors="ignore")) > self.max_diff_bytes:
            warnings.append(
                f"Diff exceeds maximum allowed size ({self.max_diff_bytes} bytes); parsing truncated."
            )
            diff_text = diff_text[: self.max_diff_bytes]
            is_truncated = True

        files: list[ChangedFile] = []
        base_commit: str | None = None
        head_commit: str | None = None

        lines = diff_text.splitlines()
        idx = 0
        num_lines = len(lines)

        current_file: ChangedFile | None = None
        current_hunk: DiffHunk | None = None
        current_new_line = 0
        current_old_line = 0

        while idx < num_lines:
            line = lines[idx]

            # Check for top-level commit headers if present
            if not base_commit:
                commit_match = COMMIT_PATTERN.match(line)
                if commit_match:
                    head_commit = commit_match.group(1)

            # Check for diff --git headers
            if line.startswith("diff --git "):
                if current_file:
                    if current_hunk:
                        current_file.hunks.append(current_hunk)
                        current_hunk = None
                    files.append(current_file)
                    current_file = None

                diff_rest = line.removeprefix("diff --git ").strip()
                old_path = None
                new_path = None

                if diff_rest.startswith('"'):
                    first_quote_end = diff_rest.find('"', 1)
                    if first_quote_end != -1:
                        old_part = diff_rest[1:first_quote_end]
                        rem = diff_rest[first_quote_end + 1 :].strip()
                        new_part = rem[1:-1] if rem.startswith('"') and rem.endswith('"') else rem
                        old_path = _clean_git_path(old_part)
                        new_path = _clean_git_path(new_part)
                elif " b/" in diff_rest:
                    split_idx = diff_rest.find(" b/")
                    old_path = _clean_git_path(diff_rest[:split_idx])
                    new_path = _clean_git_path(diff_rest[split_idx + 1 :])
                else:
                    parts = line.split()
                    if len(parts) >= 4:
                        old_path = _clean_git_path(parts[2])
                        new_path = _clean_git_path(parts[3])

                current_file = ChangedFile(
                    old_path=old_path,
                    new_path=new_path,
                    change_type=DiffChangeType.MODIFIED,
                )
                idx += 1
                continue

            if current_file is not None:
                # Check for index line to extract commit SHAs
                index_match = INDEX_PATTERN.match(line)
                if index_match:
                    if not base_commit:
                        base_commit = index_match.group(1)
                    if not head_commit:
                        head_commit = index_match.group(2)
                    idx += 1
                    continue

                if line.startswith("new file mode"):
                    current_file.change_type = DiffChangeType.ADDED
                    current_file.old_path = None
                    idx += 1
                    continue

                if line.startswith("deleted file mode"):
                    current_file.change_type = DiffChangeType.DELETED
                    current_file.new_path = None
                    idx += 1
                    continue

                if line.startswith("rename from "):
                    current_file.change_type = DiffChangeType.RENAMED
                    current_file.old_path = _clean_git_path(line.removeprefix("rename from ").strip())
                    idx += 1
                    continue

                if line.startswith("rename to "):
                    current_file.change_type = DiffChangeType.RENAMED
                    current_file.new_path = _clean_git_path(line.removeprefix("rename to ").strip())
                    idx += 1
                    continue

                if "Binary files " in line and " differ" in line:
                    current_file.is_binary = True
                    current_file.change_type = DiffChangeType.BINARY
                    idx += 1
                    continue

                if line.startswith("GIT binary patch"):
                    current_file.is_binary = True
                    current_file.change_type = DiffChangeType.BINARY
                    idx += 1
                    continue

                if line.startswith("--- "):
                    path_part = line[4:].strip()
                    if path_part == "/dev/null":
                        current_file.old_path = None
                        current_file.change_type = DiffChangeType.ADDED
                    else:
                        current_file.old_path = _clean_git_path(path_part)
                    idx += 1
                    continue

                if line.startswith("+++ "):
                    path_part = line[4:].strip()
                    if path_part == "/dev/null":
                        current_file.new_path = None
                        current_file.change_type = DiffChangeType.DELETED
                    else:
                        current_file.new_path = _clean_git_path(path_part)
                    idx += 1
                    continue

                # Check for hunk header
                hunk_match = HUNK_HEADER_PATTERN.match(line)
                if hunk_match:
                    if current_hunk:
                        current_file.hunks.append(current_hunk)
                        current_hunk = None

                    old_start = int(hunk_match.group(1))
                    old_length = int(hunk_match.group(2)) if hunk_match.group(2) else 1
                    new_start = int(hunk_match.group(3))
                    new_length = int(hunk_match.group(4)) if hunk_match.group(4) else 1
                    header_text = hunk_match.group(5) or ""

                    current_hunk = DiffHunk(
                        old_start=old_start,
                        old_length=old_length,
                        new_start=new_start,
                        new_length=new_length,
                        header=header_text,
                    )
                    current_old_line = old_start
                    current_new_line = new_start
                    idx += 1
                    continue

                # In-hunk lines
                if current_hunk is not None:
                    if line.startswith("+") and not line.startswith("+++"):
                        current_hunk.lines.append(line)
                        current_hunk.added_lines.append(current_new_line)
                        current_file.added_lines_count += 1
                        current_new_line += 1
                        idx += 1
                        continue
                    elif line.startswith("-") and not line.startswith("---"):
                        current_hunk.lines.append(line)
                        current_hunk.deleted_lines.append(current_old_line)
                        current_file.deleted_lines_count += 1
                        current_old_line += 1
                        idx += 1
                        continue
                    elif line.startswith(" ") or line == "":
                        current_hunk.lines.append(line)
                        current_old_line += 1
                        current_new_line += 1
                        idx += 1
                        continue
                    elif line.startswith(r"\ No newline at end of file"):
                        current_hunk.lines.append(line)
                        idx += 1
                        continue

            idx += 1

        if current_file:
            if current_hunk:
                current_file.hunks.append(current_hunk)
            files.append(current_file)

        total_added = sum(f.added_lines_count for f in files)
        total_deleted = sum(f.deleted_lines_count for f in files)

        return GitDiffSummary(
            base_commit=base_commit,
            head_commit=head_commit,
            files=files,
            total_added_lines=total_added,
            total_deleted_lines=total_deleted,
            is_truncated=is_truncated,
            warnings=warnings,
        )
