"""Deterministic and safe change-set detector for Git and explicit file lists."""

import re
import subprocess
from pathlib import Path

from packages.review.analyzer.symbol_mapper import SymbolMapper
from packages.review.domain.models import ChangedFile, ChangedSymbol, DiffChangeType
from packages.review.git.diff_parser import GitDiffParser
from packages.review.impact.models import ChangeSet
from packages.review.security.path_validation import validate_contained_path

REVISION_PATTERN = re.compile(r"^[A-Za-z0-9_.\-/@^~:]+$")


class ChangeSetDetector:
    """Acquires, validates, and normalizes change sets for change impact analysis."""

    def __init__(
        self,
        repo_root: str | Path,
        max_diff_bytes: int = 10_000_000,
        timeout_seconds: float = 15.0,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.max_diff_bytes = max_diff_bytes
        self.timeout_seconds = timeout_seconds
        self.diff_parser = GitDiffParser(max_diff_bytes=max_diff_bytes)
        self.symbol_mapper = SymbolMapper()

    def from_working_tree(self, staged: bool = False, unstaged: bool = False) -> ChangeSet:
        """Extracts changes from the working tree (staged, unstaged, or both)."""
        cmd = ["git", "diff"]
        origin = "working_tree"
        if staged:
            cmd.append("--cached")
            origin = "staged"
        elif unstaged:
            origin = "unstaged"
        else:
            cmd.append("HEAD")

        raw_diff, err = self._run_git(cmd)
        if err and not staged and not unstaged:
            # Fallback for initial repository without HEAD commit
            raw_diff, _ = self._run_git(["git", "diff"])

        return self._build_change_set_from_diff(
            raw_diff=raw_diff,
            origin=origin,
            base_rev="HEAD" if not staged and not unstaged else None,
            target_rev="working_tree",
        )

    def from_revisions(self, base_rev: str, target_rev: str = "HEAD") -> ChangeSet:
        """Extracts changes between two Git revisions (e.g. merge base or commit range)."""
        if not REVISION_PATTERN.match(base_rev):
            raise ValueError(f"Invalid characters in base revision: {base_rev}")
        if not REVISION_PATTERN.match(target_rev):
            raise ValueError(f"Invalid characters in target revision: {target_rev}")

        # Try triple-dot (merge base diff)
        cmd = ["git", "diff", f"{base_rev}...{target_rev}"]
        raw_diff, err = self._run_git(cmd)

        if err and "..." in cmd[-1]:
            # Fallback to two-dot comparison if triple-dot fails (e.g. shallow clone or detached)
            fallback_cmd = ["git", "diff", f"{base_rev}..{target_rev}"]
            raw_diff, fallback_err = self._run_git(fallback_cmd)
            if fallback_err:
                raise RuntimeError(
                    f"Git diff comparison failed between '{base_rev}' and '{target_rev}': {fallback_err}"
                )

        return self._build_change_set_from_diff(
            raw_diff=raw_diff,
            origin="git_revision",
            base_rev=base_rev,
            target_rev=target_rev,
        )

    def from_explicit_files(self, file_paths: list[str]) -> ChangeSet:
        """Creates a change set from an explicit list of repository-relative file paths."""
        changed_files: list[ChangedFile] = []
        added: list[str] = []
        modified: list[str] = []
        unresolved: list[str] = []

        for p_str in file_paths:
            contained = validate_contained_path(self.repo_root, p_str)
            if contained is None:
                unresolved.append(p_str)
                continue

            try:
                rel = str(contained.relative_to(self.repo_root))
            except ValueError:
                rel = p_str

            if contained.is_file():
                modified.append(rel)
                changed_files.append(
                    ChangedFile(
                        new_path=rel,
                        old_path=rel,
                        change_type=DiffChangeType.MODIFIED,
                    )
                )
            else:
                unresolved.append(rel)

        # Extract symbols for analyzable files
        symbols: list[ChangedSymbol] = []
        for cf in changed_files:
            syms = self.symbol_mapper.map_file_symbols(cf, repo_root=self.repo_root)
            symbols.extend(syms)

        return ChangeSet(
            origin="explicit_files",
            changed_files=changed_files,
            changed_symbols=symbols,
            added_paths=added,
            modified_paths=modified,
            unresolved_paths=unresolved,
        )

    def _build_change_set_from_diff(
        self,
        raw_diff: str,
        origin: str,
        base_rev: str | None,
        target_rev: str | None,
    ) -> ChangeSet:
        summary = self.diff_parser.parse(raw_diff)

        added: list[str] = []
        modified: list[str] = []
        deleted: list[str] = []
        renamed: list[tuple[str, str]] = []

        for cf in summary.files:
            if cf.change_type == DiffChangeType.ADDED and cf.new_path:
                added.append(cf.new_path)
            elif cf.change_type == DiffChangeType.MODIFIED and cf.new_path:
                modified.append(cf.new_path)
            elif cf.change_type == DiffChangeType.DELETED and cf.old_path:
                deleted.append(cf.old_path)
            elif cf.change_type == DiffChangeType.RENAMED and cf.old_path and cf.new_path:
                renamed.append((cf.old_path, cf.new_path))
                modified.append(cf.new_path)

        symbols: list[ChangedSymbol] = []
        for cf in summary.files:
            syms = self.symbol_mapper.map_file_symbols(cf, repo_root=self.repo_root)
            symbols.extend(syms)

        return ChangeSet(
            origin=origin,
            base_revision=base_rev or summary.base_commit,
            target_revision=target_rev or summary.head_commit,
            changed_files=summary.files,
            changed_symbols=symbols,
            added_paths=added,
            modified_paths=modified,
            deleted_paths=deleted,
            renamed_paths=renamed,
            total_added_lines=summary.total_added_lines,
            total_deleted_lines=summary.total_deleted_lines,
        )

    def _run_git(self, cmd: list[str]) -> tuple[str, str | None]:
        try:
            res = subprocess.run(
                cmd,
                cwd=str(self.repo_root),
                capture_output=True,
                check=False,
                timeout=self.timeout_seconds,
            )
            out = res.stdout.decode("utf-8", errors="ignore")
            err = res.stderr.decode("utf-8", errors="ignore").strip()
            return out, err if res.returncode != 0 else None
        except Exception as e:
            return "", str(e)
