"""Safe remediation engine for LogicFalcon (AEGIS AI).

Applies proposed code fixes with isolated diff previews, developer approval
gates, syntax verification, conflict detection, and non-destructive rollbacks.
"""

import ast
import difflib
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from packages.logging.logger import get_logger
from packages.review.domain.models import ProposedFix
from packages.review.security.path_validation import validate_contained_path

logger = get_logger("logicfalcon.review.fix_engine")


class FixConflictError(Exception):
    """Raised when target file content does not match expected original code."""
    pass


class FixApprovalRequiredError(Exception):
    """Raised when fix application is attempted without explicit developer approval."""
    pass


class FixSyntaxValidationError(Exception):
    """Raised when the proposed fix introduces syntax errors in the target file."""
    pass


@dataclass
class FixApplicationResult:
    """Result of attempting to apply a proposed remediation fix."""

    success: bool
    file_path: str
    diff: str = ""
    error_message: str | None = None
    backup_path: str | None = None
    applied_lines_range: tuple[int, int] = (0, 0)


@dataclass
class RemediationVerificationResult:
    """Outcome of validating a remediation in an isolated workspace with tests and linters."""

    success: bool
    fixes_applied: int
    syntax_valid: bool
    tests_passed: bool
    linters_passed: bool
    diff: str = ""
    test_output: str = ""
    linter_output: str = ""
    error_message: str | None = None
    workspace_path: str = ""


class ReviewFixEngine:
    """Engine for safely inspecting and applying automated code remediations."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root.resolve()

    def preview_fix(self, fix: ProposedFix) -> str:
        """Generates a unified diff preview of the proposed fix without modifying disk."""
        target_file = validate_contained_path(self.repo_root, fix.file_path)
        if not target_file or not target_file.is_file():
            raise FileNotFoundError(f"Target file '{fix.file_path}' does not exist or escapes repo root.")

        original_text = target_file.read_text(encoding="utf-8", errors="ignore")
        lines = original_text.splitlines(keepends=True)

        start = max(1, fix.start_line)
        end = max(start, fix.end_line)

        replacement_lines = [
            line + "\n" if not line.endswith("\n") else line
            for line in fix.replacement_code.splitlines()
        ]
        if not fix.replacement_code.strip():
            replacement_lines = []

        new_lines = lines[: start - 1] + replacement_lines + lines[end:]

        diff = "".join(
            difflib.unified_diff(
                lines,
                new_lines,
                fromfile=f"a/{fix.file_path}",
                tofile=f"b/{fix.file_path}",
            )
        )
        return diff or fix.diff_preview

    def apply_fix(
        self,
        fix: ProposedFix,
        approved: bool = False,
        dry_run: bool = False,
        validate_syntax: bool = True,
        create_backup: bool = True,
    ) -> FixApplicationResult:
        """Applies a proposed fix to the target file with safety validations."""
        if not approved and not dry_run:
            raise FixApprovalRequiredError(
                "Fix application requires explicit developer approval (approved=True)."
            )

        target_file = validate_contained_path(self.repo_root, fix.file_path)
        if not target_file or not target_file.is_file():
            return FixApplicationResult(
                success=False,
                file_path=fix.file_path,
                error_message=f"Target file '{fix.file_path}' does not exist or escapes repository root.",
            )

        original_text = target_file.read_text(encoding="utf-8", errors="ignore")
        lines = original_text.splitlines(keepends=True)

        start = max(1, fix.start_line)
        end = max(start, fix.end_line)

        # 1. Conflict detection: check original code if provided
        if fix.original_code and fix.original_code.strip():
            existing_target_snippet = "".join(lines[start - 1 : end]).strip()
            expected_snippet = fix.original_code.strip()
            # Normalize whitespace for comparison
            if "".join(existing_target_snippet.split()) != "".join(expected_snippet.split()):
                raise FixConflictError(
                    f"Target file content at {fix.file_path}:{start}-{end} has changed "
                    f"since finding generation. Expected '{expected_snippet[:40]}...', "
                    f"found '{existing_target_snippet[:40]}...'."
                )

        replacement_lines = [
            line + "\n" if not line.endswith("\n") else line
            for line in fix.replacement_code.splitlines()
        ]
        if not fix.replacement_code.strip():
            replacement_lines = []

        new_lines = lines[: start - 1] + replacement_lines + lines[end:]
        new_text = "".join(new_lines)

        diff = "".join(
            difflib.unified_diff(
                lines,
                new_lines,
                fromfile=f"a/{fix.file_path}",
                tofile=f"b/{fix.file_path}",
            )
        )

        # 2. Syntax validation for Python files
        if validate_syntax and target_file.suffix == ".py":
            try:
                ast.parse(new_text, filename=str(target_file))
            except SyntaxError as se:
                raise FixSyntaxValidationError(
                    f"Proposed fix for {fix.file_path} introduces syntax error: {se.msg} on line {se.lineno}"
                ) from se

        if dry_run:
            return FixApplicationResult(
                success=True,
                file_path=fix.file_path,
                diff=diff,
                applied_lines_range=(start, end),
            )

        # 3. Apply modification with optional backup
        backup_path: str | None = None
        if create_backup:
            backup_file = target_file.with_suffix(target_file.suffix + ".orig")
            backup_file.write_text(original_text, encoding="utf-8")
            backup_path = str(backup_file)

        try:
            target_file.write_text(new_text, encoding="utf-8")
        except Exception as e:
            # Rollback if backup exists
            if backup_path and Path(backup_path).exists():
                shutil.copyfile(backup_path, target_file)
            return FixApplicationResult(
                success=False,
                file_path=fix.file_path,
                error_message=f"Failed to write changes to {fix.file_path}: {e}",
            )

        return FixApplicationResult(
            success=True,
            file_path=fix.file_path,
            diff=diff,
            backup_path=backup_path,
            applied_lines_range=(start, end),
        )

    def apply_batch(
        self,
        fixes: list[ProposedFix],
        approved: bool = False,
        dry_run: bool = False,
    ) -> list[FixApplicationResult]:
        """Applies a batch of fixes sequentially, failing fast on conflicts."""
        results: list[FixApplicationResult] = []
        for fix in fixes:
            res = self.apply_fix(fix=fix, approved=approved, dry_run=dry_run)
            results.append(res)
            if not res.success:
                break
        return results

    def apply_in_temp_workspace(
        self,
        fixes: list[ProposedFix],
        target_dir: Path | None = None,
    ) -> Path:
        """Copies relevant files to an isolated temporary directory and applies fixes there."""
        temp_dir = target_dir or Path(tempfile.mkdtemp(prefix="logicfalcon_fix_workspace_"))

        for fix in fixes:
            src_file = validate_contained_path(self.repo_root, fix.file_path)
            if not src_file or not src_file.is_file():
                continue
            dest_file = temp_dir / fix.file_path
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src_file, dest_file)

        isolated_engine = ReviewFixEngine(repo_root=temp_dir)
        isolated_engine.apply_batch(fixes=fixes, approved=True, dry_run=False)
        return temp_dir

    def verify_remediation(
        self,
        fixes: list[ProposedFix],
        run_tests: bool = True,
        run_linters: bool = True,
        test_command: list[str] | None = None,
        lint_command: list[str] | None = None,
        target_dir: Path | None = None,
    ) -> RemediationVerificationResult:
        """Applies fixes in an isolated temporary workspace and executes syntax, linter, and test checks."""
        try:
            workspace = self.apply_in_temp_workspace(fixes=fixes, target_dir=target_dir)
        except (FixSyntaxValidationError, FixConflictError, Exception) as e:
            return RemediationVerificationResult(
                success=False,
                fixes_applied=0,
                syntax_valid=False,
                tests_passed=False,
                linters_passed=False,
                error_message=f"Remediation application failed: {e}",
            )

        # 1. Python AST syntax check on all modified Python files
        syntax_ok = True
        accumulated_diff: list[str] = []
        for fix in fixes:
            patched_file = workspace / fix.file_path
            if patched_file.is_file() and patched_file.suffix == ".py":
                try:
                    ast.parse(patched_file.read_text(encoding="utf-8", errors="ignore"))
                except SyntaxError as se:
                    syntax_ok = False
                    return RemediationVerificationResult(
                        success=False,
                        fixes_applied=len(fixes),
                        syntax_valid=False,
                        tests_passed=False,
                        linters_passed=False,
                        error_message=f"Syntax error after fix in {fix.file_path}: {se.msg} on line {se.lineno}",
                        workspace_path=str(workspace),
                    )
            if fix.diff_preview:
                accumulated_diff.append(fix.diff_preview)

        # 2. Static linter check if requested
        linter_ok = True
        linter_out = ""
        if run_linters and lint_command:
            try:
                res = subprocess.run(
                    lint_command,
                    cwd=str(workspace),
                    capture_output=True,
                    text=True,
                    timeout=30.0,
                    check=False,
                )
                linter_ok = res.returncode == 0
                linter_out = res.stdout + ("\n" + res.stderr if res.stderr else "")
            except (subprocess.SubprocessError, OSError) as e:
                linter_ok = False
                linter_out = f"Linter execution failure: {e}"

        # 3. Test suite check if requested
        tests_ok = True
        tests_out = ""
        if run_tests and test_command:
            try:
                res = subprocess.run(
                    test_command,
                    cwd=str(workspace),
                    capture_output=True,
                    text=True,
                    timeout=60.0,
                    check=False,
                )
                tests_ok = res.returncode == 0
                tests_out = res.stdout + ("\n" + res.stderr if res.stderr else "")
            except (subprocess.SubprocessError, OSError) as e:
                tests_ok = False
                tests_out = f"Test execution failure: {e}"

        overall_success = syntax_ok and tests_ok and linter_ok

        return RemediationVerificationResult(
            success=overall_success,
            fixes_applied=len(fixes),
            syntax_valid=syntax_ok,
            tests_passed=tests_ok,
            linters_passed=linter_ok,
            diff="\n".join(accumulated_diff),
            test_output=tests_out.strip(),
            linter_output=linter_out.strip(),
            workspace_path=str(workspace),
        )

