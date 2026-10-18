"""Subprocess-based Ruff static analysis adapter with process isolation and timeout enforcement."""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from packages.review.adapters.base import StaticAnalysisAdapter
from packages.review.domain.models import (
    FindingCategory,
    FindingOrigin,
    FindingSeverity,
    ReviewFinding,
    SourceLocation,
)


class RuffAnalysisAdapter(StaticAnalysisAdapter):
    """Executes Ruff in a bounded, read-only subprocess with strict timeouts and environment scrubbing.

    is_subprocess_isolated: bool = True

    Mandatory Safeguard:
    Execution is DISABLED by default. It will only run if options['enabled'] is True.
    """

    def __init__(self, ruff_path: str | None = None, default_timeout_seconds: float = 5.0) -> None:
        self._custom_path = ruff_path
        self.default_timeout_seconds = default_timeout_seconds

    @property
    def name(self) -> str:
        return "ruff"

    def _resolve_executable(self) -> str | None:
        if self._custom_path and Path(self._custom_path).is_file():
            return self._custom_path
        # Check standard venv binary
        venv_ruff = Path(".venv/bin/ruff").resolve()
        if venv_ruff.is_file():
            return str(venv_ruff)
        # Check system PATH
        return shutil.which("ruff")

    def is_available(self) -> bool:
        return self._resolve_executable() is not None

    def analyze_file(
        self,
        file_path: str,
        content: str,
        options: dict[str, Any] | None = None,
    ) -> list[ReviewFinding]:
        opts = options or {}
        # Safeguard: External tool execution must be explicitly enabled
        if not opts.get("enabled", False):
            return []

        if not file_path.endswith(".py"):
            return []

        executable = self._resolve_executable()
        if not executable:
            return []

        timeout = float(opts.get("timeout_seconds", self.default_timeout_seconds))

        # Build clean environment without sensitive credentials
        safe_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "LANG": "en_US.UTF-8",
            "LC_ALL": "en_US.UTF-8",
        }

        cmd = [
            executable,
            "check",
            "--output-format",
            "json",
            "--no-fix",
            "--stdin-filename",
            file_path,
            "-",
        ]

        try:
            result = subprocess.run(
                cmd,
                input=content.encode("utf-8"),
                capture_output=True,
                env=safe_env,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return [
                ReviewFinding(
                    rule_id="TOOL-TIMEOUT",
                    title="Ruff Execution Timeout",
                    message=f"Ruff execution timed out after {timeout} seconds on {file_path}.",
                    severity=FindingSeverity.WARNING,
                    category=FindingCategory.RELIABILITY,
                    origin=FindingOrigin.STATIC_ANALYSIS,
                    location=SourceLocation(file_path=file_path, start_line=1),
                    tool_name=self.name,
                    confidence=1.0,
                )
            ]
        except (OSError, PermissionError) as e:
            return [
                ReviewFinding(
                    rule_id="TOOL-EXEC-ERROR",
                    title="Ruff Execution Failure",
                    message=f"Failed to execute Ruff subprocess safely: {e}",
                    severity=FindingSeverity.WARNING,
                    category=FindingCategory.RELIABILITY,
                    origin=FindingOrigin.STATIC_ANALYSIS,
                    location=SourceLocation(file_path=file_path, start_line=1),
                    tool_name=self.name,
                    confidence=1.0,
                )
            ]

        if not result.stdout:
            return []

        try:
            records = json.loads(result.stdout.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []

        findings: list[ReviewFinding] = []
        for rec in records:
            rule_code = rec.get("code", "RUFF")
            message = rec.get("message", "Lint violation")
            location_info = rec.get("location", {})
            end_location = rec.get("end_location", {})

            start_line = location_info.get("row", 1)
            start_col = location_info.get("column", 1)
            end_line = end_location.get("row", start_line)
            end_col = end_location.get("column", start_col)

            severity = FindingSeverity.WARNING
            if rule_code.startswith("E9") or rule_code.startswith("F8"):
                severity = FindingSeverity.ERROR

            findings.append(
                ReviewFinding(
                    rule_id=f"RUFF-{rule_code}",
                    title=f"Ruff {rule_code}",
                    message=message,
                    severity=severity,
                    category=FindingCategory.QUALITY,
                    origin=FindingOrigin.STATIC_ANALYSIS,
                    location=SourceLocation(
                        file_path=file_path,
                        start_line=start_line,
                        end_line=end_line,
                        start_column=start_col,
                        end_column=end_col,
                    ),
                    tool_name=self.name,
                    confidence=1.0,
                )
            )

        return findings
