"""Enforceable subprocess runner for static code review adapters."""

import contextlib
import importlib
import json
import os
import signal
import subprocess
import sys
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


def execute_adapter_with_enforceable_timeout(
    adapter: StaticAnalysisAdapter,
    file_path: str,
    content: str,
    options: dict[str, Any],
    timeout_seconds: float,
) -> list[ReviewFinding]:
    """Executes a static analysis adapter within an enforceable subprocess boundary.

    Enforcement mechanism:
    1. Subprocess-native adapters (like Ruff) handle internal process cleanup directly.
    2. Pure AST analyzers (in-process, non-blocking) execute directly.
    3. Potentially blocking or custom analyzers execute inside a dedicated subprocess with start_new_session=True.
    4. If execution exceeds timeout_seconds, the entire process group is terminated via SIGKILL,
       preventing orphaned thread accumulation or blocked calling processes.
    5. Promptly returns a TOOL-TIMEOUT finding.
    """
    # 1. Native subprocess adapters (e.g. Ruff) manage subprocess.run timeouts directly
    if getattr(adapter, "is_subprocess_isolated", False):
        try:
            return adapter.analyze_file(file_path, content, options)
        except Exception as e:
            return [
                ReviewFinding(
                    rule_id="TOOL-ERROR",
                    title="Adapter Error",
                    message=f"Adapter '{adapter.name}' failed on '{file_path}': {e}",
                    severity=FindingSeverity.WARNING,
                    category=FindingCategory.RELIABILITY,
                    origin=FindingOrigin.STATIC_ANALYSIS,
                    location=SourceLocation(file_path=file_path, start_line=1),
                    tool_name=adapter.name,
                    confidence=1.0,
                )
            ]

    # 2. Known pure, non-blocking in-process AST analyzers
    if getattr(adapter, "is_pure_ast_analyzer", False):
        try:
            return adapter.analyze_file(file_path, content, options)
        except Exception as e:
            return [
                ReviewFinding(
                    rule_id="TOOL-ERROR",
                    title="Adapter Error",
                    message=f"Adapter '{adapter.name}' failed on '{file_path}': {e}",
                    severity=FindingSeverity.WARNING,
                    category=FindingCategory.RELIABILITY,
                    origin=FindingOrigin.STATIC_ANALYSIS,
                    location=SourceLocation(file_path=file_path, start_line=1),
                    tool_name=adapter.name,
                    confidence=1.0,
                )
            ]

    # 3. Subprocess execution boundary for potentially blocking or custom adapters
    module_name = adapter.__class__.__module__
    class_name = adapter.__class__.__name__

    safe_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(Path.cwd()),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
    }

    cmd = [
        sys.executable,
        "-m",
        "packages.review.adapters.runner",
        module_name,
        class_name,
        file_path,
        json.dumps(options),
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=safe_env,
            start_new_session=True,
        )
        stdout_bytes, stderr_bytes = proc.communicate(
            input=content.encode("utf-8"),
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        # Hard process group kill - terminate and kill entire process tree
        with contextlib.suppress(Exception):
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        proc.kill()
        proc.wait()

        return [
            ReviewFinding(
                rule_id="TOOL-TIMEOUT",
                title="Analysis Timeout",
                message=(
                    f"Adapter '{adapter.name}' exceeded timeout of {timeout_seconds}s "
                    f"on '{file_path}' and was forcefully terminated."
                ),
                severity=FindingSeverity.WARNING,
                category=FindingCategory.RELIABILITY,
                origin=FindingOrigin.STATIC_ANALYSIS,
                location=SourceLocation(file_path=file_path, start_line=1),
                tool_name=adapter.name,
                confidence=1.0,
            )
        ]
    except Exception as e:
        return [
            ReviewFinding(
                rule_id="TOOL-ERROR",
                title="Adapter Spawn Error",
                message=f"Failed to spawn adapter '{adapter.name}': {e}",
                severity=FindingSeverity.WARNING,
                category=FindingCategory.RELIABILITY,
                origin=FindingOrigin.STATIC_ANALYSIS,
                location=SourceLocation(file_path=file_path, start_line=1),
                tool_name=adapter.name,
                confidence=1.0,
            )
        ]

    if proc.returncode != 0:
        err_msg = stderr_bytes.decode("utf-8", errors="ignore").strip() or "Subprocess exited with non-zero code"
        return [
            ReviewFinding(
                rule_id="TOOL-ERROR",
                title="Adapter Error",
                message=f"Adapter '{adapter.name}' failed on '{file_path}': {err_msg}",
                severity=FindingSeverity.WARNING,
                category=FindingCategory.RELIABILITY,
                origin=FindingOrigin.STATIC_ANALYSIS,
                location=SourceLocation(file_path=file_path, start_line=1),
                tool_name=adapter.name,
                confidence=1.0,
            )
        ]

    try:
        raw_output = stdout_bytes.decode("utf-8").strip()
        if not raw_output:
            return []
        data = json.loads(raw_output)
        return [ReviewFinding.model_validate(item) for item in data]
    except Exception as e:
        return [
            ReviewFinding(
                rule_id="TOOL-ERROR",
                title="Adapter Output Error",
                message=f"Failed to parse adapter output from '{adapter.name}': {e}",
                severity=FindingSeverity.WARNING,
                category=FindingCategory.RELIABILITY,
                origin=FindingOrigin.STATIC_ANALYSIS,
                location=SourceLocation(file_path=file_path, start_line=1),
                tool_name=adapter.name,
                confidence=1.0,
            )
        ]


def main() -> None:
    """CLI entrypoint executed inside the isolated subprocess."""
    if len(sys.argv) < 5:
        sys.stderr.write("Usage: python -m packages.review.adapters.runner <module> <class> <file_path> <options_json>" + chr(10))
        sys.exit(1)

    module_name = sys.argv[1]
    class_name = sys.argv[2]
    file_path = sys.argv[3]
    options_json = sys.argv[4]

    try:
        options = json.loads(options_json)
    except Exception:
        options = {}

    content = sys.stdin.read()

    try:
        mod = importlib.import_module(module_name)
        adapter_cls = getattr(mod, class_name)
        adapter: StaticAnalysisAdapter = adapter_cls()
        findings = adapter.analyze_file(file_path, content, options)
        serialized = [f.model_dump(mode="json") for f in findings]
        sys.stdout.write(json.dumps(serialized))
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(f"{type(e).__name__}: {e}" + chr(10))
        sys.exit(1)


if __name__ == "__main__":
    main()
