"""Regression tests for RES-01: Enforceable timeouts and hard process cleanup."""

import time

from packages.review.adapters.base import StaticAnalysisAdapter
from packages.review.adapters.runner import execute_adapter_with_enforceable_timeout


class DeliberatelyBlockingAdapter(StaticAnalysisAdapter):
    @property
    def name(self) -> str:
        return "deliberate_blocker"

    def is_available(self) -> bool:
        return True

    def analyze_file(self, file_path: str, content: str, options: dict | None = None) -> list:
        # Hang deliberately to simulate unbounded execution or regex backtracking
        time.sleep(60)
        return []


def test_blocking_adapter_enforceable_timeout_latency() -> None:
    adapter = DeliberatelyBlockingAdapter()
    timeout = 0.4
    t0 = time.perf_counter()

    findings = execute_adapter_with_enforceable_timeout(
        adapter=adapter,
        file_path="hung_file.py",
        content="val = 1",
        options={},
        timeout_seconds=timeout,
    )
    elapsed = time.perf_counter() - t0

    # Caller must return promptly near the timeout boundary, not after 60s
    assert elapsed < timeout + 0.6, f"Caller latency was too high: {elapsed}s"
    assert len(findings) == 1
    assert findings[0].rule_id == "TOOL-TIMEOUT"
    assert "forcefully terminated" in findings[0].message


def test_repeat_timeouts_without_resource_leak() -> None:
    adapter = DeliberatelyBlockingAdapter()
    timeout = 0.2

    for i in range(3):
        t0 = time.perf_counter()
        findings = execute_adapter_with_enforceable_timeout(
            adapter=adapter,
            file_path=f"hung_{i}.py",
            content="x = 1",
            options={},
            timeout_seconds=timeout,
        )
        elapsed = time.perf_counter() - t0
        assert elapsed < timeout + 0.6
        assert len(findings) == 1
        assert findings[0].rule_id == "TOOL-TIMEOUT"
