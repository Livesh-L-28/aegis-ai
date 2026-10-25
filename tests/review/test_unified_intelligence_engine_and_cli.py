"""Integration tests for Unified Engineering Intelligence engine and CLI."""

import json
import tempfile
from pathlib import Path

import pytest

from logicfalcon.cli import run_main, run_unified
from logicfalcon.sdk import analyze_unified
from packages.review.unified.engine import UnifiedIntelligenceEngine
from packages.review.unified.models import UnifiedIntelligenceReport


def test_unified_intelligence_engine_analysis_on_synthetic_fixture() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        (repo / "models.py").write_text("class User:\n    id: int\n", encoding="utf-8")
        (repo / "service.py").write_text("from models import User\ndef run():\n    return eval('2+2')\n", encoding="utf-8")
        (repo / "test_service.py").write_text("from service import run\ndef test_run():\n    assert run() == 4\n", encoding="utf-8")

        engine = UnifiedIntelligenceEngine(repo_root=repo)
        report = engine.analyze(explicit_files=["models.py", "service.py", "test_service.py"])

        assert isinstance(report, UnifiedIntelligenceReport)
        assert report.total_files >= 3
        assert report.review_findings_count >= 1  # eval() triggers SEC-001
        assert report.review_severity_counts.get("CRITICAL", 0) >= 1

        # Check recommendations
        rec_ids = {r.id for r in report.recommendations}
        assert "REC-SEC-SEC-001" in rec_ids

        # Check SDK function analyze_unified
        sdk_rep = analyze_unified(repo_root=repo, explicit_files=["models.py", "service.py"])
        assert isinstance(sdk_rep, UnifiedIntelligenceReport)

        # Check SDK json output
        json_str = analyze_unified(repo_root=repo, explicit_files=["models.py"], format_type="json")
        data = json.loads(json_str)
        assert "recommendations" in data
        assert "architecture_score" in data


def test_cli_unified_subcommand_execution(capsys: pytest.CaptureFixture[str]) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        (repo / "app.py").write_text("def ping(): return 'pong'\n", encoding="utf-8")

        # 1. Text format
        code = run_unified(["--repo", str(repo), "--format", "text"])
        assert code == 0
        out_text = capsys.readouterr().out
        assert "Unified Engineering Intelligence Report" in out_text
        assert "Core Engineering Metrics" in out_text

        # 2. JSON format
        code_json = run_unified(["--repo", str(repo), "--format", "json"])
        assert code_json == 0
        out_json = capsys.readouterr().out
        data = json.loads(out_json)
        assert "schema_version" in data
        assert data["schema_version"] == "1.0.0"

        # 3. Markdown output to file
        report_file = repo / "UNIFIED_REPORT.md"
        code_file = run_unified(["--repo", str(repo), "--format", "markdown", "--output-file", str(report_file)])
        assert code_file == 0
        capsys.readouterr()
        assert report_file.exists()
        md_content = report_file.read_text(encoding="utf-8")
        assert "# 🦅 LogicFalcon — Unified Engineering Intelligence Report" in md_content

        # 4. Root CLI dispatch
        code_root = run_main(["unified", "--repo", str(repo), "--format", "json"])
        assert code_root == 0
        root_data = json.loads(capsys.readouterr().out)
        assert "repository_path" in root_data
