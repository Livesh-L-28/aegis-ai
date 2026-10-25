"""Integration tests for Historical Intelligence SDK and CLI execution."""

import json
import tempfile
from pathlib import Path

import pytest

from logicfalcon.cli import run_history, run_main
from logicfalcon.sdk import (
    analyze_trends,
    capture_snapshot,
    compare_snapshots,
    estimate_debt,
    evaluate_history_policy,
    list_snapshots,
)


def test_engine_capture_snapshot_and_sdk_workflows() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        (repo / "app.py").write_text("def hello():\n    eval('2+2')\n", encoding="utf-8")
        (repo / "service.py").write_text("from app import hello\ndef run():\n    hello()\n", encoding="utf-8")

        db_path = repo / "history.db"

        # 1. Capture snapshot via SDK
        snap1 = capture_snapshot(
            repo_root=repo,
            revision="rev-001",
            git_state="clean",
            db_path=db_path,
        )
        assert snap1.metrics.file_count == 2
        assert len(snap1.findings) >= 1  # Should find eval() SEC-001
        assert snap1.findings[0].rule_id == "SEC-001"

        # 2. List snapshots via SDK
        summaries = list_snapshots(repo_root=repo, db_path=db_path)
        assert len(summaries) == 1
        assert summaries[0].revision == "rev-001"

        # 3. Modify repository: resolve eval
        (repo / "app.py").write_text("def hello():\n    return 4\n", encoding="utf-8")
        snap2 = capture_snapshot(
            repo_root=repo,
            revision="rev-002",
            git_state="clean",
            db_path=db_path,
        )
        assert len(snap2.findings) == 0

        # 4. Compare snapshots via SDK
        comp = compare_snapshots(
            from_id_or_rev="rev-001",
            to_id_or_rev="rev-002",
            repo_root=repo,
            db_path=db_path,
        )
        assert len(comp.resolved_findings) >= 1
        assert len(comp.new_findings) == 0
        assert comp.health_score_delta >= 0

        # 5. Analyze trends via SDK
        trends = analyze_trends(repo_root=repo, db_path=db_path)
        assert trends.sample_count == 2

        # 6. Estimate debt via SDK
        debt = estimate_debt(repo_root=repo, db_path=db_path, snapshot_id="rev-001")
        assert debt.total_points > 0

        # 7. Evaluate policy gate via SDK
        policy_res = evaluate_history_policy(
            repo_root=repo,
            db_path=db_path,
            from_id_or_rev="rev-001",
            to_id_or_rev="rev-002",
        )
        assert policy_res.passed is True
        assert policy_res.suggested_exit_code == 0


def test_cli_history_subcommands_execution(capsys: pytest.CaptureFixture[str]) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        (repo / "mod.py").write_text("def ping(): pass\n", encoding="utf-8")
        db_file = str(repo / "test.db")

        # 1. CLI: history snapshot
        code_snap = run_history(["snapshot", "--repo", str(repo), "--revision", "c1", "--db", db_file])
        assert code_snap == 0
        out_snap = capsys.readouterr().out
        assert "Repository Health Snapshot" in out_snap

        # 2. CLI: history list
        code_list = run_history(["list", "--repo", str(repo), "--db", db_file])
        assert code_list == 0
        out_list = capsys.readouterr().out
        assert "Historical Snapshots" in out_list

        # Add second revision
        (repo / "mod.py").write_text("def ping(): eval('bad')\n", encoding="utf-8")
        run_history(["snapshot", "--repo", str(repo), "--revision", "c2", "--db", db_file])
        capsys.readouterr()

        # 3. CLI: history compare
        code_comp = run_history(["compare", "--from", "c1", "--to", "c2", "--repo", str(repo), "--db", db_file])
        assert code_comp == 0
        out_comp = capsys.readouterr().out
        assert "Revision Health Comparison" in out_comp

        # 4. CLI: history trends
        code_trends = run_history(["trends", "--repo", str(repo), "--db", db_file])
        assert code_trends == 0
        out_trends = capsys.readouterr().out
        assert "Longitudinal Engineering Trends" in out_trends

        # 5. CLI: history debt
        code_debt = run_history(["debt", "--repo", str(repo), "--db", db_file])
        assert code_debt == 0
        out_debt = capsys.readouterr().out
        assert "Technical Debt Assessment" in out_debt

        # 6. CLI: history policy gate (should fail because c2 introduced eval() CRITICAL)
        code_pol = run_history(["policy", "--from", "c1", "--to", "c2", "--repo", str(repo), "--db", db_file])
        assert code_pol == 1  # Exit code 1 for blocking failure!
        out_pol = capsys.readouterr().out
        assert "FAILED (BLOCKING)" in out_pol

        # 7. CLI: history prune
        code_prune = run_history(["prune", "--keep", "1", "--repo", str(repo), "--db", db_file])
        assert code_prune == 0
        out_prune = capsys.readouterr().out
        assert "Successfully pruned 1 historical snapshot(s)" in out_prune


def test_cli_root_dispatch_to_history(capsys: pytest.CaptureFixture[str]) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        db_file = str(repo / "test.db")
        code = run_main(["history", "snapshot", "--repo", str(repo), "--db", db_file, "--format", "json"])
        assert code == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "metadata" in data
        assert "metrics" in data
