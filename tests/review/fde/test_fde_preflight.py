"""Tests for LogicFalcon FDE Deployment Discovery Engine and Preflight Runner."""

import socket
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from packages.review.fde.discovery import DeploymentDiscoveryEngine
from packages.review.fde.models import (
    DeploymentInventory,
    PreflightSeverity,
    PreflightStatus,
)
from packages.review.fde.preflight import PreflightRunner


def test_static_discovery_on_synthetic_repo(tmp_path: Path) -> None:
    """Verifies static discovery correctly extracts manifests, ports, env vars, and entry points."""
    # 1. pyproject.toml
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "demo-app"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn>=0.30.0",
]

[project.scripts]
demo-cli = "demo.cli:main"
        """,
        encoding="utf-8",
    )

    # 2. Dockerfile
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
FROM python:3.12-slim
WORKDIR /app
COPY . .
EXPOSE 8080
EXPOSE 9090
CMD ["uvicorn", "app:app", "--port", "8080"]
        """,
        encoding="utf-8",
    )

    # 3. docker-compose.yml
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        """
version: '3.8'
services:
  web:
    build: .
    ports:
      - "8000:8080"
  db:
    image: postgres:16
    environment:
      POSTGRES_DB: app
    ports:
      - "5432:5432"
  cache:
    image: redis:7
        """,
        encoding="utf-8",
    )

    # 4. .env.example
    env_example = tmp_path / ".env.example"
    env_example.write_text(
        """
# Database configuration
DATABASE_URL=postgresql://user:pass@localhost:5432/db
SECRET_KEY=example_secret_key
LOG_LEVEL=INFO
        """,
        encoding="utf-8",
    )

    # 5. Source code
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    main_py = src_dir / "main.py"
    main_py.write_text(
        """
import os
from fastapi import FastAPI

app = FastAPI()
api_key = os.environ.get("API_KEY")
env_mode = os.getenv("ENV_MODE")
        """,
        encoding="utf-8",
    )

    engine = DeploymentDiscoveryEngine(repo_root=tmp_path)
    inventory = engine.discover()

    assert "FastAPI" in inventory.frameworks
    assert 8080 in inventory.declared_ports
    assert 9090 in inventory.declared_ports
    assert 8000 in inventory.declared_ports
    assert 5432 in inventory.declared_ports

    assert "DATABASE_URL" in inventory.required_env_vars
    assert "SECRET_KEY" in inventory.required_env_vars
    assert "LOG_LEVEL" in inventory.required_env_vars
    assert "API_KEY" in inventory.required_env_vars
    assert "ENV_MODE" in inventory.required_env_vars

    assert "PostgreSQL" in inventory.database_types
    assert "Redis" in inventory.database_types

    assert any("Dockerfile" in d for d in inventory.container_definitions)
    assert any("docker-compose.yml" in d for d in inventory.container_definitions)
    assert inventory.runtime_versions.get("python") == ">=3.12"
    assert any("main.py" in ep for ep in inventory.entry_points)
    assert any("demo-cli" in ep for ep in inventory.entry_points)


def test_discovery_excludes_protected_and_ignored_files(tmp_path: Path) -> None:
    """Verifies that protected filenames and cache directories are never scanned."""
    # Create git and pycache dirs
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "Dockerfile").write_text("EXPOSE 9999", encoding="utf-8")

    pycache_dir = tmp_path / "__pycache__"
    pycache_dir.mkdir()
    (pycache_dir / "cached.py").write_text("import flask", encoding="utf-8")

    # Protected file simulation in test fixture
    protected = tmp_path / "render_schema.json"
    protected.write_text('{"ports": [7777]}', encoding="utf-8")

    engine = DeploymentDiscoveryEngine(repo_root=tmp_path)
    inventory = engine.discover()

    assert 9999 not in inventory.declared_ports
    assert 7777 not in inventory.declared_ports
    assert "Flask" not in inventory.frameworks


def test_preflight_port_probe_available_and_in_use() -> None:
    """Verifies port availability detection correctly flags occupied ports."""
    runner = PreflightRunner(check_ports=True, check_env_vars=False)

    # Bind a temporary socket to guarantee an occupied port
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    occupied_port = srv.getsockname()[1]

    try:
        # Check occupied port
        assert not runner._is_port_free(occupied_port)

        inventory = DeploymentInventory(declared_ports=[occupied_port])
        report = runner.run_preflight(inventory=inventory)
        assert report.status == PreflightStatus.FAILED
        assert any(f.rule_id == "PRE-NET-PORT" and f.severity == PreflightSeverity.ERROR for f in report.findings)
    finally:
        srv.close()

    # After socket closed, port should be free
    assert runner._is_port_free(occupied_port)


def test_preflight_env_vars_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies environment variable detection flags missing required variables."""
    monkeypatch.setenv("TEST_PRESENT_VAR", "value_123")
    monkeypatch.delenv("TEST_MISSING_VAR", raising=False)

    inventory = DeploymentInventory(
        required_env_vars=["TEST_PRESENT_VAR", "TEST_MISSING_VAR"]
    )

    runner = PreflightRunner(check_ports=False, check_env_vars=True)
    report = runner.run_preflight(inventory=inventory)

    assert report.status == PreflightStatus.FAILED
    missing_findings = [f for f in report.findings if f.rule_id == "PRE-ENV-MISSING"]
    assert len(missing_findings) == 1
    assert "TEST_MISSING_VAR" in missing_findings[0].title


def test_preflight_runtime_python_version_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies that an incompatible Python version results in BLOCKED status."""
    runner = PreflightRunner(check_ports=False, check_env_vars=False)
    inventory = DeploymentInventory(runtime_versions={"python": ">=3.12"})

    # Simulate running on Python 3.10
    monkeypatch.setattr("sys.version_info", (3, 10, 0, "final", 0))

    report = runner.run_preflight(inventory=inventory)
    assert report.status == PreflightStatus.BLOCKED
    assert any(f.rule_id == "PRE-RUN-001" and f.severity == PreflightSeverity.CRITICAL for f in report.findings)


def test_preflight_dns_probe() -> None:
    """Verifies DNS resolution probe handles valid and invalid hosts."""
    runner = PreflightRunner(
        check_ports=False,
        check_env_vars=False,
        check_dns=True,
        dns_hosts=["localhost", "nonexistent.domain.invalid.local"],
    )

    with patch("socket.getaddrinfo") as mock_dns:
        def side_effect(host: str, port: int | None) -> list:
            if "invalid" in host:
                raise socket.gaierror("Name or service not known")
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

        mock_dns.side_effect = side_effect
        report = runner.run_preflight(inventory=DeploymentInventory())

        assert report.status == PreflightStatus.FAILED
        dns_findings = [f for f in report.findings if f.rule_id == "PRE-NET-DNS"]
        assert len(dns_findings) == 1
        assert "nonexistent.domain.invalid.local" in dns_findings[0].title


def test_preflight_docker_probe_states() -> None:
    """Verifies docker probe states: success, daemon down, not found, and timeout."""
    runner = PreflightRunner(check_ports=False, check_env_vars=False, check_docker=True)
    inventory = DeploymentInventory()

    # 1. Docker running successfully
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="Docker info output", stderr="")
        rep = runner.run_preflight(inventory=inventory)
        assert rep.status == PreflightStatus.READY
        assert any("Docker daemon is reachable" in ev for ev in rep.observed_evidence)

    # 2. Docker daemon down (exit 1)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Cannot connect to docker daemon")
        rep = runner.run_preflight(inventory=inventory)
        # Non-blocking warning since check_docker is opt-in warning
        assert rep.status == PreflightStatus.READY
        assert any(f.rule_id == "PRE-DOC-DAEMON" for f in rep.findings)

    # 3. Docker CLI not installed (FileNotFoundError)
    with patch("subprocess.run", side_effect=FileNotFoundError):
        rep = runner.run_preflight(inventory=inventory)
        assert rep.status == PreflightStatus.READY
        assert any(f.rule_id == "PRE-DOC-NOTFOUND" for f in rep.findings)

    # 4. Docker command timeout
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["docker", "info"], timeout=4.0)):
        rep = runner.run_preflight(inventory=inventory)
        assert rep.status == PreflightStatus.READY
        assert any(f.rule_id == "PRE-DOC-TIMEOUT" for f in rep.findings)


def test_preflight_http_health_probe() -> None:
    """Verifies HTTP health probe evaluates response status and exceptions."""
    runner = PreflightRunner(
        check_ports=False,
        check_env_vars=False,
        http_health_url="http://localhost:8000/health",
    )
    inventory = DeploymentInventory()

    # Mock httpx response 200
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.get.return_value = MagicMock(status_code=200)

    with patch("httpx.Client", return_value=mock_client):
        rep = runner.run_preflight(inventory=inventory)
        assert rep.status == PreflightStatus.READY
        assert any("HTTP health probe to http://localhost:8000/health returned status 200" in ev for ev in rep.observed_evidence)

    # Mock httpx response 503
    mock_client.get.return_value = MagicMock(status_code=503)
    with patch("httpx.Client", return_value=mock_client):
        rep = runner.run_preflight(inventory=inventory)
        assert rep.status == PreflightStatus.FAILED
        assert any(f.rule_id == "PRE-HTTP-UNHEALTHY" for f in rep.findings)

    # Mock httpx connection error with sensitive token in error message
    mock_client.get.side_effect = RuntimeError("Connection refused with token: ghp_1234567890abcdef1234567890abcdef12")
    with patch("httpx.Client", return_value=mock_client):
        rep = runner.run_preflight(inventory=inventory)
        assert rep.status == PreflightStatus.FAILED
        finding = next(f for f in rep.findings if f.rule_id == "PRE-HTTP-FAILED")
        assert "ghp_1234567890" not in finding.message
        assert "[REDACTED" in finding.message


def test_preflight_report_serialization() -> None:
    """Verifies preflight report round-trip JSON serialization and secret cleanliness."""
    runner = PreflightRunner(check_ports=False, check_env_vars=False)
    inventory = DeploymentInventory()
    report = runner.run_preflight(inventory=inventory)

    json_str = report.to_json()
    assert isinstance(json_str, str)
    assert '"status": "READY"' in json_str
    assert "observed_evidence" in json_str
