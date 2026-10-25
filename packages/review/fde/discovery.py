"""Static deployment requirement discovery and inventory extraction for LogicFalcon FDE."""

import re
import tomllib
from pathlib import Path
from typing import ClassVar

from packages.review.fde.models import DeploymentInventory, DeploymentRequirement
from packages.review.security.path_validation import validate_contained_path


class DeploymentDiscoveryEngine:
    """Statically discovers application topography, deployment requirements, and runtime prerequisites."""

    EXCLUDED_DIRS: ClassVar[set[str]] = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        "dist",
        "build",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    }

    PROTECTED_FILENAMES: ClassVar[set[str]] = {
        "render_schema.json",
    }

    def __init__(self, repo_root: Path | str = ".") -> None:
        self.repo_root = Path(repo_root).resolve()

    def discover(self) -> DeploymentInventory:
        """Executes non-destructive static discovery across repository assets."""
        frameworks: set[str] = set()
        ports: set[int] = set()
        required_env_vars: set[str] = set()
        optional_env_vars: set[str] = set()
        database_types: set[str] = set()
        container_definitions: list[str] = []
        entry_points: list[str] = []
        runtime_versions: dict[str, str] = {}
        requirements: list[DeploymentRequirement] = []

        # 1. Discover configuration and project manifest files
        self._inspect_manifests(
            frameworks=frameworks,
            runtime_versions=runtime_versions,
            entry_points=entry_points,
            requirements=requirements,
        )

        # 2. Discover container and compose definitions
        self._inspect_containers(
            container_definitions=container_definitions,
            ports=ports,
            required_env_vars=required_env_vars,
            database_types=database_types,
            requirements=requirements,
        )

        # 3. Discover environment templates (.env.example, etc.)
        self._inspect_env_templates(
            required_env_vars=required_env_vars,
            optional_env_vars=optional_env_vars,
            requirements=requirements,
        )

        # 4. Discover source code patterns (routes, frameworks, db usage)
        self._inspect_source_code(
            frameworks=frameworks,
            database_types=database_types,
            required_env_vars=required_env_vars,
            entry_points=entry_points,
            requirements=requirements,
        )

        return DeploymentInventory(
            frameworks=sorted(frameworks),
            declared_ports=sorted(ports),
            required_env_vars=sorted(required_env_vars),
            optional_env_vars=sorted(optional_env_vars),
            database_types=sorted(database_types),
            container_definitions=sorted(container_definitions),
            entry_points=sorted(entry_points),
            runtime_versions=runtime_versions,
            requirements=requirements,
        )

    def _safe_walk(self) -> list[Path]:
        """Safely enumerates contained files excluding protected files and build directories."""
        discovered: list[Path] = []
        if not self.repo_root.is_dir():
            return discovered

        for path in self.repo_root.rglob("*"):
            if not path.is_file():
                continue

            # Check directory exclusions
            rel_parts = path.relative_to(self.repo_root).parts
            if any(part in self.EXCLUDED_DIRS for part in rel_parts[:-1]):
                continue

            # Strict protected path exclusion
            if path.name.lower() in self.PROTECTED_FILENAMES:
                continue

            # Strict path containment verification
            contained = validate_contained_path(self.repo_root, path.relative_to(self.repo_root))
            if contained:
                discovered.append(contained)

        return discovered

    def _inspect_manifests(
        self,
        frameworks: set[str],
        runtime_versions: dict[str, str],
        entry_points: list[str],
        requirements: list[DeploymentRequirement],
    ) -> None:
        pyproject_path = self.repo_root / "pyproject.toml"
        if pyproject_path.is_file() and pyproject_path.name not in self.PROTECTED_FILENAMES:
            try:
                content = pyproject_path.read_text(encoding="utf-8", errors="replace")
                data = tomllib.loads(content)
                proj = data.get("project", {})

                # Python runtime requirement
                req_python = proj.get("requires-python")
                if req_python:
                    runtime_versions["python"] = req_python
                    requirements.append(
                        DeploymentRequirement(
                            name="Python Runtime Requirement",
                            requirement_type="RUNTIME",
                            target=f"python {req_python}",
                            is_required=True,
                            source_file="pyproject.toml",
                            details={"version_spec": req_python},
                        )
                    )

                # Scripts entry points
                scripts = proj.get("scripts", {})
                for script_name, target in scripts.items():
                    entry_points.append(f"{script_name} -> {target}")

                # Dependencies
                deps = proj.get("dependencies", [])
                for dep in deps:
                    d_lower = dep.lower()
                    if "fastapi" in d_lower:
                        frameworks.add("FastAPI")
                    elif "flask" in d_lower:
                        frameworks.add("Flask")
                    elif "django" in d_lower:
                        frameworks.add("Django")
            except Exception:
                pass

        python_ver_file = self.repo_root / ".python-version"
        if python_ver_file.is_file():
            ver = python_ver_file.read_text(encoding="utf-8", errors="replace").strip()
            if ver:
                runtime_versions["python_pin"] = ver

    def _inspect_containers(
        self,
        container_definitions: list[str],
        ports: set[int],
        required_env_vars: set[str],
        database_types: set[str],
        requirements: list[DeploymentRequirement],
    ) -> None:
        # Dockerfiles
        dockerfile_names = ["Dockerfile", "dockerfile", "Containerfile"]
        for df_name in dockerfile_names:
            df_path = self.repo_root / df_name
            if df_path.is_file():
                rel_path = str(df_path.relative_to(self.repo_root))
                container_definitions.append(rel_path)
                try:
                    text = df_path.read_text(encoding="utf-8", errors="replace")
                    for match in re.finditer(r"^\s*EXPOSE\s+(\d+)", text, re.MULTILINE | re.IGNORECASE):
                        port_num = int(match.group(1))
                        ports.add(port_num)
                        requirements.append(
                            DeploymentRequirement(
                                name=f"Container Exposed Port {port_num}",
                                requirement_type="PORT",
                                target=str(port_num),
                                is_required=True,
                                source_file=rel_path,
                                details={"port": port_num, "source": "Dockerfile"},
                            )
                        )
                except Exception:
                    pass

        # Compose files
        compose_names = ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]
        for c_name in compose_names:
            c_path = self.repo_root / c_name
            if c_path.is_file():
                rel_path = str(c_path.relative_to(self.repo_root))
                container_definitions.append(rel_path)
                try:
                    text = c_path.read_text(encoding="utf-8", errors="replace")
                    # Match port mappings: "8000:8000" or - 5432:5432
                    for match in re.finditer(r"['\"]?(\d{2,5}):(\d{2,5})['\"]?", text):
                        host_port = int(match.group(1))
                        ports.add(host_port)
                        requirements.append(
                            DeploymentRequirement(
                                name=f"Docker Compose Host Port {host_port}",
                                requirement_type="PORT",
                                target=str(host_port),
                                is_required=True,
                                source_file=rel_path,
                                details={"host_port": host_port, "container_port": int(match.group(2))},
                            )
                        )

                    # Detect DB services in compose
                    if "postgres" in text.lower():
                        database_types.add("PostgreSQL")
                    if "redis" in text.lower():
                        database_types.add("Redis")
                    if "mysql" in text.lower():
                        database_types.add("MySQL")
                except Exception:
                    pass

    def _inspect_env_templates(
        self,
        required_env_vars: set[str],
        optional_env_vars: set[str],
        requirements: list[DeploymentRequirement],
    ) -> None:
        env_files = [".env.example", ".env.template", ".env.sample"]
        for env_name in env_files:
            env_path = self.repo_root / env_name
            if env_path.is_file():
                rel_path = str(env_path.relative_to(self.repo_root))
                try:
                    for line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            var_name = line.split("=", 1)[0].strip()
                            if var_name:
                                required_env_vars.add(var_name)
                                requirements.append(
                                    DeploymentRequirement(
                                        name=f"Environment Variable {var_name}",
                                        requirement_type="ENV_VAR",
                                        target=var_name,
                                        is_required=True,
                                        source_file=rel_path,
                                        details={"variable_name": var_name},
                                    )
                                )
                except Exception:
                    pass

    def _inspect_source_code(
        self,
        frameworks: set[str],
        database_types: set[str],
        required_env_vars: set[str],
        entry_points: list[str],
        requirements: list[DeploymentRequirement],
    ) -> None:
        files = self._safe_walk()
        for f in files:
            rel_str = str(f.relative_to(self.repo_root))
            if f.name in ("main.py", "app.py", "server.py", "wsgi.py", "asgi.py") and rel_str not in entry_points:
                entry_points.append(rel_str)

            # Check Python imports
            if f.suffix == ".py":
                try:
                    content = f.read_text(encoding="utf-8", errors="replace")[:100_000]
                    if "from fastapi import" in content or "import fastapi" in content:
                        frameworks.add("FastAPI")
                    if "from flask import" in content or "import flask" in content:
                        frameworks.add("Flask")

                    if "asyncpg" in content or "psycopg" in content or "postgresql://" in content:
                        database_types.add("PostgreSQL")
                    if "redis" in content or "REDIS_URL" in content:
                        database_types.add("Redis")
                    if "sqlite" in content or "aiosqlite" in content:
                        database_types.add("SQLite")

                    # Scan for os.environ.get("...") or os.getenv("...")
                    for match in re.finditer(r'os\.(?:environ\.get|getenv)\(["\']([A-Z0-9_]+)["\']', content):
                        var_name = match.group(1)
                        if var_name not in required_env_vars:
                            required_env_vars.add(var_name)
                except Exception:
                    pass
