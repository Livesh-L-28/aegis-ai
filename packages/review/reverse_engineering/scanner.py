"""Safe, bounded repository reconnaissance scanner for LogicFalcon.

Traverses repository files safely, enforcing size limits, path containment,
and ignore patterns. Discovers languages, manifests, configs, entry points,
and environment variable references without executing repository code.
"""

import ast
import os
import re
import time
from pathlib import Path

from packages.review.adapters.ast_security import redact_secrets_in_text
from packages.review.reverse_engineering.models import (
    AnalysisLimitation,
    EntryPoint,
    EntryPointType,
    EnvironmentVariable,
    EvidenceProvenance,
    RepositoryInventory,
)
from packages.review.security.path_validation import validate_contained_path

DEFAULT_IGNORE_DIRS: set[str] = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "env",
    ".env",
    "__pycache__",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    "coverage",
    ".idea",
    ".vscode",
    "vendor",
    ".eggs",
}

MANIFEST_FILENAMES: set[str] = {
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
}

LOCK_FILENAMES: set[str] = {
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "go.sum",
}

CONFIG_FILENAMES: set[str] = {
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "tsconfig.json",
    "alembic.ini",
    ".env.example",
    ".env.sample",
    ".env.template",
    "Makefile",
}


class RepositoryScanner:
    """Safe, read-only repository explorer for reverse engineering intelligence."""

    def __init__(
        self,
        repo_root: Path | str,
        max_file_size_bytes: int = 1_000_000,
        max_depth: int = 15,
        max_files: int = 10_000,
        timeout_seconds: float = 60.0,
        exclude_dirs: set[str] | None = None,
        respect_default_ignores: bool = True,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.max_file_size_bytes = max_file_size_bytes
        self.max_depth = max_depth
        self.max_files = max_files
        self.timeout_seconds = timeout_seconds
        self.exclude_dirs = set(exclude_dirs) if exclude_dirs else set()
        if respect_default_ignores:
            self.exclude_dirs.update(DEFAULT_IGNORE_DIRS)

        self.limitations: list[AnalysisLimitation] = []
        self.discovered_files: list[Path] = []
        self.manifest_files: list[str] = []
        self.lock_files: list[str] = []
        self.config_files: list[str] = []
        self.test_files: list[str] = []
        self.entry_points: list[EntryPoint] = []
        self.env_variables: dict[str, EnvironmentVariable] = {}
        self.total_lines_of_code: int = 0

    def scan(self) -> RepositoryInventory:
        """Performs bounded filesystem walk and extracts repository inventory."""
        self.limitations.clear()
        self.discovered_files.clear()
        self.manifest_files.clear()
        self.lock_files.clear()
        self.config_files.clear()
        self.test_files.clear()
        self.entry_points.clear()
        self.env_variables.clear()
        self.total_lines_of_code = 0

        if not self.repo_root.exists() or not self.repo_root.is_dir():
            self.limitations.append(
                AnalysisLimitation(
                    category="invalid_repository_path",
                    file_path=str(self.repo_root),
                    description="Repository root path does not exist or is not a directory.",
                )
            )
            return RepositoryInventory()

        self._walk_and_catalog()
        self._inspect_manifest_entry_points()

        return RepositoryInventory(
            total_files=len(self.discovered_files),
            total_lines_of_code=self.total_lines_of_code,
            manifest_files=sorted(self.manifest_files),
            lock_files=sorted(self.lock_files),
            config_files=sorted(self.config_files),
            test_files=sorted(self.test_files),
            entry_points=self.entry_points,
            env_variables=list(self.env_variables.values()),
        )

    def _walk_and_catalog(self) -> None:
        """Walks repository enforcing ignore rules, depth bounds, symlink loops, and path safety."""
        start_time = time.monotonic()
        visited_real_dirs: set[str] = set()

        for root, dirs, files in os.walk(self.repo_root, followlinks=False):
            if time.monotonic() - start_time > self.timeout_seconds:
                self.limitations.append(
                    AnalysisLimitation(
                        category="timeout",
                        file_path="global",
                        description=f"Scanning reached configured timeout budget of {self.timeout_seconds}s.",
                    )
                )
                dirs.clear()
                break

            root_path = Path(root)
            try:
                rel_root = str(root_path.relative_to(self.repo_root))
            except ValueError:
                rel_root = root

            # Symlink loop / cycle defense
            try:
                real_root = str(root_path.resolve())
                if real_root in visited_real_dirs:
                    self.limitations.append(
                        AnalysisLimitation(
                            category="symlink_cycle",
                            file_path=rel_root,
                            description=f"Duplicate path or symlink loop detected: {rel_root}",
                        )
                    )
                    dirs.clear()
                    continue
                visited_real_dirs.add(real_root)
            except OSError:
                pass

            # Directory depth limit
            depth = len(root_path.relative_to(self.repo_root).parts) if root_path != self.repo_root else 0
            if depth > self.max_depth:
                self.limitations.append(
                    AnalysisLimitation(
                        category="max_depth_exceeded",
                        file_path=rel_root,
                        description=f"Directory depth ({depth}) exceeds limit of {self.max_depth}. Skipping subtree.",
                    )
                )
                dirs.clear()
                continue

            # In-place filter directories to avoid descending into ignored subtrees
            dirs[:] = [
                d
                for d in dirs
                if d not in self.exclude_dirs
                and not d.endswith(".egg-info")
                and not (d.startswith(".") and d != ".")
            ]

            for file_name in files:
                if len(self.discovered_files) >= self.max_files:
                    self.limitations.append(
                        AnalysisLimitation(
                            category="max_files_exceeded",
                            file_path="global",
                            description=f"Maximum scanned file limit ({self.max_files}) reached.",
                        )
                    )
                    dirs.clear()
                    return

                file_path = root_path / file_name
                try:
                    rel_path_str = str(file_path.relative_to(self.repo_root))
                except ValueError:
                    continue

                # Path traversal / symlink check
                contained = validate_contained_path(self.repo_root, rel_path_str)
                if not contained:
                    self.limitations.append(
                        AnalysisLimitation(
                            category="symlink_escaping_boundary",
                            file_path=rel_path_str,
                            description=f"File {rel_path_str} escapes repository boundary.",
                        )
                    )
                    continue

                # File classification
                lower_name = file_name.lower()
                if lower_name in MANIFEST_FILENAMES or file_name in MANIFEST_FILENAMES:
                    self.manifest_files.append(rel_path_str)
                elif lower_name in LOCK_FILENAMES or file_name in LOCK_FILENAMES:
                    self.lock_files.append(rel_path_str)
                elif lower_name in CONFIG_FILENAMES or file_name in CONFIG_FILENAMES:
                    self.config_files.append(rel_path_str)

                # Test file classification
                if self._is_test_file(rel_path_str):
                    self.test_files.append(rel_path_str)

                # Size constraint check - check BEFORE reading!
                try:
                    stat_res = file_path.stat()
                    if stat_res.st_size > self.max_file_size_bytes:
                        self.limitations.append(
                            AnalysisLimitation(
                                category="oversized_file",
                                file_path=rel_path_str,
                                description=(
                                    f"File size ({stat_res.st_size} bytes) exceeds maximum configured limit "
                                    f"({self.max_file_size_bytes} bytes). Content skipped."
                                ),
                            )
                        )
                        continue
                except OSError as os_err:
                    self.limitations.append(
                        AnalysisLimitation(
                            category="unreadable_file",
                            file_path=rel_path_str,
                            description=f"Unable to stat file {rel_path_str}: {os_err}",
                        )
                    )
                    continue

                self.discovered_files.append(file_path)

                # Read source to count lines and inspect entry points/env vars
                if self._is_analyzable_source(file_path):
                    self._inspect_file_content(file_path, rel_path_str)

    def _is_test_file(self, rel_path: str) -> bool:
        lower = rel_path.lower()
        parts = lower.split(os.sep)
        if any(p in ("tests", "test", "spec", "__tests__") for p in parts):
            return True
        filename = parts[-1]
        return (
            filename.startswith("test_")
            or filename.endswith("_test.py")
            or filename.endswith(".test.ts")
            or filename.endswith(".spec.ts")
            or filename.endswith(".test.js")
            or filename.endswith(".spec.js")
        )

    def _is_analyzable_source(self, path: Path) -> bool:
        ext = path.suffix.lower()
        lower_name = path.name.lower()
        if lower_name in (".env.example", ".env.sample", ".env.template") or lower_name.startswith(".env."):
            return True
        return ext in (".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".toml", ".yaml", ".yml")


    def _inspect_file_content(self, file_path: Path, rel_path: str) -> None:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            self.limitations.append(
                AnalysisLimitation(
                    category="unreadable_file",
                    file_path=rel_path,
                    description=f"Failed to read file: {e}",
                )
            )
            return

        lines = content.splitlines()
        self.total_lines_of_code += len(lines)

        ext = file_path.suffix.lower()
        if ext == ".py":
            self._scan_python_ast(content, rel_path)
        elif ext in (".js", ".ts", ".jsx", ".tsx"):
            self._scan_js_ts_text(content, rel_path)
        elif file_path.name.lower() in (".env.example", ".env.template", ".env.sample"):
            self._scan_env_example(content, rel_path)

    def _scan_python_ast(self, content: str, rel_path: str) -> None:
        try:
            tree = ast.parse(content, filename=rel_path)
        except SyntaxError as e:
            self.limitations.append(
                AnalysisLimitation(
                    category="malformed_syntax",
                    file_path=rel_path,
                    line_number=e.lineno,
                    description=f"Python syntax error: {e.msg}",
                )
            )
            return

        # Check for if __name__ == '__main__':
        for node in tree.body:
            if isinstance(node, ast.If):
                test = node.test
                if (
                    isinstance(test, ast.Compare)
                    and isinstance(test.left, ast.Name)
                    and test.left.id == "__name__"
                    and any(
                        isinstance(c, ast.Constant) and c.value == "__main__"
                        for c in test.comparators
                    )
                ):
                    self.entry_points.append(
                        EntryPoint(
                            name=f"{Path(rel_path).stem}-script",
                            entry_type=EntryPointType.SCRIPT,
                            file_path=rel_path,
                            symbol_name="__main__",
                            description="Executes as script via __main__ block.",
                            evidence=EvidenceProvenance(
                                file_path=rel_path,
                                line_number=node.lineno,
                                code_snippet="if __name__ == '__main__': ...",
                            ),
                        )
                    )

        # Walk AST for os.environ / os.getenv
        for walk_node in ast.walk(tree):
            env_var_name: str | None = None
            default_val: str | None = None
            lineno = getattr(walk_node, "lineno", 1)

            # os.environ.get("VAR", default) or os.getenv("VAR", default)
            if (
                isinstance(walk_node, ast.Call)
                and isinstance(walk_node.func, ast.Attribute)
                and walk_node.func.attr == "getenv"
                and isinstance(walk_node.func.value, ast.Name)
                and walk_node.func.value.id == "os"
                and walk_node.args
                and isinstance(walk_node.args[0], ast.Constant)
                and isinstance(walk_node.args[0].value, str)
            ) or (
                isinstance(walk_node, ast.Call)
                and isinstance(walk_node.func, ast.Attribute)
                and walk_node.func.attr == "get"
                and isinstance(walk_node.func.value, ast.Attribute)
                and walk_node.func.value.attr == "environ"
                and isinstance(walk_node.func.value.value, ast.Name)
                and walk_node.func.value.value.id == "os"
                and walk_node.args
                and isinstance(walk_node.args[0], ast.Constant)
                and isinstance(walk_node.args[0].value, str)
            ):
                env_var_name = walk_node.args[0].value
                if len(walk_node.args) > 1 and isinstance(walk_node.args[1], ast.Constant):
                    default_val = str(walk_node.args[1].value)

            # os.environ["VAR"]
            elif (
                isinstance(walk_node, ast.Subscript)
                and isinstance(walk_node.value, ast.Attribute)
                and walk_node.value.attr == "environ"
                and isinstance(walk_node.value.value, ast.Name)
                and walk_node.value.value.id == "os"
                and isinstance(walk_node.slice, ast.Constant)
                and isinstance(walk_node.slice.value, str)
            ):
                env_var_name = walk_node.slice.value


            if env_var_name:
                cleaned_name = env_var_name.strip()
                if cleaned_name:
                    safe_default = None
                    if default_val:
                        lower_k = cleaned_name.lower()
                        if any(s in lower_k for s in ("secret", "token", "key", "password", "auth", "cred", "private")):
                            safe_default = "[REDACTED_SECRET]"
                        else:
                            safe_default = redact_secrets_in_text(default_val)
                    if cleaned_name not in self.env_variables:
                        self.env_variables[cleaned_name] = EnvironmentVariable(
                            name=cleaned_name,
                            default_value=safe_default,
                            evidence=[],
                        )
                    self.env_variables[cleaned_name].evidence.append(
                        EvidenceProvenance(
                            file_path=rel_path,
                            line_number=lineno,
                            code_snippet=f"os.getenv('{cleaned_name}')",
                        )
                    )

    def _scan_js_ts_text(self, content: str, rel_path: str) -> None:
        # Match process.env.VAR_NAME or process.env["VAR_NAME"]
        env_pattern = re.compile(r"process\.env(?:\.([A-Za-z0-9_]+)|\[['\"]([A-Za-z0-9_]+)['\"]\])")
        for line_no, line in enumerate(content.splitlines(), start=1):
            for match in env_pattern.finditer(line):
                var_name = match.group(1) or match.group(2)
                if var_name:
                    cleaned = var_name.strip()
                    if cleaned not in self.env_variables:
                        self.env_variables[cleaned] = EnvironmentVariable(
                            name=cleaned,
                            default_value=None,
                            evidence=[],
                        )
                    self.env_variables[cleaned].evidence.append(
                        EvidenceProvenance(
                            file_path=rel_path,
                            line_number=line_no,
                            code_snippet=redact_secrets_in_text(line.strip()[:80]),
                            provenance_type="static_regex",
                        )
                    )

    def _scan_env_example(self, content: str, rel_path: str) -> None:
        for line_no, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key = stripped.split("=")[0].strip()
                if key and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
                    if key not in self.env_variables:
                        self.env_variables[key] = EnvironmentVariable(
                            name=key,
                            default_value=None,
                            evidence=[],
                        )
                    self.env_variables[key].evidence.append(
                        EvidenceProvenance(
                            file_path=rel_path,
                            line_number=line_no,
                            code_snippet=f"{key}=",
                            provenance_type="config",
                        )
                    )

    def _inspect_manifest_entry_points(self) -> None:
        """Discovers CLI commands declared in pyproject.toml and package.json."""
        # 1. pyproject.toml
        pyproject_path = self.repo_root / "pyproject.toml"
        if pyproject_path.exists():
            try:
                import tomllib
                data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
                project = data.get("project", {})
                scripts = project.get("scripts", {})
                for cmd_name, target in scripts.items():
                    symbol = ""
                    target_file = "pyproject.toml"
                    if ":" in target:
                        mod, symbol = target.split(":", 1)
                        cand = mod.replace(".", "/") + ".py"
                        cand_init = mod.replace(".", "/") + "/__init__.py"
                        if (self.repo_root / cand).is_file():
                            target_file = cand
                        elif (self.repo_root / cand_init).is_file():
                            target_file = cand_init
                    self.entry_points.append(
                        EntryPoint(
                            name=cmd_name,
                            entry_type=EntryPointType.CLI,
                            file_path=target_file,
                            symbol_name=symbol or target,
                            command=cmd_name,
                            description=f"CLI console script pointing to {target}",
                            evidence=EvidenceProvenance(
                                file_path="pyproject.toml",
                                code_snippet=f"{cmd_name} = '{target}'",
                                provenance_type="manifest",
                            ),
                        )
                    )
            except Exception as e:
                self.limitations.append(
                    AnalysisLimitation(
                        category="manifest_parse_error",
                        file_path="pyproject.toml",
                        description=f"Failed to parse pyproject.toml: {e}",
                    )
                )

        # 2. package.json
        pkg_json_path = self.repo_root / "package.json"
        if pkg_json_path.exists():
            try:
                import json
                data = json.loads(pkg_json_path.read_text(encoding="utf-8"))
                bin_data = data.get("bin", {})
                if isinstance(bin_data, str):
                    clean_bin = bin_data.lstrip("./")
                    target_file = clean_bin if (self.repo_root / clean_bin).is_file() else "package.json"
                    self.entry_points.append(
                        EntryPoint(
                            name=data.get("name", "cli"),
                            entry_type=EntryPointType.CLI,
                            file_path=target_file,
                            command=data.get("name", "cli"),
                            description=f"Node.js executable bin: {bin_data}",
                            evidence=EvidenceProvenance(
                                file_path="package.json",
                                code_snippet=f'"bin": "{bin_data}"',
                                provenance_type="manifest",
                            ),
                        )
                    )
                elif isinstance(bin_data, dict):
                    for cmd_name, raw_target in bin_data.items():
                        clean_bin = raw_target.lstrip("./")
                        target_file = clean_bin if (self.repo_root / clean_bin).is_file() else "package.json"
                        self.entry_points.append(
                            EntryPoint(
                                name=cmd_name,
                                entry_type=EntryPointType.CLI,
                                file_path=target_file,
                                command=cmd_name,
                                description=f"Node.js bin pointing to {raw_target}",
                                evidence=EvidenceProvenance(
                                    file_path="package.json",
                                    code_snippet=f'"{cmd_name}": "{raw_target}"',
                                    provenance_type="manifest",
                                ),
                            )
                        )
            except Exception as e:
                self.limitations.append(
                    AnalysisLimitation(
                        category="manifest_parse_error",
                        file_path="package.json",
                        description=f"Failed to parse package.json: {e}",
                    )
                )
