"""Deterministic language and framework detection for LogicFalcon."""

from pathlib import Path

from packages.review.reverse_engineering.models import (
    DetectedFramework,
    DetectedLanguage,
    EvidenceProvenance,
)

EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py": "Python",
    ".pyi": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".rs": "Rust",
    ".go": "Go",
    ".java": "Java",
    ".kt": "Kotlin",
    ".c": "C",
    ".cpp": "C++",
    ".h": "C/C++ Header",
    ".hpp": "C++ Header",
    ".cs": "C#",
    ".rb": "Ruby",
    ".php": "PHP",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".sql": "SQL",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".md": "Markdown",
    ".html": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
}

FRAMEWORK_MANIFEST_SIGNATURES: dict[str, tuple[str, str]] = {
    # signature string (in requirements/pyproject/package.json) -> (Framework Name, Category)
    "fastapi": ("FastAPI", "web_api"),
    "flask": ("Flask", "web_api"),
    "django": ("Django", "web_api"),
    "starlette": ("Starlette", "web_api"),
    "tornado": ("Tornado", "web_api"),
    "pydantic": ("Pydantic", "data_validation"),
    "sqlalchemy": ("SQLAlchemy", "orm_database"),
    "alembic": ("Alembic", "database_migrations"),
    "celery": ("Celery", "task_worker"),
    "pytest": ("Pytest", "testing"),
    "click": ("Click", "cli"),
    "typer": ("Typer", "cli"),
    "httpx": ("HTTPX", "http_client"),
    "requests": ("Requests", "http_client"),
    "express": ("Express", "web_api"),
    "next": ("Next.js", "web_framework"),
    "react": ("React", "ui_library"),
    "nestjs": ("NestJS", "web_framework"),
    "vue": ("Vue.js", "ui_library"),
    "jest": ("Jest", "testing"),
    "vitest": ("Vitest", "testing"),
    "tailwindcss": ("Tailwind CSS", "styling"),
}


class LanguageDetector:
    """Discovers languages and frameworks with ground-truth evidence."""

    def __init__(self, repo_root: Path | str) -> None:
        self.repo_root = Path(repo_root).resolve()

    def detect_languages(self, discovered_files: list[Path]) -> list[DetectedLanguage]:
        """Calculates language breakdown from discovered files."""
        counts: dict[str, int] = {}
        extensions_map: dict[str, set[str]] = {}

        for file_path in discovered_files:
            ext = file_path.suffix.lower()
            lang = EXTENSION_TO_LANGUAGE.get(ext)
            if not lang:
                # Check extensionless files (e.g. Dockerfile)
                if file_path.name.lower() == "dockerfile":
                    lang = "Dockerfile"
                elif file_path.name.lower() == "makefile":
                    lang = "Makefile"
                else:
                    continue

            counts[lang] = counts.get(lang, 0) + 1
            if lang not in extensions_map:
                extensions_map[lang] = set()
            if ext:
                extensions_map[lang].add(ext)

        result: list[DetectedLanguage] = []
        for lang, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            primary_manifest: str | None = None
            if lang == "Python":
                if (self.repo_root / "pyproject.toml").exists():
                    primary_manifest = "pyproject.toml"
                elif (self.repo_root / "requirements.txt").exists():
                    primary_manifest = "requirements.txt"
            elif lang in ("TypeScript", "JavaScript"):
                if (self.repo_root / "package.json").exists():
                    primary_manifest = "package.json"
            elif lang == "Rust" and (self.repo_root / "Cargo.toml").exists():
                primary_manifest = "Cargo.toml"
            elif lang == "Go" and (self.repo_root / "go.mod").exists():
                primary_manifest = "go.mod"

            result.append(
                DetectedLanguage(
                    name=lang,
                    file_count=count,
                    extensions=sorted(extensions_map.get(lang, set())),
                    primary_manifest=primary_manifest,
                )
            )

        return result

    def detect_frameworks(
        self,
        manifest_files: list[str],
        discovered_files: list[Path],
    ) -> list[DetectedFramework]:
        """Detects frameworks from manifests and source imports."""
        detected: dict[str, DetectedFramework] = {}

        # 1. Inspect manifests (requirements.txt, pyproject.toml, package.json)
        for manifest_rel in manifest_files:
            manifest_path = self.repo_root / manifest_rel
            if not manifest_path.exists():
                continue

            try:
                content = manifest_path.read_text(encoding="utf-8", errors="replace").lower()
            except OSError:
                continue

            for sig, (name, category) in FRAMEWORK_MANIFEST_SIGNATURES.items():
                if sig in content:
                    if name not in detected:
                        detected[name] = DetectedFramework(
                            name=name,
                            category=category,
                            confidence=0.95,
                            evidence=[],
                        )
                    detected[name].evidence.append(
                        EvidenceProvenance(
                            file_path=manifest_rel,
                            code_snippet=f"Declared dependency matching '{sig}' in manifest.",
                            provenance_type="manifest",
                        )
                    )

        # 2. Inspect Docker and infra files
        for f in discovered_files:
            lower_name = f.name.lower()
            rel_str = str(f.relative_to(self.repo_root))
            if "docker" in lower_name:
                if "Docker" not in detected:
                    detected["Docker"] = DetectedFramework(
                        name="Docker",
                        category="infrastructure",
                        confidence=1.0,
                        evidence=[],
                    )
                detected["Docker"].evidence.append(
                    EvidenceProvenance(
                        file_path=rel_str,
                        code_snippet="Containerization configuration file.",
                        provenance_type="config",
                    )
                )

        return sorted(detected.values(), key=lambda x: x.name)
