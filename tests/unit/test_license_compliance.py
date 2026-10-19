"""Unit tests for Apache-2.0 license implementation and repository compliance."""

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_license_file_exists() -> None:
    license_file = REPO_ROOT / "LICENSE"
    assert license_file.exists(), "Root LICENSE file must exist"
    content = license_file.read_text(encoding="utf-8")
    assert "Apache License" in content
    assert "Version 2.0, January 2004" in content
    assert "http://www.apache.org/licenses/" in content
    assert "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION" in content
    assert "Copyright 2026 LogicFalcon Authors & Contributors (powered by AEGIS AI)" in content


def test_contributing_guide_exists() -> None:
    contributing_file = REPO_ROOT / "CONTRIBUTING.md"
    assert contributing_file.exists(), "CONTRIBUTING.md must exist"
    content = contributing_file.read_text(encoding="utf-8")
    assert "Apache License 2.0" in content
    assert "No Copyright Transfer" in content
    assert "Trademark Notice" in content


def test_pyproject_toml_license_metadata() -> None:
    pyproject_file = REPO_ROOT / "pyproject.toml"
    assert pyproject_file.exists()
    data = tomllib.loads(pyproject_file.read_text(encoding="utf-8"))

    project = data.get("project", {})
    assert project.get("license", {}).get("text") == "Apache-2.0"

    classifiers = project.get("classifiers", [])
    assert "License :: OSI Approved :: Apache Software License" in classifiers


def test_readme_license_section() -> None:
    readme_file = REPO_ROOT / "README.md"
    assert readme_file.exists()
    content = readme_file.read_text(encoding="utf-8")
    assert "Apache License, Version 2.0" in content
    assert "Trademarks" in content
