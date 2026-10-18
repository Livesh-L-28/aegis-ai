"""Static dependency graph and affected test discovery for AEGIS AI Code Review."""

from collections import defaultdict
from pathlib import Path

from packages.intelligence.code.indexer import (
    FileClassification,
    PythonASTParser,
    RepositoryIndexer,
    sanitize_source_content,
)
from packages.review.domain.models import AffectedArtifacts, ChangedSymbol
from packages.review.security.path_validation import validate_contained_path


class DependencyGraph:
    """Analyzes module import relationships to determine reverse dependencies and affected tests.

    Limitations:
    - Dynamic imports via importlib or __import__ are not statically discoverable.
    - Dynamic attribute access via getattr/setattr cannot be resolved statically.
    - Global pytest fixtures (e.g., conftest.py) affect tests without explicit imports.
    """

    def __init__(self, repo_root: str | Path) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.indexer = RepositoryIndexer(self.repo_root)
        # file_path -> list of imported module strings
        self.forward_imports: dict[str, list[str]] = {}
        # imported_module_or_file -> set of source file_paths that import it
        self.reverse_deps: dict[str, set[str]] = defaultdict(set)
        # module_name -> file_path
        self.module_to_file: dict[str, str] = {}
        # file_path -> module_name
        self.file_to_module: dict[str, str] = {}

    def build_graph(self, files: list[str] | None = None) -> None:
        """Builds the import graph for the provided files or repository-wide python files."""
        target_files = files
        if target_files is None:
            indexed = self.indexer.index_repository()
            target_files = [f.path for f in indexed if f.language == "python"]

        # First pass: map python modules to files
        for rel_path in target_files:
            if not rel_path.endswith(".py"):
                continue
            # Generate expected module dot path (e.g. packages/remediation/git.py -> packages.remediation.git)
            clean_rel = rel_path.removesuffix(".py").replace("/", ".")
            if clean_rel.endswith(".__init__"):
                clean_rel = clean_rel.removesuffix(".__init__")
            self.module_to_file[clean_rel] = rel_path
            self.file_to_module[rel_path] = clean_rel

        # Second pass: extract imports from each file
        for rel_path in target_files:
            if not rel_path.endswith(".py"):
                continue
            safe_path = validate_contained_path(self.repo_root, rel_path)
            if safe_path is None or not safe_path.is_file():
                continue

            try:
                content = safe_path.read_text(encoding="utf-8", errors="ignore")
                clean_content = sanitize_source_content(content)
                _, imports = PythonASTParser.parse_source(rel_path, clean_content)
            except OSError:
                continue

            imported_modules: list[str] = []
            for dep in imports:
                mod = dep.target_module
                imported_modules.append(mod)
                # Register reverse dependency
                self.reverse_deps[mod].add(rel_path)

                # If module resolves to a known file, also register under the file path
                if mod in self.module_to_file:
                    target_file = self.module_to_file[mod]
                    self.reverse_deps[target_file].add(rel_path)

            self.forward_imports[rel_path] = imported_modules

    def find_affected_artifacts(
        self,
        changed_symbols: list[ChangedSymbol],
        changed_files: list[str],
        max_transitive_depth: int = 3,
    ) -> AffectedArtifacts:
        """Determines reverse dependencies and affected tests for changed files."""
        warnings: list[str] = [
            "Dynamic imports (importlib/__import__) are not statically discoverable.",
            "Global fixtures in conftest.py may affect test suites without explicit imports.",
        ]

        affected_tests_set: set[str] = set()
        reverse_dependencies: dict[str, list[str]] = {}

        # Traverse reverse dependencies transitively up to max_depth
        for cf in changed_files:
            dependents: set[str] = set()
            frontier: set[str] = {cf}
            mod_name = self.file_to_module.get(cf)
            if mod_name:
                frontier.add(mod_name)

            for _ in range(max_transitive_depth):
                next_frontier: set[str] = set()
                for item in frontier:
                    direct_deps = self.reverse_deps.get(item, set())
                    for dep_file in direct_deps:
                        if dep_file not in dependents and dep_file not in changed_files:
                            dependents.add(dep_file)
                            next_frontier.add(dep_file)
                            dep_mod = self.file_to_module.get(dep_file)
                            if dep_mod:
                                next_frontier.add(dep_mod)
                frontier = next_frontier
                if not frontier:
                    break

            reverse_dependencies[cf] = sorted(dependents)

            # Check if any dependent is a test file, or if the changed file itself is a test
            for dep in dependents:
                if self.is_test_file(dep):
                    affected_tests_set.add(dep)
            if self.is_test_file(cf):
                affected_tests_set.add(cf)

        return AffectedArtifacts(
            changed_symbols=changed_symbols,
            affected_tests=sorted(affected_tests_set),
            reverse_dependencies=reverse_dependencies,
            discovery_warnings=warnings,
        )

    def is_test_file(self, file_path: str) -> bool:
        """Checks if a file is classified as a test file."""
        classification = self.indexer.classify_file(file_path)
        if classification == FileClassification.TEST:
            return True
        norm = file_path.lower()
        return "test_" in norm or norm.startswith("tests/") or norm.endswith("_test.py")
