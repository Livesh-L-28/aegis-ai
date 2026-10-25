"""Static dependency graph and affected test discovery for AEGIS AI Code Review."""

import json
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from packages.intelligence.code.indexer import (
    FileClassification,
    PythonASTParser,
    RepositoryIndexer,
    sanitize_source_content,
)
from packages.intelligence.code.ts_parser import JavaScriptTypeScriptParser
from packages.review.analyzer.ast_cache import ContentHashASTCache, global_ast_cache
from packages.review.domain.models import (
    AffectedArtifacts,
    BoundaryViolation,
    ChangedSymbol,
    CycleGroup,
    DependencyCycle,
    LayerDefinition,
    RuleException,
)
from packages.review.security.path_validation import validate_contained_path

SUPPORTED_PYTHON_EXT = (".py",)
SUPPORTED_TS_JS_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
ALL_SUPPORTED_EXT = SUPPORTED_PYTHON_EXT + SUPPORTED_TS_JS_EXT


class DependencyGraph:
    """Analyzes module import relationships to determine reverse dependencies and affected tests.

    Supports both Python and JavaScript/TypeScript files with conservative module resolution.
    Limitations:
    - Dynamic imports via importlib or __import__ are not statically discoverable.
    - Dynamic attribute access via getattr/setattr cannot be resolved statically.
    - Global pytest fixtures (e.g., conftest.py) affect tests without explicit imports.
    """

    def __init__(
        self,
        repo_root: str | Path,
        ast_cache: ContentHashASTCache | None = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.ast_cache = ast_cache or global_ast_cache
        self.indexer = RepositoryIndexer(self.repo_root)
        self._ts_parser = JavaScriptTypeScriptParser()
        # file_path -> list of imported module strings
        self.forward_imports: dict[str, list[str]] = {}
        # imported_module_or_file -> set of source file_paths that import it
        self.reverse_deps: dict[str, set[str]] = defaultdict(set)
        # module_name -> file_path
        self.module_to_file: dict[str, str] = {}
        # file_path -> module_name
        self.file_to_module: dict[str, str] = {}
        # internal module -> set of internal modules it imports
        self.internal_import_graph: dict[str, set[str]] = defaultdict(set)
        self.ts_base_url, self.ts_paths = self._load_tsconfig()

    def build_graph(self, files: list[str] | None = None) -> None:
        """Builds the import graph for the provided files or repository-wide python and JS/TS files."""
        target_files = files
        if target_files is None:
            indexed = self.indexer.index_repository()
            target_files = [f.path for f in indexed if f.language in ("python", "typescript", "javascript")]

        # First pass: map modules to files across Python and JS/TS
        for rel_path in target_files:
            clean_rel = rel_path.replace("\\", "/")
            ext_matched = None
            for ext in ALL_SUPPORTED_EXT:
                if clean_rel.endswith(ext):
                    ext_matched = ext
                    break
            if not ext_matched:
                continue

            base_no_ext = clean_rel[:-len(ext_matched)]
            mod_dot = base_no_ext.replace("/", ".")

            # Normalize index or __init__ module names
            if mod_dot.endswith(".__init__"):
                primary_mod = mod_dot[:-len(".__init__")]
            elif mod_dot.endswith(".index"):
                primary_mod = mod_dot[:-len(".index")]
                self.module_to_file[mod_dot] = rel_path
            else:
                primary_mod = mod_dot

            self.module_to_file[primary_mod] = rel_path
            self.file_to_module[rel_path] = primary_mod

        # Second pass: extract imports from each file
        for rel_path in target_files:
            is_py = rel_path.endswith(SUPPORTED_PYTHON_EXT)
            is_ts_js = rel_path.endswith(SUPPORTED_TS_JS_EXT)
            if not (is_py or is_ts_js):
                continue

            safe_path = validate_contained_path(self.repo_root, rel_path)
            if safe_path is None or not safe_path.is_file():
                continue

            try:
                content = safe_path.read_text(encoding="utf-8", errors="ignore")
                clean_content = sanitize_source_content(content)
                content_hash = self.ast_cache.compute_hash(clean_content)
                cached = self.ast_cache.get(rel_path, content_hash)
                if cached is not None:
                    _, imports = cached
                else:
                    if is_py:
                        symbols, imports = PythonASTParser.parse_source(rel_path, clean_content)
                    else:
                        ts_res = self._ts_parser.parse_source(rel_path, clean_content)
                        symbols = ts_res.symbols
                        imports = ts_res.dependencies
                    self.ast_cache.put(rel_path, content_hash, (symbols, imports))
            except OSError:
                continue

            source_mod = self.file_to_module.get(rel_path)
            imported_modules: list[str] = []
            for dep in imports:
                mod = dep.target_module
                imported_modules.append(mod)
                # Register reverse dependency
                self.reverse_deps[mod].add(rel_path)

                if is_py:
                    resolved_mod = self._resolve_internal_module(mod)
                else:
                    resolved_mod = self._resolve_ts_import(rel_path, mod)

                if resolved_mod:
                    target_file = self.module_to_file[resolved_mod]
                    self.reverse_deps[target_file].add(rel_path)
                    if source_mod and source_mod != resolved_mod:
                        self.internal_import_graph[source_mod].add(resolved_mod)
                elif mod in self.module_to_file:
                    target_file = self.module_to_file[mod]
                    self.reverse_deps[target_file].add(rel_path)
                    if source_mod and source_mod != mod:
                        self.internal_import_graph[source_mod].add(mod)

            self.forward_imports[rel_path] = imported_modules

    def _load_tsconfig(self) -> tuple[str, dict[str, list[str]]]:
        """Loads baseUrl and paths aliases from tsconfig.json or jsconfig.json conservatively."""
        for name in ("tsconfig.json", "jsconfig.json"):
            cfg = self.repo_root / name
            if cfg.is_file():
                try:
                    raw = cfg.read_text(encoding="utf-8")
                    clean = re.sub(r"//.*$", "", raw, flags=re.MULTILINE)
                    clean = re.sub(r"/\*.*?\*/", "", clean, flags=re.DOTALL)
                    data = json.loads(clean)
                    copts = data.get("compilerOptions", {})
                    base_url = str(copts.get("baseUrl", "")).replace("\\", "/").strip("./")
                    raw_paths = copts.get("paths", {})
                    paths: dict[str, list[str]] = {}
                    if isinstance(raw_paths, dict):
                        for k, v in raw_paths.items():
                            if isinstance(v, list):
                                paths[k] = [str(item).replace("\\", "/") for item in v]
                    return base_url, paths
                except Exception:
                    continue
        return "", {}

    def _match_file_candidate(self, candidate_path: str) -> str | None:
        """Checks candidate extensions and returns internal module if found."""
        norm = candidate_path.replace("\\", "/").lstrip("./")
        if norm in self.file_to_module:
            return self.file_to_module[norm]

        candidate_exts = (
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".mjs",
            ".cjs",
            "/index.ts",
            "/index.tsx",
            "/index.js",
            "/index.jsx",
        )
        for ext in candidate_exts:
            cand_file = f"{norm}{ext}"
            if cand_file in self.file_to_module:
                return self.file_to_module[cand_file]

        cand_mod = norm.replace("/", ".")
        if cand_mod in self.module_to_file:
            return cand_mod
        if f"{cand_mod}.index" in self.module_to_file:
            return cand_mod
        return None

    def _resolve_ts_import(self, source_file: str, import_target: str) -> str | None:
        """Conservatively resolves JS/TS relative imports, tsconfig baseUrl, and paths aliases."""
        clean_target = import_target.strip()

        # 1. Relative imports
        if clean_target.startswith((".", "/")):
            source_dir = Path(source_file).parent
            raw_target = (source_dir / clean_target).as_posix()
            norm_target = os.path.normpath(raw_target).replace("\\", "/")
            return self._match_file_candidate(norm_target)

        # 2. tsconfig paths aliases (sorted by most specific pattern first)
        if self.ts_paths:
            sorted_patterns = sorted(self.ts_paths.keys(), key=len, reverse=True)
            for pattern in sorted_patterns:
                target_replacements = self.ts_paths[pattern]
                if pattern.endswith("*"):
                    prefix = pattern[:-1]
                    if clean_target.startswith(prefix):
                        suffix = clean_target[len(prefix):]
                        for replacement in target_replacements:
                            cand = (
                                replacement[:-1] + suffix
                                if replacement.endswith("*")
                                else replacement
                            )
                            if self.ts_base_url:
                                cand = f"{self.ts_base_url}/{cand}"
                            matched = self._match_file_candidate(os.path.normpath(cand))
                            if matched:
                                return matched
                elif clean_target == pattern:
                    for replacement in target_replacements:
                        cand = replacement
                        if self.ts_base_url:
                            cand = f"{self.ts_base_url}/{cand}"
                        matched = self._match_file_candidate(os.path.normpath(cand))
                        if matched:
                            return matched

        # 3. tsconfig baseUrl lookup without alias
        if self.ts_base_url:
            cand = os.path.normpath(f"{self.ts_base_url}/{clean_target}")
            matched = self._match_file_candidate(cand)
            if matched:
                return matched

        # 4. Exact match in module_to_file
        if clean_target in self.module_to_file:
            return clean_target

        return None

    def _resolve_internal_module(self, module_name: str) -> str | None:
        """Resolves an import target to the closest known internal module path."""
        if module_name in self.module_to_file:
            return module_name
        # Check if a prefix matches an existing module
        parts = module_name.split(".")
        for i in range(len(parts) - 1, 0, -1):
            prefix = ".".join(parts[:i])
            if prefix in self.module_to_file:
                return prefix
        return None

    def find_cycles(self, max_cycle_length: int = 8) -> list[DependencyCycle]:
        """Detects circular dependency cycles between modules deterministically."""
        cycles: list[list[str]] = []
        visited_cycles: set[tuple[str, ...]] = set()

        nodes = sorted(self.internal_import_graph.keys())

        def dfs(start: str, current: str, path: list[str], visited_set: set[str]) -> None:
            if len(path) > max_cycle_length:
                return

            for neighbor in sorted(self.internal_import_graph.get(current, set())):
                if neighbor == start:
                    cycle = list(path)
                    if len(cycle) > 1:
                        min_idx = cycle.index(min(cycle))
                        normalized = tuple(cycle[min_idx:] + cycle[:min_idx])
                        if normalized not in visited_cycles:
                            visited_cycles.add(normalized)
                            cycles.append(list(normalized))
                elif neighbor not in visited_set and neighbor in self.internal_import_graph:
                    visited_set.add(neighbor)
                    path.append(neighbor)
                    dfs(start, neighbor, path, visited_set)
                    path.pop()
                    visited_set.remove(neighbor)

        for node in nodes:
            dfs(node, node, [node], {node})

        cycles.sort(key=lambda c: (len(c), c[0]))
        return [
            DependencyCycle(
                modules=c,
                length=len(c),
                display_path=" -> ".join([*c, c[0]]),
            )
            for c in cycles
        ]

    def get_module_coupling(self) -> dict[str, dict[str, Any]]:
        """Calculates afferent coupling (Ca), efferent coupling (Ce), and instability for each module.

        Mathematical Definitions (Robert C. Martin / Package Principles):
        - Afferent Coupling (Ca): Incoming dependencies. Number of internal repository modules
          that depend upon (import) this module. Measures responsibility / blast-radius.
        - Efferent Coupling (Ce): Outgoing dependencies. Number of internal repository modules
          that this module depends upon (imports). Measures dependency reliance.
        - Instability (I): I = Ce / (Ca + Ce).
          Range: [0.0, 1.0].
          - I = 0.0: Maximally stable (depended upon by others, does not depend on others).
          - I = 1.0: Maximally unstable (depends on others, no internal module depends on it).
          - Edge Case (Isolated Module): When Ca + Ce == 0, I is defined as 0.0 (stable/neutral).
        - Hotspot Detection (Heuristic):
          Flagged if Ce > 15 (high outbound coupling / god module) or Ca > 25 (high inbound blast radius).
        """
        results: dict[str, dict[str, Any]] = {}
        all_modules = set(self.module_to_file.keys())

        afferent_counts: dict[str, int] = defaultdict(int)
        for _src, targets in self.internal_import_graph.items():
            for tgt in targets:
                afferent_counts[tgt] += 1

        for mod in sorted(all_modules):
            ce = len(self.internal_import_graph.get(mod, set()))
            ca = afferent_counts[mod]
            instability = round(ce / (ca + ce), 3) if (ca + ce) > 0 else 0.0
            results[mod] = {
                "file_path": self.module_to_file.get(mod, ""),
                "afferent_coupling": ca,
                "efferent_coupling": ce,
                "instability": instability,
                "is_hotspot": ce > 15 or ca > 25,
            }

        return results

    def find_strongly_connected_components(self) -> list[CycleGroup]:
        """Identifies strongly connected components (SCCs) to group mutually entangled cycles in O(V + E)."""
        index = 0
        stack: list[str] = []
        on_stack: set[str] = set()
        indices: dict[str, int] = {}
        lowlinks: dict[str, int] = {}
        sccs: list[list[str]] = []

        nodes = sorted(self.internal_import_graph.keys())

        def strongconnect(v: str) -> None:
            nonlocal index
            indices[v] = index
            lowlinks[v] = index
            index += 1
            stack.append(v)
            on_stack.add(v)

            for w in sorted(self.internal_import_graph.get(v, set())):
                if w not in self.internal_import_graph:
                    continue
                if w not in indices:
                    strongconnect(w)
                    lowlinks[v] = min(lowlinks[v], lowlinks[w])
                elif w in on_stack:
                    lowlinks[v] = min(lowlinks[v], indices[w])

            if lowlinks[v] == indices[v]:
                scc: list[str] = []
                while True:
                    w = stack.pop()
                    on_stack.remove(w)
                    scc.append(w)
                    if w == v:
                        break
                # Only keep components with >1 node, or 1 node with a self-loop
                if len(scc) > 1 or (len(scc) == 1 and v in self.internal_import_graph.get(v, set())):
                    sccs.append(sorted(scc))

        for node in nodes:
            if node not in indices:
                strongconnect(node)

        # Deterministic sorting: largest components first, then alphabetical by first module
        sccs.sort(key=lambda s: (-len(s), s[0]))
        return [
            CycleGroup(
                id=f"SCC-{i+1:02d}",
                modules=scc,
                size=len(scc),
                cycle_count=len(scc),
            )
            for i, scc in enumerate(sccs)
        ]

    def find_shortest_dependency_path(self, start_mod: str, target_mod: str) -> list[str]:
        """Finds the shortest transitive dependency path between two modules using BFS."""
        if start_mod == target_mod:
            return [start_mod]

        from collections import deque

        queue = deque([(start_mod, [start_mod])])
        visited: set[str] = {start_mod}

        while queue:
            curr, path = queue.popleft()
            for neighbor in sorted(self.internal_import_graph.get(curr, set())):
                if neighbor == target_mod:
                    return [*path, target_mod]
                if neighbor not in visited and neighbor in self.internal_import_graph:
                    visited.add(neighbor)
                    queue.append((neighbor, [*path, neighbor]))

        return []

    def check_boundaries(
        self,
        rules: list[dict[str, Any]] | list[Any] | None = None,
        exceptions: list[RuleException] | None = None,
        layers: list[LayerDefinition] | None = None,
    ) -> list[BoundaryViolation]:
        """Validates internal dependencies against boundary rules, layer hierarchies, and exceptions."""
        from fnmatch import fnmatch

        violations: list[BoundaryViolation] = []
        raw_rules = rules or []
        ex_list = exceptions or []
        layer_list = layers or []

        # Helper: check if a violation is suppressed by an active exception
        def is_suppressed(src_mod: str, tgt_mod: str, r_name: str) -> tuple[bool, str | None]:
            for ex in ex_list:
                s_pat = ex.source_pattern
                t_pat = ex.target_pattern
                if fnmatch(src_mod, s_pat) and fnmatch(tgt_mod, t_pat):
                    if ex.rule_name and not fnmatch(r_name, ex.rule_name):
                        continue
                    if ex.is_expired():
                        # Expired exception: DO NOT suppress; return expiration notice
                        return False, f"Exception expired on {ex.expires_at} (Reason: {ex.reason})"
                    # Active exception: suppress!
                    return True, None
            return False, None

        # 1. Custom Boundary Rules
        for src, targets in sorted(self.internal_import_graph.items()):
            for tgt in sorted(targets):
                for rule_item in raw_rules:
                    if hasattr(rule_item, "model_dump"):
                        rule = rule_item.model_dump()
                    elif isinstance(rule_item, dict):
                        rule = rule_item
                    else:
                        continue

                    src_pat = str(rule.get("source_pattern") or "*")
                    forbidden_pat = str(rule.get("forbidden_pattern") or "")
                    rule_name = str(rule.get("name") or "boundary_violation")
                    base_desc = str(
                        rule.get("description")
                        or f"Module '{src}' is forbidden from importing '{tgt}'."
                    )

                    if fnmatch(src, src_pat) and fnmatch(tgt, forbidden_pat):
                        suppressed, exp_notice = is_suppressed(src, tgt, rule_name)
                        if suppressed:
                            continue

                        desc = f"{base_desc} [{exp_notice}]" if exp_notice else base_desc
                        path = self.find_shortest_dependency_path(src, tgt)
                        violations.append(
                            BoundaryViolation(
                                source_module=src,
                                source_file=self.module_to_file.get(src, ""),
                                target_module=tgt,
                                rule_name=rule_name,
                                description=desc,
                                dependency_path=path if path else [src, tgt],
                                rule_type="BOUNDARY",
                                is_transitive=len(path) > 2,
                            )
                        )

        # 2. Architectural Layer Hierarchy Checks
        if layer_list:
            def get_layer(mod_name: str) -> LayerDefinition | None:
                mod_file = self.module_to_file.get(mod_name, mod_name)
                for l_def in layer_list:
                    for pat in l_def.patterns:
                        if fnmatch(mod_name, pat) or fnmatch(mod_file, pat):
                            return l_def
                return None

            for src, targets in sorted(self.internal_import_graph.items()):
                src_layer = get_layer(src)
                if not src_layer:
                    continue

                for tgt in sorted(targets):
                    tgt_layer = get_layer(tgt)
                    if not tgt_layer or src_layer.name == tgt_layer.name:
                        continue

                    if tgt_layer.name not in src_layer.allowed_dependencies:
                        rule_name = f"layer_{src_layer.name}_to_{tgt_layer.name}"
                        suppressed, exp_notice = is_suppressed(src, tgt, rule_name)
                        if suppressed:
                            continue

                        base_desc = (
                            f"Layer violation: '{src}' (Layer: {src_layer.name}) is forbidden from depending on "
                            f"'{tgt}' (Layer: {tgt_layer.name}). Allowed dependencies: {src_layer.allowed_dependencies}."
                        )
                        desc = f"{base_desc} [{exp_notice}]" if exp_notice else base_desc
                        path = self.find_shortest_dependency_path(src, tgt)

                        violations.append(
                            BoundaryViolation(
                                source_module=src,
                                source_file=self.module_to_file.get(src, ""),
                                target_module=tgt,
                                rule_name=rule_name,
                                description=desc,
                                dependency_path=path if path else [src, tgt],
                                rule_type="LAYER_HIERARCHY",
                                is_transitive=len(path) > 2,
                            )
                        )

        return violations

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
