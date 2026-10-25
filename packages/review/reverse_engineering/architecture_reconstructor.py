"""Architecture reconstruction and modularity decomposition for LogicFalcon."""

import os
from pathlib import Path
from typing import Any

from packages.review.analyzer.dependency_graph import DependencyGraph
from packages.review.reverse_engineering.models import (
    ArchitectureComponent,
    ComponentLayer,
)

LAYER_KEYWORD_MAP: list[tuple[list[str], ComponentLayer]] = [
    (["api", "routes", "endpoints", "interfaces", "controllers", "views"], ComponentLayer.PRESENTATION_API),
    (["service", "services", "workflows", "orchestration", "engine", "use_cases"], ComponentLayer.APPLICATION_SERVICE),
    (["domain", "models", "entities", "core", "schema", "schemas"], ComponentLayer.DOMAIN_CORE),
    (["adapter", "adapters", "infra", "infrastructure", "db", "repositories", "clients"], ComponentLayer.INFRASTRUCTURE_ADAPTER),
    (["common", "utils", "util", "helpers", "config", "logging", "shared"], ComponentLayer.COMMON_UTILITY),
    (["tests", "test", "spec", "__tests__"], ComponentLayer.TESTING),
]


class ArchitectureReconstructor:
    """Reconstructs high-level components and layers from repository dependencies."""

    def __init__(self, repo_root: Path | str) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.graph = DependencyGraph(self.repo_root)

    def reconstruct(self, discovered_files: list[Path]) -> tuple[list[ArchitectureComponent], list[dict[str, Any]]]:
        """Decomposes repository into typed components with coupling metrics and cycle groups."""
        rel_files = [
            str(f.relative_to(self.repo_root))
            for f in discovered_files
            if f.is_relative_to(self.repo_root) and f.suffix.lower() in (".py", ".ts", ".js", ".tsx", ".jsx")
        ]

        # Build internal dependency graph
        self.graph.build_graph(files=rel_files)

        # 1. Group files by top-level component prefix (e.g. "packages/review", "apps/api", "logicfalcon")
        component_files: dict[str, list[str]] = {}
        for rf in rel_files:
            prefix = self._determine_component_prefix(rf)
            component_files.setdefault(prefix, []).append(rf)

        # 2. Extract cycle groups using Tarjan SCC from DependencyGraph
        cycle_groups_raw = self.graph.find_strongly_connected_components()
        cycle_groups: list[dict[str, Any]] = [
            cg.model_dump() for cg in cycle_groups_raw
        ]


        # 3. Compute component metrics and layer classification
        components: list[ArchitectureComponent] = []
        for prefix, files in sorted(component_files.items()):
            layer = self._classify_layer(prefix)

            # Calculate outgoing and incoming dependencies across component boundaries
            outgoing_deps: set[str] = set()
            incoming_deps: set[str] = set()

            for f in files:
                f_deps = self.graph.internal_import_graph.get(f, set())
                for dep in f_deps:
                    dep_prefix = self._determine_component_prefix(dep)
                    if dep_prefix != prefix:
                        outgoing_deps.add(dep_prefix)

                f_rev = self.graph.reverse_deps.get(f, set())
                for rev in f_rev:
                    rev_prefix = self._determine_component_prefix(rev)
                    if rev_prefix != prefix:
                        incoming_deps.add(rev_prefix)

            ce = len(outgoing_deps)
            ca = len(incoming_deps)
            instability = ce / (ca + ce) if (ca + ce) > 0 else 0.0
            is_hotspot = ce > 10 and ca > 15

            components.append(
                ArchitectureComponent(
                    name=prefix.replace(os.sep, "."),
                    layer=layer,
                    module_prefix=prefix,
                    file_count=len(files),
                    outgoing_dependencies=sorted(outgoing_deps),
                    incoming_dependencies=sorted(incoming_deps),
                    instability=round(instability, 3),
                    is_hotspot=is_hotspot,
                )
            )

        return components, cycle_groups

    def _determine_component_prefix(self, rel_path: str) -> str:
        parts = rel_path.split(os.sep)
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        elif len(parts) == 1:
            return parts[0]
        return "root"

    def _classify_layer(self, prefix: str) -> ComponentLayer:
        lower = prefix.lower()
        for keywords, layer in LAYER_KEYWORD_MAP:
            if any(kw in lower for kw in keywords):
                return layer
        return ComponentLayer.UNKNOWN
