"""Dependency-aware impact propagator across modules, symbols, entry points, and layers."""

from collections import deque
from pathlib import Path
from typing import Any

from packages.review.analyzer.dependency_graph import DependencyGraph
from packages.review.impact.models import (
    ChangeSet,
    ConfidenceCategory,
    ImpactAnalysisLimitation,
    ImpactedEntity,
    ImpactEvidence,
    ImpactType,
)
from packages.review.reverse_engineering.models import ReverseEngineeringReport


class ImpactPropagator:
    """Propagates change impact transitively through dependency graphs, call graphs, and architecture layers."""

    def __init__(
        self,
        repo_root: str | Path,
        dependency_graph: DependencyGraph,
        re_report: ReverseEngineeringReport | None = None,
        max_depth: int = 5,
        max_entities: int = 500,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.dep_graph = dependency_graph
        self.re_report = re_report
        self.max_depth = max_depth
        self.max_entities = max_entities

    def propagate(self, change_set: ChangeSet) -> tuple[list[ImpactedEntity], list[ImpactAnalysisLimitation]]:
        """Traverses reverse dependencies starting from changed files and symbols."""
        limitations: list[ImpactAnalysisLimitation] = []
        seeds = self._extract_seeds(change_set)

        if not seeds:
            return [], limitations

        # Ensure dependency graph is populated
        if not self.dep_graph.reverse_deps and not self.dep_graph.forward_imports:
            self.dep_graph.build_graph()

        # Build lookup tables from Reverse Engineering Intelligence
        routes_by_file: dict[str, list[dict]] = {}
        models_by_file: dict[str, list[dict]] = {}
        entry_points_by_file: dict[str, list[str]] = {}
        prefix_to_comp: dict[str, Any] = {}

        if self.re_report:
            for r in self.re_report.api_inventory.routes:
                routes_by_file.setdefault(r.file_path, []).append({
                    "method": r.method.value,
                    "path": r.path,
                    "handler": r.handler_name,
                    "auth_detected": r.auth_detected,
                })
            for m in self.re_report.data_model_inventory.models:
                models_by_file.setdefault(m.file_path, []).append({
                    "name": m.name,
                    "model_type": m.model_type,
                    "fields_count": len(m.fields),
                })
            for ep in self.re_report.inventory.entry_points:
                entry_points_by_file.setdefault(ep.file_path, []).append(ep.name)
            for comp in self.re_report.architecture_components:
                prefix_to_comp[comp.module_prefix] = comp

        changed_symbol_names = {cs.symbol.name for cs in change_set.changed_symbols}

        # BFS Queue: (current_node, shortest_path, depth)
        # Node can be file path or module name
        queue: deque[tuple[str, list[str], int]] = deque()
        visited: dict[str, int] = {}  # file_path -> min_depth_seen
        impacted_map: dict[str, ImpactedEntity] = {}

        for seed in seeds:
            queue.append((seed, [seed], 0))
            visited[seed] = 0

        entities_count = 0
        limit_reached = False

        while queue:
            curr_item, path, depth = queue.popleft()

            if depth >= self.max_depth:
                continue

            # Resolve direct dependents (from file path or module name)
            dependents = set(self.dep_graph.reverse_deps.get(curr_item, set()))
            curr_mod = self.dep_graph.file_to_module.get(curr_item)
            if curr_mod:
                dependents.update(self.dep_graph.reverse_deps.get(curr_mod, set()))

            for dep in sorted(dependents):
                # Resolve dep to relative file path if it's a module
                dep_file = self.dep_graph.module_to_file.get(dep, dep)

                # Skip if self-dependency or already seen at shallower depth
                new_depth = depth + 1
                if dep_file in seeds:
                    continue

                if dep_file in visited and visited[dep_file] <= new_depth:
                    continue

                visited[dep_file] = new_depth
                new_path = [*path, dep_file]

                if entities_count >= self.max_entities:
                    if not limit_reached:
                        limitations.append(
                            ImpactAnalysisLimitation(
                                category="entity_limit_exceeded",
                                file_path=dep_file,
                                description=f"Propagation halted: entity limit ({self.max_entities}) exceeded.",
                            )
                        )
                        limit_reached = True
                    break

                entities_count += 1

                # Determine impact type & confidence
                if new_depth == 1:
                    rel_type = ImpactType.DIRECT_DEPENDENCY
                    confidence = ConfidenceCategory.HIGH
                else:
                    rel_type = ImpactType.TRANSITIVE_DEPENDENCY
                    confidence = ConfidenceCategory.MEDIUM

                reasons: list[str] = [
                    f"Directly imports '{path[-1]}'" if new_depth == 1
                    else f"Transitively depends on '{seeds[0]}' via path of depth {new_depth}"
                ]

                # Evidence record
                evidence = ImpactEvidence(
                    source_entity=path[0],
                    target_entity=dep_file,
                    relationship_type=rel_type,
                    confidence=confidence,
                    depth=new_depth,
                    shortest_path=new_path,
                    evidence_snippet=f"Import path: {' -> '.join(new_path)}",
                )

                # Architecture component & layer
                comp_name = None
                layer_name = None
                for prefix, comp in prefix_to_comp.items():
                    if dep_file.startswith(prefix):
                        comp_name = comp.name
                        layer_name = comp.layer.value
                        break

                # Cross-layer detection
                if layer_name and path[0]:
                    seed_layer = None
                    for prefix, comp in prefix_to_comp.items():
                        if path[0].startswith(prefix):
                            seed_layer = comp.layer.value
                            break
                    if seed_layer and seed_layer != layer_name:
                        reasons.append(f"Crosses architectural boundary from '{seed_layer}' to '{layer_name}'")

                # Correlate routes, models, entry points
                assoc_routes = routes_by_file.get(dep_file, [])
                if assoc_routes:
                    reasons.append(f"Affects {len(assoc_routes)} public API route(s)")
                assoc_models = models_by_file.get(dep_file, [])
                if assoc_models:
                    reasons.append(f"Contains {len(assoc_models)} core data model(s)")
                affected_eps = entry_points_by_file.get(dep_file, [])
                if affected_eps:
                    reasons.append(f"Exposes entry point(s): {', '.join(affected_eps)}")

                # Check symbol-level references if source symbols are known
                if changed_symbol_names:
                    for sym_name in changed_symbol_names:
                        # Check forward imports of dep_file
                        imports = self.dep_graph.forward_imports.get(dep_file, [])
                        if any(sym_name in imp for imp in imports):
                            reasons.append(f"Explicitly imports changed symbol '{sym_name}'")
                            evidence.relationship_type = ImpactType.SYMBOL_REFERENCE
                            rel_type = ImpactType.SYMBOL_REFERENCE

                entity = ImpactedEntity(
                    file_path=dep_file,
                    component_name=comp_name,
                    layer=layer_name,
                    impact_type=rel_type,
                    depth=new_depth,
                    shortest_path=new_path,
                    impact_reasons=reasons,
                    evidence=[evidence],
                    associated_routes=assoc_routes,
                    associated_models=assoc_models,
                    affected_entry_points=affected_eps,
                )
                impacted_map[dep_file] = entity

                # Continue BFS traversal
                queue.append((dep_file, new_path, new_depth))

        # Sort impacted entities deterministically by depth, then file path
        sorted_entities = sorted(impacted_map.values(), key=lambda e: (e.depth, e.file_path))
        return sorted_entities, limitations

    def _extract_seeds(self, change_set: ChangeSet) -> list[str]:
        seeds: set[str] = set()
        seeds.update(change_set.modified_paths)
        seeds.update(change_set.added_paths)
        for old, _new in change_set.renamed_paths:
            seeds.add(old)
        for cf in change_set.changed_files:
            if cf.new_path:
                seeds.add(cf.new_path)
            elif cf.old_path:
                seeds.add(cf.old_path)
        return sorted(seeds)
