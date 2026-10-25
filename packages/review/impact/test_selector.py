"""Predictive test selector identifying tests likely to exercise changed code."""

from pathlib import Path

from packages.review.analyzer.dependency_graph import DependencyGraph
from packages.review.impact.models import (
    ChangeSet,
    ConfidenceCategory,
    ImpactedEntity,
    ImpactEvidence,
    ImpactType,
    TestImpactCandidate,
)


class PredictiveTestSelector:
    """Selects and prioritizes tests based on static dependency graphs, symbols, and naming conventions."""

    def __init__(
        self,
        repo_root: str | Path,
        dependency_graph: DependencyGraph,
        conservative_mode: bool = False,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.dep_graph = dependency_graph
        self.conservative_mode = conservative_mode

    def select_tests(
        self,
        change_set: ChangeSet,
        impacted_entities: list[ImpactedEntity],
    ) -> list[TestImpactCandidate]:
        """Identifies recommended tests with evidence and confidence levels."""
        candidates_by_file: dict[str, TestImpactCandidate] = {}

        # Collect changed seeds
        changed_seeds = set(change_set.modified_paths + change_set.added_paths)
        for old, _new in change_set.renamed_paths:
            changed_seeds.add(old)

        # 1. Directly Changed Test Files
        for f in changed_seeds:
            if self.dep_graph.is_test_file(f):
                candidates_by_file[f] = TestImpactCandidate(
                    test_file=f,
                    associated_target=f,
                    selection_reason="Test file was directly modified in the change set.",
                    confidence=ConfidenceCategory.HIGH,
                    relationship_type=ImpactType.DIRECT_DEPENDENCY,
                    evidence=ImpactEvidence(
                        source_entity=f,
                        target_entity=f,
                        relationship_type=ImpactType.DIRECT_DEPENDENCY,
                        confidence=ConfidenceCategory.HIGH,
                        evidence_snippet="Direct test file modification",
                    ),
                )

        # 2. Direct Dependents: Tests importing changed files directly
        for seed in changed_seeds:
            seed_mod = self.dep_graph.file_to_module.get(seed)
            direct_deps = set(self.dep_graph.reverse_deps.get(seed, set()))
            if seed_mod:
                direct_deps.update(self.dep_graph.reverse_deps.get(seed_mod, set()))

            for dep in direct_deps:
                dep_file = self.dep_graph.module_to_file.get(dep, dep)
                if self.dep_graph.is_test_file(dep_file) and dep_file not in candidates_by_file:
                    candidates_by_file[dep_file] = TestImpactCandidate(
                        test_file=dep_file,
                        associated_target=seed,
                        selection_reason=f"Directly imports changed file '{seed}'.",
                        confidence=ConfidenceCategory.HIGH,
                        relationship_type=ImpactType.DIRECT_DEPENDENCY,
                        evidence=ImpactEvidence(
                            source_entity=seed,
                            target_entity=dep_file,
                            relationship_type=ImpactType.DIRECT_DEPENDENCY,
                            confidence=ConfidenceCategory.HIGH,
                            depth=1,
                            shortest_path=[seed, dep_file],
                            evidence_snippet=f"{dep_file} -> import {seed}",
                        ),
                    )

        # 3. Transitive Dependents: Tests importing an impacted intermediate entity
        for entity in impacted_entities:
            ent_file = entity.file_path
            if self.dep_graph.is_test_file(ent_file) and ent_file not in candidates_by_file:
                candidates_by_file[ent_file] = TestImpactCandidate(
                    test_file=ent_file,
                    associated_target=entity.shortest_path[0] if entity.shortest_path else ent_file,
                    selection_reason=(
                        f"Transitively depends on changed code via path: {' -> '.join(entity.shortest_path)}"
                    ),
                    confidence=ConfidenceCategory.MEDIUM,
                    relationship_type=ImpactType.TRANSITIVE_DEPENDENCY,
                    evidence=ImpactEvidence(
                        source_entity=entity.shortest_path[0] if entity.shortest_path else ent_file,
                        target_entity=ent_file,
                        relationship_type=ImpactType.TRANSITIVE_DEPENDENCY,
                        confidence=ConfidenceCategory.MEDIUM,
                        depth=entity.depth,
                        shortest_path=entity.shortest_path,
                        evidence_snippet=f"Transitive path: {' -> '.join(entity.shortest_path)}",
                    ),
                )

        # 4. Convention-based Matching (e.g. test_foo.py for foo.py)
        all_known_files = set(self.dep_graph.module_to_file.values())
        test_files = [f for f in all_known_files if self.dep_graph.is_test_file(f)]

        for seed in changed_seeds:
            stem = Path(seed).stem
            if stem.startswith("test_") or stem.endswith("_test"):
                continue

            for tf in test_files:
                tf_stem = Path(tf).stem.lower()
                stem_lower = stem.lower()
                if tf not in candidates_by_file and (
                    tf_stem == f"test_{stem_lower}"
                    or tf_stem == f"{stem_lower}_test"
                    or tf_stem.endswith(f"_{stem_lower}")
                ):
                    candidates_by_file[tf] = TestImpactCandidate(
                        test_file=tf,
                        associated_target=seed,
                        selection_reason=f"Naming convention matches changed module '{stem}'.",
                        confidence=ConfidenceCategory.MEDIUM,
                        relationship_type=ImpactType.HEURISTIC,
                        evidence=ImpactEvidence(
                            source_entity=seed,
                            target_entity=tf,
                            relationship_type=ImpactType.HEURISTIC,
                            confidence=ConfidenceCategory.MEDIUM,
                            evidence_snippet=f"File pattern match: '{stem}' in '{tf}'",
                        ),
                    )

        # 5. Conservative Mode Fallback
        if self.conservative_mode:
            for tf in sorted(test_files):
                if tf not in candidates_by_file:
                    candidates_by_file[tf] = TestImpactCandidate(
                        test_file=tf,
                        associated_target="<repository_wide>",
                        selection_reason="Conservative mode: included to safeguard against dynamic fixture or indirect runtime execution.",
                        confidence=ConfidenceCategory.LOW,
                        relationship_type=ImpactType.HEURISTIC,
                    )

        # Deterministic sorting: Confidence HIGH -> MEDIUM -> LOW, then test_file name
        confidence_order = {
            ConfidenceCategory.HIGH: 0,
            ConfidenceCategory.MEDIUM: 1,
            ConfidenceCategory.LOW: 2,
        }
        return sorted(
            candidates_by_file.values(),
            key=lambda c: (confidence_order.get(c.confidence, 3), c.test_file),
        )
