"""Unit tests for Phase 1A Engineering Evidence Graph domain contracts and in-memory graph."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from packages.intelligence.code.indexer import SymbolType
from packages.intelligence.evidence.graph import (
    EngineeringEvidenceGraph,
    NodeNotFoundError,
)
from packages.intelligence.evidence.graph_models import (
    DependencyEdge,
    EvidenceRecord,
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
    ProvenanceTag,
    SymbolNode,
    ValidationStatus,
)


def test_node_insertion_and_lookup() -> None:
    graph = EngineeringEvidenceGraph()
    node = GraphNode(
        id="file:app/main.py",
        node_type=GraphNodeType.FILE,
        label="app/main.py",
        attributes={"language": "python", "lines": 120},
    )
    graph.add_node(node)
    assert graph.has_node("file:app/main.py")
    assert graph.get_node("file:app/main.py") == node
    assert len(graph) == 1


def test_duplicate_node_handling() -> None:
    graph = EngineeringEvidenceGraph()
    n1 = GraphNode(id="n1", node_type=GraphNodeType.FILE, label="File 1", attributes={"v": 1})
    n2 = GraphNode(id="n1", node_type=GraphNodeType.FILE, label="File 1 updated", attributes={"v": 2})

    graph.add_node(n1)
    # With overwrite=False, n1 is retained
    graph.add_node(n2, overwrite=False)
    assert graph.get_node("n1").attributes["v"] == 1  # type: ignore

    # With overwrite=True (default), n2 updates n1
    graph.add_node(n2, overwrite=True)
    assert graph.get_node("n1").attributes["v"] == 2  # type: ignore
    assert len(graph) == 1


def test_edge_insertion_and_missing_node_validation() -> None:
    graph = EngineeringEvidenceGraph()
    edge = GraphEdge(
        source_id="file:a.py",
        target_id="file:b.py",
        edge_type=GraphEdgeType.IMPORTS_MODULE,
    )

    # Disallow unresolved node references
    with pytest.raises(NodeNotFoundError):
        graph.add_edge(edge, allow_unresolved=False)

    # Adding nodes allows adding edge with validation
    graph.add_node(GraphNode(id="file:a.py", node_type=GraphNodeType.FILE, label="a.py"))
    graph.add_node(GraphNode(id="file:b.py", node_type=GraphNodeType.FILE, label="b.py"))
    graph.add_edge(edge, allow_unresolved=False)

    outgoing = graph.get_outgoing_edges("file:a.py")
    assert len(outgoing) == 1
    assert outgoing[0].target_id == "file:b.py"

    incoming = graph.get_incoming_edges("file:b.py")
    assert len(incoming) == 1
    assert incoming[0].source_id == "file:a.py"


def test_reverse_dependency_lookup() -> None:
    graph = EngineeringEvidenceGraph()
    # A -> B -> C, and D -> B
    for name in ["A", "B", "C", "D"]:
        graph.add_node(GraphNode(id=name, node_type=GraphNodeType.FILE, label=name))

    graph.add_edge(GraphEdge(source_id="A", target_id="B", edge_type=GraphEdgeType.IMPORTS_MODULE))
    graph.add_edge(GraphEdge(source_id="D", target_id="B", edge_type=GraphEdgeType.IMPORTS_MODULE))
    graph.add_edge(GraphEdge(source_id="B", target_id="C", edge_type=GraphEdgeType.IMPORTS_MODULE))

    # Reverse dependencies of C: B, and transitively A and D
    rev_deps_c = graph.find_reverse_dependencies("C", max_depth=3)
    assert rev_deps_c == {"B", "A", "D"}

    # Reverse dependencies of B: direct A and D
    rev_deps_b = graph.find_reverse_dependencies("B", max_depth=1)
    assert rev_deps_b == {"A", "D"}


def test_cycle_detection_and_safe_traversal() -> None:
    graph = EngineeringEvidenceGraph()
    # Cycle: X -> Y -> Z -> X
    for name in ["X", "Y", "Z"]:
        graph.add_node(GraphNode(id=name, node_type=GraphNodeType.FILE, label=name))

    graph.add_edge(GraphEdge(source_id="X", target_id="Y", edge_type=GraphEdgeType.CALLS_SYMBOL))
    graph.add_edge(GraphEdge(source_id="Y", target_id="Z", edge_type=GraphEdgeType.CALLS_SYMBOL))
    graph.add_edge(GraphEdge(source_id="Z", target_id="X", edge_type=GraphEdgeType.CALLS_SYMBOL))

    cycles = graph.detect_cycles()
    assert len(cycles) > 0
    # Any cycle path must return to starting node
    assert cycles[0][0] == cycles[0][-1]

    # Cycle-safe multi-hop traversal does not infinite loop
    visited = graph.traverse_multi_hop("X", direction="outgoing", max_depth=10)
    assert set(visited) == {"X", "Y", "Z"}


def test_deterministic_serialization() -> None:
    graph1 = EngineeringEvidenceGraph()
    graph2 = EngineeringEvidenceGraph()

    # Add in different orders
    nodes = [
        GraphNode(id="b_node", node_type=GraphNodeType.FILE, label="b"),
        GraphNode(id="a_node", node_type=GraphNodeType.FILE, label="a"),
    ]
    for n in nodes:
        graph1.add_node(n)
    for n in reversed(nodes):
        graph2.add_node(n)

    e1 = GraphEdge(source_id="b_node", target_id="a_node", edge_type=GraphEdgeType.IMPORTS_MODULE)
    graph1.add_edge(e1)
    graph2.add_edge(e1)

    json1 = graph1.to_json(indent=2)
    json2 = graph2.to_json(indent=2)

    assert json1 == json2
    data = graph1.to_dict()
    assert data["node_count"] == 2
    assert data["edge_count"] == 1
    assert data["nodes"][0]["id"] == "a_node"
    assert data["nodes"][1]["id"] == "b_node"


def test_symbol_node_and_dependency_edge_mapping() -> None:
    sym = SymbolNode(
        file_path="apps/api/app/core.py",
        name="authenticate",
        qualified_name="AuthService.authenticate",
        symbol_type=SymbolType.METHOD,
        start_line=45,
        end_line=60,
        signature="def authenticate(token: str) -> Principal",
        docstring_summary="Validates JWT token.",
        embedding=[0.1] * 64,
    )
    node = sym.to_graph_node(revision="abc1234")
    assert node.node_type == GraphNodeType.SYMBOL
    assert node.revision == "abc1234"
    assert node.attributes["start_line"] == 45
    assert node.attributes["embedding_dim"] == 64

    dep = DependencyEdge(
        source_file="apps/api/app/core.py",
        target_module="packages.security.rbac",
        imported_symbols=["Principal", "Permission"],
    )
    edge = dep.to_graph_edge(revision="abc1234")
    assert edge.edge_type == GraphEdgeType.IMPORTS_MODULE
    assert edge.attributes["imported_symbols"] == ["Principal", "Permission"]


def test_evidence_record_fingerprint_and_confidence() -> None:
    record = EvidenceRecord(
        evidence_type="STATIC_ANALYSIS",
        provenance=ProvenanceTag(
            source="ast_security",
            collected_at=datetime.now(UTC),
            collector_identity="test_runner",
        ),
        file_path="apps/api/app/main.py",
        start_line=12,
        end_line=12,
        symbol_name="eval",
        content="Dangerous eval call detected",
        confidence=0.95,
        validation_status=ValidationStatus.VALIDATED,
    )

    assert record.content_hash != ""
    assert len(record.content_hash) == 64
    assert record.confidence == 0.95

    # Out of range confidence rejected by pydantic
    with pytest.raises(ValueError):
        EvidenceRecord(
            evidence_type="HYPOTHESIS",
            provenance=ProvenanceTag(source="ai", collector_identity="test"),
            content="Invalid confidence",
            confidence=1.5,
        )


def test_tenant_and_revision_filtering() -> None:
    graph = EngineeringEvidenceGraph()
    org1 = uuid4()
    org2 = uuid4()

    n1 = GraphNode(id="n1", node_type=GraphNodeType.FILE, label="f1", revision="rev1", tenant_id=org1)
    n2 = GraphNode(id="n2", node_type=GraphNodeType.FILE, label="f2", revision="rev2", tenant_id=org1)
    n3 = GraphNode(id="n3", node_type=GraphNodeType.FILE, label="f3", revision="rev1", tenant_id=org2)

    for n in [n1, n2, n3]:
        graph.add_node(n)

    graph.add_edge(GraphEdge(source_id="n1", target_id="n2", edge_type=GraphEdgeType.IMPORTS_MODULE))

    sub_rev1 = graph.filter_by_revision("rev1")
    assert sub_rev1.has_node("n1")
    assert sub_rev1.has_node("n3")
    assert not sub_rev1.has_node("n2")
    # Edge to n2 should be pruned
    assert len(sub_rev1.edges()) == 0

    sub_org1 = graph.filter_by_tenant(org1)
    assert sub_org1.has_node("n1")
    assert sub_org1.has_node("n2")
    assert not sub_org1.has_node("n3")
    assert len(sub_org1.edges()) == 1
