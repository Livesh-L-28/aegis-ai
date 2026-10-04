from uuid import UUID

from packages.intelligence.system.registry import (
    DependencyType,
    SystemIntelligenceRegistry,
)


def test_system_dependency_graph_topology() -> None:
    registry = SystemIntelligenceRegistry()
    org_id = UUID("11111111-1111-1111-1111-111111111111")
    graph = registry.get_dependency_graph(org_id)

    node_ids = [n.id for n in graph.nodes]
    assert "gateway" in node_ids
    assert "order-service" in node_ids
    assert "payment-service" in node_ids
    assert "user-service" in node_ids
    assert "postgres" in node_ids
    assert "redis" in node_ids

    # Verify edge types
    db_edges = [e for e in graph.edges if e.dependency_type == DependencyType.DATABASE]
    assert len(db_edges) >= 1
    assert db_edges[0].source == "order-service"
    assert db_edges[0].target == "postgres"

    cache_edges = [e for e in graph.edges if e.dependency_type == DependencyType.CACHE]
    assert len(cache_edges) >= 1
    assert cache_edges[0].source == "payment-service"
    assert cache_edges[0].target == "redis"
