"""In-memory property graph implementation for the Engineering Evidence Graph."""

import json
from collections import deque
from typing import Any
from uuid import UUID

from packages.intelligence.evidence.graph_models import (
    GraphEdge,
    GraphEdgeType,
    GraphNode,
)


class NodeNotFoundError(KeyError):
    """Raised when an operation targets a node identifier that does not exist in the graph."""


class GraphCycleDetectedError(ValueError):
    """Raised when an unexpected dependency cycle is detected in an acyclic traversal."""


class EngineeringEvidenceGraph:
    """In-memory directed property graph representing engineering evidence and relationships.

    Provides cycle-safe multi-hop traversal, reverse dependency queries, tenant/revision filtering,
    and deterministic serialization.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._outgoing: dict[str, list[GraphEdge]] = {}
        self._incoming: dict[str, list[GraphEdge]] = {}

    def __len__(self) -> int:
        return len(self._nodes)

    def add_node(self, node: GraphNode, overwrite: bool = True) -> None:
        """Adds a node to the graph. If node already exists and overwrite is False, skips."""
        if node.id in self._nodes and not overwrite:
            return
        self._nodes[node.id] = node
        if node.id not in self._outgoing:
            self._outgoing[node.id] = []
        if node.id not in self._incoming:
            self._incoming[node.id] = []

    def get_node(self, node_id: str) -> GraphNode | None:
        return self._nodes.get(node_id)

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def nodes(self) -> list[GraphNode]:
        return list(self._nodes.values())

    def edges(self) -> list[GraphEdge]:
        all_edges: list[GraphEdge] = []
        for edge_list in self._outgoing.values():
            all_edges.extend(edge_list)
        return all_edges

    def add_edge(self, edge: GraphEdge, allow_unresolved: bool = True) -> None:
        """Adds a directed edge.

        If allow_unresolved is False and either source or target node is missing,
        raises NodeNotFoundError.
        """
        if not allow_unresolved:
            if edge.source_id not in self._nodes:
                raise NodeNotFoundError(f"Source node '{edge.source_id}' does not exist in graph")
            if edge.target_id not in self._nodes:
                raise NodeNotFoundError(f"Target node '{edge.target_id}' does not exist in graph")

        # Initialize adjacency lists if needed
        if edge.source_id not in self._outgoing:
            self._outgoing[edge.source_id] = []
        if edge.target_id not in self._incoming:
            self._incoming[edge.target_id] = []

        # Avoid exact duplicate edges
        for existing in self._outgoing[edge.source_id]:
            if existing.target_id == edge.target_id and existing.edge_type == edge.edge_type:
                existing.attributes.update(edge.attributes)
                existing.weight = edge.weight
                return

        self._outgoing[edge.source_id].append(edge)
        self._incoming[edge.target_id].append(edge)

    def get_outgoing_edges(self, node_id: str, edge_type: GraphEdgeType | None = None) -> list[GraphEdge]:
        edges = self._outgoing.get(node_id, [])
        if edge_type is None:
            return list(edges)
        return [e for e in edges if e.edge_type == edge_type]

    def get_incoming_edges(self, node_id: str, edge_type: GraphEdgeType | None = None) -> list[GraphEdge]:
        edges = self._incoming.get(node_id, [])
        if edge_type is None:
            return list(edges)
        return [e for e in edges if e.edge_type == edge_type]

    def find_reverse_dependencies(
        self,
        target_id: str,
        max_depth: int = 3,
        edge_type: GraphEdgeType | None = None,
    ) -> set[str]:
        """Discovers all nodes that depend directly or transitively on target_id (cycle-safe BFS)."""
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(target_id, 0)])

        while queue:
            current_id, depth = queue.popleft()
            if depth >= max_depth:
                continue

            incoming = self.get_incoming_edges(current_id, edge_type=edge_type)
            for edge in incoming:
                src = edge.source_id
                if src not in visited and src != target_id:
                    visited.add(src)
                    queue.append((src, depth + 1))

        return visited

    def traverse_multi_hop(
        self,
        start_id: str,
        direction: str = "outgoing",
        max_depth: int = 3,
        edge_type: GraphEdgeType | None = None,
    ) -> list[str]:
        """Performs a cycle-safe breadth-first traversal up to max_depth hops.

        Direction can be 'outgoing' or 'incoming'. Returns ordered list of visited node IDs.
        """
        visited: set[str] = set()
        order: list[str] = []
        queue: deque[tuple[str, int]] = deque([(start_id, 0)])
        visited.add(start_id)

        while queue:
            current_id, depth = queue.popleft()
            order.append(current_id)

            if depth >= max_depth:
                continue

            edges = (
                self.get_outgoing_edges(current_id, edge_type=edge_type)
                if direction == "outgoing"
                else self.get_incoming_edges(current_id, edge_type=edge_type)
            )

            for edge in edges:
                neighbor = edge.target_id if direction == "outgoing" else edge.source_id
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, depth + 1))

        return order

    def detect_cycles(self) -> list[list[str]]:
        """Detects all directed cycles using 3-color DFS. Returns list of cycle paths."""
        white, gray, black = 0, 1, 2
        color: dict[str, int] = dict.fromkeys(self._nodes, white)
        parent: dict[str, str | None] = dict.fromkeys(self._nodes)
        cycles: list[list[str]] = []

        def dfs(u: str, path: list[str]) -> None:
            color[u] = gray
            path.append(u)

            for edge in self._outgoing.get(u, []):
                v = edge.target_id
                if v not in color:
                    continue
                if color[v] == gray:
                    # Cycle detected: extract from path
                    try:
                        idx = path.index(v)
                        cycles.append([*path[idx:], v])
                    except ValueError:
                        pass
                elif color[v] == white:
                    parent[v] = u
                    dfs(v, path)

            path.pop()
            color[u] = black

        for node_id in sorted(self._nodes.keys()):
            if color[node_id] == white:
                dfs(node_id, [])

        return cycles

    def filter_by_revision(self, revision: str) -> "EngineeringEvidenceGraph":
        """Extracts a revision-scoped subgraph containing only nodes pinned to this revision or global nodes."""
        subgraph = EngineeringEvidenceGraph()
        for node in self._nodes.values():
            if node.revision == revision or node.revision is None:
                subgraph.add_node(node)

        for edge in self.edges():
            if subgraph.has_node(edge.source_id) and subgraph.has_node(edge.target_id):
                subgraph.add_edge(edge, allow_unresolved=False)

        return subgraph

    def filter_by_tenant(self, tenant_id: UUID) -> "EngineeringEvidenceGraph":
        """Extracts a tenant-scoped subgraph for strict multi-tenant isolation."""
        subgraph = EngineeringEvidenceGraph()
        for node in self._nodes.values():
            if node.tenant_id == tenant_id or node.tenant_id is None:
                subgraph.add_node(node)

        for edge in self.edges():
            if subgraph.has_node(edge.source_id) and subgraph.has_node(edge.target_id):
                subgraph.add_edge(edge, allow_unresolved=False)

        return subgraph

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dictionary serialization with sorted nodes and edges."""
        sorted_nodes = sorted(self._nodes.values(), key=lambda n: n.id)
        sorted_edges = sorted(self.edges(), key=lambda e: (e.source_id, e.target_id, e.edge_type))
        return {
            "node_count": len(sorted_nodes),
            "edge_count": len(sorted_edges),
            "nodes": [n.model_dump(mode="json") for n in sorted_nodes],
            "edges": [e.model_dump(mode="json") for e in sorted_edges],
        }

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def clear(self) -> None:
        self._nodes.clear()
        self._outgoing.clear()
        self._incoming.clear()
