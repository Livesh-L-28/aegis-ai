"""Evidence engine, models, and Engineering Evidence Graph."""

try:
    from packages.intelligence.evidence.engine import EvidenceEngine
except (ImportError, ModuleNotFoundError):
    EvidenceEngine = None  # type: ignore[assignment, misc]
from packages.intelligence.evidence.graph import (
    EngineeringEvidenceGraph,
    GraphCycleDetectedError,
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
)
from packages.intelligence.evidence.models import (
    EvidenceItem,
    EvidenceSeverity,
    EvidenceType,
    TimelineEntry,
)

__all__ = [
    "DependencyEdge",
    "EngineeringEvidenceGraph",
    "EvidenceEngine",
    "EvidenceItem",
    "EvidenceRecord",
    "EvidenceSeverity",
    "EvidenceType",
    "GraphCycleDetectedError",
    "GraphEdge",
    "GraphEdgeType",
    "GraphNode",
    "GraphNodeType",
    "NodeNotFoundError",
    "ProvenanceTag",
    "SymbolNode",
    "TimelineEntry",
]
