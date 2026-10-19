"""Domain contracts and schema models for the Engineering Evidence Graph."""

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from packages.intelligence.code.indexer import SymbolType


class ValidationStatus(StrEnum):
    VALIDATED = "VALIDATED"
    UNVERIFIED = "UNVERIFIED"
    REJECTED_LOCATION = "REJECTED_LOCATION"
    REJECTED_CONTRADICTED = "REJECTED_CONTRADICTED"


class GraphNodeType(StrEnum):
    REPOSITORY = "REPOSITORY"
    REVISION = "REVISION"
    FILE = "FILE"
    SYMBOL = "SYMBOL"
    DEPENDENCY = "DEPENDENCY"
    TEST = "TEST"
    TEST_RESULT = "TEST_RESULT"
    FINDING = "FINDING"
    EVIDENCE_RECORD = "EVIDENCE_RECORD"
    INCIDENT = "INCIDENT"
    VALIDATION_DECISION = "VALIDATION_DECISION"


class GraphEdgeType(StrEnum):
    CONTAINS_FILE = "CONTAINS_FILE"
    DEFINES_SYMBOL = "DEFINES_SYMBOL"
    IMPORTS_MODULE = "IMPORTS_MODULE"
    CALLS_SYMBOL = "CALLS_SYMBOL"
    COVERS_COMPONENT = "COVERS_COMPONENT"
    EXERCISES_TEST = "EXERCISES_TEST"
    REFERENCES_SOURCE = "REFERENCES_SOURCE"
    SUPPORTS_FINDING = "SUPPORTS_FINDING"
    CONTRADICTS_FINDING = "CONTRADICTS_FINDING"
    PRODUCED_BY_TOOL = "PRODUCED_BY_TOOL"
    ASSOCIATED_INCIDENT = "ASSOCIATED_INCIDENT"
    PROVENANCE_LINK = "PROVENANCE_LINK"


class ProvenanceTag(BaseModel):
    """Immutable provenance record tracking evidence collector, timestamp, and source hash."""

    source: str = Field(..., description="Collector or tool source (e.g. ast_parser, ruff, git_diff, ai_hypothesis)")
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tool_version: str | None = Field(default=None, description="Analyzer or tool version if applicable")
    collector_identity: str = Field(default="system", description="User, service, or pipeline ID")
    content_hash: str | None = Field(default=None, description="SHA-256 hash of original input text")


class GraphNode(BaseModel):
    """Canonical node in the Engineering Evidence Graph."""

    id: str = Field(..., description="Deterministic or UUID identifier for the node")
    node_type: GraphNodeType
    label: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    revision: str | None = Field(default=None, description="Commit SHA this node is pinned to")
    tenant_id: UUID | None = Field(default=None, description="Tenant organization ID for multi-tenant isolation")


class GraphEdge(BaseModel):
    """Directed edge representing relationships between evidence graph nodes."""

    source_id: str
    target_id: str
    edge_type: GraphEdgeType
    attributes: dict[str, Any] = Field(default_factory=dict)
    weight: float = Field(default=1.0, ge=0.0)


class SymbolNode(BaseModel):
    """Specialized representation of an AST symbol within a source file."""

    file_path: str
    name: str
    qualified_name: str
    symbol_type: SymbolType
    start_line: int
    end_line: int
    signature: str = ""
    docstring_summary: str | None = None
    embedding: list[float] = Field(default_factory=list)

    def to_graph_node(self, revision: str | None = None, tenant_id: UUID | None = None) -> GraphNode:
        rev_part = f"@{revision}" if revision else ""
        node_id = f"sym:{self.file_path}:{self.qualified_name}{rev_part}"
        return GraphNode(
            id=node_id,
            node_type=GraphNodeType.SYMBOL,
            label=self.qualified_name,
            attributes={
                "file_path": self.file_path,
                "name": self.name,
                "qualified_name": self.qualified_name,
                "symbol_type": self.symbol_type.value,
                "start_line": self.start_line,
                "end_line": self.end_line,
                "signature": self.signature,
                "docstring_summary": self.docstring_summary,
                "embedding_dim": len(self.embedding),
            },
            revision=revision,
            tenant_id=tenant_id,
        )


class DependencyEdge(BaseModel):
    """Cross-file module or symbol dependency relationship."""

    source_file: str
    target_module: str
    imported_symbols: list[str] = Field(default_factory=list)
    edge_type: str = "IMPORT"
    source_symbol: str | None = None
    target_symbol: str | None = None

    def to_graph_edge(self, revision: str | None = None) -> GraphEdge:
        rev_part = f"@{revision}" if revision else ""
        src_id = f"file:{self.source_file}{rev_part}"
        tgt_id = f"mod:{self.target_module}{rev_part}"
        return GraphEdge(
            source_id=src_id,
            target_id=tgt_id,
            edge_type=GraphEdgeType.IMPORTS_MODULE,
            attributes={
                "imported_symbols": self.imported_symbols,
                "edge_type": self.edge_type,
                "source_symbol": self.source_symbol,
                "target_symbol": self.target_symbol,
            },
            weight=1.0,
        )


class EvidenceRecord(BaseModel):
    """Unified evidence model connecting revisions, static findings, tests, and telemetry."""

    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID | None = None
    repository_id: UUID | None = None
    revision_id: str | None = None
    evidence_type: str = Field(
        ...,
        description="Type: STATIC_ANALYSIS, SECURITY_HEURISTIC, DIFF_DELTA, TEST_EXECUTION, TELEMETRY_SIGNAL, or HYPOTHESIS",
    )
    provenance: ProvenanceTag
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    symbol_name: str | None = None
    content: str = Field(..., description="Human-readable description or observation summary")
    structured_payload: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    content_hash: str = Field(default="", description="Deterministic SHA-256 fingerprint")
    validation_status: ValidationStatus = ValidationStatus.UNVERIFIED

    def model_post_init(self, __context: Any) -> None:
        if not self.content_hash:
            self.content_hash = self.compute_fingerprint(
                file_path=self.file_path,
                start_line=self.start_line,
                evidence_type=self.evidence_type,
                symbol_name=self.symbol_name,
                content=self.content,
            )

    @staticmethod
    def compute_fingerprint(
        file_path: str | None,
        start_line: int | None,
        evidence_type: str,
        symbol_name: str | None,
        content: str,
    ) -> str:
        """Deterministic fingerprint for deduplication and content integrity."""
        raw = f"{str(file_path).strip().lower()}:{start_line or 0}:{evidence_type.strip().upper()}:{str(symbol_name).strip()}:{content.strip()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_graph_node(self) -> GraphNode:
        rev_part = f"@{self.revision_id}" if self.revision_id else ""
        node_id = f"ev:{self.id}{rev_part}"
        return GraphNode(
            id=node_id,
            node_type=GraphNodeType.EVIDENCE_RECORD,
            label=f"[{self.evidence_type}] {self.file_path or 'Global'}:{self.start_line or 0}",
            attributes={
                "evidence_type": self.evidence_type,
                "file_path": self.file_path,
                "start_line": self.start_line,
                "end_line": self.end_line,
                "symbol_name": self.symbol_name,
                "content": self.content,
                "confidence": self.confidence,
                "content_hash": self.content_hash,
                "validation_status": self.validation_status.value,
                "source": self.provenance.source,
                "collected_at": self.provenance.collected_at.isoformat(),
            },
            revision=self.revision_id,
            tenant_id=self.organization_id,
        )
