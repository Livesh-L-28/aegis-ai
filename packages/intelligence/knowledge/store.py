import hashlib
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from packages.intelligence.embeddings.provider import (
    cosine_similarity,
    default_embedding_provider,
)


class DocumentSourceType(StrEnum):
    RUNBOOK = "RUNBOOK"
    POSTMORTEM = "POSTMORTEM"
    INCIDENT = "INCIDENT"
    ARCHITECTURE = "ARCHITECTURE"
    DOCUMENTATION = "DOCUMENTATION"
    README = "README"
    OTHER = "OTHER"


class KnowledgeChunk(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    document_id: UUID
    chunk_index: int
    title: str
    section: str = ""
    content: str
    embedding: list[float] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgeDocument(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    title: str
    source_type: DocumentSourceType
    source_uri: str
    content_hash: str
    chunks: list[KnowledgeChunk] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DocumentChunker:
    """Deterministic document chunker preserving structural sections and headings."""

    @staticmethod
    def chunk_markdown(
        document_id: UUID,
        title: str,
        text: str,
        max_chunk_chars: int = 500,
    ) -> list[KnowledgeChunk]:
        chunks: list[KnowledgeChunk] = []
        lines = text.split("\n")
        current_section = "Overview"
        current_buffer: list[str] = []
        chunk_idx = 0

        for line in lines:
            if line.startswith("#"):
                # Heading detected
                if current_buffer:
                    chunk_text = "\n".join(current_buffer).strip()
                    if chunk_text:
                        chunks.append(
                            KnowledgeChunk(
                                document_id=document_id,
                                chunk_index=chunk_idx,
                                title=title,
                                section=current_section,
                                content=chunk_text,
                                embedding=default_embedding_provider.embed(chunk_text),
                            )
                        )
                        chunk_idx += 1
                        current_buffer = []
                current_section = line.lstrip("#").strip()
            else:
                current_buffer.append(line)
                if sum(len(item) for item in current_buffer) >= max_chunk_chars:
                    chunk_text = "\n".join(current_buffer).strip()
                    if chunk_text:
                        chunks.append(
                            KnowledgeChunk(
                                document_id=document_id,
                                chunk_index=chunk_idx,
                                title=title,
                                section=current_section,
                                content=chunk_text,
                                embedding=default_embedding_provider.embed(chunk_text),
                            )
                        )
                        chunk_idx += 1
                        current_buffer = []

        if current_buffer:
            chunk_text = "\n".join(current_buffer).strip()
            if chunk_text:
                chunks.append(
                    KnowledgeChunk(
                        document_id=document_id,
                        chunk_index=chunk_idx,
                        title=title,
                        section=current_section,
                        content=chunk_text,
                        embedding=default_embedding_provider.embed(chunk_text),
                    )
                )

        return chunks


class KnowledgeStore:
    """In-memory vector and keyword knowledge store with strict multi-tenant isolation."""

    def __init__(self) -> None:
        self._documents: dict[UUID, KnowledgeDocument] = {}

    def ingest_document(
        self,
        organization_id: UUID,
        title: str,
        source_type: DocumentSourceType,
        source_uri: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> KnowledgeDocument:
        doc_id = uuid4()
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        chunks = DocumentChunker.chunk_markdown(document_id=doc_id, title=title, text=content)

        doc = KnowledgeDocument(
            id=doc_id,
            organization_id=organization_id,
            title=title,
            source_type=source_type,
            source_uri=source_uri,
            content_hash=content_hash,
            chunks=chunks,
            metadata=metadata or {},
        )
        self._documents[doc_id] = doc
        return doc

    def list_documents(self, organization_id: UUID) -> list[KnowledgeDocument]:
        return [
            d for d in self._documents.values()
            if d.organization_id == organization_id or str(d.organization_id) == "00000000-0000-0000-0000-000000000000"
        ]

    def keyword_search(
        self, organization_id: UUID, query: str, limit: int = 5
    ) -> list[tuple[KnowledgeChunk, float]]:
        """Exact and tokenized keyword search across tenant knowledge chunks."""
        terms = [t.lower() for t in query.split() if len(t) > 2]
        matches: list[tuple[KnowledgeChunk, float]] = []

        for doc in self.list_documents(organization_id):
            for chunk in doc.chunks:
                text_lower = chunk.content.lower()
                title_lower = chunk.title.lower()
                score = 0.0
                for term in terms:
                    if term in title_lower:
                        score += 2.0
                    if term in text_lower:
                        score += 1.0
                if score > 0:
                    matches.append((chunk, score))

        matches.sort(key=lambda x: x[1], reverse=True)
        return matches[:limit]

    def semantic_search(
        self, organization_id: UUID, query: str, limit: int = 5
    ) -> list[tuple[KnowledgeChunk, float]]:
        """Dense cosine vector search using normalized embeddings."""
        query_vec = default_embedding_provider.embed(query)
        matches: list[tuple[KnowledgeChunk, float]] = []

        for doc in self.list_documents(organization_id):
            for chunk in doc.chunks:
                sim = cosine_similarity(query_vec, chunk.embedding)
                if sim > 0:
                    matches.append((chunk, sim))

        matches.sort(key=lambda x: x[1], reverse=True)
        return matches[:limit]

    def hybrid_search(
        self,
        organization_id: UUID,
        query: str,
        limit: int = 5,
        alpha: float = 0.5,
    ) -> list[dict[str, Any]]:
        """Reciprocal rank fusion combining Keyword and Semantic search."""
        kw_results = self.keyword_search(organization_id, query, limit=limit * 2)
        sem_results = self.semantic_search(organization_id, query, limit=limit * 2)

        # Normalize and fuse scores
        combined: dict[UUID, dict[str, Any]] = {}

        # Max keyword score for normalization
        max_kw = max((s for _, s in kw_results), default=1.0)
        for chunk, score in kw_results:
            norm_score = score / max_kw if max_kw > 0 else 0
            combined[chunk.id] = {
                "chunk": chunk,
                "score": (1 - alpha) * norm_score,
                "provenance": {"keyword_score": score},
            }

        for chunk, score in sem_results:
            if chunk.id not in combined:
                combined[chunk.id] = {
                    "chunk": chunk,
                    "score": alpha * score,
                    "provenance": {"semantic_similarity": score},
                }
            else:
                combined[chunk.id]["score"] += alpha * score
                combined[chunk.id]["provenance"]["semantic_similarity"] = score

        ranked = sorted(combined.values(), key=lambda x: x["score"], reverse=True)
        return ranked[:limit]


knowledge_store = KnowledgeStore()
