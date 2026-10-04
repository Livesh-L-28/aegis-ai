from uuid import UUID

from packages.intelligence.knowledge.store import (
    DocumentChunker,
    DocumentSourceType,
    KnowledgeStore,
)


def test_document_chunking_structure() -> None:
    doc_id = UUID("11111111-1111-1111-1111-111111111111")
    markdown_text = """# Incident Runbook
This is an overview of incident mitigation.

## Database Failover
When PostgreSQL latency spikes, follow these failover steps.
Check connection pools immediately.

## Redis Recovery
If Redis connection breaks, restart cache cluster.
"""
    chunks = DocumentChunker.chunk_markdown(doc_id, title="Test Runbook", text=markdown_text)
    assert len(chunks) >= 2
    sections = [c.section for c in chunks]
    assert any("Database Failover" in s for s in sections)
    assert any("Redis Recovery" in s for s in sections)
    assert all(len(c.embedding) == 64 for c in chunks)


def test_hybrid_search_retrieval_ranking() -> None:
    store = KnowledgeStore()
    org_id = UUID("22222222-2222-2222-2222-222222222222")

    store.ingest_document(
        organization_id=org_id,
        title="PostgreSQL Latency Runbook",
        source_type=DocumentSourceType.RUNBOOK,
        source_uri="docs/postgres.md",
        content="# PostgreSQL Latency\nTroubleshoot PostgreSQL connection pool exhaustion and slow queries.",
    )

    store.ingest_document(
        organization_id=org_id,
        title="Redis Troubleshooting Guide",
        source_type=DocumentSourceType.RUNBOOK,
        source_uri="docs/redis.md",
        content="# Redis Cache Breakdown\nSteps to diagnose Redis timeout errors and cache eviction.",
    )

    # Hybrid Search Query: "PostgreSQL connection pool exhausted"
    results = store.hybrid_search(organization_id=org_id, query="PostgreSQL connection pool exhausted", limit=3)
    assert len(results) >= 1
    top_result = results[0]
    assert "PostgreSQL" in top_result["chunk"].title or "PostgreSQL" in top_result["chunk"].content
    assert top_result["score"] > 0
    assert "provenance" in top_result
