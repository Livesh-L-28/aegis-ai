# Knowledge Intelligence & Hybrid Retrieval

## Ingestion Pipeline
```text
Markdown / Document
        ↓
Section / Header Chunking
        ↓
Embedding Generation (64-dim L2 Normalized)
        ↓
Multi-Tenant Storage (KnowledgeStore)
```

## Retrieval Architecture
- **Keyword Search**: Exact token and title matching.
- **Dense Semantic Search**: Cosine vector similarity comparing query embeddings with chunk embeddings.
- **Hybrid Fusion**: Combines normalized keyword scores and cosine similarities using parameter `alpha`:
  `Score = (1 - alpha) * Normalized_Keyword + alpha * Cosine_Similarity`
- **Tenant Boundary**: All queries require `X-Organization-ID` context; documents belonging to other organizations are excluded.
