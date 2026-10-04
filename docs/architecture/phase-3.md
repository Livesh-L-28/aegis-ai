# Phase 3: System + Code + Knowledge Intelligence Architecture

## Overview
Phase 3 expands AEGIS from observing operational metrics, logs, and traces into a platform that comprehensively understands the structure, code, runtime dependencies, and operational documentation surrounding a system.

## The Intelligence Triad

```text
                    AEGIS INTELLIGENCE
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
      SYSTEM            CODE            KNOWLEDGE
   INTELLIGENCE      INTELLIGENCE      INTELLIGENCE
          │                │                │
          ▼                ▼                ▼
      Services          Git             Docs
      Dependencies      Files           Runbooks
      Environments      Symbols         Incidents
      Deployments       Commits         Postmortems
      Telemetry         AST             Architecture
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                  UNIFIED SYSTEM MODEL
```

### 1. System Intelligence (`packages/intelligence/system`)
- **Service & Environment Inventory**: Maps service definitions, display names, and environment assignments (`production-sim`, `development`).
- **Runtime Dependency Graph**: Captures explicit directed dependency relationships (`HTTP`, `DATABASE`, `CACHE`, `QUEUE`, `EXTERNAL_API`).
- **Graph API**: Exposes machine-readable Nodes and Edges (`GET /api/v1/intelligence/dependency-graph`).

### 2. Code Intelligence (`packages/intelligence/code`)
- **Static AST Analysis**: Extracts modules, functions, classes, methods, docstrings, signatures, and imports without code execution (`PythonASTParser`).
- **Incremental & Idempotent Indexer**: Computes SHA256 content hashes, indexing changed files and skipping identical files (`RepositoryIndexer`).
- **Secret Protection**: Scans and replaces sensitive tokens, passwords, and private keys with `[REDACTED_SECRET]` during indexing.
- **Code Dependency Graph**: Distinguishes source-level imports from runtime topology dependencies.

### 3. Knowledge Intelligence (`packages/intelligence/knowledge`)
- **Document Model**: Multi-tenant operational knowledge store (`KnowledgeStore`) supporting runbooks, incident reports, and architecture guides.
- **Deterministic Chunking**: Preserves structural markdown headers and sections (`DocumentChunker`).
- **Embedding Provider**: Pluggable 64-dimensional unit vector embedding engine (`deterministic_text_embedding`).
- **Hybrid Retrieval**: Fuses keyword token matching and dense cosine vector similarity into normalized ranked results.

### 4. Unified System Model
The Unified Context Service (`packages/intelligence/system/context.py`) fuses:
- Runtime service dependencies
- Repository symbols and imports
- Operational runbooks and troubleshooting guides
Into a machine-readable context object via `GET /api/v1/intelligence/services/{name}/context`, ready for Phase 4 Evidence & AI Reasoning.
