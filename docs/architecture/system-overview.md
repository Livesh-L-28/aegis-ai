# System Architecture Overview — AEGIS AI

## Vision
AEGIS is an enterprise-grade AI Engineering & Autonomous Reliability Platform engineered to detect production incidents, inspect diagnostic evidence across metrics/logs/traces, isolate probable root causes, validate remediation candidates safely, and assist engineers with verified deployments.

## The 7-Phase Architecture Roadmap
AEGIS's roadmap is strictly partitioned into 7 frozen phases:
1. **Phase 1: Enterprise Foundation (Current Phase)**
2. **Phase 2: Production Simulation + Observability**
3. **Phase 3: System + Code + Knowledge Intelligence**
4. **Phase 4: Evidence + AI Reasoning**
5. **Phase 5: AI Trust + Reliability**
6. **Phase 6: AI Remediation + Human Approval + Deployment**
7. **Phase 7: Autonomous Reliability + Evaluation + Production Hardening**

## Architecture Tier Hierarchy
```text
           [Client / Gateway / Webhooks]
                         │
                         ▼
             [FastAPI Application Layer]
             ├── Security & Audit Middlewares
             ├── Authentication / Tenant Boundary
             └── API Versioning (/api/v1)
                         │
                         ▼
               [Application Services]
     (Organization, Project, RBAC, Health Services)
                         │
                         ▼
                 [Domain Entities]
  (PostgreSQL 16 + pgvector, UUID Primary Keys, Relations)
                         │
                         ▼
            [Infrastructure Abstractions]
 ├── PostgreSQL Engine (Asyncpg, SQLAlchemy 2.x)
 ├── Redis Service (Caching, Rate Limiting, Ephemeral State)
 └── ObjectStorage Interface (MinIO / S3 compliant)
```

## Dependency Inversion & Isolation
The platform follows a clean layered dependency architecture:
`API Handlers -> Application Services -> Domain Models -> Repositories -> Infrastructure Providers`
External infrastructure systems (such as MinIO, Postgres, Redis, or future LLM/IdP providers) never leak directly into application domain boundaries.
