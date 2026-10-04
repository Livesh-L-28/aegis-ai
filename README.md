# AEGIS AI — Enterprise-grade AI Engineering & Autonomous Reliability Platform

> **Status: Phase 7 — Autonomous Reliability + Evaluation + Production Hardening COMPLETE (CURRENT)**

AEGIS is an enterprise AI Engineering & Autonomous Reliability Platform engineered to detect production incidents, investigate evidence across metrics/logs/traces, isolate root causes, validate remediation, and assist engineers with verified deployments.

---

## The 7-Phase Roadmap

The complete AEGIS roadmap is permanently frozen at exactly 7 phases:
1. **Enterprise Foundation** — **COMPLETE**
2. **Production Simulation + Observability** — **COMPLETE**
3. **System + Code + Knowledge Intelligence** — **COMPLETE**
4. **Evidence + AI Reasoning** — **COMPLETE**
5. **AI Trust + Reliability** — **COMPLETE**
6. **AI Remediation + Human Approval + Deployment** — **COMPLETE**
7. **Autonomous Reliability + Evaluation + Production Hardening** — **COMPLETE (CURRENT)**

> **Phase 7 Scope Note:** Phase 7 concludes the roadmap by delivering bounded autonomous reliability under deterministic safety controls: bounded agent execution loops with strict tool and cost budgets, multi-tiered autonomy levels (`LEVEL_0` through `LEVEL_3`), emergency stop kill switches, change freeze mechanisms, autonomy circuit breakers, continuous evaluation against golden and adversarial datasets with strict release gates, SLO and error budget tracking, and operational learning from validated incidents without self-modifying code or policies.


---

## Unified System Model

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

---

## Intelligence Capabilities
- **System Intelligence**: Runtime topology discovery, typed dependency relationships (`HTTP`, `DATABASE`, `CACHE`), machine-readable graph API (`GET /api/v1/intelligence/dependency-graph`).
- **Code Intelligence**: Static AST parsing (classes, methods, functions, signatures, docstrings, imports), SHA256 incremental indexing, secret redaction (`[REDACTED_SECRET]`), symbol search (`POST /api/v1/intelligence/code/search`).
- **Knowledge Intelligence**: Section-based document chunking, 64-dimensional unit vector embeddings, hybrid keyword + dense vector retrieval with score normalization (`POST /api/v1/intelligence/knowledge/search`).
- **Unified Context API**: Assembles full service context across topology, symbols, and operational documentation (`GET /api/v1/intelligence/services/{service}/context`).

---

## Public Portfolio Architecture (Render All-in-One Deployment)

```text
                               GitHub Repository
                                       │
                      ┌────────────────┴────────────────┐
                      ▼                                 ▼
           Render Static Site                  Render Web Service
        React 18 + Vite Frontend               FastAPI Backend API
        (aegis-ai-web.onrender.com)        (aegis-ai-api.onrender.com)
                      │                                 │
                      │  (REST API & SSE stream)        │
                      └────────────────►────────────────┤
                                                        │
                                     ┌──────────────────┼──────────────────┐
                                     ▼                  ▼                  ▼
                                Render Postgres       Redis          Object Storage
                                  + pgvector    (Upstash / Aiven)   (Cloudflare R2 / S3)
```

---

## Live Demo & Documentation

### Deployed Portfolio URLs

* **Deployment Documentation**: [`docs/deployment/public-demo.md`](docs/deployment/public-demo.md)
* **Render Blueprint**: [`render.yaml`](render.yaml) (1-Click deployment for Frontend + Backend + PostgreSQL)
* **Frontend**: Configured for Render Static Site (`apps/web`, SPA rewrite `/* -> /index.html`, `VITE_API_BASE_URL`) or Vercel
* **API**: Configured for Render Docker Web Service with dynamic `$PORT` and container health checks

---

## Local Quickstart (Full Docker Compose Environment)

To run the complete AEGIS ecosystem locally including Prometheus, Grafana, Loki, MinIO, and 4 simulated microservices:

```bash
# 1. Clone repository
git clone <repository_url>
cd "AEGIS AI"

# 2. Configure environment
cp .env.example .env

# 3. Start complete local infrastructure
docker compose up --build -d

# 4. Open Command Center
open http://localhost:5173
```

---

## Interactive Recruiter Demo Scenario

Experience the complete **Observe → Reason → Propose → Approve → Sandbox Execute → Validate** autonomous reliability lifecycle:

1. **Open Dashboard**: Navigate to the Operational Overview.
2. **Trigger Incident (INC-001)**: Under *Canonical Fault Scenarios*, click **Inject Fault** on scenario `SCEN-001` (Redis Connection Exhaustion) or `SCEN-002` (Downstream Latency Spike).
3. **Observe Incident**: View the newly detected incident in the *Live Incident Pipeline* with its severity and affected service.
4. **Run AI Investigation**: Click **Investigate** to open the Incident Deep Dive. Click **Run AI Investigation** to correlate telemetry, git history, and runbooks.
5. **Inspect Evidence & Causal Graph**: Review multi-modal evidence signals and the determined root cause.
6. **Propose Remediation**: Click **Propose AI Remediation** to synthesize a bounded, typed action plan.
7. **Review Risk & Blast Radius**: Inspect calculated risk levels and affected services.
8. **Human Approval**: Click **Approve Action** to cryptographically authorize the plan.
9. **Sandbox Execution**: Click **Execute in Sandbox** to safely apply the fix to the simulated environment.
10. **Validate & Audit**: Inspect the automated post-flight verification check and the immutable entry recorded in the Audit log.

---

## Verification & Quality Gates

```bash
# Code formatting & lint check
uv run ruff check .

# Strict static type check
uv run mypy --explicit-package-bases apps packages tests

# Automated test suite (103/103 passed)
uv run pytest tests/ -q

# Frontend production build
npm --prefix apps/web run build
```
