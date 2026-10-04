# AEGIS AI — Public Portfolio Deployment Guide (Render)

This guide details how to deploy **both the AEGIS Frontend and Backend on Render** using Render's Infrastructure-as-Code Blueprint (`render.yaml`), with managed PostgreSQL (`pgvector`), managed Redis, and S3-compatible object storage.

---

## 1. Target Architecture (All-in-One Render)

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

## 2. Option 1: One-Click Render Blueprint Deployment (Recommended)

The repository includes a ready-to-use [`render.yaml`](file:///Users/livesh/AEGIS%20AI/render.yaml) blueprint specification that automatically provisions:
1. **`aegis-ai-api`**: FastAPI backend running in Docker, dynamic `$PORT` binding, preflight healthchecks.
2. **`aegis-ai-web`**: React/Vite Static Site with automatic SPA rewrite routing (`/* -> /index.html`).
3. **`aegis-postgres`**: Render Managed PostgreSQL database with automatic connection string linking.

### Steps:
1. Push this repository to your GitHub account.
2. In the [Render Dashboard](https://dashboard.render.com), click **New +** -> **Blueprint**.
3. Select your repository. Render will automatically detect `render.yaml`.
4. Review the provisioned resources:
   * **`aegis-ai-api`** (Web Service)
   * **`aegis-ai-web`** (Static Site)
   * **`aegis-postgres`** (PostgreSQL)
5. Click **Apply**.
6. Set the two synced environment variables in Render:
   * On **`aegis-ai-web`**:
     * `VITE_API_BASE_URL`: `https://aegis-ai-api.onrender.com`
   * On **`aegis-ai-api`**:
     * `CORS_ALLOWED_ORIGINS`: `https://aegis-ai-web.onrender.com,http://localhost:5173`
     * `REDIS_URL`: Your managed Redis connection string (e.g. from [Upstash](https://upstash.com)).

---

## 3. Option 2: Manual Service Creation on Render

### Step A: Database Provisioning & Migrations
1. In Render, create **New +** -> **PostgreSQL**.
   * Name: `aegis-postgres`
   * Database: `aegis`
   * User: `postgres`
2. Once created, copy the **Internal Database URL** (or External for local migrations).
3. Apply database migrations:
   ```bash
   DATABASE_URL="<your_database_url>" uv run alembic upgrade head
   ```
4. Confirm current migration head:
   ```bash
   DATABASE_URL="<your_database_url>" uv run alembic current
   # Expected: 0005_phase7_autonomy_reliability (head)
   ```

### Step B: Backend Web Service (`aegis-ai-api`)
1. In Render, create **New +** -> **Web Service**.
2. Connect your GitHub repository.
3. Settings:
   * **Name**: `aegis-ai-api`
   * **Language**: `Docker`
   * **Dockerfile Path**: `infrastructure/docker/Dockerfile`
   * **Docker Context**: `.` (Repository root)
   * **Health Check Path**: `/api/v1/health`
4. Environment Variables:
   * `ENVIRONMENT`: `production`
   * `DATABASE_URL`: Linked from `aegis-postgres`
   * `REDIS_URL`: `redis://...` (or Upstash `rediss://...`)
   * `CORS_ALLOWED_ORIGINS`: `https://aegis-ai-web.onrender.com,http://localhost:5173`
   * `ALLOWED_HOSTS`: `*`
   * `OBJECT_STORAGE_ENDPOINT`: `https://mock-storage.internal` (or Cloudflare R2 / AWS S3)
   * `OBJECT_STORAGE_BUCKET`: `aegis-data`
   * `OBJECT_STORAGE_ACCESS_KEY`: `render`
   * `OBJECT_STORAGE_SECRET_KEY`: `rendersecret`
   * `OBJECT_STORAGE_REGION`: `us-east-1`
   * `OBJECT_STORAGE_SECURE`: `false`

### Step C: Frontend Static Site (`aegis-ai-web`)
1. In Render, create **New +** -> **Static Site**.
2. Connect your GitHub repository.
3. Settings:
   * **Name**: `aegis-ai-web`
   * **Root Directory**: `apps/web`
   * **Build Command**: `npm install && npm run build`
   * **Publish Directory**: `dist`
4. In **Redirects / Rewrites**:
   * **Type**: `Rewrite`
   * **Source**: `/*`
   * **Destination**: `/index.html`
5. Environment Variables:
   * `VITE_API_BASE_URL`: `https://aegis-ai-api.onrender.com`

---

## 4. Verification & Health Checks

Verify your deployed API endpoints:

```bash
# Liveness Check
curl -s https://aegis-ai-api.onrender.com/api/v1/health
# {"status":"ok","service":"AEGIS AI","version":"0.1.0"}

# Readiness Check (Verifies Postgres, Redis, Storage)
curl -s https://aegis-ai-api.onrender.com/api/v1/ready

# AI Trust Plane & LLM Firewall Check
curl -s https://aegis-ai-api.onrender.com/api/v1/ai/firewall/status

# AI Reliability Engine
curl -s https://aegis-ai-api.onrender.com/api/v1/ai/reliability \
  -H "X-Organization-ID: 088adce9-4d52-4a3d-9ceb-bccba54b3d2f"
```

---

## 5. Security & Safety Invariants

* **Non-Root Execution**: Runs under unprivileged user `aegis` (UID 1001).
* **No Arbitrary Shell or Docker Socket Exposure**: Closed sandbox model.
* **Firewall Enforced**: Invariant `AI -> Policy -> llmfirewall-core -> Sandbox -> Audit` is strictly enforced.
* **Tenant Isolation**: Protected by strict `X-Organization-ID` context boundaries.
