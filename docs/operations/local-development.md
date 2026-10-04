# Local Development & Operations Guide

## Prerequisites
- Python 3.12+
- Docker & Docker Compose
- Make (optional, but recommended)

## Quick Start (Dockerized)

1. Clone repository and initialize environment:
   ```bash
   cp .env.example .env
   ```

2. Start the complete infrastructure stack:
   ```bash
   make up
   # Or: docker compose up -d
   ```

3. Run database migrations:
   ```bash
   make migrate
   # Or: alembic upgrade head
   ```

4. Verify health:
   ```bash
   curl http://localhost:8000/api/v1/health
   curl http://localhost:8000/api/v1/ready
   ```

## Local Development (Native Virtualenv)

1. Create and activate virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

2. Run quality checks and tests:
   ```bash
   make lint       # Runs ruff
   make typecheck  # Runs mypy
   make test       # Runs pytest
   ```

3. Launch development server:
   ```bash
   make dev
   ```
