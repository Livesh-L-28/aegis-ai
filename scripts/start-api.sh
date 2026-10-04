#!/bin/sh
set -e

# Default port to platform $PORT if provided (e.g. Render, Railway, Fly.io, Cloud Run), fallback to 8000
PORT="${PORT:-8000}"

echo "Starting AEGIS API on 0.0.0.0:${PORT}..."
exec uvicorn apps.api.app.main:app --host 0.0.0.0 --port "${PORT}"
