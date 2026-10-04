# apps/worker
This directory is reserved for asynchronous background worker processes (e.g., Celery, ARQ, or custom async event workers).
In Phase 1, worker extension points and event contracts are established in `packages/events`.
Actual worker task runners will be implemented in subsequent phases.
