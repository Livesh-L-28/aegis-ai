.PHONY: install dev up down logs test lint typecheck migrate migration format security ci clean

PYTHON := .venv/bin/python
PIP := .venv/bin/pip
RUFF := .venv/bin/ruff
MYPY := .venv/bin/mypy
PYTEST := .venv/bin/pytest
ALEMBIC := .venv/bin/alembic

install:
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"

dev:
	uvicorn apps.api.app.main:app --host 0.0.0.0 --port 8000 --reload

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

test:
	$(PYTEST) -v --cov=apps --cov=packages tests/

lint:
	$(RUFF) check .

format:
	$(RUFF) format .

typecheck:
	$(MYPY) --explicit-package-bases apps packages tests

migrate:
	$(ALEMBIC) upgrade head

migration:
	@read -p "Enter migration message: " msg; \
	$(ALEMBIC) revision --autogenerate -m "$$msg"

security:
	$(PYTEST) tests/security/

ci: lint typecheck test security

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
