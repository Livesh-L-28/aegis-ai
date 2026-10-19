"""Extracts API contracts, database schema definitions, Alembic migrations, and configuration dependencies from repository source."""

import ast
import re
from typing import Any

from pydantic import BaseModel, Field

# Regex patterns for fast multi-language static extraction
API_ROUTE_RE = re.compile(
    r"""@(?:router|app)\.(get|post|put|delete|patch|options|head)\s*\(\s*["']([^"']+)["'](?:,\s*response_model=([a-zA-Z_$][\w$]*))?""",
    re.MULTILINE,
)
JS_FETCH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|apiClient\.(?:get|post|put|delete|patch))\s*\(\s*["'`](/[^"'`\s?#]+)["'`]"""
)
SQLALCHEMY_TABLE_RE = re.compile(r"""__tablename__\s*=\s*["']([^"']+)["']""")
ALEMBIC_REV_RE = re.compile(r"""revision(?:\s*:\s*str)?\s*=\s*["']([^"']+)["']""")
ALEMBIC_DOWN_REV_RE = re.compile(r"""down_revision(?:\s*:\s*(?:str|None))?\s*=\s*(?:["']([^"']+)["']|None)""")
ALEMBIC_CREATE_TABLE_RE = re.compile(r"""op\.create_table\s*\(\s*["']([^"']+)["']""")
ALEMBIC_ALTER_TABLE_RE = re.compile(r"""op\.(?:add_column|drop_column|alter_column|create_foreign_key)\s*\(\s*(?:["'][^"']+["']\s*,\s*)?["']([^"']+)["']""")

PY_ENV_RE = re.compile(r"""(?:os\.environ(?:\.get)?|os\.getenv)\s*\(\s*["']([A-Z0-9_]+)["']""")
JS_ENV_RE = re.compile(r"""process\.env\.([A-Z0-9_]+)""")


class APIEndpointContract(BaseModel):
    file_path: str
    http_method: str
    route_path: str
    handler_name: str
    line_number: int
    request_schema: str | None = None
    response_model: str | None = None
    auth_required: bool = True
    permissions: list[str] = Field(default_factory=list)


class APIClientReference(BaseModel):
    file_path: str
    http_method: str
    route_path: str
    line_number: int
    client_library: str = "fetch"


class DatabaseModelContract(BaseModel):
    file_path: str
    class_name: str
    table_name: str
    columns: list[str] = Field(default_factory=list)
    foreign_keys: list[str] = Field(default_factory=list)
    line_number: int


class MigrationContract(BaseModel):
    file_path: str
    revision_id: str
    down_revision_id: str | None = None
    tables_created: list[str] = Field(default_factory=list)
    tables_altered: list[str] = Field(default_factory=list)


class ConfigurationReference(BaseModel):
    file_path: str
    config_key: str
    line_number: int
    reference_type: str = "ENV_VAR"
    source_expression: str


class SystemIntelligenceReport(BaseModel):
    api_endpoints: list[APIEndpointContract] = Field(default_factory=list)
    client_api_calls: list[APIClientReference] = Field(default_factory=list)
    database_models: list[DatabaseModelContract] = Field(default_factory=list)
    migrations: list[MigrationContract] = Field(default_factory=list)
    config_references: list[ConfigurationReference] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SystemIntelligenceExtractor:
    """Extracts system-level contracts, models, migrations, and configs statically as data."""

    @classmethod
    def extract_from_file(cls, file_path: str, source_code: str) -> SystemIntelligenceReport:
        lower = file_path.lower()
        report = SystemIntelligenceReport()

        if lower.endswith(".py"):
            cls._extract_python(file_path, source_code, report)
        elif lower.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
            cls._extract_javascript_typescript(file_path, source_code, report)

        return report

    @classmethod
    def _extract_python(cls, file_path: str, source_code: str, report: SystemIntelligenceReport) -> None:
        lines = source_code.splitlines()

        # 1. API routes (FastAPI)
        for i, line in enumerate(lines):
            match = API_ROUTE_RE.search(line)
            if match:
                method = match.group(1).upper()
                route = match.group(2)
                resp_model = match.group(3)
                # Look ahead for def handler_name
                handler = "unknown_handler"
                for lookahead in lines[i + 1 : min(len(lines), i + 6)]:
                    m_def = re.match(r"""^(?:async\s+)?def\s+([a-zA-Z_$][\w$]*)\s*\(""", lookahead.strip())
                    if m_def:
                        handler = m_def.group(1)
                        break

                report.api_endpoints.append(
                    APIEndpointContract(
                        file_path=file_path,
                        http_method=method,
                        route_path=route,
                        handler_name=handler,
                        line_number=i + 1,
                        response_model=resp_model,
                    )
                )

        # 2. Database Models & Alembic Migrations
        if "migrations" in file_path.lower() or "alembic" in file_path.lower():
            rev_match = ALEMBIC_REV_RE.search(source_code)
            if rev_match:
                down_match = ALEMBIC_DOWN_REV_RE.search(source_code)
                created = ALEMBIC_CREATE_TABLE_RE.findall(source_code)
                altered = ALEMBIC_ALTER_TABLE_RE.findall(source_code)
                report.migrations.append(
                    MigrationContract(
                        file_path=file_path,
                        revision_id=rev_match.group(1),
                        down_revision_id=down_match.group(1) if down_match and down_match.group(1) else None,
                        tables_created=list(set(created)),
                        tables_altered=list(set(altered)),
                    )
                )

        # 3. SQLAlchemy Entities
        try:
            tree = ast.parse(source_code, filename=file_path)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    table_name: str | None = None
                    cols: list[str] = []
                    fks: list[str] = []
                    for item in node.body:
                        if isinstance(item, ast.Assign):
                            for target in item.targets:
                                if (
                                    isinstance(target, ast.Name)
                                    and target.id == "__tablename__"
                                    and isinstance(item.value, ast.Constant)
                                    and isinstance(item.value.value, str)
                                ):
                                    table_name = item.value.value
                        elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                            if (
                                item.target.id == "__tablename__"
                                and isinstance(item.value, ast.Constant)
                                and isinstance(item.value.value, str)
                            ):
                                table_name = item.value.value
                            elif item.target.id != "__tablename__":
                                cols.append(item.target.id)

                    if table_name:
                        report.database_models.append(
                            DatabaseModelContract(
                                file_path=file_path,
                                class_name=node.name,
                                table_name=table_name,
                                columns=cols,
                                foreign_keys=fks,
                                line_number=node.lineno,
                            )
                        )
        except Exception:
            pass

        # 4. Configuration references
        for i, line in enumerate(lines):
            for m in PY_ENV_RE.finditer(line):
                key = m.group(1)
                report.config_references.append(
                    ConfigurationReference(
                        file_path=file_path,
                        config_key=key,
                        line_number=i + 1,
                        reference_type="ENV_VAR",
                        source_expression=m.group(0),
                    )
                )

    @classmethod
    def _extract_javascript_typescript(cls, file_path: str, source_code: str, report: SystemIntelligenceReport) -> None:
        lines = source_code.splitlines()

        for i, line in enumerate(lines):
            # Client API calls
            for m in JS_FETCH_RE.finditer(line):
                route = m.group(1)
                method = "GET"
                if "post" in line.lower():
                    method = "POST"
                elif "put" in line.lower():
                    method = "PUT"
                elif "delete" in line.lower():
                    method = "DELETE"
                elif "patch" in line.lower():
                    method = "PATCH"

                report.client_api_calls.append(
                    APIClientReference(
                        file_path=file_path,
                        http_method=method,
                        route_path=route,
                        line_number=i + 1,
                    )
                )

            # Environment variables in JS/TS
            for m in JS_ENV_RE.finditer(line):
                key = m.group(1)
                report.config_references.append(
                    ConfigurationReference(
                        file_path=file_path,
                        config_key=key,
                        line_number=i + 1,
                        reference_type="ENV_VAR",
                        source_expression=m.group(0),
                    )
                )
