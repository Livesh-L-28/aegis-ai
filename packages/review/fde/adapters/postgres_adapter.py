"""Safe, read-only PostgreSQL adapter for LogicFalcon FDE with parameterized queries and credential masking."""

import asyncio
import contextlib
import re
import time
from typing import Any
from urllib.parse import urlparse

import asyncpg

from packages.review.fde.adapters.base import (
    AdapterCapability,
    AdapterExecutionResult,
    AdapterHealth,
    AdapterHealthStatus,
    BaseAdapter,
)
from packages.review.fde.models import OperationCategory, StepRiskLevel


class PostgresAdapter(BaseAdapter):
    """Executes safe, read-only PostgreSQL queries with credential protection and timeouts."""

    DEFAULT_TIMEOUT_SECONDS = 5.0
    MAX_TIMEOUT_SECONDS = 20.0
    SAFE_IDENTIFIER_REGEX = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

    # Guard against mutating SQL keywords in read-only adapter
    MUTATING_SQL_REGEX = re.compile(
        r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|GRANT|REVOKE)\b",
        re.IGNORECASE,
    )

    def __init__(
        self,
        connection_url: str | None = None,
        adapter_id: str = "postgres",
    ) -> None:
        super().__init__(adapter_id=adapter_id, version="1.0.0")
        self._connection_url = connection_url

    @property
    def capabilities(self) -> list[AdapterCapability]:
        return [
            AdapterCapability(
                name="check_connection",
                description="Verifies TCP connectivity and authentication with PostgreSQL database.",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
                parameters_schema={"connection_url": "str optional"},
            ),
            AdapterCapability(
                name="query_version",
                description="Fetches PostgreSQL server version string.",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
            ),
            AdapterCapability(
                name="check_table_exists",
                description="Verifies table existence via parameterized query to information_schema.",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
                parameters_schema={"table_name": "str", "schema": "str optional"},
            ),
            AdapterCapability(
                name="count_table_rows",
                description="Returns row count for an authorized table.",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
                parameters_schema={"table_name": "str", "schema": "str optional"},
            ),
        ]

    def _mask_url(self, url: str) -> str:
        """Masks password and credentials in database connection URI."""
        try:
            parsed = urlparse(url)
            if parsed.password:
                netloc = f"{parsed.username}:[REDACTED]@{parsed.hostname}"
                if parsed.port:
                    netloc += f":{parsed.port}"
                return parsed._replace(netloc=netloc).geturl()
            return url
        except Exception:
            return "[REDACTED_URL]"

    def check_health(self) -> AdapterHealth:
        """Performs non-mutating connection check if URL configured."""
        if not self._connection_url:
            return AdapterHealth(
                status=AdapterHealthStatus.DEGRADED,
                message="PostgreSQL adapter is registered but no connection URL is configured.",
            )

        start_time = time.perf_counter()
        try:
            res = self.execute("check_connection", {"connection_url": self._connection_url, "timeout": 3.0})
            elapsed = (time.perf_counter() - start_time) * 1000
            if res.success:
                return AdapterHealth(
                    status=AdapterHealthStatus.HEALTHY,
                    message="Database connection verified successfully.",
                    latency_ms=elapsed,
                )
            return AdapterHealth(
                status=AdapterHealthStatus.UNAVAILABLE,
                message=f"Database unreachable: {res.error}",
                latency_ms=elapsed,
            )
        except Exception as e:
            return AdapterHealth(
                status=AdapterHealthStatus.UNAVAILABLE,
                message=f"Health probe error: {e}",
            )

    def execute(
        self,
        operation: str,
        params: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> AdapterExecutionResult:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                return executor.submit(lambda: asyncio.run(self.execute_async(operation, params, context))).result()
        return asyncio.run(self.execute_async(operation, params, context))

    async def execute_async(
        self,
        operation: str,
        params: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> AdapterExecutionResult:
        if not self.supports(operation):
            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output={},
                error=f"Operation '{operation}' is not supported by {self.adapter_id}.",
                error_category="UNSUPPORTED_OPERATION",
            )

        url = params.get("connection_url") or self._connection_url
        if not url:
            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output={},
                error="Database 'connection_url' parameter is required.",
                error_category="MISSING_CONNECTION_URL",
            )

        if operation in ("check_table_exists", "count_table_rows"):
            tbl = params.get("table_name")
            schema = params.get("schema", "public")
            if not tbl or not isinstance(tbl, str) or not self.SAFE_IDENTIFIER_REGEX.match(tbl):
                return AdapterExecutionResult(
                    success=False,
                    operation=operation,
                    output={},
                    error=f"Invalid or missing table_name '{tbl}'.",
                    error_category="INVALID_IDENTIFIER",
                )
            if not isinstance(schema, str) or not self.SAFE_IDENTIFIER_REGEX.match(schema):
                return AdapterExecutionResult(
                    success=False,
                    operation=operation,
                    output={},
                    error=f"Invalid schema name '{schema}'.",
                    error_category="INVALID_IDENTIFIER",
                )

        timeout = min(float(params.get("timeout", self.DEFAULT_TIMEOUT_SECONDS)), self.MAX_TIMEOUT_SECONDS)
        start_time = time.perf_counter()
        try:
            result = await self._execute_async(operation, url, params, timeout)
            result.execution_time_seconds = time.perf_counter() - start_time
            return result.sanitize()
        except TimeoutError:
            elapsed = time.perf_counter() - start_time
            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output={},
                error=f"Database operation timed out after {timeout:.1f}s.",
                error_category="TIMEOUT",
                execution_time_seconds=elapsed,
            ).sanitize()
        except Exception as e:
            elapsed = time.perf_counter() - start_time
            clean_err = self._mask_url(str(e))
            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output={},
                error=f"Database error: {clean_err}",
                error_category="DATABASE_ERROR",
                execution_time_seconds=elapsed,
            ).sanitize()

    async def _execute_async(
        self,
        operation: str,
        url: str,
        params: dict[str, Any],
        timeout: float,
    ) -> AdapterExecutionResult:
        conn = None
        try:
            conn = await asyncio.wait_for(asyncpg.connect(url), timeout=timeout)

            if operation == "check_connection":
                row = await asyncio.wait_for(conn.fetchrow("SELECT 1 as alive;"), timeout=timeout)
                return AdapterExecutionResult(
                    success=row is not None and row["alive"] == 1,
                    operation=operation,
                    output={"alive": True, "masked_url": self._mask_url(url)},
                )

            elif operation == "query_version":
                ver = await asyncio.wait_for(conn.fetchval("SELECT version();"), timeout=timeout)
                return AdapterExecutionResult(
                    success=True,
                    operation=operation,
                    output={"version": ver},
                )

            elif operation == "check_table_exists":
                tbl = params.get("table_name")
                schema = params.get("schema", "public")
                if not tbl or not self.SAFE_IDENTIFIER_REGEX.match(tbl):
                    return AdapterExecutionResult(
                        success=False,
                        operation=operation,
                        output={},
                        error=f"Invalid or missing table_name '{tbl}'.",
                        error_category="INVALID_IDENTIFIER",
                    )
                query = (
                    "SELECT EXISTS ("
                    "  SELECT 1 FROM information_schema.tables "
                    "  WHERE table_schema = $1 AND table_name = $2"
                    ") as tbl_exists;"
                )
                exists = await asyncio.wait_for(conn.fetchval(query, schema, tbl), timeout=timeout)
                return AdapterExecutionResult(
                    success=bool(exists),
                    operation=operation,
                    output={"table_name": tbl, "schema": schema, "exists": bool(exists)},
                    error=None if exists else f"Table '{schema}.{tbl}' does not exist.",
                    error_category=None if exists else "TABLE_NOT_FOUND",
                )

            elif operation == "count_table_rows":
                tbl = params.get("table_name")
                schema = params.get("schema", "public")
                if not tbl or not self.SAFE_IDENTIFIER_REGEX.match(tbl):
                    return AdapterExecutionResult(
                        success=False,
                        operation=operation,
                        output={},
                        error=f"Invalid or missing table_name '{tbl}'.",
                        error_category="INVALID_IDENTIFIER",
                    )
                if not self.SAFE_IDENTIFIER_REGEX.match(schema):
                    return AdapterExecutionResult(
                        success=False,
                        operation=operation,
                        output={},
                        error=f"Invalid schema name '{schema}'.",
                        error_category="INVALID_IDENTIFIER",
                    )
                # Schema and table identifiers are strictly validated against regex
                query = f'SELECT count(*) FROM "{schema}"."{tbl}";'
                count = await asyncio.wait_for(conn.fetchval(query), timeout=timeout)
                return AdapterExecutionResult(
                    success=True,
                    operation=operation,
                    output={"table_name": tbl, "schema": schema, "row_count": count},
                )

            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output={},
                error=f"Unsupported operation '{operation}'.",
                error_category="UNSUPPORTED_OPERATION",
            )
        finally:
            if conn:
                with contextlib.suppress(Exception):
                    await conn.close()
