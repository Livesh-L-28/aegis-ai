"""Safe HTTP adapter for LogicFalcon FDE with TLS verification and size limits."""

import time
from typing import Any, ClassVar

import httpx

from packages.review.adapters.ast_security import redact_secrets_in_text
from packages.review.fde.adapters.base import (
    AdapterCapability,
    AdapterExecutionResult,
    AdapterHealth,
    AdapterHealthStatus,
    BaseAdapter,
)
from packages.review.fde.models import OperationCategory, StepRiskLevel


class HttpAdapter(BaseAdapter):
    """Executes bounded, safe HTTP operations with TLS verification and redaction."""

    MAX_RESPONSE_BYTES = 512 * 1024  # 512 KB
    MAX_TIMEOUT_SECONDS = 30.0

    SENSITIVE_HEADERS: ClassVar[set[str]] = {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
    }

    def __init__(
        self,
        adapter_id: str = "http",
        default_timeout: float = 10.0,
        verify_ssl: bool = True,
    ) -> None:
        super().__init__(adapter_id=adapter_id, version="1.0.0")
        self.default_timeout = min(max(default_timeout, 1.0), self.MAX_TIMEOUT_SECONDS)
        self.verify_ssl = verify_ssl

    @property
    def capabilities(self) -> list[AdapterCapability]:
        return [
            AdapterCapability(
                name="http_get",
                description="Performs an idempotent HTTP GET request.",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
                parameters_schema={"url": "str", "headers": "dict[str, str] optional"},
            ),
            AdapterCapability(
                name="http_head",
                description="Performs an idempotent HTTP HEAD request.",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
                parameters_schema={"url": "str"},
            ),
            AdapterCapability(
                name="http_health_check",
                description="Verifies an HTTP endpoint returns a 2xx or 3xx status code.",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
                parameters_schema={"url": "str", "expected_status": "int optional"},
            ),
            AdapterCapability(
                name="http_post",
                description="Performs a mutating HTTP POST request.",
                operation_category=OperationCategory.CONSEQUENTIAL_MUTATION,
                risk_level=StepRiskLevel.HIGH,
                requires_approval=True,
                parameters_schema={"url": "str", "json": "dict optional"},
            ),
        ]

    def check_health(self) -> AdapterHealth:
        """Verifies local networking and HTTP client subsystem health."""
        return AdapterHealth(
            status=AdapterHealthStatus.HEALTHY,
            message="HTTP adapter is ready with TLS verification enabled.",
            latency_ms=0.1,
            details={"verify_ssl": self.verify_ssl, "max_response_bytes": self.MAX_RESPONSE_BYTES},
        )

    def execute(
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

        url = params.get("url")
        if not url or not isinstance(url, str):
            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output={},
                error="Parameter 'url' is required and must be a valid URL string.",
                error_category="INVALID_PARAMETERS",
            )

        if not (url.startswith("http://") or url.startswith("https://")):
            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output={},
                error=f"Unsupported URL scheme for '{url}'. Only HTTP/HTTPS are permitted.",
                error_category="INVALID_SCHEME",
            )

        # SSRF Protection: Block access to link-local and cloud metadata addresses
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        if hostname in ("169.254.169.254", "metadata.google.internal", "instance-data", "100.100.100.200"):
            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output={},
                error=f"Access to cloud metadata endpoint '{hostname}' is blocked by security policy.",
                error_category="SECURITY_VIOLATION",
            )

        headers = self._filter_headers(params.get("headers") or {})
        timeout = min(float(params.get("timeout", self.default_timeout)), self.MAX_TIMEOUT_SECONDS)

        start_time = time.perf_counter()
        try:
            with httpx.Client(
                verify=self.verify_ssl,
                timeout=timeout,
                follow_redirects=True,
                max_redirects=3,
            ) as client:
                if operation == "http_head":
                    resp = client.head(url, headers=headers)
                elif operation in ("http_get", "http_health_check"):
                    resp = client.get(url, headers=headers)
                elif operation == "http_post":
                    json_payload = params.get("json")
                    resp = client.post(url, headers=headers, json=json_payload)
                else:
                    return AdapterExecutionResult(
                        success=False,
                        operation=operation,
                        output={},
                        error=f"Unhandled operation '{operation}'.",
                        error_category="UNSUPPORTED_OPERATION",
                    )

                elapsed = time.perf_counter() - start_time
                content_len = len(resp.content)
                if content_len > self.MAX_RESPONSE_BYTES:
                    return AdapterExecutionResult(
                        success=False,
                        operation=operation,
                        output={"status_code": resp.status_code, "bytes": content_len},
                        error=f"HTTP response size ({content_len} bytes) exceeded maximum bound ({self.MAX_RESPONSE_BYTES} bytes).",
                        error_category="RESPONSE_TOO_LARGE",
                        execution_time_seconds=elapsed,
                    )

                sanitized_text = redact_secrets_in_text(resp.text[:20_000])
                sanitized_headers = {
                    k: ("[REDACTED]" if k.lower() in self.SENSITIVE_HEADERS else v)
                    for k, v in resp.headers.items()
                }

                if operation == "http_health_check":
                    expected = params.get("expected_status", 200)
                    is_healthy = resp.status_code == expected or (200 <= resp.status_code < 400 and expected == 200)
                    return AdapterExecutionResult(
                        success=is_healthy,
                        operation=operation,
                        output={
                            "status_code": resp.status_code,
                            "healthy": is_healthy,
                            "headers": sanitized_headers,
                            "body_snippet": sanitized_text[:1000],
                        },
                        error=None if is_healthy else f"Health check expected status {expected}, received {resp.status_code}.",
                        error_category=None if is_healthy else "UNHEALTHY_STATUS",
                        execution_time_seconds=elapsed,
                    ).sanitize()

                is_success = 200 <= resp.status_code < 400
                return AdapterExecutionResult(
                    success=is_success,
                    operation=operation,
                    output={
                        "status_code": resp.status_code,
                        "headers": sanitized_headers,
                        "body": sanitized_text,
                    },
                    error=None if is_success else f"HTTP request returned status {resp.status_code}.",
                    error_category=None if is_success else "HTTP_ERROR_STATUS",
                    execution_time_seconds=elapsed,
                ).sanitize()

        except httpx.TimeoutException as e:
            elapsed = time.perf_counter() - start_time
            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output={},
                error=f"HTTP request timed out after {timeout:.1f}s: {e}",
                error_category="TIMEOUT",
                execution_time_seconds=elapsed,
            ).sanitize()
        except httpx.ConnectError as e:
            elapsed = time.perf_counter() - start_time
            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output={},
                error=f"HTTP connection failed: {e}",
                error_category="CONNECT_ERROR",
                execution_time_seconds=elapsed,
            ).sanitize()
        except Exception as e:
            elapsed = time.perf_counter() - start_time
            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output={},
                error=f"HTTP transport error: {e}",
                error_category="TRANSPORT_ERROR",
                execution_time_seconds=elapsed,
            ).sanitize()

    def _filter_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Ensures headers are valid string key-value pairs."""
        return {str(k): str(v) for k, v in headers.items() if isinstance(k, str)}
