"""Declarative postcondition verifier for LogicFalcon FDE."""

import json
import socket
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from packages.review.adapters.ast_security import redact_secrets_in_text
from packages.review.fde.adapters.base import AdapterExecutionResult


class VerificationOutcome(StrEnum):
    VERIFIED_SUCCESS = "VERIFIED_SUCCESS"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class PostconditionResult:
    """Outcome of a single postcondition evaluation."""

    assertion_type: str
    target: str
    expected: Any
    actual: Any
    outcome: VerificationOutcome
    details: str = ""


class PostconditionVerifier:
    """Evaluates declarative postconditions against execution outcomes and live targets."""

    @staticmethod
    def verify_http_status(
        result: AdapterExecutionResult,
        expected_status: int = 200,
    ) -> PostconditionResult:
        """Verifies that an HTTP operation returned the expected status code."""
        if not isinstance(result.output, dict):
            return PostconditionResult(
                assertion_type="http_status",
                target=result.operation,
                expected=expected_status,
                actual=None,
                outcome=VerificationOutcome.INCONCLUSIVE,
                details="Output payload is not a dictionary.",
            )

        actual_status = result.output.get("status_code")
        if actual_status is None:
            return PostconditionResult(
                assertion_type="http_status",
                target=result.operation,
                expected=expected_status,
                actual=None,
                outcome=VerificationOutcome.INCONCLUSIVE,
                details="Missing status_code in HTTP output.",
            )

        success = actual_status == expected_status
        return PostconditionResult(
            assertion_type="http_status",
            target=result.operation,
            expected=expected_status,
            actual=actual_status,
            outcome=VerificationOutcome.VERIFIED_SUCCESS if success else VerificationOutcome.FAILED,
            details=f"Expected status {expected_status}, received {actual_status}.",
        )

    @staticmethod
    def verify_json_body_contains(
        result: AdapterExecutionResult,
        key: str,
        expected_value: Any = None,
    ) -> PostconditionResult:
        """Verifies that a JSON response body contains a specific key or key-value pair."""
        body = result.output.get("body") if isinstance(result.output, dict) else None
        if not body:
            return PostconditionResult(
                assertion_type="json_body_contains",
                target=key,
                expected=expected_value or "present",
                actual=None,
                outcome=VerificationOutcome.FAILED,
                details="No HTTP response body found in output.",
            )

        try:
            parsed = json.loads(body) if isinstance(body, str) else body
            if isinstance(parsed, dict) and key in parsed:
                actual_val = parsed[key]
                if expected_value is None or actual_val == expected_value:
                    return PostconditionResult(
                        assertion_type="json_body_contains",
                        target=key,
                        expected=expected_value or "present",
                        actual=actual_val,
                        outcome=VerificationOutcome.VERIFIED_SUCCESS,
                        details=f"Key '{key}' matched expected value.",
                    )
                return PostconditionResult(
                    assertion_type="json_body_contains",
                    target=key,
                    expected=expected_value,
                    actual=actual_val,
                    outcome=VerificationOutcome.FAILED,
                    details=f"Key '{key}' value mismatch: expected {expected_value}, got {actual_val}.",
                )
            return PostconditionResult(
                assertion_type="json_body_contains",
                target=key,
                expected=expected_value or "present",
                actual=None,
                outcome=VerificationOutcome.FAILED,
                details=f"Key '{key}' not found in JSON body.",
            )
        except Exception as e:
            return PostconditionResult(
                assertion_type="json_body_contains",
                target=key,
                expected=expected_value or "present",
                actual=None,
                outcome=VerificationOutcome.INCONCLUSIVE,
                details=f"Failed to parse body as JSON: {e}",
            )

    @staticmethod
    def verify_tcp_port_open(host: str, port: int, timeout: float = 3.0) -> PostconditionResult:
        """Verifies that a target TCP port is open and accepting connections."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            res = sock.connect_ex((host, port))
            is_open = res == 0
            return PostconditionResult(
                assertion_type="tcp_port_open",
                target=f"{host}:{port}",
                expected="OPEN (0)",
                actual=f"{'OPEN' if is_open else 'CLOSED'} ({res})",
                outcome=VerificationOutcome.VERIFIED_SUCCESS if is_open else VerificationOutcome.FAILED,
                details="TCP connection established." if is_open else f"TCP connection failed with errno {res}.",
            )
        except Exception as e:
            clean_err = redact_secrets_in_text(str(e))
            return PostconditionResult(
                assertion_type="tcp_port_open",
                target=f"{host}:{port}",
                expected="OPEN",
                actual=clean_err,
                outcome=VerificationOutcome.INCONCLUSIVE,
                details=f"Socket error: {clean_err}",
            )
        finally:
            sock.close()
