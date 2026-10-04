"""LLMFirewall Integration and Adapter Layer for AEGIS Trust Plane."""

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

try:
    from llmfirewall import Firewall
    from llmfirewall.core.models import Action as LLMFirewallAction
    _LLMFIREWALL_AVAILABLE = True
except ImportError:
    Firewall = None  # type: ignore[assignment, misc]
    LLMFirewallAction = None  # type: ignore[assignment, misc]
    _LLMFIREWALL_AVAILABLE = False

from packages.logging.logger import get_logger

logger = get_logger("aegis.security.llm_firewall")


class FirewallDecisionAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    WARN = "warn"


class FirewallFinding(BaseModel):
    detector_name: str
    threat_type: str
    description: str
    severity: str
    confidence: float = 1.0
    matched_text: str | None = None


class FirewallScanResult(BaseModel):
    allowed: bool
    action: FirewallDecisionAction
    reason: str
    risk_score: float = 0.0
    findings: list[FirewallFinding] = Field(default_factory=list)
    sanitized_text: str | None = None
    execution_time_ms: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolFirewallResult(BaseModel):
    allowed: bool
    action: FirewallDecisionAction
    tool_name: str
    reason: str
    risk_score: float = 0.0
    findings: list[FirewallFinding] = Field(default_factory=list)
    execution_time_ms: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class LLMFirewall(ABC):
    """Abstract interface for LLM Security Firewall."""

    @abstractmethod
    def inspect_prompt(
        self,
        prompt: str,
        user_id: str | None = None,
        session_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> FirewallScanResult:
        """Inspect and sanitize input prompts against prompt injection, jailbreaks, and sensitive data."""
        pass

    @abstractmethod
    def inspect_output(
        self,
        generation: str,
        user_id: str | None = None,
        session_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> FirewallScanResult:
        """Inspect model generation against leakage, hallucinations, and safety violations."""
        pass

    @abstractmethod
    def inspect_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        user_id: str | None = None,
        session_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> ToolFirewallResult:
        """Inspect tool execution request against unsafe parameters and malicious commands."""
        pass

    @abstractmethod
    def is_healthy(self) -> bool:
        """Check if firewall engine is active and operational."""
        pass


class LLMFirewallCoreAdapter(LLMFirewall):
    """First-class adapter connecting AEGIS Trust Plane directly to llmfirewall-core."""

    def __init__(self, fail_closed: bool = True) -> None:
        self.fail_closed = fail_closed
        self._firewall: Any = None
        self._version = "1.0.0"
        self._initialize()

    def _initialize(self) -> None:
        if _LLMFIREWALL_AVAILABLE and Firewall is not None:
            try:
                self._firewall = Firewall()
                logger.info("llmfirewall-core initialized successfully (version %s)", self._version)
            except Exception as exc:
                logger.error("Failed to instantiate llmfirewall-core: %s", exc)
                self._firewall = None
        else:
            logger.warning("llmfirewall-core package is not installed or available")
            self._firewall = None

    def is_healthy(self) -> bool:
        return self._firewall is not None

    def health_status(self) -> dict[str, Any]:
        """Operational firewall health metrics without leaking security rules."""
        healthy = self.is_healthy()
        return {
            "enabled": True,
            "healthy": healthy,
            "version": self._version,
            "policy_version": "default-v1",
        }


    def inspect_prompt(
        self,
        prompt: str,
        user_id: str | None = None,
        session_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> FirewallScanResult:
        if not self.is_healthy():
            if self.fail_closed:
                return FirewallScanResult(
                    allowed=False,
                    action=FirewallDecisionAction.BLOCK,
                    reason="LLM Firewall is unavailable; failing closed for safety.",
                    findings=[
                        FirewallFinding(
                            detector_name="system",
                            threat_type="firewall_unavailable",
                            description="Firewall core engine unavailable",
                            severity="CRITICAL",
                        )
                    ],
                )
            return FirewallScanResult(allowed=True, action=FirewallDecisionAction.ALLOW, reason="Firewall bypassed")

        try:
            res = self._firewall.check_prompt(
                prompt=prompt, user_id=user_id, session_id=session_id, context=context
            )
            # Map LLMFirewall action
            llm_action_name = getattr(res.decision.action, "name", "BLOCK")
            if llm_action_name == "ALLOW":
                action = FirewallDecisionAction.ALLOW
                is_allow = True
            elif llm_action_name == "REDACT":
                action = FirewallDecisionAction.REDACT
                is_allow = True  # Allowed with sanitized/redacted text
            elif llm_action_name == "WARN":
                action = FirewallDecisionAction.WARN
                is_allow = True
            else:
                action = FirewallDecisionAction.BLOCK
                is_allow = False


            findings = [
                FirewallFinding(
                    detector_name=getattr(f, "detector_name", "unknown"),
                    threat_type=str(getattr(f, "threat_type", "unknown")),
                    description=getattr(f, "description", ""),
                    severity=str(getattr(f, "severity", "medium")),
                    confidence=float(getattr(f, "confidence", 1.0)),
                    matched_text=getattr(f, "matched_text", None),
                )
                for f in (res.findings or [])
            ]

            return FirewallScanResult(
                allowed=is_allow,
                action=action,
                reason=res.decision.reason,
                risk_score=float(getattr(res.risk_score, "score", 0.0)),
                findings=findings,
                sanitized_text=getattr(res, "processed_text", prompt),
                execution_time_ms=float(getattr(res, "execution_time_ms", 0.0)),
                metadata={"policy_id": getattr(res.decision, "policy_id", "")},
            )
        except Exception as exc:
            logger.error("Error executing check_prompt in llmfirewall-core: %s", exc)
            if self.fail_closed:
                return FirewallScanResult(
                    allowed=False,
                    action=FirewallDecisionAction.BLOCK,
                    reason=f"Firewall execution error: {exc}",
                )
            return FirewallScanResult(allowed=True, action=FirewallDecisionAction.ALLOW, reason="Error bypassed")

    def inspect_output(
        self,
        generation: str,
        user_id: str | None = None,
        session_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> FirewallScanResult:
        if not self.is_healthy():
            if self.fail_closed:
                return FirewallScanResult(
                    allowed=False,
                    action=FirewallDecisionAction.BLOCK,
                    reason="LLM Firewall is unavailable; failing closed for safety.",
                )
            return FirewallScanResult(allowed=True, action=FirewallDecisionAction.ALLOW, reason="Firewall bypassed")

        try:
            res = self._firewall.check_output(
                generation=generation, user_id=user_id, session_id=session_id, context=context
            )
            llm_action_name = getattr(res.decision.action, "name", "BLOCK")
            if llm_action_name == "ALLOW":
                action = FirewallDecisionAction.ALLOW
                is_allow = True
            elif llm_action_name == "REDACT":
                action = FirewallDecisionAction.REDACT
                is_allow = True
            elif llm_action_name == "WARN":
                action = FirewallDecisionAction.WARN
                is_allow = True
            else:
                action = FirewallDecisionAction.BLOCK
                is_allow = False


            findings = [
                FirewallFinding(
                    detector_name=getattr(f, "detector_name", "unknown"),
                    threat_type=str(getattr(f, "threat_type", "unknown")),
                    description=getattr(f, "description", ""),
                    severity=str(getattr(f, "severity", "medium")),
                    confidence=float(getattr(f, "confidence", 1.0)),
                    matched_text=getattr(f, "matched_text", None),
                )
                for f in (res.findings or [])
            ]

            return FirewallScanResult(
                allowed=is_allow,
                action=action,
                reason=res.decision.reason,
                risk_score=float(getattr(res.risk_score, "score", 0.0)),
                findings=findings,
                sanitized_text=getattr(res, "processed_text", generation),
                execution_time_ms=float(getattr(res, "execution_time_ms", 0.0)),
                metadata={"policy_id": getattr(res.decision, "policy_id", "")},
            )
        except Exception as exc:
            logger.error("Error executing check_output in llmfirewall-core: %s", exc)
            if self.fail_closed:
                return FirewallScanResult(
                    allowed=False,
                    action=FirewallDecisionAction.BLOCK,
                    reason=f"Firewall output execution error: {exc}",
                )
            return FirewallScanResult(allowed=True, action=FirewallDecisionAction.ALLOW, reason="Error bypassed")

    def inspect_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        user_id: str | None = None,
        session_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> ToolFirewallResult:
        if not self.is_healthy():
            if self.fail_closed:
                return ToolFirewallResult(
                    allowed=False,
                    action=FirewallDecisionAction.BLOCK,
                    tool_name=tool_name,
                    reason="LLM Firewall is unavailable; failing closed on tool execution.",
                )
            return ToolFirewallResult(
                allowed=True,
                action=FirewallDecisionAction.ALLOW,
                tool_name=tool_name,
                reason="Firewall bypassed",
            )

        try:
            res = self._firewall.check_tool_call(
                tool_call_or_name=tool_name,
                arguments=arguments or {},
                user_id=user_id,
                session_id=session_id,
                context=context,
            )
            is_allow = res.is_allowed if hasattr(res, "is_allowed") else (res.action == LLMFirewallAction.ALLOW)
            action = FirewallDecisionAction.ALLOW if is_allow else FirewallDecisionAction.BLOCK

            findings = [
                FirewallFinding(
                    detector_name=getattr(f, "detector_name", "unknown"),
                    threat_type=str(getattr(f, "threat_type", "unknown")),
                    description=getattr(f, "description", ""),
                    severity=str(getattr(f, "severity", "medium")),
                    confidence=float(getattr(f, "confidence", 1.0)),
                    matched_text=getattr(f, "matched_text", None),
                )
                for f in (res.findings or [])
            ]

            return ToolFirewallResult(
                allowed=is_allow,
                action=action,
                tool_name=tool_name,
                reason=res.reason,
                risk_score=float(getattr(res.risk_score, "score", 0.0)),
                findings=findings,
                execution_time_ms=float(getattr(res, "execution_time_ms", 0.0)),
            )
        except Exception as exc:
            logger.error("Error executing check_tool_call in llmfirewall-core: %s", exc)
            if self.fail_closed:
                return ToolFirewallResult(
                    allowed=False,
                    action=FirewallDecisionAction.BLOCK,
                    tool_name=tool_name,
                    reason=f"Firewall tool execution error: {exc}",
                )
            return ToolFirewallResult(
                allowed=True,
                action=FirewallDecisionAction.ALLOW,
                tool_name=tool_name,
                reason="Error bypassed",
            )


# Default global instance
default_llm_firewall = LLMFirewallCoreAdapter()
