"""Phase 7 Continuous Reliability Engine: Alert Deduplication & SLO / Error Budget Management."""

import hashlib
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from packages.autonomy.domain.enums import SLOType
from packages.autonomy.domain.models import IncidentFingerprint, SLODefinition

try:
    from aireliability.resilience.circuit_breaker import CircuitBreaker as AIRelCircuitBreaker
    _AIRELIABILITY_CB_AVAILABLE = True
except ImportError:
    AIRelCircuitBreaker = None  # type: ignore[assignment, misc]
    _AIRELIABILITY_CB_AVAILABLE = False


class IncidentCorrelationEngine:
    """Computes deterministic incident fingerprints and groups repeated alerts."""

    @staticmethod
    def generate_fingerprint(
        environment: str,
        service: str,
        symptom: str,
        window_minutes: int = 15,
    ) -> IncidentFingerprint:
        # Time slot bucket
        now = datetime.now(UTC)
        slot = now.minute // window_minutes
        slot_key = f"{now.strftime('%Y-%m-%d-%H')}-{slot}"

        raw = f"{environment}:{service}:{symptom}:{slot_key}".encode()
        fingerprint_hash = hashlib.sha256(raw).hexdigest()

        return IncidentFingerprint(
            environment=environment,
            service=service,
            symptom=symptom,
            time_window_key=slot_key,
            fingerprint_hash=fingerprint_hash,
        )


class SLOGovernanceEngine:
    """Calculates error budgets, burn rates, and reliability metrics,
    backed by aireliability resilience mechanisms."""

    def __init__(self) -> None:
        self._slos: dict[str, SLODefinition] = {}
        self._circuit_breakers: dict[str, Any] = {}

    def register_slo(
        self,
        organization_id: UUID,
        service_name: str,
        slo_type: SLOType = SLOType.AVAILABILITY,
        target_percentage: float = 99.9,
    ) -> SLODefinition:
        key = f"{organization_id}:{service_name}:{slo_type.value}"
        slo = SLODefinition(
            organization_id=organization_id,
            service_name=service_name,
            slo_type=slo_type,
            target_percentage=target_percentage,
            current_percentage=100.0,
            error_budget_remaining=1.0,
            burn_rate=0.0,
        )
        self._slos[key] = slo
        return slo

    def evaluate_telemetry(
        self,
        organization_id: UUID,
        service_name: str,
        observed_availability: float,
        slo_type: SLOType = SLOType.AVAILABILITY,
    ) -> SLODefinition:
        key = f"{organization_id}:{service_name}:{slo_type.value}"
        slo = self._slos.get(key)
        if not slo:
            slo = self.register_slo(organization_id, service_name, slo_type)

        slo.current_percentage = observed_availability
        allowed_unavailability = 100.0 - slo.target_percentage
        actual_unavailability = max(0.0, 100.0 - observed_availability)

        if allowed_unavailability > 0:
            budget_consumed = actual_unavailability / allowed_unavailability
            slo.error_budget_remaining = max(0.0, 1.0 - budget_consumed)
            slo.burn_rate = round(actual_unavailability / allowed_unavailability, 2)
        else:
            slo.error_budget_remaining = 1.0 if observed_availability >= 100.0 else 0.0

        slo.is_breached = slo.current_percentage < slo.target_percentage
        slo.last_evaluated_at = datetime.now(UTC)
        return slo

    def should_freeze_autonomy(
        self,
        organization_id: UUID,
        service_name: str,
    ) -> bool:
        """If error budget is completely exhausted or burn rate is severe (> 10x), freeze autonomy.
        Also coordinates with aireliability circuit breaker for the service."""
        key = f"{organization_id}:{service_name}:{SLOType.AVAILABILITY.value}"
        slo = self._slos.get(key)
        if not slo:
            return False

        exhausted = slo.error_budget_remaining <= 0.0 or slo.burn_rate >= 10.0
        if _AIRELIABILITY_CB_AVAILABLE and AIRelCircuitBreaker is not None:
            cb = self._circuit_breakers.get(key)
            if not cb:
                cb = AIRelCircuitBreaker()
                self._circuit_breakers[key] = cb
            if exhausted:
                # If budget exhausted, set underlying breaker to open
                cb._state = "open"
            cb_open = getattr(cb, "state", "closed") == "open"
            return exhausted or cb_open

        return exhausted


default_slo_engine = SLOGovernanceEngine()
