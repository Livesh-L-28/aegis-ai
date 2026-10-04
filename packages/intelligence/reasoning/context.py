"""Bounded reasoning context builder and deterministic context hashing."""

import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from packages.intelligence.evidence.models import EvidenceItem, TimelineEntry
from packages.intelligence.reasoning.hypotheses import HypothesisItem

PROMPTS_DIR = Path(__file__).parent / "prompts"
PROMPT_VERSION = "v1"


class BoundedReasoningContext(BaseModel):
    """Immutable bounded packet of verified evidence and prompts passed to the reasoning model."""

    incident_id: UUID
    investigation_id: UUID
    service_name: str | None
    incident_title: str
    incident_severity: str
    context_hash: str
    prompt_version: str = PROMPT_VERSION
    system_prompt: str
    user_prompt: str
    top_evidence: list[EvidenceItem]
    timeline: list[TimelineEntry]
    hypotheses: list[HypothesisItem]
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReasoningContextBuilder:
    """Builds a bounded, token-budgeted, deterministic context packet."""

    def __init__(self, max_evidence_items: int = 15, max_hypotheses: int = 5) -> None:
        self.max_evidence_items = max_evidence_items
        self.max_hypotheses = max_hypotheses
        self._load_prompts()

    def _load_prompts(self) -> None:
        sys_path = PROMPTS_DIR / "investigation_system.txt"
        user_path = PROMPTS_DIR / "investigation_user.txt"
        self.system_prompt_template = sys_path.read_text(encoding="utf-8")
        self.user_prompt_template = user_path.read_text(encoding="utf-8")

    def build_context(
        self,
        incident_id: UUID,
        investigation_id: UUID,
        incident_title: str,
        incident_description: str,
        incident_severity: str,
        detected_at: str,
        service_name: str | None,
        evidence: list[EvidenceItem],
        timeline: list[TimelineEntry],
        hypotheses: list[HypothesisItem],
        topology_summary: str = "Standard multi-service architecture",
    ) -> BoundedReasoningContext:
        """Constructs bounded reasoning context with deterministic hashing."""
        # Bound evidence to top-K by relevance score
        top_evidence = evidence[: self.max_evidence_items]
        bounded_hypotheses = hypotheses[: self.max_hypotheses]

        # Format timeline text
        timeline_lines = [
            f"- [{t.timestamp.isoformat()}] {t.title}: {t.description} (Evidence: {', '.join(str(e) for e in t.evidence_ids)})"
            for t in timeline[:10]
        ]
        timeline_summary = "\n".join(timeline_lines) or "No timeline events recorded."

        # Format evidence summary
        evidence_lines = [
            f"[{e.id}] Type={e.evidence_type.value} Service={e.service_name} Signal={e.signal} "
            f"Severity={e.severity.value} Score={e.relevance_score:.2f} Provenance='{e.provenance}' Content: {e.content}"
            for e in top_evidence
        ]
        evidence_summary = "\n".join(evidence_lines) or "No evidence items available."

        # Format hypotheses summary
        hypotheses_lines = [
            f"[{h.id}] Title: '{h.title}' (Status={h.status.value}, Score={h.score:.2f}) "
            f"Supporting Evidence IDs={json.dumps([str(i) for i in h.supporting_evidence_ids])} "
            f"Contradicting Evidence IDs={json.dumps([str(i) for i in h.contradicting_evidence_ids])}"
            for h in bounded_hypotheses
        ]
        hypotheses_summary = "\n".join(hypotheses_lines) or "No candidate hypotheses generated."

        # Interpolate user prompt
        user_prompt = self.user_prompt_template.format(
            incident_title=incident_title,
            service_name=service_name or "Unknown",
            severity=incident_severity,
            detected_at=detected_at,
            description=incident_description,
            timeline_summary=timeline_summary,
            evidence_summary=evidence_summary,
            hypotheses_summary=hypotheses_summary,
            topology_summary=topology_summary,
        )

        # Compute deterministic context hash
        hash_payload = {
            "incident_id": str(incident_id),
            "investigation_id": str(investigation_id),
            "evidence_ids": [str(e.id) for e in top_evidence],
            "hypotheses_ids": [str(h.id) for h in bounded_hypotheses],
            "prompt_version": PROMPT_VERSION,
        }
        context_hash = hashlib.sha256(
            json.dumps(hash_payload, sort_keys=True).encode("utf-8")
        ).hexdigest()

        return BoundedReasoningContext(
            incident_id=incident_id,
            investigation_id=investigation_id,
            service_name=service_name,
            incident_title=incident_title,
            incident_severity=incident_severity,
            context_hash=context_hash,
            prompt_version=PROMPT_VERSION,
            system_prompt=self.system_prompt_template,
            user_prompt=user_prompt,
            top_evidence=top_evidence,
            timeline=timeline,
            hypotheses=bounded_hypotheses,
        )
