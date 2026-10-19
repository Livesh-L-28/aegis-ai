"""Root-cause analysis engine: generates and ranks competing evidence-grounded hypotheses."""

from packages.intelligence.debugging.models import (
    DebuggingEvidenceItem,
    FrameOriginType,
    HypothesisVerdict,
    NormalizedDebuggingIncident,
    RankedHypothesis,
    StackTraceFrame,
)
from packages.intelligence.reasoning.provider import MockReasoningProvider, ReasoningModelProvider


class RootCauseAnalyzer:
    """Evaluates technical evidence and localized frames to generate ranked competing hypotheses."""

    def __init__(self, llm_provider: ReasoningModelProvider | None = None) -> None:
        self.llm_provider = llm_provider or MockReasoningProvider()

    async def analyze_root_cause(
        self,
        incident: NormalizedDebuggingIncident,
        localized_frames: list[StackTraceFrame],
        evidence: list[DebuggingEvidenceItem],
    ) -> list[RankedHypothesis]:
        """Produces ranked root-cause hypotheses with traceable citations to evidence."""
        # Check for insufficient evidence
        internal_resolved = [f for f in localized_frames if f.is_resolved and f.origin == FrameOriginType.INTERNAL]
        if not internal_resolved and not incident.commit_sha and len(evidence) <= 1:
            return [
                RankedHypothesis(
                    title="Insufficient Evidence for Root Cause Determination",
                    description=(
                        "Unable to localize failure to repository source code. "
                        "No internal stack frames resolved against an indexed commit revision."
                    ),
                    verdict=HypothesisVerdict.INSUFFICIENT_EVIDENCE,
                    score=0.1,
                    confidence=0.1,
                    supporting_evidence_ids=[e.id for e in evidence],
                    reasoning_summary="Missing repository revision or stack trace precluded deterministic source correlation.",
                    assumptions=["Incident requires additional contextual metadata (commit_sha, internal frames, logs)."],
                    ranking_rationale="Insufficient evidence prevents establishing a verifiable hypothesis.",
                    verification_steps=[
                        "Provide the exact repository commit SHA where the failure occurred.",
                        "Provide an unstripped application stack trace showing internal package calls.",
                        "Supply execution logs or reproduction steps.",
                    ],
                )
            ]

        evidence_by_id = {e.id: e for e in evidence}
        hypotheses: list[RankedHypothesis] = []

        # Identify key localized frame (deepest internal frame)
        primary_frame: StackTraceFrame | None = internal_resolved[-1] if internal_resolved else None
        target_file = primary_frame.file_path if primary_frame else None
        target_symbol = primary_frame.matched_symbol if primary_frame else None

        exc_type = incident.exception_type.lower()
        exc_msg = incident.exception_message.lower()

        # ---------------------------------------------------------------------
        # Rule 1: Unhandled NoneType / Undefined Attribute Dereference
        # ---------------------------------------------------------------------
        if "nonetype" in exc_msg or "undefined" in exc_msg or "null" in exc_msg or "attributeerror" in exc_type:
            sup_ids = [
                e.id for e in evidence
                if e.evidence_type in ("FAILURE_SYMPTOM", "AST_SYMBOL", "SOURCE_FILE")
            ]
            hypotheses.append(
                RankedHypothesis(
                    title="Unexpected None/Null Value Dereferenced",
                    description=(
                        f"A function or variable evaluated to None/undefined prior to attribute access "
                        f"in {target_file or 'source'}."
                    ),
                    verdict=HypothesisVerdict.CONFIRMED if primary_frame else HypothesisVerdict.PLAUSIBLE,
                    score=0.92 if primary_frame else 0.70,
                    confidence=0.90 if primary_frame else 0.65,
                    supporting_evidence_ids=sup_ids,
                    affected_file=target_file,
                    affected_symbol=target_symbol,
                    reasoning_summary=(
                        f"Exception '{incident.exception_type}' indicates an object was accessed "
                        f"before existence or return-value checking at {target_file}:{primary_frame.line_number if primary_frame else 'unknown'}."
                    ),
                    assumptions=["The upstream supplier of the referenced variable returned None or empty."],
                    ranking_rationale="Directly matches Python/JavaScript null dereference signature in active frame.",
                    verification_steps=[
                        f"Inspect return values leading into {target_symbol or target_file}.",
                        "Verify optional/nullable handling on input arguments.",
                    ],
                )
            )

        # ---------------------------------------------------------------------
        # Rule 2: Database Schema or Column Name Drift
        # ---------------------------------------------------------------------
        db_evidence = [e for e in evidence if e.evidence_type in ("DATABASE_MODEL", "MIGRATION")]
        if db_evidence or "column" in exc_msg or "relation" in exc_msg or "table" in exc_msg or "operationalerror" in exc_type:
            sup_ids = [e.id for e in db_evidence] + [e.id for e in evidence if e.evidence_type == "FAILURE_SYMPTOM"]
            hypotheses.append(
                RankedHypothesis(
                    title="Database Schema Definition or Migration Mismatch",
                    description="Query failed due to missing or mismatched table, column, or constraint in persistent schema.",
                    verdict=HypothesisVerdict.CONFIRMED if db_evidence else HypothesisVerdict.PLAUSIBLE,
                    score=0.88,
                    confidence=0.85,
                    supporting_evidence_ids=sup_ids,
                    affected_file=db_evidence[0].file_path if db_evidence else target_file,
                    affected_symbol=db_evidence[0].symbol_name if db_evidence else None,
                    reasoning_summary="Error pattern and schema models indicate persistent schema divergence.",
                    assumptions=["Database migration has not been applied or model column name does not match database."],
                    ranking_rationale="High technical alignment between exception message and database model definitions.",
                    verification_steps=[
                        "Compare SQLAlchemy entity column definitions against current database schema.",
                        "Inspect pending Alembic migrations.",
                    ],
                )
            )

        # ---------------------------------------------------------------------
        # Rule 3: Missing or Unset Configuration Environment Variable
        # ---------------------------------------------------------------------
        cfg_evidence = [e for e in evidence if e.evidence_type == "CONFIGURATION"]
        if cfg_evidence or "keyerror" in exc_type or "env" in exc_msg or "config" in exc_msg:
            sup_ids = [e.id for e in cfg_evidence] + [e.id for e in evidence if e.evidence_type == "FAILURE_SYMPTOM"]
            cfg_name = cfg_evidence[0].symbol_name if cfg_evidence else "environment variable"
            hypotheses.append(
                RankedHypothesis(
                    title=f"Missing Required Configuration Key '{cfg_name}'",
                    description=f"Process attempted to read unset configuration key '{cfg_name}' without fallback.",
                    verdict=HypothesisVerdict.CONFIRMED if cfg_evidence else HypothesisVerdict.PLAUSIBLE,
                    score=0.85,
                    confidence=0.80,
                    supporting_evidence_ids=sup_ids,
                    affected_file=cfg_evidence[0].file_path if cfg_evidence else target_file,
                    affected_symbol=cfg_name,
                    reasoning_summary=f"KeyError or lookup failure accessing required environment setting '{cfg_name}'.",
                    assumptions=["Configuration key is expected in deployment environment but missing from runtime."],
                    ranking_rationale="Directly maps lookup error to indexed configuration references.",
                    verification_steps=[
                        f"Check presence of environment variable '{cfg_name}' in runtime container/environment.",
                        "Add sensible default value or explicit missing configuration validation.",
                    ],
                )
            )

        # ---------------------------------------------------------------------
        # Rule 4: API Endpoint Contract or Request Validation Failure
        # ---------------------------------------------------------------------
        api_evidence = [e for e in evidence if e.evidence_type == "API_CONTRACT"]
        if api_evidence or "validationerror" in exc_type or "422" in exc_msg or "404" in exc_msg or incident.route:
            sup_ids = [e.id for e in api_evidence] + [e.id for e in evidence if e.evidence_type == "FAILURE_SYMPTOM"]
            hypotheses.append(
                RankedHypothesis(
                    title="API Contract or Request Payload Schema Mismatch",
                    description="Request parameters or client payload did not conform to the expected API schema contract.",
                    verdict=HypothesisVerdict.PLAUSIBLE,
                    score=0.75,
                    confidence=0.75,
                    supporting_evidence_ids=sup_ids,
                    affected_file=api_evidence[0].file_path if api_evidence else target_file,
                    affected_symbol=api_evidence[0].symbol_name if api_evidence else None,
                    reasoning_summary=f"FastAPI route contract or validation failed for endpoint '{incident.route or 'handler'}'.",
                    assumptions=["Client submitted payload with missing or improperly typed fields."],
                    ranking_rationale="Correlated incident route to indexed FastAPI endpoint definitions.",
                    verification_steps=[
                        "Inspect client request JSON payload against FastAPI Pydantic schema.",
                        "Run integration test matching the target route.",
                    ],
                )
            )

        # ---------------------------------------------------------------------
        # Fallback Hypothesis: Unhandled Exception in Localized Function
        # ---------------------------------------------------------------------
        if not hypotheses and primary_frame:
            sup_ids = [e.id for e in evidence if e.evidence_type in ("FAILURE_SYMPTOM", "AST_SYMBOL", "SOURCE_FILE")]
            hypotheses.append(
                RankedHypothesis(
                    title=f"Unhandled Exception in '{primary_frame.function_name}'",
                    description=f"Function {primary_frame.function_name} in {primary_frame.file_path} failed during execution.",
                    verdict=HypothesisVerdict.PLAUSIBLE,
                    score=0.70,
                    confidence=0.65,
                    supporting_evidence_ids=sup_ids,
                    affected_file=primary_frame.file_path,
                    affected_symbol=primary_frame.matched_symbol or primary_frame.function_name,
                    reasoning_summary=f"Traceback localized execution to {primary_frame.file_path}:{primary_frame.line_number}.",
                    assumptions=["Input parameters triggered an untested boundary condition."],
                    ranking_rationale="Execution halted in localized internal frame.",
                    verification_steps=[
                        f"Run unit tests for {primary_frame.file_path}.",
                        "Inspect input parameters at time of invocation.",
                    ],
                )
            )

        # Stage 2: Factuality validation check
        # Ensure all supporting evidence IDs actually exist in the evidence packet
        valid_ev_ids = set(evidence_by_id.keys())
        for hyp in hypotheses:
            hyp.supporting_evidence_ids = [eid for eid in hyp.supporting_evidence_ids if eid in valid_ev_ids]
            hyp.contradicting_evidence_ids = [eid for eid in hyp.contradicting_evidence_ids if eid in valid_ev_ids]

        # Sort hypotheses deterministically by score descending
        hypotheses.sort(key=lambda h: (h.score, h.confidence), reverse=True)
        return hypotheses
