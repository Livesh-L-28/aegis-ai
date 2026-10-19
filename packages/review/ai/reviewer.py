"""Repository-aware AI code review engine with firewall, reliability scoring, and validation."""

import json
from uuid import UUID

from packages.intelligence.reasoning.provider import MockReasoningProvider, ReasoningModelProvider
from packages.logging.logger import get_logger
from packages.reliability.adapter import AIReliabilityEngine, default_reliability_engine
from packages.review.ai.context_builder import BoundedReviewContext
from packages.review.ai.prompts import REVIEW_SYSTEM_PROMPT, build_review_user_prompt
from packages.review.ai.schemas import AIReviewResponse
from packages.review.domain.models import (
    FindingOrigin,
    ReviewFinding,
    SourceLocation,
    ValidationStatus,
)
from packages.security.llm_firewall.adapter import (
    FirewallDecisionAction,
    LLMFirewall,
    default_llm_firewall,
)

logger = get_logger("aegis.review.ai")


class AIReviewEngine:
    """Coordinates AI code review with defense-in-depth security, output validation, and reliability scoring."""

    def __init__(
        self,
        llm_provider: ReasoningModelProvider | None = None,
        firewall: LLMFirewall | None = None,
        reliability_engine: AIReliabilityEngine | None = None,
    ) -> None:
        self.llm_provider = llm_provider or MockReasoningProvider()
        self.firewall = firewall or default_llm_firewall
        self.reliability = reliability_engine or default_reliability_engine

    async def review(
        self,
        context: BoundedReviewContext,
        review_id: UUID | None = None,
    ) -> tuple[list[ReviewFinding], str, list[str]]:
        """Executes AI review over bounded context, returning validated findings and summary."""
        errors: list[str] = []
        user_prompt = build_review_user_prompt(context)

        # 1. Firewall pre-screening (Prompt Injection & Secrets Defense)
        try:
            prompt_scan = self.firewall.inspect_prompt(user_prompt)
            if prompt_scan.action == FirewallDecisionAction.BLOCK or not prompt_scan.allowed:
                logger.warning(
                    "AI Review prompt blocked by LLM firewall (risk: %s, reason: %s)",
                    prompt_scan.risk_score,
                    prompt_scan.reason,
                )
                errors.append(f"Prompt blocked by LLM Firewall: {prompt_scan.reason}")
                return [], "AI review halted due to security firewall policy block.", errors
            if prompt_scan.sanitized_text:
                user_prompt = prompt_scan.sanitized_text
        except Exception as e:
            logger.warning("Firewall prompt scan skipped due to runtime error: %s", e)

        # 2. Invoke LLM provider or fallback
        raw_output_text: str = ""
        try:
            if hasattr(self.llm_provider, "generate_review"):
                raw_output_text = await self.llm_provider.generate_review(
                    system_prompt=REVIEW_SYSTEM_PROMPT,
                    user_prompt=user_prompt,
                )
            else:
                # Deterministic synthetic review response for mock provider
                raw_output_text = self._generate_synthetic_review(context)
        except Exception as e:
            logger.error("LLM provider execution error during code review: %s", e)
            errors.append(f"LLM provider error: {e}")
            return [], "AI review could not be completed due to model provider error.", errors

        # 3. Firewall post-screening (Output validation & leak prevention)
        try:
            output_scan = self.firewall.inspect_output(raw_output_text)
            if output_scan.action == FirewallDecisionAction.BLOCK or not output_scan.allowed:
                errors.append("Model output blocked by security firewall.")
                return [], "Model output contained restricted content and was withheld.", errors
            if output_scan.sanitized_text:
                raw_output_text = output_scan.sanitized_text
        except Exception as e:
            logger.warning("Firewall output scan skipped due to runtime error: %s", e)

        # 4. Schema validation
        parsed_response = self._parse_and_validate_response(raw_output_text)
        if not parsed_response:
            errors.append("Failed to parse valid structured JSON from AI review response.")
            return [], "Model response did not conform to the required review schema.", errors

        # 5. Evidence, location, and deduplication validation
        validated_findings = self._validate_and_normalize_findings(
            raw_findings=parsed_response.findings,
            context=context,
            review_id=review_id,
        )

        return validated_findings, parsed_response.summary, errors

    def _generate_synthetic_review(self, context: BoundedReviewContext) -> str:
        """Deterministic high-quality fallback/mock generator for tests and offline runs."""
        findings: list[dict] = []

        # Inspect diff snippets for obvious patterns to provide realistic deterministic findings
        for snippet in context.diff_snippets:
            file_path = snippet["file_path"]
            content = snippet["content"]

            if "None" in content and "get(" in content:
                findings.append(
                    {
                        "file_path": file_path,
                        "start_line": 1,
                        "end_line": 5,
                        "title": "Potential Unhandled NoneType Dereference",
                        "description": "Dictionary get() can return None if key is absent; accessing attributes on it causes AttributeError.",
                        "category": "RELIABILITY",
                        "severity": "WARNING",
                        "technical_evidence": "dict.get() call without default or None-guard",
                        "impact": "Uncaught AttributeError leading to 500 server error in production.",
                        "remediation": "Provide a sensible default value to .get() or add an explicit None check.",
                        "confidence": 0.85,
                        "rule_id": "AI-REL-001",
                    }
                )

        response = {
            "summary": f"Completed automated AI code review for {len(context.changed_files)} changed file(s).",
            "findings": findings,
            "missing_context": context.missing_context_notes,
        }
        return json.dumps(response)

    def _parse_and_validate_response(self, raw_text: str) -> AIReviewResponse | None:
        try:
            data = json.loads(raw_text.strip())
            return AIReviewResponse.model_validate(data)
        except Exception:
            # Attempt to extract JSON from markdown fence if present
            if "```json" in raw_text:
                try:
                    inner = raw_text.split("```json")[1].split("```")[0].strip()
                    data = json.loads(inner)
                    return AIReviewResponse.model_validate(data)
                except Exception:
                    pass
            return None

    def _validate_and_normalize_findings(
        self,
        raw_findings: list,
        context: BoundedReviewContext,
        review_id: UUID | None,
    ) -> list[ReviewFinding]:
        valid_files = set(context.changed_files)
        results: list[ReviewFinding] = []
        seen_fingerprints: set[str] = set()

        # Build index of known symbols from context for factuality gating
        file_symbols: dict[str, set[str]] = {}
        for sym in context.changed_symbols:
            fp = sym.get("file_path", "")
            if fp not in file_symbols:
                file_symbols[fp] = set()
            if "name" in sym:
                file_symbols[fp].add(sym["name"])
            if "qualified_name" in sym:
                file_symbols[fp].add(sym["qualified_name"])

        for item in raw_findings:
            # 1. Location validation: file must exist in changed files
            if item.file_path not in valid_files:
                logger.info(
                    "Rejecting finding with fabricated or unreviewed file path: %s",
                    item.file_path,
                )
                continue

            # 2. Line range validation
            validation_status = ValidationStatus.VALIDATED
            start_line = item.start_line
            end_line = item.end_line or start_line

            if start_line < 1 or (item.end_line is not None and item.end_line < start_line):
                logger.info(
                    "Flagging finding with invalid line range [%s, %s] as REJECTED_LOCATION",
                    start_line,
                    end_line,
                )
                validation_status = ValidationStatus.REJECTED_LOCATION

            # 3. Symbol verification against revision-indexed AST symbols
            claimed_symbol = getattr(item, "symbol_name", None)
            if claimed_symbol:
                known_for_file = file_symbols.get(item.file_path)
                if known_for_file is not None and len(known_for_file) > 0:
                    if claimed_symbol not in known_for_file:
                        logger.info(
                            "Rejecting finding claiming fabricated symbol '%s' not present in %s",
                            claimed_symbol,
                            item.file_path,
                        )
                        validation_status = ValidationStatus.REJECTED_LOCATION
                    else:
                        if validation_status == ValidationStatus.VALIDATED:
                            validation_status = ValidationStatus.VALIDATED
                else:
                    if validation_status == ValidationStatus.VALIDATED:
                        validation_status = ValidationStatus.UNVERIFIED
            else:
                if item.file_path not in file_symbols and validation_status == ValidationStatus.VALIDATED:
                    validation_status = ValidationStatus.UNVERIFIED

            finding = ReviewFinding(
                review_id=review_id,
                rule_id=item.rule_id,
                title=item.title,
                message=item.description,
                severity=item.severity,
                category=item.category,
                origin=FindingOrigin.HYPOTHESIS,
                location=SourceLocation(
                    file_path=item.file_path,
                    start_line=max(1, start_line),
                    end_line=max(1, end_line),
                    symbol_name=claimed_symbol,
                ),
                suggestion=item.remediation,
                technical_evidence=item.technical_evidence,
                validation_status=validation_status,
                tool_name="ai_review_engine",
                confidence=round(min(1.0, max(0.0, item.confidence)), 2),
                metadata={"impact": item.impact},
            )

            # 4. Deduplication check
            if finding.deduplication_hash in seen_fingerprints:
                continue

            seen_fingerprints.add(finding.deduplication_hash)
            results.append(finding)

        return results
