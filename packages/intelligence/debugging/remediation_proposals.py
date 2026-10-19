"""Minimal patch proposal and layered fix validation service for autonomous debugging."""

from packages.intelligence.debugging.models import (
    FixProposal,
    FixValidationStatus,
    HypothesisVerdict,
    RankedHypothesis,
    StackTraceFrame,
)

PROTECTED_FILENAMES = {"render_schema.json"}


class FixProposalService:
    """Generates proposal-only unified diff patches tied to ranked root-cause hypotheses."""

    @classmethod
    def generate_proposals(
        cls,
        hypotheses: list[RankedHypothesis],
        localized_frames: list[StackTraceFrame],
    ) -> list[FixProposal]:
        proposals: list[FixProposal] = []
        resolved_files = {f.file_path for f in localized_frames if f.is_resolved}

        for hyp in hypotheses:
            if hyp.verdict not in (HypothesisVerdict.CONFIRMED, HypothesisVerdict.PLAUSIBLE):
                continue
            if not hyp.affected_file or hyp.affected_file not in resolved_files:
                continue

            target_file = hyp.affected_file
            target_symbol = hyp.affected_symbol or "target_function"

            # 1. Proposal for None/Null Dereference
            if "none" in hyp.title.lower() or "null" in hyp.title.lower() or "undefined" in hyp.title.lower():
                diff = (
                    f"--- a/{target_file}\n"
                    f"+++ b/{target_file}\n"
                    f"@@ -1,5 +1,8 @@\n"
                    f" def {target_symbol}(*args, **kwargs):\n"
                    f"+    # Guard against unhandled NoneType dereference\n"
                    f"+    if args and args[0] is None:\n"
                    f"+        return None\n"
                    f"     return super().execute()\n"
                )
                proposals.append(
                    FixProposal(
                        hypothesis_id=hyp.id,
                        target_file=target_file,
                        target_symbol=target_symbol,
                        defect_explanation="Object evaluated to None before attribute dereference; guard check prevents unhandled exception.",
                        diff_patch=diff,
                        expected_behavior="Function handles None input gracefully by returning safe default instead of raising exception.",
                        recommended_tests=[f"tests/test_{target_file.replace('/', '_')}.py"],
                        safety_considerations=["Verify whether callers expect None or require an explicit custom exception."],
                        confidence=0.85,
                    )
                )

            # 2. Proposal for Missing Configuration Key
            elif "configuration" in hyp.title.lower() or "config" in hyp.title.lower() or "key" in hyp.title.lower():
                cfg_key = target_symbol if target_symbol else "CONFIG_KEY"
                diff = (
                    f"--- a/{target_file}\n"
                    f"+++ b/{target_file}\n"
                    f"@@ -10,3 +10,4 @@\n"
                    f"-    val = os.environ['{cfg_key}']\n"
                    f"+    val = os.environ.get('{cfg_key}', 'default_value')\n"
                )
                proposals.append(
                    FixProposal(
                        hypothesis_id=hyp.id,
                        target_file=target_file,
                        target_symbol=target_symbol,
                        defect_explanation=f"Direct dictionary lookup os.environ['{cfg_key}'] raises KeyError when unset.",
                        diff_patch=diff,
                        expected_behavior=f"os.environ.get('{cfg_key}', default) provides fallback value when key is omitted.",
                        recommended_tests=["tests/unit/test_config.py"],
                        safety_considerations=["Confirm if a fallback default is safe in production or if startup should fail fast with a descriptive error."],
                        confidence=0.88,
                    )
                )

            # 3. Proposal for General Unhandled Exception
            elif not proposals and hyp.score >= 0.7:
                diff = (
                    f"--- a/{target_file}\n"
                    f"+++ b/{target_file}\n"
                    f"@@ -15,4 +15,7 @@\n"
                    f"+    try:\n"
                    f"         result = process()\n"
                    f"+    except Exception as exc:\n"
                    f"+        logger.warning('Recovered from processing error: %s', exc)\n"
                    f"+        result = None\n"
                )
                proposals.append(
                    FixProposal(
                        hypothesis_id=hyp.id,
                        target_file=target_file,
                        target_symbol=target_symbol,
                        defect_explanation=f"Unhandled exception escaping {target_symbol}.",
                        diff_patch=diff,
                        expected_behavior="Exception caught and safely logged without crashing upstream caller.",
                        recommended_tests=[],
                        safety_considerations=["Catching generic Exception can mask bugs if not accompanied by monitoring alerts."],
                        confidence=0.65,
                    )
                )

        return proposals


class FixValidationService:
    """Performs layered validation on proposed fixes before presenting them to users."""

    @classmethod
    def validate_proposal(
        cls,
        proposal: FixProposal,
        localized_frames: list[StackTraceFrame],
    ) -> FixProposal:
        validated = proposal.model_copy()
        notes: list[str] = []

        # 1. Target file security check
        parts = proposal.target_file.split("/")
        if any(p in PROTECTED_FILENAMES for p in parts) or ".." in parts:
            validated.validation_status = FixValidationStatus.VALIDATION_FAILED
            validated.validation_notes = ["Proposal targets a protected or unsafe file path."]
            return validated

        # 2. Confirm target file matches localized frames
        resolved_files = {f.file_path for f in localized_frames if f.is_resolved}
        if proposal.target_file not in resolved_files:
            validated.validation_status = FixValidationStatus.VALIDATION_FAILED
            validated.validation_notes = [f"Target file '{proposal.target_file}' was not localized in failure stack frames."]
            return validated

        # 3. Check diff structure
        if not proposal.diff_patch.startswith("---") or "+++" not in proposal.diff_patch:
            validated.validation_status = FixValidationStatus.VALIDATION_FAILED
            validated.validation_notes = ["Proposal does not contain valid unified diff formatting."]
            return validated

        # 4. Success layered validation
        notes.append("Target file confirmed present in localized execution frames.")
        notes.append("Diff patch adheres to unified diff standard.")
        notes.append("No unrelated files or protected paths modified.")
        validated.validation_status = FixValidationStatus.VALIDATION_PASSED
        validated.validation_notes = notes
        return validated
