"""Verification planner and hypothesis verifier: generates reproducible, safe verification plans."""

from packages.intelligence.debugging.models import (
    DebuggingEvidenceItem,
    RankedHypothesis,
    VerificationStatus,
    VerificationStep,
)


class VerificationPlanner:
    """Creates reproducible, safe verification plans evaluating candidate root-cause hypotheses."""

    @classmethod
    def plan_verification(
        cls,
        hypotheses: list[RankedHypothesis],
        evidence: list[DebuggingEvidenceItem],
    ) -> list[VerificationStep]:
        steps: list[VerificationStep] = []
        evidence_by_id = {e.id: e for e in evidence}

        # Collect affected tests from evidence
        affected_tests = [
            e.file_path for e in evidence
            if e.evidence_type == "AFFECTED_TEST" and e.file_path
        ]

        for hyp in hypotheses:
            # 1. Test Verification Step
            if affected_tests:
                for test_file in affected_tests[:2]:  # Limit to 2 most relevant test suites
                    steps.append(
                        VerificationStep(
                            hypothesis_id=hyp.id,
                            action_type="RUN_TEST",
                            target=test_file,
                            command_preview=f"pytest {test_file} -v",
                            is_executable=False,  # Propose only; requires explicit user permission
                            expected_outcome="Test failure reproducing the defect or verifying candidate fix.",
                            status=VerificationStatus.NOT_RUN,
                            notes=f"Selected candidate test suite covering downstream reverse dependencies of {hyp.affected_file or 'component'}.",
                        )
                    )
            elif hyp.affected_file:
                # Propose targeted test check
                steps.append(
                    VerificationStep(
                        hypothesis_id=hyp.id,
                        action_type="STATIC_CHECK",
                        target=hyp.affected_file,
                        command_preview=f"ruff check {hyp.affected_file}",
                        is_executable=False,
                        expected_outcome="Static analysis verifies syntax and type safety.",
                        status=VerificationStatus.NOT_RUN,
                        notes=f"Static inspection of localized file {hyp.affected_file}.",
                    )
                )

            # 2. Contract or Configuration Verification Step
            for eid in hyp.supporting_evidence_ids:
                ev = evidence_by_id.get(eid)
                if not ev:
                    continue
                if ev.evidence_type == "API_CONTRACT":
                    steps.append(
                        VerificationStep(
                            hypothesis_id=hyp.id,
                            action_type="INSPECT_CONTRACT",
                            target=ev.symbol_name or "API Endpoint",
                            command_preview=None,
                            is_executable=False,
                            expected_outcome="Verify client payload matches FastAPI route schema.",
                            status=VerificationStatus.NOT_RUN,
                            notes=f"Check endpoint {ev.symbol_name} defined in {ev.file_path}.",
                        )
                    )
                elif ev.evidence_type == "CONFIGURATION":
                    steps.append(
                        VerificationStep(
                            hypothesis_id=hyp.id,
                            action_type="VALIDATE_CONFIG",
                            target=ev.symbol_name or "Config Key",
                            command_preview=None,
                            is_executable=False,
                            expected_outcome=f"Verify configuration key '{ev.symbol_name}' is set in deployment environment.",
                            status=VerificationStatus.NOT_RUN,
                            notes=f"Environment variable referenced at {ev.file_path}.",
                        )
                    )
                elif ev.evidence_type == "DATABASE_MODEL":
                    steps.append(
                        VerificationStep(
                            hypothesis_id=hyp.id,
                            action_type="STATIC_CHECK",
                            target=ev.symbol_name or "Database Model",
                            command_preview=None,
                            is_executable=False,
                            expected_outcome="Confirm entity columns match database migration declarations.",
                            status=VerificationStatus.NOT_RUN,
                            notes=f"SQLAlchemy model {ev.symbol_name} in {ev.file_path}.",
                        )
                    )

        return steps
