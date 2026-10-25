"""Configurable engineering policy gates for PR and CI pipeline enforcement."""

import json
from pathlib import Path
from typing import Any

from packages.review.history.models import (
    PolicyEvaluationResult,
    PolicyMode,
    PolicyRule,
    PolicyViolation,
    RepositorySnapshot,
    SnapshotComparison,
)

DEFAULT_POLICY_RULES: list[dict[str, Any]] = [
    {
        "id": "POL-001",
        "name": "no_new_critical_findings",
        "description": "Reject pull requests introducing new CRITICAL severity findings.",
        "condition": "max_new_critical_findings",
        "threshold": 0.0,
        "mode": "BLOCKING",
    },
    {
        "id": "POL-002",
        "name": "no_new_dependency_cycles",
        "description": "Prevent introduction of new circular dependency cycles.",
        "condition": "max_new_cycles",
        "threshold": 0.0,
        "mode": "BLOCKING",
    },
    {
        "id": "POL-003",
        "name": "max_health_score_drop",
        "description": "Warn if repository architecture health score degrades by more than 5 points.",
        "condition": "max_health_score_drop",
        "threshold": 5.0,
        "mode": "WARNING",
    },
]


class EngineeringPolicyEvaluator:
    """Evaluates configurable health and regression policies against snapshots and comparisons."""

    def __init__(self, rules: list[PolicyRule] | None = None) -> None:
        if rules is not None:
            self.rules = rules
        else:
            self.rules = [PolicyRule(**r) for r in DEFAULT_POLICY_RULES]

    @classmethod
    def from_config_file(cls, config_path: str | Path) -> "EngineeringPolicyEvaluator":
        """Loads policy rules from a JSON configuration file with validation."""
        path = Path(config_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Policy configuration file not found: {path}")

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            raise ValueError(f"Malformed JSON in policy configuration '{path}': {e}") from None

        raw_rules = data.get("rules", []) if isinstance(data, dict) else data
        if not isinstance(raw_rules, list):
            raise ValueError("Policy configuration must contain a 'rules' list.")

        parsed_rules: list[PolicyRule] = []
        for item in raw_rules:
            parsed_rules.append(PolicyRule(**item))

        return cls(rules=parsed_rules)

    def evaluate_comparison(self, comparison: SnapshotComparison) -> PolicyEvaluationResult:
        """Evaluates policy rules against a pairwise revision comparison."""
        violations: list[PolicyViolation] = []
        warnings: list[PolicyViolation] = []
        is_blocking = False

        for rule in self.rules:
            cond = rule.condition.lower()
            actual: float = 0.0
            triggered = False
            msg = ""

            if cond == "max_new_critical_findings":
                crit_count = sum(1 for f in comparison.new_findings if f.severity.upper() == "CRITICAL")
                actual = float(crit_count)
                if actual > rule.threshold:
                    triggered = True
                    msg = f"Introduced {crit_count} new CRITICAL finding(s) (threshold: {int(rule.threshold)})."

            elif cond in ("max_new_high_findings", "max_new_error_findings"):
                high_count = sum(
                    1 for f in comparison.new_findings if f.severity.upper() in ("HIGH", "ERROR", "CRITICAL")
                )
                actual = float(high_count)
                if actual > rule.threshold:
                    triggered = True
                    msg = f"Introduced {high_count} new HIGH/CRITICAL finding(s) (threshold: {int(rule.threshold)})."

            elif cond == "max_new_cycles":
                cycles = max(0.0, comparison.metric_deltas.get("cycle_count", 0.0))
                actual = cycles
                if actual > rule.threshold:
                    triggered = True
                    msg = f"Introduced {int(actual)} new circular dependency cycle(s) (threshold: {int(rule.threshold)})."

            elif cond in ("max_new_boundary_violations", "max_new_architecture_violations"):
                b_violations = max(0.0, comparison.metric_deltas.get("boundary_violations", 0.0))
                actual = b_violations
                if actual > rule.threshold:
                    triggered = True
                    msg = f"Introduced {int(actual)} new boundary violation(s) (threshold: {int(rule.threshold)})."

            elif cond == "max_health_score_drop":
                drop = max(0.0, -comparison.health_score_delta)
                actual = drop
                if actual > rule.threshold:
                    triggered = True
                    msg = f"Health score dropped by {actual:.1f} pts (threshold: {rule.threshold:.1f} pts)."

            elif cond == "max_tech_debt_growth":
                growth = max(0.0, comparison.tech_debt_delta)
                actual = growth
                if actual > rule.threshold:
                    triggered = True
                    msg = f"Technical debt increased by {actual:.1f} pts (threshold: {rule.threshold:.1f} pts)."

            elif cond == "max_reopened_findings":
                reopened = float(len(comparison.reopened_findings))
                actual = reopened
                if actual > rule.threshold:
                    triggered = True
                    msg = f"Reopened {int(actual)} previously resolved finding(s) (threshold: {int(rule.threshold)})."

            if triggered:
                violation = PolicyViolation(
                    rule_id=rule.id,
                    condition=rule.condition,
                    actual_value=actual,
                    threshold_value=rule.threshold,
                    mode=rule.mode,
                    message=msg,
                    is_blocking=(rule.mode == PolicyMode.BLOCKING),
                )
                if rule.mode == PolicyMode.BLOCKING:
                    violations.append(violation)
                    is_blocking = True
                elif rule.mode == PolicyMode.WARNING:
                    warnings.append(violation)
                else:
                    # Informational
                    warnings.append(violation)

        passed = not is_blocking
        exit_code = 1 if is_blocking else 0

        return PolicyEvaluationResult(
            passed=passed,
            is_blocking_failure=is_blocking,
            violations=violations,
            warnings=warnings,
            rules_evaluated=len(self.rules),
            suggested_exit_code=exit_code,
        )

    def evaluate_snapshot(self, snapshot: RepositorySnapshot) -> PolicyEvaluationResult:
        """Evaluates policy rules against an absolute snapshot state."""
        violations: list[PolicyViolation] = []
        warnings: list[PolicyViolation] = []
        is_blocking = False

        for rule in self.rules:
            cond = rule.condition.lower()
            actual: float = 0.0
            triggered = False
            msg = ""

            if cond in ("max_total_critical_findings", "max_critical_findings"):
                crit = sum(1 for f in snapshot.findings if f.severity.upper() == "CRITICAL")
                actual = float(crit)
                if actual > rule.threshold:
                    triggered = True
                    msg = f"Total CRITICAL findings count is {crit} (threshold: {int(rule.threshold)})."

            elif cond in ("max_total_cycles", "max_cycles"):
                actual = float(snapshot.metrics.cycle_count)
                if actual > rule.threshold:
                    triggered = True
                    msg = f"Total circular dependency cycles count is {int(actual)} (threshold: {int(rule.threshold)})."

            elif cond == "min_scan_coverage":
                actual = snapshot.metadata.scan_coverage
                if actual < rule.threshold:
                    triggered = True
                    msg = f"Scan coverage is {actual:.1%} (required minimum: {rule.threshold:.1%})."

            elif cond == "min_health_score":
                actual = snapshot.metrics.health_score
                if actual < rule.threshold:
                    triggered = True
                    msg = f"Architecture health score is {actual:.1f} (required minimum: {rule.threshold:.1f})."

            if triggered:
                violation = PolicyViolation(
                    rule_id=rule.id,
                    condition=rule.condition,
                    actual_value=actual,
                    threshold_value=rule.threshold,
                    mode=rule.mode,
                    message=msg,
                    is_blocking=(rule.mode == PolicyMode.BLOCKING),
                )
                if rule.mode == PolicyMode.BLOCKING:
                    violations.append(violation)
                    is_blocking = True
                else:
                    warnings.append(violation)

        passed = not is_blocking
        exit_code = 1 if is_blocking else 0

        return PolicyEvaluationResult(
            passed=passed,
            is_blocking_failure=is_blocking,
            violations=violations,
            warnings=warnings,
            rules_evaluated=len(self.rules),
            suggested_exit_code=exit_code,
        )
