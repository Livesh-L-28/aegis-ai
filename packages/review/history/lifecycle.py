"""Finding identity and revision-aware lifecycle tracking for LogicFalcon historical intelligence."""

from pathlib import Path

from packages.review.history.models import (
    FindingLifecycleState,
    FindingLifecycleTransition,
    SnapshotFinding,
)


class FindingLifecycleTracker:
    """Tracks the lifecycle of engineering findings across snapshots with false-resolution defense."""

    @classmethod
    def compute_lifecycle(
        cls,
        prior_findings: list[SnapshotFinding],
        current_findings: list[SnapshotFinding],
        current_parsed_files: set[str],
        current_skipped_files: set[str] | None = None,
        enabled_rules_current: set[str] | None = None,
        historical_resolved_fingerprints: set[str] | None = None,
    ) -> tuple[list[SnapshotFinding], list[FindingLifecycleTransition]]:
        """Evaluates lifecycle state transitions between two snapshots.

        Returns:
            Tuple of:
            1. Enriched current_findings with updated resolution_state.
            2. Complete list of FindingLifecycleTransition records (including resolved and uncertain).
        """
        skipped = current_skipped_files or set()
        prior_by_fp: dict[str, SnapshotFinding] = {f.fingerprint: f for f in prior_findings}
        curr_by_fp: dict[str, SnapshotFinding] = {f.fingerprint: f for f in current_findings}
        resolved_history = historical_resolved_fingerprints or set()

        enriched_current: list[SnapshotFinding] = []
        transitions: list[FindingLifecycleTransition] = []

        # 1. Inspect current findings: NEW, UNCHANGED, CHANGED, or REOPENED
        for f in current_findings:
            prior_f = prior_by_fp.get(f.fingerprint)
            if prior_f is None:
                # Check if it was previously marked resolved in older history
                if f.fingerprint in resolved_history:
                    state = FindingLifecycleState.REOPENED
                    reason = "Finding previously resolved was reintroduced in this revision."
                else:
                    state = FindingLifecycleState.NEW
                    reason = "Newly observed finding not present in prior snapshot."
                prev_state = None
            else:
                # Present in both
                if f.severity != prior_f.severity or f.message != prior_f.message:
                    state = FindingLifecycleState.CHANGED
                    reason = f"Finding modified (severity: {prior_f.severity} -> {f.severity})."
                else:
                    state = FindingLifecycleState.UNCHANGED
                    reason = "Finding persistently active across revisions."
                prev_state = prior_f.resolution_state

            # Clone finding with updated state
            updated_f = f.model_copy(update={"resolution_state": state})
            enriched_current.append(updated_f)
            transitions.append(
                FindingLifecycleTransition(
                    fingerprint=f.fingerprint,
                    rule_id=f.rule_id,
                    file_path=f.file_path,
                    start_line=f.start_line,
                    severity=f.severity,
                    previous_state=prev_state,
                    current_state=state,
                    transition_reason=reason,
                    is_confirmed=True,
                )
            )

        # 2. Inspect prior findings missing in current: RESOLVED vs UNCERTAIN
        for fp, prior_f in prior_by_fp.items():
            if fp not in curr_by_fp:
                norm_path = cls._normalize_relpath(prior_f.file_path)
                # Check if the file was scanned and parsed in the current snapshot
                file_was_parsed = (
                    norm_path in current_parsed_files
                    or prior_f.file_path in current_parsed_files
                )
                file_was_skipped = (
                    norm_path in skipped
                    or prior_f.file_path in skipped
                )
                rule_is_enabled = (
                    enabled_rules_current is None
                    or prior_f.rule_id in enabled_rules_current
                )

                if file_was_skipped or not file_was_parsed or not rule_is_enabled:
                    # Incomplete analysis: DO NOT claim resolved!
                    state = FindingLifecycleState.UNCERTAIN
                    if file_was_skipped:
                        reason = f"File '{prior_f.file_path}' was skipped during current scan (size/timeout/ignore)."
                    elif not file_was_parsed:
                        reason = f"File '{prior_f.file_path}' was not included or unparsed in current analysis."
                    else:
                        reason = f"Rule '{prior_f.rule_id}' was disabled in current analysis configuration."
                    is_confirmed = False
                else:
                    # File was fully parsed, rule was active, and finding was absent: genuinely resolved!
                    state = FindingLifecycleState.RESOLVED
                    reason = f"Verified absent in fully parsed module '{prior_f.file_path}'."
                    is_confirmed = True

                transitions.append(
                    FindingLifecycleTransition(
                        fingerprint=prior_f.fingerprint,
                        rule_id=prior_f.rule_id,
                        file_path=prior_f.file_path,
                        start_line=prior_f.start_line,
                        severity=prior_f.severity,
                        previous_state=prior_f.resolution_state,
                        current_state=state,
                        transition_reason=reason,
                        is_confirmed=is_confirmed,
                    )
                )

        return enriched_current, transitions

    @staticmethod
    def _normalize_relpath(path_str: str) -> str:
        """Normalizes path representation for stable matching."""
        p = Path(path_str)
        return str(p.as_posix()).lstrip("./")
