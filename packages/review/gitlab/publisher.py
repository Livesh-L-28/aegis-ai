"""GitLab MR review publisher with stale-review rejection and out-of-diff fallback."""

from typing import Any

from packages.logging.logger import get_logger
from packages.review.domain.models import GitDiffSummary, ReviewFinding
from packages.review.github.publisher import StaleReviewError
from packages.review.gitlab.client import (
    GitLabClient,
    GitLabDiffPosition,
    GitLabMRMetadata,
)

logger = get_logger("logicfalcon.review.gitlab.publisher")


class GitLabReviewPublisher:
    """Publishes validated review findings to GitLab Merge Requests with safety checks."""

    def __init__(
        self,
        client: GitLabClient | None = None,
        publish_enabled: bool = False,
    ) -> None:
        self.client = client or GitLabClient()
        self.publish_enabled = publish_enabled

    def _build_inline_positions(self, diff_summary: GitDiffSummary) -> dict[str, set[int]]:
        """Maps file paths to valid 1-indexed line numbers present in added diff hunks."""
        positions: dict[str, set[int]] = {}
        for cf in diff_summary.files:
            path = cf.new_path or cf.old_path
            if not path:
                continue
            lines: set[int] = set()
            for hunk in cf.hunks:
                lines.update(hunk.added_lines)
            positions[path] = lines
        return positions

    async def publish_review(
        self,
        project_id: str | int,
        mr_iid: int,
        analyzed_head_sha: str,
        findings: list[ReviewFinding],
        diff_summary: GitDiffSummary,
    ) -> dict[str, Any]:
        """Validates current MR head SHA and publishes findings to GitLab."""
        # 1. Stale review verification
        mr_meta: GitLabMRMetadata = await self.client.get_merge_request(
            project_id=project_id,
            mr_iid=mr_iid,
        )
        if mr_meta.head_sha != analyzed_head_sha:
            msg = (
                f"Stale review rejected for MR !{mr_iid}: analyzed head SHA "
                f"'{analyzed_head_sha}' does not match current MR head '{mr_meta.head_sha}'."
            )
            logger.warning(msg)
            raise StaleReviewError(msg)

        # 2. Partition findings into inline discussions vs summary table
        valid_positions = self._build_inline_positions(diff_summary)
        inline_discussions: list[dict[str, Any]] = []
        out_of_diff_findings: list[ReviewFinding] = []

        for finding in findings:
            file_path = finding.location.file_path
            start_line = finding.location.start_line

            if file_path in valid_positions and start_line in valid_positions[file_path]:
                comment_body = (
                    f"### 🦅 LogicFalcon Review: **[{finding.severity.value}] {finding.title}**\n\n"
                    f"{finding.message}\n\n"
                    f"**Evidence:** `{finding.technical_evidence or 'N/A'}`\n\n"
                    f"**Suggestion:** {finding.suggestion or 'Review implementation.'}\n\n"
                )
                if finding.proposed_fix and finding.proposed_fix.replacement_code:
                    comment_body += (
                        "```suggestion\n"
                        f"{finding.proposed_fix.replacement_code}\n"
                        "```\n\n"
                    )
                comment_body += f"*Origin: {finding.origin.value} | Confidence: {finding.confidence}*"

                pos = GitLabDiffPosition(
                    base_sha=mr_meta.base_sha,
                    start_sha=mr_meta.start_sha,
                    head_sha=mr_meta.head_sha,
                    new_path=file_path,
                    new_line=start_line,
                )
                inline_discussions.append({"body": comment_body, "position": pos})
            else:
                out_of_diff_findings.append(finding)

        # 3. Assemble main summary note
        body_lines = [
            f"## 🦅 LogicFalcon Code Review Summary for commit `{analyzed_head_sha[:8]}`",
            "",
            f"- **Total Findings:** {len(findings)}",
            f"- **Inline Discussions:** {len(inline_discussions)}",
            f"- **Repository Context Findings:** {len(out_of_diff_findings)}",
            "",
        ]

        if out_of_diff_findings:
            body_lines.append("### 📋 Additional File & Architecture Findings (Out of Diff)")
            body_lines.append("| Severity | File | Line | Rule | Message |")
            body_lines.append("|---|---|---|---|---|")
            for oof in out_of_diff_findings:
                body_lines.append(
                    f"| **{oof.severity.value}** | `{oof.location.file_path}` | {oof.location.start_line} | `{oof.rule_id}` | {oof.title} |"
                )
            body_lines.append("")

        if not findings:
            body_lines.append("✅ **All quality, security, and reliability checks passed cleanly.**")

        review_body = "\n".join(body_lines)

        # 4. Dry-run safety gate
        if not self.publish_enabled:
            logger.info("Dry-run mode: skipping remote GitLab API review publication")
            return {
                "status": "dry_run",
                "mr_iid": mr_iid,
                "head_sha": analyzed_head_sha,
                "inline_discussions_count": len(inline_discussions),
                "summary": review_body,
            }

        # 5. Remote publication
        note_res = await self.client.post_merge_request_note(
            project_id=project_id,
            mr_iid=mr_iid,
            body=review_body,
        )

        published_inline = 0
        for disc in inline_discussions:
            try:
                await self.client.post_merge_request_discussion(
                    project_id=project_id,
                    mr_iid=mr_iid,
                    body=disc["body"],
                    position=disc["position"],
                )
                published_inline += 1
            except Exception as e:
                logger.warning(f"Failed to publish inline discussion: {e}")

        return {
            "status": "published",
            "mr_iid": mr_iid,
            "head_sha": analyzed_head_sha,
            "note_id": note_res.get("id"),
            "inline_published": published_inline,
        }
