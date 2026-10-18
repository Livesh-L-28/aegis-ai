"""GitHub review publisher with stale-review rejection and out-of-diff inline fallback."""

from typing import Any

from packages.logging.logger import get_logger
from packages.review.domain.models import GitDiffSummary, ReviewFinding
from packages.review.github.client import GitHubClient, GitHubReviewComment

logger = get_logger("aegis.review.github.publisher")


class StaleReviewError(Exception):
    """Raised when a pull request's head SHA has changed since analysis began."""
    pass


class GitHubReviewPublisher:
    """Publishes validated review findings to GitHub Pull Requests with strict safety checks."""

    def __init__(
        self,
        client: GitHubClient | None = None,
        publish_enabled: bool = False,
    ) -> None:
        self.client = client or GitHubClient()
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
        owner: str,
        repo: str,
        pr_number: int,
        analyzed_head_sha: str,
        findings: list[ReviewFinding],
        diff_summary: GitDiffSummary,
    ) -> dict[str, Any]:
        """Validates current PR head SHA and publishes findings to GitHub."""
        # 1. Stale review verification
        pr_meta = await self.client.get_pull_request(owner=owner, repo=repo, pr_number=pr_number)
        if pr_meta.head_sha != analyzed_head_sha:
            msg = (
                f"Stale review rejected for PR #{pr_number}: analyzed head SHA "
                f"'{analyzed_head_sha}' does not match current PR head '{pr_meta.head_sha}'."
            )
            logger.warning(msg)
            raise StaleReviewError(msg)

        # 2. Partition findings into inline comments vs summary table
        valid_positions = self._build_inline_positions(diff_summary)
        inline_comments: list[GitHubReviewComment] = []
        out_of_diff_findings: list[ReviewFinding] = []

        for finding in findings:
            file_path = finding.location.file_path
            start_line = finding.location.start_line

            if file_path in valid_positions and start_line in valid_positions[file_path]:
                comment_body = (
                    f"### 🛡️ AEGIS AI Review: **[{finding.severity.value}] {finding.title}**\n\n"
                    f"{finding.message}\n\n"
                    f"**Evidence:** `{finding.technical_evidence or 'N/A'}`\n\n"
                    f"**Suggestion:** {finding.suggestion or 'Review implementation.'}\n\n"
                    f"*Origin: {finding.origin.value} | Confidence: {finding.confidence}*"
                )
                inline_comments.append(
                    GitHubReviewComment(
                        path=file_path,
                        line=start_line,
                        body=comment_body,
                    )
                )
            else:
                out_of_diff_findings.append(finding)

        # 3. Assemble main review body
        body_lines = [
            f"## 🛡️ AEGIS AI Code Review Summary for commit `{analyzed_head_sha[:8]}`",
            "",
            f"- **Total Findings:** {len(findings)}",
            f"- **Inline Comments:** {len(inline_comments)}",
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
        event = "COMMENT"
        if any(f.severity.value in ("ERROR", "CRITICAL") for f in findings):
            event = "REQUEST_CHANGES"

        # 4. Dry-run safety gate
        if not self.publish_enabled:
            logger.info("Dry-run mode: skipping remote GitHub API review publication")
            return {
                "status": "dry_run",
                "pr_number": pr_number,
                "head_sha": analyzed_head_sha,
                "event": event,
                "inline_comments_count": len(inline_comments),
                "summary": review_body,
            }

        # 5. Remote publication
        return await self.client.post_review(
            owner=owner,
            repo=repo,
            pr_number=pr_number,
            commit_id=analyzed_head_sha,
            body=review_body,
            event=event,
            comments=inline_comments,
        )
