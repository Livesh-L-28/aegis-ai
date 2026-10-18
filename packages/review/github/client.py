"""GitHub API client supporting PR diff retrieval, review comments, and checks."""

from typing import Any, cast

import httpx
from pydantic import BaseModel


class GitHubPRMetadata(BaseModel):
    owner: str
    repo: str
    pr_number: int
    title: str
    base_sha: str
    head_sha: str
    state: str = "open"


class GitHubReviewComment(BaseModel):
    path: str
    line: int
    body: str
    side: str = "RIGHT"


class GitHubClient:
    """Least-privilege client for GitHub Pull Request inspections and reviews."""

    def __init__(
        self,
        token: str | None = None,
        base_url: str = "https://api.github.com",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._transport = transport

    def _headers(self, accept: str = "application/vnd.github.v3+json") -> dict[str, str]:
        headers = {
            "Accept": accept,
            "User-Agent": "AEGIS-AI-CodeReview/1.0",
        }
        if self._token:
            headers["Authorization"] = f"token {self._token}"
        return headers

    async def get_pull_request(self, owner: str, repo: str, pr_number: int) -> GitHubPRMetadata:
        """Retrieves PR metadata including current head and base commit SHAs."""
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}"
        async with httpx.AsyncClient(transport=self._transport) as client:
            resp = await client.get(url, headers=self._headers())
            resp.raise_for_status()
            data = resp.json()
            return GitHubPRMetadata(
                owner=owner,
                repo=repo,
                pr_number=pr_number,
                title=data.get("title", ""),
                base_sha=data["base"]["sha"],
                head_sha=data["head"]["sha"],
                state=data.get("state", "open"),
            )

    async def get_pull_request_diff(self, owner: str, repo: str, pr_number: int) -> str:
        """Fetches unified diff for the pull request."""
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}"
        headers = self._headers(accept="application/vnd.github.v3.diff")
        async with httpx.AsyncClient(transport=self._transport) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.text

    async def post_review(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        commit_id: str,
        body: str,
        event: str = "COMMENT",
        comments: list[GitHubReviewComment] | None = None,
    ) -> dict[str, Any]:
        """Submits a pull request review with summary and optional inline comments."""
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
        payload: dict[str, Any] = {
            "commit_id": commit_id,
            "body": body,
            "event": event,
        }
        if comments:
            payload["comments"] = [c.model_dump() for c in comments]

        async with httpx.AsyncClient(transport=self._transport) as client:
            resp = await client.post(url, headers=self._headers(), json=payload)
            resp.raise_for_status()
            data = resp.json()
            return cast(dict[str, Any], data)
