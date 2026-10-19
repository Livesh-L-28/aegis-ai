"""GitLab API client supporting MR diff retrieval, discussions, and inline comments."""

from typing import Any, cast

import httpx
from pydantic import BaseModel


class GitLabMRMetadata(BaseModel):
    project_id: str | int
    mr_iid: int
    title: str
    base_sha: str
    head_sha: str
    start_sha: str
    state: str = "opened"


class GitLabDiffPosition(BaseModel):
    base_sha: str
    start_sha: str
    head_sha: str
    old_path: str | None = None
    new_path: str | None = None
    new_line: int | None = None
    old_line: int | None = None
    position_type: str = "text"


class GitLabClient:
    """Least-privilege client for GitLab Merge Request inspections and reviews."""

    def __init__(
        self,
        token: str | None = None,
        base_url: str = "https://gitlab.com",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._transport = transport

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "LogicFalcon-CodeReview/1.0",
        }
        if self._token:
            headers["PRIVATE-TOKEN"] = self._token
        return headers

    async def get_merge_request(self, project_id: str | int, mr_iid: int) -> GitLabMRMetadata:
        """Retrieves Merge Request metadata including head and base commit SHAs."""
        encoded_project = str(project_id).replace("/", "%2F")
        url = f"{self.base_url}/api/v4/projects/{encoded_project}/merge_requests/{mr_iid}"
        async with httpx.AsyncClient(transport=self._transport) as client:
            resp = await client.get(url, headers=self._headers())
            resp.raise_for_status()
            data = resp.json()

            diff_refs = data.get("diff_refs", {})
            return GitLabMRMetadata(
                project_id=project_id,
                mr_iid=mr_iid,
                title=data.get("title", ""),
                base_sha=diff_refs.get("base_sha") or data.get("diff_refs", {}).get("base_sha", ""),
                head_sha=diff_refs.get("head_sha") or data.get("sha", ""),
                start_sha=diff_refs.get("start_sha") or diff_refs.get("base_sha", ""),
                state=data.get("state", "opened"),
            )

    async def post_merge_request_discussion(
        self,
        project_id: str | int,
        mr_iid: int,
        body: str,
        position: GitLabDiffPosition | None = None,
    ) -> dict[str, Any]:
        """Publishes an inline discussion note to a GitLab MR diff."""
        encoded_project = str(project_id).replace("/", "%2F")
        url = f"{self.base_url}/api/v4/projects/{encoded_project}/merge_requests/{mr_iid}/discussions"
        payload: dict[str, Any] = {"body": body}
        if position:
            payload["position"] = position.model_dump(exclude_none=True)

        async with httpx.AsyncClient(transport=self._transport) as client:
            resp = await client.post(url, headers=self._headers(), json=payload)
            resp.raise_for_status()
            return cast(dict[str, Any], resp.json())

    async def post_merge_request_note(
        self,
        project_id: str | int,
        mr_iid: int,
        body: str,
    ) -> dict[str, Any]:
        """Publishes a general comment / summary note on a GitLab MR."""
        encoded_project = str(project_id).replace("/", "%2F")
        url = f"{self.base_url}/api/v4/projects/{encoded_project}/merge_requests/{mr_iid}/notes"
        payload = {"body": body}

        async with httpx.AsyncClient(transport=self._transport) as client:
            resp = await client.post(url, headers=self._headers(), json=payload)
            resp.raise_for_status()
            return cast(dict[str, Any], resp.json())
