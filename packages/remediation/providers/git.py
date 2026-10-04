"""Phase 6 Controlled Git Provider and Patch Application."""

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field


class GitPatchValidationResult(BaseModel):
    valid: bool
    files_changed: list[str] = Field(default_factory=list)
    lines_added: int = 0
    lines_removed: int = 0
    security_violations: list[str] = Field(default_factory=list)


class PullRequestInfo(BaseModel):
    pr_number: int
    title: str
    branch_name: str
    target_branch: str
    url: str
    diff: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class GitProvider(ABC):
    @abstractmethod
    def create_branch(self, repo_name: str, branch_name: str, base_branch: str = "main") -> str:
        pass

    @abstractmethod
    def apply_patch(self, repo_name: str, branch_name: str, diff: str) -> bool:
        pass

    @abstractmethod
    def create_pull_request(
        self,
        repo_name: str,
        branch_name: str,
        title: str,
        body: str,
        target_branch: str = "main",
    ) -> PullRequestInfo:
        pass


class ControlledGitProvider(GitProvider):
    """In-memory and policy-governed Git provider ensuring isolated branch and PR workflows."""

    def __init__(self, max_files_changed: int = 5, max_lines_changed: int = 300) -> None:
        self.max_files_changed = max_files_changed
        self.max_lines_changed = max_lines_changed
        self._branches: dict[str, list[str]] = {}
        self._prs: dict[int, PullRequestInfo] = {}
        self._pr_counter = 100

    def validate_patch(self, diff: str) -> GitPatchValidationResult:
        files: list[str] = []
        added = 0
        removed = 0
        violations: list[str] = []

        for line in diff.splitlines():
            if line.startswith("+++ b/"):
                filepath = line[6:].strip()
                files.append(filepath)
                # Check protected boundary paths
                if any(k in filepath for k in (".env", "id_rsa", "credentials", ".git", "security/")):
                    violations.append(f"Patch attempts to modify restricted security file: {filepath}")
            elif line.startswith("+") and not line.startswith("+++"):
                added += 1
                if any(secret in line.lower() for secret in ("password =", "secret_key =", "bearer ")):
                    violations.append("Patch introduces unredacted credential or secret token")
            elif line.startswith("-") and not line.startswith("---"):
                removed += 1

        if len(files) > self.max_files_changed:
            violations.append(f"Exceeded maximum files changed ({len(files)} > {self.max_files_changed})")

        if (added + removed) > self.max_lines_changed:
            violations.append(f"Exceeded maximum lines changed ({added + removed} > {self.max_lines_changed})")

        valid = len(violations) == 0
        return GitPatchValidationResult(
            valid=valid,
            files_changed=files,
            lines_added=added,
            lines_removed=removed,
            security_violations=violations,
        )

    def create_branch(self, repo_name: str, branch_name: str, base_branch: str = "main") -> str:
        if base_branch in ("main", "master") and branch_name == base_branch:
            raise PermissionError("Direct commits to protected branches (main/master) are blocked.")
        if repo_name not in self._branches:
            self._branches[repo_name] = []
        self._branches[repo_name].append(branch_name)
        return branch_name

    def apply_patch(self, repo_name: str, branch_name: str, diff: str) -> bool:
        val = self.validate_patch(diff)
        if not val.valid:
            raise ValueError(f"Patch validation failed: {'; '.join(val.security_violations)}")
        return True

    def create_pull_request(
        self,
        repo_name: str,
        branch_name: str,
        title: str,
        body: str,
        target_branch: str = "main",
    ) -> PullRequestInfo:
        self._pr_counter += 1
        pr = PullRequestInfo(
            pr_number=self._pr_counter,
            title=title,
            branch_name=branch_name,
            target_branch=target_branch,
            url=f"https://github.com/aegis-enterprise/{repo_name}/pull/{self._pr_counter}",
            diff=body,
            metadata={"repo": repo_name},
        )
        self._prs[self._pr_counter] = pr
        return pr


default_git_provider = ControlledGitProvider()
