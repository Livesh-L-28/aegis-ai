"""Deterministic local dependency vulnerability advisory analyzer for LogicFalcon."""

import re
from typing import Any

from packages.review.adapters.base import StaticAnalysisAdapter
from packages.review.domain.models import (
    FindingCategory,
    FindingOrigin,
    FindingSeverity,
    ProposedFix,
    ReviewFinding,
    SourceLocation,
)

# Curated offline advisory database of known critical vulnerabilities
KNOWN_ADVISORIES: list[dict[str, Any]] = [
    {
        "package": "requests",
        "vulnerable_max": (2, 31, 0),
        "safe_version": "2.31.0",
        "cve": "CVE-2023-32681",
        "description": "Requests before 2.31.0 leaks Proxy-Authorization headers to destination servers upon redirect.",
    },
    {
        "package": "urllib3",
        "vulnerable_max": (1, 26, 18),
        "safe_version": "1.26.18",
        "cve": "CVE-2023-45803",
        "description": "urllib3 before 1.26.18 does not strip HTTP request bodies on redirects, risking request smuggling.",
    },
    {
        "package": "jinja2",
        "vulnerable_max": (3, 1, 3),
        "safe_version": "3.1.3",
        "cve": "CVE-2024-22195",
        "description": "Jinja2 before 3.1.3 contains an HTML attribute injection vulnerability in xmlattr filter.",
    },
    {
        "package": "aiohttp",
        "vulnerable_max": (3, 9, 0),
        "safe_version": "3.9.0",
        "cve": "CVE-2023-47627",
        "description": "aiohttp before 3.9.0 is vulnerable to HTTP request smuggling via ambiguous header parsing.",
    },
    {
        "package": "cryptography",
        "vulnerable_max": (41, 0, 6),
        "safe_version": "41.0.6",
        "cve": "CVE-2023-49083",
        "description": "cryptography before 41.0.6 NULL pointer dereference in PKCS#7 certificate loading.",
    },
    {
        "package": "lodash",
        "vulnerable_max": (4, 17, 21),
        "safe_version": "4.17.21",
        "cve": "CVE-2021-23337",
        "description": "Lodash before 4.17.21 is vulnerable to Command Injection via template.",
    },
    {
        "package": "axios",
        "vulnerable_max": (0, 21, 2),
        "safe_version": "0.21.2",
        "cve": "CVE-2021-3749",
        "description": "axios before 0.21.2 is vulnerable to Regular Expression Denial of Service (ReDoS).",
    },
]


def _parse_version(version_str: str) -> tuple[int, ...] | None:
    parts: list[int] = []
    for segment in version_str.split("."):
        clean_seg = re.sub(r"[^\d]", "", segment)
        if clean_seg:
            try:
                parts.append(int(clean_seg))
            except ValueError:
                break
        else:
            break
    return tuple(parts) if parts else None


class DependencyAdvisoryAdapter(StaticAnalysisAdapter):
    """Analyzes package dependency declarations for known security advisories."""

    def __init__(self, custom_advisories: list[dict[str, Any]] | None = None) -> None:
        self.advisories = custom_advisories if custom_advisories is not None else KNOWN_ADVISORIES

    @property
    def name(self) -> str:
        return "dependency_advisory"

    def is_available(self) -> bool:
        return True

    def analyze_file(
        self,
        file_path: str,
        content: str,
        options: dict[str, Any] | None = None,
    ) -> list[ReviewFinding]:
        norm_path = file_path.lower()
        if not (
            norm_path.endswith("requirements.txt")
            or "requirements" in norm_path
            or norm_path.endswith("pyproject.toml")
            or norm_path.endswith("package.json")
        ):
            return []

        findings: list[ReviewFinding] = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            stripped = line.strip().split("#")[0].strip()
            if not stripped:
                continue

            # Match package pinning e.g. "requests==2.28.1", "requests<=2.30.0", '"axios": "^0.21.0"'
            for adv in self.advisories:
                pkg = adv["package"]
                pattern = rf"(?i)(?:^|[\"'\s])({pkg})[\"']?\s*(?:==|<=|<|:|\^|~=)\s*[\"'\^~><=\s]*([0-9\.]+)"
                match = re.search(pattern, stripped)

                if match:
                    parsed_ver = _parse_version(match.group(2))
                    vuln_max = tuple(adv["vulnerable_max"]) if isinstance(adv["vulnerable_max"], list) else adv["vulnerable_max"]
                    if parsed_ver and parsed_ver < vuln_max:
                        vuln_pkg = match.group(1)
                        vuln_ver = match.group(2)
                        safe_ver = adv["safe_version"]
                        cve = adv["cve"]
                        desc = adv["description"]

                        findings.append(
                            ReviewFinding(
                                rule_id="DEP-001",
                                title=f"Vulnerable Dependency Declared: {vuln_pkg} ({cve})",
                                message=(
                                    f"Declared dependency '{vuln_pkg}=={vuln_ver}' is vulnerable to {cve}. "
                                    f"{desc}"
                                ),
                                severity=FindingSeverity.ERROR,
                                category=FindingCategory.SECURITY,
                                origin=FindingOrigin.STATIC_ANALYSIS,
                                location=SourceLocation(
                                    file_path=file_path,
                                    start_line=line_idx,
                                    end_line=line_idx,
                                    symbol_name=vuln_pkg,
                                ),
                                suggestion=f"Upgrade '{vuln_pkg}' to >= {safe_ver}.",
                                why_it_matters=desc,
                                proposed_fix=ProposedFix(
                                    file_path=file_path,
                                    start_line=line_idx,
                                    end_line=line_idx,
                                    replacement_code=line.replace(vuln_ver, safe_ver),
                                    explanation=f"Bump {vuln_pkg} from {vuln_ver} to {safe_ver} to remediate {cve}.",
                                ),
                                tool_name=self.name,
                                confidence=1.0,
                                metadata={
                                    "package": vuln_pkg,
                                    "declared_version": vuln_ver,
                                    "safe_version": safe_ver,
                                    "cve": cve,
                                },
                            )
                        )

        return findings
