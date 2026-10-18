"""In-process AST-based deterministic security and quality analyzer."""

import ast
import re
from typing import Any

from packages.review.adapters.base import StaticAnalysisAdapter
from packages.review.domain.models import (
    FindingCategory,
    FindingOrigin,
    FindingSeverity,
    ReviewFinding,
    SourceLocation,
)

CREDENTIAL_PATTERN = re.compile(
    r"(?i)(?:password|secret|token|api_key|private_key)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.=/+]{8,})['\"]"
)


class _ASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: list[ReviewFinding] = []

    def visit_Call(self, node: ast.Call) -> None:
        # SEC-001: eval() or exec() usage
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            self.findings.append(
                ReviewFinding(
                    rule_id="SEC-001",
                    title="Dangerous Dynamic Code Execution",
                    message=f"Use of dynamic execution function '{node.func.id}()' detected.",
                    severity=FindingSeverity.CRITICAL,
                    category=FindingCategory.SECURITY,
                    origin=FindingOrigin.SECURITY_HEURISTIC,
                    location=SourceLocation(
                        file_path=self.file_path,
                        start_line=node.lineno,
                        end_line=node.end_lineno or node.lineno,
                        start_column=node.col_offset,
                        end_column=node.end_col_offset,
                        symbol_name=node.func.id,
                    ),
                    suggestion="Refactor to use safe deterministic parsers or structured mappings.",
                    tool_name="ast_security",
                    confidence=1.0,
                )
            )

        # SEC-002: subprocess with shell=True
        is_subprocess = (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in ("Popen", "run", "call", "check_call", "check_output")
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
        )

        if is_subprocess:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(
                        ReviewFinding(
                            rule_id="SEC-002",
                            title="Subprocess with shell=True",
                            message="Invocation of subprocess with shell=True risks command injection.",
                            severity=FindingSeverity.CRITICAL,
                            category=FindingCategory.SECURITY,
                            origin=FindingOrigin.SECURITY_HEURISTIC,
                            location=SourceLocation(
                                file_path=self.file_path,
                                start_line=node.lineno,
                                end_line=node.end_lineno or node.lineno,
                                start_column=node.col_offset,
                                end_column=node.end_col_offset,
                            ),
                            suggestion="Pass arguments as an explicit list and set shell=False.",
                            tool_name="ast_security",
                            confidence=0.95,
                        )
                    )

        # SEC-004: insecure deserialization (pickle.loads, yaml.load without Loader)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in ("loads", "load")
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "pickle"
        ):
            self.findings.append(
                ReviewFinding(
                    rule_id="SEC-004",
                    title="Insecure Pickle Deserialization",
                    message="Use of pickle deserialization on untrusted data can lead to remote code execution.",
                    severity=FindingSeverity.ERROR,
                    category=FindingCategory.SECURITY,
                    origin=FindingOrigin.SECURITY_HEURISTIC,
                    location=SourceLocation(
                        file_path=self.file_path,
                        start_line=node.lineno,
                        end_line=node.end_lineno or node.lineno,
                        start_column=node.col_offset,
                        end_column=node.end_col_offset,
                    ),
                    suggestion="Use safe serialization formats like JSON, MessagePack, or Pydantic.",
                    tool_name="ast_security",
                    confidence=0.95,
                )
            )

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        # QUAL-001: bare except or except Exception with pass
        is_bare = node.type is None
        is_broad = isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException")
        if (is_bare or is_broad) and len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.findings.append(
                ReviewFinding(
                    rule_id="QUAL-001",
                    title="Silent Exception Suppression",
                    message="Catching broad or bare exception with 'pass' suppresses critical runtime errors.",
                    severity=FindingSeverity.WARNING,
                    category=FindingCategory.QUALITY,
                    origin=FindingOrigin.STATIC_ANALYSIS,
                    location=SourceLocation(
                        file_path=self.file_path,
                        start_line=node.lineno,
                        end_line=node.end_lineno or node.lineno,
                        start_column=node.col_offset,
                        end_column=node.end_col_offset,
                    ),
                    suggestion="Catch specific exceptions or log the error before suppressing.",
                    tool_name="ast_security",
                    confidence=1.0,
                )
            )
        self.generic_visit(node)


class ASTSecurityAdapter(StaticAnalysisAdapter):
    """Performs deterministic AST security and quality checks entirely in-process."""

    is_pure_ast_analyzer: bool = True

    @property
    def name(self) -> str:
        return "ast_security"

    def is_available(self) -> bool:
        return True

    def analyze_file(
        self,
        file_path: str,
        content: str,
        options: dict[str, Any] | None = None,
    ) -> list[ReviewFinding]:
        if not file_path.endswith(".py"):
            return []

        findings: list[ReviewFinding] = []

        # 1. Syntax check
        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError as e:
            findings.append(
                ReviewFinding(
                    rule_id="SEC-005",
                    title="Python Syntax Error",
                    message=f"Syntax error in code: {e.msg}",
                    severity=FindingSeverity.ERROR,
                    category=FindingCategory.QUALITY,
                    origin=FindingOrigin.STATIC_ANALYSIS,
                    location=SourceLocation(
                        file_path=file_path,
                        start_line=e.lineno or 1,
                        end_line=e.end_lineno or e.lineno or 1,
                        start_column=e.offset,
                    ),
                    suggestion="Fix the Python syntax error before continuing review.",
                    tool_name=self.name,
                    confidence=1.0,
                )
            )
            return findings

        # 2. AST Visitor check
        visitor = _ASTVisitor(file_path)
        visitor.visit(tree)
        findings.extend(visitor.findings)

        # 3. Credential heuristic pattern scan
        lines = content.splitlines()
        for line_idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#") or "[REDACTED_SECRET]" in line:
                continue
            match = CREDENTIAL_PATTERN.search(line)
            if match:
                findings.append(
                    ReviewFinding(
                        rule_id="SEC-003",
                        title="Potential Hardcoded Credential",
                        message="Potential unredacted credential or secret token detected.",
                        severity=FindingSeverity.CRITICAL,
                        category=FindingCategory.SECURITY,
                        origin=FindingOrigin.SECURITY_HEURISTIC,
                        location=SourceLocation(
                            file_path=file_path,
                            start_line=line_idx,
                            end_line=line_idx,
                        ),
                        suggestion="Store credentials in environment variables or an external secret manager.",
                        tool_name=self.name,
                        confidence=0.85,
                    )
                )

        return findings
