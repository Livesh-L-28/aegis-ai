"""In-process AST-based deterministic security and quality analyzer."""

import ast
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

CREDENTIAL_PATTERN = re.compile(
    r"(?i)(?:password|secret|token|api_key|private_key)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.=/+]{8,})['\"]"
)


class _ASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: list[ReviewFinding] = []
        self._with_context_depth = 0

    def visit_With(self, node: ast.With) -> None:
        self._with_context_depth += 1
        self.generic_visit(node)
        self._with_context_depth -= 1

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._with_context_depth += 1
        self.generic_visit(node)
        self._with_context_depth -= 1

    def _check_function_defaults(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for default in node.args.defaults + node.args.kw_defaults:
            if default is not None and isinstance(default, (ast.List, ast.Dict, ast.Set)):
                kind = "list" if isinstance(default, ast.List) else "dict" if isinstance(default, ast.Dict) else "set"
                self.findings.append(
                    ReviewFinding(
                        rule_id="QUAL-002",
                        title="Mutable Default Argument",
                        message=f"Function '{node.name}' uses a mutable {kind} as default argument.",
                        severity=FindingSeverity.WARNING,
                        category=FindingCategory.QUALITY,
                        origin=FindingOrigin.STATIC_ANALYSIS,
                        location=SourceLocation(
                            file_path=self.file_path,
                            start_line=default.lineno,
                            end_line=default.end_lineno or default.lineno,
                            symbol_name=node.name,
                        ),
                        suggestion=f"Use 'None' as default value and initialize new {kind} in the function body.",
                        why_it_matters="Python shares default argument instances across calls, leading to state leakage.",
                        proposed_fix=ProposedFix(
                            file_path=self.file_path,
                            start_line=default.lineno,
                            end_line=default.end_lineno or default.lineno,
                            replacement_code="None",
                            explanation=f"Replace mutable {kind} default with None and initialize inside the function.",
                        ),
                        tool_name="ast_security",
                        confidence=1.0,
                    )
                )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function_defaults(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function_defaults(node)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        for op, comp in zip(node.ops, node.comparators, strict=False):
            if (
                isinstance(op, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot))
                and ast.dump(node.left) == ast.dump(comp)
                and not isinstance(node.left, ast.Constant)
            ):
                self.findings.append(
                        ReviewFinding(
                            rule_id="QUAL-003",
                            title="Useless Self-Comparison",
                            message="Comparison of identical expression against itself is always constant.",
                            severity=FindingSeverity.WARNING,
                            category=FindingCategory.QUALITY,
                            origin=FindingOrigin.STATIC_ANALYSIS,
                            location=SourceLocation(
                                file_path=self.file_path,
                                start_line=node.lineno,
                                end_line=node.end_lineno or node.lineno,
                            ),
                            suggestion="Check if one operand was intended to reference another variable.",
                            why_it_matters="Self-comparisons (x == x) usually indicate a copy-paste mistake.",
                            tool_name="ast_security",
                            confidence=1.0,
                        )
                    )
        self.generic_visit(node)

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
                    why_it_matters="Dynamic evaluation can allow arbitrary code execution when untrusted data is evaluated.",
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
                            why_it_matters="Command strings passed to shell=True can be manipulated to run arbitrary shell commands.",
                            proposed_fix=ProposedFix(
                                file_path=self.file_path,
                                start_line=node.lineno,
                                end_line=node.end_lineno or node.lineno,
                                explanation="Pass command as a list of arguments and set shell=False.",
                            ),
                            tool_name="ast_security",
                            confidence=0.95,
                        )
                    )

        # SEC-004: insecure deserialization (pickle.loads, pickle.load)
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
                    why_it_matters="Pickle bytecode can construct arbitrary objects and execute arbitrary code on unpickling.",
                    tool_name="ast_security",
                    confidence=0.95,
                )
            )

        # SEC-006: tempfile.mktemp()
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "mktemp"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "tempfile"
        ):
            self.findings.append(
                ReviewFinding(
                    rule_id="SEC-006",
                    title="Insecure Temporary File Creation",
                    message="tempfile.mktemp() is deprecated and vulnerable to symlink race conditions (TOCTOU).",
                    severity=FindingSeverity.ERROR,
                    category=FindingCategory.SECURITY,
                    origin=FindingOrigin.SECURITY_HEURISTIC,
                    location=SourceLocation(
                        file_path=self.file_path,
                        start_line=node.lineno,
                        end_line=node.end_lineno or node.lineno,
                        symbol_name="mktemp",
                    ),
                    suggestion="Use tempfile.NamedTemporaryFile() or tempfile.TemporaryDirectory() instead.",
                    why_it_matters="An attacker can create a symlink with the generated filename before the application opens it.",
                    tool_name="ast_security",
                    confidence=1.0,
                )
            )

        # SEC-007: SQL query dynamic string interpolation
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in ("execute", "executemany")
            and node.args
        ):
            first_arg = node.args[0]
            is_dynamic_sql = False
            if isinstance(first_arg, ast.JoinedStr):
                raw_parts = [p.value for p in first_arg.values if isinstance(p, ast.Constant) and isinstance(p.value, str)]
                sql_preview = " ".join(raw_parts).upper()
                if any(kw in sql_preview for kw in ("SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER")):
                    is_dynamic_sql = True
            elif (
                isinstance(first_arg, ast.BinOp)
                and isinstance(first_arg.op, ast.Mod)
                and isinstance(first_arg.left, ast.Constant)
                and isinstance(first_arg.left.value, str)
                and any(kw in first_arg.left.value.upper() for kw in ("SELECT", "INSERT", "UPDATE", "DELETE"))
            ):
                is_dynamic_sql = True

            if is_dynamic_sql:
                self.findings.append(
                    ReviewFinding(
                        rule_id="SEC-007",
                        title="Potential SQL Injection via Dynamic String Formatting",
                        message="SQL query executed with unparameterized dynamic string interpolation.",
                        severity=FindingSeverity.CRITICAL,
                        category=FindingCategory.SECURITY,
                        origin=FindingOrigin.SECURITY_HEURISTIC,
                        location=SourceLocation(
                            file_path=self.file_path,
                            start_line=first_arg.lineno,
                            end_line=first_arg.end_lineno or first_arg.lineno,
                        ),
                        suggestion="Use parameterized query placeholders and pass parameters as an explicit sequence or dict.",
                        why_it_matters="String formatting allows attackers to inject arbitrary SQL statements.",
                        tool_name="ast_security",
                        confidence=0.95,
                    )
                )

        # QUAL-006: open() outside of with context
        if isinstance(node.func, ast.Name) and node.func.id == "open" and self._with_context_depth == 0:
            self.findings.append(
                ReviewFinding(
                    rule_id="QUAL-006",
                    title="Unmanaged File Resource (Missing Context Manager)",
                    message="File opened without 'with' statement context manager risks resource leaks.",
                    severity=FindingSeverity.WARNING,
                    category=FindingCategory.RELIABILITY,
                    origin=FindingOrigin.STATIC_ANALYSIS,
                    location=SourceLocation(
                        file_path=self.file_path,
                        start_line=node.lineno,
                        end_line=node.end_lineno or node.lineno,
                        symbol_name="open",
                    ),
                    suggestion="Use 'with open(...) as f:' to ensure the file descriptor is closed.",
                    why_it_matters="Unclosed file handles remain open until garbage collection, risking descriptor exhaustion.",
                    proposed_fix=ProposedFix(
                        file_path=self.file_path,
                        start_line=node.lineno,
                        end_line=node.end_lineno or node.lineno,
                        explanation="Wrap file access in a 'with' context manager to guarantee automatic resource cleanup.",
                    ),
                    tool_name="ast_security",
                    confidence=0.9,
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
                    why_it_matters="Suppressing all exceptions hides bugs, interrupts, and crashes.",
                    proposed_fix=ProposedFix(
                        file_path=self.file_path,
                        start_line=node.lineno,
                        end_line=node.end_lineno or node.lineno,
                        explanation="Catch specific exception types and log or handle the error gracefully.",
                    ),
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
