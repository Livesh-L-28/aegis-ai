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
URI_CREDENTIAL_PATTERN = re.compile(
    r"([a-zA-Z0-9_+]+://[^:\s]+:)([^@\s]+)(@[^\s\"'\`]+)"
)
TOKEN_PATTERN = re.compile(
    r"(?:ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|bearer\s+[a-zA-Z0-9_\-\.=/+]{16,})"
)


def redact_secrets_in_text(text: str) -> str:
    """Replaces any potential hardcoded secret, token, or connection string credentials with redaction markers."""
    res = CREDENTIAL_PATTERN.sub(
        lambda m: m.group(0).replace(m.group(1), "[REDACTED_SECRET]"),
        text,
    )
    res = URI_CREDENTIAL_PATTERN.sub(
        r"\1[REDACTED_PASSWORD]\3",
        res,
    )
    return TOKEN_PATTERN.sub("[REDACTED_TOKEN]", res)


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

        # SEC-002: subprocess with shell=True or os.system / os.popen
        is_subprocess = (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in ("Popen", "run", "call", "check_call", "check_output")
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
        )
        is_os_cmd = (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in ("system", "popen")
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
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
        elif is_os_cmd and isinstance(node.func, ast.Attribute):
            cmd_func = f"os.{node.func.attr}"
            self.findings.append(
                ReviewFinding(
                    rule_id="SEC-002",
                    title=f"Insecure Shell Command Execution ({cmd_func})",
                    message=f"Invocation of '{cmd_func}()' executes arbitrary shell commands and risks command injection.",
                    severity=FindingSeverity.CRITICAL,
                    category=FindingCategory.SECURITY,
                    origin=FindingOrigin.SECURITY_HEURISTIC,
                    location=SourceLocation(
                        file_path=self.file_path,
                        start_line=node.lineno,
                        end_line=node.end_lineno or node.lineno,
                        start_column=node.col_offset,
                        end_column=node.end_col_offset,
                        symbol_name=cmd_func,
                    ),
                    suggestion="Use subprocess.run([...], shell=False) with an argument list instead.",
                    why_it_matters="Commands passed to os.system() or os.popen() run via the system shell, enabling command injection.",
                    tool_name="ast_security",
                    confidence=1.0,
                )
            )

        # SEC-004: insecure deserialization (pickle, marshal, shelve)
        is_pickle = (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in ("loads", "load")
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "pickle"
        )
        is_marshal = (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in ("loads", "load")
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "marshal"
        )
        is_shelve = (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "open"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "shelve"
        )

        if (is_pickle or is_marshal or is_shelve) and isinstance(node.func, ast.Attribute):
            lib_name = "pickle" if is_pickle else ("marshal" if is_marshal else "shelve")
            action_desc = f"{lib_name}.{node.func.attr}()"

            self.findings.append(
                ReviewFinding(
                    rule_id="SEC-004",
                    title=f"Insecure {lib_name.capitalize()} Deserialization",
                    message=f"Use of {action_desc} on untrusted data can lead to arbitrary code execution.",
                    severity=FindingSeverity.ERROR,
                    category=FindingCategory.SECURITY,
                    origin=FindingOrigin.SECURITY_HEURISTIC,
                    location=SourceLocation(
                        file_path=self.file_path,
                        start_line=node.lineno,
                        end_line=node.end_lineno or node.lineno,
                        start_column=node.col_offset,
                        end_column=node.end_col_offset,
                        symbol_name=action_desc,
                    ),
                    suggestion="Use safe serialization formats like JSON, MessagePack, or Pydantic.",
                    why_it_matters=f"{lib_name.capitalize()} deserialization can construct arbitrary objects and execute arbitrary code.",
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

        # SEC-008: Unsafe YAML deserialization
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "load"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "yaml"
        ):
            loader_arg = None
            for kw in node.keywords:
                if kw.arg == "Loader":
                    loader_arg = kw.value
            is_unsafe_yaml = True
            if (
                loader_arg
                and isinstance(loader_arg, ast.Attribute)
                and loader_arg.attr in ("SafeLoader", "CSafeLoader")
            ):
                is_unsafe_yaml = False
            if is_unsafe_yaml:
                self.findings.append(
                    ReviewFinding(
                        rule_id="SEC-008",
                        title="Insecure YAML Deserialization",
                        message="yaml.load() without SafeLoader is vulnerable to arbitrary object instantiation and code execution.",
                        severity=FindingSeverity.CRITICAL,
                        category=FindingCategory.SECURITY,
                        origin=FindingOrigin.SECURITY_HEURISTIC,
                        location=SourceLocation(
                            file_path=self.file_path,
                            start_line=node.lineno,
                            end_line=node.end_lineno or node.lineno,
                            symbol_name="yaml.load",
                        ),
                        suggestion="Use yaml.safe_load() or specify Loader=yaml.SafeLoader.",
                        why_it_matters="Default or unrestricted PyYAML loaders can instantiate arbitrary Python objects.",
                        tool_name="ast_security",
                        confidence=1.0,
                    )
                )

        # SEC-009: Insecure archive extraction (path traversal / Zip Slip)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "extractall":
            has_safe_filter = False
            for kw in node.keywords:
                if kw.arg == "filter" and isinstance(kw.value, ast.Constant) and kw.value.value in ("data", "tar"):
                    has_safe_filter = True
            if not has_safe_filter:
                self.findings.append(
                    ReviewFinding(
                        rule_id="SEC-009",
                        title="Unsafe Archive Extraction (Path Traversal Risk)",
                        message="Calling extractall() without explicit safe filtering can overwrite arbitrary files (Zip Slip / Tarbomb).",
                        severity=FindingSeverity.ERROR,
                        category=FindingCategory.SECURITY,
                        origin=FindingOrigin.SECURITY_HEURISTIC,
                        location=SourceLocation(
                            file_path=self.file_path,
                            start_line=node.lineno,
                            end_line=node.end_lineno or node.lineno,
                            symbol_name="extractall",
                        ),
                        suggestion="For tarfile, use filter='data' (Python 3.12+). For zipfile, validate members before extraction.",
                        why_it_matters="Archives containing filenames with '../' or absolute paths can escape the extraction directory.",
                        tool_name="ast_security",
                        confidence=0.9,
                    )
                )

        # SEC-010: Insecure XML entity expansion
        if isinstance(node.func, ast.Attribute):
            is_xml_parse = False
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id in ("minidom", "etree", "ElementTree")
                and node.func.attr in ("parse", "fromstring", "parseString")
            ) or (
                isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "ElementTree"
                and node.func.attr in ("parse", "fromstring")
            ):
                is_xml_parse = True

            if is_xml_parse:
                self.findings.append(
                    ReviewFinding(
                        rule_id="SEC-010",
                        title="Insecure XML Parsing (XXE / Entity Expansion Risk)",
                        message="Standard library XML parsers are vulnerable to XML entity expansion and external entity injection (XXE).",
                        severity=FindingSeverity.WARNING,
                        category=FindingCategory.SECURITY,
                        origin=FindingOrigin.SECURITY_HEURISTIC,
                        location=SourceLocation(
                            file_path=self.file_path,
                            start_line=node.lineno,
                            end_line=node.end_lineno or node.lineno,
                            symbol_name=node.func.attr,
                        ),
                        suggestion="Use defusedxml (e.g. defusedxml.ElementTree) for parsing untrusted XML input.",
                        why_it_matters="Untrusted XML can exploit entity expansion (Billion Laughs) or external DTD retrieval.",
                        tool_name="ast_security",
                        confidence=0.9,
                    )
                )

        # REL-002: Network request without explicit timeout
        is_http_request = False
        http_lib = ""
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id in ("requests", "httpx")
                and node.func.attr in ("get", "post", "put", "delete", "patch", "head", "request")
            ):
                is_http_request = True
                http_lib = f"{node.func.value.id}.{node.func.attr}"
            elif (
                isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "request"
                and node.func.attr == "urlopen"
            ):
                is_http_request = True
                http_lib = "urllib.request.urlopen"

        if is_http_request:
            has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
            if not has_timeout:
                self.findings.append(
                    ReviewFinding(
                        rule_id="REL-002",
                        title="HTTP Request Missing Timeout",
                        message=f"Invocation of '{http_lib}()' without explicit timeout risks blocking the thread indefinitely.",
                        severity=FindingSeverity.WARNING,
                        category=FindingCategory.RELIABILITY,
                        origin=FindingOrigin.STATIC_ANALYSIS,
                        location=SourceLocation(
                            file_path=self.file_path,
                            start_line=node.lineno,
                            end_line=node.end_lineno or node.lineno,
                            symbol_name=http_lib,
                        ),
                        suggestion="Specify an explicit timeout in seconds, e.g., timeout=10.0.",
                        why_it_matters="Default timeouts in HTTP clients can hang indefinitely on network drops or unresponsive servers.",
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
                        technical_evidence=redact_secrets_in_text(line).strip(),
                        suggestion="Store credentials in environment variables or an external secret manager.",
                        tool_name=self.name,
                        confidence=0.85,
                    )
                )

        return findings
