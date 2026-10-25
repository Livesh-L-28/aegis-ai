"""Static symbol extractor for Python and JavaScript/TypeScript in LogicFalcon."""

import ast
import re
from pathlib import Path

from packages.review.reverse_engineering.models import (
    AnalysisLimitation,
    ExtractedSymbol,
    SymbolKind,
)


class SymbolExtractor:
    """Extracts classes, functions, methods, and callees from source code."""

    def __init__(self, repo_root: Path | str) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.limitations: list[AnalysisLimitation] = []

    def extract_file_symbols(self, file_path: Path | str, content: str | None = None) -> list[ExtractedSymbol]:
        """Extracts all top-level and method symbols from a single file."""
        target_path = Path(file_path)
        if not target_path.is_absolute():
            target_path = self.repo_root / target_path

        rel_path = str(target_path.relative_to(self.repo_root)) if target_path.is_relative_to(self.repo_root) else str(target_path)

        if content is None:
            try:
                content = target_path.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                self.limitations.append(
                    AnalysisLimitation(
                        category="unreadable_file",
                        file_path=rel_path,
                        description=f"Cannot read file for symbol extraction: {e}",
                    )
                )
                return []

        ext = target_path.suffix.lower()
        if ext == ".py":
            return self._extract_python_symbols(content, rel_path)
        elif ext in (".js", ".ts", ".jsx", ".tsx"):
            return self._extract_js_ts_symbols(content, rel_path)

        return []

    def _extract_python_symbols(self, content: str, rel_path: str) -> list[ExtractedSymbol]:
        symbols: list[ExtractedSymbol] = []
        try:
            tree = ast.parse(content, filename=rel_path)
        except SyntaxError as e:
            self.limitations.append(
                AnalysisLimitation(
                    category="malformed_syntax",
                    file_path=rel_path,
                    line_number=e.lineno,
                    description=f"Syntax error during symbol extraction: {e.msg}",
                )
            )
            return []

        seen_keys: set[tuple[str, str, int]] = set()

        def _traverse(node: ast.AST, scope: list[tuple[str, str]]) -> None:
            if isinstance(node, ast.ClassDef):
                doc = ast.get_docstring(node)
                decorators = [self._unparse_node(d) for d in node.decorator_list]
                qname = ".".join([s[0] for s in scope] + [node.name])
                key = (rel_path, qname, node.lineno)
                if key not in seen_keys:
                    seen_keys.add(key)
                    symbols.append(
                        ExtractedSymbol(
                            name=node.name,
                            qualified_name=qname,
                            kind=SymbolKind.CLASS,
                            file_path=rel_path,
                            start_line=node.lineno,
                            end_line=node.end_lineno or node.lineno,
                            docstring=doc,
                            decorators=decorators,
                            parameters=[],
                            return_type=None,
                            is_exported=not node.name.startswith("_"),
                        )
                    )
                for item in node.body:
                    _traverse(item, [*scope, (node.name, "class")])

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                doc = ast.get_docstring(node)
                decorators = [self._unparse_node(d) for d in node.decorator_list]
                params = [arg.arg for arg in node.args.args]
                ret_type = self._unparse_node(node.returns) if node.returns else None
                parent_is_class = bool(scope and scope[-1][1] == "class")
                parent_is_func = bool(scope and scope[-1][1] in ("function", "async_function", "method"))

                if parent_is_class:
                    kind = SymbolKind.METHOD
                    qname = ".".join([s[0] for s in scope] + [node.name])
                elif parent_is_func:
                    kind = SymbolKind.ASYNC_FUNCTION if isinstance(node, ast.AsyncFunctionDef) else SymbolKind.FUNCTION
                    qname = ".".join([s[0] for s in scope] + ["<locals>", node.name])
                else:
                    kind = SymbolKind.ASYNC_FUNCTION if isinstance(node, ast.AsyncFunctionDef) else SymbolKind.FUNCTION
                    qname = ".".join([s[0] for s in scope] + [node.name])

                key = (rel_path, qname, node.lineno)
                if key not in seen_keys:
                    seen_keys.add(key)
                    callees: list[str] = []
                    for inner in ast.walk(node):
                        if isinstance(inner, ast.Call):
                            call_name = self._resolve_call_name(inner.func)
                            if call_name and call_name not in callees:
                                callees.append(call_name)

                    symbols.append(
                        ExtractedSymbol(
                            name=node.name,
                            qualified_name=qname,
                            kind=kind,
                            file_path=rel_path,
                            start_line=node.lineno,
                            end_line=node.end_lineno or node.lineno,
                            docstring=doc,
                            decorators=decorators,
                            parameters=params,
                            return_type=ret_type,
                            is_exported=not node.name.startswith("_"),
                            callees=callees,
                        )
                    )

                # Traverse nested definitions within the function body
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        _traverse(item, [*scope, (node.name, kind.value)])

        for top_node in tree.body:
            _traverse(top_node, [])

        return symbols

    def _resolve_call_name(self, func_node: ast.expr) -> str | None:
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            val = self._resolve_call_name(func_node.value)
            if val:
                return f"{val}.{func_node.attr}"
            return func_node.attr
        return None

    def _unparse_node(self, node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return getattr(node, "id", "") or getattr(node, "attr", "") or ""

    def _extract_js_ts_symbols(self, content: str, rel_path: str) -> list[ExtractedSymbol]:
        symbols: list[ExtractedSymbol] = []
        lines = content.splitlines()

        # Regex for functions: function foo(...) or export function foo(...) or const foo = (...) =>
        fn_pattern = re.compile(
            r"^(?:export\s+)?(?:async\s+)?function\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)"
        )
        class_pattern = re.compile(
            r"^(?:export\s+)?class\s+([A-Za-z0-9_]+)"
        )
        arrow_pattern = re.compile(
            r"^(?:export\s+)?(?:const|let)\s+([A-Za-z0-9_]+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>"
        )

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Function match
            m_fn = fn_pattern.match(stripped)
            if m_fn:
                name = m_fn.group(1)
                symbols.append(
                    ExtractedSymbol(
                        name=name,
                        qualified_name=name,
                        kind=SymbolKind.FUNCTION,
                        file_path=rel_path,
                        start_line=line_no,
                        end_line=line_no,
                        parameters=[p.strip() for p in m_fn.group(2).split(",") if p.strip()],
                        is_exported="export" in stripped,
                    )
                )
                continue

            # Class match
            m_cls = class_pattern.match(stripped)
            if m_cls:
                name = m_cls.group(1)
                symbols.append(
                    ExtractedSymbol(
                        name=name,
                        qualified_name=name,
                        kind=SymbolKind.CLASS,
                        file_path=rel_path,
                        start_line=line_no,
                        end_line=line_no,
                        is_exported="export" in stripped,
                    )
                )
                continue

            # Arrow function match
            m_arrow = arrow_pattern.match(stripped)
            if m_arrow:
                name = m_arrow.group(1)
                symbols.append(
                    ExtractedSymbol(
                        name=name,
                        qualified_name=name,
                        kind=SymbolKind.FUNCTION,
                        file_path=rel_path,
                        start_line=line_no,
                        end_line=line_no,
                        is_exported="export" in stripped,
                    )
                )

        return symbols
