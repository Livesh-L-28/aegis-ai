"""Deterministic, static JavaScript and TypeScript AST analyzer for AEGIS AI.

Extracts functions, classes, methods, interfaces, type aliases, enums, constants,
and import/export dependencies without executing code.
"""

import re
from typing import ClassVar

from packages.intelligence.code.indexer import (
    CodeDependency,
    CodeSymbol,
    SymbolType,
    sanitize_source_content,
)
from packages.intelligence.code.parser_base import (
    LanguageParser,
    ParseError,
    ParseResult,
    ParserSupportStatus,
)

# Regular expressions for imports and exports
IMPORT_FROM_RE = re.compile(
    r"""import\s+(?:type\s+)?(?:([a-zA-Z_$][\w$]*)\s*,?\s*)?(?:\{\s*([^}]+)\s*\}\s*,?\s*)?(?:\*\s*as\s+([a-zA-Z_$][\w$]*)\s*)?from\s*['"]([^'"]+)['"]""",
    re.MULTILINE,
)
IMPORT_SIDE_EFFECT_RE = re.compile(r"""import\s*['"]([^'"]+)['"]""", re.MULTILINE)
REQUIRE_RE = re.compile(r"""(?:const|let|var)\s+(?:\{\s*([^}]+)\s*\}|([a-zA-Z_$][\w$]*))\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)""")
DYNAMIC_IMPORT_RE = re.compile(r"""import\s*\(\s*['"]([^'"]+)['"]\s*\)""")
RE_EXPORT_RE = re.compile(r"""export\s+(?:(?:\{\s*([^}]+)\s*\}|\*\s*(?:as\s+([a-zA-Z_$][\w$]*))?)\s+from\s*['"]([^'"]+)['"])""")

# Declarations supporting standard and unicode identifiers
ID_PATTERN = r"""(?:[a-zA-Z_$][\w$]*|[^\W\d]\w*)"""
CLASS_RE = re.compile(
    rf"""^(?:export\s+)?(?:default\s+)?class\s+({ID_PATTERN})(?:\s+extends\s+([a-zA-Z_$][\w$.]*|[^\W\d]\w*))?(?:\s+implements\s+([^\{{]+))?""",
    re.MULTILINE,
)
INTERFACE_RE = re.compile(
    rf"""^(?:export\s+)?interface\s+({ID_PATTERN})(?:\s+extends\s+([^\{{]+))?""",
    re.MULTILINE,
)
TYPE_ALIAS_RE = re.compile(
    rf"""^(?:export\s+)?type\s+({ID_PATTERN})\s*(?:<[^>]+>)?\s*=""",
    re.MULTILINE,
)
ENUM_RE = re.compile(
    rf"""^(?:export\s+)?(?:const\s+)?enum\s+({ID_PATTERN})\s*\{{""",
    re.MULTILINE,
)
FUNCTION_DECL_RE = re.compile(
    rf"""^(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*({ID_PATTERN})?\s*\(([^)]*)\)""",
    re.MULTILINE,
)
VAR_FUNCTION_RE = re.compile(
    rf"""^(?:export\s+)?(?:const|let|var)\s+({ID_PATTERN})\s*(?::\s*[^=]+)?\s*=\s*(?:async\s*)?(?:\([^)]*\)|{ID_PATTERN})\s*(?::\s*[^=>]+)?\s*=>""",
    re.MULTILINE,
)
CONST_DECL_RE = re.compile(
    rf"""^(?:export\s+)?const\s+({ID_PATTERN})\s*(?::\s*[^=]+)?\s*=""",
    re.MULTILINE,
)
METHOD_RE = re.compile(
    rf"""^\s*(?:(?:public|private|protected|static|async|readonly|override)\s+)*({ID_PATTERN})\s*\(([^)]*)\)(?:\s*:\s*[^{{;]+)?\s*\{{"""
)


class JavaScriptTypeScriptParser(LanguageParser):
    """Static parser for JavaScript and TypeScript repositories supporting ES Modules and CommonJS."""

    language: str = "typescript"
    parser_version: str = "2.0.0"
    supported_extensions: ClassVar[set[str]] = {
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".d.ts",
    }
    support_status: ParserSupportStatus = ParserSupportStatus.SUPPORTED

    def parse_source(self, file_path: str, source_code: str) -> ParseResult:
        clean_code = sanitize_source_content(source_code)
        lines = clean_code.splitlines()
        symbols: list[CodeSymbol] = []
        dependencies: list[CodeDependency] = []
        exports: list[str] = []
        errors: list[ParseError] = []

        is_ts = file_path.lower().endswith((".ts", ".tsx", ".d.ts"))
        lang_id = "typescript" if is_ts else "javascript"

        # 1. Check brace balance for syntax error detection
        open_braces = clean_code.count("{")
        close_braces = clean_code.count("}")
        if open_braces != close_braces:
            errors.append(
                ParseError(
                    file_path=file_path,
                    line=len(lines),
                    column=1,
                    message=f"Syntax error: Unbalanced braces in {file_path} (open: {open_braces}, close: {close_braces})",
                    error_type="SYNTAX_ERROR",
                )
            )

        # 2. Extract Imports
        self._extract_imports(file_path, clean_code, dependencies)

        # 3. Extract Re-exports
        self._extract_re_exports(file_path, clean_code, dependencies, exports)

        # 4. Extract Symbols (Classes, Interfaces, Functions, Types, Enums)
        self._extract_symbols(file_path, lines, symbols, exports, errors)

        return ParseResult(
            file_path=file_path,
            language=lang_id,
            support_status=self.support_status,
            parser_name="JavaScriptTypeScriptParser",
            parser_version=self.parser_version,
            symbols=symbols,
            dependencies=dependencies,
            exports=exports,
            errors=errors,
            is_success=len(errors) == 0,
        )

    def _extract_imports(
        self,
        file_path: str,
        content: str,
        dependencies: list[CodeDependency],
    ) -> None:
        # ES import statements: import ... from '...'
        for match in IMPORT_FROM_RE.finditer(content):
            default_name, named_part, ns_name, target = match.groups()
            imported_names: list[str] = []
            if default_name:
                imported_names.append(default_name)
            if ns_name:
                imported_names.append(f"* as {ns_name}")
            if named_part:
                for item in named_part.split(","):
                    name = item.strip().split(" as ")[0].strip()
                    if name:
                        imported_names.append(name)

            is_type_only = bool(re.search(r"import\s+type\b", match.group(0)))
            resolution = self._classify_module_target(target)
            dependencies.append(
                CodeDependency(
                    source_file=file_path,
                    target_module=target,
                    imported_names=imported_names,
                    edge_type="IMPORT",
                    resolution_quality=resolution,
                    is_type_only=is_type_only,
                )
            )

        # Side-effect imports: import '...'
        for match in IMPORT_SIDE_EFFECT_RE.finditer(content):
            target = match.group(1)
            # Avoid duplicating if already caught by IMPORT_FROM_RE
            if any(d.target_module == target for d in dependencies):
                continue
            resolution = self._classify_module_target(target)
            dependencies.append(
                CodeDependency(
                    source_file=file_path,
                    target_module=target,
                    imported_names=[],
                    edge_type="IMPORT",
                    resolution_quality=resolution,
                    is_type_only=False,
                )
            )

        # CommonJS: require('...')
        for match in REQUIRE_RE.finditer(content):
            destructured, single_var, target = match.groups()
            imported_names = []
            if single_var:
                imported_names.append(single_var)
            if destructured:
                imported_names.extend([s.strip() for s in destructured.split(",") if s.strip()])
            resolution = self._classify_module_target(target)
            dependencies.append(
                CodeDependency(
                    source_file=file_path,
                    target_module=target,
                    imported_names=imported_names,
                    edge_type="IMPORT",
                    resolution_quality=resolution,
                    is_type_only=False,
                )
            )

        # Dynamic import('...')
        for match in DYNAMIC_IMPORT_RE.finditer(content):
            target = match.group(1)
            if not any(d.target_module == target for d in dependencies):
                resolution = self._classify_module_target(target)
                dependencies.append(
                    CodeDependency(
                        source_file=file_path,
                        target_module=target,
                        imported_names=[],
                        edge_type="IMPORT",
                        resolution_quality=resolution,
                        is_type_only=False,
                    )
                )

    def _extract_re_exports(
        self,
        file_path: str,
        content: str,
        dependencies: list[CodeDependency],
        exports: list[str],
    ) -> None:
        for match in RE_EXPORT_RE.finditer(content):
            named_part, ns_name, target = match.groups()
            exported_names: list[str] = []
            if ns_name:
                exported_names.append(f"* as {ns_name}")
            if named_part:
                for item in named_part.split(","):
                    n = item.strip().split(" as ")[-1].strip()
                    if n:
                        exported_names.append(n)
                        exports.append(n)
            resolution = self._classify_module_target(target)
            dependencies.append(
                CodeDependency(
                    source_file=file_path,
                    target_module=target,
                    imported_names=exported_names,
                    edge_type="EXPORT_FROM",
                    resolution_quality=resolution,
                    is_type_only=False,
                )
            )

    def _extract_symbols(
        self,
        file_path: str,
        lines: list[str],
        symbols: list[CodeSymbol],
        exports: list[str],
        errors: list[ParseError],
    ) -> None:
        total_lines = len(lines)
        idx = 0

        while idx < total_lines:
            line = lines[idx]
            stripped = line.strip()

            # Skip comments and blank lines
            if not stripped or stripped.startswith(("//", "/*", "*")):
                idx += 1
                continue

            docstring = self._lookup_preceding_jsdoc(lines, idx)
            line_no = idx + 1

            # 1. Classes
            cls_match = CLASS_RE.match(stripped)
            if cls_match:
                cls_name = cls_match.group(1)
                end_line = self._find_closing_brace(lines, idx)
                sig = f"class {cls_name}"
                if cls_match.group(2):
                    sig += f" extends {cls_match.group(2)}"
                cls_sym = CodeSymbol(
                    file_path=file_path,
                    symbol_type=SymbolType.CLASS,
                    name=cls_name,
                    qualified_name=cls_name,
                    start_line=line_no,
                    end_line=end_line,
                    signature=sig,
                    docstring=docstring,
                )
                symbols.append(cls_sym)
                if "export " in stripped:
                    exports.append(cls_name)

                # Inspect methods inside class body
                self._extract_class_methods(file_path, lines, idx, end_line, cls_name, symbols)
                idx = max(idx + 1, end_line)
                continue

            # 2. Interfaces
            iface_match = INTERFACE_RE.match(stripped)
            if iface_match:
                iface_name = iface_match.group(1)
                end_line = self._find_closing_brace(lines, idx)
                symbols.append(
                    CodeSymbol(
                        file_path=file_path,
                        symbol_type=SymbolType.INTERFACE,
                        name=iface_name,
                        qualified_name=iface_name,
                        start_line=line_no,
                        end_line=end_line,
                        signature=f"interface {iface_name}",
                        docstring=docstring,
                    )
                )
                if "export " in stripped:
                    exports.append(iface_name)
                idx = max(idx + 1, end_line)
                continue

            # 3. Type Aliases
            type_match = TYPE_ALIAS_RE.match(stripped)
            if type_match:
                t_name = type_match.group(1)
                symbols.append(
                    CodeSymbol(
                        file_path=file_path,
                        symbol_type=SymbolType.TYPE_ALIAS,
                        name=t_name,
                        qualified_name=t_name,
                        start_line=line_no,
                        end_line=line_no,
                        signature=f"type {t_name}",
                        docstring=docstring,
                    )
                )
                if "export " in stripped:
                    exports.append(t_name)
                idx += 1
                continue

            # 4. Enums
            enum_match = ENUM_RE.match(stripped)
            if enum_match:
                e_name = enum_match.group(1)
                end_line = self._find_closing_brace(lines, idx)
                symbols.append(
                    CodeSymbol(
                        file_path=file_path,
                        symbol_type=SymbolType.ENUM,
                        name=e_name,
                        qualified_name=e_name,
                        start_line=line_no,
                        end_line=end_line,
                        signature=f"enum {e_name}",
                        docstring=docstring,
                    )
                )
                if "export " in stripped:
                    exports.append(e_name)
                idx = max(idx + 1, end_line)
                continue

            # 5. Functions
            fn_match = FUNCTION_DECL_RE.match(stripped)
            if fn_match and fn_match.group(1):
                fn_name = fn_match.group(1)
                end_line = self._find_closing_brace(lines, idx)
                sig = f"function {fn_name}({fn_match.group(2)})"
                symbols.append(
                    CodeSymbol(
                        file_path=file_path,
                        symbol_type=SymbolType.FUNCTION,
                        name=fn_name,
                        qualified_name=fn_name,
                        start_line=line_no,
                        end_line=end_line,
                        signature=sig,
                        docstring=docstring,
                    )
                )
                if "export " in stripped:
                    exports.append(fn_name)
                idx = max(idx + 1, end_line)
                continue

            # 6. Arrow function assignments: const f = () => { ... }
            arrow_match = VAR_FUNCTION_RE.match(stripped)
            if arrow_match:
                fn_name = arrow_match.group(1)
                end_line = self._find_closing_brace(lines, idx) if "{" in stripped else line_no
                symbols.append(
                    CodeSymbol(
                        file_path=file_path,
                        symbol_type=SymbolType.FUNCTION,
                        name=fn_name,
                        qualified_name=fn_name,
                        start_line=line_no,
                        end_line=end_line,
                        signature=f"const {fn_name} = () => ...",
                        docstring=docstring,
                    )
                )
                if "export " in stripped:
                    exports.append(fn_name)
                idx = max(idx + 1, end_line)
                continue

            # 7. Constants: export const FOO = 10;
            const_match = CONST_DECL_RE.match(stripped)
            if const_match:
                c_name = const_match.group(1)
                symbols.append(
                    CodeSymbol(
                        file_path=file_path,
                        symbol_type=SymbolType.CONSTANT,
                        name=c_name,
                        qualified_name=c_name,
                        start_line=line_no,
                        end_line=line_no,
                        signature=f"const {c_name}",
                        docstring=docstring,
                    )
                )
                if "export " in stripped:
                    exports.append(c_name)
                idx += 1
                continue

            idx += 1

    def _extract_class_methods(
        self,
        file_path: str,
        lines: list[str],
        start_idx: int,
        end_line: int,
        class_name: str,
        symbols: list[CodeSymbol],
    ) -> None:
        for i in range(start_idx + 1, min(len(lines), end_line - 1)):
            line = lines[i]
            match = METHOD_RE.match(line)
            if match:
                m_name = match.group(1)
                if m_name in ("if", "for", "while", "switch", "catch"):
                    continue
                m_end = self._find_closing_brace(lines, i)
                doc = self._lookup_preceding_jsdoc(lines, i)
                symbols.append(
                    CodeSymbol(
                        file_path=file_path,
                        symbol_type=SymbolType.METHOD,
                        name=m_name,
                        qualified_name=f"{class_name}.{m_name}",
                        parent_symbol=class_name,
                        start_line=i + 1,
                        end_line=m_end,
                        signature=f"{m_name}({match.group(2)})",
                        docstring=doc,
                    )
                )

    def _find_closing_brace(self, lines: list[str], start_idx: int) -> int:
        """Finds matching closing brace line with balance tracking."""
        depth = 0
        found_first = False
        for idx in range(start_idx, len(lines)):
            line = lines[idx]
            for ch in line:
                if ch == "{":
                    depth += 1
                    found_first = True
                elif ch == "}":
                    depth -= 1
                    if found_first and depth <= 0:
                        return idx + 1
        return start_idx + 1

    def _lookup_preceding_jsdoc(self, lines: list[str], current_idx: int) -> str | None:
        """Looks backwards for JSDoc comment blocks immediately preceding current_idx."""
        if current_idx == 0:
            return None
        i = current_idx - 1
        doc_lines: list[str] = []
        in_jsdoc = False

        while i >= 0:
            stripped = lines[i].strip()
            if not stripped:
                i -= 1
                continue
            if stripped.endswith("*/"):
                in_jsdoc = True
            if in_jsdoc:
                doc_lines.insert(0, stripped.lstrip("/* ").rstrip("*/").strip())
                if stripped.startswith("/**"):
                    break
            else:
                break
            i -= 1

        if doc_lines:
            return "\n".join(doc_lines).strip()
        return None

    def _classify_module_target(self, target: str) -> str:
        """Distinguishes internal relative, internal alias, or external package dependencies."""
        if target.startswith(("./", "../")):
            return "RESOLVED"
        if target.startswith(("@/", "~/")):
            return "RESOLVED"
        if not target.startswith((".", "/")):
            return "RESOLVED"  # External package e.g. 'react', 'axios'
        return "AMBIGUOUS"
