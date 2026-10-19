import ast
import hashlib
import re
from enum import StrEnum
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

SECRET_PATTERNS = [
    re.compile(r"(?i)(password|secret|token|api_key|apikey|private_key)\s*[:=]\s*['\"][^'\"]+['\"]"),
    re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}"),
]


def sanitize_source_content(content: str) -> str:
    """Redacts potential secrets in source text prior to indexing or storage."""
    sanitized = content
    # Redact assignments
    sanitized = re.sub(
        r"(?i)(password|secret|token|api_key|apikey|private_key)\s*[:=]\s*['\"][^'\"]+['\"]",
        r"\1 = '[REDACTED_SECRET]'",
        sanitized,
    )
    # Redact bearer tokens
    sanitized = re.sub(
        r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}",
        "Bearer [REDACTED_SECRET]",
        sanitized,
    )
    return sanitized


class FileClassification(StrEnum):
    SOURCE = "SOURCE"
    TEST = "TEST"
    CONFIG = "CONFIG"
    DOCUMENTATION = "DOCUMENTATION"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    UNKNOWN = "UNKNOWN"


class SymbolType(StrEnum):
    MODULE = "MODULE"
    CLASS = "CLASS"
    FUNCTION = "FUNCTION"
    METHOD = "METHOD"
    VARIABLE = "VARIABLE"
    INTERFACE = "INTERFACE"
    TYPE_ALIAS = "TYPE_ALIAS"
    ENUM = "ENUM"
    CONSTANT = "CONSTANT"


class CodeSymbol(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    file_path: str
    symbol_type: SymbolType
    name: str
    qualified_name: str
    parent_symbol: str | None = None
    start_line: int
    end_line: int
    signature: str = ""
    docstring: str | None = None


class CodeDependency(BaseModel):
    source_file: str
    target_module: str
    imported_names: list[str] = Field(default_factory=list)
    edge_type: str = "IMPORT"
    resolution_quality: str = "RESOLVED"  # RESOLVED, UNRESOLVED, AMBIGUOUS, INFERRED
    is_type_only: bool = False


class IndexedFile(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    path: str
    classification: FileClassification
    language: str
    size_bytes: int
    content_hash: str
    symbols: list[CodeSymbol] = Field(default_factory=list)
    imports: list[CodeDependency] = Field(default_factory=list)


class GitCommit(BaseModel):
    commit_sha: str
    author: str
    timestamp: str
    message: str
    changed_files: list[str] = Field(default_factory=list)


class PythonASTParser:
    """Static AST analyzer extracting functions, classes, methods, and imports from Python source."""

    @staticmethod
    def parse_source(file_path: str, source_code: str) -> tuple[list[CodeSymbol], list[CodeDependency]]:
        symbols: list[CodeSymbol] = []
        dependencies: list[CodeDependency] = []

        try:
            tree = ast.parse(source_code, filename=file_path)
        except SyntaxError:
            return symbols, dependencies

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    dependencies.append(CodeDependency(source_file=file_path, target_module=alias.name))
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported_names = [alias.name for alias in node.names]
                    dependencies.append(
                        CodeDependency(
                            source_file=file_path,
                            target_module=node.module,
                            imported_names=imported_names,
                        )
                    )
            elif isinstance(node, ast.ClassDef):
                docstring = ast.get_docstring(node)
                cls_symbol = CodeSymbol(
                    file_path=file_path,
                    symbol_type=SymbolType.CLASS,
                    name=node.name,
                    qualified_name=node.name,
                    start_line=node.lineno,
                    end_line=node.end_lineno or node.lineno,
                    docstring=docstring,
                )
                symbols.append(cls_symbol)

                # Inspect methods within class
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_doc = ast.get_docstring(sub)
                        args = [a.arg for a in sub.args.args]
                        sig = f"def {sub.name}({', '.join(args)})"
                        symbols.append(
                            CodeSymbol(
                                file_path=file_path,
                                symbol_type=SymbolType.METHOD,
                                name=sub.name,
                                qualified_name=f"{node.name}.{sub.name}",
                                parent_symbol=node.name,
                                start_line=sub.lineno,
                                end_line=sub.end_lineno or sub.lineno,
                                signature=sig,
                                docstring=method_doc,
                            )
                        )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_doc = ast.get_docstring(node)
                args = [a.arg for a in node.args.args]
                sig = f"def {node.name}({', '.join(args)})"
                symbols.append(
                    CodeSymbol(
                        file_path=file_path,
                        symbol_type=SymbolType.FUNCTION,
                        name=node.name,
                        qualified_name=node.name,
                        start_line=node.lineno,
                        end_line=node.end_lineno or node.lineno,
                        signature=sig,
                        docstring=fn_doc,
                    )
                )

        return symbols, dependencies


class RepositoryIndexer:
    """Scans and indexes source repositories statically without executing code."""

    def __init__(self, root_dir: str | Path) -> None:
        self.root_dir = Path(root_dir).resolve()
        self.files_index: dict[str, IndexedFile] = {}
        self.commits: list[GitCommit] = []

    def classify_file(self, rel_path: str) -> FileClassification:
        lower = rel_path.lower()
        if (
            "test" in lower
            or lower.startswith(("tests/", "__tests__/"))
            or lower.endswith(("_test.py", "test.py", ".test.ts", ".test.tsx", ".test.js", ".test.jsx", ".spec.ts", ".spec.tsx", ".spec.js"))
        ):
            return FileClassification.TEST
        if lower.endswith((".md", ".rst", ".txt")):
            return FileClassification.DOCUMENTATION
        if lower.endswith((".yml", ".yaml", ".json", ".toml", ".ini")):
            return FileClassification.CONFIG
        if "docker" in lower or lower.endswith("dockerfile"):
            return FileClassification.INFRASTRUCTURE
        if lower.endswith((".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".go", ".rs")):
            return FileClassification.SOURCE
        return FileClassification.UNKNOWN

    def index_repository(self) -> list[IndexedFile]:
        """Indexes all discoverable files incrementally with hash deduplication."""
        if not self.root_dir.exists():
            return []

        from packages.intelligence.code.parser_base import (
            ParserSupportStatus,
            default_parser_registry,
        )

        for p in self.root_dir.rglob("*"):
            if not p.is_file():
                continue
            # Ignore virtualenv, git, build artifacts
            rel_str = str(p.relative_to(self.root_dir))
            if any(part in rel_str for part in [".git", ".venv", "venv", "__pycache__", ".ruff_cache", ".mypy_cache"]):
                continue

            try:
                raw_bytes = p.read_bytes()
            except OSError:
                continue

            content_hash = hashlib.sha256(raw_bytes).hexdigest()

            # Incremental check: if file already indexed and unchanged, retain existing index
            if rel_str in self.files_index and self.files_index[rel_str].content_hash == content_hash:
                continue

            classification = self.classify_file(rel_str)
            lang = "python" if p.suffix == ".py" else p.suffix.replace(".", "")

            symbols: list[CodeSymbol] = []
            imports: list[CodeDependency] = []

            parser = default_parser_registry.get_parser_for_file(rel_str)
            if parser.support_status != ParserSupportStatus.UNSUPPORTED:
                try:
                    text_content = raw_bytes.decode("utf-8", errors="ignore")
                    clean_content = sanitize_source_content(text_content)
                    res = parser.parse_source(rel_str, clean_content)
                    symbols = res.symbols
                    imports = res.dependencies
                except Exception:
                    pass

            indexed_file = IndexedFile(
                path=rel_str,
                classification=classification,
                language=lang,
                size_bytes=len(raw_bytes),
                content_hash=content_hash,
                symbols=symbols,
                imports=imports,
            )
            self.files_index[rel_str] = indexed_file

        return list(self.files_index.values())

    def search_symbols(self, query: str) -> list[CodeSymbol]:
        q = query.lower()
        results = []
        for file in self.files_index.values():
            for sym in file.symbols:
                if q in sym.name.lower() or q in sym.qualified_name.lower():
                    results.append(sym)
        return results
