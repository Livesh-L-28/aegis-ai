"""Modular language parser architecture for the AEGIS AI Software Engineering Intelligence Platform."""

import ast
from abc import ABC, abstractmethod
from enum import StrEnum
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from packages.intelligence.code.indexer import (
    CodeDependency,
    CodeSymbol,
    PythonASTParser,
    sanitize_source_content,
)


class ParserSupportStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    PARTIAL = "PARTIAL"
    UNSUPPORTED = "UNSUPPORTED"


class ParseError(BaseModel):
    """Structured capture of syntax, tokenization, or parsing anomalies."""

    file_path: str
    line: int | None = None
    column: int | None = None
    message: str
    error_type: str = "SYNTAX_ERROR"


class ParseResult(BaseModel):
    """Normalized parse result containing extracted symbols, dependencies, and diagnostic metadata."""

    file_path: str
    language: str
    support_status: ParserSupportStatus
    parser_name: str
    parser_version: str
    symbols: list[CodeSymbol] = Field(default_factory=list)
    dependencies: list[CodeDependency] = Field(default_factory=list)
    exports: list[str] = Field(default_factory=list)
    errors: list[ParseError] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    is_success: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class LanguageParser(ABC):
    """Abstract base class for language-specific static AST analysis."""

    language: str
    parser_version: str = "1.0.0"
    supported_extensions: ClassVar[set[str]]
    support_status: ParserSupportStatus = ParserSupportStatus.SUPPORTED

    def can_parse(self, file_path: str) -> bool:
        """Determines if this parser handles the given file based on suffix."""
        suffix = Path(file_path).suffix.lower()
        # Handle compound extensions like .d.ts
        if file_path.lower().endswith(".d.ts"):
            return ".d.ts" in self.supported_extensions
        return suffix in self.supported_extensions

    @abstractmethod
    def parse_source(self, file_path: str, source_code: str) -> ParseResult:
        """Parses raw source code into normalized symbols and dependencies."""
        pass


class PythonLanguageParser(LanguageParser):
    """Standard Python AST parser implementation wrapping PythonASTParser."""

    language: str = "python"
    parser_version: str = "1.0.0"
    supported_extensions: ClassVar[set[str]] = {".py", ".pyi"}
    support_status: ParserSupportStatus = ParserSupportStatus.SUPPORTED

    def parse_source(self, file_path: str, source_code: str) -> ParseResult:
        clean_code = sanitize_source_content(source_code)
        errors: list[ParseError] = []
        is_success = True

        # Test syntax first to capture precise error locations if malformed
        try:
            ast.parse(clean_code, filename=file_path)
        except SyntaxError as syn_err:
            is_success = False
            errors.append(
                ParseError(
                    file_path=file_path,
                    line=syn_err.lineno,
                    column=syn_err.offset,
                    message=syn_err.msg or "Python syntax error",
                    error_type="SYNTAX_ERROR",
                )
            )

        symbols, deps = PythonASTParser.parse_source(file_path, clean_code)

        return ParseResult(
            file_path=file_path,
            language=self.language,
            support_status=self.support_status,
            parser_name="PythonASTParser",
            parser_version=self.parser_version,
            symbols=symbols,
            dependencies=deps,
            errors=errors,
            is_success=is_success,
        )


class FallbackParser(LanguageParser):
    """Graceful fallback parser for unhandled or unsupported programming languages."""

    language: str = "unsupported"
    parser_version: str = "1.0.0"
    supported_extensions: ClassVar[set[str]] = set()
    support_status: ParserSupportStatus = ParserSupportStatus.UNSUPPORTED

    def can_parse(self, file_path: str) -> bool:
        return True

    def parse_source(self, file_path: str, source_code: str) -> ParseResult:
        suffix = Path(file_path).suffix.lower()
        return ParseResult(
            file_path=file_path,
            language=suffix.replace(".", "") or "unknown",
            support_status=ParserSupportStatus.UNSUPPORTED,
            parser_name="FallbackParser",
            parser_version=self.parser_version,
            symbols=[],
            dependencies=[],
            warnings=[f"No dedicated parser available for file suffix '{suffix}'"],
            is_success=True,
        )


class ParserRegistry:
    """Central registry providing language parsers and capability discovery."""

    def __init__(self) -> None:
        self._parsers: list[LanguageParser] = []
        self._fallback = FallbackParser()
        self.register(PythonLanguageParser())

    def register(self, parser: LanguageParser) -> None:
        """Registers a new language parser, placing it ahead of older parsers."""
        self._parsers.insert(0, parser)

    def get_parser_for_file(self, file_path: str) -> LanguageParser:
        """Finds the first registered parser that claims support for the given file."""
        for p in self._parsers:
            if p.can_parse(file_path):
                return p
        return self._fallback

    def get_capabilities(self) -> dict[str, Any]:
        """Returns structured metadata of registered language parsers and versions."""
        return {
            "supported_languages": [
                {
                    "language": p.language,
                    "version": p.parser_version,
                    "extensions": sorted(p.supported_extensions),
                    "status": p.support_status.value,
                }
                for p in self._parsers
            ]
        }


def create_default_registry() -> ParserRegistry:
    from packages.intelligence.code.ts_parser import JavaScriptTypeScriptParser

    registry = ParserRegistry()
    registry.register(JavaScriptTypeScriptParser())
    return registry


# Global default parser registry
default_parser_registry = create_default_registry()

