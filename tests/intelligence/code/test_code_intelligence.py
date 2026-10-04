import tempfile
from pathlib import Path

from packages.intelligence.code.indexer import (
    FileClassification,
    PythonASTParser,
    RepositoryIndexer,
    SymbolType,
    sanitize_source_content,
)


def test_python_ast_parser_extraction() -> None:
    source_code = """
import os
from datetime import datetime
from packages.config import settings

class OrderEngine:
    '''Core order processing engine docstring.'''
    def __init__(self, retries: int = 3):
        self.retries = retries

    def process_order(self, order_id: str) -> bool:
        return True

def calculate_tax(amount: float) -> float:
    '''Calculates state tax.'''
    return amount * 0.08
"""
    symbols, dependencies = PythonASTParser.parse_source("test_module.py", source_code)

    # Verify imports
    modules = [d.target_module for d in dependencies]
    assert "os" in modules
    assert "datetime" in modules
    assert "packages.config" in modules

    # Verify class, methods, functions
    names = [s.name for s in symbols]
    assert "OrderEngine" in names
    assert "__init__" in names
    assert "process_order" in names
    assert "calculate_tax" in names

    cls_sym = next(s for s in symbols if s.name == "OrderEngine")
    assert cls_sym.symbol_type == SymbolType.CLASS
    assert "Core order processing engine" in (cls_sym.docstring or "")

    fn_sym = next(s for s in symbols if s.name == "calculate_tax")
    assert fn_sym.symbol_type == SymbolType.FUNCTION
    assert "def calculate_tax" in fn_sym.signature


def test_incremental_indexing_and_idempotence() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        file1 = tmp_path / "service.py"
        file1.write_text("class MyService:\n    pass\n")

        file2 = tmp_path / "README.md"
        file2.write_text("# Project Docs\n")

        indexer = RepositoryIndexer(tmp_path)
        first_run = indexer.index_repository()
        assert len(first_run) == 2

        # Verify idempotence (second run without changes doesn't duplicate)
        second_run = indexer.index_repository()
        assert len(second_run) == 2
        assert "service.py" in indexer.files_index
        assert indexer.files_index["service.py"].classification == FileClassification.SOURCE
        assert indexer.files_index["README.md"].classification == FileClassification.DOCUMENTATION

        # Modify one file and verify incremental update
        file1.write_text("class MyService:\n    def execute(self):\n        return True\n")
        third_run = indexer.index_repository()
        assert len(third_run) == 2
        symbols = indexer.files_index["service.py"].symbols
        method_names = [s.name for s in symbols]
        assert "execute" in method_names


def test_secret_sanitization() -> None:
    code_with_secret = 'API_KEY = "sk-1234567890abcdef"\npassword = "SuperSecret123!"\nnormal_var = "public"'
    cleaned = sanitize_source_content(code_with_secret)
    assert "sk-1234567890abcdef" not in cleaned
    assert "SuperSecret123!" not in cleaned
    assert "[REDACTED_SECRET]" in cleaned
    assert "public" in cleaned
