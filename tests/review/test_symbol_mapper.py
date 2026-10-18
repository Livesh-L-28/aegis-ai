"""Tests for SymbolMapper correlating Git diff lines to AST symbols."""

from packages.review.analyzer.symbol_mapper import SymbolMapper
from packages.review.domain.models import ChangedFile, DiffChangeType, DiffHunk

SAMPLE_PYTHON_SOURCE = """# Sample module
import os

class Worker:
    def __init__(self, name: str) -> None:
        self.name = name

    def process(self, data: str) -> str:
        return data.upper()

def standalone_task(x: int) -> int:
    return x * 2
"""


def test_symbol_mapper_identifies_modified_method() -> None:
    mapper = SymbolMapper()

    # Suppose lines 8 and 9 (inside process method) were modified
    hunk = DiffHunk(
        old_start=8,
        old_length=2,
        new_start=8,
        new_length=2,
        added_lines=[8, 9],
    )
    changed_file = ChangedFile(
        new_path="service/worker.py",
        change_type=DiffChangeType.MODIFIED,
        hunks=[hunk],
    )

    symbols = mapper.map_file_symbols(changed_file, source_content=SAMPLE_PYTHON_SOURCE)

    # Should detect Worker class and Worker.process method
    names = [s.symbol.qualified_name for s in symbols]
    assert "Worker.process" in names
    assert "Worker" in names


def test_symbol_mapper_identifies_standalone_function() -> None:
    mapper = SymbolMapper()

    # Suppose lines 11 and 12 (standalone_task) were modified
    hunk = DiffHunk(
        old_start=11,
        old_length=2,
        new_start=11,
        new_length=2,
        added_lines=[11, 12],
    )
    changed_file = ChangedFile(
        new_path="service/worker.py",
        change_type=DiffChangeType.MODIFIED,
        hunks=[hunk],
    )

    symbols = mapper.map_file_symbols(changed_file, source_content=SAMPLE_PYTHON_SOURCE)
    names = [s.symbol.qualified_name for s in symbols]
    assert "standalone_task" in names
    assert "Worker.process" not in names


def test_symbol_mapper_ignores_non_python_or_deleted() -> None:
    mapper = SymbolMapper()

    # Non-python
    cf_txt = ChangedFile(
        new_path="notes.txt",
        change_type=DiffChangeType.MODIFIED,
        hunks=[DiffHunk(old_start=1, old_length=1, new_start=1, new_length=1, added_lines=[1])],
    )
    assert mapper.map_file_symbols(cf_txt, source_content="hello") == []

    # Deleted
    cf_del = ChangedFile(
        old_path="old.py",
        change_type=DiffChangeType.DELETED,
        hunks=[],
    )
    assert mapper.map_file_symbols(cf_del) == []
