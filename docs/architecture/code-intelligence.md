# Code Intelligence & Static AST Analysis

## Security & Execution Model
Repository indexing is strictly static:
- **No Code Execution**: Neither `setup.py`, `pip`, tests, nor arbitrary scripts are executed during parsing.
- **Path Confinement**: Repositories must reside within explicitly approved workspace roots to prevent directory traversal.
- **Secret Redaction**: Regex scanners mask password assignments, API keys, and bearer tokens before symbols or chunks are stored.

## AST Parser Capabilities
The `PythonASTParser` traverses AST syntax nodes to extract:
- Class definitions with class docstrings
- Methods with parameter signatures and line numbers
- Top-level functions with docstrings
- Imports (`import x` and `from y import z`)
