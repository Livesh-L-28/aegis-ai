"""Model Context Protocol (MCP) stdio server for LogicFalcon.

Provides standard JSON-RPC 2.0 endpoints for AI agents in Cursor, Antigravity,
and other MCP-compatible hosts to invoke deterministic code review and remediation.
"""

import json
import sys
from pathlib import Path
from typing import Any

from logicfalcon import __product__, __version__
from logicfalcon.sdk import apply_fix, review_file, review_workspace
from packages.review.domain.models import ProposedFix
from packages.review.security.path_validation import validate_contained_path

TOOLS = [
    {
        "name": "logicfalcon_review_file",
        "description": "Reviews a single file deterministically for quality, security vulnerabilities, and logic flaws.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the target source file (relative to workspace root).",
                },
                "repo_root": {
                    "type": "string",
                    "description": "Path to workspace/repository root (default: current directory).",
                    "default": ".",
                },
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "logicfalcon_review_workspace",
        "description": "Scans supported workspace source files for deterministic findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_root": {
                    "type": "string",
                    "description": "Path to workspace/repository root.",
                    "default": ".",
                },
                "max_files": {
                    "type": "integer",
                    "description": "Maximum number of files to scan (default: 500).",
                    "default": 500,
                },
            },
        },
    },
    {
        "name": "logicfalcon_apply_fix",
        "description": "Safely applies an automated code remediation to disk with syntax checks and backups. Requires approved=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "fix": {
                    "type": "object",
                    "description": "ProposedFix payload with file_path, start_line, end_line, and replacement_code.",
                    "properties": {
                        "file_path": {"type": "string"},
                        "start_line": {"type": "integer"},
                        "end_line": {"type": "integer"},
                        "replacement_code": {"type": "string"},
                        "explanation": {"type": "string"},
                    },
                    "required": ["file_path", "start_line", "end_line", "replacement_code"],
                },
                "approved": {
                    "type": "boolean",
                    "description": "Explicit authorization to write changes to disk. If false, returns diff preview only.",
                    "default": False,
                },
                "repo_root": {
                    "type": "string",
                    "description": "Path to repository root.",
                    "default": ".",
                },
            },
            "required": ["fix"],
        },
    },
    {
        "name": "logicfalcon_doctor",
        "description": "Reports operational status and capabilities of the LogicFalcon engine.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "logicfalcon_analyze_architecture",
        "description": "Analyzes repository modularity, circular dependencies, boundary violations, and architecture health score.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_root": {
                    "type": "string",
                    "description": "Path to workspace/repository root.",
                    "default": ".",
                },
            },
        },
    },
]


def handle_review_file(arguments: dict[str, Any]) -> dict[str, Any]:
    file_path = arguments.get("file_path", "")
    repo_root = arguments.get("repo_root", ".")

    root_path = Path(repo_root).resolve()
    contained = validate_contained_path(root_path, file_path)
    if not contained:
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Error: Target path escapes repository root: {file_path}"}],
        }

    try:
        from packages.review.adapters.ast_security import redact_secrets_in_text

        report = review_file(file_path=file_path, repo_root=root_path)
        output = redact_secrets_in_text(report.model_dump_json(indent=2))
        return {
            "content": [{"type": "text", "text": output}],
        }
    except Exception as e:
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Review execution error: {e}"}],
        }


def handle_review_workspace(arguments: dict[str, Any]) -> dict[str, Any]:
    repo_root = arguments.get("repo_root", ".")
    max_files = arguments.get("max_files", 500)

    root_path = Path(repo_root).resolve()
    try:
        from packages.review.adapters.ast_security import redact_secrets_in_text

        report = review_workspace(repo_root=root_path, max_files=max_files)
        summary = {
            "files_scanned": len(report.files_reviewed),
            "findings_count": len(report.findings),
            "execution_time_seconds": report.execution_time_seconds,
            "findings": [f.model_dump() for f in report.findings],
        }
        output = redact_secrets_in_text(json.dumps(summary, indent=2, default=str))
        return {
            "content": [{"type": "text", "text": output}],
        }
    except Exception as e:
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Workspace scan error: {e}"}],
        }


def handle_analyze_architecture(arguments: dict[str, Any]) -> dict[str, Any]:
    repo_root = arguments.get("repo_root", ".")
    root_path = Path(repo_root).resolve()
    from packages.review.analyzer.architecture import ArchitectureAnalyzer
    from packages.review.engine import ReviewConfig

    try:
        config = ReviewConfig.load_config(repo_root=root_path)
        policy = config.get_effective_policy()
        analyzer = ArchitectureAnalyzer(repo_root=root_path, policy=policy)
        report = analyzer.analyze()
        return {
            "content": [{"type": "text", "text": report.model_dump_json(indent=2)}],
        }
    except Exception as e:
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Architecture analysis error: {e}"}],
        }



def handle_apply_fix(arguments: dict[str, Any]) -> dict[str, Any]:
    raw_fix = arguments.get("fix", {})
    approved = bool(arguments.get("approved", False))
    repo_root = arguments.get("repo_root", ".")

    try:
        fix_obj = ProposedFix.model_validate(raw_fix)
    except Exception as e:
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Invalid ProposedFix specification: {e}"}],
        }

    root_path = Path(repo_root).resolve()
    contained = validate_contained_path(root_path, fix_obj.file_path)
    if not contained:
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Error: Target path escapes repository root: {fix_obj.file_path}"}],
        }

    try:
        result = apply_fix(
            fix=fix_obj,
            approved=approved,
            repo_root=root_path,
            dry_run=not approved,
        )
        res_data = {
            "success": result.success,
            "dry_run": not approved,
            "file_path": result.file_path,
            "diff": result.diff,
            "backup_path": result.backup_path,
            "error_message": result.error_message,
        }
        return {
            "content": [{"type": "text", "text": json.dumps(res_data, indent=2)}],
        }
    except Exception as e:
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Fix application error: {e}"}],
        }


def handle_doctor(_arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(
                    {
                        "product": __product__,
                        "version": __version__,
                        "status": "operational",
                        "tools_available": [t["name"] for t in TOOLS],
                    },
                    indent=2,
                ),
            }
        ],
    }


def process_request(request: dict[str, Any]) -> dict[str, Any] | None:
    method = request.get("method")
    req_id = request.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                },
                "serverInfo": {
                    "name": "logicfalcon-mcp",
                    "version": __version__,
                },
            },
        }

    elif method == "notifications/initialized":
        return None

    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": TOOLS,
            },
        }

    elif method == "tools/call":
        params = request.get("params", {})
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name == "logicfalcon_review_file":
            res = handle_review_file(arguments)
        elif tool_name == "logicfalcon_review_workspace":
            res = handle_review_workspace(arguments)
        elif tool_name == "logicfalcon_analyze_architecture":
            res = handle_analyze_architecture(arguments)
        elif tool_name == "logicfalcon_apply_fix":
            res = handle_apply_fix(arguments)
        elif tool_name == "logicfalcon_doctor":
            res = handle_doctor(arguments)
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method or tool not found: {tool_name}",
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": res,
        }

    elif req_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Unsupported method: {method}",
            },
        }

    return None


def main() -> None:
    """Stdio JSON-RPC loop for Model Context Protocol."""
    for line in sys.stdin:
        line_str = line.strip()
        if not line_str:
            continue
        try:
            req = json.loads(line_str)
            response = process_request(req)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
        except Exception as e:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {e}"},
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
