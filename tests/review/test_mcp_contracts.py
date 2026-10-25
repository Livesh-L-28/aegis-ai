"""Contract tests for LogicFalcon Model Context Protocol (MCP) server endpoints."""

import json
import tempfile
from pathlib import Path

from logicfalcon.mcp.server import process_request


def test_mcp_initialize_and_tools_list() -> None:
    """Verifies that MCP protocol initialize and tools/list conform to JSON-RPC 2.0."""
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {},
    }
    init_res = process_request(init_req)
    assert init_res is not None
    assert init_res["id"] == 1
    assert "result" in init_res
    assert init_res["result"]["serverInfo"]["name"] == "logicfalcon-mcp"

    list_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    }
    list_res = process_request(list_req)
    assert list_res is not None
    tool_names = [t["name"] for t in list_res["result"]["tools"]]
    assert "logicfalcon_review_file" in tool_names
    assert "logicfalcon_review_workspace" in tool_names
    assert "logicfalcon_apply_fix" in tool_names
    assert "logicfalcon_doctor" in tool_names
    assert "logicfalcon_analyze_architecture" in tool_names


def test_mcp_review_file_path_traversal_blocked() -> None:
    """Verifies that MCP tool calls attempting path traversal are strictly rejected."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "logicfalcon_review_file",
                "arguments": {
                    "file_path": "../../../../../etc/passwd",
                    "repo_root": tmp_dir,
                },
            },
        }
        res = process_request(req)
        assert res is not None
        result = res["result"]
        assert result.get("isError") is True
        assert "escapes repository root" in result["content"][0]["text"]


def test_mcp_apply_fix_approval_boundaries() -> None:
    """Verifies that MCP apply_fix enforces explicit developer approval boundaries."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        target = root / "sample.py"
        initial_content = "def hello(val=[]): pass\n"
        target.write_text(initial_content)

        fix_payload = {
            "file_path": "sample.py",
            "start_line": 1,
            "end_line": 1,
            "replacement_code": "def hello(val=None): pass",
            "explanation": "Fix mutable default argument",
        }

        # 1. Unapproved call: returns dry-run diff preview and NEVER modifies disk
        req_unapproved = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "logicfalcon_apply_fix",
                "arguments": {
                    "fix": fix_payload,
                    "approved": False,
                    "repo_root": tmp_dir,
                },
            },
        }
        res_unapproved = process_request(req_unapproved)
        assert res_unapproved is not None
        data = json.loads(res_unapproved["result"]["content"][0]["text"])
        assert data["dry_run"] is True
        assert data["success"] is True
        assert target.read_text() == initial_content

        # 2. Approved call: safely modifies file and creates backup
        req_approved = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "logicfalcon_apply_fix",
                "arguments": {
                    "fix": fix_payload,
                    "approved": True,
                    "repo_root": tmp_dir,
                },
            },
        }
        res_approved = process_request(req_approved)
        assert res_approved is not None
        data_app = json.loads(res_approved["result"]["content"][0]["text"])
        assert data_app["dry_run"] is False
        assert data_app["success"] is True
        assert target.read_text() == "def hello(val=None): pass\n"
        assert data_app["backup_path"] is not None
        assert Path(data_app["backup_path"]).is_file()


def test_mcp_secret_redaction_before_transmission() -> None:
    """Verifies that MCP review output strictly redacts raw credentials."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        cred_file = root / "secrets.py"
        raw_secret = "ghp_TopSecretToken1234567890abcdef"
        cred_file.write_text(f"GITHUB_TOKEN = '{raw_secret}'\n")

        req = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "logicfalcon_review_file",
                "arguments": {
                    "file_path": "secrets.py",
                    "repo_root": tmp_dir,
                },
            },
        }
        res = process_request(req)
        assert res is not None
        output = res["result"]["content"][0]["text"]
        assert raw_secret not in output
        assert "[REDACTED_SECRET]" in output


def test_mcp_analyze_architecture() -> None:
    """Verifies that MCP architecture analysis tool produces structured metrics and health score."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        pkg = root / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "mod.py").write_text("def run(): pass\n")

        req = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "logicfalcon_analyze_architecture",
                "arguments": {
                    "repo_root": tmp_dir,
                },
            },
        }
        res = process_request(req)
        assert res is not None
        data = json.loads(res["result"]["content"][0]["text"])
        assert "health_score" in data
        assert data["health_score"] == 100.0
        assert data["total_modules"] >= 1
