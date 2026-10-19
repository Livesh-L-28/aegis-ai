"""Unit tests for Phase 3B StackTraceParser: Python and JS/TS stack frame extraction."""

from packages.intelligence.debugging.models import FrameOriginType
from packages.intelligence.debugging.stack_parser import StackTraceParser


def test_python_traceback_parsing() -> None:
    raw_trace = """
Traceback (most recent call last):
  File "/workspace/apps/api/app/services/order.py", line 45, in process_order
    tax = calculate_tax(order.total)
  File "/workspace/packages/finance/tax.py", line 12, in calculate_tax
    return amount * RATE
ZeroDivisionError: division by zero
    """
    frames = StackTraceParser.parse_trace(raw_trace)
    assert len(frames) == 2

    assert frames[0].file_path == "/workspace/apps/api/app/services/order.py"
    assert frames[0].line_number == 45
    assert frames[0].function_name == "process_order"
    assert frames[0].origin == FrameOriginType.INTERNAL

    assert frames[1].file_path == "/workspace/packages/finance/tax.py"
    assert frames[1].line_number == 12
    assert frames[1].function_name == "calculate_tax"
    assert frames[1].origin == FrameOriginType.INTERNAL


def test_nodejs_typescript_stack_parsing() -> None:
    raw_trace = """
Error: Request failed with status code 500
    at Object.sendRequest (/app/src/client/api.ts:25:12)
    at async OrderService.createOrder (src/services/orders.ts:114:9)
    at processTicksAndRejections (node:internal/process/task_queues:95:5)
    at Object.<anonymous> (/node_modules/express/lib/router/layer.js:95:5)
    """
    frames = StackTraceParser.parse_trace(raw_trace)
    assert len(frames) == 4

    assert frames[0].file_path == "/app/src/client/api.ts"
    assert frames[0].line_number == 25
    assert frames[0].function_name == "Object.sendRequest"
    assert frames[0].origin == FrameOriginType.INTERNAL

    assert frames[1].file_path == "src/services/orders.ts"
    assert frames[1].line_number == 114
    assert frames[1].function_name == "async OrderService.createOrder"
    assert frames[1].origin == FrameOriginType.INTERNAL

    assert frames[2].origin == FrameOriginType.EXTERNAL_LIBRARY
    assert frames[3].origin == FrameOriginType.EXTERNAL_LIBRARY


def test_test_frame_identification() -> None:
    trace = """
  File "tests/unit/test_calculator.py", line 30, in test_add
    assert add(2, 2) == 5
AssertionError: assert 4 == 5
    """
    frames = StackTraceParser.parse_trace(trace)
    assert len(frames) == 1
    assert frames[0].origin == FrameOriginType.TEST_FRAME


def test_protected_file_quarantine_in_stack_trace() -> None:
    trace = """
  File "config/render_schema.json", line 1, in load
    invalid json
    """
    frames = StackTraceParser.parse_trace(trace)
    assert len(frames) == 1
    assert frames[0].is_protected_file is True
    assert frames[0].file_path == "[PROTECTED_FILE_REDACTED]"


def test_path_traversal_detection_in_stack_trace() -> None:
    trace = """
  File "../../../etc/passwd", line 10, in read
    root:x:0:0
    """
    frames = StackTraceParser.parse_trace(trace)
    assert len(frames) == 1
    assert "traversal" in frames[0].resolution_note.lower()


def test_secret_redaction_in_stack_trace() -> None:
    trace = """
  File "src/auth.py", line 5, in login
    token = "Bearer secret_jwt_token_1234567890abcdef"
ValueError: Authorization failed with token = "super_secret_test_token_12345"
    """
    frames = StackTraceParser.parse_trace(trace)
    assert len(frames) == 1
    # Check that secrets are redacted from the raw text
    parsed_again = StackTraceParser.parse_trace(trace)
    assert "super_secret_test_token_12345" not in str(parsed_again)
    assert "secret_jwt_token_1234567890abcdef" not in str(parsed_again)
