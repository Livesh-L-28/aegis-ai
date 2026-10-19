"""Deterministic multi-language stack trace parser for Python and JavaScript/TypeScript failures."""

import re

from packages.intelligence.debugging.models import (
    FrameOriginType,
    StackTraceFrame,
    redact_sensitive_content,
)

# Python traceback pattern: File "...", line 123, in func_name
PY_FRAME_RE = re.compile(
    r"""^\s*File\s+["'](?P<path>[^"']+)["'],\s+line\s+(?P<line>\d+)(?:,\s+in\s+(?P<func>[^\n]+))?""",
    re.MULTILINE,
)

# Node.js / V8 stack frame pattern: at [func] (path:line:col) or at path:line:col
NODE_FRAME_PAREN_RE = re.compile(
    r"""^\s*at\s+(?:(?P<func>[^\(\n]+?)\s+\()?(?P<path>(?:node:)?[^\s\(\)]+?):(?P<line>\d+):(?P<col>\d+)\)?""",
    re.MULTILINE,
)
NODE_FRAME_BARE_RE = re.compile(
    r"""^\s*at\s+(?P<path>(?:node:)?[^\s\(\)]+?):(?P<line>\d+):(?P<col>\d+)""",
    re.MULTILINE,
)

PROTECTED_FILENAMES = {"render_schema.json"}


class StackTraceParser:
    """Parses raw multi-language stack traces into structured, normalized StackTraceFrame objects."""

    @classmethod
    def parse_trace(cls, raw_trace: str) -> list[StackTraceFrame]:
        if not raw_trace or not raw_trace.strip():
            return []

        clean_trace = redact_sensitive_content(raw_trace)
        frames: list[StackTraceFrame] = []

        # 1. Try Python traceback parsing
        py_matches = list(PY_FRAME_RE.finditer(clean_trace))
        if py_matches:
            for m in py_matches:
                raw_path = m.group("path").strip()
                line_str = m.group("line")
                func_name = (m.group("func") or "<module>").strip()
                frame = cls._create_frame(raw_path, int(line_str), func_name)
                frames.append(frame)
            return frames

        # 2. Try Node.js / TypeScript stack trace parsing
        node_lines = clean_trace.splitlines()
        for line in node_lines:
            paren_match = NODE_FRAME_PAREN_RE.match(line)
            if paren_match:
                raw_path = paren_match.group("path").strip()
                line_str = paren_match.group("line")
                func_name = (paren_match.group("func") or "<anonymous>").strip()
                frames.append(cls._create_frame(raw_path, int(line_str), func_name))
                continue

            bare_match = NODE_FRAME_BARE_RE.match(line)
            if bare_match:
                raw_path = bare_match.group("path").strip()
                line_str = bare_match.group("line")
                frames.append(cls._create_frame(raw_path, int(line_str), "<anonymous>"))
                continue

        return frames

    @classmethod
    def _create_frame(cls, raw_path: str, line_number: int, function_name: str) -> StackTraceFrame:
        norm_path = raw_path.replace("\\", "/").strip()

        # Check protected file isolation
        parts = norm_path.split("/")
        if any(part in PROTECTED_FILENAMES for part in parts):
            return StackTraceFrame(
                file_path="[PROTECTED_FILE_REDACTED]",
                line_number=line_number,
                function_name=function_name,
                origin=FrameOriginType.UNKNOWN,
                is_resolved=False,
                is_protected_file=True,
                resolution_note="Access to protected file denied by security policy.",
            )

        # Check path traversal
        if ".." in parts:
            return StackTraceFrame(
                file_path=norm_path,
                line_number=line_number,
                function_name=function_name,
                origin=FrameOriginType.UNKNOWN,
                is_resolved=False,
                resolution_note="Path traversal rejected.",
            )

        # Classify Origin
        lower = norm_path.lower()
        if (
            "site-packages" in lower
            or "node_modules" in lower
            or lower.startswith("node:")
            or "/lib/python" in lower
            or "/usr/lib" in lower
        ):
            origin = FrameOriginType.EXTERNAL_LIBRARY
        elif (
            "test" in lower
            or lower.startswith(("tests/", "__tests__/"))
            or lower.endswith(
                (
                    "_test.py",
                    "test.py",
                    ".test.ts",
                    ".test.tsx",
                    ".test.js",
                    ".test.jsx",
                    ".spec.ts",
                    ".spec.tsx",
                )
            )
        ):
            origin = FrameOriginType.TEST_FRAME
        elif lower.endswith((".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
            origin = FrameOriginType.INTERNAL
        else:
            origin = FrameOriginType.UNKNOWN

        return StackTraceFrame(
            file_path=norm_path,
            line_number=line_number,
            function_name=function_name,
            origin=origin,
            is_resolved=False,
        )
