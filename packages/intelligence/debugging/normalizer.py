"""Incident normalizer: sanitizes inputs, redacts credentials, and establishes facts vs missing context."""

from packages.intelligence.debugging.models import (
    DebuggingIncidentInput,
    NormalizedDebuggingIncident,
    StackTraceFrame,
    redact_sensitive_content,
)
from packages.intelligence.debugging.stack_parser import StackTraceParser


class IncidentNormalizer:
    """Normalizes raw failure inputs into sanitized internal representations."""

    @classmethod
    def normalize(cls, payload: DebuggingIncidentInput) -> NormalizedDebuggingIncident:
        sanitized_title = redact_sensitive_content(payload.title.strip())
        sanitized_msg = redact_sensitive_content(payload.exception_message.strip())
        sanitized_trace = redact_sensitive_content(payload.raw_stack_trace) if payload.raw_stack_trace else None
        sanitized_logs = [redact_sensitive_content(lg) for lg in payload.logs]
        sanitized_test_out = redact_sensitive_content(payload.test_output) if payload.test_output else None
        sanitized_repro = [redact_sensitive_content(r) for r in payload.reproduction_steps]

        # 1. Parse or adapt stack frames
        parsed_frames: list[StackTraceFrame] = []
        if payload.stack_frames:
            for f in payload.stack_frames:
                frame = StackTraceParser._create_frame(f.file_path, f.line_number, f.function_name)
                if f.code_context:
                    frame.code_context = redact_sensitive_content(f.code_context)
                parsed_frames.append(frame)
        elif sanitized_trace:
            parsed_frames = StackTraceParser.parse_trace(sanitized_trace)

        # 2. Track provided facts vs missing context explicitly
        provided_facts: dict[str, str] = {
            "exception_type": payload.exception_type,
            "environment": payload.environment,
        }
        if payload.service_name:
            provided_facts["service_name"] = payload.service_name
        if payload.route:
            provided_facts["route"] = payload.route
        if payload.correlation_id:
            provided_facts["correlation_id"] = payload.correlation_id
        if payload.commit_sha:
            provided_facts["commit_sha"] = payload.commit_sha
        if payload.repository_id:
            provided_facts["repository_id"] = str(payload.repository_id)

        missing_context: list[str] = []
        if not payload.repository_id:
            missing_context.append("missing_repository_id")
        if not payload.commit_sha:
            missing_context.append("missing_commit_sha")
        if not parsed_frames:
            missing_context.append("missing_stack_trace")
        if not payload.route and not payload.service_name:
            missing_context.append("missing_entrypoint_component")
        if not payload.test_output and not payload.reproduction_steps:
            missing_context.append("missing_reproduction_or_test_output")

        return NormalizedDebuggingIncident(
            title=sanitized_title,
            exception_type=payload.exception_type,
            exception_message=sanitized_msg,
            raw_stack_trace=sanitized_trace,
            parsed_frames=parsed_frames,
            service_name=payload.service_name,
            route=payload.route,
            correlation_id=payload.correlation_id,
            environment=payload.environment,
            repository_id=payload.repository_id,
            commit_sha=payload.commit_sha,
            test_output=sanitized_test_out,
            sanitized_logs=sanitized_logs,
            reproduction_steps=sanitized_repro,
            provided_facts=provided_facts,
            missing_context=missing_context,
        )
