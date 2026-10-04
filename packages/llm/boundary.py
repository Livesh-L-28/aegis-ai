"""Architectural boundary definition for future LLM integration.

Per Phase 1 Architecture Guidelines:
LLM calls, autonomous agents, RAG, embeddings, model routing, prompt engineering,
and llmfirewall deep integrations MUST NOT be implemented in Phase 1.
This package reserves the protocol interfaces for Phase 5 (AI Trust + Reliability)
and Phase 4 (Evidence + AI Reasoning).
"""

from typing import Protocol, runtime_checkable


@runtime_checkable
class LLMProvider(Protocol):
    """Protocol for future LLM clients (Phase 4/5)."""

    async def complete(self, prompt: str) -> str: ...


@runtime_checkable
class LLMFirewallInspection(Protocol):
    """Protocol extension point for Phase 5 llmfirewall-core integration."""

    async def inspect_input(self, text: str) -> bool: ...
    async def inspect_output(self, text: str) -> bool: ...
