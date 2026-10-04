# LLM Firewall Integration Guide

## Overview
AEGIS integrates `llmfirewall-core` as a first-class security boundary across input prompts, output generations, and tool calls.

The core adapter is located at:
`packages/security/llm_firewall/adapter.py`

## Methods & Protections

### 1. `inspect_prompt(prompt, user_id=None, session_id=None, context=None)`
- Scans input text for prompt injection, DAN jailbreaks, system prompt overrides, and unauthorized commands.
- Automatically redacts PII and sensitive data patterns (e.g., IPv4 addresses, access tokens).
- Returns `FirewallScanResult` with:
  - `allowed: bool`
  - `action: FirewallDecisionAction` (`ALLOW`, `BLOCK`, `REDACT`, `WARN`)
  - `sanitized_text: str | None`
  - `reason: str`
  - `findings: list[FirewallFinding]`

### 2. `inspect_output(generation, user_id=None, session_id=None, context=None)`
- Scans model responses for credential leakage, secret tokens, or malicious payload echos.
- Rejects invalid or dangerous model generations before passing them to the application layer.

### 3. `inspect_tool_call(tool_name, arguments, user_id=None, session_id=None, context=None)`
- Evaluates tool invocations against destructive bash patterns, unsafe subshells, and filesystem manipulation.
- Blocks commands like `rm -rf /` or unauthorized network egress.

## Health & Operational Monitoring
The operational status of the firewall can be queried via:
```http
GET /api/v1/ai/firewall/status
```
Response:
```json
{
  "enabled": true,
  "healthy": true,
  "version": "1.0.0",
  "policy_version": "default-v1"
}
```
*Note: Internal security heuristics and rule signatures are kept confidential and are not exposed over the REST API.*
