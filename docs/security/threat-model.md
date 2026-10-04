# Security Threat Model — Phase 7 Hardening

| Threat | Attack Vector | Security Control | Detection & Response |
| :--- | :--- | :--- | :--- |
| **Prompt Injection** | Adversarial instructions hidden in logs or user input | `LLMFirewall` scan via `llmfirewall-core` | Requests blocked; findings audited with alert |
| **Credential Leakage** | Tokens or secrets in source, diffs, or logs | Regex pattern matching + project AST redactor | Diff rejected, token redacted, audit logged |
| **Runaway Agent** | Recursive tool execution loops | Hard budgets (`max_tool_calls`, `max_cost`) | Execution aborted, incident escalated to human |
| **Privilege Escalation** | Low-privilege user attempting auto-remediation | RBAC verification on every REST API route | 403 Forbidden raised and recorded |
| **Tenant Boundary Escape** | Querying resources of another tenant | Tenant context middleware + SQL where clause | 403 / 404 raised; tenant violations audited |
| **Self-Modification** | LLM proposing edits to security policies or firewall | Deny-by-default tool registry, protected git paths | Patches modifying security files are rejected |
