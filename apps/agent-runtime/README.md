# apps/agent-runtime
This directory is reserved for autonomous agent execution runtimes, sandbox controllers, and tool executors.
Per Phase 1 architectural restrictions, agent and LLM execution logic is deferred to later phases.
The architectural extension points and event interfaces are established in `packages/events` and `packages/llm`.
