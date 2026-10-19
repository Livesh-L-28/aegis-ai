# Contributing to LogicFalcon

Thank you for your interest in contributing to **LogicFalcon** (powered by AEGIS AI)! We welcome contributions from developers, researchers, and organizations building AI-assisted software engineering intelligence.

---

## 1. Open Source Licensing of Contributions

LogicFalcon is licensed under the **Apache License 2.0** ([`LICENSE`](LICENSE)).

- **Inbound = Outbound Model:** By submitting a pull request or patch to this repository, you agree that your contributions will be licensed under the terms of the Apache License 2.0.
- **No Copyright Transfer:** You retain copyright in your original contributions. You are granting a non-exclusive, perpetual, worldwide license under the terms of Apache-2.0.
- **Right to Contribute:** You represent and warrant that you are the author of the submitted code or have explicit authorization from your employer or copyright owner to submit the work under Apache-2.0.

---

## 2. Code of Conduct & Review Standards

We expect all contributors to maintain a professional, respectful, and constructive environment.

All pull requests undergo code review focusing on:
- **Correctness and Determinism:** LogicFalcon prioritizes evidence-grounded analysis. Reasoning and code review features must be backed by verifiable AST or graph evidence.
- **Security & Privacy:** Code review rules and telemetry ingestion must treat user repository data as untrusted. Never log secrets, credentials, or private keys.
- **Architectural Separation:** Preserve the layered architecture: API routers → application services → domain models → repositories → infrastructure.

---

## 3. How to Submit Issues and Pull Requests

### Reporting Issues
- Check existing GitHub issues before creating a new report to avoid duplicates.
- Include Python version, OS platform, and relevant terminal/CLI output.
- **Security Disclosures:** Do not post suspected security vulnerabilities in public issues. Please report security concerns privately to the project maintainers.

### Pull Request Process
1. **Fork the Repository:** Create your feature branch from `main`.
2. **Make Changes:** Keep commits focused, well-structured, and descriptively titled.
3. **Add Tests:** Every new feature, rule, parser, or bugfix must include unit or integration tests in `tests/`.
4. **Run Quality Gates:**
   ```bash
   # 1. Run linter
   uv run ruff check .

   # 2. Run static type checker
   uv run mypy --explicit-package-bases logicfalcon aegis apps packages tests

   # 3. Run test suite
   uv run pytest tests/
   ```
5. **Submit PR:** Open a Pull Request against `main`. Provide a clear summary of the problem addressed, changes introduced, and test results.

---

## 4. Third-Party Code & Dependencies Policy

- **License Compatibility:** Any new third-party dependency or library introduced must be compatible with Apache-2.0 (e.g., Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC).
- **Prohibited Licenses:** Do not introduce copyleft dependencies (GPL, AGPL) or libraries with commercial restriction clauses without explicit maintainer approval.
- **Preserving Notices:** If you incorporate permitted third-party code snippets or files, you must preserve existing copyright notices, license headers, and disclaimers.
- **Documenting Dependencies:** All dependencies must be declared in `pyproject.toml` with pinned lower bounds.

---

## 5. Trademark Notice

The **LogicFalcon** name, logo, and brand marks are trademarks of the project authors and are separate from the software copyright license. The Apache-2.0 license grants software usage and modification rights but does not grant unrestricted trademark rights to use the LogicFalcon brand marks without permission.
