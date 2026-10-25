"""Deterministic, secure report generator for change impact analysis and test selection."""

import os
from pathlib import Path

from packages.review.adapters.ast_security import redact_secrets_in_text
from packages.review.impact.models import ChangeImpactReport
from packages.review.reverse_engineering.report_generator import (
    escape_mermaid_id,
    escape_mermaid_label,
)
from packages.review.security.path_validation import validate_contained_path


class ChangeImpactReportGenerator:
    """Generates Markdown, JSON, Plain Text, and Mermaid reports for change impact intelligence."""

    def __init__(self, report: ChangeImpactReport) -> None:
        self.report = report

    def to_json(self, indent: int = 2) -> str:
        """Serializes report to structured, schema-stable JSON."""
        return redact_secrets_in_text(self.report.model_dump_json(indent=indent))

    def to_text(self) -> str:
        """Generates concise plain-text summary suitable for CLI stdout."""
        cs = self.report.change_set
        lines: list[str] = [
            "🦅  Change Impact Intelligence & Predictive Test Selection — LogicFalcon",
            "=" * 70,
            f"Repository: {self.report.repository_path}",
            f"Risk Level: {self.report.risk_level.value} (Score: {self.report.risk_score}/100)",
            f"Execution Time: {self.report.execution_time_seconds:.2f}s",
            "",
            "Change Set Overview:",
            f"  - Modified Files: {len(cs.modified_paths)}",
            f"  - Added Files: {len(cs.added_paths)}",
            f"  - Deleted Files: {len(cs.deleted_paths)}",
            f"  - Renamed Files: {len(cs.renamed_paths)}",
            f"  - Changed Symbols: {len(cs.changed_symbols)}",
            f"  - Lines: +{cs.total_added_lines} / -{cs.total_deleted_lines}",
            "",
            f"Impacted Entities: {len(self.report.impacted_entities)}",
        ]

        for ent in self.report.impacted_entities[:8]:
            comp_tag = f" [{ent.component_name}]" if ent.component_name else ""
            lines.append(f"  - [Depth {ent.depth}] {ent.file_path}{comp_tag} (Score: {ent.impact_score})")

        lines.append(f"\nRecommended Tests to Run: {len(self.report.recommended_tests)}")
        for tc in self.report.recommended_tests[:10]:
            lines.append(f"  - [{tc.confidence.value}] {tc.test_file} ({tc.selection_reason})")

        if self.report.risk_reasons:
            lines.append("\nRisk Analysis Factors:")
            for r in self.report.risk_reasons:
                lines.append(f"  - {r}")

        if self.report.limitations:
            lines.append("\nAnalysis Limitations:")
            for lim in self.report.limitations:
                lines.append(f"  - [{lim.category}] {lim.file_path}: {lim.description}")

        lines.append("=" * 70)
        return redact_secrets_in_text("\n".join(lines))

    def to_markdown(self) -> str:
        """Generates comprehensive Markdown report with tables and Mermaid diagrams."""
        cs = self.report.change_set
        lines: list[str] = [
            "# LogicFalcon — Change Impact Intelligence Report",
            "",
            f"> **Repository:** `{self.report.repository_path}`  ",
            f"> **Base Revision:** `{cs.base_revision or 'HEAD'}` | **Target Revision:** `{cs.target_revision or 'working_tree'}`  ",
            f"> **Generated:** `{self.report.timestamp}` | **Duration:** `{self.report.execution_time_seconds:.2f}s`  ",
            "",
            "---",
            "",
            "## 1. Executive Summary & Change Risk Assessment",
            "",
            "| Assessment Metric | Value | Meaning |",
            "| :--- | :--- | :--- |",
            f"| **Overall Risk Level** | **`{self.report.risk_level.value}`** | Risk classification based on blast radius & critical modules |",
            f"| **Impact Risk Score** | **`{self.report.risk_score} / 100`** | Weighted composite score of dependency distance & reachability |",
            f"| **Changed Files** | **{len(cs.modified_paths) + len(cs.added_paths) + len(cs.deleted_paths)}** | Total modified, added, deleted, or renamed source files |",
            f"| **Impacted Dependents** | **{len(self.report.impacted_entities)}** | Modules and components consuming changed code |",
            f"| **Recommended Tests** | **{len(self.report.recommended_tests)}** | Test suites statically prioritized for execution |",
            "",
            "### Risk Rationale",
            "",
        ]

        for r in self.report.risk_reasons:
            lines.append(f"- **{r}**")

        lines.extend([
            "",
            "---",
            "",
            "## 2. Detected Change Set",
            "",
            "| File Path | Operation | Added Lines | Deleted Lines | Changed Symbols |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])

        for cf in cs.changed_files:
            p = cf.new_path or cf.old_path or "unknown"
            syms_for_file = [s.symbol.name for s in cs.changed_symbols if s.file_path == p]
            sym_str = ", ".join(syms_for_file[:3]) if syms_for_file else "-"
            lines.append(f"| `{p}` | `{cf.change_type.value}` | `+{cf.added_lines_count}` | `-{cf.deleted_lines_count}` | `{sym_str}` |")

        lines.extend([
            "",
            "---",
            "",
            "## 3. Impacted Entities & Blast Radius",
            "",
            "| Depth | Target Entity | Component / Layer | Impact Score | Shortest Explanatory Path |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])

        for ent in self.report.impacted_entities[:25]:
            comp_layer = f"{ent.component_name or '-'} / {ent.layer or '-'}"
            path_str = " &rarr; ".join(f"`{p}`" for p in ent.shortest_path)
            lines.append(f"| `{ent.depth}` | `{ent.file_path}` | `{comp_layer}` | **`{ent.impact_score}`** | {path_str} |")

        if len(self.report.impacted_entities) > 25:
            lines.append(f"\n*... and {len(self.report.impacted_entities) - 25} additional impacted entity records omitted for brevity.*")

        lines.extend([
            "",
            "---",
            "",
            "## 4. Recommended Test Selection (Predictive Test Impact)",
            "",
            "| Confidence | Recommended Test File | Triggering Target | Selection Justification |",
            "| :--- | :--- | :--- | :--- |",
        ])

        for tc in self.report.recommended_tests:
            lines.append(f"| **`{tc.confidence.value}`** | `{tc.test_file}` | `{tc.associated_target}` | {tc.selection_reason} |")

        if not self.report.recommended_tests:
            lines.append("| - | *No tests directly or transitively associated with this change.* | - | Run full regression suite if unsure. |")

        # Mermaid Graph Diagram
        lines.extend([
            "",
            "---",
            "",
            "## 5. Visual Impact Propagation Flow",
            "",
            "```mermaid",
            "flowchart TD",
        ])

        # Render top 12 edges in Mermaid
        rendered_edges = 0
        for ent in self.report.impacted_entities[:12]:
            if len(ent.shortest_path) >= 2:
                for i in range(len(ent.shortest_path) - 1):
                    src_id = escape_mermaid_id(ent.shortest_path[i])
                    tgt_id = escape_mermaid_id(ent.shortest_path[i + 1])
                    src_label = escape_mermaid_label(ent.shortest_path[i])
                    tgt_label = escape_mermaid_label(ent.shortest_path[i + 1])
                    lines.append(f'  {src_id}["{src_label}"] --> {tgt_id}["{tgt_label}"]')
                    rendered_edges += 1

        if rendered_edges == 0:
            lines.append('  change["Changed Files"] -->|"No dependents"| clean["Isolated"]')

        lines.extend([
            "```",
            "",
            "---",
            "",
            "## 6. Analysis Limitations & Provenance",
            "",
            "- **Static Analysis Boundary**: Dynamic reflection, dynamic `importlib` calls, and global test fixtures may obscure runtime relationships.",
            "- **Deterministic Guarantees**: Test recommendations and impact scores are prioritization heuristics and do not guarantee absence of runtime failures.",
        ])

        for lim in self.report.limitations:
            lines.append(f"- `[{lim.category}]` `{lim.file_path}`: {lim.description}")

        raw_md = "\n".join(lines)
        return redact_secrets_in_text(raw_md)

    def write_to_file(self, target_path_str: str, repo_root: str | Path | None = None) -> str:
        """Atomically writes formatted report to target path with safety guards."""
        target_path = Path(target_path_str)

        # 1. Overwrite defense against source files
        suffix = target_path.suffix.lower()
        if suffix in (".py", ".ts", ".js", ".tsx", ".jsx", ".go", ".rs", ".java"):
            raise PermissionError(
                f"Refusing to write report to source code file '{target_path.name}'. "
                "Reports must use report extensions (.md, .json, .txt)."
            )

        # 2. Path containment check
        if repo_root is not None:
            resolved_root = Path(repo_root).resolve()
            if target_path.is_absolute():
                resolved_target = target_path.resolve()
                try:
                    if not resolved_target.is_relative_to(resolved_root):
                        raise PermissionError(f"Rejected report path outside repository: '{target_path_str}'")
                    target_path = resolved_target
                except (ValueError, AttributeError):
                    raise PermissionError(f"Rejected report path outside repository: '{target_path_str}'") from None
            else:
                contained = validate_contained_path(resolved_root, target_path_str)
                if contained is None:
                    raise PermissionError(f"Rejected report path outside repository: '{target_path_str}'")
                target_path = contained

        if suffix in (".json",):
            rendered = self.to_json()
        elif suffix in (".txt",):
            rendered = self.to_text()
        else:
            rendered = self.to_markdown()

        target_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = target_path.with_suffix(f"{target_path.suffix}.tmp.{os.getpid()}")
        try:
            temp_path.write_text(rendered, encoding="utf-8")
            temp_path.replace(target_path)
        except Exception:
            if temp_path.exists():
                temp_path.unlink(missing_ok=True)
            raise

        return rendered
