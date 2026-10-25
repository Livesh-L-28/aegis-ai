"""Deterministic documentation and report generator for reverse engineering intelligence."""

import os
import re
from pathlib import Path

from packages.review.adapters.ast_security import redact_secrets_in_text
from packages.review.reverse_engineering.models import (
    ReverseEngineeringReport,
)
from packages.review.security.path_validation import validate_contained_path


def escape_mermaid_id(text: str) -> str:
    """Escapes strings to create valid, safe Mermaid node identifiers."""
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", text)
    return cleaned if cleaned else "node"


def escape_mermaid_label(text: str) -> str:
    """Escapes strings to safely embed within Mermaid label quotes."""
    cleaned = (
        text.replace('"', "'")
        .replace("[", "(")
        .replace("]", ")")
        .replace("{", "(")
        .replace("}", ")")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("`", "'")
        .replace("\n", " ")
        .replace("\r", "")
    )
    return cleaned.strip()


class ReverseEngineeringReportGenerator:
    """Generates Markdown, JSON, and Mermaid reports from reverse engineering data."""

    def __init__(self, report: ReverseEngineeringReport) -> None:
        self.report = report

    def to_json(self, indent: int = 2) -> str:
        """Serializes report to structured JSON."""
        return self.report.model_dump_json(indent=indent)

    def to_text(self) -> str:
        """Generates concise text summary for CLI stdout."""
        inv = self.report.inventory
        lines: list[str] = [
            "🦅  Reverse Engineering Intelligence — LogicFalcon",
            "=" * 60,
            f"Repository: {self.report.repository_path}",
            f"Total Scanned Files: {inv.total_files}",
            f"Total Lines of Code: {inv.total_lines_of_code}",
            f"Execution Time: {self.report.execution_time_seconds:.2f}s",
            "",
            "Detected Languages:",
        ]
        for lang in inv.languages[:5]:
            lines.append(f"  - {lang.name}: {lang.file_count} files")

        if inv.frameworks:
            lines.append("\nDetected Frameworks:")
            for fw in inv.frameworks:
                lines.append(f"  - {fw.name} ({fw.category})")

        if inv.entry_points:
            lines.append("\nEntry Points:")
            for ep in inv.entry_points[:8]:
                lines.append(f"  - [{ep.entry_type.value}] {ep.name} -> {ep.file_path}")

        lines.append(f"\nArchitecture Components: {len(self.report.architecture_components)}")
        for comp in self.report.architecture_components[:8]:
            lines.append(f"  - {comp.name} [{comp.layer.value}]: {comp.file_count} files (Instability: {comp.instability})")

        lines.append(f"\nDiscovered API Endpoints: {self.report.api_inventory.total_routes}")
        for r in self.report.api_inventory.routes[:10]:
            auth_tag = " [AUTH]" if r.is_authenticated else ""
            lines.append(f"  - {r.method.value:<6} {r.path}{auth_tag} -> {r.handler_name} ({r.framework})")

        lines.append(f"\nData Models / Schemas: {self.report.data_model_inventory.total_models}")
        for m in self.report.data_model_inventory.models[:8]:
            lines.append(f"  - {m.name} ({m.model_type}): {len(m.fields)} fields in {m.file_path}")

        if self.report.review_findings:
            lines.append(f"\nIntegrated Review Findings: {len(self.report.review_findings)}")
            for f in self.report.review_findings[:8]:
                f_sev = getattr(f, "severity", None)
                sev_val = str(getattr(f_sev, "value", f_sev or "INFO"))
                rule_id = getattr(f, "rule_id", "UNKNOWN")
                loc = getattr(f, "location", None)
                loc_str = f"{loc.file_path}:{loc.start_line}" if loc else "-"
                title = getattr(f, "title", "")
                lines.append(f"  - [{sev_val}] {rule_id} in {loc_str}: {title}")

        if self.report.limitations:
            lines.append(f"\nAnalysis Limitations: {len(self.report.limitations)}")
            for lim in self.report.limitations[:5]:
                lines.append(f"  - [{lim.category}] {lim.file_path}: {lim.description}")

        lines.append("=" * 60)
        return "\n".join(lines)

    def to_markdown(self) -> str:
        """Generates comprehensive, formatted Markdown report with Mermaid diagrams."""
        inv = self.report.inventory
        lines: list[str] = [
            "# LogicFalcon — Reverse Engineering Intelligence Report",
            "",
            f"> **Repository:** `{self.report.repository_path}`  ",
            f"> **Generated:** `{self.report.timestamp}`  ",
            f"> **Analysis Duration:** `{self.report.execution_time_seconds:.2f}s`  ",
            "",
            "---",
            "",
            "## 1. Executive Summary & Inventory",
            "",
            "| Metric | Count | Details |",
            "| :--- | :--- | :--- |",
            f"| **Scanned Files** | {inv.total_files} | Excludes ignored directories (.git, node_modules, etc.) |",
            f"| **Lines of Code** | {inv.total_lines_of_code:,} | Total across analyzable source files |",
            f"| **Architecture Components** | {len(self.report.architecture_components)} | Subsystems decomposed by module hierarchy |",
            f"| **API Endpoints** | {self.report.api_inventory.total_routes} | HTTP routes across FastAPI, Flask, Express |",
            f"| **Data Models** | {self.report.data_model_inventory.total_models} | Pydantic, SQLAlchemy, dataclasses |",
            f"| **Model Relationships** | {len(self.report.data_model_inventory.relationships)} | Grounded inheritance and type references |",
            f"| **Call Graph Nodes / Edges** | {len(self.report.call_graph.nodes)} / {len(self.report.call_graph.edges)} | Static call invocation relationships |",
            f"| **Environment Variables** | {len(inv.env_variables)} | Required or optional configuration parameters |",
            "",
            "### Language Distribution",
            "",
            "| Language | Files | Extensions | Primary Manifest |",
            "| :--- | :--- | :--- | :--- |",
        ]

        for lang in inv.languages:
            ext_str = ", ".join(lang.extensions) if lang.extensions else "-"
            lines.append(f"| `{lang.name}` | {lang.file_count} | `{ext_str}` | `{lang.primary_manifest or '-'}` |")

        if inv.frameworks:
            lines.extend([
                "",
                "### Detected Frameworks & Infrastructure",
                "",
                "| Framework | Category | Confidence | Evidence Reference |",
                "| :--- | :--- | :--- | :--- |",
            ])
            for fw in inv.frameworks:
                ev_str = fw.evidence[0].file_path if fw.evidence else "-"
                lines.append(f"| **{fw.name}** | `{fw.category}` | {int(fw.confidence * 100)}% | `{ev_str}` |")

        # 2. Onboarding Guide
        lines.extend([
            "",
            "---",
            "",
            "## 2. Onboarding & Code Navigation Guide",
            "",
            "### Core Entry Points",
            "",
            "| Entry Point | Type | Target Path | Symbol / Command | Description |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for ep in inv.entry_points:
            lines.append(f"| **{ep.name}** | `{ep.entry_type.value}` | `{ep.file_path}` | `{ep.symbol_name or ep.command or '-'}` | {ep.description or '-'} |")

        if not inv.entry_points:
            lines.append("| *No explicit entry points detected* | - | - | - | - |")

        # 3. Architecture & Subsystems
        lines.extend([
            "",
            "---",
            "",
            "## 3. Architecture & Subsystems",
            "",
            "| Component | Layer | Files | Outgoing Dependencies | Incoming Dependencies | Instability ($I$) |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for comp in self.report.architecture_components:
            out_str = f"{len(comp.outgoing_dependencies)} components" if comp.outgoing_dependencies else "0"
            in_str = f"{len(comp.incoming_dependencies)} components" if comp.incoming_dependencies else "0"
            hotspot_tag = " ⚠️ **Hotspot**" if comp.is_hotspot else ""
            lines.append(f"| `{comp.name}` | `{comp.layer.value}` | {comp.file_count} | {out_str} | {in_str} | `{comp.instability:.2f}`{hotspot_tag} |")

        # Mermaid Component Diagram
        lines.extend([
            "",
            "### Component Dependency Diagram",
            "",
            "```mermaid",
            "graph TD",
        ])
        for comp in self.report.architecture_components[:12]:
            comp_id = escape_mermaid_id(comp.name)
            comp_label = escape_mermaid_label(f"{comp.name} [{comp.layer.value}]")
            lines.append(f'    {comp_id}["{comp_label}"]')
            for dep in comp.outgoing_dependencies[:3]:
                dep_id = escape_mermaid_id(dep)
                lines.append(f"    {comp_id} --> {dep_id}")
        lines.append("```")

        # 4. API Endpoint Catalog
        lines.extend([
            "",
            "---",
            "",
            "## 4. Discovered API Endpoints & Interfaces",
            "",
            "| Method | Path | Handler | Auth Required | Framework | File Location |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for r in self.report.api_inventory.routes:
            auth_str = "🔒 Yes" if r.is_authenticated else "🔓 No"
            lines.append(f"| `{r.method.value}` | `{r.path}` | `{r.handler_name}` | {auth_str} | `{r.framework}` | `{r.file_path}:{r.line_number}` |")

        if not self.report.api_inventory.routes:
            lines.append("| *No HTTP routes discovered* | - | - | - | - | - |")

        # 5. Data Models & Entity Relationships
        lines.extend([
            "",
            "---",
            "",
            "## 5. Data Models & Schemas",
            "",
            "| Model | Type | Fields Count | Location | Base Classes |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for m in self.report.data_model_inventory.models:
            bases = ", ".join(m.base_classes) if m.base_classes else "-"
            lines.append(f"| **{m.name}** | `{m.model_type}` | {len(m.fields)} | `{m.file_path}:{m.line_number}` | `{bases}` |")

        if not self.report.data_model_inventory.models:
            lines.append("| *No data models discovered* | - | - | - | - |")

        # Mermaid Model Relationship Diagram
        if self.report.data_model_inventory.relationships:
            lines.extend([
                "",
                "### Entity Relationship Diagram",
                "",
                "```mermaid",
                "classDiagram",
            ])
            for rel in self.report.data_model_inventory.relationships[:20]:
                src_id = escape_mermaid_id(rel.source_model)
                tgt_id = escape_mermaid_id(rel.target_model)
                if rel.relationship_type.value == "inheritance":
                    lines.append(f"    {tgt_id} <|-- {src_id}")
                elif rel.relationship_type.value == "one_to_many":
                    lines.append(f'    {src_id} "1" --> "*" {tgt_id} : {escape_mermaid_label(rel.field_name)}')
                else:
                    lines.append(f'    {src_id} --> {tgt_id} : {escape_mermaid_label(rel.field_name)}')
            lines.append("```")

        # 6. Environment Variables
        if inv.env_variables:
            lines.extend([
                "",
                "---",
                "",
                "## 6. Environment Variables & Configuration",
                "",
                "| Variable Name | Default Value | References Count | First Referenced In |",
                "| :--- | :--- | :--- | :--- |",
            ])
            for ev in inv.env_variables:
                def_val = f"`{ev.default_value}`" if ev.default_value else "*None*"
                first_ref = f"`{ev.evidence[0].file_path}:{ev.evidence[0].line_number}`" if ev.evidence else "-"
                lines.append(f"| `{ev.name}` | {def_val} | {len(ev.evidence)} | {first_ref} |")

        # 7. Analysis Limitations
        lines.extend([
            "",
            "---",
            "",
            "## 7. Analysis Limitations & Provenance",
            "",
            "> Static reverse engineering constructs representations strictly from static AST and configuration analysis.",
            "> Dynamic dispatch, runtime-generated routes, reflection, and external services cannot be fully proven statically.",
            "",
        ])
        if self.report.limitations:
            lines.extend([
                "| Category | File | Description |",
                "| :--- | :--- | :--- |",
            ])
            for lim in self.report.limitations[:25]:
                lines.append(f"| `{lim.category}` | `{lim.file_path}` | {lim.description} |")
        else:
            lines.append("*No analysis limitations encountered during scan.*")

        # 8. Integrated Code Review Findings
        if self.report.review_findings:
            lines.extend([
                "",
                "---",
                "",
                "## 8. Integrated Code Review Findings",
                "",
                f"> **Total Review Findings:** {len(self.report.review_findings)}  ",
                "",
                "| Severity | Rule ID | Title | Location | Component | Blast Radius |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
            ])
            for f in self.report.review_findings:
                f_sev = getattr(f, "severity", None)
                sev_val = str(getattr(f_sev, "value", f_sev or "INFO"))
                rule_id = getattr(f, "rule_id", "UNKNOWN")
                title = getattr(f, "title", "")
                loc = getattr(f, "location", None)
                loc_str = f"{loc.file_path}:{loc.start_line}" if loc else "-"
                meta = getattr(f, "metadata", {}) or {}
                comp_str = meta.get("re_component", "-")
                blast = meta.get("reverse_dependencies_count", "-")
                lines.append(f"| `{sev_val}` | `{rule_id}` | {title} | `{loc_str}` | `{comp_str}` | {blast} |")

        return "\n".join(lines) + "\n"

    def write_output(
        self,
        output_format: str = "markdown",
        output_file: Path | str | None = None,
        output_dir: Path | str | None = None,
        repo_root: Path | str | None = None,
    ) -> str:
        """Renders report and optionally writes to output file with atomic write and safety checks."""
        if output_format == "json":
            rendered = self.to_json()
        elif output_format == "text":
            rendered = self.to_text()
        else:
            rendered = self.to_markdown()

        # Final pass redaction to guarantee secrets never leak in generated output
        rendered = redact_secrets_in_text(rendered)

        if output_file or output_dir:
            target_path: Path
            if output_file:
                target_path = Path(output_file).resolve()
            elif output_dir:
                ext = "json" if output_format == "json" else ("txt" if output_format == "text" else "md")
                target_path = (Path(output_dir).resolve() / f"reverse_engineering_report.{ext}").resolve()
            else:
                return rendered

            # Enforce path containment if repo_root is provided
            if repo_root:
                root_path = Path(repo_root).resolve()
                contained = validate_contained_path(root_path, str(target_path))
                if not contained and not target_path.is_relative_to(root_path):
                    raise PermissionError(f"Output path escapes repository root: {target_path}")

            # Defense: Prevent accidental overwrite of source files!
            if target_path.suffix.lower() in (".py", ".ts", ".js", ".tsx", ".jsx", ".go", ".rs", ".java"):
                raise PermissionError(
                    f"Refusing to write report to source code file '{target_path.name}'. "
                    "Reports must use report extensions (.md, .json, .txt)."
                )

            # Atomic write via temporary file
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


# Backward-compatible alias
ReportGenerator = ReverseEngineeringReportGenerator
