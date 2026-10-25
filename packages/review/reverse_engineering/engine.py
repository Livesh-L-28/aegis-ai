"""Unified orchestration engine for LogicFalcon Reverse Engineering Intelligence."""

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from packages.review.reverse_engineering.api_inventory import APIInventoryExtractor
from packages.review.reverse_engineering.architecture_reconstructor import ArchitectureReconstructor
from packages.review.reverse_engineering.data_model_extractor import DataModelExtractor
from packages.review.reverse_engineering.flow_analyzer import FlowAnalyzer
from packages.review.reverse_engineering.language_detection import LanguageDetector
from packages.review.reverse_engineering.models import (
    AnalysisLimitation,
    ReverseEngineeringReport,
)
from packages.review.reverse_engineering.scanner import RepositoryScanner
from packages.review.reverse_engineering.symbol_extractor import SymbolExtractor


class ReverseEngineeringEngine:
    """Orchestrates safe, read-only static reverse engineering of a software repository."""

    def __init__(
        self,
        repo_root: Path | str = ".",
        max_file_size_bytes: int = 1_000_000,
        max_depth: int = 15,
        max_files: int = 10_000,
        exclude_dirs: set[str] | None = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.max_file_size_bytes = max_file_size_bytes
        self.max_depth = max_depth
        self.max_files = max_files
        self.exclude_dirs = exclude_dirs
        self.timeout_seconds = timeout_seconds

    def analyze(self) -> ReverseEngineeringReport:
        """Executes full reverse engineering pipeline across the repository."""
        start_time = time.monotonic()
        all_limitations: list[AnalysisLimitation] = []

        # 1. Safe Reconnaissance Scan
        scanner = RepositoryScanner(
            repo_root=self.repo_root,
            max_file_size_bytes=self.max_file_size_bytes,
            max_depth=self.max_depth,
            max_files=self.max_files,
            timeout_seconds=self.timeout_seconds,
            exclude_dirs=self.exclude_dirs,
        )
        inventory = scanner.scan()
        all_limitations.extend(scanner.limitations)

        # 2. Language & Framework Detection
        lang_detector = LanguageDetector(self.repo_root)
        detected_languages = lang_detector.detect_languages(scanner.discovered_files)
        detected_frameworks = lang_detector.detect_frameworks(
            inventory.manifest_files,
            scanner.discovered_files,
        )
        inventory.languages = detected_languages
        inventory.frameworks = detected_frameworks

        # Filter analyzable source files
        source_files = [
            f for f in scanner.discovered_files
            if f.suffix.lower() in (".py", ".ts", ".js", ".tsx", ".jsx")
        ]

        # 3. Symbol Extraction
        symbol_extractor = SymbolExtractor(self.repo_root)
        extracted_symbols = []
        for sf in source_files:
            # Check timeout
            if time.monotonic() - start_time > self.timeout_seconds:
                all_limitations.append(
                    AnalysisLimitation(
                        category="timeout",
                        file_path="global",
                        description=f"Analysis exceeded timeout limit of {self.timeout_seconds}s.",
                    )
                )
                break
            symbols = symbol_extractor.extract_file_symbols(sf)
            extracted_symbols.extend(symbols)
        all_limitations.extend(symbol_extractor.limitations)

        # 4. Call-Graph & Execution Flow Analysis
        flow_analyzer = FlowAnalyzer()
        call_graph = flow_analyzer.build_call_graph(extracted_symbols)

        # 5. API & Integration Discovery
        api_extractor = APIInventoryExtractor(self.repo_root)
        api_inventory = api_extractor.extract_inventory(source_files)

        # 6. Data Model & Schema Reconstruction
        data_model_extractor = DataModelExtractor(self.repo_root)
        data_model_inventory = data_model_extractor.extract_inventory(source_files)

        # 7. Architecture Decomposition & Cycle Groups
        arch_reconstructor = ArchitectureReconstructor(self.repo_root)
        arch_components, cycle_groups = arch_reconstructor.reconstruct(scanner.discovered_files)

        # Link symbol counts to architecture components
        for comp in arch_components:
            comp.symbols_count = sum(
                1 for s in extracted_symbols if s.file_path.startswith(comp.module_prefix)
            )

        duration = round(time.monotonic() - start_time, 3)

        return ReverseEngineeringReport(
            repository_path=str(self.repo_root),
            timestamp=datetime.now(UTC).isoformat(),
            inventory=inventory,
            architecture_components=arch_components,
            cycle_groups=cycle_groups,
            call_graph=call_graph,
            api_inventory=api_inventory,
            data_model_inventory=data_model_inventory,
            limitations=all_limitations,
            execution_time_seconds=duration,
            metadata={
                "engine": "LogicFalcon",
                "version": "0.1.2",
                "max_file_size_bytes": self.max_file_size_bytes,
                "timeout_seconds": self.timeout_seconds,
            },
        )

    def analyze_with_review(
        self,
        run_review: bool = True,
        review_config: Any | None = None,
    ) -> ReverseEngineeringReport:
        """Executes reverse engineering analysis and optionally runs integrated code review."""
        report = self.analyze()
        if not run_review:
            return report

        try:
            from packages.review.engine import LocalReviewEngine, ReviewConfig

            cfg = review_config or ReviewConfig()
            review_engine = LocalReviewEngine(repo_root=self.repo_root, config=cfg)

            source_paths: list[str] = [
                str(Path(f).relative_to(self.repo_root))
                for f in self.repo_root.rglob("*")
                if f.is_file() and f.suffix.lower() in (".py", ".ts", ".js", ".tsx", ".jsx")
                and not any(ig in str(f) for ig in cfg.ignored_patterns)
            ]

            if source_paths:
                review_report = review_engine.review_files(file_paths=source_paths[:200])
                report.review_findings = review_report.findings
                report.review_summary = {
                    "total_findings": len(review_report.findings),
                    "is_clean": review_report.is_clean,
                    "execution_time_seconds": review_report.execution_time_seconds,
                    "files_reviewed_count": len(review_report.files_reviewed),
                }
        except Exception as e:
            report.limitations.append(
                AnalysisLimitation(
                    category="review_integration_error",
                    file_path="global",
                    description=f"Integrated code review execution failure: {e}",
                )
            )

        return report
