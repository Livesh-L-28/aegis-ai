"""Application service coordinating Engineering Evidence Graph indexing, reverse dependency traversal, and evidence recording."""

import hashlib
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.entities import (
    CodeDependencyEdgeEntity,
    CodeSymbolNodeEntity,
    EngineeringEvidenceRecordEntity,
    RepositoryEntity,
    RevisionEntity,
)
from apps.api.app.repositories.evidence_graph import EvidenceGraphRepository
from packages.intelligence.code.indexer import (
    FileClassification,
    sanitize_source_content,
)
from packages.intelligence.code.parser_base import (
    ParserSupportStatus,
    default_parser_registry,
)
from packages.intelligence.code.system_intelligence import SystemIntelligenceExtractor
from packages.intelligence.evidence.graph_models import EvidenceRecord
from packages.logging.logger import get_logger
from packages.service_runtime.metrics import (
    AEGIS_EVIDENCE_CACHE_HITS_TOTAL,
    AEGIS_EVIDENCE_FILES_INDEXED_TOTAL,
    AEGIS_EVIDENCE_NODES_TOTAL,
    AEGIS_EVIDENCE_QUERY_DURATION_SECONDS,
)

logger = get_logger("aegis.services.evidence_graph")

IGNORED_PATH_PATTERNS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".ruff_cache",
    ".mypy_cache",
    ".pytest_cache",
    "node_modules",
    "dist",
    "build",
}

# Protected files that must NEVER be indexed or accessed
PROTECTED_FILENAMES = {
    "render_schema.json",
}


class EvidenceGraphService:
    """Coordinates tenant-isolated indexing, caching, traversal, and persistence for engineering evidence."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = EvidenceGraphRepository(session)

    # -------------------------------------------------------------------------
    # 1. Revision Indexing & Content-Hash Caching
    # -------------------------------------------------------------------------
    async def index_repository_revision(
        self,
        organization_id: UUID,
        project_id: UUID,
        repo_slug: str,
        commit_sha: str,
        repo_name: str | None = None,
        author: str = "unknown",
        commit_message: str = "",
        parent_shas: list[str] | None = None,
        file_contents: Mapping[str, str | bytes] | None = None,
        repo_dir: str | Path | None = None,
        force_reindex: bool = False,
    ) -> tuple[RepositoryEntity, RevisionEntity, int]:
        """Indexes source files, AST symbols, and dependency edges for an immutable revision.

        Implements content-hash caching to reuse prior symbol extractions across revisions.
        """
        # Resolve repository and revision
        repo_name = repo_name or repo_slug
        repository = await self.repo.get_or_create_repository(
            organization_id=organization_id,
            project_id=project_id,
            name=repo_name,
            slug=repo_slug,
        )

        revision = await self.repo.get_or_create_revision(
            organization_id=organization_id,
            repository_id=repository.id,
            commit_sha=commit_sha,
            author=author,
            commit_message=commit_message,
            parent_shas=parent_shas or [],
        )

        # Collect files to index safely
        target_files = self._collect_files(repo_dir=repo_dir, file_contents=file_contents)
        indexed_count = 0

        for rel_path, raw_bytes in target_files.items():
            # Check if this exact file is already indexed for this specific revision (idempotency)
            existing_node = await self.repo.get_file_node(revision.id, rel_path)
            if existing_node and not force_reindex:
                continue

            content_hash = hashlib.sha256(raw_bytes).hexdigest()
            classification = self._classify_file(rel_path)
            lang = self._detect_language(rel_path)

            # Check content-hash cache in the same repository across past revisions
            cached_file = None if force_reindex else await self.repo.find_identical_file_across_revisions(
                repository_id=repository.id,
                file_path=rel_path,
                content_hash=content_hash,
            )

            file_node = await self.repo.create_file_node(
                organization_id=organization_id,
                repository_id=repository.id,
                revision_id=revision.id,
                file_path=rel_path,
                classification=classification.value,
                language=lang,
                content_hash=content_hash,
                size_bytes=len(raw_bytes),
            )
            AEGIS_EVIDENCE_NODES_TOTAL.labels(node_type="source_file").inc()

            parser = default_parser_registry.get_parser_for_file(rel_path)

            if cached_file and cached_file.symbols and not force_reindex:
                # Cache hit: Replicate pre-extracted symbols to this revision's file node
                cached_symbols = [
                    CodeSymbolNodeEntity(
                        organization_id=organization_id,
                        file_node_id=file_node.id,
                        name=s.name,
                        qualified_name=s.qualified_name,
                        symbol_type=s.symbol_type,
                        start_line=s.start_line,
                        end_line=s.end_line,
                        signature=s.signature,
                        docstring_summary=s.docstring_summary,
                    )
                    for s in cached_file.symbols
                ]
                await self.repo.create_symbols(cached_symbols)
                AEGIS_EVIDENCE_NODES_TOTAL.labels(node_type="symbol").inc(len(cached_symbols))
                AEGIS_EVIDENCE_CACHE_HITS_TOTAL.inc()
                AEGIS_EVIDENCE_FILES_INDEXED_TOTAL.labels(language=lang, status="cached").inc()
            elif parser.support_status != ParserSupportStatus.UNSUPPORTED:
                # Parse AST safely as data without executing target code
                try:
                    text_content = raw_bytes.decode("utf-8", errors="ignore")
                    clean_content = sanitize_source_content(text_content)
                    parse_result = parser.parse_source(rel_path, clean_content)
                    extracted_symbols = parse_result.symbols
                    extracted_deps = parse_result.dependencies

                    symbol_entities = [
                        CodeSymbolNodeEntity(
                            organization_id=organization_id,
                            file_node_id=file_node.id,
                            name=sym.name,
                            qualified_name=sym.qualified_name,
                            symbol_type=sym.symbol_type.value,
                            start_line=sym.start_line,
                            end_line=sym.end_line,
                            signature=sym.signature,
                            docstring_summary=sym.docstring,
                        )
                        for sym in extracted_symbols
                    ]
                    if symbol_entities:
                        await self.repo.create_symbols(symbol_entities)
                        AEGIS_EVIDENCE_NODES_TOTAL.labels(node_type="symbol").inc(len(symbol_entities))

                    edge_entities = [
                        CodeDependencyEdgeEntity(
                            organization_id=organization_id,
                            repository_id=repository.id,
                            revision_id=revision.id,
                            source_file_path=rel_path,
                            target_module=dep.target_module,
                            imported_symbols=dep.imported_names,
                            edge_type=getattr(dep, "edge_type", "IMPORT"),
                        )
                        for dep in extracted_deps
                    ]
                    if edge_entities:
                        await self.repo.create_dependency_edges(edge_entities)
                        AEGIS_EVIDENCE_NODES_TOTAL.labels(node_type="dependency_edge").inc(len(edge_entities))

                    # Phase 2D: Static System Intelligence extraction (APIs, models, migrations, configs)
                    sys_report = SystemIntelligenceExtractor.extract_from_file(rel_path, clean_content)
                    for ep in sys_report.api_endpoints:
                        ev = EngineeringEvidenceRecordEntity(
                            organization_id=organization_id,
                            repository_id=repository.id,
                            revision_id=revision.id,
                            evidence_type="API_CONTRACT",
                            provenance_source="SYSTEM_INTELLIGENCE",
                            file_path=rel_path,
                            start_line=ep.line_number,
                            end_line=ep.line_number,
                            symbol_name=f"{ep.http_method} {ep.route_path}",
                            content=f"FastAPI endpoint {ep.handler_name} handling {ep.http_method} {ep.route_path}",
                            structured_payload=ep.model_dump(),
                            confidence=1.0,
                            content_hash=hashlib.sha256(f"{ep.http_method}:{ep.route_path}:{rel_path}".encode()).hexdigest(),
                            validation_status="VALIDATED",
                        )
                        await self.repo.create_evidence_record(ev)

                    for cl in sys_report.client_api_calls:
                        ev = EngineeringEvidenceRecordEntity(
                            organization_id=organization_id,
                            repository_id=repository.id,
                            revision_id=revision.id,
                            evidence_type="API_CONTRACT",
                            provenance_source="SYSTEM_INTELLIGENCE",
                            file_path=rel_path,
                            start_line=cl.line_number,
                            end_line=cl.line_number,
                            symbol_name=f"CLIENT {cl.http_method} {cl.route_path}",
                            content=f"Client API call to {cl.http_method} {cl.route_path}",
                            structured_payload=cl.model_dump(),
                            confidence=0.9,
                            content_hash=hashlib.sha256(f"CLIENT:{cl.http_method}:{cl.route_path}:{rel_path}".encode()).hexdigest(),
                            validation_status="VALIDATED",
                        )
                        await self.repo.create_evidence_record(ev)

                    for dm in sys_report.database_models:
                        ev = EngineeringEvidenceRecordEntity(
                            organization_id=organization_id,
                            repository_id=repository.id,
                            revision_id=revision.id,
                            evidence_type="DATABASE_MODEL",
                            provenance_source="SYSTEM_INTELLIGENCE",
                            file_path=rel_path,
                            start_line=dm.line_number,
                            end_line=dm.line_number,
                            symbol_name=dm.table_name,
                            content=f"SQLAlchemy model {dm.class_name} mapped to table {dm.table_name}",
                            structured_payload=dm.model_dump(),
                            confidence=1.0,
                            content_hash=hashlib.sha256(f"{dm.table_name}:{rel_path}".encode()).hexdigest(),
                            validation_status="VALIDATED",
                        )
                        await self.repo.create_evidence_record(ev)

                    for mg in sys_report.migrations:
                        ev = EngineeringEvidenceRecordEntity(
                            organization_id=organization_id,
                            repository_id=repository.id,
                            revision_id=revision.id,
                            evidence_type="MIGRATION",
                            provenance_source="SYSTEM_INTELLIGENCE",
                            file_path=rel_path,
                            start_line=1,
                            end_line=1,
                            symbol_name=mg.revision_id,
                            content=f"Alembic migration revision {mg.revision_id} (down: {mg.down_revision_id})",
                            structured_payload=mg.model_dump(),
                            confidence=1.0,
                            content_hash=hashlib.sha256(f"MIGRATION:{mg.revision_id}:{rel_path}".encode()).hexdigest(),
                            validation_status="VALIDATED",
                        )
                        await self.repo.create_evidence_record(ev)

                    for cf in sys_report.config_references:
                        ev = EngineeringEvidenceRecordEntity(
                            organization_id=organization_id,
                            repository_id=repository.id,
                            revision_id=revision.id,
                            evidence_type="CONFIGURATION",
                            provenance_source="SYSTEM_INTELLIGENCE",
                            file_path=rel_path,
                            start_line=cf.line_number,
                            end_line=cf.line_number,
                            symbol_name=cf.config_key,
                            content=f"Configuration reference to {cf.config_key}",
                            structured_payload=cf.model_dump(),
                            confidence=1.0,
                            content_hash=hashlib.sha256(f"CONFIG:{cf.config_key}:{rel_path}".encode()).hexdigest(),
                            validation_status="VALIDATED",
                        )
                        await self.repo.create_evidence_record(ev)

                    AEGIS_EVIDENCE_FILES_INDEXED_TOTAL.labels(language=lang, status="indexed").inc()
                except Exception as exc:
                    AEGIS_EVIDENCE_FILES_INDEXED_TOTAL.labels(language=lang, status="failed").inc()
                    logger.warning(
                        "AST parsing failed for file %s: %s",
                        rel_path,
                        exc,
                    )
            else:
                AEGIS_EVIDENCE_FILES_INDEXED_TOTAL.labels(language=lang, status="unsupported").inc()

            indexed_count += 1

        return repository, revision, indexed_count

    # -------------------------------------------------------------------------
    # 2. Reverse Dependency & Traversal Queries
    # -------------------------------------------------------------------------
    async def get_symbols_for_revision(
        self,
        organization_id: UUID,
        repository_id: UUID,
        commit_sha: str,
        file_path: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> tuple[Sequence[CodeSymbolNodeEntity], int]:
        """Queries symbols for a specific repository revision with tenant isolation."""
        t0 = time.perf_counter()
        revision = await self.repo.get_revision_by_sha(
            organization_id=organization_id,
            repository_id=repository_id,
            commit_sha=commit_sha,
        )
        if not revision:
            return [], 0

        symbols = await self.repo.get_symbols_for_revision(
            organization_id=organization_id,
            revision_id=revision.id,
            file_path=file_path,
            limit=limit,
            offset=offset,
        )
        total = await self.repo.count_symbols_for_revision(
            organization_id=organization_id,
            revision_id=revision.id,
            file_path=file_path,
        )
        AEGIS_EVIDENCE_QUERY_DURATION_SECONDS.labels(operation="get_symbols").observe(
            time.perf_counter() - t0
        )
        return symbols, total

    async def get_affected_tests(
        self,
        organization_id: UUID,
        repository_id: UUID,
        commit_sha: str,
        changed_files: list[str],
        max_depth: int = 3,
    ) -> list[str]:
        """Resolves affected test files through reverse dependency traversal."""
        t0 = time.perf_counter()
        revision = await self.repo.get_revision_by_sha(
            organization_id=organization_id,
            repository_id=repository_id,
            commit_sha=commit_sha,
        )
        if not revision:
            return []

        affected = await self.repo.find_affected_tests_for_files(
            organization_id=organization_id,
            revision_id=revision.id,
            changed_files=changed_files,
            max_depth=max_depth,
        )
        AEGIS_EVIDENCE_QUERY_DURATION_SECONDS.labels(operation="find_affected_tests").observe(
            time.perf_counter() - t0
        )
        return affected

    # -------------------------------------------------------------------------
    # 3. Evidence Record Management
    # -------------------------------------------------------------------------
    async def record_evidence(
        self,
        organization_id: UUID,
        record: EvidenceRecord,
        repository_id: UUID | None = None,
        commit_sha: str | None = None,
    ) -> EngineeringEvidenceRecordEntity:
        """Persists a validated engineering evidence record with strict tenant isolation."""
        revision_id = None
        if repository_id and commit_sha:
            rev = await self.repo.get_revision_by_sha(
                organization_id=organization_id,
                repository_id=repository_id,
                commit_sha=commit_sha,
            )
            if rev:
                revision_id = rev.id

        entity = EngineeringEvidenceRecordEntity(
            id=record.id,
            organization_id=organization_id,
            repository_id=repository_id,
            revision_id=revision_id,
            evidence_type=record.evidence_type.upper(),
            provenance_source=record.provenance.source,
            file_path=record.file_path,
            start_line=record.start_line,
            end_line=record.end_line,
            symbol_name=record.symbol_name,
            content=record.content,
            structured_payload=record.structured_payload,
            confidence=record.confidence,
            content_hash=record.content_hash,
            validation_status=record.validation_status.value,
        )
        persisted = await self.repo.create_evidence_record(entity)
        AEGIS_EVIDENCE_NODES_TOTAL.labels(node_type="evidence_record").inc()
        return persisted

    async def list_evidence(
        self,
        organization_id: UUID,
        repository_id: UUID | None = None,
        commit_sha: str | None = None,
        evidence_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[Sequence[EngineeringEvidenceRecordEntity], int]:
        """Lists evidence records filtered by repository, revision, or type."""
        t0 = time.perf_counter()
        revision_id = None
        if repository_id and commit_sha:
            rev = await self.repo.get_revision_by_sha(
                organization_id=organization_id,
                repository_id=repository_id,
                commit_sha=commit_sha,
            )
            if rev:
                revision_id = rev.id

        items = await self.repo.list_evidence_records(
            organization_id=organization_id,
            repository_id=repository_id,
            revision_id=revision_id,
            evidence_type=evidence_type,
            limit=limit,
            offset=offset,
        )
        total = await self.repo.count_evidence_records(
            organization_id=organization_id,
            repository_id=repository_id,
            revision_id=revision_id,
            evidence_type=evidence_type,
        )
        AEGIS_EVIDENCE_QUERY_DURATION_SECONDS.labels(operation="list_evidence").observe(
            time.perf_counter() - t0
        )
        return items, total

    # -------------------------------------------------------------------------
    # 4. Helper & Security Methods
    # -------------------------------------------------------------------------
    def _collect_files(
        self,
        repo_dir: str | Path | None = None,
        file_contents: Mapping[str, str | bytes] | None = None,
    ) -> dict[str, bytes]:
        """Collects candidate files while validating path safety and excluding protected files."""
        collected: dict[str, bytes] = {}

        if file_contents:
            for p, content in file_contents.items():
                clean_path = self._validate_and_normalize_path(p)
                if not clean_path:
                    continue
                raw_bytes = content.encode("utf-8") if isinstance(content, str) else content
                collected[clean_path] = raw_bytes

        if repo_dir:
            root = Path(repo_dir).resolve()
            if root.exists():
                for disk_file in root.rglob("*"):
                    if not disk_file.is_file():
                        continue
                    try:
                        rel_path = str(disk_file.relative_to(root))
                    except ValueError:
                        continue
                    clean_path = self._validate_and_normalize_path(rel_path)
                    if not clean_path:
                        continue
                    try:
                        collected[clean_path] = disk_file.read_bytes()
                    except OSError:
                        continue

        return collected

    def _validate_and_normalize_path(self, raw_path: str) -> str | None:
        """Validates that a path does not escape the repository boundary and is not protected."""
        # Normalize slashes and remove leading slashes
        norm = raw_path.replace("\\", "/").strip().lstrip("/")

        # Reject path traversal
        if ".." in norm.split("/"):
            return None

        # Absolute paths are disallowed
        if norm.startswith("/"):
            return None

        # Exclude protected files absolutely
        parts = norm.split("/")
        if any(part in PROTECTED_FILENAMES for part in parts):
            return None

        # Exclude ignored path patterns
        if any(part in IGNORED_PATH_PATTERNS for part in parts):
            return None

        return norm

    def _classify_file(self, rel_path: str) -> FileClassification:
        lower = rel_path.lower()
        if (
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
                    ".spec.js",
                )
            )
        ):
            return FileClassification.TEST
        if lower.endswith((".md", ".rst", ".txt")):
            return FileClassification.DOCUMENTATION
        if lower.endswith((".yml", ".yaml", ".json", ".toml", ".ini")):
            return FileClassification.CONFIG
        if "docker" in lower or lower.endswith("dockerfile"):
            return FileClassification.INFRASTRUCTURE
        if lower.endswith((".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".go", ".rs")):
            return FileClassification.SOURCE
        return FileClassification.UNKNOWN

    def _detect_language(self, rel_path: str) -> str:
        if rel_path.lower().endswith(".d.ts"):
            return "typescript"
        suffix = Path(rel_path).suffix.lower()
        if suffix in (".py", ".pyi"):
            return "python"
        if suffix in (".js", ".jsx", ".mjs", ".cjs"):
            return "javascript"
        if suffix in (".ts", ".tsx"):
            return "typescript"
        if suffix == ".go":
            return "go"
        if suffix == ".rs":
            return "rust"
        return suffix.replace(".", "") or "unknown"

    async def get_system_contracts(
        self,
        organization_id: UUID,
        repository_id: UUID,
        commit_sha: str,
    ) -> dict[str, list[dict]]:
        """Retrieves system intelligence contracts for a revision from indexed evidence records."""
        revision = await self.repo.get_revision_by_sha(
            organization_id=organization_id,
            repository_id=repository_id,
            commit_sha=commit_sha,
        )
        if not revision:
            return {
                "api_endpoints": [],
                "client_api_calls": [],
                "database_models": [],
                "migrations": [],
                "config_references": [],
            }

        records = await self.repo.list_evidence_records(
            organization_id=organization_id,
            repository_id=repository_id,
            revision_id=revision.id,
            limit=500,
            offset=0,
        )

        endpoints: list[dict] = []
        clients: list[dict] = []
        models: list[dict] = []
        migrations: list[dict] = []
        configs: list[dict] = []

        for r in records:
            if r.evidence_type == "API_CONTRACT":
                if r.symbol_name and r.symbol_name.startswith("CLIENT "):
                    clients.append(r.structured_payload)
                else:
                    endpoints.append(r.structured_payload)
            elif r.evidence_type == "DATABASE_MODEL":
                models.append(r.structured_payload)
            elif r.evidence_type == "MIGRATION":
                migrations.append(r.structured_payload)
            elif r.evidence_type == "CONFIGURATION":
                configs.append(r.structured_payload)

        return {
            "api_endpoints": endpoints,
            "client_api_calls": clients,
            "database_models": models,
            "migrations": migrations,
            "config_references": configs,
        }


