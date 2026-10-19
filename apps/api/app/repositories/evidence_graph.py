"""Database repository managing Engineering Evidence Graph entities with strict tenant isolation."""

from collections import defaultdict, deque
from collections.abc import Sequence
from pathlib import Path
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from apps.api.app.models.entities import (
    CodeDependencyEdgeEntity,
    CodeSymbolNodeEntity,
    EngineeringEvidenceRecordEntity,
    RepositoryEntity,
    RevisionEntity,
    SourceFileNodeEntity,
)


class EvidenceGraphRepository:
    """Manages transactional persistence, querying, and traversal of evidence graph entities."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # 1. Repository Management
    async def get_or_create_repository(
        self,
        organization_id: UUID,
        project_id: UUID,
        name: str,
        slug: str,
        default_branch: str = "main",
        repo_url: str | None = None,
    ) -> RepositoryEntity:
        query = select(RepositoryEntity).where(
            RepositoryEntity.organization_id == organization_id,
            RepositoryEntity.project_id == project_id,
            RepositoryEntity.slug == slug,
        )
        res = await self.session.execute(query)
        existing = res.scalar_one_or_none()
        if existing:
            return existing

        repo = RepositoryEntity(
            organization_id=organization_id,
            project_id=project_id,
            name=name,
            slug=slug,
            default_branch=default_branch,
            repo_url=repo_url,
        )
        self.session.add(repo)
        await self.session.flush()
        return repo

    async def get_repository_by_id(
        self,
        organization_id: UUID,
        repository_id: UUID,
    ) -> RepositoryEntity | None:
        query = select(RepositoryEntity).where(
            RepositoryEntity.id == repository_id,
            RepositoryEntity.organization_id == organization_id,
        )
        res = await self.session.execute(query)
        return res.scalar_one_or_none()

    async def get_repository_by_slug(
        self,
        organization_id: UUID,
        project_id: UUID,
        slug: str,
    ) -> RepositoryEntity | None:
        query = select(RepositoryEntity).where(
            RepositoryEntity.organization_id == organization_id,
            RepositoryEntity.project_id == project_id,
            RepositoryEntity.slug == slug,
        )
        res = await self.session.execute(query)
        return res.scalar_one_or_none()

    # 2. Revision Management
    async def get_or_create_revision(
        self,
        organization_id: UUID,
        repository_id: UUID,
        commit_sha: str,
        author: str = "unknown",
        commit_message: str = "",
        parent_shas: list[str] | None = None,
    ) -> RevisionEntity:
        query = select(RevisionEntity).where(
            RevisionEntity.organization_id == organization_id,
            RevisionEntity.repository_id == repository_id,
            RevisionEntity.commit_sha == commit_sha,
        )
        res = await self.session.execute(query)
        existing = res.scalar_one_or_none()
        if existing:
            return existing

        rev = RevisionEntity(
            organization_id=organization_id,
            repository_id=repository_id,
            commit_sha=commit_sha,
            author=author,
            commit_message=commit_message,
            parent_shas=parent_shas or [],
        )
        self.session.add(rev)
        await self.session.flush()
        return rev

    async def get_revision_by_sha(
        self,
        organization_id: UUID,
        repository_id: UUID,
        commit_sha: str,
    ) -> RevisionEntity | None:
        query = select(RevisionEntity).where(
            RevisionEntity.organization_id == organization_id,
            RevisionEntity.repository_id == repository_id,
            RevisionEntity.commit_sha == commit_sha,
        )
        res = await self.session.execute(query)
        return res.scalar_one_or_none()

    # 3. Source File & Content Caching
    async def get_file_node(
        self,
        revision_id: UUID,
        file_path: str,
    ) -> SourceFileNodeEntity | None:
        query = (
            select(SourceFileNodeEntity)
            .where(
                SourceFileNodeEntity.revision_id == revision_id,
                SourceFileNodeEntity.file_path == file_path,
            )
            .options(selectinload(SourceFileNodeEntity.symbols))
        )
        res = await self.session.execute(query)
        return res.scalar_one_or_none()

    async def find_identical_file_across_revisions(
        self,
        repository_id: UUID,
        file_path: str,
        content_hash: str,
    ) -> SourceFileNodeEntity | None:
        """Finds a previously indexed source file with identical content hash in this repo."""
        query = (
            select(SourceFileNodeEntity)
            .where(
                SourceFileNodeEntity.repository_id == repository_id,
                SourceFileNodeEntity.file_path == file_path,
                SourceFileNodeEntity.content_hash == content_hash,
            )
            .order_by(SourceFileNodeEntity.created_at.desc())
            .options(selectinload(SourceFileNodeEntity.symbols))
            .limit(1)
        )
        res = await self.session.execute(query)
        return res.scalar_one_or_none()

    async def create_file_node(
        self,
        organization_id: UUID,
        repository_id: UUID,
        revision_id: UUID,
        file_path: str,
        classification: str,
        language: str,
        content_hash: str,
        size_bytes: int,
    ) -> SourceFileNodeEntity:
        node = SourceFileNodeEntity(
            organization_id=organization_id,
            repository_id=repository_id,
            revision_id=revision_id,
            file_path=file_path,
            classification=classification,
            language=language,
            content_hash=content_hash,
            size_bytes=size_bytes,
        )
        self.session.add(node)
        await self.session.flush()
        return node

    async def create_symbols(
        self,
        symbols: list[CodeSymbolNodeEntity],
    ) -> list[CodeSymbolNodeEntity]:
        for s in symbols:
            self.session.add(s)
        await self.session.flush()
        return symbols

    async def create_dependency_edges(
        self,
        edges: list[CodeDependencyEdgeEntity],
    ) -> list[CodeDependencyEdgeEntity]:
        for e in edges:
            self.session.add(e)
        await self.session.flush()
        return edges

    # 4. Queries & Traversal
    async def get_symbols_for_revision(
        self,
        organization_id: UUID,
        revision_id: UUID,
        file_path: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> Sequence[CodeSymbolNodeEntity]:
        query = (
            select(CodeSymbolNodeEntity)
            .join(SourceFileNodeEntity, CodeSymbolNodeEntity.file_node_id == SourceFileNodeEntity.id)
            .where(
                CodeSymbolNodeEntity.organization_id == organization_id,
                SourceFileNodeEntity.revision_id == revision_id,
            )
        )
        if file_path:
            query = query.where(SourceFileNodeEntity.file_path == file_path)

        query = (
            query.order_by(SourceFileNodeEntity.file_path.asc(), CodeSymbolNodeEntity.start_line.asc())
            .limit(limit)
            .offset(offset)
        )
        res = await self.session.execute(query)
        return res.scalars().all()

    async def count_symbols_for_revision(
        self,
        organization_id: UUID,
        revision_id: UUID,
        file_path: str | None = None,
    ) -> int:
        query = (
            select(func.count(CodeSymbolNodeEntity.id))
            .join(SourceFileNodeEntity, CodeSymbolNodeEntity.file_node_id == SourceFileNodeEntity.id)
            .where(
                CodeSymbolNodeEntity.organization_id == organization_id,
                SourceFileNodeEntity.revision_id == revision_id,
            )
        )
        if file_path:
            query = query.where(SourceFileNodeEntity.file_path == file_path)
        res = await self.session.execute(query)
        return res.scalar_one() or 0

    async def get_dependency_edges_for_revision(
        self,
        organization_id: UUID,
        revision_id: UUID,
    ) -> Sequence[CodeDependencyEdgeEntity]:
        query = (
            select(CodeDependencyEdgeEntity)
            .where(
                CodeDependencyEdgeEntity.organization_id == organization_id,
                CodeDependencyEdgeEntity.revision_id == revision_id,
            )
            .order_by(CodeDependencyEdgeEntity.source_file_path.asc())
        )
        res = await self.session.execute(query)
        return res.scalars().all()

    async def find_affected_tests_for_files(
        self,
        organization_id: UUID,
        revision_id: UUID,
        changed_files: list[str],
        max_depth: int = 3,
    ) -> list[str]:
        """Resolves affected test files via reverse dependency graph traversal up to max_depth hops."""
        edges = await self.get_dependency_edges_for_revision(organization_id, revision_id)
        if not edges:
            return []

        # Build reverse index: target -> set of source files that import it
        reverse_index: dict[str, set[str]] = defaultdict(set)
        file_to_modules: dict[str, set[str]] = defaultdict(set)

        for edge in edges:
            src = edge.source_file_path
            tgt = edge.target_module
            reverse_index[tgt].add(src)
            reverse_index[src].add(src)

            # Map dot module names (Python)
            mod_dot = src.removesuffix(".py").replace("/", ".")
            file_to_modules[src].add(mod_dot)
            reverse_index[mod_dot].add(src)

            # Map JS/TS module variations (extensionless, relative, alias)
            for ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
                if src.endswith(ext):
                    bare = src[:-len(ext)]
                    file_to_modules[src].add(bare)
                    reverse_index[bare].add(src)
                    # Relative forms
                    base_name = Path(bare).name
                    file_to_modules[src].add(f"./{base_name}")
                    reverse_index[f"./{base_name}"].add(src)
                    # Alias form @/
                    if bare.startswith("src/"):
                        alias_path = "@/" + bare[4:]
                        file_to_modules[src].add(alias_path)
                        reverse_index[alias_path].add(src)
                    break

        visited_dependents: set[str] = set()
        affected_tests: set[str] = set()

        for cf in changed_files:
            if self._is_test_file(cf):
                affected_tests.add(cf)

            queue: deque[tuple[str, int]] = deque([(cf, 0)])
            for m in file_to_modules.get(cf, set()):
                queue.append((m, 0))

            while queue:
                curr, depth = queue.popleft()
                if depth >= max_depth:
                    continue

                direct_dependents = reverse_index.get(curr, set())
                for dep_file in direct_dependents:
                    if dep_file not in visited_dependents:
                        visited_dependents.add(dep_file)
                        queue.append((dep_file, depth + 1))
                        for dep_mod in file_to_modules.get(dep_file, set()):
                            queue.append((dep_mod, depth + 1))

                        if self._is_test_file(dep_file):
                            affected_tests.add(dep_file)

        return sorted(affected_tests)

    def _is_test_file(self, path: str) -> bool:
        norm = path.lower()
        return (
            "test_" in norm
            or norm.startswith(("tests/", "__tests__/"))
            or norm.endswith(
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
        )


    # 5. Unified Evidence Persistence
    async def create_evidence_record(
        self,
        record: EngineeringEvidenceRecordEntity,
    ) -> EngineeringEvidenceRecordEntity:
        self.session.add(record)
        await self.session.flush()
        return record

    async def list_evidence_records(
        self,
        organization_id: UUID,
        repository_id: UUID | None = None,
        revision_id: UUID | None = None,
        evidence_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[EngineeringEvidenceRecordEntity]:
        query = select(EngineeringEvidenceRecordEntity).where(
            EngineeringEvidenceRecordEntity.organization_id == organization_id,
        )
        if repository_id:
            query = query.where(EngineeringEvidenceRecordEntity.repository_id == repository_id)
        if revision_id:
            query = query.where(EngineeringEvidenceRecordEntity.revision_id == revision_id)
        if evidence_type:
            query = query.where(EngineeringEvidenceRecordEntity.evidence_type == evidence_type.upper())

        query = (
            query.order_by(EngineeringEvidenceRecordEntity.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        res = await self.session.execute(query)
        return res.scalars().all()

    async def count_evidence_records(
        self,
        organization_id: UUID,
        repository_id: UUID | None = None,
        revision_id: UUID | None = None,
        evidence_type: str | None = None,
    ) -> int:
        query = select(func.count(EngineeringEvidenceRecordEntity.id)).where(
            EngineeringEvidenceRecordEntity.organization_id == organization_id,
        )
        if repository_id:
            query = query.where(EngineeringEvidenceRecordEntity.repository_id == repository_id)
        if revision_id:
            query = query.where(EngineeringEvidenceRecordEntity.revision_id == revision_id)
        if evidence_type:
            query = query.where(EngineeringEvidenceRecordEntity.evidence_type == evidence_type.upper())

        res = await self.session.execute(query)
        return res.scalar_one() or 0
