from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class DependencyType(StrEnum):
    HTTP = "HTTP"
    DATABASE = "DATABASE"
    CACHE = "CACHE"
    QUEUE = "QUEUE"
    EXTERNAL_API = "EXTERNAL_API"


class ServiceDependency(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    source_service_name: str
    target_service_name: str
    dependency_type: DependencyType
    protocol: str = "HTTP"
    metadata: dict[str, Any] = Field(default_factory=dict)


class SystemNode(BaseModel):
    id: str
    name: str
    type: str  # "service" | "database" | "cache" | "gateway"
    environment: str = "production-sim"
    status: str = "healthy"
    version: str = "1.0.0"
    metadata: dict[str, Any] = Field(default_factory=dict)


class SystemEdge(BaseModel):
    source: str
    target: str
    dependency_type: DependencyType
    protocol: str = "HTTP"


class SystemDependencyGraph(BaseModel):
    nodes: list[SystemNode]
    edges: list[SystemEdge]


class SystemIntelligenceRegistry:
    """Registry maintaining active service definitions, environments, and runtime topology."""

    def __init__(self) -> None:
        self._dependencies: list[ServiceDependency] = []
        self._initialize_production_sim_topology()

    def _initialize_production_sim_topology(self) -> None:
        # Default topology for simulated production
        default_org = UUID("00000000-0000-0000-0000-000000000000")
        self._dependencies = [
            ServiceDependency(
                organization_id=default_org,
                source_service_name="gateway",
                target_service_name="user-service",
                dependency_type=DependencyType.HTTP,
                protocol="HTTP/REST",
            ),
            ServiceDependency(
                organization_id=default_org,
                source_service_name="gateway",
                target_service_name="order-service",
                dependency_type=DependencyType.HTTP,
                protocol="HTTP/REST",
            ),
            ServiceDependency(
                organization_id=default_org,
                source_service_name="order-service",
                target_service_name="user-service",
                dependency_type=DependencyType.HTTP,
                protocol="HTTP/REST",
            ),
            ServiceDependency(
                organization_id=default_org,
                source_service_name="order-service",
                target_service_name="payment-service",
                dependency_type=DependencyType.HTTP,
                protocol="HTTP/REST",
            ),
            ServiceDependency(
                organization_id=default_org,
                source_service_name="order-service",
                target_service_name="postgres",
                dependency_type=DependencyType.DATABASE,
                protocol="PostgreSQL",
            ),
            ServiceDependency(
                organization_id=default_org,
                source_service_name="payment-service",
                target_service_name="redis",
                dependency_type=DependencyType.CACHE,
                protocol="RESP/Redis",
            ),
        ]

    def add_dependency(self, dep: ServiceDependency) -> ServiceDependency:
        self._dependencies.append(dep)
        return dep

    def list_dependencies(self, organization_id: UUID | None = None) -> list[ServiceDependency]:
        if organization_id:
            return [
                d for d in self._dependencies
                if d.organization_id == organization_id or str(d.organization_id) == "00000000-0000-0000-0000-000000000000"
            ]
        return list(self._dependencies)

    def get_dependency_graph(self, organization_id: UUID | None = None) -> SystemDependencyGraph:
        deps = self.list_dependencies(organization_id)
        node_names = set()
        for d in deps:
            node_names.add(d.source_service_name)
            node_names.add(d.target_service_name)

        nodes = []
        for name in sorted(node_names):
            ntype = "service"
            if name == "postgres":
                ntype = "database"
            elif name == "redis":
                ntype = "cache"
            elif name == "gateway":
                ntype = "gateway"
            nodes.append(SystemNode(id=name, name=name, type=ntype))

        edges = [
            SystemEdge(
                source=d.source_service_name,
                target=d.target_service_name,
                dependency_type=d.dependency_type,
                protocol=d.protocol,
            )
            for d in deps
        ]
        return SystemDependencyGraph(nodes=nodes, edges=edges)


system_registry = SystemIntelligenceRegistry()
