"""Typed data models for the LogicFalcon Reverse Engineering Intelligence subsystem.

Defines structured models for repository inventories, detected languages and frameworks,
entry points, architecture components, symbols, call graphs, API endpoints, data models,
and analysis limitations.
"""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ConfidenceLevel(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    HEURISTIC = "HEURISTIC"


class EvidenceProvenance(BaseModel):
    """Ground-truth provenance reference for a reverse-engineered artifact."""

    file_path: str
    line_number: int | None = None
    end_line: int | None = None
    code_snippet: str | None = None
    confidence: float = 1.0
    provenance_type: str = "static_ast"


class DetectedLanguage(BaseModel):
    """Information about a programming or configuration language detected in the repository."""

    name: str
    file_count: int
    line_count: int = 0
    extensions: list[str] = Field(default_factory=list)
    primary_manifest: str | None = None


class DetectedFramework(BaseModel):
    """A framework, library, or platform detected through configuration or imports."""

    name: str
    category: str  # "web_api", "orm_database", "testing", "cli", "ai_llm", "infrastructure"
    confidence: float = 1.0
    version_hint: str | None = None
    evidence: list[EvidenceProvenance] = Field(default_factory=list)


class EntryPointType(StrEnum):
    CLI = "cli"
    ASGI_WSGI = "asgi_wsgi"
    SCRIPT = "script"
    WORKER = "worker"
    TEST = "test"
    CONTAINER = "container"
    UNKNOWN = "unknown"


class EntryPoint(BaseModel):
    """Executable boundary or entry point into the application."""

    name: str
    entry_type: EntryPointType
    file_path: str
    symbol_name: str | None = None
    command: str | None = None
    description: str | None = None
    evidence: EvidenceProvenance


class EnvironmentVariable(BaseModel):
    """Environment variable read or required by the codebase."""

    name: str
    default_value: str | None = None
    is_required: bool = False
    evidence: list[EvidenceProvenance] = Field(default_factory=list)


class RepositoryInventory(BaseModel):
    """Holistic reconnaissance inventory of scanned repository assets."""

    total_files: int = 0
    total_lines_of_code: int = 0
    languages: list[DetectedLanguage] = Field(default_factory=list)
    frameworks: list[DetectedFramework] = Field(default_factory=list)
    manifest_files: list[str] = Field(default_factory=list)
    lock_files: list[str] = Field(default_factory=list)
    config_files: list[str] = Field(default_factory=list)
    test_files: list[str] = Field(default_factory=list)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    env_variables: list[EnvironmentVariable] = Field(default_factory=list)


class SymbolKind(StrEnum):
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    ASYNC_FUNCTION = "async_function"
    INTERFACE = "interface"
    TYPE_ALIAS = "type_alias"
    CONSTANT = "constant"
    VARIABLE = "variable"


class ExtractedSymbol(BaseModel):
    """Extracted code symbol with location, signature, and documentation."""

    name: str
    qualified_name: str
    kind: SymbolKind
    file_path: str
    start_line: int
    end_line: int
    docstring: str | None = None
    decorators: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)
    return_type: str | None = None
    is_exported: bool = True
    callees: list[str] = Field(default_factory=list)


class CallGraphEdge(BaseModel):
    """Direct or static call invocation between two symbols."""

    caller_symbol: str
    callee_symbol: str
    caller_file: str
    callee_file: str | None = None
    call_type: str = "direct_call"  # "direct_call", "async_call", "method_call", "dynamic_unresolved"
    line_number: int | None = None
    confidence: float = 1.0
    is_partial: bool = False


class CallGraph(BaseModel):
    """Static call graph mapping caller-callee invocations."""

    nodes: list[str] = Field(default_factory=list)
    edges: list[CallGraphEdge] = Field(default_factory=list)
    unresolved_calls: list[str] = Field(default_factory=list)


class HTTPMethod(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"
    ANY = "ANY"


class APIRoute(BaseModel):
    """Reverse-engineered API endpoint declaration."""

    path: str
    method: HTTPMethod
    handler_name: str
    file_path: str
    line_number: int
    framework: str
    docstring: str | None = None
    parameters: list[str] = Field(default_factory=list)
    request_schema: str | None = None
    response_schema: str | None = None
    auth_requirements: list[str] = Field(default_factory=list)
    is_authenticated: bool = False
    auth_detected: bool = False
    auth_evidence: str | None = None


class APIInventory(BaseModel):
    """Inventory of discovered HTTP endpoints and integration interfaces."""

    total_routes: int = 0
    routes: list[APIRoute] = Field(default_factory=list)
    frameworks_used: list[str] = Field(default_factory=list)
    auth_mechanisms: list[str] = Field(default_factory=list)


class ModelField(BaseModel):
    """Field or attribute in a data model or schema."""

    name: str
    type_annotation: str
    is_required: bool = True
    default_value: str | None = None
    is_primary_key: bool = False
    is_foreign_key: bool = False
    foreign_key_target: str | None = None
    description: str | None = None


class RelationshipType(StrEnum):
    ONE_TO_ONE = "one_to_one"
    ONE_TO_MANY = "one_to_many"
    MANY_TO_MANY = "many_to_many"
    INHERITANCE = "inheritance"
    COMPOSITION = "composition"
    REFERENCE = "reference"


class ModelRelationship(BaseModel):
    """Evidence-grounded relationship between two data models."""

    source_model: str
    target_model: str
    relationship_type: RelationshipType
    field_name: str
    evidence: EvidenceProvenance


class DataModel(BaseModel):
    """Reverse-engineered data model, entity, or schema."""

    name: str
    model_type: str  # "pydantic", "sqlalchemy", "dataclass", "typeddict", "interface"
    file_path: str
    line_number: int
    fields: list[ModelField] = Field(default_factory=list)
    docstring: str | None = None
    base_classes: list[str] = Field(default_factory=list)


class DataModelInventory(BaseModel):
    """Inventory of data models, schemas, and entity relationships."""

    total_models: int = 0
    models: list[DataModel] = Field(default_factory=list)
    relationships: list[ModelRelationship] = Field(default_factory=list)


class ComponentLayer(StrEnum):
    PRESENTATION_API = "presentation_api"
    APPLICATION_SERVICE = "application_service"
    DOMAIN_CORE = "domain_core"
    INFRASTRUCTURE_ADAPTER = "infrastructure_adapter"
    COMMON_UTILITY = "common_utility"
    TESTING = "testing"
    UNKNOWN = "unknown"


class ArchitectureComponent(BaseModel):
    """Decomposed architectural subsystem or layer component."""

    name: str
    layer: ComponentLayer
    module_prefix: str
    file_count: int = 0
    symbols_count: int = 0
    outgoing_dependencies: list[str] = Field(default_factory=list)
    incoming_dependencies: list[str] = Field(default_factory=list)
    instability: float = 0.0
    is_hotspot: bool = False


class AnalysisLimitation(BaseModel):
    """Explicitly documented static analysis limitation or uncertainty."""

    category: str  # "dynamic_dispatch", "reflection", "unresolved_import", "malformed_syntax", "oversized_file", "timeout"
    file_path: str
    description: str
    line_number: int | None = None


class ReverseEngineeringReport(BaseModel):
    """Top-level unified reverse engineering intelligence report."""

    repository_path: str
    timestamp: str
    inventory: RepositoryInventory = Field(default_factory=RepositoryInventory)
    architecture_components: list[ArchitectureComponent] = Field(default_factory=list)
    cycle_groups: list[dict[str, Any]] = Field(default_factory=list)
    call_graph: CallGraph = Field(default_factory=CallGraph)
    api_inventory: APIInventory = Field(default_factory=APIInventory)
    data_model_inventory: DataModelInventory = Field(default_factory=DataModelInventory)
    limitations: list[AnalysisLimitation] = Field(default_factory=list)
    execution_time_seconds: float = 0.0
    review_findings: list[Any] = Field(default_factory=list)
    review_summary: dict[str, Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
