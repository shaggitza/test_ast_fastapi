"""
Endpoint data models.

Models representing FastAPI endpoints and their handler functions.
"""

from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from fastapi_endpoint_detector.models.surface_contract import (
    CallbackMode,
    CallbackRangeMode,
    SurfaceExecutionMode,
    SurfaceMatchKind,
)


class EndpointMethod(str, Enum):
    """HTTP methods supported by FastAPI."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"
    TRACE = "TRACE"
    WEBSOCKET = "WEBSOCKET"
    CUSTOM = "CUSTOM"


class InventoryStatus(str, Enum):
    """Completeness of an execution-free route inventory."""

    ESTABLISHED = "established"
    CONDITIONAL = "conditional"
    UNAVAILABLE = "unavailable"


class EndpointDiscoveryStatus(str, Enum):
    """Strength of execution-free route discovery evidence."""

    ESTABLISHED = "established"
    CONDITIONAL = "conditional"


class DependencyGraphStatus(str, Enum):
    """Completeness of runtime dependency-graph evidence."""

    ESTABLISHED = "established"
    CONDITIONAL = "conditional"
    UNAVAILABLE = "unavailable"


class DependencyDeclarationScope(str, Enum):
    """Best runtime-attested declaration scope for one dependency occurrence."""

    ASSEMBLY = "assembly"
    PARAMETER = "parameter"
    NESTED = "nested"
    UNKNOWN = "unknown"


class DependencyDeclarationKind(str, Enum):
    """FastAPI declaration construct, without guessing ambiguous empty Security scopes."""

    DEPENDS = "depends"
    SECURITY = "security"
    DEPENDS_OR_SECURITY = "depends_or_security"
    UNKNOWN = "unknown"


class DependencyCallableKind(str, Enum):
    """Stable structural category of a dependency callable."""

    FUNCTION = "function"
    BOUND_METHOD = "bound_method"
    PARTIAL = "partial"
    CALLABLE_INSTANCE = "callable_instance"
    UNKNOWN = "unknown"


class DependencyResolutionStatus(str, Enum):
    """Strength of the identity recorded for one dependency occurrence."""

    ESTABLISHED = "established"
    CONDITIONAL = "conditional"
    UNAVAILABLE = "unavailable"


class DependencySourceSpan(BaseModel):
    """Runtime-inspected source span for a dependency callable."""

    file_path: Path
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_lines(self) -> "DependencySourceSpan":
        if self.end_line < self.start_line:
            raise ValueError("dependency source span end must not precede start")
        return self

    class Config:
        frozen = True


class DependencyCallableStructure(BaseModel):
    """One bounded, address-free layer in a structured callable."""

    kind: DependencyCallableKind
    module: str | None = Field(default=None, min_length=1, max_length=512)
    qualname: str | None = Field(default=None, min_length=1, max_length=1024)
    bound_positional_count: int = Field(default=0, ge=0, le=1024)
    bound_keyword_names: tuple[str, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def validate_identity(self) -> "DependencyCallableStructure":
        if (self.module is None) != (self.qualname is None):
            raise ValueError("dependency callable module and qualname must be provided together")
        if any(not name or len(name) > 256 for name in self.bound_keyword_names):
            raise ValueError("dependency bound keyword names must be nonblank and bounded")
        return self

    class Config:
        frozen = True


class EndpointDependencyOccurrence(BaseModel):
    """One ordered occurrence in FastAPI's declared dependency graph."""

    index_path: tuple[int, ...] = Field(min_length=1, max_length=64)
    parent_path: tuple[int, ...] = Field(max_length=63)
    depth: int = Field(ge=1, le=64)
    order: int = Field(ge=0)
    declaration_scope: DependencyDeclarationScope
    declaration_kind: DependencyDeclarationKind
    callable_kind: DependencyCallableKind
    resolution_status: DependencyResolutionStatus
    display_name: str = Field(min_length=1, max_length=512)
    module: str | None = Field(default=None, min_length=1, max_length=512)
    qualname: str | None = Field(default=None, min_length=1, max_length=1024)
    source_span: DependencySourceSpan | None = None
    security_scopes: tuple[str, ...] = Field(default=(), max_length=256)
    use_cache: bool | None = None
    callable_structure: tuple[DependencyCallableStructure, ...] = Field(default=(), max_length=8)

    @model_validator(mode="after")
    def validate_occurrence(self) -> "EndpointDependencyOccurrence":
        if len(self.index_path) != self.depth or self.parent_path != self.index_path[:-1]:
            raise ValueError("dependency index path must agree with parent path and depth")
        if (self.module is None) != (self.qualname is None):
            raise ValueError("dependency module and qualname must be provided together")
        if self.resolution_status == DependencyResolutionStatus.ESTABLISHED and (
            self.module is None or self.source_span is None
        ):
            raise ValueError("established dependency identity requires qualified source evidence")
        if any(not scope or len(scope) > 512 for scope in self.security_scopes):
            raise ValueError("dependency security scopes must be nonblank and bounded")
        return self

    class Config:
        frozen = True


class DependencyGraphLimitation(BaseModel):
    """Source-backed limitation scoped only to dependency graph collection."""

    code: str = Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=64)
    source_path: Path
    source_line: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=2048)

    @field_validator("reason")
    @classmethod
    def reason_must_be_substantive(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("dependency graph limitation reason must not be blank")
        return value

    class Config:
        frozen = True


class EndpointDependencyGraph(BaseModel):
    """Authoritative declared FastAPI dependency graph for one endpoint."""

    schema_version: Literal[1] = 1
    status: DependencyGraphStatus
    semantics: Literal["declared"] = "declared"
    occurrences: tuple[EndpointDependencyOccurrence, ...] = Field(default=(), max_length=65536)
    limitations: tuple[DependencyGraphLimitation, ...] = Field(default=(), max_length=65536)

    @model_validator(mode="after")
    def validate_strength(self) -> "EndpointDependencyGraph":
        if (self.status == DependencyGraphStatus.ESTABLISHED) == bool(self.limitations):
            raise ValueError(
                "established dependency graph forbids limitations; "
                "conditional/unavailable require them"
            )
        if self.status == DependencyGraphStatus.UNAVAILABLE and self.occurrences:
            raise ValueError("unavailable dependency graph cannot contain occurrences")
        expected_order = tuple(range(len(self.occurrences)))
        if tuple(item.order for item in self.occurrences) != expected_order:
            raise ValueError("dependency occurrence order must be contiguous and deterministic")
        paths = [item.index_path for item in self.occurrences]
        if len(set(paths)) != len(paths):
            raise ValueError("dependency occurrence index paths must be unique")
        if any(component < 0 or component > 65535 for path in paths for component in path):
            raise ValueError("dependency occurrence index components must be bounded nonnegative")
        if paths != sorted(paths):
            raise ValueError("dependency occurrences must use deterministic depth-first preorder")
        seen: set[tuple[int, ...]] = set()
        next_sibling: dict[tuple[int, ...], int] = {}
        for item in self.occurrences:
            if item.parent_path and item.parent_path not in seen:
                raise ValueError("dependency occurrence parent must exist earlier")
            expected_index = next_sibling.get(item.parent_path, 0)
            if item.index_path[-1] != expected_index:
                raise ValueError("dependency root and sibling indexes must be contiguous")
            next_sibling[item.parent_path] = expected_index + 1
            seen.add(item.index_path)
        if self.status == DependencyGraphStatus.ESTABLISHED and any(
            item.resolution_status != DependencyResolutionStatus.ESTABLISHED
            for item in self.occurrences
        ):
            raise ValueError("established graph may contain only established occurrences")
        if (
            any(
                item.resolution_status != DependencyResolutionStatus.ESTABLISHED
                for item in self.occurrences
            )
            and not self.limitations
        ):
            raise ValueError("uncertain dependency occurrences require graph limitations")
        return self

    class Config:
        frozen = True


class EndpointDiscoveryCondition(BaseModel):
    """Source-backed limitation on a conditionally discovered route."""

    source_path: Path
    source_line: int = Field(ge=1)
    reason: str = Field(min_length=1)

    @field_validator("reason")
    @classmethod
    def reason_must_be_substantive(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("discovery condition reason must not be blank")
        return value

    class Config:
        frozen = True


class HandlerInfo(BaseModel):
    """Information about an endpoint handler function."""

    name: str = Field(description="Name of the handler function")
    module: str = Field(description="Fully qualified module name")
    file_path: Path = Field(description="Path to the file containing the handler")
    line_number: int = Field(description="Line number where the handler is defined")
    end_line_number: int | None = Field(
        default=None,
        description="End line number of the handler function",
    )

    class Config:
        frozen = True


class SurfaceRegistrationEvidence(BaseModel):
    """Data-only registration and contract provenance for a custom surface."""

    schema_version: Literal[1, 2, 3, 4, 5] = 1
    surface_kind: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=64)
    surface_id: str = Field(min_length=1, max_length=512)
    resource: str = Field(min_length=1, max_length=256)
    callback_mode: CallbackMode
    callback_range: CallbackRangeMode = CallbackRangeMode.FULL
    execution_mode: SurfaceExecutionMode = SurfaceExecutionMode.DIRECT
    activates_routes: bool = False
    contract_id: str
    match_kind: SurfaceMatchKind
    registration_symbol: str
    registration_file: Path
    registration_line: int = Field(ge=1)
    registration_column: int = Field(ge=0)
    registration_source_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    handler_source_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_source_path: str
    raw_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    config_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    preset_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    conditions: tuple[str, ...] = ()

    class Config:
        frozen = True


class RouteActivationEvidence(BaseModel):
    """Exact lifecycle contract and source occurrence that conditionally installs a route."""

    schema_version: Literal[5] = 5
    phase: Literal["startup"] = "startup"
    execution_mode: SurfaceExecutionMode = SurfaceExecutionMode.FRAMEWORK
    lifecycle_surface_id: str = Field(min_length=1, max_length=512)
    contract_id: str
    registration_file: Path
    registration_line: int = Field(ge=1)
    activation_file: Path
    activation_line: int = Field(ge=1)
    activation_source_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_source_path: str
    raw_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    config_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    preset_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    class Config:
        frozen = True


class Endpoint(BaseModel):
    """Represents a FastAPI endpoint."""

    path: str = Field(description="URL path of the endpoint")
    methods: list[EndpointMethod] = Field(description="HTTP methods for this endpoint")
    handler: HandlerInfo = Field(description="Handler function information")
    name: str | None = Field(default=None, description="Optional endpoint name")
    tags: list[str] = Field(default_factory=list, description="OpenAPI tags")
    dependencies: list[str] = Field(
        default_factory=list,
        description="FastAPI Depends() dependencies (function names)",
    )
    dependency_graph: EndpointDependencyGraph | None = Field(
        default=None,
        description="Authoritative declared dependency graph; None means not collected",
    )
    discovery_status: EndpointDiscoveryStatus = EndpointDiscoveryStatus.ESTABLISHED
    discovery_conditions: tuple[EndpointDiscoveryCondition, ...] = ()
    surface: SurfaceRegistrationEvidence | None = None
    activation: RouteActivationEvidence | None = None

    @model_validator(mode="after")
    def validate_discovery_provenance(self) -> "Endpoint":
        conditional = self.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
        if conditional != bool(self.discovery_conditions):
            raise ValueError(
                "conditional discovery requires conditions and established discovery forbids them"
            )
        custom = EndpointMethod.CUSTOM in self.methods
        if custom and self.methods != [EndpointMethod.CUSTOM]:
            raise ValueError("CUSTOM must be the only method on a custom surface")
        if custom != (self.surface is not None):
            raise ValueError("custom endpoints require CUSTOM method and surface provenance")
        if self.activation is not None and (
            custom
            or self.surface is not None
            or self.discovery_status != EndpointDiscoveryStatus.CONDITIONAL
            or not self.discovery_conditions
        ):
            raise ValueError(
                "activated routes must be conditional native endpoints with source conditions"
            )
        if self.surface is not None:
            if self.path != self.surface.surface_id:
                raise ValueError("custom endpoint path must equal its surface ID")
            if (
                self.surface.match_kind == SurfaceMatchKind.WILDCARD
                and self.discovery_status != EndpointDiscoveryStatus.CONDITIONAL
            ):
                raise ValueError("wildcard custom surfaces must remain conditional")
            if self.surface.conditions and not self.discovery_conditions:
                raise ValueError("declared surface conditions require discovery conditions")
            if self.surface.activates_routes and (
                self.surface.schema_version < 5
                or self.surface.surface_kind != "framework.lifecycle"
                or self.surface.execution_mode != SurfaceExecutionMode.FRAMEWORK
            ):
                raise ValueError(
                    "route activation evidence requires schema-v5 framework lifecycle semantics"
                )
        return self

    class Config:
        frozen = True

    @property
    def identifier(self) -> str:
        """Unique identifier for this endpoint."""
        if self.surface is not None:
            return f"{self.surface.surface_kind.upper()} {self.surface.surface_id}"
        methods_str = ",".join(sorted(m.value for m in self.methods))
        return f"{methods_str} {self.path}"


class EndpointInventory(BaseModel):
    """Execution-free endpoints plus whole-inventory completeness evidence."""

    endpoints: list[Endpoint] = Field(default_factory=list)
    status: InventoryStatus = InventoryStatus.ESTABLISHED
    limitations: tuple[EndpointDiscoveryCondition, ...] = ()
    route_conditions: tuple[EndpointDiscoveryCondition, ...] = ()

    @model_validator(mode="after")
    def validate_strength(self) -> "EndpointInventory":
        has_limitations = bool(self.limitations)
        if (self.status == InventoryStatus.ESTABLISHED) == has_limitations:
            raise ValueError(
                "established inventory forbids limitations; conditional/unavailable require them"
            )
        if any(condition not in self.limitations for condition in self.route_conditions):
            raise ValueError("route-wide conditions must also be inventory limitations")
        if self.route_conditions and self.status == InventoryStatus.ESTABLISHED:
            raise ValueError("route-wide conditions forbid established inventory")
        if self.route_conditions and any(
            endpoint.surface is None
            and (
                endpoint.discovery_status != EndpointDiscoveryStatus.CONDITIONAL
                or any(
                    condition not in endpoint.discovery_conditions
                    for condition in self.route_conditions
                )
            )
            for endpoint in self.endpoints
        ):
            raise ValueError(
                "native endpoints must be conditional and include every route-wide condition"
            )
        if self.status == InventoryStatus.UNAVAILABLE and any(
            endpoint.discovery_status != EndpointDiscoveryStatus.CONDITIONAL
            for endpoint in self.endpoints
        ):
            raise ValueError("unavailable inventory may retain only conditional endpoints")
        return self

    class Config:
        frozen = True
