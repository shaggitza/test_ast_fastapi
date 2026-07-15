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

    schema_version: Literal[1, 2] = 1
    surface_kind: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=64)
    surface_id: str = Field(min_length=1, max_length=512)
    resource: str = Field(min_length=1, max_length=256)
    callback_mode: CallbackMode
    execution_mode: SurfaceExecutionMode = SurfaceExecutionMode.DIRECT
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
    discovery_status: EndpointDiscoveryStatus = EndpointDiscoveryStatus.ESTABLISHED
    discovery_conditions: tuple[EndpointDiscoveryCondition, ...] = ()
    surface: SurfaceRegistrationEvidence | None = None

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

    @model_validator(mode="after")
    def validate_strength(self) -> "EndpointInventory":
        has_limitations = bool(self.limitations)
        if (self.status == InventoryStatus.ESTABLISHED) == has_limitations:
            raise ValueError(
                "established inventory forbids limitations; conditional/unavailable require them"
            )
        if self.status == InventoryStatus.UNAVAILABLE and any(
            endpoint.discovery_status != EndpointDiscoveryStatus.CONDITIONAL
            for endpoint in self.endpoints
        ):
            raise ValueError("unavailable inventory may retain only conditional endpoints")
        return self

    class Config:
        frozen = True
