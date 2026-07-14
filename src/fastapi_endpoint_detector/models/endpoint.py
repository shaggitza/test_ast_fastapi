"""
Endpoint data models.

Models representing FastAPI endpoints and their handler functions.
"""

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field, field_validator, model_validator


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

    @model_validator(mode="after")
    def validate_discovery_provenance(self) -> "Endpoint":
        conditional = self.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
        if conditional != bool(self.discovery_conditions):
            raise ValueError(
                "conditional discovery requires conditions and established discovery forbids them"
            )
        return self

    class Config:
        frozen = True

    @property
    def identifier(self) -> str:
        """Unique identifier for this endpoint."""
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
