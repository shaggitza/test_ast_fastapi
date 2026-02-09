"""
Endpoint data models.

Models representing FastAPI endpoints and their handler functions.
"""

from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


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


class HandlerInfo(BaseModel):
    """Information about an endpoint handler function."""
    
    name: str = Field(description="Name of the handler function")
    module: str = Field(description="Fully qualified module name")
    file_path: Path = Field(description="Path to the file containing the handler")
    line_number: int = Field(description="Line number where the handler is defined")
    end_line_number: Optional[int] = Field(
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
    name: Optional[str] = Field(default=None, description="Optional endpoint name")
    tags: list[str] = Field(default_factory=list, description="OpenAPI tags")
    dependencies: list[str] = Field(
        default_factory=list,
        description="FastAPI Depends() dependencies (function names)",
    )
    
    class Config:
        frozen = True
    
    @property
    def identifier(self) -> str:
        """Unique identifier for this endpoint."""
        methods_str = ",".join(sorted(m.value for m in self.methods))
        return f"{methods_str} {self.path}"
