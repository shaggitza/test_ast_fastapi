"""
Dependency data models.

Models representing code dependencies and module information.
"""

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class DependencyType(str, Enum):
    """Types of dependencies between code elements."""

    IMPORT = "import"           # Module import
    FUNCTION_CALL = "call"      # Function call
    CLASS_USAGE = "class"       # Class instantiation/usage
    FASTAPI_DEPENDS = "depends" # FastAPI Depends() injection


class ModuleInfo(BaseModel):
    """Information about a Python module."""

    name: str = Field(description="Fully qualified module name")
    file_path: Path | None = Field(
        default=None,
        description="Path to the module file (None for built-in modules)",
    )
    is_package: bool = Field(default=False, description="Whether this is a package")

    class Config:
        frozen = True


class Dependency(BaseModel):
    """Represents a dependency relationship between code elements."""

    source_module: str = Field(description="Module that has the dependency")
    target_module: str = Field(description="Module being depended upon")
    dependency_type: DependencyType = Field(description="Type of dependency")
    source_file: Path | None = Field(default=None, description="Source file path")
    target_file: Path | None = Field(default=None, description="Target file path")
    line_number: int | None = Field(
        default=None,
        description="Line number of the dependency in source",
    )

    class Config:
        frozen = True
