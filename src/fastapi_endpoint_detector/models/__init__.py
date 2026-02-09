"""
Data models for FastAPI Endpoint Change Detector.

This package contains Pydantic models for representing endpoints,
dependencies, diff changes, and analysis reports.
"""

from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointMethod,
    HandlerInfo,
)
from fastapi_endpoint_detector.models.dependency import (
    Dependency,
    DependencyType,
    ModuleInfo,
)
from fastapi_endpoint_detector.models.diff import (
    DiffFile,
    DiffHunk,
    FileChange,
    ChangeType,
)
from fastapi_endpoint_detector.models.report import (
    AffectedEndpoint,
    AnalysisReport,
    ConfidenceLevel,
)

__all__ = [
    # Endpoint models
    "Endpoint",
    "EndpointMethod",
    "HandlerInfo",
    # Dependency models
    "Dependency",
    "DependencyType",
    "ModuleInfo",
    # Diff models
    "DiffFile",
    "DiffHunk",
    "FileChange",
    "ChangeType",
    # Report models
    "AffectedEndpoint",
    "AnalysisReport",
    "ConfidenceLevel",
]
