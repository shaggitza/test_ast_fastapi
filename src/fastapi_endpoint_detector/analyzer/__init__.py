"""
Analyzer package for FastAPI Endpoint Change Detector.

This package contains modules for:
- Mypy-based type-aware dependency analysis
- Endpoint registry management
- Change-to-endpoint mapping
"""

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
    from fastapi_endpoint_detector.analyzer.client_observations import (
        ClientObservation,
        ClientObservationIssue,
        ClientSurfaceMatch,
        EstablishedSurface,
    )
    from fastapi_endpoint_detector.analyzer.deployment_observations import DeploymentObservation
    from fastapi_endpoint_detector.analyzer.endpoint_registry import EndpointRegistry
    from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
    from fastapi_endpoint_detector.analyzer.project_observations import (
        ProjectObservationSnapshot,
        SourceObservationIssue,
    )

_EXPORT_MODULES = {
    "ChangeMapper": "change_mapper",
    "ClientObservation": "client_observations",
    "ClientObservationIssue": "client_observations",
    "ClientSurfaceMatch": "client_observations",
    "DeploymentObservation": "deployment_observations",
    "EndpointRegistry": "endpoint_registry",
    "EstablishedSurface": "client_observations",
    "MypyAnalyzer": "mypy_analyzer",
    "ProjectObservationSnapshot": "project_observations",
    "SourceObservationIssue": "project_observations",
    "established_surfaces": "client_observations",
    "extract_client_observations": "client_observations",
    "extract_client_observation_inventory": "client_observations",
    "extract_dockerfile_observations": "deployment_observations",
    "extract_env_observations": "deployment_observations",
    "extract_subprocess_observations": "deployment_observations",
    "join_established_surfaces": "client_observations",
    "scan_project_observations": "project_observations",
}


def __getattr__(name: str) -> Any:
    """Load public analyzers on demand so model imports cannot form a cycle."""
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(f"{__name__}.{module_name}"), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Expose public exports without eagerly importing their implementations."""
    return sorted(set(globals()) | set(_EXPORT_MODULES))


__all__ = [
    "ChangeMapper",
    "ClientObservation",
    "ClientObservationIssue",
    "ClientSurfaceMatch",
    "DeploymentObservation",
    "EndpointRegistry",
    "EstablishedSurface",
    "MypyAnalyzer",
    "ProjectObservationSnapshot",
    "SourceObservationIssue",
    "established_surfaces",
    "extract_client_observation_inventory",
    "extract_client_observations",
    "extract_dockerfile_observations",
    "extract_env_observations",
    "extract_subprocess_observations",
    "join_established_surfaces",
    "scan_project_observations",
]
