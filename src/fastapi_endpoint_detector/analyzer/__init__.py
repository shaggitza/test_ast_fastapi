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
    from fastapi_endpoint_detector.analyzer.endpoint_registry import EndpointRegistry
    from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer

_EXPORT_MODULES = {
    "ChangeMapper": "change_mapper",
    "EndpointRegistry": "endpoint_registry",
    "MypyAnalyzer": "mypy_analyzer",
}


def __getattr__(name: str) -> Any:
    """Load public analyzers on demand so model imports cannot form a cycle."""
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(f"{__name__}.{module_name}"), name)
    globals()[name] = value
    return value


__all__ = [
    "ChangeMapper",
    "EndpointRegistry",
    "MypyAnalyzer",
]
