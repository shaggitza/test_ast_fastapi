"""
Analyzer package for FastAPI Endpoint Change Detector.

This package contains modules for:
- Mypy-based type-aware dependency analysis
- Endpoint registry management
- Change-to-endpoint mapping
"""

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.client_observations import (
    ClientObservation,
    ClientSurfaceMatch,
    EstablishedSurface,
    established_surfaces,
    extract_client_observations,
    join_established_surfaces,
)
from fastapi_endpoint_detector.analyzer.endpoint_registry import EndpointRegistry
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer

__all__ = [
    "ChangeMapper",
    "ClientObservation",
    "ClientSurfaceMatch",
    "EndpointRegistry",
    "EstablishedSurface",
    "MypyAnalyzer",
    "established_surfaces",
    "extract_client_observations",
    "join_established_surfaces",
]
