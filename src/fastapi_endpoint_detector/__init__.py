"""
FastAPI Endpoint Change Detector

A CLI tool that analyzes code changes and identifies which FastAPI endpoints
are affected. It uses AST parsing, static analysis, and dependency graph
construction to provide accurate impact analysis.
"""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("fastapi-endpoint-detector")
except PackageNotFoundError:
    __version__ = "0.1.0"

__author__ = "Your Name"
__email__ = "your.email@example.com"

# Public API exports
__all__ = [
    "__version__",
    "__author__",
    "__email__",
]
