"""
Base formatter and formatter registry.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi_endpoint_detector.models.endpoint import Endpoint
    from fastapi_endpoint_detector.models.report import AnalysisReport


class BaseFormatter(ABC):
    """
    Abstract base class for output formatters.

    Subclasses must implement format() and format_endpoints() methods.
    """

    @abstractmethod
    def format(self, report: "AnalysisReport") -> str:
        """
        Format an analysis report.

        Args:
            report: The analysis report to format.

        Returns:
            Formatted string representation.
        """
        pass

    @abstractmethod
    def format_endpoints(self, endpoints: list["Endpoint"]) -> str:
        """
        Format a list of endpoints.

        Args:
            endpoints: List of endpoints to format.

        Returns:
            Formatted string representation.
        """
        pass


# Formatter registry
_FORMATTERS: dict[str, type[BaseFormatter]] = {}


def register_formatter(name: str) -> callable:
    """
    Decorator to register a formatter.

    Args:
        name: The name to register the formatter under.

    Returns:
        Decorator function.
    """
    def decorator(cls: type[BaseFormatter]) -> type[BaseFormatter]:
        _FORMATTERS[name] = cls
        return cls
    return decorator


def get_formatter(name: str) -> BaseFormatter:
    """
    Get a formatter instance by name.

    Args:
        name: The formatter name (e.g., "text", "json", "yaml").

    Returns:
        An instance of the requested formatter.

    Raises:
        ValueError: If the formatter name is not recognized.
    """
    # Import formatters to ensure they're registered
    from fastapi_endpoint_detector.output import (  # noqa: F401
        html_output,
        json_output,
        markdown_output,
        text_output,
        yaml_output,
    )

    if name not in _FORMATTERS:
        available = ", ".join(_FORMATTERS.keys())
        raise ValueError(f"Unknown formatter: {name}. Available: {available}")

    return _FORMATTERS[name]()
