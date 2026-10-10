"""
Base formatter and formatter registry.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from fastapi_endpoint_detector.config import OutputConfig
    from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointInventory
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

    def format_inventory(self, inventory: "EndpointInventory") -> str:
        """Format a strength-aware inventory; legacy formatters retain endpoint output."""
        return self.format_endpoints(inventory.endpoints)

    @staticmethod
    def summarize_source_observations(observations: dict[str, object]) -> str:
        """Summarize the optional source-only report section for human formats."""
        clients = observations.get("client_observations")
        client_uncertainties = observations.get("client_uncertainties")
        deployments = observations.get("deployment_observations")
        matches = observations.get("surface_matches")
        deployment_rows = deployments if isinstance(deployments, list) else []
        exact_deployments = sum(
            isinstance(item, dict) and item.get("certainty") == "exact" for item in deployment_rows
        )
        complete = observations.get("complete") is True
        scanned_files = observations.get("scanned_files", 0)
        return (
            f"{'complete' if complete else 'incomplete'} scan of {scanned_files} files; "
            f"{len(clients) if isinstance(clients, list) else 0} exact client observations, "
            f"{len(client_uncertainties) if isinstance(client_uncertainties, list) else 0} "
            "uncertain client calls, "
            f"{exact_deployments} exact and "
            f"{len(deployment_rows) - exact_deployments} uncertain deployment observations, "
            f"{len(matches) if isinstance(matches, list) else 0} explicitly trusted route joins"
        )

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


def register_formatter(
    name: str,
) -> Callable[[type[BaseFormatter]], type[BaseFormatter]]:
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


_OUTPUT_DEFAULTS = {
    "show_confidence": True,
    "show_dependency_chain": False,
    "colorize": True,
    "verbose": False,
}


def get_formatter(
    name: str, output_config: "OutputConfig | Mapping[str, object] | None" = None
) -> BaseFormatter:
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
    from fastapi_endpoint_detector.output import (  # noqa: F401, PLC0415
        html_output,
        json_output,
        markdown_output,
        text_output,
        yaml_output,
    )

    if name not in _FORMATTERS:
        available = ", ".join(_FORMATTERS.keys())
        raise ValueError(f"Unknown formatter: {name}. Available: {available}")

    formatter_type = _FORMATTERS[name]
    if output_config is None:
        return formatter_type()

    if isinstance(output_config, Mapping):
        unknown = set(output_config) - set(_OUTPUT_DEFAULTS)
        if unknown:
            option = sorted(unknown)[0]
            raise ValueError(f"Unknown output option '{option}' for formatter '{name}'")
        options = {**_OUTPUT_DEFAULTS, **output_config}
    else:
        options = {
            key: getattr(output_config, key, default) for key, default in _OUTPUT_DEFAULTS.items()
        }

    for option, value in options.items():
        if type(value) is not bool:
            raise ValueError(
                f"Output option '{option}' for formatter '{name}' must be a bool; "
                f"received {type(value).__name__}"
            )

    unsupported = {
        "json": {key for key, value in options.items() if value != _OUTPUT_DEFAULTS[key]},
        "yaml": {key for key, value in options.items() if value != _OUTPUT_DEFAULTS[key]},
    }
    if unsupported.get(name):
        option = sorted(unsupported[name])[0]
        raise ValueError(
            f"Output option '{option}' cannot be applied to '{name}' format; "
            "structured output preserves the complete report schema"
        )
    if name != "text" and options["colorize"] is False:
        raise ValueError("Output option 'colorize' is only supported by 'text' format")

    if name in {"json", "yaml"}:
        return formatter_type()

    configured_formatter = cast("Callable[..., BaseFormatter]", formatter_type)
    return configured_formatter(
        show_confidence=options["show_confidence"],
        show_dependency_chain=options["show_dependency_chain"],
        colorize=options["colorize"],
        verbose=options["verbose"],
    )
