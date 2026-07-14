"""
Configuration loading and validation for FastAPI Endpoint Change Detector.

This module handles configuration file parsing, validation, and provides
sensible defaults for all configuration options.
"""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from fastapi_endpoint_detector.models.effect_contract import load_effect_contracts
from fastapi_endpoint_detector.strict_data import load_yaml_unique


class ParserConfig(BaseModel):
    """Configuration for the code parser."""

    model_config = ConfigDict(extra="forbid")

    include_patterns: list[str] = Field(
        default=["**/*.py"],
        description="Glob patterns for files to include in analysis.",
    )
    exclude_patterns: list[str] = Field(
        default=["**/test_*.py", "**/*_test.py", "**/tests/**", "**/__pycache__/**"],
        description="Glob patterns for files to exclude from analysis.",
    )
    follow_imports: bool = Field(
        default=True,
        description="Whether to follow and analyze imported modules.",
    )
    max_depth: int = Field(
        default=10,
        ge=1,
        description="Maximum depth for dependency traversal.",
    )


class AnalysisConfig(BaseModel):
    """Configuration for the analysis engine."""

    model_config = ConfigDict(extra="forbid")

    track_transitive: bool = Field(
        default=True,
        description="Track transitive (indirect) dependencies.",
    )
    confidence_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description=(
            "Legacy presentation threshold for affected_endpoints; all reachable results "
            "remain available in candidate_endpoints."
        ),
    )
    include_test_endpoints: bool = Field(
        default=False,
        description="Include test endpoints in analysis.",
    )
    effect_contracts: Path | None = Field(
        default=None,
        description="Path to a strict versioned effect-contract document.",
    )


class OutputConfig(BaseModel):
    """Configuration for output formatting."""

    model_config = ConfigDict(extra="forbid")

    show_confidence: bool = Field(
        default=True,
        description="Show confidence scores in output.",
    )
    show_dependency_chain: bool = Field(
        default=False,
        description="Show full dependency chain for each affected endpoint.",
    )
    colorize: bool = Field(
        default=True,
        description="Use colors in terminal output.",
    )
    verbose: bool = Field(
        default=False,
        description="Enable verbose output.",
    )


class IntegrationConfig(BaseModel):
    """Configuration for external tool integrations."""

    model_config = ConfigDict(extra="forbid")

    use_mypy: bool = Field(
        default=True,
        description="Use mypy for type-aware analysis.",
    )
    mypy_config: Path | None = Field(
        default=None,
        description="Path to mypy configuration file.",
    )


class Config(BaseModel):
    """Root configuration model for FastAPI Endpoint Change Detector."""

    model_config = ConfigDict(extra="forbid")

    parser: ParserConfig = Field(default_factory=ParserConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    integrations: IntegrationConfig = Field(default_factory=IntegrationConfig)


def load_config(config_path: Path | None = None) -> Config:
    """
    Load configuration from a YAML file.

    Args:
        config_path: Path to the configuration file. If None, returns defaults.

    Returns:
        Config object with loaded or default values.

    Raises:
        FileNotFoundError: If the specified config file doesn't exist.
        ValueError: If the config file is invalid.
    """
    if config_path is None:
        return Config()

    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    try:
        data = load_yaml_unique(config_path.read_text(encoding="utf-8")) or {}
        config = Config(**data)
        contracts_path = config.analysis.effect_contracts
        if contracts_path is not None:
            if not contracts_path.is_absolute():
                contracts_path = config_path.resolve().parent / contracts_path
            contracts_path = contracts_path.resolve()
            load_effect_contracts(contracts_path)
            config = config.model_copy(
                update={
                    "analysis": config.analysis.model_copy(
                        update={"effect_contracts": contracts_path}
                    )
                }
            )
        return config
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in configuration file: {e}") from e
    except Exception as e:
        raise ValueError(f"Failed to load configuration: {e}") from e


def find_config_file(start_path: Path) -> Path | None:
    """
    Search for a configuration file starting from the given path.

    Searches for `.endpoint-detector.yaml` or `.endpoint-detector.yml`
    in the start path and parent directories.

    Args:
        start_path: Directory to start searching from.

    Returns:
        Path to the config file if found, None otherwise.
    """
    config_names = [".endpoint-detector.yaml", ".endpoint-detector.yml"]

    current = start_path.resolve()
    while current != current.parent:
        for name in config_names:
            config_path = current / name
            if config_path.exists():
                return config_path
        current = current.parent

    return None
