"""
Configuration loading and validation for FastAPI Endpoint Change Detector.

This module handles configuration file parsing, validation, and provides
sensible defaults for all configuration options.
"""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

from fastapi_endpoint_detector.models.effect_contract import (
    LoadedEffectContracts,
    load_effect_contracts,
    load_effect_preset,
)
from fastapi_endpoint_detector.models.resource_coupling import (
    LoadedResourceCoupling,
    load_resource_coupling,
)
from fastapi_endpoint_detector.models.surface_contract import (
    LoadedSurfaceContracts,
    load_surface_contracts,
    load_surface_preset,
)
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
    effect_preset: (
        Literal[
            "filesystem-v1",
            "http-clients-v1",
            "mongodb-v1",
            "object-storage-v1",
            "redis-v1",
            "sqlalchemy-v1",
        ]
        | None
    ) = Field(
        default=None,
        description="Named package-owned exact effect-contract preset.",
    )
    sql_transaction_diagnostics: bool = Field(
        default=False,
        description="Emit conservative report-only SQL staging/transaction diagnostics.",
    )
    resource_coupling: Path | None = Field(
        default=None,
        description="Path to strict report-only finite resource coupling configuration.",
    )
    surface_contracts: Path | None = Field(
        default=None,
        description="Path to strict data-only custom-surface contracts.",
    )
    surface_preset: Literal["event-listeners-v1", "mcp-v1", "workers-v1", "framework-v1"] | None = (
        Field(
            default=None,
            description="Named package-owned custom-surface adapter preset.",
        )
    )

    @model_validator(mode="after")
    def validate_contract_sources(self) -> "AnalysisConfig":
        if self.effect_contracts is not None and self.effect_preset is not None:
            raise ValueError("effect_contracts and effect_preset are mutually exclusive")
        has_effect_source = self.effect_contracts is not None or self.effect_preset is not None
        if self.sql_transaction_diagnostics and not has_effect_source:
            raise ValueError(
                "sql_transaction_diagnostics requires effect_contracts or effect_preset"
            )
        if self.resource_coupling is not None and not has_effect_source:
            raise ValueError("resource_coupling requires effect_contracts or effect_preset")
        if self.surface_contracts is not None and self.surface_preset is not None:
            raise ValueError("surface_contracts and surface_preset are mutually exclusive")
        return self


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

    _effect_contract_snapshot: LoadedEffectContracts | None = PrivateAttr(default=None)
    _resource_coupling_snapshot: LoadedResourceCoupling | None = PrivateAttr(default=None)
    _surface_contract_snapshot: LoadedSurfaceContracts | None = PrivateAttr(default=None)

    parser: ParserConfig = Field(default_factory=ParserConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    integrations: IntegrationConfig = Field(default_factory=IntegrationConfig)

    def load_surface_contract_snapshot(self) -> LoadedSurfaceContracts | None:
        """Load configured custom surfaces once to prevent analysis-time drift."""
        path = self.analysis.surface_contracts
        preset = self.analysis.surface_preset
        if path is None and preset is None:
            return None
        if self._surface_contract_snapshot is None:
            self._surface_contract_snapshot = (
                load_surface_contracts(path)
                if path is not None
                else load_surface_preset(preset or "")
            )
        return self._surface_contract_snapshot

    def load_resource_coupling_snapshot(self) -> LoadedResourceCoupling | None:
        """Load report-only coupling configuration once to prevent analysis-time drift."""
        path = self.analysis.resource_coupling
        if path is None:
            return None
        if self._resource_coupling_snapshot is None:
            self._resource_coupling_snapshot = load_resource_coupling(path)
        return self._resource_coupling_snapshot

    def load_effect_contract_snapshot(self) -> LoadedEffectContracts | None:
        """Load configured contract bytes once for validation and later analysis."""
        path = self.analysis.effect_contracts
        preset = self.analysis.effect_preset
        if path is None and preset is None:
            return None
        if self._effect_contract_snapshot is None:
            self._effect_contract_snapshot = (
                load_effect_contracts(path)
                if path is not None
                else load_effect_preset(preset or "")
            )
        return self._effect_contract_snapshot


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
        effect_path = config.analysis.effect_contracts
        resource_coupling_path = config.analysis.resource_coupling
        surface_path = config.analysis.surface_contracts
        updates: dict[str, Path] = {}
        for field_name, configured_path in (
            ("effect_contracts", effect_path),
            ("resource_coupling", resource_coupling_path),
            ("surface_contracts", surface_path),
        ):
            if configured_path is None:
                continue
            resolved_path = configured_path
            if not resolved_path.is_absolute():
                resolved_path = config_path.resolve().parent / resolved_path
            updates[field_name] = resolved_path.resolve()
        if updates:
            config = config.model_copy(
                update={"analysis": config.analysis.model_copy(update=updates)}
            )
        config.load_effect_contract_snapshot()
        config.load_resource_coupling_snapshot()
        config.load_surface_contract_snapshot()
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
