"""
Configuration loading and validation for FastAPI Endpoint Change Detector.

This module handles configuration file parsing, validation, and provides
sensible defaults for all configuration options.
"""

from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator

from fastapi_endpoint_detector.analyzer.source_inventory import (
    SourceInventory,
    build_source_inventory,
)
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


def _validate_observation_patterns(patterns: list[str]) -> list[str]:  # noqa: PLR0912
    """Accept only bounded, root-relative glob patterns understood by Path.glob."""
    if len(patterns) > 128:
        raise ValueError("route observation pattern lists may contain at most 128 entries")
    seen: set[str] = set()
    for pattern in patterns:
        if not pattern or pattern != pattern.strip() or len(pattern) > 512:
            raise ValueError("route observation patterns must be non-empty strings up to 512 chars")
        if "\x00" in pattern or "\\" in pattern:
            raise ValueError("route observation patterns must use relative POSIX glob syntax")
        posix = PurePosixPath(pattern)
        windows = PureWindowsPath(pattern)
        if posix.is_absolute() or windows.is_absolute() or windows.drive:
            raise ValueError("route observation patterns must be relative to the application root")
        if any(part in {".", ".."} for part in pattern.split("/")):
            raise ValueError(
                "route observation patterns cannot traverse outside the application root"
            )
        if "{" in pattern or "}" in pattern:
            raise ValueError("route observation patterns do not support brace expansion")
        in_class = False
        class_has_content = False
        for char in pattern:
            if char == "[":
                if in_class:
                    raise ValueError("route observation pattern has an invalid character class")
                in_class = True
                class_has_content = False
            elif char == "]":
                if not in_class or not class_has_content:
                    raise ValueError("route observation pattern has an invalid character class")
                in_class = False
            elif in_class:
                class_has_content = True
        if in_class:
            raise ValueError("route observation pattern has an unterminated character class")
        if pattern in seen:
            raise ValueError(f"duplicate route observation pattern: {pattern}")
        seen.add(pattern)
    return patterns


def _normalize_observation_origin(origin: str) -> str:
    """Validate and canonicalize an explicitly configured HTTP/WebSocket origin."""
    if not origin or origin != origin.strip() or any(char.isspace() for char in origin):
        raise ValueError("trusted server origins must be explicit URL origins")
    try:
        parsed = urlsplit(origin)
        # Accessing .port validates malformed and out-of-range ports.
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid trusted server origin {origin!r}: {exc}") from exc
    if (
        parsed.scheme.lower() not in {"http", "https", "ws", "wss"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.netloc.endswith(":")
        or parsed.path not in {"", "/"}
        or "?" in origin
        or "#" in origin
    ):
        raise ValueError(
            "trusted server origins must contain only an http(s) or ws(s) scheme and authority"
        )
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


class RouteObservationConfig(BaseModel):
    """Opt-in bounded extraction of client and deployment route observations."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(
        default=False,
        strict=True,
        description="Include bounded source route observations in analyze output.",
    )
    client_include_patterns: list[str] = Field(
        default=["**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", "**/*.svelte"],
        description="Application-root-relative globs for client source files.",
    )
    deployment_include_patterns: list[str] = Field(
        default=[
            ".env",
            ".env.*",
            "**/.env",
            "**/.env.*",
            "**/Dockerfile*",
            "**/*.Dockerfile",
            "**/*.py",
        ],
        description="Application-root-relative globs for deployment observation files.",
    )
    max_files: int = Field(
        default=256,
        strict=True,
        ge=1,
        le=10_000,
        description="Maximum number of files read across both observation categories.",
    )
    max_file_bytes: int = Field(
        default=262_144,
        strict=True,
        ge=1,
        le=16 * 1024 * 1024,
        description="Maximum bytes read from any one observation source file.",
    )
    trusted_server_origins: dict[str, str] = Field(
        default_factory=dict,
        description="Explicit established server surface IDs mapped to trusted URL origins.",
    )

    @field_validator("client_include_patterns", "deployment_include_patterns", mode="before")
    @classmethod
    def validate_pattern_list_input(cls, value: object) -> object:
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError("route observation include patterns must be a list of strings")
        return value

    @field_validator("client_include_patterns", "deployment_include_patterns")
    @classmethod
    def validate_pattern_list(cls, value: list[str]) -> list[str]:
        return _validate_observation_patterns(value)

    @field_validator("trusted_server_origins", mode="before")
    @classmethod
    def validate_trusted_origin_mapping_input(cls, value: object) -> object:
        if not isinstance(value, dict):
            raise ValueError("trusted_server_origins must be a mapping of surface IDs to origins")
        if len(value) > 4096:
            raise ValueError("trusted_server_origins may contain at most 4096 surface IDs")
        if any(
            not isinstance(key, str) or not isinstance(origin, str) for key, origin in value.items()
        ):
            raise ValueError("trusted_server_origins keys and values must be strings")
        return value

    @field_validator("trusted_server_origins")
    @classmethod
    def validate_trusted_origin_mapping(cls, value: dict[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for surface_id, origin in value.items():
            if (
                not surface_id
                or surface_id != surface_id.strip()
                or len(surface_id) > 2048
                or "\x00" in surface_id
            ):
                raise ValueError("trusted server surface IDs must be non-empty exact identifiers")
            normalized[surface_id] = _normalize_observation_origin(origin)
        return normalized


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
    sql_transaction_ordered_paths: bool = Field(
        default=False,
        description="Emit bounded same-scope lexical SQL stage-to-boundary diagnostics.",
    )
    sql_transaction_path_max_pairs: int = Field(
        default=1024,
        ge=1,
        le=10_000,
        description="Atomic pair limit for ordered SQL transaction path analysis.",
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
    route_observations: RouteObservationConfig = Field(default_factory=RouteObservationConfig)

    @model_validator(mode="after")
    def validate_contract_sources(self) -> "AnalysisConfig":
        if self.effect_contracts is not None and self.effect_preset is not None:
            raise ValueError("effect_contracts and effect_preset are mutually exclusive")
        has_effect_source = self.effect_contracts is not None or self.effect_preset is not None
        if self.sql_transaction_diagnostics and not has_effect_source:
            raise ValueError(
                "sql_transaction_diagnostics requires effect_contracts or effect_preset"
            )
        if self.sql_transaction_ordered_paths and not self.sql_transaction_diagnostics:
            raise ValueError("sql_transaction_ordered_paths requires sql_transaction_diagnostics")
        if self.resource_coupling is not None and not has_effect_source:
            raise ValueError("resource_coupling requires effect_contracts or effect_preset")
        if self.surface_contracts is not None and self.surface_preset is not None:
            raise ValueError("surface_contracts and surface_preset are mutually exclusive")
        route_observations = self.route_observations
        if (
            route_observations.enabled
            and not route_observations.client_include_patterns
            and not route_observations.deployment_include_patterns
        ):
            raise ValueError(
                "route_observations requires at least one client or deployment include pattern"
            )
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

    @model_validator(mode="after")
    def validate_typed_integration(self) -> "Config":
        if self.integrations.mypy_config is not None:
            raise ValueError(
                "integrations.mypy_config is not supported by the current mypy analyzer; "
                "remove it rather than relying on an ignored configuration path"
            )
        return self

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

    def source_inventory(self, source: Path) -> SourceInventory:
        """Return the canonical configured inventory for one source snapshot."""
        excludes = self.parser.exclude_patterns
        if self.analysis.include_test_endpoints:
            excludes = [
                p for p in excludes if p not in {"**/test_*.py", "**/*_test.py", "**/tests/**"}
            ]
        return build_source_inventory(
            source,
            include_patterns=tuple(self.parser.include_patterns),
            exclude_patterns=tuple(excludes),
            follow_imports=self.parser.follow_imports,
            max_depth=self.parser.max_depth,
        )


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
