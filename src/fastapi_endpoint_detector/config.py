"""
Configuration loading and validation for FastAPI Endpoint Change Detector.

This module handles configuration file parsing, validation, and provides
sensible defaults for all configuration options.
"""

from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field


class ParserConfig(BaseModel):
    """Configuration for the code parser."""
    
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
        description="Maximum depth for dependency traversal.",
    )


class AnalysisConfig(BaseModel):
    """Configuration for the analysis engine."""
    
    track_transitive: bool = Field(
        default=True,
        description="Track transitive (indirect) dependencies.",
    )
    confidence_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Minimum confidence level for reporting affected endpoints.",
    )
    include_test_endpoints: bool = Field(
        default=False,
        description="Include test endpoints in analysis.",
    )


class OutputConfig(BaseModel):
    """Configuration for output formatting."""
    
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
    
    use_mypy: bool = Field(
        default=False,
        description="Use mypy for enhanced type analysis.",
    )
    use_ruff: bool = Field(
        default=False,
        description="Use ruff for fast import analysis.",
    )
    mypy_config: Optional[Path] = Field(
        default=None,
        description="Path to mypy configuration file.",
    )


class Config(BaseModel):
    """Root configuration model for FastAPI Endpoint Change Detector."""
    
    parser: ParserConfig = Field(default_factory=ParserConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    integrations: IntegrationConfig = Field(default_factory=IntegrationConfig)
    
    class Config:
        """Pydantic model configuration."""
        
        extra = "forbid"


def load_config(config_path: Optional[Path] = None) -> Config:
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
        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return Config(**data)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in configuration file: {e}") from e
    except Exception as e:
        raise ValueError(f"Failed to load configuration: {e}") from e


def find_config_file(start_path: Path) -> Optional[Path]:
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
