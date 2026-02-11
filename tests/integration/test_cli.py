"""
Integration tests for the CLI.
"""

from pathlib import Path

import pytest
from click.testing import CliRunner

from fastapi_endpoint_detector.cli import cli


@pytest.fixture
def runner() -> CliRunner:
    """Create a CLI test runner."""
    return CliRunner()


class TestCLI:
    """Integration tests for the CLI."""
    
    def test_version(self, runner: CliRunner) -> None:
        """Test the version option."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "fastapi-endpoint-detector" in result.output
    
    def test_help(self, runner: CliRunner) -> None:
        """Test the help option."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "FastAPI Endpoint Change Detector" in result.output
    
    def test_analyze_help(self, runner: CliRunner) -> None:
        """Test the analyze command help."""
        result = runner.invoke(cli, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "--app" in result.output
        assert "--diff" in result.output
    
    def test_list_help(self, runner: CliRunner) -> None:
        """Test the list command help."""
        result = runner.invoke(cli, ["list", "--help"])
        assert result.exit_code == 0
        assert "--app" in result.output
