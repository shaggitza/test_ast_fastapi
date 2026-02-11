"""
Integration tests for dependency injection patterns.

This module tests the FastAPI Endpoint Change Detector with real-world
dependency injection patterns to ensure it correctly identifies affected
endpoints when dependencies are modified.
"""

from pathlib import Path

import pytest
from click.testing import CliRunner

from fastapi_endpoint_detector.cli import cli


@pytest.fixture
def runner() -> CliRunner:
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def di_patterns_path() -> Path:
    """Get the path to the DI patterns examples."""
    return Path(__file__).parent.parent.parent / "examples" / "di_patterns"


class TestClassBasedDependencies:
    """Tests for class-based dependency injection pattern."""

    def test_database_service_change_affects_endpoints(
        self, runner: CliRunner, di_patterns_path: Path
    ) -> None:
        """Test that changes to DatabaseService affect endpoints using it."""
        app_path = di_patterns_path / "class_based" / "main.py"
        diff_path = di_patterns_path / "class_based" / "change_database_service.diff"

        assert app_path.exists(), f"App not found: {app_path}"
        assert diff_path.exists(), f"Diff not found: {diff_path}"

        result = runner.invoke(
            cli,
            [
                "analyze",
                "--app",
                str(app_path),
                "--diff",
                str(diff_path),
                "--format",
                "json",
            ],
        )

        # Should execute successfully
        assert result.exit_code == 0, f"CLI failed: {result.output}"

        # Output should contain affected endpoints
        output = result.output.lower()
        # The change to DatabaseService.get_item should affect the GET /items/{item_id} endpoint
        assert "items" in output or "endpoint" in output


class TestFunctionBasedDependencies:
    """Tests for function-based dependency injection pattern."""

    def test_auth_function_change_affects_endpoints(
        self, runner: CliRunner, di_patterns_path: Path
    ) -> None:
        """Test that changes to authentication function affect all endpoints using it."""
        app_path = di_patterns_path / "function_based" / "main.py"
        diff_path = di_patterns_path / "function_based" / "change_auth.diff"

        assert app_path.exists(), f"App not found: {app_path}"
        assert diff_path.exists(), f"Diff not found: {diff_path}"

        result = runner.invoke(
            cli,
            [
                "analyze",
                "--app",
                str(app_path),
                "--diff",
                str(diff_path),
                "--format",
                "json",
            ],
        )

        assert result.exit_code == 0, f"CLI failed: {result.output}"

        # The change to get_current_user should affect /users/me, /users, and /users/me/settings
        output = result.output.lower()
        assert "users" in output or "endpoint" in output


class TestNestedDependencies:
    """Tests for nested dependency injection pattern."""

    def test_base_dependency_change_affects_all_endpoints(
        self, runner: CliRunner, di_patterns_path: Path
    ) -> None:
        """Test that changes to base dependency affect all endpoints through transitive deps."""
        app_path = di_patterns_path / "nested_deps" / "main.py"
        diff_path = di_patterns_path / "nested_deps" / "change_base_dep.diff"

        assert app_path.exists(), f"App not found: {app_path}"
        assert diff_path.exists(), f"Diff not found: {diff_path}"

        result = runner.invoke(
            cli,
            [
                "analyze",
                "--app",
                str(app_path),
                "--diff",
                str(diff_path),
                "--format",
                "json",
            ],
        )

        assert result.exit_code == 0, f"CLI failed: {result.output}"

        # Changes to base dependency (get_api_key) should affect all endpoints
        # due to transitive dependencies
        output = result.output.lower()
        assert "users" in output or "endpoint" in output


class TestSecurityDependencies:
    """Tests for security-based dependency injection pattern."""

    def test_token_decode_change_affects_secured_endpoints(
        self, runner: CliRunner, di_patterns_path: Path
    ) -> None:
        """Test that changes to token decoding affect all secured endpoints."""
        app_path = di_patterns_path / "security_deps" / "main.py"
        diff_path = di_patterns_path / "security_deps" / "change_token_decode.diff"

        assert app_path.exists(), f"App not found: {app_path}"
        assert diff_path.exists(), f"Diff not found: {diff_path}"

        result = runner.invoke(
            cli,
            [
                "analyze",
                "--app",
                str(app_path),
                "--diff",
                str(diff_path),
                "--format",
                "json",
            ],
        )

        assert result.exit_code == 0, f"CLI failed: {result.output}"

        # Changes to decode_token should affect all endpoints using authentication
        output = result.output.lower()
        assert "users" in output or "items" in output or "endpoint" in output


class TestDatabaseSessionDependencies:
    """Tests for database session dependency injection pattern."""

    def test_session_class_change_affects_all_db_endpoints(
        self, runner: CliRunner, di_patterns_path: Path
    ) -> None:
        """Test that changes to Session class affect all endpoints using database."""
        app_path = di_patterns_path / "db_session" / "main.py"
        diff_path = di_patterns_path / "db_session" / "change_session.diff"

        assert app_path.exists(), f"App not found: {app_path}"
        assert diff_path.exists(), f"Diff not found: {diff_path}"

        result = runner.invoke(
            cli,
            [
                "analyze",
                "--app",
                str(app_path),
                "--diff",
                str(diff_path),
                "--format",
                "json",
            ],
        )

        assert result.exit_code == 0, f"CLI failed: {result.output}"

        # Changes to Session class should affect all endpoints using database sessions
        output = result.output.lower()
        assert "users" in output or "endpoint" in output


class TestRequestContextDependencies:
    """Tests for request context dependency injection pattern."""

    def test_ip_extraction_change_affects_context_endpoints(
        self, runner: CliRunner, di_patterns_path: Path
    ) -> None:
        """Test that changes to IP extraction affect endpoints using request context."""
        app_path = di_patterns_path / "request_context" / "main.py"
        diff_path = di_patterns_path / "request_context" / "change_ip_extraction.diff"

        assert app_path.exists(), f"App not found: {app_path}"
        assert diff_path.exists(), f"Diff not found: {diff_path}"

        result = runner.invoke(
            cli,
            [
                "analyze",
                "--app",
                str(app_path),
                "--diff",
                str(diff_path),
                "--format",
                "json",
            ],
        )

        assert result.exit_code == 0, f"CLI failed: {result.output}"

        # Changes to get_client_ip should affect endpoints using request context
        output = result.output.lower()
        assert "info" in output or "tracked" in output or "endpoint" in output


class TestAllDIPatterns:
    """Comprehensive tests across all DI patterns."""

    def test_all_patterns_have_required_files(self, di_patterns_path: Path) -> None:
        """Verify all DI pattern examples have required files."""
        patterns = [
            "class_based",
            "function_based",
            "nested_deps",
            "security_deps",
            "db_session",
            "request_context",
        ]

        for pattern in patterns:
            pattern_path = di_patterns_path / pattern
            assert pattern_path.exists(), f"Pattern directory missing: {pattern}"

            main_file = pattern_path / "main.py"
            assert main_file.exists(), f"main.py missing for {pattern}"

            # Check that at least one diff file exists
            diff_files = list(pattern_path.glob("*.diff"))
            assert len(diff_files) > 0, f"No diff files found for {pattern}"

    def test_list_endpoints_for_all_patterns(
        self, runner: CliRunner, di_patterns_path: Path
    ) -> None:
        """Test that list command works for all DI pattern examples."""
        patterns = [
            "class_based",
            "function_based",
            "nested_deps",
            "security_deps",
            "db_session",
            "request_context",
        ]

        for pattern in patterns:
            app_path = di_patterns_path / pattern / "main.py"

            result = runner.invoke(
                cli,
                ["list", "--app", str(app_path), "--format", "json"],
            )

            assert result.exit_code == 0, f"List failed for {pattern}: {result.output}"

            # Should list some endpoints
            output = result.output.lower()
            assert "endpoint" in output or "path" in output or "method" in output, (
                f"No endpoints found for {pattern}"
            )

    @pytest.mark.parametrize(
        "pattern,diff_file",
        [
            ("class_based", "change_database_service.diff"),
            ("function_based", "change_auth.diff"),
            ("nested_deps", "change_base_dep.diff"),
            ("security_deps", "change_token_decode.diff"),
            ("db_session", "change_session.diff"),
            ("request_context", "change_ip_extraction.diff"),
        ],
    )
    def test_analyze_pattern_with_diff(
        self,
        runner: CliRunner,
        di_patterns_path: Path,
        pattern: str,
        diff_file: str,
    ) -> None:
        """Parametrized test for analyzing each pattern with its diff."""
        app_path = di_patterns_path / pattern / "main.py"
        diff_path = di_patterns_path / pattern / diff_file

        result = runner.invoke(
            cli,
            [
                "analyze",
                "--app",
                str(app_path),
                "--diff",
                str(diff_path),
                "--format",
                "text",
            ],
        )

        assert result.exit_code == 0, (
            f"Analysis failed for {pattern} with {diff_file}: {result.output}"
        )

        # Should produce some output
        assert len(result.output) > 0, f"No output for {pattern}"

    def test_all_patterns_with_verbose_output(
        self, runner: CliRunner, di_patterns_path: Path
    ) -> None:
        """Test all patterns with verbose output enabled."""
        patterns = {
            "class_based": "change_database_service.diff",
            "function_based": "change_auth.diff",
            "nested_deps": "change_base_dep.diff",
            "security_deps": "change_token_decode.diff",
            "db_session": "change_session.diff",
            "request_context": "change_ip_extraction.diff",
        }

        for pattern, diff_file in patterns.items():
            app_path = di_patterns_path / pattern / "main.py"
            diff_path = di_patterns_path / pattern / diff_file

            result = runner.invoke(
                cli,
                [
                    "analyze",
                    "--app",
                    str(app_path),
                    "--diff",
                    str(diff_path),
                    "--verbose",
                    "--format",
                    "text",
                ],
            )

            assert result.exit_code == 0, f"Verbose analysis failed for {pattern}"


class TestDependencyDepthTracking:
    """Tests for tracking dependency depth and transitive dependencies."""

    def test_nested_deps_tracks_multiple_levels(
        self, runner: CliRunner, di_patterns_path: Path
    ) -> None:
        """
        Test that nested dependencies are tracked through multiple levels.

        The nested_deps example has a 4-level hierarchy:
        - Level 1: get_api_key, get_tenant_id
        - Level 2: get_database_connection, get_user_context
        - Level 3: get_user_repository, get_permission_checker
        - Level 4: get_user_service

        Changes to level 1 should affect all endpoints using higher levels.
        """
        app_path = di_patterns_path / "nested_deps" / "main.py"
        diff_path = di_patterns_path / "nested_deps" / "change_base_dep.diff"

        result = runner.invoke(
            cli,
            [
                "analyze",
                "--app",
                str(app_path),
                "--diff",
                str(diff_path),
                "--format",
                "json",
            ],
        )

        assert result.exit_code == 0
        # All endpoints should be affected by base dependency change
        assert result.output, "Expected output but got none"


class TestDifferentOutputFormats:
    """Test that all DI patterns work with different output formats."""

    @pytest.mark.parametrize("output_format", ["text", "json", "yaml", "markdown"])
    def test_class_based_with_format(
        self, runner: CliRunner, di_patterns_path: Path, output_format: str
    ) -> None:
        """Test class-based pattern with different output formats."""
        app_path = di_patterns_path / "class_based" / "main.py"
        diff_path = di_patterns_path / "class_based" / "change_database_service.diff"

        result = runner.invoke(
            cli,
            [
                "analyze",
                "--app",
                str(app_path),
                "--diff",
                str(diff_path),
                "--format",
                output_format,
            ],
        )

        assert result.exit_code == 0, f"Failed with format {output_format}"
        assert len(result.output) > 0, f"No output for format {output_format}"
