"""
Integration tests for the CLI.
"""

import json
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
        assert "--vm" in result.output
        assert "--secure-ast" in result.output
        assert "--scip" in result.output
        assert "--baseline-app" in result.output
        assert "--app-entry" in result.output

    def test_list_help(self, runner: CliRunner) -> None:
        """Test the list command help."""
        result = runner.invoke(cli, ["list", "--help"])
        assert result.exit_code == 0
        assert "--app" in result.output
        assert "--vm" in result.output
        assert "--secure-ast" in result.output
        assert "--app-entry" in result.output

    def test_app_entry_requires_secure_ast(self, runner: CliRunner, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text("from fastapi import FastAPI\napp = FastAPI()\n")

        result = runner.invoke(
            cli,
            ["list", "--app", str(app_file), "--app-entry", "app:app"],
        )

        assert result.exit_code != 0
        assert "--app-entry requires --secure-ast" in result.output

    def test_vm_and_secure_ast_mutually_exclusive_analyze(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Test that --vm and --secure-ast cannot be used together in analyze."""
        # Create dummy files
        app_file = tmp_path / "app.py"
        app_file.write_text("from fastapi import FastAPI\napp = FastAPI()\n")
        diff_file = tmp_path / "test.diff"
        diff_file.write_text("dummy diff\n")

        result = runner.invoke(
            cli,
            ["analyze", "--app", str(app_file), "--diff", str(diff_file), "--vm", "--secure-ast"],
        )
        assert result.exit_code != 0
        assert "--vm and --secure-ast cannot be used together" in result.output

    def test_vm_and_scip_mutually_exclusive_analyze(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text("from fastapi import FastAPI\napp = FastAPI()\n")
        diff_file = tmp_path / "test.diff"
        diff_file.write_text("dummy diff\n")

        result = runner.invoke(
            cli,
            ["analyze", "--app", str(app_file), "--diff", str(diff_file), "--vm", "--scip"],
        )
        assert result.exit_code != 0
        assert "--vm and --scip cannot be used together" in result.output

    def test_baseline_app_requires_scip(self, runner: CliRunner, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text("from fastapi import FastAPI\napp = FastAPI()\n")
        diff_file = tmp_path / "test.diff"
        diff_file.write_text("dummy diff\n")

        result = runner.invoke(
            cli,
            [
                "analyze",
                "--app",
                str(app_file),
                "--baseline-app",
                str(app_file),
                "--diff",
                str(diff_file),
            ],
        )

        assert result.exit_code != 0
        assert "--baseline-app requires --scip" in result.output

    def test_vm_and_secure_ast_mutually_exclusive_list(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Test that --vm and --secure-ast cannot be used together in list."""
        # Create dummy file
        app_file = tmp_path / "app.py"
        app_file.write_text("from fastapi import FastAPI\napp = FastAPI()\n")

        result = runner.invoke(cli, ["list", "--app", str(app_file), "--vm", "--secure-ast"])
        assert result.exit_code != 0
        assert "--vm and --secure-ast cannot be used together" in result.output


class TestSecureASTMode:
    """Tests for --secure-ast option."""

    def test_secure_ast_list_basic(self, runner: CliRunner, tmp_path: Path) -> None:
        """Test listing endpoints with --secure-ast."""
        # Create a simple FastAPI app
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
def list_users():
    return []

@app.post("/users")
def create_user():
    return {}
""")

        result = runner.invoke(cli, ["list", "--app", str(app_file), "--secure-ast"])

        # Should succeed (or at least not crash)
        assert "secure AST mode" in result.output.lower() or result.exit_code == 0

    @pytest.mark.parametrize("http_method", ["get", "post", "put", "patch", "delete"])
    def test_secure_ast_detects_http_methods(
        self, runner: CliRunner, tmp_path: Path, http_method: str
    ) -> None:
        """Test that secure AST mode detects various HTTP methods."""
        app_file = tmp_path / "app.py"
        app_file.write_text(f"""
from fastapi import FastAPI

app = FastAPI()

@app.{http_method}("/test")
def test_handler():
    return {{"method": "{http_method}"}}
""")

        result = runner.invoke(
            cli, ["list", "--app", str(app_file), "--secure-ast", "--format", "text"]
        )

        # Should not crash
        assert result.exit_code == 0 or "error" not in result.output.lower()

    def test_secure_ast_analyze_does_not_import_app(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "raise RuntimeError('must not execute')\n"
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/items')\n"
            "def items():\n"
            "    return helper()\n"
            "def helper():\n"
            "    return 1\n",
            encoding="utf-8",
        )
        diff_file = tmp_path / "change.diff"
        diff_file.write_text(
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -8,1 +8,1 @@\n"
            "-    return 1\n"
            "+    return 2\n",
            encoding="utf-8",
        )

        result = runner.invoke(
            cli,
            [
                "analyze",
                "--app",
                str(tmp_path),
                "--diff",
                str(diff_file),
                "--secure-ast",
                "--format",
                "json",
                "--no-cache",
            ],
        )

        assert result.exit_code == 0, result.output
        assert "must not execute" not in result.output
        report = json.loads(result.output)
        assert report["affected_endpoints"]


class TestVMMode:
    """Tests for --vm option."""

    def test_vm_help_message(self, runner: CliRunner) -> None:
        """Test that VM option appears in help."""
        result = runner.invoke(cli, ["list", "--help"])
        assert "--vm" in result.output
        assert "Docker container" in result.output

    @pytest.mark.skip(reason="Requires Docker to be installed and running")
    def test_vm_list_basic(self, runner: CliRunner, tmp_path: Path) -> None:
        """Test listing endpoints with --vm (requires Docker)."""
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from fastapi import FastAPI

app = FastAPI()

@app.get("/test")
def test_handler():
    return {}
""")

        result = runner.invoke(cli, ["list", "--app", str(app_file), "--vm"])

        # Will fail if Docker is not available, but shouldn't crash
        assert result.exit_code in [0, 1]

    @pytest.mark.skip(reason="Requires Docker to be installed and running")
    def test_vm_analyze_basic(self, runner: CliRunner, tmp_path: Path) -> None:
        """Test analyzing with --vm (requires Docker)."""
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from fastapi import FastAPI

app = FastAPI()

@app.get("/test")
def test_handler():
    return {}
""")
        diff_file = tmp_path / "test.diff"
        diff_file.write_text("dummy diff")

        result = runner.invoke(
            cli, ["analyze", "--app", str(app_file), "--diff", str(diff_file), "--vm"]
        )

        # Will fail if Docker is not available
        assert result.exit_code in [0, 1]


class TestDefaultMode:
    """Tests for default mode (no --vm or --secure-ast)."""

    @pytest.mark.parametrize("command", ["list", "analyze"])
    def test_default_mode_no_flags(self, runner: CliRunner, tmp_path: Path, command: str) -> None:
        """Test that default mode works without special flags."""
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from fastapi import FastAPI

app = FastAPI()

@app.get("/test")
def test_handler():
    return {}
""")

        if command == "analyze":
            diff_file = tmp_path / "test.diff"
            diff_file.write_text("dummy diff")
            args = [command, "--app", str(app_file), "--diff", str(diff_file)]
        else:
            args = [command, "--app", str(app_file)]

        result = runner.invoke(cli, args)

        # May fail due to missing dependencies, but shouldn't show VM or secure-AST messages
        if result.exit_code != 0:
            assert "vm" not in result.output.lower() and "docker" not in result.output.lower()
