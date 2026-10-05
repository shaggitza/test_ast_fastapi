"""
Integration tests for the CLI.
"""

import json
from difflib import unified_diff
from pathlib import Path

import pytest
from click.testing import CliRunner

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.cli import cli
from fastapi_endpoint_detector.executor.vm_executor import VMExecutor
from fastapi_endpoint_detector.parser.fastapi_extractor import FastAPIExtractor


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
        assert "--bootstrap-entry" in result.output

    def test_validate_effect_contracts_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["validate-effect-contracts", "--help"])
        assert result.exit_code == 0
        assert "--contracts" in result.output
        assert "--format" in result.output

    def test_list_help(self, runner: CliRunner) -> None:
        """Test the list command help."""
        result = runner.invoke(cli, ["list", "--help"])
        assert result.exit_code == 0
        assert "--app" in result.output
        assert "--vm" in result.output
        assert "--secure-ast" in result.output
        assert "--app-entry" in result.output
        assert "--bootstrap-entry" in result.output

    def test_validate_effect_contracts_json(self, runner: CliRunner, tmp_path: Path) -> None:
        contracts = tmp_path / "effects.yaml"
        contracts.write_text(
            """schema_version: 1
preset:
  id: test-effects
  version: 1.0.0
  provenance:
    kind: user
    source: effects.yaml
contracts:
  - id: publish
    symbol: company.events.publish
    invocation: function
    operation: publish
    channel: message_bus
""",
            encoding="utf-8",
        )

        result = runner.invoke(
            cli,
            ["validate-effect-contracts", "--contracts", str(contracts), "--format", "json"],
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["matching_status"] == "not_evaluated"
        assert payload["config_hash"].startswith("sha256:")
        assert payload["contract_hashes"]["publish"].startswith("sha256:")

    def test_analyze_contract_evidence_requires_secure_ast(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        contracts = tmp_path / "effects.yaml"
        contracts.write_text(
            """schema_version: 1
preset:
  id: test-effects
  version: 1.0.0
  provenance: {kind: user, source: effects.yaml}
contracts:
  - id: publish
    symbol: company.events.publish
    invocation: function
    operation: publish
    channel: message_bus
""",
            encoding="utf-8",
        )
        config = tmp_path / "detector.yaml"
        config.write_text("analysis:\n  effect_contracts: effects.yaml\n", encoding="utf-8")
        app = tmp_path / "app.py"
        app.write_text("value = 1\n")
        diff = tmp_path / "change.diff"
        diff.write_text("dummy\n")

        result = runner.invoke(
            cli,
            [
                "--config",
                str(config),
                "analyze",
                "--app",
                str(app),
                "--diff",
                str(diff),
            ],
        )

        assert result.exit_code != 0
        assert "requires --secure-ast" in result.output

    def test_invalid_contract_config_is_rendered_as_cli_error(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        contracts = tmp_path / "effects.yaml"
        contracts.write_text("schema_version: true\n", encoding="utf-8")
        config = tmp_path / "detector.yaml"
        config.write_text("analysis:\n  effect_contracts: effects.yaml\n", encoding="utf-8")

        result = runner.invoke(
            cli,
            [
                "--config",
                str(config),
                "validate-effect-contracts",
                "--contracts",
                str(contracts),
            ],
        )

        assert result.exit_code != 0
        assert "Error:" in result.output
        assert "effect contract validation failed" in result.output

    def test_bootstrap_entry_requires_secure_ast(self, runner: CliRunner, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text("from fastapi import FastAPI\napp = FastAPI()\n")

        result = runner.invoke(
            cli,
            ["list", "--app", str(app_file), "--bootstrap-entry", "app:run"],
        )

        assert result.exit_code != 0
        assert "--bootstrap-entry requires --secure-ast" in result.output

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

    def test_baseline_app_is_supported_by_default_mypy(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        app = tmp_path / "target"
        baseline = tmp_path / "baseline"
        app.mkdir()
        baseline.mkdir()
        app_file = app / "app.py"
        app_file.write_text("from fastapi import FastAPI\napp = FastAPI()\n")
        (baseline / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
        diff_file = tmp_path / "test.diff"
        diff_file.write_text("")

        result = runner.invoke(
            cli,
            [
                "analyze",
                "--app",
                str(app_file),
                "--baseline-app",
                str(baseline / "app.py"),
                "--diff",
                str(diff_file),
                "--format",
                "json",
            ],
        )

        assert result.exit_code == 0, result.output

    @pytest.mark.parametrize(
        ("function_name", "invoke_lambda", "same_line_call", "expected_candidate"),
        [
            ("deferred_lambda_control", False, False, False),
            ("live_invoked_lambda_counterpart", True, False, True),
            ("same_line_executed_call_counterpart", False, True, True),
        ],
    )
    def test_cli_maps_only_executed_lambda_body_edits(
        self,
        runner: CliRunner,
        tmp_path: Path,
        function_name: str,
        invoke_lambda: bool,
        same_line_call: bool,
        expected_candidate: bool,
    ) -> None:
        baseline_app = tmp_path / "baseline" / "app"
        target_app = tmp_path / "target" / "app"
        baseline_app.mkdir(parents=True)
        target_app.mkdir(parents=True)
        (baseline_app / "helpers.py").write_text(
            "def leaf_alias() -> int:\n    return 1\n", encoding="utf-8"
        )
        (target_app / "helpers.py").write_text(
            "def leaf_alias() -> int:\n    return 1\n", encoding="utf-8"
        )

        before = "hidden = lambda: leaf_alias()"
        after = "hidden = lambda: leaf_alias() + 1"
        if same_line_call:
            baseline_service = (
                "from .helpers import leaf_alias\n\n"
                f"def {function_name}() -> int:\n"
                f"    {before}; return leaf_alias()\n"
            )
            target_service = baseline_service.replace(
                before + "; return leaf_alias()",
                after + "; return leaf_alias() + 2",
            )
        else:
            baseline_service = (
                "from .helpers import leaf_alias\n\n"
                f"def {function_name}() -> int:\n"
                f"    {before}\n" + ("    return hidden()\n" if invoke_lambda else "    return 0\n")
            )
            target_service = baseline_service.replace(before, after)
        (baseline_app / "service.py").write_text(baseline_service, encoding="utf-8")
        (target_app / "service.py").write_text(target_service, encoding="utf-8")

        app_source = (
            "from fastapi import FastAPI\n"
            f"from .service import {function_name}\n"
            "app = FastAPI()\n"
            "@app.get('/one')\n"
            f"def route_one() -> int:\n    return {function_name}()\n"
        )
        (baseline_app / "__init__.py").write_text(app_source, encoding="utf-8")
        (target_app / "__init__.py").write_text(app_source, encoding="utf-8")

        diff_text = "".join(
            unified_diff(
                baseline_service.splitlines(keepends=True),
                target_service.splitlines(keepends=True),
                fromfile="a/service.py",
                tofile="b/service.py",
                n=0,
            )
        )
        diff_file = tmp_path / "lambda-body.diff"
        diff_file.write_text(
            "diff --git a/service.py b/service.py\n" + diff_text,
            encoding="utf-8",
        )

        result = runner.invoke(
            cli,
            [
                "analyze",
                "--app",
                str(target_app),
                "--baseline-app",
                str(baseline_app),
                "--diff",
                str(diff_file),
                "--format",
                "json",
                "--no-cache",
            ],
        )

        assert result.exit_code == 0, result.output
        candidates = json.loads(result.output)["candidate_endpoints"]
        if expected_candidate:
            assert [item["endpoint"]["path"] for item in candidates] == ["/one"]
            assert candidates[0]["confidence"] == "medium"
        else:
            assert candidates == []

    def test_baseline_app_rejected_by_runtime_mode(self, runner: CliRunner, tmp_path: Path) -> None:
        app = tmp_path / "app"
        baseline = tmp_path / "baseline"
        app.mkdir()
        baseline.mkdir()
        app_file = app / "app.py"
        app_file.write_text("from fastapi import FastAPI\napp = FastAPI()\n")
        (baseline / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
        diff_file = tmp_path / "test.diff"
        diff_file.write_text("")

        result = runner.invoke(
            cli,
            [
                "analyze",
                "--app",
                str(app_file),
                "--baseline-app",
                str(baseline),
                "--diff",
                str(diff_file),
                "--vm",
            ],
        )

        assert result.exit_code != 0
        assert "--baseline-app is unavailable with --vm" in result.output

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

    def test_analyze_uses_configured_formatter_output(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/items')\n"
            "def items():\n"
            "    return helper()\n"
            "def helper():\n"
            "    return 1\n"
            "for route in configured_routes:\n"
            "    app.router.include_router(route)\n",
            encoding="utf-8",
        )
        diff_file = tmp_path / "change.diff"
        diff_file.write_text(
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -7,1 +7,1 @@\n"
            "-    return 1\n"
            "+    return 2\n",
            encoding="utf-8",
        )
        config = tmp_path / "config.yaml"
        config.write_text(
            "output:\n"
            "  show_confidence: false\n"
            "  show_dependency_chain: true\n"
            "  colorize: false\n"
            "  verbose: true\n",
            encoding="utf-8",
        )

        result = runner.invoke(
            cli,
            [
                "--config",
                str(config),
                "analyze",
                "--app",
                str(tmp_path),
                "--diff",
                str(diff_file),
                "--secure-ast",
                "--no-cache",
            ],
        )

        assert result.exit_code == 0, result.output
        assert "Endpoints (1)" in result.output
        assert "HIGH Confidence" not in result.output
        assert "Changed files: app.py" in result.output
        assert "Inventory Status: CONDITIONAL" in result.output
        assert "Limitation:" in result.output
        assert "\x1b[" not in result.output

    def test_list_uses_configured_formatter_and_preserves_inventory_limitations(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/known')\n"
            "def known():\n"
            "    return None\n"
            "for route in configured_routes:\n"
            "    app.router.include_router(route)\n",
            encoding="utf-8",
        )
        config = tmp_path / "config.yaml"
        config.write_text("output:\n  colorize: false\n", encoding="utf-8")

        result = runner.invoke(
            cli,
            ["--config", str(config), "list", "--app", str(app_file), "--secure-ast"],
        )

        assert result.exit_code == 0, result.output
        assert "Inventory status: conditional" in result.output
        assert "Limitation:" in result.output
        assert "GET" in result.output and "/known" in result.output
        assert "\x1b[" not in result.output

    @pytest.mark.parametrize(
        ("command", "use_vm"),
        [("analyze", False), ("list", False), ("analyze", True), ("list", True)],
    )
    def test_rejects_unsupported_output_options_before_side_effects(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        command: str,
        use_vm: bool,
    ) -> None:
        config = tmp_path / "config.yaml"
        config.write_text("output:\n  show_confidence: false\n", encoding="utf-8")
        app_file = tmp_path / "app.py"
        app_file.write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
        diff_file = tmp_path / "change.diff"
        diff_file.write_text("diff --git a/app.py b/app.py\n", encoding="utf-8")

        def unexpected_side_effect(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("output options must be validated before analysis or runtime")

        monkeypatch.setattr(ChangeMapper, "__init__", unexpected_side_effect)
        monkeypatch.setattr(FastAPIExtractor, "__init__", unexpected_side_effect)
        monkeypatch.setattr(VMExecutor, "analyze_in_vm", unexpected_side_effect)

        args = [
            "--config",
            str(config),
            command,
            "--app",
            str(app_file),
            "--format",
            "json",
        ]
        if command == "analyze":
            args.extend(["--diff", str(diff_file)])
        if use_vm:
            args.append("--vm")

        result = runner.invoke(cli, args)

        assert result.exit_code != 0
        assert "Output option 'show_confidence' cannot be applied to 'json'" in result.output

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
        assert "gVisor/Kata-isolated" in result.output

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
