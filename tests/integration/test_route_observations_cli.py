"""Public CLI integration for opt-in source route observations."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from click.testing import CliRunner

from fastapi_endpoint_detector.analyzer import change_mapper
from fastapi_endpoint_detector.cli import cli
from fastapi_endpoint_detector.config import Config
from fastapi_endpoint_detector.models.report import AnalysisReport
from fastapi_endpoint_detector.output import formatters

if TYPE_CHECKING:
    from pathlib import Path

if not hasattr(Config().analysis, "route_observations"):
    pytest.skip(
        "the stacked route-observation CLI integration is supplied by PR #312",
        allow_module_level=True,
    )


def _install_stub_mapper(monkeypatch: Any, app_root: Path) -> None:
    class StubMypyAnalyzer:
        def set_line_progress_callback(self, _callback: object) -> None:
            pass

    class StubMapper:
        def __init__(self, **_kwargs: object) -> None:
            self.target_project_root = app_root
            self.mypy_analyzer = StubMypyAnalyzer()

        def analyze_diff(self, _diff: Path, progress_callback: object = None) -> AnalysisReport:
            del progress_callback
            return AnalysisReport(
                app_path=str(app_root),
                diff_source="fixture.diff",
                total_endpoints=0,
            )

        def get_endpoints(self) -> list[object]:
            return []

    monkeypatch.setattr(change_mapper, "ChangeMapper", StubMapper)


def _write_cli_inputs(tmp_path: Path) -> tuple[Path, Path]:
    app_root = tmp_path / "app"
    app_root.mkdir()
    (app_root / "main.py").write_text("app = None\n", encoding="utf-8")
    (app_root / "client.ts").write_text(
        "fetch('https://api.example.test/items')\n", encoding="utf-8"
    )
    (app_root / "Dockerfile").write_text(
        "ENV API_BASE_URL=https://api.example.test\n", encoding="utf-8"
    )
    diff = tmp_path / "empty.diff"
    diff.write_text("", encoding="utf-8")
    return app_root, diff


def test_analyze_cli_emits_opt_in_source_observations_and_preserves_output_config(
    tmp_path: Path, monkeypatch: Any
) -> None:
    app_root, diff = _write_cli_inputs(tmp_path)
    _install_stub_mapper(monkeypatch, app_root)
    config = tmp_path / "config.yaml"
    config.write_text(
        """analysis:
  route_observations:
    enabled: true
    client_include_patterns: ["**/*.ts"]
    deployment_include_patterns: ["**/Dockerfile*"]
    max_files: 10
    max_file_bytes: 4096
    trusted_server_origins: {}
output:
  colorize: false
""",
        encoding="utf-8",
    )

    received_output_config: list[object] = []
    real_get_formatter = formatters.get_formatter

    def capture_output_config(name: str, output_config: object = None) -> object:
        received_output_config.append(output_config)
        return real_get_formatter(name, output_config)  # type: ignore[arg-type]

    monkeypatch.setattr(formatters, "get_formatter", capture_output_config)
    result = CliRunner().invoke(
        cli,
        [
            "--config",
            str(config),
            "analyze",
            "--app",
            str(app_root),
            "--diff",
            str(diff),
            "--format",
            "text",
            "--secure-ast",
        ],
    )

    assert result.exit_code == 0, result.output
    normalized_output = " ".join(result.output.split())
    assert "Source Observations: complete scan of 2 files" in normalized_output
    assert "1 exact client observations" in normalized_output
    assert "1 exact and 0 uncertain deployment observations" in normalized_output
    assert received_output_config and received_output_config[0].colorize is False


def test_analyze_cli_keeps_source_observations_absent_when_disabled(
    tmp_path: Path, monkeypatch: Any
) -> None:
    app_root, diff = _write_cli_inputs(tmp_path)
    _install_stub_mapper(monkeypatch, app_root)

    result = CliRunner().invoke(
        cli,
        [
            "analyze",
            "--app",
            str(app_root),
            "--diff",
            str(diff),
            "--format",
            "text",
            "--secure-ast",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Source Observations:" not in result.output
