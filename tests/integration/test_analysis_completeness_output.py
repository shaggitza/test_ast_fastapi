"""Integration coverage for machine and human analysis completeness output."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

import pytest
import yaml
from click.testing import CliRunner

from fastapi_endpoint_detector.cli import cli
from fastapi_endpoint_detector.models.report import AnalysisReport, OrphanChange
from fastapi_endpoint_detector.output.formatters import get_formatter

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("replacement", "expected"),
    [(False, "complete"), (True, "partial")],
)
def test_secure_ast_cli_reports_completeness_for_unbased_diffs(
    tmp_path: Path,
    replacement: bool,
    expected: str,
) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/items')\n"
        "def items():\n"
        + ("    return {}\n" if replacement else "    marker = 1\n    return {}\n"),
        encoding="utf-8",
    )
    diff_file = tmp_path / "change.diff"
    if replacement:
        diff = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -4,2 +4,2 @@\n"
            " def items():\n"
            "-    return {'items': []}\n"
            "+    return {}\n"
        )
    else:
        diff = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -4,0 +5 @@\n"
            "+    marker = 1\n"
        )
    diff_file.write_text(diff, encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        [
            "analyze",
            "--app",
            str(app_file),
            "--diff",
            str(diff_file),
            "--secure-ast",
            "--no-cache",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["analysis_completeness"] == expected
    if replacement:
        assert any(item["removed_lines"] for item in payload["orphan_changes"])
        assert any(
            "baseline analysis is incomplete" in warning.lower() and "removed" in warning.lower()
            for warning in payload["warnings"]
        )


@pytest.mark.parametrize("output_format", ["text", "markdown", "html", "json", "yaml"])
@pytest.mark.parametrize("completeness", ["complete", "partial"])
def test_all_report_formatters_expose_analysis_completeness(
    output_format: str,
    completeness: str,
) -> None:
    report = AnalysisReport(
        app_path="app.py",
        diff_source="change.diff",
        total_endpoints=0,
        analysis_completeness=completeness,
        warnings=(
            ["Mypy baseline analysis is incomplete: removed lines remain unresolved."]
            if completeness == "partial"
            else []
        ),
        orphan_changes=(
            [OrphanChange(file_path="app.py", removed_lines=[5], reason="Unresolved removal")]
            if completeness == "partial"
            else []
        ),
    )
    formatter = (
        get_formatter("text", {"colorize": False})
        if output_format == "text"
        else get_formatter(output_format)
    )
    rendered = formatter.format(report)

    if output_format == "json":
        payload = json.loads(rendered)
        assert payload["schema_version"] == 4
        assert payload["analysis_completeness"] == completeness
    elif output_format == "yaml":
        payload = yaml.safe_load(rendered)
        assert payload["schema_version"] == 4
        assert payload["analysis_completeness"] == completeness
    else:
        plain = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", rendered)
        plain = re.sub(r"<[^>]+>", " ", plain)
        plain = re.sub(r"[#*_]", "", plain).replace(chr(96), "")
        assert re.search(
            rf"Analysis Completeness\s*:\s*{completeness}\b",
            plain,
            flags=re.IGNORECASE,
        )
