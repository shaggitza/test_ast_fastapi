from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from fastapi_endpoint_detector.analyzer.scip_analyzer import (
    SCIPAnalyzer,
    SCIPAnalyzerError,
    SCIPDefinition,
)


def completed(
    stdout: str = "", *, code: int = 0, stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], code, stdout, stderr)


def test_outline_converts_zero_based_ranges_and_selects_narrowest(tmp_path: Path) -> None:
    analyzer = SCIPAnalyzer(tmp_path)
    payload = {
        "result": [
            {
                "symbol": "outer",
                "shortName": "m:outer()",
                "startLine": 0,
                "endLine": 10,
                "children": [
                    {
                        "symbol": "inner",
                        "shortName": "m:inner()",
                        "startLine": 4,
                        "endLine": 5,
                    }
                ],
            },
        ]
    }
    with (
        patch.object(analyzer, "_executable", return_value="scip-query"),
        patch("subprocess.run", return_value=completed(json.dumps(payload))),
    ):
        definitions = analyzer.definitions_at(Path("module.py"), {5})

    assert definitions == (SCIPDefinition("inner", "m:inner()", Path("module.py"), 5, 6),)


def test_affected_resolves_returned_functions_through_file_outline(tmp_path: Path) -> None:
    analyzer = SCIPAnalyzer(tmp_path)
    seed = SCIPDefinition("seed", "services:changed()", Path("services.py"), 1, 2)

    def fake_run(args: list[str], *, json_output: bool = False):
        if "affected" in args:
            return {
                "matched": True,
                "affected": [{"shortName": "main:handler()", "file": "main.py", "depth": 2}],
            }
        return [{"symbol": "handler", "shortName": "main:handler()", "startLine": 6, "endLine": 8}]

    with (
        patch.object(analyzer, "_run", side_effect=fake_run),
        patch.object(analyzer, "_executable", return_value="scip-query"),
    ):
        reached = analyzer.affected(seed)

    assert reached[0].definition == seed
    assert reached[1].definition.symbol == "handler"
    assert reached[1].definition.start_line == 7
    assert reached[1].depth == 2


def test_validate_tools_rejects_plus_indexer(tmp_path: Path) -> None:
    analyzer = SCIPAnalyzer(tmp_path)
    with (
        patch("shutil.which", return_value="/bin/tool"),
        pytest.raises(SCIPAnalyzerError, match="scip-python-plus"),
    ):
        analyzer.validate_tools()


def test_reindex_rejects_unverified_cached_or_plus_provenance(tmp_path: Path) -> None:
    analyzer = SCIPAnalyzer(tmp_path)
    with (
        patch.object(analyzer, "validate_tools"),
        patch.object(analyzer, "_executable", return_value="scip-query"),
        patch.object(
            analyzer,
            "_run",
            return_value={
                "indexPath": "/tmp/index.scip",
                "reused": False,
                "shards": [{"command": "scip-python-plus index --output index.scip"}],
            },
        ),
        pytest.raises(SCIPAnalyzerError, match="provenance"),
    ):
        analyzer.ensure_index()


def test_command_failure_is_explicit(tmp_path: Path) -> None:
    analyzer = SCIPAnalyzer(tmp_path)
    with (
        patch("subprocess.run", return_value=completed(code=7, stderr="broken index")),
        pytest.raises(SCIPAnalyzerError, match="broken index"),
    ):
        analyzer._run(["scip-query", "outline", "x.py", "--json"], json_output=True)
