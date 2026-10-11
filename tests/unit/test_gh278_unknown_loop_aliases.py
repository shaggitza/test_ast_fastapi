"""Public dependency controls for unknown iteration binders."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper


def _diff(path: str, line: int) -> str:
    return (
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n+++ b/{path}\n"
        f"@@ -{line},1 +{line},1 @@\n"
        "-    return 1\n"
        "+    return 2\n"
    )


def _helpers(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first() -> int:\n    return 1\n\n"
        "def second() -> int:\n    return 1\n\n"
        "def run(callback):\n    return callback()\n\n"
        "def keep() -> int:\n    return 1\n",
        encoding="utf-8",
    )


def _binding(kind: str, target: str) -> tuple[str, str]:
    if kind == "partial":
        return "bound", f"partial(run, {target})"
    if kind == "lambda":
        return "callback", f"lambda: {target}()"
    return "callback", target


@pytest.mark.parametrize("kind", ["callable", "partial", "lambda"])
def test_unknown_loop_retains_only_possible_zero_trip_callable_evidence(
    tmp_path: Path, kind: str
) -> None:
    _helpers(tmp_path)
    alias, initial = _binding(kind, "first")
    (tmp_path / "main.py").write_text(
        "from typing import Any, Iterable\nfrom functools import partial\n"
        "from fastapi import FastAPI\nfrom helpers import first, run\n"
        "app = FastAPI()\n@app.get('/unknown-loop')\n"
        "def handler(items: Iterable[Any], flag: bool):\n"
        f"    {alias} = {initial}\n"
        f"    for {alias} in items:\n        pass\n"
        "    if flag:\n        pass\n"
        f"    return {alias}()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    report = mapper.analyze_diff(_diff("helpers.py", 2))
    assert report.analysis_completeness == "partial"
    assert any(item.cap == "UNKNOWN_ITERATION_BINDING" for item in report.analysis_limitations)
    if kind == "callable":
        assert {item.endpoint.identifier for item in report.candidate_endpoints} == {
            "GET /unknown-loop"
        }
        assert all(item.confidence.value == "low" for item in report.candidate_endpoints)
    else:
        assert report.candidate_endpoints == []
