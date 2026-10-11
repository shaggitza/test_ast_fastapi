"""Public dependency controls for zero-trip callable binders."""

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
@pytest.mark.parametrize("empty", ["[]", "()"])
def test_literal_empty_loop_preserves_alias_and_excludes_dead_body(
    tmp_path: Path, kind: str, empty: str
) -> None:
    _helpers(tmp_path)
    alias, initial = _binding(kind, "first")
    _, replaced = _binding(kind, "second")
    (tmp_path / "main.py").write_text(
        "from functools import partial\nfrom fastapi import FastAPI\n"
        "from helpers import first, second, run\n"
        "app = FastAPI()\n@app.get('/empty')\ndef handler():\n"
        f"    {alias} = {initial}\n"
        f"    for {alias} in {empty}:\n"
        "        second()\n"
        f"        {alias} = {replaced}\n"
        f"    return {alias}()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    first = mapper.analyze_diff(_diff("helpers.py", 2))
    second = mapper.analyze_diff(_diff("helpers.py", 5))
    assert {item.endpoint.identifier for item in first.candidate_endpoints} == {"GET /empty"}
    assert second.candidate_endpoints == []


def test_literal_empty_loop_runs_else_binding(tmp_path: Path) -> None:
    _helpers(tmp_path)
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\nfrom helpers import first, second\n"
        "app = FastAPI()\n@app.get('/empty-else')\ndef handler():\n"
        "    callback = first\n"
        "    for callback in ():\n        first()\n"
        "    else:\n        callback = second\n"
        "    return callback()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    assert mapper.analyze_diff(_diff("helpers.py", 2)).candidate_endpoints == []
    assert {
        item.endpoint.identifier
        for item in mapper.analyze_diff(_diff("helpers.py", 5)).candidate_endpoints
    } == {"GET /empty-else"}
