"""Public dependency controls for context manager local bindings."""

from pathlib import Path

import pytest
from mypy.nodes import (
    AssignmentStmt,
    Block,
    DelStmt,
    ExpressionStmt,
    FuncDef,
    NameExpr,
    NonlocalDecl,
    PassStmt,
    Statement,
)

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.mypy_analyzer import (
    MypyAnalyzer,
    _context_binding_census,
)
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


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
def test_context_preserves_untouched_aliases_and_nested_scope_writes(
    tmp_path: Path, kind: str
) -> None:
    _helpers(tmp_path)
    alias, initial = _binding(kind, "first")
    (tmp_path / "main.py").write_text(
        "from typing import Any\nfrom functools import partial\n"
        "from fastapi import FastAPI\nfrom helpers import first, second, run\n"
        "app = FastAPI()\n@app.get('/untouched')\ndef handler(context: Any):\n"
        f"    {alias} = {initial}\n"
        "    with context as resource:\n"
        "        def nested():\n"
        f"            {alias} = second\n"
        "        pass\n"
        f"    return {alias}()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    first = mapper.analyze_diff(_diff("helpers.py", 2))
    second = mapper.analyze_diff(_diff("helpers.py", 5))
    assert {item.endpoint.identifier for item in first.candidate_endpoints} == {"GET /untouched"}
    assert second.candidate_endpoints == []
    assert all(item.cap != "UNKNOWN_CONTEXT_EXIT_BINDING" for item in first.analysis_limitations)


@pytest.mark.parametrize("kind", ["callable", "partial", "lambda"])
def test_context_as_binder_kills_previous_alias_inside_and_after(tmp_path: Path, kind: str) -> None:
    _helpers(tmp_path)
    alias, initial = _binding(kind, "first")
    (tmp_path / "main.py").write_text(
        "from typing import Any\nfrom functools import partial\n"
        "from fastapi import FastAPI\nfrom helpers import first, run\n"
        "app = FastAPI()\n@app.get('/context-binder')\ndef handler(context: Any):\n"
        f"    {alias} = {initial}\n"
        f"    with context as {alias}:\n        {alias}()\n"
        f"    return {alias}()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    assert mapper.analyze_diff(_diff("helpers.py", 2)).candidate_endpoints == []


def test_context_suppression_abstains_on_written_alias_but_keeps_sibling(
    tmp_path: Path,
) -> None:
    _helpers(tmp_path)
    (tmp_path / "main.py").write_text(
        "from typing import Any\nfrom fastapi import FastAPI\n"
        "from helpers import first, second, keep\n"
        "app = FastAPI()\n@app.get('/suppressed')\n"
        "def handler(context: Any, flag: bool):\n"
        "    callback = first\n    safe = keep\n"
        "    with context:\n"
        "        if flag:\n            raise RuntimeError()\n"
        "        callback = second\n        raise ValueError()\n"
        "    safe()\n    return callback()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    for line in (2, 5):
        report = mapper.analyze_diff(_diff("helpers.py", line))
        assert report.candidate_endpoints == []
        assert report.analysis_completeness == "partial"
        assert any(
            item.cap == "UNKNOWN_CONTEXT_EXIT_BINDING" for item in report.analysis_limitations
        )
    assert {
        item.endpoint.identifier
        for item in mapper.analyze_diff(_diff("helpers.py", 11)).candidate_endpoints
    } == {"GET /suppressed"}


def test_context_dead_branch_does_not_kill_alias(tmp_path: Path) -> None:
    _helpers(tmp_path)
    (tmp_path / "main.py").write_text(
        "from typing import Any\nfrom fastapi import FastAPI\n"
        "from helpers import first, second\n"
        "app = FastAPI()\n@app.get('/dead-context')\ndef handler(context: Any):\n"
        "    callback = first\n    with context:\n"
        "        if False:\n            callback = second\n"
        "    return callback()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    first = mapper.analyze_diff(_diff("helpers.py", 2))
    second = mapper.analyze_diff(_diff("helpers.py", 5))
    assert {item.endpoint.identifier for item in first.candidate_endpoints} == {"GET /dead-context"}
    assert second.candidate_endpoints == []


@pytest.mark.parametrize("kind", ["partial", "lambda"])
def test_reassigned_context_parameter_does_not_preserve_alias(tmp_path: Path, kind: str) -> None:
    _helpers(tmp_path)
    alias, initial = _binding(kind, "first")
    (tmp_path / "main.py").write_text(
        "from typing import Any\nfrom functools import partial\n"
        "from fastapi import FastAPI\nfrom helpers import first, second, run\n"
        "app=FastAPI()\n@app.get('/reassigned-manager')\n"
        "def handler(context: Any, replacement: Any):\n"
        f"    {alias} = {initial}\n"
        "    context = replacement\n"
        "    with context:\n        pass\n"
        f"    return {alias}()\n",
        encoding="utf-8",
    )
    report = ChangeMapper(tmp_path, secure_ast=True, use_cache=False).analyze_diff(
        _diff("helpers.py", 2)
    )
    assert report.candidate_endpoints == []
    assert any(row.cap == "UNKNOWN_CONTEXT_MANAGER_EXIT" for row in report.analysis_limitations)


@pytest.mark.parametrize("kind", ["partial", "lambda"])
def test_local_manager_closure_does_not_restore_alias(tmp_path: Path, kind: str) -> None:
    _helpers(tmp_path)
    alias, initial = _binding(kind, "first")
    (tmp_path / "main.py").write_text(
        "from functools import partial\nfrom fastapi import FastAPI\n"
        "from helpers import first, second, run\n"
        "app=FastAPI()\n@app.get('/closure-manager')\ndef handler():\n"
        f"    {alias} = {initial}\n"
        "    class Mutator:\n"
        "        def __enter__(self): return self\n"
        "        def __exit__(self, exc_type, exc, tb):\n"
        f"            nonlocal {alias}\n"
        f"            {alias} = second\n"
        "            return False\n"
        "    with Mutator():\n        pass\n"
        f"    return {alias}()\n",
        encoding="utf-8",
    )
    report = ChangeMapper(tmp_path, secure_ast=True, use_cache=False).analyze_diff(
        _diff("helpers.py", 2)
    )
    assert report.candidate_endpoints == []
    assert any(row.cap == "UNKNOWN_CONTEXT_MANAGER_EXIT" for row in report.analysis_limitations)


def test_post_context_lambda_execution_is_possible(tmp_path: Path) -> None:

    app_path = tmp_path / "app.py"
    app_path.write_text(
        "from typing import Any\ndef hit() -> int:\n    return 1\n"
        "def handler(context: Any) -> int:\n"
        "    callback = lambda: hit()\n    with context:\n        pass\n"
        "    return callback()\n",
        encoding="utf-8",
    )
    endpoint = Endpoint(
        path="/context-continuation",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="handler", module="app", file_path=app_path, line_number=4),
    )
    dependencies = MypyAnalyzer(tmp_path).analyze_endpoint(endpoint)
    hit = dependencies.references_symbol_at_line("app.py", 3)
    assert hit is not None
    assert hit.low_confidence
    states = {
        span.execution_state
        for span in dependencies.source_evidence_spans
        if span.start_line == span.end_line == 5
    }
    assert "possible_execution" in states
    assert "established_execution" not in states


@pytest.mark.parametrize(
    ("binding", "expected"),
    [
        ("read", False),
        ("nested_other", False),
        ("assign", True),
        ("delete", True),
        ("nonlocal", True),
        ("nested_nonlocal", True),
    ],
)
def test_context_parameter_binding_census(binding: str, expected: bool) -> None:

    statement: Statement
    if binding == "read":
        statement = ExpressionStmt(NameExpr("context"))
    elif binding == "nested_other":
        statement = FuncDef(
            "nested", [], Block([AssignmentStmt([NameExpr("callback")], NameExpr("second"))])
        )
    elif binding == "assign":
        statement = AssignmentStmt([NameExpr("context")], NameExpr("replacement"))
    elif binding == "delete":
        statement = DelStmt(NameExpr("context"))
    elif binding == "nonlocal":
        statement = NonlocalDecl(["context"])
    else:
        statement = FuncDef("nested", [], Block([NonlocalDecl(["context"])]))
    names = _context_binding_census(Block([statement]), node_limit=100, item_limit=1000)
    assert names is not None
    assert ("context" in names) is expected


@pytest.mark.parametrize("limit_kind", ["nodes", "items", "bulk_names"])
def test_context_parameter_binding_census_abstains_at_budget(limit_kind: str) -> None:

    body = (
        Block([NonlocalDecl(["context"] * 100)])
        if limit_kind == "bulk_names"
        else Block([PassStmt(), PassStmt()])
    )
    names = _context_binding_census(
        body,
        node_limit=1 if limit_kind == "nodes" else 100,
        item_limit=2 if limit_kind == "items" else 10 if limit_kind == "bulk_names" else 1000,
    )
    assert names is None
