"""Explicit callback wrappers stay limited to the declared summary allowlist."""

import pytest
from mypy.nodes import MemberExpr, MypyFile, NameExpr, Var

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer


@pytest.mark.parametrize(
    ("imported", "line", "fullname", "expected"),
    [
        (
            "starlette.concurrency.run_in_threadpool",
            -1,
            "main.execute",
            "starlette.concurrency.run_in_threadpool",
        ),
        (
            "fastapi.concurrency.run_in_threadpool",
            -1,
            "main.execute",
            None,
        ),
        ("anyio.to_thread.run_sync", -1, "main.execute", "anyio.to_thread.run_sync"),
        ("foreign.run_in_threadpool", -1, "main.execute", None),
        ("starlette.concurrency.run_in_threadpool", 20, "main.execute", None),
        ("starlette.concurrency.run_in_threadpool", -1, "", None),
        ("starlette.concurrency.run_in_threadpool", -1, "execute", None),
    ],
)
def test_explicit_callback_wrapper_requires_allowlisted_unshadowed_import(
    imported, line, fullname, expected
):
    variable = Var("execute")
    variable.line = line
    expression = NameExpr("execute")
    expression.node = variable
    expression.fullname = fullname
    analyzer = MypyAnalyzer.__new__(MypyAnalyzer)
    assert (
        analyzer._explicit_callback_wrapper_fullname(expression, {"execute": imported}) == expected
    )
    assert analyzer._explicit_callback_wrapper_fullname(expression, {}) is None


def test_explicit_callback_wrapper_accepts_imported_module_attribute_chain():
    module = NameExpr("workers")
    module.node = MypyFile([], [])
    module.fullname = "starlette.concurrency"
    expression = MemberExpr(module, "run_in_threadpool")
    analyzer = MypyAnalyzer.__new__(MypyAnalyzer)
    assert (
        analyzer._explicit_callback_wrapper_fullname(
            expression, {"workers": "starlette.concurrency"}
        )
        == "starlette.concurrency.run_in_threadpool"
    )
