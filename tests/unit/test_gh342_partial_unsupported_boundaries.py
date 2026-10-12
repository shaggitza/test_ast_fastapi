"""Unsupported partial syntax and executor boundaries must report incomplete evidence."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.config import Config, ParserConfig


def _diff() -> str:
    return (
        "diff --git a/helpers.py b/helpers.py\n"
        "--- a/helpers.py\n+++ b/helpers.py\n"
        "@@ -2,1 +2,1 @@\n-    return 1\n+    return 2\n"
    )


@pytest.mark.parametrize(
    ("expression", "cap"),
    [
        (
            "outer = partial(run, callback=partial(first))\n    return outer()",
            "NESTED_PARTIAL_CAPTURE_UNSUPPORTED",
        ),
        ("return invoke(partial(first))", "INLINE_PARTIAL_ARGUMENT_UNSUPPORTED"),
    ],
)
def test_inline_partial_syntax_has_explicit_limitation(
    tmp_path: Path, expression: str, cap: str
) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first():\n    return 1\n\n"
        "def run(callback):\n    return callback()\n\n"
        "def invoke(callback):\n    return callback()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from functools import partial\nfrom fastapi import FastAPI\n"
        "from helpers import first, run, invoke\n"
        "app = FastAPI()\n@app.get('/inline')\ndef inline():\n"
        f"    {expression}\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(
        tmp_path,
        config=Config(parser=ParserConfig(follow_imports=False)),
        secure_ast=True,
        use_cache=False,
    )
    report = mapper.analyze_diff(_diff())
    assert report.candidate_endpoints == []
    assert report.analysis_completeness == "partial"
    assert any(item.cap == cap for item in report.analysis_limitations)


@pytest.mark.parametrize("inline", [False, True])
def test_partial_executor_callback_reports_unsupported_capture(
    tmp_path: Path, inline: bool
) -> None:
    (tmp_path / "helpers.py").write_text("def first():\n    return 1\n", encoding="utf-8")
    setup = "" if inline else "    bound = partial(first)\n"
    expression = "partial(first)" if inline else "bound"
    (tmp_path / "main.py").write_text(
        "from functools import partial\nfrom fastapi import FastAPI\n"
        "from starlette.concurrency import run_in_threadpool\nfrom helpers import first\n"
        "app = FastAPI()\n@app.get('/executor')\nasync def executor():\n"
        f"{setup}    return await run_in_threadpool({expression})\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(
        tmp_path,
        config=Config(parser=ParserConfig(follow_imports=False)),
        secure_ast=True,
        use_cache=False,
    )
    report = mapper.analyze_diff(_diff())
    assert report.candidate_endpoints == []
    assert report.analysis_completeness == "partial"
    assert any(
        item.cap == "PARTIAL_EXECUTOR_CALLBACK_UNSUPPORTED" for item in report.analysis_limitations
    )
