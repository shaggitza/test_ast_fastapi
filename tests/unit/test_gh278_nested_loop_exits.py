"""Public callable controls for nested exits in an otherwise single-pass loop."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.config import Config, ParserConfig


@pytest.mark.parametrize(
    "nested_control",
    [
        "        with nullcontext():\n            if flag:\n                break\n",
        "        match flag:\n            case True:\n                break\n"
        "            case _:\n                pass\n",
    ],
)
def test_nested_loop_exits_preserve_both_possible_callback_targets(
    tmp_path: Path, nested_control: str
) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first():\n    return 1\n\ndef second():\n    return 1\n", encoding="utf-8"
    )
    (tmp_path / "main.py").write_text(
        "from contextlib import nullcontext\nfrom fastapi import FastAPI\n"
        "from helpers import first, second\n"
        "app = FastAPI()\n@app.get('/nested-exit')\ndef nested_exit(flag: bool):\n"
        "    callback = first\n    while True:\n"
        f"{nested_control}"
        "        callback = second\n        break\n    return callback()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(
        tmp_path,
        config=Config(parser=ParserConfig(follow_imports=False)),
        secure_ast=True,
        use_cache=False,
    )
    for line in (2, 5):
        diff = (
            "diff --git a/helpers.py b/helpers.py\n"
            "--- a/helpers.py\n+++ b/helpers.py\n"
            f"@@ -{line},1 +{line},1 @@\n"
            "-    return 1\n+    return 2\n"
        )
        report = mapper.analyze_diff(diff)
        assert {item.endpoint.identifier for item in report.candidate_endpoints} == {
            "GET /nested-exit"
        }
        assert all(item.confidence.value == "low" for item in report.candidate_endpoints)
        endpoint = mapper.registry.get_all()[0]
        dependencies = mapper.mypy_analyzer.get_endpoint_dependencies(endpoint)
        assert dependencies is not None
        assert dependencies.references_lines_low_only(str(tmp_path / "helpers.py"), {line})
