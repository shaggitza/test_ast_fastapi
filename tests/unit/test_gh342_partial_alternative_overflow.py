"""Public mapper controls for bounded partial alternatives without a prefix winner."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.config import Config, ParserConfig


@pytest.mark.parametrize("order", [("first", "second", "third"), ("third", "second", "first")])
def test_partial_alternative_overflow_reports_all_targets_as_unresolved(
    tmp_path: Path, order: tuple[str, str, str]
) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first():\n    return 1\n\ndef second():\n    return 1\n\ndef third():\n    return 1\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from functools import partial\nfrom fastapi import FastAPI\n"
        "from helpers import first, second, third\n"
        "app = FastAPI()\n@app.get('/overflow')\ndef overflow(flag: int):\n"
        f"    if flag == 1:\n        bound = partial({order[0]})\n"
        f"    elif flag == 2:\n        bound = partial({order[1]})\n"
        f"    else:\n        bound = partial({order[2]})\n"
        "    return bound()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(
        tmp_path,
        config=Config(parser=ParserConfig(follow_imports=False)),
        secure_ast=True,
        use_cache=False,
    )
    mapper.mypy_analyzer.MAX_POINTS_TO_TARGETS = 2
    for line in (2, 5, 8):
        diff = (
            "diff --git a/helpers.py b/helpers.py\n"
            "--- a/helpers.py\n+++ b/helpers.py\n"
            f"@@ -{line},1 +{line},1 @@\n"
            "-    return 1\n+    return 2\n"
        )
        report = mapper.analyze_diff(diff)
        assert report.candidate_endpoints == []
        assert report.analysis_completeness == "partial"
        assert any(
            item.cap == "MAX_POINTS_TO_TARGETS" and item.limit == 2
            for item in report.analysis_limitations
        )
