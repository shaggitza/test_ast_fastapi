from __future__ import annotations

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.scip_analyzer import (
    SCIPAnalyzerError,
    SCIPDefinition,
    SCIPReachedDefinition,
)
from fastapi_endpoint_detector.parser.diff_parser import DiffParser


class FakeSCIPAnalyzer:
    use_cache = False

    def ensure_index(self, *, force: bool = False) -> None:
        assert force

    def definitions_at(self, file_path: Path, lines: set[int]):
        assert file_path == Path("services.py")
        assert 2 in lines
        return (
            SCIPDefinition(
                "changed-symbol", "services:calculate_total()", Path("services.py"), 1, 2
            ),
        )

    def affected(self, seed: SCIPDefinition, *, max_depth: int | None = None):
        assert max_depth == 10
        return (
            SCIPReachedDefinition(seed, 0),
            SCIPReachedDefinition(
                SCIPDefinition("dependency-symbol", "main:quote_service()", Path("main.py"), 5, 6),
                1,
            ),
            SCIPReachedDefinition(
                SCIPDefinition("quote-symbol", "main:quote()", Path("main.py"), 8, 10),
                2,
            ),
            SCIPReachedDefinition(
                SCIPDefinition("order-symbol", "main:order()", Path("main.py"), 12, 14),
                1,
            ),
        )


def test_scip_mapper_rejects_deleted_definitions_without_baseline_index(
    tmp_path: Path,
) -> None:
    mapper = ChangeMapper(tmp_path, use_cache=False, secure_ast=True, use_scip=True)
    mapper._scip_analyzer = FakeSCIPAnalyzer()  # type: ignore[assignment]
    diff_file = DiffParser.parse_string(
        "diff --git a/services.py b/services.py\n"
        "deleted file mode 100644\n"
        "--- a/services.py\n"
        "+++ /dev/null\n"
        "@@ -1,2 +0,0 @@\n"
        "-def removed():\n"
        "-    return 1\n"
    )[0]

    with pytest.raises(SCIPAnalyzerError, match="baseline dual-index"):
        mapper._analyze_with_scip([diff_file], None)


def test_scip_mapper_reaches_direct_and_depends_endpoints(tmp_path: Path) -> None:
    (tmp_path / "services.py").write_text(
        "def calculate_total(price: float, quantity: int) -> float:\n"
        "    return round(price * quantity, 2)\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from services import calculate_total\n"
        "app = FastAPI()\n\n"
        "def quote_service() -> float:\n"
        "    return calculate_total(10, 2)\n\n"
        "@app.post('/quotes')\n"
        "def quote(total: float = Depends(quote_service)) -> dict:\n"
        "    return {'total': total}\n\n"
        "@app.post('/orders')\n"
        "def order() -> dict:\n"
        "    return {'total': calculate_total(10, 1)}\n",
        encoding="utf-8",
    )
    diff = tmp_path / "change.diff"
    diff.write_text(
        "diff --git a/services.py b/services.py\n"
        "--- a/services.py\n"
        "+++ b/services.py\n"
        "@@ -2 +2 @@\n"
        "-    return price * quantity\n"
        "+    return round(price * quantity, 2)\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, use_cache=False, secure_ast=True, use_scip=True)
    mapper._scip_analyzer = FakeSCIPAnalyzer()  # type: ignore[assignment]

    report = mapper.analyze_diff(diff)

    assert {item.endpoint.identifier for item in report.affected_endpoints} == {
        "POST /orders",
        "POST /quotes",
    }
    assert not report.orphan_changes
    assert all(item.confidence.value == "medium" for item in report.affected_endpoints)
