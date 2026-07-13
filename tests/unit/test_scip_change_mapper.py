from __future__ import annotations

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper, ChangeMapperError
from fastapi_endpoint_detector.analyzer.scip_analyzer import (
    SCIPAnalyzerError,
    SCIPDefinition,
    SCIPReachedDefinition,
)
from fastapi_endpoint_detector.parser.diff_parser import DiffParser


class OverrideEdgeAnalyzer:
    def ensure_index(self, *, force: bool = False) -> None:
        assert force

    def definitions_at(self, file_path: Path, lines: set[int]):
        return (SCIPDefinition("impl", "impl:Impl:run()", Path("impl.py"), 4, 5),)

    def base_method_definitions(self, definition: SCIPDefinition):
        if definition.symbol == "impl":
            return (SCIPDefinition("base", "base:Base:run()", Path("base.py"), 2, 3),)
        return ()

    def affected(self, seed: SCIPDefinition, *, max_depth: int | None = None):
        if seed.symbol == "base":
            return (
                SCIPReachedDefinition(seed, 0),
                SCIPReachedDefinition(
                    SCIPDefinition("handler", "main:handler()", Path("main.py"), 4, 6),
                    1,
                ),
            )
        return (SCIPReachedDefinition(seed, 0),)


class PartiallyFailingAnalyzer:
    def ensure_index(self, *, force: bool = False) -> None:
        assert force

    def definitions_at(self, file_path: Path, lines: set[int]):
        assert file_path == Path("services.py")
        return (
            SCIPDefinition("bad", "services:__all__", Path("services.py"), 1, 1),
            SCIPDefinition("good", "services:changed()", Path("services.py"), 1, 1),
        )

    def affected(self, seed: SCIPDefinition, *, max_depth: int | None = None):
        if seed.symbol == "bad":
            raise SCIPAnalyzerError("ambiguous export")
        return (
            SCIPReachedDefinition(seed, 0),
            SCIPReachedDefinition(
                SCIPDefinition("handler", "main:handler()", Path("main.py"), 4, 6),
                1,
            ),
        )


class BaselineDeletionAnalyzer:
    def ensure_index(self, *, force: bool = False) -> None:
        assert force

    def definitions_at(self, file_path: Path, lines: set[int]):
        assert file_path == Path("services.py")
        assert lines in ({1}, {2})
        return (SCIPDefinition("removed", "services:removed()", Path("services.py"), 1, 2),)

    def affected(self, _seed: SCIPDefinition, *, max_depth: int | None = None):
        assert max_depth == 10
        return (
            SCIPReachedDefinition(
                SCIPDefinition("handler", "main:items()", Path("main.py"), 5, 7),
                1,
            ),
        )


class EmptyTargetAnalyzer:
    def ensure_index(self, *, force: bool = False) -> None:
        assert force

    def definitions_at(self, _file_path: Path, _lines: set[int]):
        return ()

    def affected(self, _seed: SCIPDefinition, *, max_depth: int | None = None):
        assert max_depth is not None
        return ()


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


def test_programmatic_baseline_requires_scip(tmp_path: Path) -> None:
    with pytest.raises(ChangeMapperError, match="only with use_scip"):
        ChangeMapper(tmp_path, baseline_app_path=tmp_path)


def test_scip_expands_proven_override_to_base_method_callers(tmp_path: Path) -> None:
    (tmp_path / "impl.py").write_text(
        "from base import Base\n\nclass Impl(Base):\n    def run(self): return 1\n"
    )
    (tmp_path / "base.py").write_text("class Base:\n    def run(self): raise NotImplementedError\n")
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n\n"
        "@app.get('/items')\ndef handler():\n    return 1\n"
    )
    diff_file = DiffParser.parse_string(
        "diff --git a/impl.py b/impl.py\n--- a/impl.py\n+++ b/impl.py\n"
        "@@ -3,0 +4 @@\n+    def run(self): return 1\n"
    )[0]
    mapper = ChangeMapper(tmp_path, use_cache=False, secure_ast=True, use_scip=True)
    mapper._scip_analyzer = OverrideEdgeAnalyzer()  # type: ignore[assignment]

    affected, _orphans = mapper._analyze_with_scip([diff_file], [], None)

    assert [item.endpoint.identifier for item in affected] == ["GET /items"]


def test_scip_seed_failure_does_not_discard_other_seed_results(tmp_path: Path) -> None:
    (tmp_path / "services.py").write_text("def changed():\n    return 1\n")
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n\n"
        "@app.get('/items')\ndef handler():\n    return 1\n"
    )
    diff_file = DiffParser.parse_string(
        "diff --git a/services.py b/services.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/services.py\n"
        "@@ -0,0 +1 @@\n"
        "+def changed(): pass\n"
    )[0]
    mapper = ChangeMapper(tmp_path, use_cache=False, secure_ast=True, use_scip=True)
    mapper._scip_analyzer = PartiallyFailingAnalyzer()  # type: ignore[assignment]
    warnings: list[str] = []

    affected, _orphans = mapper._analyze_with_scip([diff_file], warnings, None)

    assert [item.endpoint.identifier for item in affected] == ["GET /items"]
    assert len(warnings) == 1
    assert "services:__all__" in warnings[0]


def test_scip_mapper_rejects_identical_target_and_baseline(tmp_path: Path) -> None:
    with pytest.raises(ChangeMapperError, match="must differ"):
        ChangeMapper(
            tmp_path,
            use_cache=False,
            secure_ast=True,
            use_scip=True,
            baseline_app_path=tmp_path,
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

    with pytest.raises(SCIPAnalyzerError, match="--baseline-app"):
        mapper._analyze_with_scip([diff_file], [], None)


def test_deleted_helper_uses_baseline_index_and_unchanged_target_endpoint(
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "baseline"
    target = tmp_path / "target"
    baseline.mkdir()
    target.mkdir()
    main_source = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n\n"
        "@app.get('/items')\n"
        "def items():\n"
        "    return 1\n"
    )
    (baseline / "main.py").write_text(main_source)
    (target / "main.py").write_text(main_source)
    (baseline / "services.py").write_text("def removed():\n    return 1\n")
    diff_file = DiffParser.parse_string(
        "diff --git a/services.py b/services.py\n"
        "deleted file mode 100644\n"
        "--- a/services.py\n"
        "+++ /dev/null\n"
        "@@ -1,2 +0,0 @@\n"
        "-def removed():\n"
        "-    return 1\n"
    )[0]
    mapper = ChangeMapper(
        target,
        use_cache=False,
        secure_ast=True,
        use_scip=True,
        baseline_app_path=baseline,
    )
    mapper._scip_analyzer = EmptyTargetAnalyzer()  # type: ignore[assignment]
    mapper._baseline_scip_analyzer = BaselineDeletionAnalyzer()  # type: ignore[assignment]

    affected, orphans = mapper._analyze_with_scip([diff_file], [], None)

    assert [item.endpoint.identifier for item in affected] == ["GET /items"]
    assert affected[0].endpoint.handler.file_path == target / "main.py"
    assert not orphans


def test_scip_mapper_reaches_direct_and_depends_endpoints(tmp_path: Path) -> None:
    target = tmp_path / "target"
    baseline = tmp_path / "baseline"
    target.mkdir()
    baseline.mkdir()
    (target / "services.py").write_text(
        "def calculate_total(price: float, quantity: int) -> float:\n"
        "    return round(price * quantity, 2)\n",
        encoding="utf-8",
    )
    (target / "main.py").write_text(
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
    for name in ("services.py", "main.py"):
        (baseline / name).write_text((target / name).read_text(encoding="utf-8"))
    mapper = ChangeMapper(
        target,
        use_cache=False,
        secure_ast=True,
        use_scip=True,
        baseline_app_path=baseline,
    )
    mapper._scip_analyzer = FakeSCIPAnalyzer()  # type: ignore[assignment]
    mapper._baseline_scip_analyzer = FakeSCIPAnalyzer()  # type: ignore[assignment]

    report = mapper.analyze_diff(diff)

    assert {item.endpoint.identifier for item in report.affected_endpoints} == {
        "POST /orders",
        "POST /quotes",
    }
    assert not report.orphan_changes
    assert all(item.confidence.value == "medium" for item in report.affected_endpoints)
