from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import (
    ChangeMapper,
    ChangeMapperError,
    _expanded_scip_affected,
)
from fastapi_endpoint_detector.analyzer.scip_analyzer import (
    SCIPAnalyzerError,
    SCIPDefinition,
    SCIPOccurrence,
    SCIPReverseCallEdge,
    SCIPSourceScope,
)
from fastapi_endpoint_detector.config import Config
from fastapi_endpoint_detector.models.report import (
    ConfidenceLevel,
    EvidenceStatus,
)
from fastapi_endpoint_detector.output.json_output import JsonFormatter
from fastapi_endpoint_detector.parser.diff_parser import DiffParser


def reference_edge(callee: SCIPDefinition, caller: SCIPDefinition) -> SCIPReverseCallEdge:
    return SCIPReverseCallEdge(
        caller=caller,
        callee=callee,
        occurrence=SCIPOccurrence(caller.file_path, caller.start_line),
        limitations=("Reference-only evidence does not establish execution.",),
    )


class ReferenceAnalyzerMixin:
    def source_scope(self) -> SCIPSourceScope:
        return SCIPSourceScope(
            "project_root",
            None,
            ("SCIP indexing remains project-root-wide.",),
        )

    def reverse_call_edge_limitations(self, _callee: SCIPDefinition) -> tuple[str, ...]:
        return ("Reference-only edges have LOW confidence.",)


class OverrideEdgeAnalyzer(ReferenceAnalyzerMixin):
    def ensure_index(self, *, force: bool = False) -> None:
        assert force

    def definitions_at(self, _file_path: Path, _lines: set[int]):
        return (SCIPDefinition("impl", "impl:Impl:run()", Path("impl.py"), 4, 5),)

    def base_method_definitions(self, definition: SCIPDefinition):
        if definition.symbol == "impl":
            return (SCIPDefinition("base", "base:Base:run()", Path("base.py"), 2, 3),)
        return ()

    def reverse_call_edges(self, seed: SCIPDefinition):
        if seed.symbol == "base":
            return (
                reference_edge(
                    seed,
                    SCIPDefinition("handler", "main:handler()", Path("main.py"), 4, 6),
                ),
            )
        return ()


def definition(symbol: str, *, file_path: str = "graph.py") -> SCIPDefinition:
    return SCIPDefinition(symbol, f"graph:{symbol}()", Path(file_path), 1, 2)


def test_scip_mapper_keeps_only_low_reference_edges_and_scope_limitations() -> None:
    seed = definition("seed")
    caller = definition("caller")
    handler = definition("handler")

    class ReferenceEvidenceAnalyzer:
        def __init__(self) -> None:
            self.edges = {
                seed.symbol: (
                    SimpleNamespace(
                        caller=caller,
                        execution_status="reference_only",
                        confidence="LOW",
                        occurrence=SimpleNamespace(file_path=Path("graph.py")),
                        limitations=(
                            "reference is not proof of execution",
                            "the caller may be an uninvoked deferred lambda",
                        ),
                    ),
                    SimpleNamespace(
                        caller=definition("excluded", file_path="ignored.py"),
                        execution_status="reference_only",
                        confidence="LOW",
                        occurrence=SimpleNamespace(file_path=Path("ignored.py")),
                        limitations=(),
                    ),
                    SimpleNamespace(
                        caller=definition("rejected"),
                        execution_status="reachable",
                        confidence="HIGH",
                        occurrence=SimpleNamespace(file_path=Path("graph.py")),
                        limitations=(),
                    ),
                ),
                caller.symbol: (
                    SimpleNamespace(
                        caller=handler,
                        execution_status="reference_only",
                        confidence="LOW",
                        occurrence=SimpleNamespace(file_path=Path("graph.py")),
                        limitations=("index is broader than selected files",),
                    ),
                ),
            }

        def source_scope(self):
            return SimpleNamespace(
                index_scope="project_root",
                selected_inventory_paths=("graph.py",),
                limitations=("SCIP indexes the project root",),
            )

        def reverse_call_edge_limitations(self, _callee: SCIPDefinition):
            return ("reference-only edge; LOW confidence",)

        def reverse_call_edges(self, callee: SCIPDefinition):
            return self.edges.get(callee.symbol, ())

    warnings: list[str] = []
    reached = _expanded_scip_affected(ReferenceEvidenceAnalyzer(), seed, 4, warnings)  # type: ignore[arg-type]

    assert [(item.definition.symbol, item.depth) for item in reached] == [
        ("seed", 0),
        ("caller", 1),
        ("handler", 2),
    ]
    assert "reference-only edge; LOW confidence" in reached[1].limitations
    assert "the caller may be an uninvoked deferred lambda" in reached[1].limitations
    assert "index is broader than selected files" in reached[2].limitations
    assert any("lacks reference_only/LOW" in warning for warning in warnings)
    assert any("outside the selected source inventory" in warning for warning in warnings)


class FixedPointAnalyzer(ReferenceAnalyzerMixin):
    def __init__(
        self,
        *,
        edges: dict[str, tuple[SCIPDefinition, ...]],
        bases: dict[str, tuple[SCIPDefinition, ...]],
        failing_bases: set[str] | None = None,
    ) -> None:
        self.edges = edges
        self.bases = bases
        self.failing_bases = failing_bases or set()
        self.edge_calls: list[str] = []
        self.bridge_calls: list[str] = []

    def reverse_call_edges(self, seed: SCIPDefinition):
        self.edge_calls.append(seed.symbol)
        if seed.symbol in self.failing_bases:
            raise SCIPAnalyzerError(f"failed {seed.symbol}")
        return tuple(reference_edge(seed, caller) for caller in self.edges.get(seed.symbol, ()))

    def base_method_definitions(self, reached: SCIPDefinition):
        self.bridge_calls.append(reached.symbol)
        return self.bases.get(reached.symbol, ())


class SuccessiveBridgeMapperAnalyzer(FixedPointAnalyzer):
    def ensure_index(self, *, force: bool = False) -> None:
        assert force

    def definitions_at(self, file_path: Path, lines: set[int]):
        assert file_path == Path("first.py")
        assert lines == {1}
        return (definition("FirstImpl", file_path="first.py"),)


class PartiallyFailingAnalyzer(ReferenceAnalyzerMixin):
    def ensure_index(self, *, force: bool = False) -> None:
        assert force

    def definitions_at(self, file_path: Path, lines: set[int]):
        assert file_path == Path("services.py")
        assert lines == {1}
        return (
            SCIPDefinition("bad", "services:__all__", Path("services.py"), 1, 1),
            SCIPDefinition("good", "services:changed()", Path("services.py"), 1, 1),
        )

    def reverse_call_edges(self, seed: SCIPDefinition):
        if seed.symbol == "bad":
            raise SCIPAnalyzerError("ambiguous export")
        return (
            reference_edge(
                seed,
                SCIPDefinition("handler", "main:handler()", Path("main.py"), 4, 6),
            ),
        )


class BaselineDeletionAnalyzer(ReferenceAnalyzerMixin):
    def ensure_index(self, *, force: bool = False) -> None:
        assert force

    def definitions_at(self, file_path: Path, lines: set[int]):
        assert file_path == Path("services.py")
        assert lines in ({1}, {2})
        return (SCIPDefinition("removed", "services:removed()", Path("services.py"), 1, 2),)

    def reverse_call_edges(self, seed: SCIPDefinition):
        return (
            reference_edge(
                seed,
                SCIPDefinition("handler", "main:items()", Path("main.py"), 5, 7),
            ),
        )


class EmptyTargetAnalyzer(ReferenceAnalyzerMixin):
    def ensure_index(self, *, force: bool = False) -> None:
        assert force

    def definitions_at(self, _file_path: Path, _lines: set[int]):
        return ()

    def reverse_call_edges(self, _seed: SCIPDefinition):
        return ()


class FakeSCIPAnalyzer(ReferenceAnalyzerMixin):
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

    def reverse_call_edges(self, seed: SCIPDefinition):
        if seed.symbol == "changed-symbol":
            return (
                reference_edge(
                    seed,
                    SCIPDefinition(
                        "dependency-symbol", "main:quote_service()", Path("main.py"), 5, 6
                    ),
                ),
                reference_edge(
                    seed,
                    SCIPDefinition("order-symbol", "main:order()", Path("main.py"), 12, 14),
                ),
            )
        if seed.symbol == "dependency-symbol":
            return (
                reference_edge(
                    seed,
                    SCIPDefinition("quote-symbol", "main:quote()", Path("main.py"), 8, 10),
                ),
            )
        return ()


def test_programmatic_baseline_is_supported_by_mypy(tmp_path: Path) -> None:
    target = tmp_path / "target"
    baseline = tmp_path / "baseline"
    target.mkdir()
    baseline.mkdir()

    mapper = ChangeMapper(target, baseline_app_path=baseline)

    assert mapper.baseline_app_path == baseline.resolve()


def test_scip_analyzers_receive_side_specific_effective_inventories(tmp_path: Path) -> None:
    target = tmp_path / "target"
    baseline = tmp_path / "baseline"
    for root in (target, baseline):
        (root / "pkg").mkdir(parents=True)
        (root / "pkg" / "app.py").write_text("def app():\n    return 1\n")
        (root / "ignored.py").write_text("def ignored():\n    return 2\n")
    mapper = ChangeMapper(
        target,
        secure_ast=True,
        use_scip=True,
        baseline_app_path=baseline,
        config=Config(parser={"include_patterns": ["pkg/*.py"]}),
    )

    target_inventory = mapper.scip_analyzer.source_inventory
    baseline_inventory = mapper.baseline_scip_analyzer.source_inventory

    assert target_inventory is not None
    assert baseline_inventory is not None
    assert target_inventory is mapper.source_inventory
    assert baseline_inventory is mapper.baseline_source_inventory
    assert target_inventory.root == target.resolve()
    assert baseline_inventory.root == baseline.resolve()
    assert {path.relative_to(target).as_posix() for path in target_inventory.paths} == {
        "pkg/app.py"
    }
    assert {path.relative_to(baseline).as_posix() for path in baseline_inventory.paths} == {
        "pkg/app.py"
    }


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
    assert affected[0].confidence is ConfidenceLevel.LOW
    assert "depth 2" in affected[0].reason
    assert affected[0].dependency_chain == ["impl", "base", "handler"]
    assert affected[0].effect_evidence[0].status is EvidenceStatus.REACHABILITY_ONLY


def test_fixed_point_reaches_route_after_successive_bridges(tmp_path: Path) -> None:
    first = definition("FirstImpl", file_path="first.py")
    first_base = definition("FirstBase")
    second = definition("SecondImpl")
    second_base = definition("SecondBase")
    handler = SCIPDefinition("handler", "main:handler()", Path("main.py"), 5, 6)
    analyzer = SuccessiveBridgeMapperAnalyzer(
        edges={
            first_base.symbol: (second,),
            second_base.symbol: (handler,),
        },
        bases={first.symbol: (first_base,), second.symbol: (second_base,)},
    )
    (tmp_path / "first.py").write_text("def changed():\n    return 1\n")
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n\n"
        "@app.get('/result')\ndef handler():\n    return 1\n"
    )
    diff_file = DiffParser.parse_string(
        "diff --git a/first.py b/first.py\n--- a/first.py\n+++ b/first.py\n"
        "@@ -0,0 +1 @@\n+def changed(): pass\n"
    )[0]
    mapper = ChangeMapper(tmp_path, use_cache=False, secure_ast=True, use_scip=True)
    mapper._scip_analyzer = analyzer  # type: ignore[assignment]

    affected, _orphans = mapper._analyze_with_scip([diff_file], [], None)

    assert [item.endpoint.identifier for item in affected] == ["GET /result"]
    assert affected[0].confidence is ConfidenceLevel.LOW
    assert "depth 4" in affected[0].reason
    assert affected[0].dependency_chain == [
        "FirstImpl",
        "FirstBase",
        "SecondImpl",
        "SecondBase",
        "handler",
    ]


def test_fixed_point_preserves_initial_results_and_selects_minimum_depth() -> None:
    seed = definition("seed")
    native = definition("native")
    handler = definition("handler")
    base = definition("base")
    analyzer = FixedPointAnalyzer(
        edges={
            seed.symbol: (native, handler),
        },
        bases={seed.symbol: (base,), base.symbol: (handler,)},
    )

    reached = _expanded_scip_affected(analyzer, seed, 10)  # type: ignore[arg-type]

    assert [(item.definition.symbol, item.depth) for item in reached] == [
        ("seed", 0),
        ("base", 1),
        ("handler", 1),
        ("native", 1),
    ]


def test_fixed_point_cycle_terminates_without_requerying() -> None:
    first = definition("FirstImpl")
    base = definition("Base")
    analyzer = FixedPointAnalyzer(
        edges={
            first.symbol: (base,),
            base.symbol: (first,),
        },
        bases={},
    )

    reached = _expanded_scip_affected(analyzer, first, 20)  # type: ignore[arg-type]

    assert [(item.definition.symbol, item.depth) for item in reached] == [
        ("FirstImpl", 0),
        ("Base", 1),
    ]
    assert analyzer.edge_calls == ["FirstImpl", "Base"]


def test_fixed_point_honors_exact_depth_budget() -> None:
    first = definition("FirstImpl")
    first_base = definition("FirstBase")
    second = definition("SecondImpl")
    second_base = definition("SecondBase")
    handler = definition("handler")

    def run(max_depth: int) -> set[str]:
        analyzer = FixedPointAnalyzer(
            edges={
                first.symbol: (first_base,),
                first_base.symbol: (second,),
                second.symbol: (second_base,),
                second_base.symbol: (handler,),
            },
            bases={},
        )
        return {
            item.definition.symbol
            for item in _expanded_scip_affected(  # type: ignore[arg-type]
                analyzer, first, max_depth
            )
        }

    assert "handler" not in run(3)
    assert "handler" in run(4)


def test_fixed_point_collapses_duplicate_symbols_deterministically() -> None:
    seed = definition("seed")
    duplicate_late = SCIPDefinition("same", "z:same()", Path("z.py"), 4, 5)
    duplicate_early = SCIPDefinition("same", "a:same()", Path("a.py"), 1, 2)
    analyzer = FixedPointAnalyzer(
        edges={seed.symbol: (duplicate_late, duplicate_late, duplicate_early)},
        bases={},
    )

    reached = _expanded_scip_affected(analyzer, seed, 5)  # type: ignore[arg-type]

    duplicate_results = [item for item in reached if item.definition.symbol == "same"]
    assert len(duplicate_results) == 1
    assert duplicate_results[0].definition == duplicate_early
    assert duplicate_results[0].depth == 1


def test_fixed_point_bridge_failure_preserves_proven_results() -> None:
    seed = definition("seed")
    native = definition("native")
    failing_base = definition("failing_base")
    analyzer = FixedPointAnalyzer(
        edges={seed.symbol: (native,)},
        bases={seed.symbol: (failing_base,)},
        failing_bases={failing_base.symbol},
    )
    warnings: list[str] = []

    reached = _expanded_scip_affected(  # type: ignore[arg-type]
        analyzer, seed, 5, warnings
    )

    assert {item.definition.symbol for item in reached} >= {"seed", "native"}
    assert any("failed failing_base" in warning for warning in warnings)


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
    assert any("services:__all__" in warning for warning in warnings)

    report = mapper.analyze_diff(
        "diff --git a/services.py b/services.py\n"
        "new file mode 100644\n--- /dev/null\n+++ b/services.py\n"
        "@@ -0,0 +1 @@\n+def changed(): pass\n"
    )
    assert [item.endpoint.identifier for item in report.candidate_endpoints] == ["GET /items"]
    assert report.analysis_completeness == "partial"
    assert any("ambiguous export" in warning for warning in report.warnings)
    assert json.loads(JsonFormatter().format(report))["analysis_completeness"] == "partial"


def test_scip_baseline_lifecycle_failure_is_partial_on_additions_only(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/items')\ndef items():\n    return 1\n"
    )
    (target / "services.py").write_text("def changed(): pass\n")
    mapper = ChangeMapper(
        target,
        baseline_app_path=tmp_path / "missing" / "main.py",
        use_cache=False,
        secure_ast=True,
        use_scip=True,
    )
    mapper._scip_analyzer = EmptyTargetAnalyzer()  # type: ignore[assignment]
    report = mapper.analyze_diff(
        "diff --git a/services.py b/services.py\nnew file mode 100644\n"
        "--- /dev/null\n+++ b/services.py\n@@ -0,0 +1 @@\n+def changed(): pass\n"
    )
    assert report.total_endpoints == 1
    assert report.endpoint_lifecycle == []
    assert report.analysis_completeness == "partial"
    assert any("baseline endpoint lifecycle" in warning for warning in report.warnings)
    assert json.loads(JsonFormatter().format(report))["analysis_completeness"] == "partial"


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

    assert report.affected_endpoints == []
    assert {item.endpoint.identifier for item in report.candidate_endpoints} == {
        "POST /orders",
        "POST /quotes",
    }
    assert not report.orphan_changes
    assert all(item.confidence.value == "low" for item in report.candidate_endpoints)


def test_scip_mapper_keeps_depth_zero_endpoint_seed_low(tmp_path: Path) -> None:
    app_path = tmp_path / "main.py"
    app_path.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n\n"
        "@app.get('/direct')\n"
        "def handler():\n"
        "    pass\n"
        "    return 2\n",
        encoding="utf-8",
    )
    diff = tmp_path / "change.diff"
    diff.write_text(
        "diff --git a/main.py b/main.py\n"
        "--- a/main.py\n"
        "+++ b/main.py\n"
        "@@ -6,0 +7 @@\n"
        "+    return 2\n",
        encoding="utf-8",
    )

    class DirectHandlerAnalyzer(ReferenceAnalyzerMixin):
        def ensure_index(self, *, force: bool = False) -> None:
            assert force

        def definitions_at(self, file_path: Path, lines: set[int]):
            assert file_path == Path("main.py")
            assert lines == {7}
            return (SCIPDefinition("handler", "main:handler()", Path("main.py"), 5, 7),)

        def reverse_call_edges(self, _seed: SCIPDefinition):
            return ()

    mapper = ChangeMapper(tmp_path, use_cache=False, secure_ast=True, use_scip=True)
    mapper._scip_analyzer = DirectHandlerAnalyzer()  # type: ignore[assignment]

    report = mapper.analyze_diff(diff)

    assert report.affected_endpoints == []
    assert [item.endpoint.identifier for item in report.candidate_endpoints] == ["GET /direct"]
    assert report.candidate_endpoints[0].confidence is ConfidenceLevel.LOW
    assert (
        report.candidate_endpoints[0].effect_evidence[0].status is EvidenceStatus.REACHABILITY_ONLY
    )
    assert report.candidate_endpoints[0].effect_evidence[0].effect.value == "unknown"
    assert not report.orphan_changes
