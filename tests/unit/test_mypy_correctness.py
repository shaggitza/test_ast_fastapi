"""Regression tests for conservative mypy path, depth, and cache semantics."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.mypy_analyzer import (
    EndpointDependencies,
    MypyAnalyzer,
)
from fastapi_endpoint_detector.config import AnalysisConfig, Config, ParserConfig
from fastapi_endpoint_detector.models.diff import ChangeType, DiffFile
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


def _endpoint(main: Path) -> Endpoint:
    return Endpoint(
        path="/chain",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="handler", module="main", file_path=main, line_number=3),
    )


def test_adjacent_new_definition_does_not_inherit_previous_function_evidence(
    tmp_path: Path,
) -> None:
    source = tmp_path / "events.py"
    source.write_text("def previous():\n    return 1\n\ndef added():\n    return 2\n")
    endpoint = Endpoint(
        path="/events",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler", module="main", file_path=tmp_path / "main.py", line_number=1
        ),
    )
    deps = EndpointDependencies(
        endpoint_id=endpoint.identifier,
        methods=["GET"],
        path=endpoint.path,
        source_root=str(tmp_path),
        project_files={str(source)},
    )
    deps.add_symbol_reference(str(source), "events.previous", 1, 2)

    class FakeAnalyzer:
        def get_endpoint_dependencies(self, _endpoint: Endpoint) -> EndpointDependencies:
            return deps

    mapper = ChangeMapper(tmp_path)
    mapper._mypy_analyzer = FakeAnalyzer()  # type: ignore[assignment]
    diff_file = DiffFile(path=Path("events.py"), change_type=ChangeType.MODIFIED)

    assert mapper._check_mypy_dependency(endpoint, diff_file, [4, 5], []) is None
    assert mapper._check_mypy_dependency(endpoint, diff_file, [2], []) is not None


def test_duplicate_basenames_fail_closed_but_unique_suffix_resolves(tmp_path: Path) -> None:
    first = tmp_path / "pkg_a" / "models" / "user.py"
    second = tmp_path / "pkg_b" / "models" / "user.py"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    first.write_text("a = 1\n")
    second.write_text("b = 1\n")
    deps = EndpointDependencies(
        endpoint_id="GET /",
        methods=["GET"],
        path="/",
        source_root=str(tmp_path),
        project_files={str(first), str(second)},
    )
    deps.add_reference(str(first), 1)
    deps.add_reference(str(second), 1)

    assert not deps.references_file("user.py")
    assert deps.references_lines("user.py", {1}) == set()
    assert deps.references_file("pkg_a/models/user.py")
    assert deps.references_lines("pkg_a\\models\\user.py", {1}) == {1}


def test_effective_mypy_depth_matches_configuration(tmp_path: Path) -> None:
    direct = ChangeMapper(
        tmp_path,
        config=Config(
            parser=ParserConfig(max_depth=7),
            analysis=AnalysisConfig(track_transitive=False),
        ),
    )
    transitive = ChangeMapper(
        tmp_path,
        config=Config(
            parser=ParserConfig(max_depth=7),
            analysis=AnalysisConfig(track_transitive=True),
        ),
    )

    assert direct.mypy_analyzer.max_depth == 1
    assert transitive.mypy_analyzer.max_depth == 7
    with pytest.raises(ValidationError):
        ParserConfig(max_depth=0)


def test_mypy_traversal_stops_at_effective_depth(tmp_path: Path) -> None:
    (tmp_path / "levels.py").write_text(
        "def third() -> int:\n    return 3\n\n"
        "def second() -> int:\n    return third()\n\n"
        "def first() -> int:\n    return second()\n"
    )
    main = tmp_path / "main.py"
    main.write_text("from levels import first\n\ndef handler() -> int:\n    return first()\n")

    shallow = MypyAnalyzer(tmp_path, max_depth=1).analyze_endpoint(_endpoint(main))
    deep = MypyAnalyzer(tmp_path, max_depth=3).analyze_endpoint(_endpoint(main))

    assert shallow.references_symbol_at_line("levels.py", 7) is not None
    assert shallow.references_symbol_at_line("levels.py", 4) is None
    assert deep.references_symbol_at_line("levels.py", 4) is not None
    assert deep.references_symbol_at_line("levels.py", 1) is not None


def test_depth_traversal_is_independent_of_first_encounter_order(tmp_path: Path) -> None:
    (tmp_path / "graph.py").write_text(
        "def leaf() -> int:\n    return 1\n\n"
        "def shared() -> int:\n    return leaf()\n\n"
        "def detour() -> int:\n    return shared()\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from graph import detour, shared\n\n"
        "def handler() -> int:\n    return detour() + shared()\n"
    )

    deps = MypyAnalyzer(tmp_path, max_depth=2).analyze_endpoint(_endpoint(main))

    assert deps.references_symbol_at_line("graph.py", 1) is not None


def test_handler_line_disambiguates_duplicate_class_methods(tmp_path: Path) -> None:
    (tmp_path / "deps.py").write_text(
        "def dep_a() -> int:\n    return 1\n\ndef dep_b() -> int:\n    return 2\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from deps import dep_a, dep_b\n\n"
        "class First:\n"
        "    def run(self) -> int:\n"
        "        return dep_a()\n\n"
        "class Second:\n"
        "    def run(self) -> int:\n"
        "        return dep_b()\n"
    )
    endpoint = Endpoint(
        path="/second",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="run",
            module="main",
            file_path=main,
            line_number=8,
            end_line_number=9,
        ),
    )

    deps = MypyAnalyzer(tmp_path).analyze_endpoint(endpoint)

    assert deps.references_symbol_at_line("deps.py", 4) is not None
    assert deps.references_symbol_at_line("deps.py", 1) is None


def test_decorator_line_disambiguates_duplicate_class_handlers(tmp_path: Path) -> None:
    (tmp_path / "deps.py").write_text(
        "def dep_a() -> int:\n    return 1\n\ndef dep_b() -> int:\n    return 2\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from deps import dep_a, dep_b\n\n"
        "def deco(func):\n    return func\n\n"
        "class First:\n    @deco\n    def run(self) -> int:\n        return dep_a()\n\n"
        "class Second:\n    @deco\n    def run(self) -> int:\n        return dep_b()\n"
    )
    endpoint = Endpoint(
        path="/decorated",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="run", module="main", file_path=main, line_number=12),
    )

    deps = MypyAnalyzer(tmp_path).analyze_endpoint(endpoint)

    assert deps.references_symbol_at_line("deps.py", 4) is not None
    assert deps.references_symbol_at_line("deps.py", 1) is None


def test_imported_class_method_calls_resolve_exactly(tmp_path: Path) -> None:
    (tmp_path / "deps.py").write_text("def dep() -> int:\n    return 1\n")
    (tmp_path / "services.py").write_text(
        "from deps import dep\n\n"
        "class Static:\n    @staticmethod\n    def run() -> int:\n        return dep()\n\n"
        "class Instance:\n    def run(self) -> int:\n        return dep()\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from services import Instance, Static\n\n"
        "def handler() -> int:\n    return Static.run() + Instance().run()\n"
    )

    deps = MypyAnalyzer(tmp_path, max_depth=3).analyze_endpoint(_endpoint(main))

    assert deps.references_symbol_at_line("services.py", 5) is not None
    assert deps.references_symbol_at_line("services.py", 9) is not None
    assert deps.references_symbol_at_line("deps.py", 1) is not None


def test_cache_rejects_source_edits_depth_changes_legacy_and_malformed(
    tmp_path: Path,
) -> None:
    source = tmp_path / "main.py"
    source.write_text("value = 1\n")
    cache = tmp_path / "cache.json"
    analyzer = MypyAnalyzer(tmp_path, max_depth=2)
    analyzer.set_cache_path(cache)
    analyzer._endpoint_deps["GET /"] = EndpointDependencies(
        endpoint_id="GET /", methods=["GET"], path="/"
    )
    analyzer._save_cache()

    assert MypyAnalyzer(tmp_path, max_depth=2)._cache_fingerprint() == analyzer._cache_fingerprint()
    same = MypyAnalyzer(tmp_path, max_depth=2)
    same.set_cache_path(cache)
    assert same._load_cache()

    source.write_text("value = 2\n")
    edited = MypyAnalyzer(tmp_path, max_depth=2)
    edited.set_cache_path(cache)
    assert not edited._load_cache()

    source.write_text("value = 1\n")
    different_depth = MypyAnalyzer(tmp_path, max_depth=3)
    different_depth.set_cache_path(cache)
    assert not different_depth._load_cache()

    cache.write_text(json.dumps({"GET /": {}}))
    assert not same._load_cache()
    cache.write_text("not-json")
    assert not same._load_cache()


def test_cache_keys_same_route_by_physical_handler(tmp_path: Path) -> None:
    (tmp_path / "deps.py").write_text(
        "def dep_a() -> int:\n    return 1\n\ndef dep_b() -> int:\n    return 2\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from deps import dep_a, dep_b\n\n"
        "def handler_a() -> int:\n    return dep_a()\n\n"
        "def handler_b() -> int:\n    return dep_b()\n"
    )
    endpoint_a = Endpoint(
        path="/same",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="handler_a", module="main", file_path=main, line_number=3),
    )
    endpoint_b = Endpoint(
        path="/same",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="handler_b", module="main", file_path=main, line_number=6),
    )
    cache = tmp_path / "cache.json"
    first = MypyAnalyzer(tmp_path)
    first.set_cache_path(cache)
    first.analyze_endpoints([endpoint_a])

    second = MypyAnalyzer(tmp_path)
    second.set_cache_path(cache)
    second.analyze_endpoints([endpoint_b])
    deps = second.get_endpoint_dependencies(endpoint_b)

    assert deps is not None
    assert deps.references_symbol_at_line("deps.py", 4) is not None
    assert deps.references_symbol_at_line("deps.py", 1) is None


def test_cache_rejects_sibling_project_and_malformed_nested_data(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "main.py").write_text("value = 1\n")
    (second / "main.py").write_text("value = 1\n")
    shared_cache = tmp_path / "shared.json"

    original = MypyAnalyzer(first)
    original.set_cache_path(shared_cache)
    original._endpoint_deps["GET /"] = EndpointDependencies(
        endpoint_id="GET /", methods=["GET"], path="/"
    )
    original._save_cache()

    sibling = MypyAnalyzer(second)
    sibling.set_cache_path(shared_cache)
    assert not sibling._load_cache()

    fingerprint, sources = original._cache_fingerprint()
    shared_cache.write_text(
        json.dumps(
            {
                "schema_version": original.CACHE_SCHEMA_VERSION,
                "fingerprint": fingerprint,
                "metadata": {"source_root": str(first), "sources": sources},
                "endpoints": {
                    "GET /": {
                        "methods": ["GET"],
                        "path": "/",
                        "referenced_files": {},
                        "referenced_symbols": [],
                        "call_stacks": [],
                    }
                },
            }
        )
    )
    assert not original._load_cache()
