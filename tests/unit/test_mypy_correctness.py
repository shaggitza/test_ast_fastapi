"""Regression tests for conservative mypy path, depth, and cache semantics."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.mypy_analyzer import (
    CallFrame,
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


def test_shared_project_path_index_is_enumerated_and_resolved_once(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "pkg" / "service.py"
    source.parent.mkdir()
    source.write_text("value = 1\n")
    original_rglob = Path.rglob
    enumerations = 0

    def counted_rglob(path: Path, pattern: str):
        nonlocal enumerations
        enumerations += 1
        return original_rglob(path, pattern)

    monkeypatch.setattr(Path, "rglob", counted_rglob)
    analyzer = MypyAnalyzer(tmp_path)
    index = analyzer._project_path_index()
    dependencies = []
    for number in range(250):
        deps = EndpointDependencies(
            endpoint_id=f"GET /{number}",
            methods=["GET"],
            path=f"/{number}",
            source_root=str(tmp_path),
            project_files=index.project_files,
            _path_index=index,
        )
        deps.add_reference(str(source), 1)
        deps.add_symbol_reference(str(source), "pkg.service", 1, 1)
        deps.call_stacks[str(source)] = [[CallFrame(str(source), 1, "service")]]
        dependencies.append(deps)

    for deps in dependencies:
        assert deps.references_lines("pkg/service.py", {1}) == {1}
        assert deps.references_lines("pkg/service.py", {1}) == {1}
        assert deps.references_symbol_at_line("pkg/service.py", 1) is not None
        assert deps.get_call_stack("pkg/service.py")

    assert enumerations == 1
    assert len(index._query_cache) == 1
    assert all(deps._path_index is index for deps in dependencies)
    assert all(
        set(deps._canonical_key_indexes)
        == {"referenced_files", "referenced_symbols", "call_stacks"}
        for deps in dependencies
    )
    assert all(
        all(len(category) == 1 for category in deps._canonical_key_indexes.values())
        for deps in dependencies
    )


def test_dependency_category_keys_are_scanned_only_once(tmp_path: Path) -> None:
    source = tmp_path / "service.py"
    source.write_text("value = 1\n")
    iterations = 0

    class CountingDict(dict[str, set[int]]):
        def __iter__(self):
            nonlocal iterations
            iterations += 1
            return super().__iter__()

    deps = EndpointDependencies(
        endpoint_id="GET /",
        methods=["GET"],
        path="/",
        source_root=str(tmp_path),
        project_files={str(source)},
        referenced_files=CountingDict({str(source): {1}}),
    )

    assert deps.references_lines("service.py", {1}) == {1}
    first_iterations = iterations
    assert deps.references_lines("service.py", {1}) == {1}
    assert iterations == first_iterations


def test_project_path_index_reuses_built_module_inventory(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "pkg" / "service.py"
    source.parent.mkdir()
    source.write_text("value = 1\n")
    analyzer = MypyAnalyzer(tmp_path)
    analyzer._module_to_path = {"pkg.service": str(source)}

    monkeypatch.setattr(
        Path,
        "rglob",
        lambda *_args, **_kwargs: pytest.fail("built inventory must avoid rglob"),
    )

    assert analyzer._project_path_index().project_files == frozenset({str(source.resolve())})


def test_shared_query_cache_is_bounded(tmp_path: Path) -> None:
    source = tmp_path / "service.py"
    source.write_text("value = 1\n")
    index = MypyAnalyzer(tmp_path)._project_path_index()

    for number in range(1100):
        index.resolve(f"missing-{number}.py")

    assert len(index._query_cache) == index._MAX_QUERY_CACHE
    assert "missing-0.py" not in index._query_cache
    assert "missing-1099.py" in index._query_cache


def test_normal_analysis_reuses_build_inventory_and_handler_reverse_index(
    tmp_path: Path, monkeypatch
) -> None:
    main = tmp_path / "main.py"
    main.write_text("def handler() -> int:\n    return 1\n")
    endpoint = Endpoint(
        path="/",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="handler", module="main", file_path=main, line_number=1),
    )
    original_rglob = Path.rglob
    enumerations = 0

    def counted_rglob(path: Path, pattern: str):
        nonlocal enumerations
        enumerations += 1
        return original_rglob(path, pattern)

    monkeypatch.setattr(Path, "rglob", counted_rglob)
    analyzer = MypyAnalyzer(tmp_path)
    deps = analyzer.analyze_endpoint(endpoint)

    assert deps.references_symbol_at_line("main.py", 1) is not None
    assert enumerations == 1
    assert any(
        module.endswith(".main") or module == "main"
        for module in analyzer._modules_by_canonical_path[str(main.resolve())]
    )

    class NoItems(dict[str, str]):
        def items(self):
            pytest.fail("handler resolution must not scan module paths")

    analyzer._module_to_path = NoItems(analyzer._module_to_path)
    assert analyzer.analyze_endpoint(endpoint).references_symbol_at_line("main.py", 1)


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
    assert deps.references_lines(str(first.resolve()), {1}) == {1}
    assert not deps.references_file("missing.py")
    assert deps.references_lines("missing.py", {1}) == set()


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


def test_annotated_dependency_alias_traces_provider_and_nested_calls(tmp_path: Path) -> None:
    dependencies = tmp_path / "dependencies.py"
    dependencies.write_text(
        "from typing import Annotated\nfrom fastapi import Depends\n\n"
        "def nested() -> int:\n    return 1\n\n"
        "def provider(value: Annotated[int, Depends(nested)]) -> int:\n    return value\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from typing import Annotated\n"
        "from fastapi import Depends\n"
        "from dependencies import provider\n\n"
        "Provider = Annotated[int, Depends(provider)]\n\n"
        "def handler(value: Provider) -> int:\n    return value\n"
    )
    endpoint = Endpoint(
        path="/annotated",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler", module="main", file_path=main, line_number=7, end_line_number=8
        ),
    )

    deps = MypyAnalyzer(tmp_path, max_depth=3).analyze_endpoint(endpoint)

    assert deps.references_symbol_at_line("dependencies.py", 7) is not None
    assert deps.references_symbol_at_line("dependencies.py", 4) is not None


def test_imported_global_is_referenced_at_definition(tmp_path: Path) -> None:
    config = tmp_path / "config.py"
    config.write_text("DEFAULT = {'used': 1}\nUNRELATED = 2\n")
    main = tmp_path / "main.py"
    main.write_text(
        "from config import DEFAULT\n\ndef handler() -> int:\n    return DEFAULT['used']\n"
    )

    deps = MypyAnalyzer(tmp_path).analyze_endpoint(_endpoint(main))

    assert deps.references_symbol_at_line("config.py", 1) is not None
    assert deps.references_symbol_at_line("config.py", 2) is None


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


def test_constructor_does_not_reference_unrelated_class_methods(tmp_path: Path) -> None:
    services = tmp_path / "services.py"
    services.write_text(
        "class Service:\n"
        "    def __init__(self) -> None:\n        self.ready = True\n\n"
        "    def used(self) -> int:\n        return 1\n\n"
        "    def unused(self) -> int:\n        return 2\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from services import Service\n\ndef handler() -> int:\n    return Service().used()\n"
    )

    deps = MypyAnalyzer(tmp_path, max_depth=3).analyze_endpoint(_endpoint(main))

    assert deps.references_symbol_at_line("services.py", 2) is not None
    assert deps.references_symbol_at_line("services.py", 5) is not None
    assert deps.references_symbol_at_line("services.py", 8) is None


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

    initial_fingerprint = analyzer._cache_fingerprint()
    assert MypyAnalyzer(tmp_path, max_depth=2)._cache_fingerprint() == initial_fingerprint

    added = tmp_path / "added.py"
    added.write_text("added = True\n")
    assert analyzer._cache_fingerprint() != initial_fingerprint
    added.unlink()
    assert analyzer._cache_fingerprint() == initial_fingerprint

    outside = tmp_path.parent / "outside-mypy-fingerprint.py"
    outside.write_text("outside = True\n")
    symlink = tmp_path / "escape.py"
    symlink.symlink_to(outside)
    assert analyzer._cache_fingerprint() == initial_fingerprint
    symlink.unlink()
    outside.unlink()
    same = MypyAnalyzer(tmp_path, max_depth=2)
    same.set_cache_path(cache)
    assert same._load_cache()
    loaded = same.get_endpoint_dependencies("GET /")
    assert loaded is not None
    assert loaded._path_index is same._project_path_index()
    assert loaded.project_files is loaded._path_index.project_files

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
