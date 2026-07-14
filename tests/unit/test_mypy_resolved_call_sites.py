from __future__ import annotations

import json
from pathlib import Path

from fastapi_endpoint_detector.analyzer.mypy_analyzer import (
    EndpointDependencies,
    MypyAnalyzer,
)
from fastapi_endpoint_detector.models.effect_contract import (
    CallResolutionStatus,
    InvocationKind,
    ResolvedCallSite,
)
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointMethod,
    HandlerInfo,
)


def _endpoint(path: Path, *, line: int, name: str = "handler") -> Endpoint:
    return Endpoint(
        path="/test",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name=name,
            module=path.stem,
            file_path=path,
            line_number=line,
        ),
    )


def _site_by_spelling(sites: list[ResolvedCallSite], spelling: str) -> list[ResolvedCallSite]:
    return [site for site in sites if site.source_spelling == spelling]


def test_captures_exact_functions_constructors_and_method_kinds(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def emit() -> int:\n    return 1\n",
        encoding="utf-8",
    )
    (tmp_path / "services.py").write_text(
        "class Service:\n"
        "    @classmethod\n"
        "    def build(cls) -> int:\n        return 2\n\n"
        "    @staticmethod\n"
        "    def ping() -> int:\n        return 3\n\n"
        "    def run(self) -> int:\n        return 4\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from helpers import emit as publish\n"
        "from services import Service\n\n"
        "def handler() -> int:\n"
        "    service = Service()\n"
        "    return publish() + service.run() + Service.build() + "
        "Service.ping() + Service().run()\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=3).analyze_endpoint(_endpoint(main, line=4))
    sites = deps.get_resolved_call_sites(str(main))

    publish = _site_by_spelling(sites, "publish")[0]
    assert publish.status == CallResolutionStatus.EXACT
    assert publish.canonical_symbol is not None
    assert publish.canonical_symbol.endswith("helpers.emit")
    assert publish.invocation == InvocationKind.FUNCTION

    constructors = _site_by_spelling(sites, "Service")
    assert len(constructors) == 2
    assert all(site.invocation == InvocationKind.CONSTRUCTOR for site in constructors)
    assert len({site.column for site in constructors}) == 2

    run_sites = [site for site in sites if site.source_spelling.endswith(".run")]
    assert len(run_sites) == 2
    immediate_run = _site_by_spelling(sites, "Service().run")[0]
    assert immediate_run.invocation == InvocationKind.INSTANCE_METHOD
    assert immediate_run.canonical_symbol and immediate_run.canonical_symbol.endswith("Service.run")
    local_run = _site_by_spelling(sites, "service.run")[0]
    assert local_run.status == CallResolutionStatus.UNRESOLVED
    assert local_run.reason_code == "dynamic_receiver"

    build = _site_by_spelling(sites, "Service.build")[0]
    assert build.invocation == InvocationKind.CLASS_METHOD
    assert build.canonical_symbol and build.canonical_symbol.endswith("Service.build")

    ping = _site_by_spelling(sites, "Service.ping")[0]
    assert ping.invocation == InvocationKind.FUNCTION
    assert ping.canonical_symbol and ping.canonical_symbol.endswith("Service.ping")
    assert all(site.resolver == "mypy" and site.resolver_version for site in sites)


def test_captures_module_qualified_functions_constructors_and_methods(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def emit() -> int:\n    return 1\n\n"
        "class Service:\n"
        "    @staticmethod\n"
        "    def run() -> int:\n        return 2\n\n"
        "    def instance(self) -> int:\n        return 3\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "import helpers\n\n"
        "def handler() -> int:\n"
        "    helpers.Service()\n"
        "    return helpers.emit() + helpers.Service.run() + helpers.Service().instance()\n",
        encoding="utf-8",
    )

    sites = MypyAnalyzer(tmp_path).analyze_endpoint(_endpoint(main, line=3)).resolved_call_sites
    emit = _site_by_spelling(sites, "helpers.emit")[0]
    service = _site_by_spelling(sites, "helpers.Service")[0]
    run = _site_by_spelling(sites, "helpers.Service.run")[0]
    instance = _site_by_spelling(sites, "helpers.Service().instance")[0]

    assert emit.status == CallResolutionStatus.EXACT
    assert emit.canonical_symbol and emit.canonical_symbol.endswith("helpers.emit")
    assert emit.invocation == InvocationKind.FUNCTION
    assert service.status == CallResolutionStatus.EXACT
    assert service.canonical_symbol and service.canonical_symbol.endswith("helpers.Service")
    assert service.invocation == InvocationKind.CONSTRUCTOR
    assert run.status == CallResolutionStatus.EXACT
    assert run.canonical_symbol and run.canonical_symbol.endswith("helpers.Service.run")
    assert run.invocation == InvocationKind.FUNCTION
    assert instance.status == CallResolutionStatus.EXACT
    assert instance.canonical_symbol and instance.canonical_symbol.endswith(
        "helpers.Service.instance"
    )
    assert instance.invocation == InvocationKind.INSTANCE_METHOD


def test_module_suffix_resolution_fails_closed_when_project_identity_is_ambiguous(
    tmp_path: Path,
) -> None:
    for package in ("one", "two"):
        directory = tmp_path / package
        directory.mkdir()
        (directory / "helpers.py").write_text(
            "def emit() -> int:\n    return 1\n",
            encoding="utf-8",
        )
    main = tmp_path / "main.py"
    main.write_text("def handler() -> int:\n    return 1\n", encoding="utf-8")
    analyzer = MypyAnalyzer(tmp_path)
    analyzer.analyze_endpoint(_endpoint(main, line=1))

    assert analyzer._canonical_project_fullname("helpers.emit") is None


def test_captures_canonical_identity_through_explicit_reexports(tmp_path: Path) -> None:
    (tmp_path / "implementations.py").write_text(
        "def emit() -> int:\n    return 1\n\nclass Service:\n    pass\n",
        encoding="utf-8",
    )
    (tmp_path / "api.py").write_text(
        "from implementations import Service, emit\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from api import Service, emit\n\n"
        "def handler() -> int:\n"
        "    Service()\n"
        "    return emit()\n",
        encoding="utf-8",
    )

    sites = MypyAnalyzer(tmp_path).analyze_endpoint(_endpoint(main, line=3)).resolved_call_sites
    emit = _site_by_spelling(sites, "emit")[0]
    service = _site_by_spelling(sites, "Service")[0]

    assert emit.status == CallResolutionStatus.EXACT
    assert emit.canonical_symbol and emit.canonical_symbol.endswith("implementations.emit")
    assert emit.invocation == InvocationKind.FUNCTION
    assert service.status == CallResolutionStatus.EXACT
    assert service.canonical_symbol and service.canonical_symbol.endswith("implementations.Service")
    assert service.invocation == InvocationKind.CONSTRUCTOR


def test_union_receiver_is_ambiguous_when_implementations_differ(tmp_path: Path) -> None:
    main = tmp_path / "main.py"
    main.write_text(
        "class First:\n"
        "    def run(self) -> int:\n        return 1\n\n"
        "class Second:\n"
        "    def run(self) -> int:\n        return 2\n\n"
        "def handler(value: First | Second) -> int:\n"
        "    return value.run()\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path).analyze_endpoint(_endpoint(main, line=9))
    site = _site_by_spelling(deps.resolved_call_sites, "value.run")[0]

    assert site.status == CallResolutionStatus.AMBIGUOUS
    assert site.reason_code == "ambiguous_receiver"
    assert site.canonical_symbol is None
    assert site.invocation is None
    assert len(site.receiver_candidates) == 2
    assert site.receiver_candidates == tuple(sorted(site.receiver_candidates))


def test_union_receiver_with_common_inherited_method_is_exact(tmp_path: Path) -> None:
    main = tmp_path / "main.py"
    main.write_text(
        "class Base:\n"
        "    def run(self) -> int:\n        return 1\n\n"
        "class First(Base):\n    pass\n\n"
        "class Second(Base):\n    pass\n\n"
        "def handler(value: First | Second) -> int:\n"
        "    return value.run()\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path).analyze_endpoint(_endpoint(main, line=10))
    site = _site_by_spelling(deps.resolved_call_sites, "value.run")[0]

    assert site.status == CallResolutionStatus.EXACT
    assert site.canonical_symbol and site.canonical_symbol.endswith("Base.run")
    assert site.invocation == InvocationKind.INSTANCE_METHOD
    assert len(site.receiver_candidates) == 2


def test_import_map_does_not_override_lexically_shadowed_names(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def emit() -> int:\n    return 1\n\nclass Service:\n    pass\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from typing import Any\n"
        "import helpers as helper_module\n"
        "from helpers import Service, emit\n\n"
        "def handler(emit: Any, Service: Any, helper_module: Any) -> int:\n"
        "    emit()\n"
        "    Service()\n"
        "    Service.run()\n"
        "    Service().run()\n"
        "    helper_module.emit()\n"
        "    return 1\n",
        encoding="utf-8",
    )

    sites = MypyAnalyzer(tmp_path).analyze_endpoint(_endpoint(main, line=5)).resolved_call_sites
    emit = _site_by_spelling(sites, "emit")[0]
    service_calls = _site_by_spelling(sites, "Service")
    member_calls = [
        site
        for site in sites
        if site.source_spelling.endswith(".run") or site.source_spelling == "helper_module.emit"
    ]

    assert emit.status == CallResolutionStatus.UNRESOLVED
    assert emit.reason_code == "dynamic_callable"
    assert all(site.status == CallResolutionStatus.UNRESOLVED for site in service_calls)
    assert all(site.reason_code == "dynamic_callable" for site in service_calls)
    assert all(site.status == CallResolutionStatus.UNRESOLVED for site in member_calls)
    assert all(site.reason_code == "dynamic_receiver" for site in member_calls)
    assert all(site.canonical_symbol is None for site in [emit, *service_calls, *member_calls])


def test_overloaded_static_and_class_methods_preserve_invocation_kind(tmp_path: Path) -> None:
    main = tmp_path / "main.py"
    main.write_text(
        "from typing import overload\n\n"
        "class Service:\n"
        "    @staticmethod\n"
        "    @overload\n"
        "    def parse(value: int) -> int: ...\n"
        "    @staticmethod\n"
        "    @overload\n"
        "    def parse(value: str) -> str: ...\n"
        "    @staticmethod\n"
        "    def parse(value: object) -> object:\n        return value\n\n"
        "    @classmethod\n"
        "    @overload\n"
        "    def build(cls, value: int) -> int: ...\n"
        "    @classmethod\n"
        "    @overload\n"
        "    def build(cls, value: str) -> str: ...\n"
        "    @classmethod\n"
        "    def build(cls, value: object) -> object:\n        return value\n\n"
        "def handler() -> object:\n"
        "    Service.parse(1)\n"
        "    return Service.build('x')\n",
        encoding="utf-8",
    )

    sites = MypyAnalyzer(tmp_path).analyze_endpoint(_endpoint(main, line=24)).resolved_call_sites
    parse = _site_by_spelling(sites, "Service.parse")[0]
    build = _site_by_spelling(sites, "Service.build")[0]

    assert parse.status == CallResolutionStatus.EXACT
    assert parse.invocation == InvocationKind.FUNCTION
    assert build.status == CallResolutionStatus.EXACT
    assert build.invocation == InvocationKind.CLASS_METHOD


def test_dynamic_callable_and_receiver_remain_unresolved(tmp_path: Path) -> None:
    main = tmp_path / "main.py"
    main.write_text(
        "from typing import Any, Callable\n\n"
        "def handler(callback: Callable[[], int], client: Any) -> int:\n"
        "    callback()\n"
        "    client.send()\n"
        "    return 1\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path).analyze_endpoint(_endpoint(main, line=3))
    callback = _site_by_spelling(deps.resolved_call_sites, "callback")[0]
    send = _site_by_spelling(deps.resolved_call_sites, "client.send")[0]

    assert callback.status == CallResolutionStatus.UNRESOLVED
    assert callback.reason_code == "dynamic_callable"
    assert send.status == CallResolutionStatus.UNRESOLVED
    assert send.reason_code == "dynamic_receiver"
    assert callback.canonical_symbol is None and send.canonical_symbol is None


def test_external_library_internals_are_not_recorded_as_project_call_sites(
    tmp_path: Path,
) -> None:
    main = tmp_path / "main.py"
    main.write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "@app.get('/')\n"
        "def handler() -> int:\n"
        "    return 1\n",
        encoding="utf-8",
    )

    sites = MypyAnalyzer(tmp_path).analyze_endpoint(_endpoint(main, line=6)).resolved_call_sites

    assert sites
    assert all(Path(site.file_path).resolve().is_relative_to(tmp_path) for site in sites)


def test_synthetic_mypy_calls_without_source_spans_are_not_recorded(tmp_path: Path) -> None:
    main = tmp_path / "main.py"
    main.write_text(
        "def format_value(value: object) -> str:\n"
        "    return f'{value}'\n\n"
        "def handler() -> str:\n"
        "    return format_value(1)\n",
        encoding="utf-8",
    )

    sites = MypyAnalyzer(tmp_path).analyze_endpoint(_endpoint(main, line=4)).resolved_call_sites

    assert [site.source_spelling for site in sites] == ["format_value"]


def test_utf8_byte_columns_and_same_line_calls_keep_physical_identity(tmp_path: Path) -> None:
    main = tmp_path / "main.py"
    main.write_text(
        "def emit() -> int:\n    return 1\n\n"
        "def handler() -> int:\n"
        "    label = 'é'; return emit() + emit()\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path).analyze_endpoint(_endpoint(main, line=4))
    sites = _site_by_spelling(deps.get_resolved_call_sites(str(main)), "emit")

    assert len(sites) == 2
    assert sites[0].line == sites[1].line == 5
    assert sites[0].column != sites[1].column
    source = main.read_bytes().splitlines()[4]
    for site in sites:
        assert site.end_column is not None
        assert source[site.column : site.end_column].decode("utf-8") == "emit"


def test_dependency_query_filters_status_and_fails_closed_on_ambiguous_suffixes(
    tmp_path: Path,
) -> None:
    first = tmp_path / "one" / "service.py"
    second = tmp_path / "two" / "service.py"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_text("pass\n")
    second.write_text("pass\n")
    exact = ResolvedCallSite(
        file_path=str(first),
        line=1,
        column=0,
        source_spelling="run",
        canonical_symbol="one.service.run",
        invocation=InvocationKind.FUNCTION,
        status=CallResolutionStatus.EXACT,
        resolver="mypy",
        resolver_version="1.19.1",
    )
    unresolved = ResolvedCallSite(
        file_path=str(second),
        line=1,
        column=0,
        source_spelling="run",
        status=CallResolutionStatus.UNRESOLVED,
        resolver="mypy",
        resolver_version="1.19.1",
        reason_code="dynamic_callable",
    )
    deps = EndpointDependencies(
        endpoint_id="GET /test",
        methods=["GET"],
        path="/test",
        resolved_call_sites=[unresolved, exact],
        source_root=str(tmp_path),
        project_files={str(first), str(second)},
    )

    assert deps.get_resolved_call_sites("service.py") == []
    assert deps.get_resolved_call_sites(str(first)) == [exact]
    assert deps.get_resolved_call_sites(status=CallResolutionStatus.UNRESOLVED) == [unresolved]
    returned = deps.get_resolved_call_sites()
    returned.clear()
    assert len(deps.resolved_call_sites) == 2


def test_resolved_call_sites_round_trip_through_cache(tmp_path: Path) -> None:
    source = tmp_path / "main.py"
    source.write_text("def handler() -> int:\n    return len([])\n", encoding="utf-8")
    endpoint = _endpoint(source, line=1)
    cache = tmp_path / "cache.json"
    analyzer = MypyAnalyzer(tmp_path)
    analyzer.set_cache_path(cache)
    expected = analyzer.analyze_endpoint(endpoint).get_resolved_call_sites()
    analyzer._save_cache()

    payload = json.loads(cache.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 8
    assert payload["endpoints"][analyzer._endpoint_key(endpoint)]["resolved_call_sites"]

    loaded = MypyAnalyzer(tmp_path)
    loaded.set_cache_path(cache)
    assert loaded._load_cache()
    assert loaded.get_resolved_call_sites(endpoint) == expected

    payload["endpoints"][analyzer._endpoint_key(endpoint)].pop("resolved_call_sites")
    cache.write_text(json.dumps(payload), encoding="utf-8")
    malformed = MypyAnalyzer(tmp_path)
    malformed.set_cache_path(cache)
    assert not malformed._load_cache()
    assert malformed._endpoint_deps == {}
