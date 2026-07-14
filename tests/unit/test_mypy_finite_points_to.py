"""Conservative LOW-only finite points-to propagation regressions."""

from pathlib import Path

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.diff import ChangeType, DiffFile
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointMethod,
    HandlerInfo,
)
from fastapi_endpoint_detector.models.report import ConfidenceLevel


def _endpoint(main: Path, *, line: int = 3) -> Endpoint:
    return Endpoint(
        path="/finite",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler",
            module="main",
            file_path=main,
            line_number=line,
        ),
    )


def _write_service(root: Path) -> Path:
    service = root / "services.py"
    service.write_text(
        "class Service:\n"
        "    def changed(self) -> int:\n"
        "        return 1\n\n"
        "    def unrelated(self) -> int:\n"
        "        return 2\n",
        encoding="utf-8",
    )
    return service


def test_independent_standard_path_dominates_low_reference_provenance(
    tmp_path: Path,
) -> None:
    service = _write_service(tmp_path)
    deps = MypyAnalyzer(tmp_path).analyze_endpoint(
        Endpoint(
            path="/direct",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(
                name="changed",
                module="services",
                file_path=service,
                line_number=2,
            ),
        )
    )
    deps.add_symbol_reference(
        str(service),
        "services.Service.changed",
        2,
        3,
        low_confidence=True,
    )

    assert not deps.references_lines_low_only("services.py", {2})


def test_local_constructor_and_alias_reach_only_exact_receiver_at_low(
    tmp_path: Path,
) -> None:
    service = _write_service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "from services import Service\n\n"
        "def handler() -> int:\n"
        "    original = Service()\n"
        "    alias = original\n"
        "    return alias.changed()\n",
        encoding="utf-8",
    )

    endpoint = _endpoint(main)
    deps = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(endpoint)

    assert deps.references_symbol_at_line("services.py", 2) is not None
    assert deps.references_symbol_at_line("services.py", 5) is None
    assert deps.references_lines_low_only("services.py", {2})

    mapper = ChangeMapper(tmp_path)
    mapper._mypy_analyzer = type(
        "FakeAnalyzer",
        (),
        {"get_endpoint_dependencies": lambda _self, _endpoint: deps},
    )()
    affected = mapper._check_mypy_dependency(
        endpoint,
        DiffFile(path=service.relative_to(tmp_path), change_type=ChangeType.MODIFIED),
        [2],
        [],
    )
    assert affected is not None
    assert affected.confidence == ConfidenceLevel.LOW


def test_imported_module_global_constructor_is_a_finite_receiver(tmp_path: Path) -> None:
    _write_service(tmp_path)
    clients = tmp_path / "clients.py"
    clients.write_text(
        "from services import Service\n\nCLIENT = Service()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from clients import CLIENT\n\ndef handler() -> int:\n    return CLIENT.changed()\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main))

    assert deps.references_symbol_at_line("services.py", 2) is not None
    assert deps.references_symbol_at_line("services.py", 5) is None
    assert deps.references_lines_low_only("services.py", {2})


def test_finite_factory_return_propagates_without_other_method_fanout(
    tmp_path: Path,
) -> None:
    _write_service(tmp_path)
    factory = tmp_path / "factory.py"
    factory.write_text(
        "from services import Service\n\ndef build():\n    value = Service()\n    return value\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from factory import build\n\n"
        "def handler() -> int:\n"
        "    service = build()\n"
        "    return service.changed()\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main))

    assert deps.references_symbol_at_line("services.py", 2) is not None
    assert deps.references_symbol_at_line("services.py", 5) is None
    assert deps.references_lines_low_only("services.py", {2})


def test_factory_joins_all_finite_return_paths_before_dispatch(tmp_path: Path) -> None:
    implementations = tmp_path / "implementations.py"
    implementations.write_text(
        "class Base:\n"
        "    def run(self) -> int:\n"
        "        return 1\n\n"
        "class First(Base):\n"
        "    pass\n\n"
        "class Second(Base):\n"
        "    pass\n",
        encoding="utf-8",
    )
    factory = tmp_path / "factory.py"
    factory.write_text(
        "from implementations import First, Second\n\n"
        "def build(flag: bool):\n"
        "    if flag:\n"
        "        return First()\n"
        "    return Second()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from factory import build\n\n"
        "def handler(flag: bool) -> int:\n"
        "    service = build(flag)\n"
        "    return service.run()\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main))

    assert deps.references_symbol_at_line("implementations.py", 2) is not None
    assert deps.references_lines_low_only("implementations.py", {2})


def test_constructor_parameter_to_self_field_delegation_is_finite_and_low(
    tmp_path: Path,
) -> None:
    _write_service(tmp_path)
    wrapper = tmp_path / "wrapper.py"
    wrapper.write_text(
        "class Wrapper:\n"
        "    def __init__(self, service):\n"
        "        self.service = service\n\n"
        "    def run(self) -> int:\n"
        "        return self.service.changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from services import Service\n"
        "from wrapper import Wrapper\n\n"
        "def handler() -> int:\n"
        "    wrapper = Wrapper(Service())\n"
        "    return wrapper.run()\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=6).analyze_endpoint(_endpoint(main, line=4))

    assert deps.references_symbol_at_line("wrapper.py", 5) is not None
    assert deps.references_symbol_at_line("services.py", 2) is not None
    assert deps.references_symbol_at_line("services.py", 5) is None
    assert deps.references_lines_low_only("services.py", {2})


def test_conflicting_finite_overrides_fail_closed_without_partial_fanout(
    tmp_path: Path,
) -> None:
    implementations = tmp_path / "implementations.py"
    implementations.write_text(
        "class First:\n"
        "    def run(self) -> int:\n"
        "        return 1\n\n"
        "class Second:\n"
        "    def run(self) -> int:\n"
        "        return 2\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from implementations import First, Second\n\n"
        "def handler(flag: bool) -> int:\n"
        "    service = First() if flag else Second()\n"
        "    return service.run()\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main))

    assert deps.references_symbol_at_line("implementations.py", 2) is None
    assert deps.references_symbol_at_line("implementations.py", 6) is None


def test_exact_finite_mro_dispatch_selects_concrete_override_only(tmp_path: Path) -> None:
    implementations = tmp_path / "implementations.py"
    implementations.write_text(
        "class Base:\n"
        "    def run(self) -> int:\n"
        "        return 1\n\n"
        "class Child(Base):\n"
        "    def run(self) -> int:\n"
        "        return 2\n\n"
        "class Other(Base):\n"
        "    def run(self) -> int:\n"
        "        return 3\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from implementations import Child\n\n"
        "def handler() -> int:\n"
        "    service = Child()\n"
        "    return service.run()\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main))

    assert deps.references_symbol_at_line("implementations.py", 6) is not None
    assert deps.references_symbol_at_line("implementations.py", 2) is None
    assert deps.references_symbol_at_line("implementations.py", 10) is None


def test_multiple_finite_receivers_must_share_one_exact_mro_declaration(
    tmp_path: Path,
) -> None:
    implementations = tmp_path / "implementations.py"
    implementations.write_text(
        "class Base:\n"
        "    def run(self) -> int:\n"
        "        return 1\n\n"
        "class First(Base):\n"
        "    pass\n\n"
        "class Second(Base):\n"
        "    pass\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from implementations import First, Second\n\n"
        "def handler(flag: bool) -> int:\n"
        "    service = First() if flag else Second()\n"
        "    return service.run()\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main))

    assert deps.references_symbol_at_line("implementations.py", 2) is not None
    assert deps.references_lines_low_only("implementations.py", {2})


def test_points_to_target_cap_fails_closed_without_partial_fanout(tmp_path: Path) -> None:
    class_names = [f"Service{number}" for number in range(9)]
    implementations = tmp_path / "implementations.py"
    implementations.write_text(
        "class Base:\n"
        "    def run(self) -> int:\n"
        "        return 1\n\n"
        + "\n".join(f"class {name}(Base):\n    pass\n" for name in class_names),
        encoding="utf-8",
    )
    imports = ", ".join(class_names)
    expression = "Service8()"
    for number in reversed(range(8)):
        expression = f"Service{number}() if value == {number} else ({expression})"
    main = tmp_path / "main.py"
    main.write_text(
        f"from implementations import {imports}\n\n"
        "def handler(value: int) -> int:\n"
        f"    service = {expression}\n"
        "    return service.run()\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main))

    assert deps.references_symbol_at_line("implementations.py", 2) is None


def test_global_control_flow_reassignment_invalidates_summary(tmp_path: Path) -> None:
    implementations = tmp_path / "implementations.py"
    implementations.write_text(
        "class First:\n"
        "    def run(self) -> int:\n"
        "        return 1\n\n"
        "class Second:\n"
        "    def run(self) -> int:\n"
        "        return 2\n",
        encoding="utf-8",
    )
    clients = tmp_path / "clients.py"
    clients.write_text(
        "from implementations import First, Second\n\n"
        "flag = False\n"
        "CLIENT = First()\n"
        "if flag:\n"
        "    CLIENT = Second()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from clients import CLIENT\n\ndef handler() -> int:\n    return CLIENT.run()\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main))

    assert deps.references_symbol_at_line("implementations.py", 2) is None
    assert deps.references_symbol_at_line("implementations.py", 6) is None


def test_member_or_callback_mutation_invalidates_finite_heap_state(tmp_path: Path) -> None:
    _write_service(tmp_path)
    wrapper = tmp_path / "wrapper.py"
    wrapper.write_text(
        "class Wrapper:\n"
        "    def __init__(self, service):\n"
        "        self.service = service\n\n"
        "    def run(self) -> int:\n"
        "        return self.service.changed()\n\n"
        "def mutate(value):\n"
        "    value.service = object()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from services import Service\n"
        "from wrapper import Wrapper, mutate\n\n"
        "def handler(flag: bool) -> int:\n"
        "    first = Wrapper(Service())\n"
        "    second = Wrapper(Service())\n"
        "    if flag:\n"
        "        first.__class__ = Wrapper\n"
        "    mutate(second)\n"
        "    return second.run()\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=4))

    assert deps.references_symbol_at_line("services.py", 2) is None


def test_exact_super_dispatch_preserves_standard_reachability(tmp_path: Path) -> None:
    inheritance = tmp_path / "inheritance.py"
    inheritance.write_text(
        "def leaf() -> int:\n"
        "    return 1\n\n"
        "class Base:\n"
        "    def run(self) -> int:\n"
        "        return leaf()\n\n"
        "class Child(Base):\n"
        "    def run(self) -> int:\n"
        "        return super().run()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from inheritance import Child\n\ndef handler() -> int:\n    return Child().run()\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main))

    assert deps.references_symbol_at_line("inheritance.py", 5) is not None
    assert deps.references_symbol_at_line("inheritance.py", 1) is not None
    assert not deps.references_lines_low_only("inheritance.py", {1})


def test_endpoint_order_does_not_change_finite_results(tmp_path: Path) -> None:
    _write_service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "from services import Service\n\n"
        "def first() -> int:\n"
        "    service = Service()\n"
        "    return service.changed()\n\n"
        "def second() -> int:\n"
        "    service = Service()\n"
        "    return service.changed()\n",
        encoding="utf-8",
    )
    endpoints = [
        Endpoint(
            path=f"/{name}",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(
                name=name,
                module="main",
                file_path=main,
                line_number=line,
            ),
        )
        for name, line in (("first", 3), ("second", 7))
    ]

    def normalized(order: list[Endpoint]) -> dict[str, list[tuple[str, bool]]]:
        analyses = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoints(order, use_cache=False)
        return {
            dependencies.endpoint_id: sorted(
                (reference.symbol_name, reference.low_confidence)
                for reference in dependencies.referenced_symbols
            )
            for dependencies in analyses.values()
        }

    assert normalized(endpoints) == normalized(list(reversed(endpoints)))


def test_low_provenance_round_trips_through_cache(tmp_path: Path) -> None:
    _write_service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "from services import Service\n\n"
        "def handler() -> int:\n"
        "    service = Service()\n"
        "    return service.changed()\n",
        encoding="utf-8",
    )
    endpoint = _endpoint(main)
    cache = tmp_path / "mypy-cache.json"
    writer = MypyAnalyzer(tmp_path, max_depth=4)
    writer.set_cache_path(cache)
    writer.analyze_endpoints([endpoint], use_cache=True)

    reader = MypyAnalyzer(tmp_path, max_depth=4)
    reader.set_cache_path(cache)
    loaded = reader.analyze_endpoints([endpoint], use_cache=True)[reader._endpoint_key(endpoint)]

    assert loaded.references_lines_low_only("services.py", {2})
