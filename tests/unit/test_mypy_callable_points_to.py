"""Bounded callable points-to and conservative dispatch regressions."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.effect_contract import CallResolutionStatus
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


def _endpoint(path: Path, line: int, name: str = "handler") -> Endpoint:
    return Endpoint(
        path=f"/{name}",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name=name,
            module=path.stem,
            file_path=path,
            line_number=line,
        ),
    )


def test_exact_function_alias_and_forwarding_chain_reach_callback_at_low(
    tmp_path: Path,
) -> None:
    callbacks = tmp_path / "callbacks.py"
    callbacks.write_text(
        "def changed() -> int:\n    return 1\n\ndef unrelated() -> int:\n    return 2\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from collections.abc import Callable\n"
        "from callbacks import changed\n\n"
        "def invoke(callback: Callable[[], int]) -> int:\n"
        "    return callback()\n\n"
        "def forward(callback: Callable[[], int]) -> int:\n"
        "    return invoke(callback)\n\n"
        "def direct() -> int:\n"
        "    callback = changed\n"
        "    str(1)\n"
        "    return callback()\n\n"
        "def handler() -> int:\n"
        "    return forward(changed)\n",
        encoding="utf-8",
    )

    direct = MypyAnalyzer(tmp_path, max_depth=6).analyze_endpoint(_endpoint(main, 10, "direct"))
    forwarded = MypyAnalyzer(tmp_path, max_depth=6).analyze_endpoint(_endpoint(main, 15))

    for dependencies in (direct, forwarded):
        assert dependencies.references_symbol_at_line("callbacks.py", 1) is not None
        assert dependencies.references_symbol_at_line("callbacks.py", 4) is None
        assert dependencies.references_lines_low_only("callbacks.py", {1})


def test_bound_method_alias_uses_only_the_source_proven_receiver(tmp_path: Path) -> None:
    services = tmp_path / "services.py"
    services.write_text(
        "class Service:\n"
        "    def changed(self) -> int:\n"
        "        return 1\n\n"
        "    def unrelated(self) -> int:\n"
        "        return 2\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from services import Service\n\n"
        "def handler() -> int:\n"
        "    service = Service()\n"
        "    callback = service.changed\n"
        "    return callback()\n",
        encoding="utf-8",
    )

    dependencies = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, 3))

    assert dependencies.references_symbol_at_line("services.py", 2) is not None
    assert dependencies.references_symbol_at_line("services.py", 5) is None
    assert dependencies.references_lines_low_only("services.py", {2})


def test_callable_reassignment_kills_the_previous_target(tmp_path: Path) -> None:
    callbacks = tmp_path / "callbacks.py"
    callbacks.write_text(
        "def stale() -> int:\n    return 1\n\ndef selected() -> int:\n    return 2\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from callbacks import selected, stale\n\n"
        "def handler() -> int:\n"
        "    callback = stale\n"
        "    callback = selected\n"
        "    return callback()\n",
        encoding="utf-8",
    )

    dependencies = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main, 3))

    assert dependencies.references_symbol_at_line("callbacks.py", 1) is None
    assert dependencies.references_symbol_at_line("callbacks.py", 4) is not None


def test_finite_callable_branch_union_traces_all_and_only_possible_targets(
    tmp_path: Path,
) -> None:
    callbacks = tmp_path / "callbacks.py"
    callbacks.write_text(
        "def first() -> int:\n"
        "    return 1\n\n"
        "def second() -> int:\n"
        "    return 2\n\n"
        "def unrelated() -> int:\n"
        "    return 3\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from callbacks import first, second\n\n"
        "def handler(flag: bool) -> int:\n"
        "    callback = first if flag else second\n"
        "    return callback()\n",
        encoding="utf-8",
    )

    dependencies = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main, 3))

    assert dependencies.references_symbol_at_line("callbacks.py", 1) is not None
    assert dependencies.references_symbol_at_line("callbacks.py", 4) is not None
    assert dependencies.references_symbol_at_line("callbacks.py", 7) is None
    assert dependencies.references_lines_low_only("callbacks.py", {1, 4})


def test_finite_callable_union_with_unsupported_target_drops_all_targets(
    tmp_path: Path,
) -> None:
    callbacks = tmp_path / "callbacks.py"
    callbacks.write_text(
        "def fixed() -> int:\n"
        "    return 1\n\n"
        "def variadic(*args: object) -> int:\n"
        "    return len(args)\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from callbacks import fixed, variadic\n\n"
        "def handler(flag: bool) -> int:\n"
        "    callback = fixed if flag else variadic\n"
        "    return callback()\n",
        encoding="utf-8",
    )

    dependencies = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main, 3))

    assert dependencies.references_symbol_at_line("callbacks.py", 1) is None
    assert dependencies.references_symbol_at_line("callbacks.py", 4) is None


def test_finite_callable_union_with_generator_target_drops_all_targets(
    tmp_path: Path,
) -> None:
    callbacks = tmp_path / "callbacks.py"
    callbacks.write_text(
        "from collections.abc import Iterator\n\n"
        "def fixed() -> Iterator[int]:\n"
        "    return iter((1,))\n\n"
        "def deferred() -> Iterator[int]:\n"
        "    yield 1\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from collections.abc import Iterator\n"
        "from callbacks import deferred, fixed\n\n"
        "def handler(flag: bool) -> Iterator[int]:\n"
        "    callback = fixed if flag else deferred\n"
        "    return callback()\n",
        encoding="utf-8",
    )

    dependencies = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main, 4))

    assert dependencies.references_symbol_at_line("callbacks.py", 3) is None
    assert dependencies.references_symbol_at_line("callbacks.py", 6) is None


def test_finite_callable_union_reserves_all_edges_before_tracing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    callbacks = tmp_path / "callbacks.py"
    callbacks.write_text(
        "def first() -> int:\n"
        "    return 1\n\n"
        "def second() -> int:\n"
        "    return 2\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from callbacks import first, second\n\n"
        "def handler(flag: bool) -> int:\n"
        "    callback = first if flag else second\n"
        "    return callback()\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(MypyAnalyzer, "MAX_POINTS_TO_EDGES", 1)

    dependencies = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main, 3))

    assert dependencies.references_symbol_at_line("callbacks.py", 1) is None
    assert dependencies.references_symbol_at_line("callbacks.py", 4) is None


def test_finite_callable_union_reserves_all_binding_states_before_tracing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    callbacks = tmp_path / "callbacks.py"
    callbacks.write_text(
        "from collections.abc import Callable\n\n"
        "def first(callback: Callable[[], int]) -> int:\n"
        "    return callback()\n\n"
        "def second(callback: Callable[[], int]) -> int:\n"
        "    return callback()\n\n"
        "def changed() -> int:\n"
        "    return 1\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from callbacks import changed, first, second\n\n"
        "def handler(flag: bool) -> int:\n"
        "    callback = first if flag else second\n"
        "    return callback(changed)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(MypyAnalyzer, "MAX_FACTORY_STATES", 5)

    dependencies = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, 3))

    assert dependencies.references_symbol_at_line("callbacks.py", 3) is None
    assert dependencies.references_symbol_at_line("callbacks.py", 6) is None
    assert dependencies.references_symbol_at_line("callbacks.py", 9) is None


def test_callable_target_cap_fails_closed_without_partial_fanout(tmp_path: Path) -> None:
    callbacks = tmp_path / "callbacks.py"
    callbacks.write_text(
        "\n".join(f"def callback_{number}() -> int:\n    return {number}\n" for number in range(9)),
        encoding="utf-8",
    )
    imports = ", ".join(f"callback_{number}" for number in range(9))
    branches = "".join(
        (
            f"    {'if' if number == 0 else 'elif'} value == {number}:\n"
            f"        callback = callback_{number}\n"
        )
        for number in range(8)
    )
    main = tmp_path / "main.py"
    main.write_text(
        f"from callbacks import {imports}\n\n"
        "def handler(value: int) -> int:\n"
        f"{branches}"
        "    else:\n"
        "        callback = callback_8\n"
        "    return callback()\n",
        encoding="utf-8",
    )

    dependencies = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main, 3))

    assert all(
        dependencies.references_symbol_at_line("callbacks.py", line) is None
        for line in range(1, 27, 3)
    )


def test_bound_receiver_union_traces_each_concrete_override(tmp_path: Path) -> None:
    services = tmp_path / "services.py"
    services.write_text(
        "class First:\n"
        "    def changed(self) -> int:\n"
        "        return 1\n\n"
        "class Second:\n"
        "    def changed(self) -> int:\n"
        "        return 2\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from services import First, Second\n\n"
        "def handler(flag: bool) -> int:\n"
        "    service = First() if flag else Second()\n"
        "    callback = service.changed\n"
        "    return callback()\n",
        encoding="utf-8",
    )

    dependencies = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main, 3))

    assert dependencies.references_symbol_at_line("services.py", 2) is not None
    assert dependencies.references_symbol_at_line("services.py", 6) is not None
    assert dependencies.references_lines_low_only("services.py", {2, 6})


def test_bound_receiver_union_with_unresolved_member_drops_all_targets(
    tmp_path: Path,
) -> None:
    services = tmp_path / "services.py"
    services.write_text(
        "from collections.abc import Callable\n\n"
        "def dynamic() -> int:\n"
        "    return 0\n\n"
        "class Supported:\n"
        "    def changed(self) -> int:\n"
        "        return 1\n\n"
        "class Dynamic:\n"
        "    def __getattr__(self, name: str) -> Callable[[], int]:\n"
        "        return dynamic\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from services import Dynamic, Supported\n\n"
        "def handler(flag: bool) -> int:\n"
        "    service = Supported() if flag else Dynamic()\n"
        "    callback = service.changed\n"
        "    return callback()\n",
        encoding="utf-8",
    )

    dependencies = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main, 3))

    assert dependencies.references_symbol_at_line("services.py", 3) is None
    assert dependencies.references_symbol_at_line("services.py", 7) is None


def test_protocol_and_open_base_receivers_are_not_exact_dispatch(tmp_path: Path) -> None:
    main = tmp_path / "main.py"
    main.write_text(
        "from typing import Protocol\n\n"
        "class Runner(Protocol):\n"
        "    def run(self) -> int: ...\n\n"
        "class Base:\n"
        "    def run(self) -> int:\n"
        "        return 1\n\n"
        "class Child(Base):\n"
        "    def run(self) -> int:\n"
        "        return 2\n\n"
        "def protocol_handler(value: Runner) -> int:\n"
        "    return value.run()\n\n"
        "def handler(value: Base) -> int:\n"
        "    return value.run()\n",
        encoding="utf-8",
    )

    protocol = MypyAnalyzer(tmp_path).analyze_endpoint(_endpoint(main, 14, "protocol_handler"))
    open_base = MypyAnalyzer(tmp_path).analyze_endpoint(_endpoint(main, 17))
    protocol_site = next(
        site for site in protocol.resolved_call_sites if site.source_spelling == "value.run"
    )
    base_site = next(
        site for site in open_base.resolved_call_sites if site.source_spelling == "value.run"
    )

    for site in (protocol_site, base_site):
        assert site.status == CallResolutionStatus.AMBIGUOUS
        assert site.canonical_symbol is None
        assert site.reason_code == "open_receiver"


def test_open_annotation_with_concrete_constructor_uses_only_finite_override(
    tmp_path: Path,
) -> None:
    main = tmp_path / "main.py"
    main.write_text(
        "class Base:\n"
        "    def run(self) -> int:\n"
        "        return 1\n\n"
        "class Child(Base):\n"
        "    def run(self) -> int:\n"
        "        return 2\n\n"
        "def handler() -> int:\n"
        "    value: Base = Child()\n"
        "    return value.run()\n",
        encoding="utf-8",
    )

    dependencies = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main, 9))
    site = next(
        item for item in dependencies.resolved_call_sites if item.source_spelling == "value.run"
    )

    assert site.status == CallResolutionStatus.AMBIGUOUS
    assert site.reason_code == "open_receiver"
    assert dependencies.references_symbol_at_line("main.py", 2) is None
    assert dependencies.references_symbol_at_line("main.py", 6) is not None
    assert dependencies.references_lines_low_only("main.py", {6})


def test_final_receiver_annotation_can_remain_exact(tmp_path: Path) -> None:
    main = tmp_path / "main.py"
    main.write_text(
        "from typing import final\n\n"
        "@final\n"
        "class Closed:\n"
        "    def run(self) -> int:\n"
        "        return 1\n\n"
        "def handler(value: Closed) -> int:\n"
        "    return value.run()\n",
        encoding="utf-8",
    )

    dependencies = MypyAnalyzer(tmp_path).analyze_endpoint(_endpoint(main, 8))
    site = next(
        item for item in dependencies.resolved_call_sites if item.source_spelling == "value.run"
    )

    assert site.status == CallResolutionStatus.EXACT
    assert site.canonical_symbol and site.canonical_symbol.endswith("Closed.run")
