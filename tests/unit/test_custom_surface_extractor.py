"""Execution-free custom surface discovery tests."""

import json
import re
import sys
from pathlib import Path

import pytest
import yaml

from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointDiscoveryCondition,
    EndpointDiscoveryStatus,
    EndpointInventory,
    EndpointMethod,
    HandlerInfo,
    InventoryStatus,
)
from fastapi_endpoint_detector.models.report import (
    AffectedEndpoint,
    AnalysisReport,
    ConfidenceLevel,
)
from fastapi_endpoint_detector.models.surface_contract import (
    load_surface_contracts,
    load_surface_preset,
)
from fastapi_endpoint_detector.output.formatters import get_formatter
from fastapi_endpoint_detector.parser.custom_surface_extractor import (
    CustomSurfaceExtractor,
    CustomSurfaceExtractorError,
    merge_surface_inventory,
)


def _contracts(
    tmp_path: Path,
    *,
    symbol: str = "framework.Reactor.listen",
    callback_mode: str = "async",
    handler: dict[str, object] | None = None,
    receiver_type: str | None = "framework.Reactor",
    invocation: str = "instance_method",
) -> Path:
    path = tmp_path / "surfaces.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "preset": {
                    "id": "fixture",
                    "version": "1",
                    "provenance": {"kind": "user", "source": "tests"},
                },
                "contracts": [
                    {
                        "id": "listener",
                        "registration": {
                            "symbol": symbol,
                            "invocation": invocation,
                            **(
                                {"receiver_type": receiver_type}
                                if receiver_type is not None
                                else {}
                            ),
                        },
                        "handler": handler or {"kind": "decorated_function"},
                        "surface": {
                            "kind": "reactor",
                            "id_template": "topic:{resource}",
                            "resource": {"kind": "argument", "index": 0},
                        },
                        "callback_mode": callback_mode,
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return path


def _argument_inventory(
    tmp_path: Path,
    source: str,
    *,
    handler: dict[str, object] | None = None,
) -> EndpointInventory:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "main.py").write_text(source, encoding="utf-8")
    return CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(
            _contracts(
                tmp_path,
                handler=handler or {"kind": "argument", "index": 1},
            )
        ),
    ).extract_inventory()


def test_missing_root_does_not_discover_sibling_surfaces(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "@reactor.listen('sibling')\n"
        "async def process(): pass\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path))
    missing = tmp_path / "missing.py"

    inventory = CustomSurfaceExtractor(missing, loaded).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.UNAVAILABLE
    assert inventory.limitations[0].source_path == missing


def test_unparseable_explicit_file_is_unavailable(tmp_path: Path) -> None:
    broken = tmp_path / "broken.py"
    broken.write_text("def broken(:\n", encoding="utf-8")
    loaded = load_surface_contracts(_contracts(tmp_path))

    inventory = CustomSurfaceExtractor(broken, loaded).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.UNAVAILABLE
    assert any(item.source_path == broken.resolve() for item in inventory.limitations)


def test_root_without_parseable_python_modules_is_unavailable(tmp_path: Path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    loaded = load_surface_contracts(_contracts(tmp_path))

    inventory = CustomSurfaceExtractor(app, loaded).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.UNAVAILABLE
    assert inventory.limitations == (
        EndpointDiscoveryCondition(
            source_path=app.resolve(),
            source_line=1,
            reason="custom surface root has no successfully parsed Python modules",
        ),
    )


def test_partially_parsed_directory_is_conditional(tmp_path: Path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "valid.py").write_text("value = 1\n", encoding="utf-8")
    (app / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    loaded = load_surface_contracts(_contracts(tmp_path))

    inventory = CustomSurfaceExtractor(app, loaded).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.limitations[0].source_path == app / "broken.py"


def test_merge_surface_inventory_is_symmetric_for_empty_inventories(tmp_path: Path) -> None:
    limitation = EndpointDiscoveryCondition(
        source_path=tmp_path / "main.py",
        source_line=1,
        reason="inventory incomplete",
    )

    def inventory(status: InventoryStatus) -> EndpointInventory:
        return EndpointInventory(
            status=status,
            limitations=() if status == InventoryStatus.ESTABLISHED else (limitation,),
        )

    for left in InventoryStatus:
        for right in InventoryStatus:
            merged = merge_surface_inventory(inventory(left), inventory(right))
            reverse = merge_surface_inventory(inventory(right), inventory(left))
            if InventoryStatus.UNAVAILABLE in (left, right):
                expected = InventoryStatus.UNAVAILABLE
            elif InventoryStatus.CONDITIONAL in (left, right):
                expected = InventoryStatus.CONDITIONAL
            else:
                expected = InventoryStatus.ESTABLISHED
            assert merged.status == reverse.status == expected
            assert merged.endpoints == reverse.endpoints == []


def test_merge_route_conditions_are_symmetric_and_condition_native_endpoints(
    tmp_path: Path,
) -> None:
    condition = EndpointDiscoveryCondition(
        source_path=tmp_path / "startup.py",
        source_line=7,
        reason="startup may mutate routes",
    )
    endpoint = Endpoint(
        path="/items",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="items", module="main", file_path=tmp_path / "main.py", line_number=1
        ),
    )
    conditioned = endpoint.model_copy(
        update={
            "discovery_status": EndpointDiscoveryStatus.CONDITIONAL,
            "discovery_conditions": (condition,),
        }
    )
    route_wide = EndpointInventory(
        endpoints=[conditioned],
        status=InventoryStatus.CONDITIONAL,
        limitations=(condition,),
        route_conditions=(condition,),
    )
    empty = EndpointInventory()

    forward = merge_surface_inventory(empty, route_wide)
    reverse = merge_surface_inventory(route_wide, empty)

    assert forward == reverse
    assert forward.route_conditions == (condition,)
    assert forward.endpoints == [conditioned]


def test_merge_nonempty_inventories_is_reverse_order_symmetric(tmp_path: Path) -> None:
    def endpoint(path: str, line: int) -> Endpoint:
        return Endpoint(
            path=path,
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(
                name=path.removeprefix("/"),
                module="main",
                file_path=tmp_path / "main.py",
                line_number=line,
            ),
        )

    left = EndpointInventory(endpoints=[endpoint("/z", 2)])
    right = EndpointInventory(endpoints=[endpoint("/a", 1)])

    forward = merge_surface_inventory(left, right)
    reverse = merge_surface_inventory(right, left)

    assert forward == reverse
    assert [item.path for item in forward.endpoints] == ["/a", "/z"]


def test_merge_with_usable_endpoints_and_incomplete_input_is_conditional(
    tmp_path: Path,
) -> None:
    endpoint = Endpoint(
        path="/items",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="items", module="main", file_path=tmp_path / "main.py", line_number=1
        ),
    )
    established = EndpointInventory(endpoints=[endpoint])
    limitation = EndpointDiscoveryCondition(
        source_path=tmp_path / "broken.py", source_line=1, reason="module unavailable"
    )
    unavailable = EndpointInventory(
        status=InventoryStatus.UNAVAILABLE,
        limitations=(limitation,),
    )

    for merged in (
        merge_surface_inventory(established, unavailable),
        merge_surface_inventory(unavailable, established),
    ):
        assert merged.endpoints == [endpoint]
        assert merged.status == InventoryStatus.CONDITIONAL
        assert merged.limitations == (limitation,)


def test_exact_decorator_registration_has_complete_provenance(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "@reactor.listen('orders')\n"
        "async def process_order():\n"
        "    return None\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path))

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [item.identifier for item in inventory.endpoints] == ["REACTOR topic:orders"]
    endpoint = inventory.endpoints[0]
    assert endpoint.handler.name == "process_order"
    assert endpoint.discovery_status == EndpointDiscoveryStatus.ESTABLISHED
    assert endpoint.surface is not None
    assert endpoint.surface.registration_symbol == "framework.Reactor.listen"
    assert endpoint.surface.contract_id == "listener"
    assert endpoint.surface.registration_line == 4
    assert endpoint.surface.config_hash == loaded.config_hash
    assert endpoint.surface.registration_source_hash.startswith("sha256:")
    assert endpoint.surface.handler_source_hash.startswith("sha256:")
    assert inventory.limitations == ()


def test_nested_decorator_registration_is_eager_without_revisiting_root(
    tmp_path: Path,
) -> None:
    inventory = _argument_inventory(
        tmp_path,
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "def identity(value): return value\n"
        "@identity(reactor.listen('nested', process))\n"
        "def wrapper(): pass\n",
    )

    assert [item.path for item in inventory.endpoints] == ["topic:nested"]
    assert inventory.status == InventoryStatus.ESTABLISHED
    assert inventory.limitations == ()


@pytest.mark.parametrize(
    ("header", "resources"),
    [
        (
            "def wrapper(a=reactor.listen('positional-default', process), "
            "*, b=reactor.listen('keyword-default', process)): pass\n",
            ["keyword-default", "positional-default"],
        ),
        (
            "def wrapper(\n"
            "    a: reactor.listen('positional', process), /,\n"
            "    b: reactor.listen('ordinary', process),\n"
            "    *args: reactor.listen('vararg', process),\n"
            "    c: reactor.listen('keyword-only', process),\n"
            "    **kwargs: reactor.listen('kwarg', process),\n"
            ") -> reactor.listen('return', process): pass\n",
            ["keyword-only", "kwarg", "ordinary", "positional", "return", "vararg"],
        ),
    ],
)
def test_function_definition_eager_values_are_discovered_in_runtime_order(
    tmp_path: Path,
    header: str,
    resources: list[str],
) -> None:
    inventory = _argument_inventory(
        tmp_path,
        "from framework import Reactor\nreactor = Reactor()\nasync def process(): pass\n" + header,
    )

    assert (
        sorted(item.surface.resource for item in inventory.endpoints if item.surface) == resources
    )
    assert inventory.status == InventoryStatus.ESTABLISHED


def test_postponed_annotations_skip_calls_but_defaults_remain_eager(tmp_path: Path) -> None:
    inventory = _argument_inventory(
        tmp_path,
        "from __future__ import annotations\n"
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "def wrapper(\n"
        "    value: reactor.listen('function-annotation', process) = "
        "reactor.listen('default', process),\n"
        "): pass\n"
        "class Container:\n"
        "    value: reactor.listen('class-annotation', process)\n",
    )

    assert [item.path for item in inventory.endpoints] == ["topic:default"]
    assert inventory.status == InventoryStatus.ESTABLISHED


@pytest.mark.parametrize(
    "definition",
    [
        "@reactor.listen('class-decorator', process)\nclass Container: pass\n",
        "class Container(reactor.listen('class-base', process)): pass\n",
        "class Container(metaclass=reactor.listen('class-keyword', process)): pass\n",
        "class Container:\n    reactor.listen('class-body', process)\n",
        "class Container:\n    value: reactor.listen('class-annotation', process)\n",
    ],
)
def test_class_definition_eager_surfaces_are_discovered(
    tmp_path: Path,
    definition: str,
) -> None:
    inventory = _argument_inventory(
        tmp_path,
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n" + definition,
    )

    assert len(inventory.endpoints) == 1
    assert inventory.status == InventoryStatus.ESTABLISHED


def test_definition_headers_apply_state_changes_in_source_order(tmp_path: Path) -> None:
    inventory = _argument_inventory(
        tmp_path / "defaults",
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "def wrapper(\n"
        "    first=(reactor := None),\n"
        "    second=reactor.listen('not-reachable', process),\n"
        "): pass\n",
    )

    annotations = _argument_inventory(
        tmp_path / "annotations",
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "def wrapper(\n"
        "    *args: (reactor := None),\n"
        "    value: reactor.listen('not-reachable', process),\n"
        "): pass\n",
    )
    class_header = _argument_inventory(
        tmp_path / "class-header",
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "def identity(value): return value\n"
        "@identity((reactor := None))\n"
        "class Container(reactor.listen('not-reachable', process)): pass\n",
    )

    for result in (inventory, annotations, class_header):
        assert result.endpoints == []
        assert result.status == InventoryStatus.CONDITIONAL
        assert any("unresolved callable identity" in item.reason for item in result.limitations)


def test_class_locals_do_not_leak_but_explicit_globals_do(tmp_path: Path) -> None:
    local = _argument_inventory(
        tmp_path / "local",
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "class Container:\n"
        "    reactor = None\n"
        "reactor.listen('after', process)\n",
    )
    global_binding = _argument_inventory(
        tmp_path / "global",
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "class Container:\n"
        "    global reactor\n"
        "    reactor = None\n"
        "reactor.listen('after', process)\n",
    )

    assert [item.path for item in local.endpoints] == ["topic:after"]
    assert global_binding.endpoints == []
    assert global_binding.status == InventoryStatus.CONDITIONAL


def test_class_body_mutation_invalidates_enclosing_receiver_aliases(tmp_path: Path) -> None:
    inventory = _argument_inventory(
        tmp_path,
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "class Container:\n"
        "    reactor.listen = None\n"
        "reactor.listen('after', process)\n",
    )

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("unresolved callable identity" in item.reason for item in inventory.limitations)


def test_nested_class_body_mutation_invalidates_enclosing_receiver(tmp_path: Path) -> None:
    inventory = _argument_inventory(
        tmp_path,
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "class Outer:\n"
        "    class Inner:\n"
        "        reactor.listen = None\n"
        "reactor.listen('after', process)\n",
    )

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL


def test_class_nonlocal_effect_propagates_inside_selected_bootstrap(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "async def process(): pass\n"
        "def configure():\n"
        "    reactor = Reactor()\n"
        "    class Container:\n"
        "        nonlocal reactor\n"
        "        reactor = None\n"
        "    reactor.listen('after', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
        bootstrap_entry="main:configure",
    ).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("unresolved callable identity" in item.reason for item in inventory.limitations)


def test_class_body_comprehension_does_not_resolve_through_class_locals(
    tmp_path: Path,
) -> None:
    inventory = _argument_inventory(
        tmp_path,
        "from framework import Reactor\n"
        "async def process(): pass\n"
        "items = [1]\n"
        "class Container:\n"
        "    reactor = Reactor()\n"
        "    registrations = [reactor.listen('wrong', process) for item in items]\n",
    )

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("unresolved callable identity" in item.reason for item in inventory.limitations)


def test_nested_class_global_write_updates_module_frame(tmp_path: Path) -> None:
    inventory = _argument_inventory(
        tmp_path,
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "class Outer:\n"
        "    class Inner:\n"
        "        global reactor\n"
        "        reactor = None\n"
        "reactor.listen('wrong', process)\n",
    )

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL


def test_class_global_write_is_visible_to_later_nested_class(tmp_path: Path) -> None:
    unresolved = _argument_inventory(
        tmp_path / "unresolved",
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "class Outer:\n"
        "    global reactor\n"
        "    reactor = None\n"
        "    class Inner:\n"
        "        reactor.listen('wrong', process)\n",
    )
    exact_alias = _argument_inventory(
        tmp_path / "exact",
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "class Outer:\n"
        "    global alias\n"
        "    alias = reactor\n"
        "    class Inner:\n"
        "        alias.listen('inside', process)\n",
    )

    assert unresolved.endpoints == []
    assert unresolved.status == InventoryStatus.CONDITIONAL
    assert [item.path for item in exact_alias.endpoints] == ["topic:inside"]


def test_nested_class_nonlocal_write_updates_bootstrap_frame(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "async def process(): pass\n"
        "def configure():\n"
        "    reactor = Reactor()\n"
        "    class Outer:\n"
        "        class Inner:\n"
        "            nonlocal reactor\n"
        "            reactor = None\n"
        "    reactor.listen('wrong', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
        bootstrap_entry="main:configure",
    ).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL


def test_class_mutation_propagation_uses_exact_binding_not_root_name(
    tmp_path: Path,
) -> None:
    alias_mutation = _argument_inventory(
        tmp_path / "alias",
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "class Container:\n"
        "    alias = reactor\n"
        "    alias.listen = None\n"
        "reactor.listen('wrong', process)\n",
    )
    local_mutation = _argument_inventory(
        tmp_path / "local",
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "class Container:\n"
        "    reactor = Reactor()\n"
        "    reactor.listen = None\n"
        "reactor.listen('after', process)\n",
    )
    conditional_alias_mutation = _argument_inventory(
        tmp_path / "conditional",
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "class Container:\n"
        "    if condition:\n"
        "        alias = reactor\n"
        "        alias.listen = None\n"
        "reactor.listen('maybe-mutated', process)\n",
    )

    assert alias_mutation.endpoints == []
    assert alias_mutation.status == InventoryStatus.CONDITIONAL
    assert [item.path for item in local_mutation.endpoints] == ["topic:after"]
    assert local_mutation.status == InventoryStatus.ESTABLISHED
    assert conditional_alias_mutation.endpoints == []
    assert conditional_alias_mutation.status == InventoryStatus.CONDITIONAL


def test_class_body_fallthrough_conditions_later_registrations(tmp_path: Path) -> None:
    definite = _argument_inventory(
        tmp_path / "definite",
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "class Container:\n"
        "    raise RuntimeError()\n"
        "reactor.listen('unreachable', process)\n",
    )
    conditional = _argument_inventory(
        tmp_path / "conditional",
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "class Container:\n"
        "    if condition:\n"
        "        raise RuntimeError()\n"
        "reactor.listen('conditional', process)\n",
    )

    assert definite.endpoints == []
    assert [item.path for item in conditional.endpoints] == ["topic:conditional"]
    assert conditional.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL


def test_annotation_only_class_name_does_not_shadow_enclosing_receiver(
    tmp_path: Path,
) -> None:
    inventory = _argument_inventory(
        tmp_path,
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "class Container:\n"
        "    reactor: int\n"
        "    reactor.listen('inside', process)\n",
    )

    assert [item.path for item in inventory.endpoints] == ["topic:inside"]
    assert inventory.status == InventoryStatus.ESTABLISHED


def test_positional_annotations_follow_cpython_evaluation_order(tmp_path: Path) -> None:
    inventory = _argument_inventory(
        tmp_path,
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "def wrapper(\n"
        "    positional_only: (reactor := None), /,\n"
        "    ordinary: reactor.listen('ordinary-first', process),\n"
        "): pass\n",
    )

    assert [item.path for item in inventory.endpoints] == ["topic:ordinary-first"]


def test_decorator_callable_is_captured_before_named_argument_effects(
    tmp_path: Path,
) -> None:
    inventory = _argument_inventory(
        tmp_path,
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def original(): pass\n"
        "async def other(): pass\n"
        "@reactor.listen(\n"
        "    'orders', receiver=(reactor := None), "
        "mutate=(original := other), handler=original\n"
        ")\n"
        "def wrapper(): pass\n",
        handler={"kind": "keyword", "name": "handler"},
    )

    assert [item.path for item in inventory.endpoints] == ["topic:orders"]
    assert inventory.endpoints[0].handler.name == "other"
    assert inventory.limitations == ()


@pytest.mark.parametrize(
    "context",
    [
        "{call}\n",
        "def wrapper(value={call}): pass\n",
        "def wrapper(value: {call}): pass\n",
        "class Wrapper({call}): pass\n",
        "class Wrapper(metaclass={call}): pass\n",
        "class Wrapper:\n    {call}\n",
        "def identity(value): return value\n@identity({call})\ndef wrapper(): pass\n",
    ],
)
@pytest.mark.parametrize(
    ("keywords", "expected_handler"),
    [
        ("mutate=(original := other), handler=original", "other"),
        ("handler=original, mutate=(original := other)", "original"),
    ],
)
def test_eager_calls_capture_each_handler_argument(
    tmp_path: Path,
    context: str,
    keywords: str,
    expected_handler: str,
) -> None:
    call = f"reactor.listen('orders', {keywords})"
    inventory = _argument_inventory(
        tmp_path,
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def original(): pass\n"
        "async def other(): pass\n" + context.format(call=call),
        handler={"kind": "keyword", "name": "handler"},
    )

    assert [item.path for item in inventory.endpoints] == ["topic:orders"]
    assert inventory.endpoints[0].handler.name == expected_handler
    assert inventory.limitations == ()


def test_python_call_order_uses_args_before_textually_earlier_keywords(
    tmp_path: Path,
) -> None:
    inventory = _argument_inventory(
        tmp_path,
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "original = reactor\n"
        "async def process(): pass\n"
        "reactor.listen(\n"
        "    'first', reset=(reactor := None), *((reactor := original),)\n"
        ")\n"
        "reactor.listen('impossible-second', process)\n",
    )

    assert all(item.path != "topic:impossible-second" for item in inventory.endpoints)
    assert any("unresolved callable identity" in item.reason for item in inventory.limitations)


def test_class_method_handler_uses_its_positional_capture(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from starlette.middleware.base import BaseHTTPMiddleware as Base\n\n"
        "class First(Base):\n"
        "    async def dispatch(self, request, call_next):\n"
        "        return await call_next(request)\n\n"
        "class Second(Base):\n"
        "    async def dispatch(self, request, call_next):\n"
        "        return await call_next(request)\n\n"
        "app = FastAPI()\n"
        "app.add_middleware(First, mutate=(First := Second))\n",
        encoding="utf-8",
    )

    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_preset("framework-v1"),
    ).extract_inventory()

    middleware = next(item for item in inventory.endpoints if item.path == "protocol:http")
    assert middleware.handler.line_number == 5


def test_class_try_finally_does_not_revive_pending_exception(tmp_path: Path) -> None:
    inventory = _argument_inventory(
        tmp_path,
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "class Container:\n"
        "    try:\n"
        "        raise RuntimeError()\n"
        "    finally:\n"
        "        pass\n"
        "reactor.listen('unreachable', process)\n",
    )

    assert inventory.endpoints == []


def test_bootstrap_class_global_does_not_overwrite_function_local(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = None\n"
        "async def process(): pass\n"
        "def configure():\n"
        "    reactor = Reactor()\n"
        "    class Container:\n"
        "        global reactor\n"
        "        reactor = None\n"
        "    reactor.listen('local', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
        bootstrap_entry="main:configure",
    ).extract_inventory()

    assert [item.path for item in inventory.endpoints] == ["topic:local"]


def test_bootstrap_class_global_refreshes_lookup_without_function_local(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "def configure():\n"
        "    class Container:\n"
        "        global reactor\n"
        "        reactor = None\n"
        "    reactor.listen('wrong', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
        bootstrap_entry="main:configure",
    ).extract_inventory()

    assert inventory.endpoints == []
    assert any("unresolved callable identity" in item.reason for item in inventory.limitations)


def test_bootstrap_class_global_reads_module_not_function_local(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = None\n"
        "async def process(): pass\n"
        "def configure():\n"
        "    reactor = Reactor()\n"
        "    class Container:\n"
        "        global reactor\n"
        "        reactor.listen('wrong', process)\n"
        "    reactor.listen('local', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
        bootstrap_entry="main:configure",
    ).extract_inventory()

    assert [item.path for item in inventory.endpoints] == ["topic:local"]
    assert any("unresolved callable identity" in item.reason for item in inventory.limitations)


def test_inner_declared_outer_write_preserves_outer_class_local(tmp_path: Path) -> None:
    inventory = _argument_inventory(
        tmp_path,
        "from framework import Reactor\n"
        "reactor = None\n"
        "async def process(): pass\n"
        "class Outer:\n"
        "    reactor = Reactor()\n"
        "    class Inner:\n"
        "        global reactor\n"
        "        reactor = None\n"
        "    reactor.listen('outer-local', process)\n",
    )

    assert [item.path for item in inventory.endpoints] == ["topic:outer-local"]


def test_dead_class_binding_does_not_shield_outer_from_global_update(
    tmp_path: Path,
) -> None:
    inventory = _argument_inventory(
        tmp_path,
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "class Outer:\n"
        "    if False:\n"
        "        reactor = Reactor()\n"
        "    class Inner:\n"
        "        global reactor\n"
        "        reactor = None\n"
        "    reactor.listen('wrong', process)\n",
    )

    assert inventory.endpoints == []
    assert any("unresolved callable identity" in item.reason for item in inventory.limitations)


def test_inner_nonlocal_write_preserves_outer_class_local(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "async def process(): pass\n"
        "def configure():\n"
        "    reactor = None\n"
        "    class Outer:\n"
        "        reactor = Reactor()\n"
        "        class Inner:\n"
        "            nonlocal reactor\n"
        "            reactor = None\n"
        "        reactor.listen('outer-local', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
        bootstrap_entry="main:configure",
    ).extract_inventory()

    assert [item.path for item in inventory.endpoints] == ["topic:outer-local"]


def test_conditional_global_overlay_reaches_nested_class_with_condition(
    tmp_path: Path,
) -> None:
    inventory = _argument_inventory(
        tmp_path,
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "class Outer:\n"
        "    global alias\n"
        "    if condition:\n"
        "        alias = reactor\n"
        "        class Inner:\n"
        "            alias.listen('conditional', process)\n",
    )

    assert [item.path for item in inventory.endpoints] == ["topic:conditional"]
    assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL
    assert any(
        item.source_line == 6 and "guarded by source control flow" in item.reason
        for item in inventory.limitations
    )


def test_nested_generator_does_not_change_callback_mode(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "@reactor.listen('orders')\n"
        "async def process():\n"
        "    async def nested():\n"
        "        yield 1\n"
        "    return nested\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, callback_mode="async"))

    endpoints = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory().endpoints

    assert [item.handler.name for item in endpoints] == ["process"]


def test_unrelated_same_method_name_never_matches(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "from unrelated import Other\n"
        "reactor = Reactor()\n"
        "other = Other()\n\n"
        "@other.listen('wrong')\n"
        "async def wrong(): pass\n\n"
        "@reactor.listen('right')\n"
        "async def right(): pass\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path))

    endpoints = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory().endpoints

    assert [item.identifier for item in endpoints] == ["REACTOR topic:right"]


def test_dynamic_registration_is_omitted_with_inventory_limitation(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import make_reactor\n\n"
        "@make_reactor().listen('orders')\n"
        "async def process(): pass\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path))

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert "unresolved callable identity" in inventory.limitations[0].reason


def test_augmented_receiver_rebinding_fails_closed_with_limitation(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "reactor += other\n\n"
        "@reactor.listen('orders')\n"
        "async def process(): pass\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path))

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL


def test_receiver_rebinding_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "reactor = object()\n\n"
        "@reactor.listen('orders')\n"
        "async def process(): pass\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path))

    assert CustomSurfaceExtractor(tmp_path, loaded).extract_inventory().endpoints == []


def test_registration_inside_uncalled_method_is_not_a_surface(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "async def process(): pass\n\n"
        "class NeverInstantiated:\n"
        "    def configure(self):\n"
        "        reactor.listen('orders', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    assert CustomSurfaceExtractor(tmp_path, loaded).extract_inventory().endpoints == []


def test_registration_inside_uncalled_function_is_not_a_surface(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "async def process(): pass\n\n"
        "def configure():\n"
        "    reactor.listen('orders', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    assert CustomSurfaceExtractor(tmp_path, loaded).extract_inventory().endpoints == []


def test_explicit_bootstrap_executes_registration_body(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "async def process(): pass\n\n"
        "def configure():\n"
        "    reactor.listen('orders', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    endpoints = (
        CustomSurfaceExtractor(
            tmp_path,
            loaded,
            bootstrap_entry="main:configure",
        )
        .extract_inventory()
        .endpoints
    )

    assert [item.identifier for item in endpoints] == ["REACTOR topic:orders"]


@pytest.mark.parametrize(
    "signature",
    ["required", "*, required", "*args", "**kwargs"],
)
def test_bootstrap_rejects_required_and_variadic_parameters(
    tmp_path: Path,
    signature: str,
) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        f"def configure({signature}):\n"
        "    reactor.listen('orders', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    with pytest.raises(CustomSurfaceExtractorError, match="callable with zero arguments"):
        CustomSurfaceExtractor(
            tmp_path,
            loaded,
            bootstrap_entry="main:configure",
        ).extract_inventory()


def test_bootstrap_rejects_generator_without_executing_body(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "def configure():\n"
        "    reactor.listen('orders', process)\n"
        "    yield None\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    with pytest.raises(CustomSurfaceExtractorError, match="must not be a generator"):
        CustomSurfaceExtractor(
            tmp_path,
            loaded,
            bootstrap_entry="main:configure",
        ).extract_inventory()


def test_bootstrap_accepts_fully_defaulted_parameters(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "def configure(optional=None, *, enabled=True):\n"
        "    reactor.listen('orders', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    inventory = CustomSurfaceExtractor(
        tmp_path,
        loaded,
        bootstrap_entry="main:configure",
    ).extract_inventory()

    assert [item.identifier for item in inventory.endpoints] == ["REACTOR topic:orders"]
    assert inventory.status == InventoryStatus.ESTABLISHED


def test_callback_argument_requires_one_unambiguous_project_function(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "async def process(): pass\n\n"
        "reactor.listen('orders', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    endpoints = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory().endpoints

    assert [item.handler.name for item in endpoints] == ["process"]


@pytest.mark.parametrize(
    ("body", "expected_identifiers", "conditional"),
    [
        (
            "match subject:\n    case _ if enabled:\n        reactor.listen('guarded', process)\n",
            ["REACTOR topic:guarded"],
            True,
        ),
        (
            "match subject:\n    case reactor:\n        reactor.listen('shadowed', process)\n",
            [],
            True,
        ),
        (
            "match subject:\n"
            "    case process:\n"
            "        reactor.listen('shadowed-callback', process)\n",
            [],
            True,
        ),
        (
            "match subject:\n    case captured:\n        pass\nreactor.listen('after', process)\n",
            ["REACTOR topic:after"],
            False,
        ),
    ],
)
def test_match_cases_shadow_bindings_and_join_post_state(
    tmp_path: Path,
    body: str,
    expected_identifiers: list[str],
    conditional: bool,
) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "subject = object()\n"
        "enabled = True\n"
        f"{body}",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert [item.identifier for item in inventory.endpoints] == expected_identifiers
    if conditional:
        assert inventory.status == InventoryStatus.CONDITIONAL
    else:
        assert inventory.status == InventoryStatus.ESTABLISHED
    if inventory.endpoints and conditional:
        assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL
        assert inventory.endpoints[0].discovery_conditions
    if not inventory.endpoints and conditional:
        assert inventory.limitations
        assert all(
            condition.source_path == (tmp_path / "main.py").resolve()
            for condition in inventory.limitations
        )


@pytest.mark.parametrize(
    ("expression", "expected_identifiers"),
    [
        ("[reactor.listen('bare', process) for item in values]", ["REACTOR topic:bare"]),
        (
            "result = [reactor.listen('assigned', process) for item in values]",
            ["REACTOR topic:assigned"],
        ),
        ("[reactor.listen('shadowed', process) for reactor in values]", []),
    ],
)
def test_comprehension_registrations_are_conditional_and_targets_do_not_leak(
    tmp_path: Path, expression: str, expected_identifiers: list[str]
) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "values = []\n"
        f"{expression}\n"
        "reactor.listen('after', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert [item.identifier for item in inventory.endpoints] == sorted(
        [*expected_identifiers, "REACTOR topic:after"]
    )
    if expected_identifiers:
        nested = next(
            item for item in inventory.endpoints if item.identifier != "REACTOR topic:after"
        )
        assert nested.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
        assert "comprehension iteration" in nested.discovery_conditions[0].reason
    assert (
        next(
            item for item in inventory.endpoints if item.identifier == "REACTOR topic:after"
        ).discovery_status
        == EndpointDiscoveryStatus.ESTABLISHED
    )


@pytest.mark.parametrize(
    ("target", "expected"),
    [("reactor", []), ("unrelated", ["REACTOR topic:after"])],
)
def test_comprehension_walrus_invalidation_is_targeted(
    tmp_path: Path, target: str, expected: list[str]
) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "values = []\n"
        f"[( {target} := object()) for item in values]\n"
        "reactor.listen('after', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert [item.identifier for item in inventory.endpoints] == expected
    if not expected:
        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.limitations
        assert all(
            condition.source_path == (tmp_path / "main.py").resolve()
            for condition in inventory.limitations
        )


@pytest.mark.parametrize(
    "try_keyword",
    [
        "except",
        pytest.param(
            "except*",
            marks=pytest.mark.skipif(sys.version_info < (3, 11), reason="requires Python 3.11"),
        ),
    ],
)
def test_exception_handlers_are_traversed_conditionally(tmp_path: Path, try_keyword: str) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "try:\n"
        "    risky()\n"
        f"{try_keyword} Error:\n"
        "    reactor.listen('handled', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert [item.identifier for item in inventory.endpoints] == ["REACTOR topic:handled"]
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL


def test_exception_target_shadows_and_is_deleted_after_handler(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "try:\n"
        "    risky()\n"
        "except Error as reactor:\n"
        "    reactor.listen('shadowed', process)\n"
        "reactor.listen('after', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.limitations
    assert all(
        condition.source_path == (tmp_path / "main.py").resolve()
        for condition in inventory.limitations
    )


@pytest.mark.parametrize(
    "source",
    [
        "import a.b\na.b.listen('orders', process)\n",
        "import a.b as api\napi.listen('orders', process)\n",
        "from a import b\nb.listen('orders', process)\n",
    ],
)
def test_equivalent_dotted_import_spellings_resolve_exactly(tmp_path: Path, source: str) -> None:
    (tmp_path / "main.py").write_text(f"async def process(): pass\n{source}", encoding="utf-8")
    loaded = load_surface_contracts(
        _contracts(
            tmp_path,
            symbol="a.b.listen",
            receiver_type=None,
            invocation="function",
            handler={"kind": "argument", "index": 1},
        )
    )

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert [item.identifier for item in inventory.endpoints] == ["REACTOR topic:orders"]
    assert inventory.status == InventoryStatus.ESTABLISHED


def test_unaliased_dotted_import_does_not_bind_submodule_identity_to_root(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "async def process(): pass\nimport a.b\na.listen('orders', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(
        _contracts(
            tmp_path,
            symbol="a.b.listen",
            receiver_type=None,
            invocation="function",
            handler={"kind": "argument", "index": 1},
        )
    )

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.ESTABLISHED


@pytest.mark.parametrize(
    "mutation",
    [
        "counter += 1",
        "left, right = pair",
        "del counter",
        "if flag:\n    counter = 2",
        "match value:\n    case captured:\n        pass",
    ],
)
def test_unrelated_rebinding_and_branching_preserve_known_receiver(
    tmp_path: Path, mutation: str
) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "counter = 0\n"
        "pair = (1, 2)\n"
        "flag = True\n"
        "value = object()\n"
        f"{mutation}\n"
        "reactor.listen('orders', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert [item.identifier for item in inventory.endpoints] == ["REACTOR topic:orders"]
    assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.ESTABLISHED


@pytest.mark.parametrize(
    "expression",
    [
        "enabled and reactor.listen('orders', process)",
        "reactor.listen('orders', process) if enabled else None",
        "0 < value < reactor.listen('orders', process)",
    ],
)
def test_short_circuit_expression_registrations_are_conditional(
    tmp_path: Path, expression: str
) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "enabled = dynamic()\n"
        "value = dynamic()\n"
        f"{expression}\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert [item.identifier for item in inventory.endpoints] == ["REACTOR topic:orders"]
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL
    assert (
        inventory.endpoints[0].discovery_conditions[0].source_path
        == (tmp_path / "main.py").resolve()
    )


@pytest.mark.parametrize(
    "expression",
    [
        "False and reactor.listen('dead', process)",
        "reactor.listen('dead', process) if False else None",
        "2 < 1 < reactor.listen('dead', process)",
    ],
)
def test_literal_dead_expression_paths_are_skipped(tmp_path: Path, expression: str) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        f"{expression}\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
    ).extract_inventory()

    assert inventory.endpoints == []


def test_short_circuit_walrus_effects_are_joined_conservatively(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "enabled = dynamic()\n"
        "enabled and (reactor := object())\n"
        "reactor.listen('after', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
    ).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.limitations
    assert inventory.limitations[0].source_path == (tmp_path / "main.py").resolve()


@pytest.mark.parametrize(
    "mutation",
    [
        "reactor.settings = value",
        "reactor[make_index()] = value",
        "alias = reactor\nalias.settings = value",
        "alias = reactor\nalias[make_index()] = value",
        "(alias := reactor).settings = value",
        "(alias := reactor)[make_index()] = value",
        "(alias := (nested := reactor)).settings = value",
    ],
)
def test_receiver_and_exact_alias_target_mutations_fail_closed(
    tmp_path: Path, mutation: str
) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "value = object()\n"
        f"{mutation}\n"
        "reactor.listen('after', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
    ).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.limitations
    assert all(
        condition.source_path == (tmp_path / "main.py").resolve()
        for condition in inventory.limitations
    )


@pytest.mark.parametrize(
    "statement",
    [
        "target[reactor.listen('target', process)] = value",
        "target[reactor.listen('target', process)] += value",
        "del target[reactor.listen('target', process)]",
        "make_target(reactor.listen('target', process)).field = value",
    ],
)
def test_registration_calls_in_target_expressions_are_inspected(
    tmp_path: Path, statement: str
) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "target = object()\n"
        "value = object()\n"
        f"{statement}\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
    ).extract_inventory()

    assert [item.identifier for item in inventory.endpoints] == ["REACTOR topic:target"]
    assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.ESTABLISHED


def test_mutating_one_receiver_does_not_invalidate_an_independent_receiver(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "first = Reactor()\n"
        "second = Reactor()\n"
        "async def process(): pass\n"
        "first.settings = object()\n"
        "second.listen('orders', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
    ).extract_inventory()

    assert [item.identifier for item in inventory.endpoints] == ["REACTOR topic:orders"]
    assert inventory.status == InventoryStatus.ESTABLISHED


@pytest.mark.parametrize("terminal", ["break", "continue"])
def test_loop_terminal_skips_unreachable_later_body_registration(
    tmp_path: Path, terminal: str
) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "values = dynamic()\n"
        "def configure():\n"
        "    for item in values:\n"
        f"        {terminal}\n"
        "        reactor.listen('dead', process)\n"
        "    reactor.listen('after', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
        bootstrap_entry="main:configure",
    ).extract_inventory()

    assert [item.identifier for item in inventory.endpoints] == ["REACTOR topic:after"]
    assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL


@pytest.mark.parametrize(
    "control_flow",
    [
        "for item in values:\n        return",
        "while flag:\n        return",
    ],
)
def test_loop_return_makes_following_bootstrap_registration_conditional(
    tmp_path: Path, control_flow: str
) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "values = dynamic()\n"
        "flag = dynamic()\n"
        "def configure():\n"
        f"    {control_flow}\n"
        "    reactor.listen('after', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
        bootstrap_entry="main:configure",
    ).extract_inventory()

    assert [item.identifier for item in inventory.endpoints] == ["REACTOR topic:after"]
    assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL
    assert inventory.endpoints[0].discovery_conditions


def test_literal_true_loop_without_break_stops_following_bootstrap_registration(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "def configure():\n"
        "    while True:\n"
        "        pass\n"
        "    reactor.listen('dead', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
        bootstrap_entry="main:configure",
    ).extract_inventory()

    assert inventory.endpoints == []


def test_with_return_stops_following_bootstrap_registration(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "def configure():\n"
        "    with manager():\n"
        "        return\n"
        "    reactor.listen('dead', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
        bootstrap_entry="main:configure",
    ).extract_inventory()

    assert inventory.endpoints == []


def test_partial_return_makes_later_bootstrap_registration_conditional(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "flag = dynamic()\n"
        "def configure():\n"
        "    if flag:\n"
        "        return\n"
        "    reactor.listen('after', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
        bootstrap_entry="main:configure",
    ).extract_inventory()

    assert [item.identifier for item in inventory.endpoints] == ["REACTOR topic:after"]
    assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL
    assert inventory.endpoints[0].discovery_conditions


def test_unreachable_bootstrap_registration_after_raise_is_not_emitted(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "def configure():\n"
        "    raise RuntimeError\n"
        "    reactor.listen('dead', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
        bootstrap_entry="main:configure",
    ).extract_inventory()

    assert inventory.endpoints == []


def test_match_guard_false_path_invalidates_walrus_binding(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "subject = object()\n"
        "match subject:\n"
        "    case _ if (reactor := dynamic()):\n"
        "        pass\n"
        "reactor.listen('after', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
    ).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.limitations


def test_try_body_rebinding_is_not_stale_in_exception_handler(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "async def process(): pass\n"
        "try:\n"
        "    reactor = object()\n"
        "    risky()\n"
        "except Error:\n"
        "    reactor.listen('stale', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
    ).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.limitations
    assert inventory.limitations[0].source_line == 8


def test_try_intermediate_rebinding_cannot_restore_stale_exact_handler_state(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "original = reactor\n"
        "async def process(): pass\n"
        "def configure():\n"
        "    try:\n"
        "        reactor = object()\n"
        "        risky()\n"
        "        reactor = original\n"
        "    except Error:\n"
        "        pass\n"
        "    reactor.listen('after', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1})),
        bootstrap_entry="main:configure",
    ).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.limitations


@pytest.mark.parametrize(
    "imports",
    [
        "import a.b\nreactor = a.b.Reactor()",
        "import a.b as api\nreactor = api.Reactor()",
        "from a import b\nreactor = b.Reactor()",
    ],
)
def test_dotted_instance_receiver_import_spellings_are_equivalent(
    tmp_path: Path, imports: str
) -> None:
    (tmp_path / "main.py").write_text(
        f"async def process(): pass\n{imports}\nreactor.listen('orders', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(
            _contracts(
                tmp_path,
                symbol="a.b.Reactor.listen",
                receiver_type="a.b.Reactor",
                handler={"kind": "argument", "index": 1},
            )
        ),
    ).extract_inventory()

    assert [item.identifier for item in inventory.endpoints] == ["REACTOR topic:orders"]
    assert inventory.status == InventoryStatus.ESTABLISHED


def test_dotted_instance_receiver_does_not_use_wrong_root_identity(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "async def process(): pass\n"
        "import a.b\n"
        "reactor = a.Reactor()\n"
        "reactor.listen('orders', process)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_contracts(
            _contracts(
                tmp_path,
                symbol="a.b.Reactor.listen",
                receiver_type="a.b.Reactor",
                handler={"kind": "argument", "index": 1},
            )
        ),
    ).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.limitations


def test_wildcard_match_is_always_conditional_low_only(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from vendor.framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "@reactor.listen('orders')\n"
        "async def process(): pass\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(
        _contracts(
            tmp_path,
            symbol="vendor.*.Reactor.listen",
            receiver_type="vendor.framework.Reactor",
        )
    )

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    endpoint = inventory.endpoints[0]
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert endpoint.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
    assert endpoint.surface is not None and endpoint.surface.match_kind.value == "wildcard"
    assert "LOW-only wildcard" in endpoint.discovery_conditions[0].reason


def test_finite_positional_topics_expand_to_distinct_surfaces(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "@reactor.listen('payments', 'orders')\n"
        "async def process(): pass\n",
        encoding="utf-8",
    )
    path = _contracts(tmp_path)
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    payload["contracts"][0]["surface"]["resource"] = {
        "kind": "arguments",
        "index": 0,
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    inventory = CustomSurfaceExtractor(tmp_path, load_surface_contracts(path)).extract_inventory()

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "REACTOR topic:orders",
        "REACTOR topic:payments",
    ]


def test_literal_topic_collection_is_finite_and_deduplicated(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "@reactor.listen(['orders', 'payments', 'orders'])\n"
        "async def process(): pass\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path))

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert [endpoint.surface.resource for endpoint in inventory.endpoints if endpoint.surface] == [
        "orders",
        "payments",
    ]


def test_dynamic_member_of_topic_set_fails_closed_without_partial_fanout(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "dynamic = get_topic()\n\n"
        "@reactor.listen('orders', dynamic)\n"
        "async def process(): pass\n",
        encoding="utf-8",
    )
    path = _contracts(tmp_path)
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    payload["contracts"][0]["surface"]["resource"] = {
        "kind": "arguments",
        "index": 0,
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    inventory = CustomSurfaceExtractor(tmp_path, load_surface_contracts(path)).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert "resource set was not finite literal data" in inventory.limitations[0].reason


def test_resource_set_over_cap_fails_closed(tmp_path: Path) -> None:
    resources = ", ".join(repr(f"topic-{index}") for index in range(33))
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        f"@reactor.listen([{resources}])\n"
        "async def process(): pass\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path))

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL


def test_surface_provenance_is_visible_in_all_output_formats(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "@reactor.listen('orders')\n"
        "async def process(): pass\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path))
    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()
    endpoint = inventory.endpoints[0]
    affected = AffectedEndpoint(
        endpoint=endpoint,
        confidence=ConfidenceLevel.HIGH,
        reason="changed handler",
    )
    report = AnalysisReport(
        app_path=str(tmp_path),
        diff_source="change.diff",
        total_endpoints=1,
        affected_endpoints=[affected],
        candidate_endpoints=[affected],
    )

    rendered = {
        name: get_formatter(name).format(report)
        for name in ("json", "yaml", "text", "markdown", "html")
    }
    payload = json.loads(rendered["json"])

    assert payload["affected_endpoints"][0]["endpoint"]["surface"]["contract_id"] == "listener"
    for name, output in rendered.items():
        plain = re.sub(r"\x1b\[[0-9;]*m", "", output)
        assert "listener" in plain, name
        assert loaded.config_hash in plain, name
    for name in ("json", "yaml", "text", "markdown", "html"):
        inventory_output = get_formatter(name).format_inventory(inventory)
        assert "listener" in inventory_output, name


def test_exact_match_dominates_overlapping_wildcard_without_duplication(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from vendor.framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "@reactor.listen('orders')\n"
        "async def process(): pass\n",
        encoding="utf-8",
    )
    path = _contracts(
        tmp_path,
        symbol="vendor.framework.Reactor.listen",
        receiver_type="vendor.framework.Reactor",
    )
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    wildcard = dict(payload["contracts"][0])
    wildcard["id"] = "wildcard-listener"
    wildcard["registration"] = dict(wildcard["registration"])
    wildcard["registration"]["symbol"] = "vendor.*.Reactor.listen"
    payload["contracts"].append(wildcard)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    loaded = load_surface_contracts(path)

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert len(inventory.endpoints) == 1
    assert inventory.endpoints[0].surface is not None
    assert inventory.endpoints[0].surface.contract_id == "listener"
    assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.ESTABLISHED


def test_handler_redefinition_is_ambiguous_and_inventory_is_conditional(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "async def process(): pass\n"
        "async def process(): pass\n\n"
        "reactor.listen('orders', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert "handler was unresolved" in inventory.limitations[0].reason
