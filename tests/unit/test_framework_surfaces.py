"""Exact FastAPI and Starlette lifecycle/middleware surface contracts."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.config import AnalysisConfig, Config
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointDiscoveryStatus,
    EndpointInventory,
    EndpointMethod,
    HandlerInfo,
    InventoryStatus,
)
from fastapi_endpoint_detector.models.surface_contract import load_surface_preset
from fastapi_endpoint_detector.parser.custom_surface_extractor import (
    CustomSurfaceExtractor,
    merge_surface_inventory,
)


def _extract(tmp_path: Path) -> EndpointInventory:
    return CustomSurfaceExtractor(
        tmp_path,
        load_surface_preset("framework-v1"),
    ).extract_inventory()


def test_fastapi_lifespan_splits_exact_pre_and_post_yield_ranges(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n\n"
        "@asynccontextmanager\n"
        "async def lifespan(app: FastAPI):\n"
        "    await initialize()\n"
        "    yield\n"
        "    await finalize()\n\n"
        "app = FastAPI(lifespan=lifespan)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "FRAMEWORK.LIFECYCLE lifespan:shutdown",
        "FRAMEWORK.LIFECYCLE lifespan:startup",
    ]
    shutdown, startup = inventory.endpoints
    assert (startup.handler.line_number, startup.handler.end_line_number) == (5, 7)
    assert (shutdown.handler.line_number, shutdown.handler.end_line_number) == (7, 8)
    assert startup.surface is not None
    assert startup.surface.callback_range.value == "before_yield"
    assert shutdown.surface is not None
    assert shutdown.surface.callback_range.value == "after_yield"


def test_lifespan_with_conditional_yield_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n\n"
        "@asynccontextmanager\n"
        "async def lifespan(app: FastAPI):\n"
        "    if enabled():\n"
        "        yield\n\n"
        "app = FastAPI(lifespan=lifespan)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("unconditional top-level yield" in item.reason for item in inventory.limitations)


def test_fastapi_decorator_lifecycle_callbacks_are_distinct(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None: pass\n\n"
        "@app.on_event('shutdown')\n"
        "def shutdown() -> None: pass\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "FRAMEWORK.LIFECYCLE event:shutdown",
        "FRAMEWORK.LIFECYCLE event:startup",
    ]
    assert all(
        endpoint.surface is not None and endpoint.surface.execution_mode.value == "framework"
        for endpoint in inventory.endpoints
    )


def test_starlette_imperative_lifecycle_callbacks_resolve_exact_handlers(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from starlette.applications import Starlette\n\n"
        "app = Starlette()\n\n"
        "async def start() -> None: pass\n"
        "def stop() -> None: pass\n\n"
        "app.add_event_handler('startup', start)\n"
        "app.add_event_handler('shutdown', stop)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.handler.name for endpoint in inventory.endpoints] == ["stop", "start"]


def test_fastapi_http_middleware_is_exact_async_surface(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "@app.middleware('http')\n"
        "async def timing(request, call_next):\n"
        "    return await call_next(request)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "FRAMEWORK.MIDDLEWARE protocol:http"
    ]
    assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.ESTABLISHED


def test_fastapi_class_middleware_resolves_exact_local_dispatch(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from starlette.middleware.base import BaseHTTPMiddleware as Base\n\n"
        "class TimingMiddleware(Base):\n"
        "    async def dispatch(self, request, call_next):\n"
        "        return await call_next(request)\n\n"
        "app = FastAPI()\n"
        "app.add_middleware(TimingMiddleware)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "FRAMEWORK.MIDDLEWARE protocol:http"
    ]
    endpoint = inventory.endpoints[0]
    assert endpoint.handler.name == "dispatch"
    assert (endpoint.handler.line_number, endpoint.handler.end_line_number) == (5, 6)
    assert endpoint.surface is not None
    assert endpoint.surface.contract_id == "fastapi-base-http-middleware"
    assert endpoint.surface.schema_version == 5


def test_starlette_class_middleware_resolves_imported_local_class(tmp_path: Path) -> None:
    (tmp_path / "middleware.py").write_text(
        "from starlette.middleware.base import BaseHTTPMiddleware\n\n"
        "class AuditMiddleware(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next):\n"
        "        return await call_next(request)\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from starlette.applications import Starlette\n"
        "from middleware import AuditMiddleware as Audit\n\n"
        "app = Starlette()\n"
        "app.add_middleware(Audit)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert len(inventory.endpoints) == 1
    assert inventory.endpoints[0].handler.file_path.name == "middleware.py"
    assert inventory.endpoints[0].surface is not None
    assert inventory.endpoints[0].surface.contract_id == "starlette-base-http-middleware"


def test_class_middleware_wrong_base_and_rebinding_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "class Unrelated:\n"
        "    async def dispatch(self, request, call_next):\n"
        "        return await call_next(request)\n\n"
        "app = FastAPI()\n"
        "app.add_middleware(Unrelated)\n"
        "Unrelated = factory()\n"
        "app.add_middleware(Unrelated)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert all("handler was unresolved" in item.reason for item in inventory.limitations)


def test_class_middleware_unsafe_base_and_dispatch_shapes_fail_closed(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from wrong import WrongBase\n"
        "from starlette.middleware.base import BaseHTTPMiddleware\n\n"
        "Alias = BaseHTTPMiddleware\n\n"
        "class ReboundBase(WrongBase):\n"
        "    async def dispatch(self, request, call_next): return await call_next(request)\n"
        "WrongBase = BaseHTTPMiddleware\n\n"
        "class DynamicBase(BaseHTTPMiddleware, factory()):\n"
        "    async def dispatch(self, request, call_next): return await call_next(request)\n\n"
        "class DuplicateBase(BaseHTTPMiddleware, Alias):\n"
        "    async def dispatch(self, request, call_next): return await call_next(request)\n\n"
        "class ReboundDispatch(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next): return await call_next(request)\n"
        "    dispatch = factory(dispatch)\n\n"
        "class ImportedDispatch(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next): return await call_next(request)\n"
        "    import math as dispatch\n\n"
        "class HeaderRebound(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next): return await call_next(request)\n"
        "    def other(self, value=(dispatch := None)): return value\n\n"
        "class WithMetaclass(BaseHTTPMiddleware, metaclass=Meta):\n"
        "    async def dispatch(self, request, call_next): return await call_next(request)\n\n"
        "class DynamicHeader(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request: factory(), call_next):\n"
        "        return await call_next(request)\n\n"
        "class StarCapture(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next): return await call_next(request)\n"
        "    match value:\n"
        "        case [*dispatch]: pass\n\n"
        "class MappingCapture(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next): return await call_next(request)\n"
        "    match value:\n"
        "        case {**dispatch}: pass\n\n"
        "app = FastAPI()\n"
        "app.add_middleware(ReboundBase)\n"
        "app.add_middleware(DynamicBase)\n"
        "app.add_middleware(DuplicateBase)\n"
        "app.add_middleware(ReboundDispatch)\n"
        "app.add_middleware(ImportedDispatch)\n"
        "app.add_middleware(HeaderRebound)\n"
        "app.add_middleware(WithMetaclass)\n"
        "app.add_middleware(DynamicHeader)\n"
        "app.add_middleware(StarCapture)\n"
        "app.add_middleware(MappingCapture)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.endpoints == []
    assert len(inventory.limitations) == 10


def test_imported_class_rebound_in_defining_module_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "middleware.py").write_text(
        "from starlette.middleware.base import BaseHTTPMiddleware\n\n"
        "class AuditMiddleware(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next):\n"
        "        return await call_next(request)\n"
        "AuditMiddleware = factory()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from middleware import AuditMiddleware\n\n"
        "app = FastAPI()\n"
        "app.add_middleware(AuditMiddleware)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL


def test_duplicate_middleware_protocol_retains_physical_handlers_conditionally(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "@app.middleware('http')\n"
        "async def first(request, call_next): return await call_next(request)\n\n"
        "@app.middleware('http')\n"
        "async def second(request, call_next): return await call_next(request)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.CONDITIONAL
    assert [endpoint.handler.name for endpoint in inventory.endpoints] == ["first", "second"]
    assert all(
        endpoint.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
        for endpoint in inventory.endpoints
    )


def test_startup_callback_adds_only_conditional_direct_routes(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "async def late() -> dict[str, bool]: return {'ready': True}\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.add_api_route('/late', late, methods=['POST'])\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.CONDITIONAL
    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "FRAMEWORK.LIFECYCLE event:startup",
        "POST /late",
    ]
    lifecycle = inventory.endpoints[0]
    assert lifecycle.surface is not None and lifecycle.surface.activates_routes is True
    route = inventory.endpoints[1]
    assert route.surface is None
    assert route.activation is not None
    assert route.activation.phase == "startup"
    assert route.activation.contract_id == "fastapi-on-event"
    assert route.activation.lifecycle_surface_id == "event:startup"
    assert route.activation.registration_file == (tmp_path / "main.py").resolve()
    assert route.activation.registration_line == 7
    assert route.activation.activation_file == (tmp_path / "main.py").resolve()
    assert route.activation.activation_line == 9
    assert route.activation.activation_source_hash.startswith("sha256:")
    assert len(route.activation.activation_source_hash) == 71
    assert lifecycle.surface.registration_source_hash.startswith("sha256:")
    assert route.handler.name == "late"
    assert route.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
    assert any("only if framework startup" in item.reason for item in route.discovery_conditions)


def test_startup_route_receiver_rebinding_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.add_api_route('/late', late)\n\n"
        "app = factory()\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "FRAMEWORK.LIFECYCLE event:startup"
    ]
    assert any("receiver was rebound" in item.reason for item in inventory.limitations)


def test_lifespan_adds_pre_yield_route_but_not_shutdown_route(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n\n"
        "async def early(): return {'phase': 'startup'}\n"
        "async def late(): return {'phase': 'shutdown'}\n\n"
        "@asynccontextmanager\n"
        "async def lifespan(app: FastAPI):\n"
        "    app.add_api_route('/early', early)\n"
        "    yield\n"
        "    app.add_api_route('/late', late)\n\n"
        "app = FastAPI(lifespan=lifespan)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "FRAMEWORK.LIFECYCLE lifespan:shutdown",
        "FRAMEWORK.LIFECYCLE lifespan:startup",
        "GET /early",
    ]
    assert all(endpoint.path != "/late" for endpoint in inventory.endpoints)


def test_startup_route_control_flow_and_dynamic_arguments_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    if enabled():\n"
        "        app.add_api_route('/guarded', late)\n"
        "    app.add_api_route(dynamic_path(), late)\n"
        "    app.include_router(build_router())\n"
        "    configure(app)\n"
        "    return\n"
        "    app.add_api_route('/unreachable', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "FRAMEWORK.LIFECYCLE event:startup"
    ]
    assert inventory.status == InventoryStatus.CONDITIONAL
    reasons = {item.reason for item in inventory.limitations}
    assert any("unsupported control flow" in reason for reason in reasons)
    assert any("dynamic or unresolved" in reason for reason in reasons)
    assert any("not finitely modeled" in reason for reason in reasons)
    assert any("receiver escapes" in reason for reason in reasons)


def test_startup_route_state_is_lexical_exact_and_source_sequential(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "other = FastAPI()\n\n"
        "async def first(): return 1\n"
        "async def second(): return 2\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    alias = app\n"
        "    handler = first\n"
        "    alias.add_api_route('/first', handler)\n"
        "    alias = other\n"
        "    alias.add_api_route('/other', second)\n"
        "    handler = second\n"
        "    app.add_api_route('/second', handler)\n"
        "    del handler\n"
        "    app.add_api_route('/missing', handler)\n"
        "    title = app.title\n",
        encoding="utf-8",
    )

    first = _extract(tmp_path)
    second = _extract(tmp_path)

    assert first == second
    assert [endpoint.identifier for endpoint in first.endpoints] == [
        "FRAMEWORK.LIFECYCLE event:startup",
        "GET /first",
        "GET /second",
    ]
    assert [endpoint.handler.name for endpoint in first.endpoints[1:]] == ["first", "second"]
    assert first.route_conditions == ()


def test_startup_whole_function_local_shadowing_omits_earlier_route(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "other = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.add_api_route('/not-global', late)\n"
        "    app = other\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "FRAMEWORK.LIFECYCLE event:startup"
    ]
    assert any("receiver was rebound" in item.reason for item in inventory.limitations)
    assert inventory.route_conditions == ()


def test_startup_lexical_handler_shadowing_and_nested_definition_fail_closed(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.add_api_route('/shadowed', late)\n"
        "    def late(): return None\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert all(endpoint.path != "/shadowed" for endpoint in inventory.endpoints)
    assert any("dynamic or unresolved" in item.reason for item in inventory.limitations)


@pytest.mark.parametrize(
    "nested_header",
    [
        "    def nested(value=(late := None)): pass\n",
        "    class Nested((late := object)): pass\n",
    ],
)
def test_startup_nested_eager_headers_contribute_lexical_bindings(
    tmp_path: Path,
    nested_header: str,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.add_api_route('/shadowed', late)\n" + nested_header,
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert all(endpoint.path != "/shadowed" for endpoint in inventory.endpoints)
    assert any("dynamic or unresolved" in item.reason for item in inventory.limitations)


def test_startup_compound_rebindings_invalidate_receivers_and_handlers(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "other = FastAPI()\n"
        "async def first(): return 1\n"
        "async def second(): return 2\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    alias = app\n"
        "    if enabled():\n"
        "        alias = other\n"
        "    alias.add_api_route('/stale-alias', first)\n"
        "    handler = first\n"
        "    if enabled():\n"
        "        handler = second\n"
        "    app.add_api_route('/stale-handler', handler)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert all(
        endpoint.path not in {"/stale-alias", "/stale-handler"} for endpoint in inventory.endpoints
    )
    assert inventory.route_conditions == ()


@pytest.mark.parametrize(
    "mutation",
    [
        "    if enabled():\n        app.router.routes = []\n",
        "    if enabled():\n        del app.router.routes[0]\n",
        "    app.router.routes += []\n",
        "    app.router = other.router\n",
        "    routes = app.router.routes\n    routes.clear()\n",
    ],
)
def test_startup_destructive_targets_and_route_aliases_are_route_wide(
    tmp_path: Path,
    mutation: str,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "other = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.add_api_route('/before', late)\n"
        + mutation
        + "    app.add_api_route('/after', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory == _extract(tmp_path)
    assert inventory.route_conditions
    routes = [endpoint for endpoint in inventory.endpoints if endpoint.surface is None]
    assert [endpoint.path for endpoint in routes] == ["/before"]
    assert all(
        endpoint.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
        and all(
            condition in endpoint.discovery_conditions for condition in inventory.route_conditions
        )
        for endpoint in routes
    )


@pytest.mark.parametrize(
    "escape",
    [
        "    return [app]\n",
        "    configure([app])\n",
        "    box.value = app\n",
        "    alias = app\n    alias = configure(alias)\n",
    ],
)
def test_startup_receiver_escapes_recurse_and_taint_exact_state(
    tmp_path: Path,
    escape: str,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.add_api_route('/before', late)\n"
        + escape
        + "    app.add_api_route('/after', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.route_conditions
    assert all(endpoint.path != "/after" for endpoint in inventory.endpoints)
    route = next(endpoint for endpoint in inventory.endpoints if endpoint.path == "/before")
    assert all(condition in route.discovery_conditions for condition in inventory.route_conditions)


def test_startup_assignment_rhs_clear_is_route_wide(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.add_api_route('/before', late)\n"
        "    result = app.router.routes.clear()\n"
        "    app.add_api_route('/after', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.route_conditions
    assert any("destructively call 'clear'" in item.reason for item in inventory.route_conditions)
    assert all(endpoint.path != "/after" for endpoint in inventory.endpoints)


def test_startup_unknown_route_collection_append_limits_inventory_only(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.router.routes.append(dynamic_route)\n",
        encoding="utf-8",
    )
    custom = _extract(tmp_path)
    known = Endpoint(
        path="/known",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="known",
            module="main",
            file_path=tmp_path / "main.py",
            line_number=1,
        ),
    )

    merged = merge_surface_inventory(EndpointInventory(endpoints=[known]), custom)

    assert merged.route_conditions == ()
    assert any("collection mutation 'append'" in item.reason for item in merged.limitations)
    assert next(endpoint for endpoint in merged.endpoints if endpoint.path == "/known") == known


def test_startup_compound_alias_then_clear_is_source_ordered(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.add_api_route('/before', late)\n"
        "    if enabled():\n"
        "        alias = app\n"
        "        alias.router.routes.clear()\n"
        "    app.add_api_route('/after', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.route_conditions
    assert any("destructively call 'clear'" in item.reason for item in inventory.route_conditions)
    assert all(endpoint.path != "/after" for endpoint in inventory.endpoints)


def test_startup_nested_definition_header_escape_is_eager(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.add_api_route('/before', late)\n"
        "    def nested(value=configure(app)): return value\n"
        "    app.add_api_route('/after', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.route_conditions
    assert all(endpoint.path != "/after" for endpoint in inventory.endpoints)


def test_postponed_nested_annotation_has_no_startup_route_effect(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from __future__ import annotations\n"
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def first(): return 1\n"
        "async def second(): return 2\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.add_api_route('/first', first)\n"
        "    def nested(value: configure(app)): return value\n"
        "    app.add_api_route('/second', second)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.route_conditions == ()
    assert [endpoint.path for endpoint in inventory.endpoints if endpoint.surface is None] == [
        "/first",
        "/second",
    ]


def test_startup_nested_class_additive_route_effect_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    class Configure:\n"
        "        app.add_api_route('/class-body', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert all(endpoint.path != "/class-body" for endpoint in inventory.endpoints)
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any(
        "unsupported control flow or expression" in item.reason for item in inventory.limitations
    )
    assert inventory.route_conditions == ()


@pytest.mark.parametrize(
    "class_effect",
    [
        "        app.router.routes.clear()\n",
        "        saved = app\n",
    ],
)
def test_startup_nested_class_destructive_and_escape_effects_are_route_wide(
    tmp_path: Path,
    class_effect: str,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def first(): return 1\n"
        "async def second(): return 2\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.add_api_route('/before', first)\n"
        "    class Configure:\n" + class_effect + "    app.add_api_route('/after', second)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.route_conditions
    assert [endpoint.path for endpoint in inventory.endpoints if endpoint.surface is None] == [
        "/before"
    ]
    assert any(
        "eager nested class body" in item.reason or "destructively call" in item.reason
        for item in inventory.route_conditions
    )


def test_startup_nested_inert_class_body_does_not_condition_inventory(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    class Metadata:\n"
        "        value = 1\n"
        "    app.add_api_route('/after', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.route_conditions == ()
    assert any(endpoint.path == "/after" for endpoint in inventory.endpoints)


def test_nested_startup_class_uses_nonclass_fallback_for_exact_app(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def first(): return 1\n"
        "async def second(): return 2\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.add_api_route('/before', first)\n"
        "    class Outer:\n"
        "        app = object()\n"
        "        class Inner:\n"
        "            app.router.routes.clear()\n"
        "    app.add_api_route('/after', second)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.route_conditions
    assert [endpoint.path for endpoint in inventory.endpoints if endpoint.surface is None] == [
        "/before"
    ]


def test_postponed_function_annotation_inside_startup_class_is_not_eager(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from __future__ import annotations\n"
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    class Metadata:\n"
        "        def nested(value: configure(app)): return value\n"
        "    app.add_api_route('/after', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.route_conditions == ()
    assert any(endpoint.path == "/after" for endpoint in inventory.endpoints)


def test_annotation_only_startup_class_target_does_not_mutate_routes(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.router: int\n"
        "    class Metadata:\n"
        "        app.router: int\n"
        "    app.add_api_route('/after', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.route_conditions == ()
    assert any(endpoint.path == "/after" for endpoint in inventory.endpoints)


def test_startup_class_local_app_shadow_does_not_condition_exact_app(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    class Metadata:\n"
        "        app = object()\n"
        "        app.add_api_route('/wrong', late)\n"
        "    app.add_api_route('/after', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.route_conditions == ()
    assert not any("receiver was rebound" in item.reason for item in inventory.limitations)
    assert any(endpoint.path == "/after" for endpoint in inventory.endpoints)


@pytest.mark.parametrize(
    "header",
    [
        "    def nested(value=(alias := None)): pass\n",
        "    @(alias := None)\n    def nested(): pass\n",
        "    class Nested((alias := None)): pass\n",
        "    def nested(value: (alias := None)): pass\n",
    ],
)
def test_startup_nested_headers_apply_named_expression_bindings(
    tmp_path: Path, header: str
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    alias = app\n"
        "    app.add_api_route('/before', late)\n"
        + header
        + "    alias.add_api_route('/after', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert all(endpoint.path != "/after" for endpoint in inventory.endpoints)
    assert any("receiver was rebound" in item.reason for item in inventory.limitations)


@pytest.mark.parametrize(
    "dead_effect",
    [
        "        if False:\n            app.router.routes.clear()\n",
        "        if False:\n            saved = app\n",
        "        while False:\n            app.router.routes.clear()\n",
        "        for item in ():\n            app.router.routes.clear()\n",
        "        False and app.router.routes.clear()\n",
        "        app.router.routes.clear() if False else None\n",
        "        values = [app.router.routes.clear() for item in ()]\n",
    ],
)
def test_dead_startup_class_effect_does_not_taint_routes(tmp_path: Path, dead_effect: str) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    class Metadata:\n" + dead_effect + "    app.add_api_route('/after', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.route_conditions == ()
    assert any(endpoint.path == "/after" for endpoint in inventory.endpoints)


def test_dead_class_assignment_does_not_hide_reachable_destructive_effect(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    class Configure:\n"
        "        if False:\n"
        "            app = object()\n"
        "        app.router.routes.clear()\n"
        "    app.add_api_route('/after', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.route_conditions
    assert all(endpoint.path != "/after" for endpoint in inventory.endpoints)


def test_unknown_startup_class_branches_remain_conservative(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    class Configure:\n"
        "        if condition:\n"
        "            app = object()\n"
        "        else:\n"
        "            app.router.routes.clear()\n"
        "    app.add_api_route('/after', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.route_conditions
    assert all(endpoint.path != "/after" for endpoint in inventory.endpoints)


def test_startup_class_raise_stops_later_route_discovery(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    class Configure:\n"
        "        raise RuntimeError()\n"
        "    app.add_api_route('/after', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert all(endpoint.path != "/after" for endpoint in inventory.endpoints)


def test_possible_startup_class_nonfallthrough_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    class Configure:\n"
        "        if condition:\n"
        "            raise RuntimeError()\n"
        "    app.add_api_route('/after', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert all(endpoint.path != "/after" for endpoint in inventory.endpoints)
    assert any("may not fall through" in item.reason for item in inventory.limitations)


def test_startup_activation_uses_pre_argument_receiver_capture(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "alias = app\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup', marker=(app := None))\n"
        "async def startup() -> None:\n"
        "    alias.add_api_route('/captured', late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert any(endpoint.path == "/captured" for endpoint in inventory.endpoints)


@pytest.mark.parametrize(
    "branch_body",
    [
        "        if condition:\n"
        "            app = object()\n"
        "            app.router.routes.clear()\n",
        "        if condition:\n"
        "            app = object()\n"
        "        else:\n"
        "            alias = app\n"
        "            alias.router.routes.clear()\n",
    ],
)
def test_possible_exact_startup_class_aliases_taint_route_wide(
    tmp_path: Path, branch_body: str
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def first(): return 1\n"
        "async def second(): return 2\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.add_api_route('/before', first)\n"
        "    class Configure:\n" + branch_body + "    app.add_api_route('/after', second)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.route_conditions
    assert all(endpoint.path != "/after" for endpoint in inventory.endpoints)
    before = next(endpoint for endpoint in inventory.endpoints if endpoint.path == "/before")
    assert before.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
    assert all(condition in before.discovery_conditions for condition in inventory.route_conditions)


def test_startup_class_global_uses_module_app_not_same_named_function_local(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "alias = app\n"
        "async def first(): return 1\n"
        "async def second(): return 2\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app = object()\n"
        "    alias.add_api_route('/before', first)\n"
        "    class Configure:\n"
        "        global app\n"
        "        app.router.routes.clear()\n"
        "    alias.add_api_route('/after', second)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.route_conditions
    assert all(endpoint.path != "/after" for endpoint in inventory.endpoints)
    before = next(endpoint for endpoint in inventory.endpoints if endpoint.path == "/before")
    assert all(condition in before.discovery_conditions for condition in inventory.route_conditions)


def test_imported_exact_app_discovers_finite_startup_route(tmp_path: Path) -> None:
    (tmp_path / "apps.py").write_text(
        "from fastapi import FastAPI\n\napp = FastAPI()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from apps import app\n\n"
        "async def imported_handler(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.add_api_route('/imported', imported_handler)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert any(endpoint.path == "/imported" for endpoint in inventory.endpoints)
    assert inventory.route_conditions == ()


def test_destructive_startup_condition_downgrades_only_native_routes(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.add_api_route('/late', late)\n"
        "    app.router.routes.clear()\n",
        encoding="utf-8",
    )
    custom = _extract(tmp_path)
    native = EndpointInventory(
        endpoints=[
            Endpoint(
                path="/known",
                methods=[EndpointMethod.GET],
                handler=HandlerInfo(
                    name="known",
                    module="main",
                    file_path=tmp_path / "main.py",
                    line_number=1,
                ),
            )
        ]
    )

    merged = merge_surface_inventory(native, custom)

    assert merged.route_conditions
    assert all(condition in merged.limitations for condition in merged.route_conditions)
    routes = [endpoint for endpoint in merged.endpoints if endpoint.surface is None]
    assert {endpoint.path for endpoint in routes} == {"/known", "/late"}
    assert all(
        endpoint.discovery_status == EndpointDiscoveryStatus.CONDITIONAL for endpoint in routes
    )
    lifecycle = next(endpoint for endpoint in merged.endpoints if endpoint.surface is not None)
    assert lifecycle.discovery_status == EndpointDiscoveryStatus.ESTABLISHED


def test_same_named_unrelated_lifecycle_method_never_matches(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from unrelated import App\n\n"
        "app = App()\n\n"
        "@app.on_event('startup')\n"
        "async def start() -> None: pass\n",
        encoding="utf-8",
    )

    assert _extract(tmp_path).endpoints == []


def test_framework_preset_loads_once() -> None:
    config = Config(analysis=AnalysisConfig(surface_preset="framework-v1"))

    first = config.load_surface_contract_snapshot()

    assert first is config.load_surface_contract_snapshot()
    assert first is not None
    assert first.document.preset.id == "framework-callbacks"
