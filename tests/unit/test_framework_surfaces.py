"""Exact FastAPI and Starlette lifecycle/middleware surface contracts."""

from pathlib import Path

from fastapi_endpoint_detector.config import AnalysisConfig, Config
from fastapi_endpoint_detector.models.endpoint import (
    EndpointDiscoveryStatus,
    EndpointInventory,
    InventoryStatus,
)
from fastapi_endpoint_detector.models.surface_contract import load_surface_preset
from fastapi_endpoint_detector.parser.custom_surface_extractor import CustomSurfaceExtractor


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
    assert endpoint.surface.schema_version == 4


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
