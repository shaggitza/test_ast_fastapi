"""Runtime FastAPI extractor parity tests."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from fastapi_endpoint_detector.parser.fastapi_extractor import (
    FastAPIExtractor,
    FastAPIExtractorError,
)
from fastapi_endpoint_detector.parser.secure_ast_extractor import SecureASTExtractor


def test_runtime_extractor_handles_websockets_and_mounted_fastapi(tmp_path: Path) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        """from fastapi import FastAPI

app = FastAPI()
sub = FastAPI()

@app.websocket("/events")
async def events(websocket):
    pass

@sub.get("/status")
def status():
    return {}

app.mount("/sub", sub)
"""
    )

    endpoints = FastAPIExtractor(app_file).extract_endpoints()

    custom = {
        endpoint.identifier for endpoint in endpoints if endpoint.path in {"/events", "/sub/status"}
    }
    assert custom == {"GET /sub/status", "WEBSOCKET /events"}


def test_runtime_extractor_preserves_slashes_websocket_dependencies_and_mount_cycles(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        """from fastapi import Depends, FastAPI

app = FastAPI()
sub = FastAPI()

def authenticate():
    return "token"

@sub.get("/")
def root():
    return {}

@app.websocket("/events/")
async def events(websocket, token=Depends(authenticate)):
    pass

app.mount("/sub", sub)
app.mount("/cycle", app)
"""
    )

    endpoints = FastAPIExtractor(app_file).extract_endpoints()

    assert {endpoint.identifier for endpoint in endpoints} >= {
        "GET /sub/",
        "WEBSOCKET /events/",
    }
    websocket = next(endpoint for endpoint in endpoints if endpoint.path == "/events/")
    assert websocket.dependencies == ["authenticate"]


def test_runtime_extractor_expands_nested_included_routers_with_effective_metadata(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "included_app.py"
    app_file.write_text(
        """from fastapi import APIRouter, Depends, FastAPI
from fastapi.routing import APIRoute


class AuditRoute(APIRoute):
    pass


def app_dependency():
    return "app"


def include_dependency():
    return "include"


def route_dependency():
    return "route"


def parameter_dependency():
    return "parameter"


inner = APIRouter(prefix="/inner", tags=["router"], route_class=AuditRoute)

@inner.get(
    "/items",
    tags=["route"],
    dependencies=[Depends(route_dependency)],
)
def items(token=Depends(parameter_dependency)):
    return {"token": token}

@inner.websocket("/socket", dependencies=[Depends(route_dependency)])
async def socket(websocket, token=Depends(parameter_dependency)):
    pass

outer = APIRouter(prefix="/outer")
outer.include_router(
    inner,
    prefix="/included",
    tags=["include"],
    dependencies=[Depends(include_dependency)],
)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(
    outer,
    prefix="/api",
    tags=["app"],
    dependencies=[Depends(app_dependency)],
)
"""
    )

    endpoints = FastAPIExtractor(app_file).extract_endpoints()

    assert {endpoint.identifier for endpoint in endpoints} == {
        "GET /api/outer/included/inner/items",
        "WEBSOCKET /api/outer/included/inner/socket",
    }
    http = next(endpoint for endpoint in endpoints if endpoint.methods[0].value == "GET")
    assert http.tags == ["app", "include", "router", "route"]
    assert http.dependencies == [
        "app_dependency",
        "include_dependency",
        "route_dependency",
        "parameter_dependency",
    ]
    assert http.handler.file_path == app_file
    assert http.handler.name == "items"

    websocket = next(endpoint for endpoint in endpoints if endpoint.path.endswith("/socket"))
    assert websocket.dependencies == [
        "app_dependency",
        "include_dependency",
        "route_dependency",
        "parameter_dependency",
    ]
    assert websocket.handler.file_path == app_file
    assert websocket.handler.name == "socket"


def test_runtime_and_secure_extractors_agree_on_static_nested_routes(tmp_path: Path) -> None:
    app_file = tmp_path / "differential_app.py"
    app_file.write_text(
        """from fastapi import APIRouter, FastAPI

inner = APIRouter(prefix="/inner")

@inner.get("/items")
def items():
    return {}

@inner.websocket("/socket")
async def socket(websocket):
    pass

outer = APIRouter(prefix="/outer")
outer.include_router(inner, prefix="/included")
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(outer, prefix="/api")
"""
    )

    runtime_endpoints = FastAPIExtractor(app_file).extract_endpoints()
    secure_endpoints = SecureASTExtractor(
        app_file, app_entry="differential_app:app"
    ).extract_endpoints()

    assert [endpoint.identifier for endpoint in runtime_endpoints] == [
        endpoint.identifier for endpoint in secure_endpoints
    ]


def test_runtime_extractor_preserves_multiple_include_occurrences_and_nested_mounts(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "reused_router_app.py"
    app_file.write_text(
        """from fastapi import APIRouter, FastAPI

shared = APIRouter()

@shared.get("/value")
def value():
    return {}

mounted = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
mounted.include_router(shared, prefix="/one")
mounted.include_router(shared, prefix="/two")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/service", mounted)
"""
    )

    endpoints = FastAPIExtractor(app_file).extract_endpoints()

    assert {endpoint.identifier for endpoint in endpoints} == {
        "GET /service/one/value",
        "GET /service/two/value",
    }


def test_runtime_extractor_handles_root_mounts(tmp_path: Path) -> None:
    app_file = tmp_path / "root_mount_app.py"
    app_file.write_text(
        """from fastapi import FastAPI

mounted = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

@mounted.get("/status")
def status():
    return {}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/", mounted)
"""
    )

    endpoints = FastAPIExtractor(app_file).extract_endpoints()

    assert {endpoint.identifier for endpoint in endpoints} == {"GET /status"}


def test_runtime_extractor_accepts_http_and_websocket_route_subclasses(tmp_path: Path) -> None:
    app_file = tmp_path / "custom_routes_app.py"
    app_file.write_text(
        """from fastapi import FastAPI
from fastapi.routing import APIRoute, APIWebSocketRoute

class AuditRoute(APIRoute):
    pass

class AuditWebSocketRoute(APIWebSocketRoute):
    pass


def custom_http():
    return {}


async def custom_websocket(websocket):
    pass


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.router.routes.append(AuditRoute("/custom", custom_http, methods=["GET"]))
app.router.routes.append(AuditWebSocketRoute("/custom-ws", custom_websocket))
"""
    )

    endpoints = FastAPIExtractor(app_file).extract_endpoints()

    assert {endpoint.identifier for endpoint in endpoints} == {
        "GET /custom",
        "WEBSOCKET /custom-ws",
    }
    assert {endpoint.handler.name for endpoint in endpoints} == {
        "custom_http",
        "custom_websocket",
    }
    assert {endpoint.handler.file_path for endpoint in endpoints} == {app_file}


def test_runtime_extractor_fails_closed_for_unsupported_http_methods(tmp_path: Path) -> None:
    app_file = tmp_path / "unsupported_method_app.py"
    app_file.write_text(
        """from fastapi import FastAPI
from fastapi.routing import APIRoute


def custom_http():
    return {}


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.router.routes.append(APIRoute("/custom", custom_http, methods=["PROPFIND"]))
"""
    )

    with pytest.raises(FastAPIExtractorError, match="Unsupported FastAPI HTTP methods: PROPFIND"):
        FastAPIExtractor(app_file).extract_endpoints()


def test_runtime_extractor_fails_closed_for_unknown_included_router_shape(
    tmp_path: Path,
) -> None:
    class UnknownIncludedRouter:
        original_router = object()
        include_context = object()

    extractor = FastAPIExtractor(tmp_path / "unused.py")
    extractor._app = SimpleNamespace(routes=[UnknownIncludedRouter()])

    with pytest.raises(
        FastAPIExtractorError,
        match="Unsupported included FastAPI router representation",
    ):
        extractor.extract_endpoints()
