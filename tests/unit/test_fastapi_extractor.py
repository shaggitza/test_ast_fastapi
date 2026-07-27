"""Runtime FastAPI extractor parity tests."""

import os
import py_compile
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

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
        extractor._extract_endpoints_in_process()


def test_runtime_extractor_imports_package_directory_with_relative_routes(tmp_path: Path) -> None:
    package = tmp_path / "runtime_package"
    package.mkdir()
    (package / "__init__.py").write_text(
        """from fastapi import FastAPI
from .routes import router

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)
"""
    )
    routes = package / "routes.py"
    routes.write_text(
        """from fastapi import APIRouter

router = APIRouter()

@router.get("/package")
def package_route():
    return {}
"""
    )

    endpoints = FastAPIExtractor(package).extract_endpoints()

    assert [endpoint.identifier for endpoint in endpoints] == ["GET /package"]
    assert endpoints[0].handler.module == "runtime_package.routes"
    assert endpoints[0].handler.file_path == routes
    assert "runtime_package" not in sys.modules
    assert "runtime_package.routes" not in sys.modules


def test_runtime_extractor_imports_nested_package_file_with_relative_routes(
    tmp_path: Path,
) -> None:
    package = tmp_path / "outer_package"
    nested = package / "api"
    nested.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (nested / "__init__.py").write_text("")
    routes = nested / "routes.py"
    routes.write_text(
        """from fastapi import APIRouter

router = APIRouter()

@router.get("/nested")
def nested_route():
    return {}
"""
    )
    main = nested / "main.py"
    main.write_text(
        """from fastapi import FastAPI
from .routes import router

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)
"""
    )

    endpoints = FastAPIExtractor(main).extract_endpoints()

    assert [endpoint.identifier for endpoint in endpoints] == ["GET /nested"]
    assert endpoints[0].handler.module == "outer_package.api.routes"
    assert endpoints[0].handler.file_path == routes


def test_runtime_extractor_supports_explicit_namespace_module_name(tmp_path: Path) -> None:
    namespace = tmp_path / "runtime_namespace"
    namespace.mkdir()
    routes = namespace / "routes.py"
    routes.write_text(
        """from fastapi import APIRouter

router = APIRouter()

@router.get("/namespace")
def namespace_route():
    return {}
"""
    )
    main = namespace / "main.py"
    main.write_text(
        """from fastapi import FastAPI
from .routes import router

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)
"""
    )

    endpoints = FastAPIExtractor(
        main,
        module_name="runtime_namespace.main",
    ).extract_endpoints()

    assert [endpoint.identifier for endpoint in endpoints] == ["GET /namespace"]
    assert endpoints[0].handler.module == "runtime_namespace.routes"
    assert endpoints[0].handler.file_path == routes


def test_runtime_extractor_isolates_colliding_modules_and_preserves_parent_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "runtime_collision_helper"
    sentinel = ModuleType(module_name)
    sentinel.__dict__["marker"] = "parent"
    monkeypatch.setitem(sys.modules, module_name, sentinel)
    original_path = list(sys.path)

    projects: list[Path] = []
    for project_name, route_path in (("one", "/one"), ("two", "/two")):
        project = tmp_path / project_name
        project.mkdir()
        (project / f"{module_name}.py").write_text(f"ROUTE_PATH = {route_path!r}\n")
        (project / "main.py").write_text(
            f"""from fastapi import FastAPI
from {module_name} import ROUTE_PATH

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

@app.get(ROUTE_PATH)
def endpoint():
    return {{}}
"""
        )
        projects.append(project)

    first = FastAPIExtractor(projects[0] / "main.py").extract_endpoints()
    second = FastAPIExtractor(projects[1] / "main.py").extract_endpoints()

    assert [endpoint.identifier for endpoint in first] == ["GET /one"]
    assert [endpoint.identifier for endpoint in second] == ["GET /two"]
    assert sys.modules[module_name] is sentinel
    assert sentinel.__dict__["marker"] == "parent"
    assert sys.path == original_path


def test_runtime_extractor_reloads_project_modules_on_each_extraction(tmp_path: Path) -> None:
    helper = tmp_path / "runtime_reload_helper.py"
    helper.write_text('ROUTE_PATH = "/before"\n')
    main = tmp_path / "main.py"
    main.write_text(
        """from fastapi import FastAPI
from runtime_reload_helper import ROUTE_PATH

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

@app.get(ROUTE_PATH)
def endpoint():
    return {}
"""
    )
    extractor = FastAPIExtractor(main)

    first = extractor.extract_endpoints()
    helper.write_text('ROUTE_PATH = "/after-change"\n')
    second = extractor.extract_endpoints()

    assert [endpoint.identifier for endpoint in first] == ["GET /before"]
    assert [endpoint.identifier for endpoint in second] == ["GET /after-change"]
    assert "runtime_reload_helper" not in sys.modules


def test_runtime_extractor_ignores_existing_stale_bytecode(tmp_path: Path) -> None:
    helper = tmp_path / "runtime_stale_helper.py"
    helper.write_text('ROUTE_PATH = "/before"\n')
    py_compile.compile(str(helper), doraise=True)
    original_stat = helper.stat()
    helper.write_text('ROUTE_PATH = "/afterx"\n')
    os.utime(helper, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    main = tmp_path / "main.py"
    main.write_text(
        """from fastapi import FastAPI
from runtime_stale_helper import ROUTE_PATH

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

@app.get(ROUTE_PATH)
def endpoint():
    return {}
"""
    )

    endpoints = FastAPIExtractor(main).extract_endpoints()

    assert [endpoint.identifier for endpoint in endpoints] == ["GET /afterx"]


def test_runtime_extractor_failure_and_timeout_leave_parent_state_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "runtime_failure_helper"
    sentinel = ModuleType(module_name)
    monkeypatch.setitem(sys.modules, module_name, sentinel)
    original_path = list(sys.path)
    (tmp_path / f"{module_name}.py").write_text("VALUE = 1\n")
    failing = tmp_path / "failing.py"
    failing.write_text(
        f"""from {module_name} import VALUE
raise RuntimeError(f"failed after import: {{VALUE}}")
"""
    )

    with pytest.raises(FastAPIExtractorError, match="failed after import: 1"):
        FastAPIExtractor(failing).extract_endpoints()

    hanging = tmp_path / "hanging.py"
    hanging.write_text("import time\ntime.sleep(10)\n")
    started = time.monotonic()
    with pytest.raises(FastAPIExtractorError, match="timed out"):
        FastAPIExtractor(hanging, timeout_seconds=0.2).extract_endpoints()

    assert time.monotonic() - started < 5
    assert sys.modules[module_name] is sentinel
    assert sys.path == original_path


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-session cleanup")
def test_runtime_extractor_reaps_worker_when_parent_is_interrupted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app_file = tmp_path / "hanging.py"
    app_file.write_text("import time\ntime.sleep(10)\n")
    worker_pids: list[int] = []

    def interrupt_communicate(
        process: subprocess.Popen[str],
        *_args: object,
        **_kwargs: object,
    ) -> tuple[str, str]:
        worker_pids.append(process.pid)
        raise KeyboardInterrupt

    monkeypatch.setattr(subprocess.Popen, "communicate", interrupt_communicate)

    with pytest.raises(KeyboardInterrupt):
        FastAPIExtractor(app_file).extract_endpoints()

    assert len(worker_pids) == 1
    with pytest.raises(ProcessLookupError):
        os.kill(worker_pids[0], 0)


def test_runtime_extractor_reports_worker_hard_exit(tmp_path: Path) -> None:
    app_file = tmp_path / "hard_exit.py"
    app_file.write_text("import os\nos._exit(7)\n")

    with pytest.raises(FastAPIExtractorError, match="status 7"):
        FastAPIExtractor(app_file).extract_endpoints()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"timeout_seconds": 0}, "timeout_seconds must be a finite positive number"),
        ({"timeout_seconds": float("nan")}, "timeout_seconds must be a finite positive number"),
        ({"timeout_seconds": float("inf")}, "timeout_seconds must be a finite positive number"),
        ({"timeout_seconds": True}, "timeout_seconds must be a finite positive number"),
        ({"output_limit_bytes": 0}, "output_limit_bytes must be a positive integer"),
        ({"output_limit_bytes": 1.5}, "output_limit_bytes must be a positive integer"),
        ({"output_limit_bytes": True}, "output_limit_bytes must be a positive integer"),
    ],
)
def test_runtime_extractor_rejects_invalid_worker_limits(
    tmp_path: Path,
    kwargs: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        FastAPIExtractor(tmp_path / "main.py", **kwargs)
