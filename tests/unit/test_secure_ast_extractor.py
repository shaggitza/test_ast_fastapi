"""
Unit tests for SecureASTExtractor.
"""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.parser.secure_ast_extractor import (
    SecureASTExtractor,
)


class TestSecureASTExtractor:
    """Tests for SecureASTExtractor class."""

    def test_init(self, tmp_path: Path) -> None:
        """Test extractor initialization."""
        app_file = tmp_path / "app.py"
        app_file.write_text("# test")

        extractor = SecureASTExtractor(app_path=app_file, app_variable="app")

        assert extractor.app_path == app_file.resolve()
        assert extractor.app_variable == "app"

    def test_extract_simple_get_endpoint(self, tmp_path: Path) -> None:
        """Test extracting a simple GET endpoint."""
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
def list_users():
    return []
""")

        extractor = SecureASTExtractor(app_path=app_file)
        endpoints = extractor.extract_endpoints()

        assert len(endpoints) >= 1
        # Find the /users endpoint
        users_endpoint = next((e for e in endpoints if e.path == "/users"), None)
        assert users_endpoint is not None
        assert "GET" in [m.value for m in users_endpoint.methods]

    @pytest.mark.parametrize("method", ["get", "post", "put", "patch", "delete"])
    def test_extract_different_http_methods(self, tmp_path: Path, method: str) -> None:
        """Test extracting different HTTP methods."""
        app_file = tmp_path / "app.py"
        app_file.write_text(f"""
from fastapi import FastAPI

app = FastAPI()

@app.{method}("/test")
def handler():
    return {{}}
""")

        extractor = SecureASTExtractor(app_path=app_file)
        endpoints = extractor.extract_endpoints()

        assert len(endpoints) >= 1
        test_endpoint = next((e for e in endpoints if e.path == "/test"), None)
        assert test_endpoint is not None
        assert method.upper() in [m.value for m in test_endpoint.methods]

    def test_extract_multiple_endpoints(self, tmp_path: Path) -> None:
        """Test extracting multiple endpoints from one file."""
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
def list_users():
    return []

@app.post("/users")
def create_user():
    return {}

@app.get("/items/{item_id}")
def get_item(item_id: int):
    return {}
""")

        extractor = SecureASTExtractor(app_path=app_file)
        endpoints = extractor.extract_endpoints()

        assert len(endpoints) >= 3
        paths = [e.path for e in endpoints]
        assert "/users" in paths
        assert "/items/{item_id}" in paths

    def test_extract_from_router(self, tmp_path: Path) -> None:
        """Test extracting endpoints from APIRouter."""
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from fastapi import APIRouter

router = APIRouter()

@router.get("/admin")
def admin_page():
    return {}
""")

        extractor = SecureASTExtractor(app_path=app_file, app_variable="router")
        endpoints = extractor.extract_endpoints()

        # An explicitly selected router can be analyzed as a root.
        admin_endpoint = next((e for e in endpoints if e.path == "/admin"), None)
        assert admin_endpoint is not None

    def test_no_code_execution(self, tmp_path: Path) -> None:
        """Test that no code is executed during extraction."""
        app_file = tmp_path / "app.py"
        # This code would crash if executed
        app_file.write_text("""
from fastapi import FastAPI

# This would fail if executed
raise RuntimeError("Code was executed!")

app = FastAPI()

@app.get("/test")
def test_handler():
    return {}
""")

        extractor = SecureASTExtractor(app_path=app_file)

        # Should not raise RuntimeError because code is not executed
        endpoints = extractor.extract_endpoints()

        # Should still find the endpoint
        test_endpoint = next((e for e in endpoints if e.path == "/test"), None)
        assert test_endpoint is not None

    def test_handles_syntax_errors_gracefully(self, tmp_path: Path) -> None:
        """Test that syntax errors are handled gracefully."""
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from fastapi import FastAPI

app = FastAPI(

# Syntax error - unclosed parenthesis
""")

        extractor = SecureASTExtractor(app_path=app_file)

        # Should not crash, just return empty list
        endpoints = extractor.extract_endpoints()
        assert isinstance(endpoints, list)

    def test_extract_from_directory(self, tmp_path: Path) -> None:
        """Test extracting endpoints from a directory."""
        # Create multiple files
        (tmp_path / "main.py").write_text("""
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def root():
    return {}
""")

        (tmp_path / "users.py").write_text("""
from fastapi import APIRouter

router = APIRouter()

@router.get("/users")
def list_users():
    return []
""")

        extractor = SecureASTExtractor(app_path=tmp_path)
        endpoints = extractor.extract_endpoints()

        # An unattached router is not publicly reachable from the discovered app.
        assert [endpoint.path for endpoint in endpoints] == ["/"]

    def test_handler_info_includes_file_and_line(self, tmp_path: Path) -> None:
        """Test that handler info includes file path and line numbers."""
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from fastapi import FastAPI

app = FastAPI()

@app.get("/test")
def test_handler():
    return {}
""")

        extractor = SecureASTExtractor(app_path=app_file)
        endpoints = extractor.extract_endpoints()

        test_endpoint = next((e for e in endpoints if e.path == "/test"), None)
        assert test_endpoint is not None
        assert test_endpoint.handler.file_path == app_file
        assert test_endpoint.handler.line_number > 0
        assert test_endpoint.handler.name == "test_handler"

    def test_composes_project_route_graph_without_execution(self, tmp_path: Path) -> None:
        """Compose imported/nested/repeated routers, mounts, and imperative routes."""
        routes = tmp_path / "routes"
        routes.mkdir()
        (routes / "__init__.py").write_text("")
        users_file = routes / "users.py"
        users_file.write_text(
            """from fastapi import APIRouter

BASE = "/v" + "1"
router = APIRouter(prefix=BASE)

@router.api_route("/users", methods=["GET", "POST"])
async def users():
    return []

@router.websocket("/events")
async def events(websocket):
    pass
"""
        )
        (routes / "nested.py").write_text(
            """from fastapi import APIRouter
from .users import router as users_router

router = APIRouter(prefix="/nested")
router.include_router(users_router, prefix="/members")
"""
        )
        main_file = tmp_path / "main.py"
        main_file.write_text(
            """from fastapi import FastAPI as API
import routes.nested as nested

app = API()
app.include_router(nested.router, prefix="/api")
app.include_router(nested.router, prefix="/admin")

async def health():
    return {}

app.add_api_route("/health", health, methods=["GET", "HEAD"])

sub = API()

@sub.get("/status")
def status():
    return {}

app.mount("/sub", sub)
"""
        )

        endpoints = SecureASTExtractor(tmp_path).extract_endpoints()

        assert {endpoint.identifier for endpoint in endpoints} == {
            "GET,POST /admin/nested/members/v1/users",
            "GET,POST /api/nested/members/v1/users",
            "GET,HEAD /health",
            "GET /sub/status",
            "WEBSOCKET /admin/nested/members/v1/events",
            "WEBSOCKET /api/nested/members/v1/events",
        }
        users = next(endpoint for endpoint in endpoints if endpoint.path.endswith("/users"))
        assert users.handler.file_path == users_file
        assert users.handler.name == "users"
        assert users.handler.end_line_number is not None

    def test_honors_exact_app_variable_and_file_imported_router(self, tmp_path: Path) -> None:
        """Select only the requested root and follow project-local package imports."""
        package = tmp_path / "pkg"
        package.mkdir()
        (package / "__init__.py").write_text("")
        (package / "routes.py").write_text(
            """from fastapi import APIRouter
router = APIRouter(prefix="/v1")
@router.get("/items/")
def items():
    return []
"""
        )
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI
from pkg import routes
app = FastAPI()
admin = FastAPI()
app.include_router(routes.router, prefix="/api")
@admin.get("/private")
def private():
    return {}
app.mount("/admin", admin)
"""
        )

        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(main, "app").extract_endpoints()
        ] == ["GET /admin/private", "GET /api/v1/items/"]
        assert [
            endpoint.identifier
            for endpoint in SecureASTExtractor(main, "admin").extract_endpoints()
        ] == ["GET /private"]
        assert SecureASTExtractor(main, "missing").extract_endpoints() == []

    def test_source_order_rebinding_and_include_snapshots(self, tmp_path: Path) -> None:
        """Respect top-level execution order, rebinding, and include-time route copies."""
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI, APIRouter
PREFIX = "/old"
router = APIRouter(prefix=PREFIX)
@router.get("/before")
def before():
    pass
app = FastAPI()
app.include_router(router)
PREFIX = "/new"
router = APIRouter(prefix=PREFIX)
@router.get("/after")
def after():
    pass
app.include_router(router)
app.include_router(router)
app = object()
@app.get("/not-fastapi")
def invalid():
    pass

def configure():
    app.include_router(router, prefix="/nested")
"""
        )

        # The requested binding is no longer a FastAPI instance. Earlier app state
        # must not leak through the rebinding.
        assert SecureASTExtractor(app_file).extract_endpoints() == []

        app_file.write_text(app_file.read_text().replace("app = object()", "other = object()"))
        identifiers = [
            endpoint.identifier for endpoint in SecureASTExtractor(app_file).extract_endpoints()
        ]
        assert identifiers == [
            "GET /new/after",
            "GET /new/after",
            "GET /not-fastapi",
            "GET /old/before",
        ]
        assert all("/nested" not in identifier for identifier in identifiers)

    def test_include_before_route_does_not_retroactively_copy_it(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI, APIRouter
app = FastAPI()
router = APIRouter()
app.include_router(router, prefix="/early")
@router.get("/later/")
def later():
    pass
app.include_router(router, prefix="/late")
"""
        )

        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(app_file).extract_endpoints()
        ] == ["GET /late/later/"]

    def test_ignores_shadowed_fastapi_constructor(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI

FastAPI = lambda: object()
app = FastAPI()

@app.get("/false")
def false_route():
    pass
"""
        )

        assert SecureASTExtractor(app_file).extract_endpoints() == []

    def test_skips_cross_module_router_mutation_after_include(self, tmp_path: Path) -> None:
        (tmp_path / "routes.py").write_text(
            """from fastapi import APIRouter
router = APIRouter(prefix="/snap")
"""
        )
        app_file = tmp_path / "main.py"
        app_file.write_text(
            """from fastapi import FastAPI
from routes import router

app = FastAPI()
app.include_router(router)

def late():
    pass

router.add_api_route("/late", late)
"""
        )

        assert SecureASTExtractor(app_file).extract_endpoints() == []

    def test_factory_composes_imported_router_prefixes_from_file_entry(
        self, tmp_path: Path
    ) -> None:
        routes = tmp_path / "routes.py"
        routes.write_text(
            """from fastapi import APIRouter
router = APIRouter(prefix="/items")

@router.get("/{item_id}")
def item(item_id: str):
    return item_id
"""
        )
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI
from routes import router

API_PREFIX = "/api" + "/v1"

def create_app():
    application = FastAPI()
    unused = FastAPI()

    @unused.get("/not-public")
    def hidden():
        return None

    application.include_router(router, prefix=API_PREFIX)
    return application

app = create_app()
"""
        )

        endpoints = SecureASTExtractor(main).extract_endpoints()

        assert [endpoint.identifier for endpoint in endpoints] == ["GET /api/v1/items/{item_id}"]
        assert endpoints[0].handler.file_path == routes

    def test_factory_skips_conditional_and_dynamic_registration(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI, APIRouter
router = APIRouter()

@router.get("/conditional")
def conditional():
    return None

def create_app():
    app = FastAPI()
    if unknown_flag:
        app.include_router(router)
    for prefix in prefixes:
        app.include_router(router, prefix=prefix)
    return app

app = create_app()
"""
        )

        assert SecureASTExtractor(main).extract_endpoints() == []

    def test_factory_preserves_router_include_snapshot_and_reassignment(
        self, tmp_path: Path
    ) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import APIRouter, FastAPI

def create_app():
    app = FastAPI()
    router = APIRouter(prefix="/factory")

    @router.get("/before")
    def before():
        return None

    app.include_router(router)

    @router.get("/after")
    def after():
        return None

    return app

app = create_app()
"""
        )

        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(main).extract_endpoints()
        ] == ["GET /factory/before"]

        main.write_text(main.read_text().replace("return app", "app = object()\n    return app"))
        assert SecureASTExtractor(main).extract_endpoints() == []

    def test_factory_supports_simple_direct_helper_and_langflow_style_router(
        self, tmp_path: Path
    ) -> None:
        api = tmp_path / "api"
        api.mkdir()
        (api / "__init__.py").write_text("")
        route_file = api / "v1.py"
        route_file.write_text(
            """from fastapi import APIRouter
router = APIRouter(prefix="/flows")

@router.post("/{flow_id}/run")
def run_flow(flow_id: str):
    return flow_id
"""
        )
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI
from api.v1 import router as v1_router

def health():
    return {"ok": True}

def base_app():
    result = FastAPI()
    result.add_api_route("/health", health, methods=["GET"])
    return result

def create_app():
    application = base_app()
    application.include_router(v1_router, prefix="/api/v1")
    return application

app = create_app()
"""
        )

        # Langflow-style modules bind the selected app to the factory result.
        endpoints = SecureASTExtractor(tmp_path).extract_endpoints()

        assert {endpoint.identifier for endpoint in endpoints} == {
            "GET /health",
            "POST /api/v1/flows/{flow_id}/run",
        }
        flow = next(endpoint for endpoint in endpoints if endpoint.path.endswith("/run"))
        assert flow.handler.file_path == route_file

    def test_uncalled_factory_is_not_synthesized(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI

def create_app():
    app = FastAPI()
    @app.get("/phantom")
    def phantom():
        return None
    return app
"""
        )

        assert SecureASTExtractor(main).extract_endpoints() == []

    def test_factory_constructor_reassignment_uses_only_returned_identity(
        self, tmp_path: Path
    ) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI

def create_app():
    app = FastAPI()
    @app.get("/old")
    def old():
        return None
    app = FastAPI()
    @app.get("/new")
    def new():
        return None
    return app

app = create_app()
"""
        )

        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(main).extract_endpoints()
        ] == ["GET /new"]

    def test_factory_call_respects_function_rebinding(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI

def create_app():
    app = FastAPI()
    return app

create_app = lambda: object()
app = create_app()
"""
        )

        assert SecureASTExtractor(main).extract_endpoints() == []

    def test_factory_respects_import_shadowing_before_call(self, tmp_path: Path) -> None:
        (tmp_path / "routes.py").write_text(
            """from fastapi import APIRouter
router = APIRouter()
@router.get("/wrong")
def wrong():
    return None
"""
        )
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI
from routes import router

def create_app():
    app = FastAPI()
    app.include_router(router)
    return app

router = object()
app = create_app()
"""
        )

        assert SecureASTExtractor(main).extract_endpoints() == []

    @pytest.mark.parametrize(
        "unsafe_body",
        [
            "del app",
            "if flag:\n        app = FastAPI()",
            "configure(app)",
            "if flag:\n        app.include_router(router)",
        ],
    )
    def test_factory_rejects_conditional_rebinding_and_unknown_mutation(
        self, tmp_path: Path, unsafe_body: str
    ) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            f"""from fastapi import APIRouter, FastAPI
router = APIRouter()

def configure(value):
    return value

def create_app():
    app = FastAPI()
    {unsafe_body}
    return app

app = create_app()
"""
        )

        assert SecureASTExtractor(main).extract_endpoints() == []

    @pytest.mark.parametrize(
        "return_body",
        [
            "if flag:\n        return app\n    return app",
            "if flag:\n        return app\n    else:\n        return app",
            "return app\n    return app",
        ],
    )
    def test_factory_rejects_ambiguous_returns(self, tmp_path: Path, return_body: str) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            f"""from fastapi import FastAPI

def create_app():
    app = FastAPI()
    {return_body}

app = create_app()
"""
        )

        assert SecureASTExtractor(main).extract_endpoints() == []

    def test_factory_binds_default_and_keyword_literal_parameters(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI

def health():
    return None

def create_app(base="/default", *, suffix="/health"):
    app = FastAPI()
    app.add_api_route(base + suffix, health)
    return app

app = create_app(base="/api")
"""
        )

        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(main).extract_endpoints()
        ] == ["GET /api/health"]

    def test_factory_binds_required_and_positional_only_parameters(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI

def health():
    return None

def create_app(base, /, suffix):
    app = FastAPI()
    app.add_api_route(base + suffix, health)
    return app

app = create_app("/api", "/health")
"""
        )

        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(main).extract_endpoints()
        ] == ["GET /api/health"]

    def test_factory_default_captures_definition_time_global(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI

PREFIX = "/old"
def health():
    return None

def create_app(prefix=PREFIX):
    app = FastAPI()
    app.add_api_route(prefix + "/health", health)
    return app

PREFIX = "/new"
app = create_app()
"""
        )

        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(main).extract_endpoints()
        ] == ["GET /old/health"]

    @pytest.mark.parametrize(
        "shadow",
        [
            "FastAPI = lambda: object()",
            "def FastAPI():\n        return object()",
            "del FastAPI",
            "from fake import FastAPI",
        ],
    )
    def test_factory_local_constructor_shadowing_fails_closed(
        self, tmp_path: Path, shadow: str
    ) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            f"""from fastapi import FastAPI

def create_app():
    {shadow}
    app = FastAPI()
    return app

app = create_app()
"""
        )

        assert SecureASTExtractor(main).extract_endpoints() == []

    def test_factory_local_router_and_helper_shadowing_fails_closed(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import APIRouter, FastAPI
router = APIRouter()
@router.get("/false")
def false_route():
    return None

def base_app():
    app = FastAPI()
    return app

def create_app():
    def base_app():
        return object()
    router = object()
    app = base_app()
    app.include_router(router)
    return app

app = create_app()
"""
        )

        assert SecureASTExtractor(main).extract_endpoints() == []

    def test_module_delete_and_rebinding_invalidate_app_and_router(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import APIRouter, FastAPI
router = APIRouter()
@router.get("/false")
def false_route():
    return None

del router
app = FastAPI()
app.include_router(router)
del app
"""
        )

        assert SecureASTExtractor(main).extract_endpoints() == []

    def test_factory_chained_alias_mutation_is_rejected(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI

def create_app():
    app = FastAPI()
    @app.get("/false")
    def route():
        return None
    alias = other = app
    alias.routes.clear()
    return app

app = create_app()
"""
        )

        assert SecureASTExtractor(main).extract_endpoints() == []

    def test_factory_called_nested_mutator_is_rejected(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI

def create_app():
    app = FastAPI()
    @app.get("/false")
    def route():
        return None
    def wipe():
        app.routes.clear()
    wipe()
    return app

app = create_app()
"""
        )

        assert SecureASTExtractor(main).extract_endpoints() == []

    def test_factory_alias_registration_and_unknown_alias_mutation(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import APIRouter, FastAPI
router = APIRouter()
@router.get("/ok")
def ok():
    return None

def create_app():
    app = FastAPI()
    alias = app
    alias.include_router(router)
    return app

app = create_app()
"""
        )
        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(main).extract_endpoints()
        ] == ["GET /ok"]

        main.write_text(
            main.read_text().replace("alias.include_router(router)", "configure(alias)")
        )
        assert SecureASTExtractor(main).extract_endpoints() == []

    def test_factory_rejects_nested_receiver_mutation_of_alias(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI

def create_app():
    app = FastAPI()
    holder = app
    holder.routes.clear()
    return app

app = create_app()
"""
        )

        assert SecureASTExtractor(main).extract_endpoints() == []

    def test_factory_nested_helper_routes_use_runtime_snapshot_not_source_lines(
        self, tmp_path: Path
    ) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import APIRouter, FastAPI

def create_app():
    app = FastAPI()
    router = make_router()
    app.include_router(router)
    return app

def make_router():
    router = APIRouter(prefix="/nested")
    @router.get("/ok")
    def ok():
        return None
    return router

app = create_app()
"""
        )

        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(main).extract_endpoints()
        ] == ["GET /nested/ok"]

    def test_factory_snapshots_module_router_at_call_time(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import APIRouter, FastAPI
router = APIRouter()
@router.get("/before")
def before():
    return None

def create_app():
    app = FastAPI()
    app.include_router(router)
    return app

app = create_app()

@router.get("/after")
def after():
    return None
"""
        )

        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(main).extract_endpoints()
        ] == ["GET /before"]

    def test_factory_same_line_objects_have_unique_identity(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI

def health():
    return None

def create_app():
    first = FastAPI(); second = FastAPI(); second.add_api_route("/ok", health); return second

app = create_app()
"""
        )

        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(main).extract_endpoints()
        ] == ["GET /ok"]

    def test_router_file_fallback_requires_latest_router_binding(self, tmp_path: Path) -> None:
        router_file = tmp_path / "routes.py"
        router_file.write_text(
            """from fastapi import APIRouter
router = APIRouter()
@router.get("/false")
def false_route():
    return None
router = object()
"""
        )

        assert SecureASTExtractor(router_file, app_variable="router").extract_endpoints() == []

    def test_cross_module_factory_resolution_is_file_order_independent(
        self, tmp_path: Path
    ) -> None:
        caller = tmp_path / "a_caller.py"
        caller.write_text(
            """from z_factory import create_app
app = create_app()
"""
        )
        (tmp_path / "y_helper.py").write_text(
            """from fastapi import FastAPI

def base_app():
    app = FastAPI()
    @app.get("/cross-module")
    def route():
        return None
    return app
"""
        )
        (tmp_path / "z_factory.py").write_text(
            """from y_helper import base_app

def create_app():
    app = base_app()
    return app
"""
        )

        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(caller).extract_endpoints()
        ] == ["GET /cross-module"]

    def test_ignores_unproven_route_receivers_and_dynamic_paths(self, tmp_path: Path) -> None:
        """Do not interpret arbitrary methods or unresolved paths as FastAPI routes."""
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI

app = FastAPI()
client = object()
PATH = unknown_value

@client.get("/not-a-route")
def client_get():
    pass

@app.get(PATH)
def dynamic():
    pass
"""
        )

        assert SecureASTExtractor(app_file).extract_endpoints() == []
