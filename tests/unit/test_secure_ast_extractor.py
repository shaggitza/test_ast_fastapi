"""
Unit tests for SecureASTExtractor.
"""

import sys
from pathlib import Path

import pytest

from fastapi_endpoint_detector.models.endpoint import (
    EndpointDiscoveryStatus,
    InventoryStatus,
)
from fastapi_endpoint_detector.parser.secure_ast_extractor import (
    SecureASTExtractor,
    SecureASTExtractorError,
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

    def test_explicit_app_entry_selects_object_as_only_root(self, tmp_path: Path) -> None:
        app_file = tmp_path / "main.py"
        app_file.write_text(
            """from fastapi import FastAPI
primary = FastAPI()
secondary = FastAPI()
@primary.get('/primary')
def primary_route(): return {}
@secondary.get('/secondary')
def secondary_route(): return {}
"""
        )

        endpoints = SecureASTExtractor(tmp_path, app_entry="main:primary").extract_endpoints()

        assert [endpoint.identifier for endpoint in endpoints] == ["GET /primary"]

    def test_explicit_app_entry_authorizes_uncalled_zero_arg_factory(self, tmp_path: Path) -> None:
        (tmp_path / "routes.py").write_text(
            """from fastapi import APIRouter
router = APIRouter()
@router.get('/items')
def items(): return []
"""
        )
        (tmp_path / "main.py").write_text(
            """from fastapi import FastAPI
from routes import router
def create_app(title='safe'):
    app = FastAPI(title=title)
    app.include_router(router, prefix='/api')
    return app
"""
        )

        assert SecureASTExtractor(tmp_path).extract_endpoints() == []
        endpoints = SecureASTExtractor(tmp_path, app_entry="main:create_app").extract_endpoints()

        assert [endpoint.identifier for endpoint in endpoints] == ["GET /api/items"]

    def test_explicit_app_entry_selects_factory_produced_object(self, tmp_path: Path) -> None:
        (tmp_path / "main.py").write_text(
            """from fastapi import FastAPI
def create_app():
    service = FastAPI()
    @service.get('/factory-object')
    def route(): return {}
    return service
app = create_app()
"""
        )

        endpoints = SecureASTExtractor(tmp_path, app_entry="main:app").extract_endpoints()

        assert [endpoint.identifier for endpoint in endpoints] == ["GET /factory-object"]

    def test_explicit_factory_retains_known_routes_with_conditional_provenance(
        self, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "main.py"
        app_file.write_text(
            """from fastapi import FastAPI, APIRouter
router = APIRouter()
@router.get('/known')
def known(): return {}
def load_plugins(app): pass
def create_app():
    app = FastAPI()
    app.include_router(router, prefix='/api')
    load_plugins(app)
    return app
"""
        )

        assert SecureASTExtractor(tmp_path).extract_endpoints() == []
        inventory = SecureASTExtractor(tmp_path, app_entry="main:create_app").extract_inventory()
        endpoints = inventory.endpoints

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.limitations
        assert [endpoint.identifier for endpoint in endpoints] == ["GET /api/known"]
        endpoint = endpoints[0]
        assert endpoint.discovery_status.value == "conditional"
        assert len(endpoint.discovery_conditions) == 1
        assert endpoint.discovery_conditions[0].source_path == app_file
        assert endpoint.discovery_conditions[0].source_line == 9
        assert "unresolved call" in endpoint.discovery_conditions[0].reason

    def test_nested_imported_router_factory_propagates_conditions(self, tmp_path: Path) -> None:
        (tmp_path / "routes.py").write_text(
            """from fastapi import APIRouter
def plugin(router): pass
def build_router():
    router = APIRouter()
    @router.get('/known')
    def known(): return {}
    plugin(router)
    return router
"""
        )
        (tmp_path / "main.py").write_text(
            """from fastapi import FastAPI
from routes import build_router
def create_app():
    app = FastAPI()
    router = build_router()
    app.include_router(router, prefix='/api')
    return app
"""
        )

        endpoint = SecureASTExtractor(tmp_path, app_entry="main:create_app").extract_endpoints()[0]

        assert endpoint.identifier == "GET /api/known"
        assert endpoint.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
        assert endpoint.discovery_conditions[0].source_path.name == "routes.py"

    def test_explicit_factory_does_not_invent_routes_from_unresolved_plugin(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "main.py").write_text(
            """from fastapi import FastAPI
def load_plugins(app): pass
def create_app():
    app = FastAPI()
    load_plugins(app)
    return app
"""
        )

        extractor = SecureASTExtractor(tmp_path, app_entry="main:create_app")
        inventory = extractor.extract_inventory()

        assert inventory.endpoints == []
        assert inventory.status == InventoryStatus.CONDITIONAL
        assert len(inventory.limitations) == 1
        assert "unresolved call" in inventory.limitations[0].reason
        assert extractor.extract_endpoints() == []

    def test_dynamic_app_state_marks_explicit_factory_conditional(self, tmp_path: Path) -> None:
        (tmp_path / "main.py").write_text(
            """from fastapi import FastAPI
def build_state(): return object()
def create_app():
    app = FastAPI()
    app.state.service = build_state()
    @app.get('/known')
    def known(): return {}
    return app
"""
        )

        endpoint = SecureASTExtractor(tmp_path, app_entry="main:create_app").extract_endpoints()[0]

        assert endpoint.discovery_status.value == "conditional"
        assert "app.state" in endpoint.discovery_conditions[0].reason

    def test_arbitrary_app_attribute_assignment_remains_a_hard_failure(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "main.py").write_text(
            """from fastapi import FastAPI
def create_app():
    app = FastAPI()
    app.routes = []
    @app.get('/not-proven')
    def route(): return {}
    return app
"""
        )

        with pytest.raises(SecureASTExtractorError, match="cannot be summarized safely"):
            SecureASTExtractor(tmp_path, app_entry="main:create_app").extract_endpoints()

    @pytest.mark.parametrize(
        "source",
        [
            "async def create_app():\n    return None\n",
            "@decorator\ndef create_app():\n    return None\n",
            "def create_app(required):\n    return required\n",
            "def create_app():\n    return None\ncreate_app = other\n",
            "def create_app():\n    return None\ndef create_app():\n    return None\n",
        ],
    )
    def test_explicit_app_entry_rejects_unsafe_factory(self, tmp_path: Path, source: str) -> None:
        app_file = tmp_path / "main.py"
        app_file.write_text("from fastapi import FastAPI\n" + source)

        with pytest.raises(SecureASTExtractorError):
            SecureASTExtractor(tmp_path, app_entry="main:create_app").extract_endpoints()

    @pytest.mark.parametrize("entry", ["main", "main:", ":app", "main:app:extra", "bad-name:app"])
    def test_explicit_app_entry_requires_exact_module_symbol(
        self, tmp_path: Path, entry: str
    ) -> None:
        with pytest.raises(SecureASTExtractorError, match="MODULE:SYMBOL"):
            SecureASTExtractor(tmp_path, app_entry=entry)

    def test_missing_selected_root_is_unavailable_not_established_empty(
        self, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "main.py"
        app_file.write_text("value = 1\n")
        extractor = SecureASTExtractor(app_file)

        inventory = extractor.extract_inventory()

        assert inventory.status == InventoryStatus.UNAVAILABLE
        assert inventory.endpoints == []
        assert inventory.limitations
        assert extractor.extract_endpoints() == []

    def test_explicit_bootstrap_applies_imported_nested_registration_helpers(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "routes.py").write_text(
            """from fastapi import APIRouter
router = APIRouter()
@router.get('/items')
def items(): return []
"""
        )
        (tmp_path / "configure.py").write_text(
            """def nested(target, router, prefix):
    alias = target
    alias.include_router(router, prefix=prefix)
def configure(app):
    from routes import router
    nested(target=app, router=router, prefix='/api')
"""
        )
        (tmp_path / "main.py").write_text(
            """from fastapi import FastAPI
from configure import configure
app = FastAPI()
def run(enabled=True):
    configure(app)
"""
        )

        endpoints = SecureASTExtractor(tmp_path, bootstrap_entry="main:run").extract_endpoints()

        assert [endpoint.identifier for endpoint in endpoints] == ["GET /api/items"]

    def test_bootstrap_never_aliases_selected_root_to_conventional_app_name(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "main.py").write_text("from fastapi import FastAPI\nservice = FastAPI()\n")
        (tmp_path / "boot.py").write_text(
            """from fastapi import APIRouter, FastAPI
app = FastAPI()
router = APIRouter()
@router.get('/private')
def private(): return None
def run():
    app.include_router(router)
"""
        )

        inventory = SecureASTExtractor(
            tmp_path,
            app_entry="main:service",
            bootstrap_entry="boot:run",
        ).extract_inventory()

        assert inventory.endpoints == []
        assert inventory.status == InventoryStatus.ESTABLISHED

    def test_bootstrap_zero_argument_defaults_and_return_stop_execution(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "main.py").write_text(
            """from fastapi import APIRouter, FastAPI
app = FastAPI()
router = APIRouter()
@router.get('/late')
def late(): return None
def run(target=None):
    return
    app.include_router(router)
"""
        )

        assert SecureASTExtractor(tmp_path, bootstrap_entry="main:run").extract_endpoints() == []

    @pytest.mark.parametrize(
        "registration",
        [
            "app.include_router(*[router])",
            "app.include_router(router, **{'prefix': '/x'})",
            "app.include_router(router, prefix=dynamic)",
            "choose().include_router(router)",
        ],
    )
    def test_bootstrap_ambiguous_direct_registration_is_conditional(
        self, tmp_path: Path, registration: str
    ) -> None:
        (tmp_path / "main.py").write_text(
            f"""from fastapi import APIRouter, FastAPI
app = FastAPI()
router = APIRouter()
def run():
    {registration}
"""
        )

        inventory = SecureASTExtractor(tmp_path, bootstrap_entry="main:run").extract_inventory()

        assert inventory.endpoints == []
        assert inventory.status == InventoryStatus.CONDITIONAL

    def test_bootstrap_helper_rebinding_and_object_escape_are_conditional(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "helpers.py").write_text("def configure(app): pass\n")
        (tmp_path / "main.py").write_text(
            """from fastapi import FastAPI
from helpers import configure
app = FastAPI()
def other(value): pass
def run():
    configure = other
    configure(app)
"""
        )

        inventory = SecureASTExtractor(tmp_path, bootstrap_entry="main:run").extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.limitations

    @pytest.mark.parametrize(
        "escape",
        ["box = [app]", "consume(app)", "global saved\nsaved = app", "return app"],
    )
    def test_bootstrap_object_escape_is_conditional(self, tmp_path: Path, escape: str) -> None:
        indented = "\n".join(f"    {line}" for line in escape.splitlines())
        (tmp_path / "main.py").write_text(
            f"from fastapi import FastAPI\napp = FastAPI()\ndef run():\n{indented}\n"
        )

        inventory = SecureASTExtractor(tmp_path, bootstrap_entry="main:run").extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.limitations

    def test_bootstrap_formal_rebinding_does_not_fall_back_to_global(self, tmp_path: Path) -> None:
        (tmp_path / "main.py").write_text(
            """from fastapi import APIRouter, FastAPI
app = FastAPI()
router = APIRouter()
@router.get('/false')
def false(): return None
def configure(app):
    app = None
    app.include_router(router)
def run():
    configure(app)
"""
        )

        inventory = SecureASTExtractor(tmp_path, bootstrap_entry="main:run").extract_inventory()
        assert inventory.endpoints == []
        assert inventory.status == InventoryStatus.CONDITIONAL

    def test_bootstrap_module_attribute_helper_and_copy_cutoff(self, tmp_path: Path) -> None:
        (tmp_path / "helpers.py").write_text(
            """def configure(app, router):
    app.include_router(router)
"""
        )
        (tmp_path / "main.py").write_text(
            """from fastapi import APIRouter, FastAPI
import helpers
app = FastAPI()
router = APIRouter()
def before(): return None
def after(): return None
def run():
    router.add_api_route('/before', before)
    helpers.configure(app, router)
    router.add_api_route('/after', after)
"""
        )

        assert [
            endpoint.identifier
            for endpoint in SecureASTExtractor(
                tmp_path, bootstrap_entry="main:run"
            ).extract_endpoints()
        ] == ["GET /before"]

    def test_bootstrap_does_not_follow_helper_without_object_flow(self, tmp_path: Path) -> None:
        (tmp_path / "main.py").write_text(
            """from fastapi import APIRouter, FastAPI
app = FastAPI()
router = APIRouter()
@router.get('/false')
def false(): return None
def hidden():
    app.include_router(router)
def run():
    hidden()
"""
        )

        inventory = SecureASTExtractor(tmp_path, bootstrap_entry="main:run").extract_inventory()
        assert inventory.endpoints == []
        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.limitations

    @pytest.mark.parametrize(
        "bootstrap",
        [
            "async def run():\n    pass\n",
            "@decorator\ndef run():\n    pass\n",
            "def run(required):\n    pass\n",
            "def run():\n    pass\nrun = other\n",
        ],
    )
    def test_explicit_bootstrap_rejects_unsafe_entry(self, tmp_path: Path, bootstrap: str) -> None:
        (tmp_path / "main.py").write_text(
            "from fastapi import FastAPI\napp = FastAPI()\n" + bootstrap
        )

        with pytest.raises(SecureASTExtractorError):
            SecureASTExtractor(tmp_path, bootstrap_entry="main:run").extract_endpoints()

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

    def test_extracts_exhaustive_conditional_fastapi_binding(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI
if debug:
    app = FastAPI(debug=True)
elif staging:
    app = FastAPI(title="staging")
else:
    app = FastAPI()

@app.get("/conditional")
def conditional():
    return {}
"""
        )

        endpoints = SecureASTExtractor(app_file).extract_endpoints()

        assert [endpoint.identifier for endpoint in endpoints] == ["GET /conditional"]

    def test_conditional_binding_is_metamorphic_over_app_name(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI
if enabled:
    service = FastAPI()
else:
    service: object = FastAPI()

@service.post("/renamed")
def renamed():
    return {}
"""
        )

        endpoints = SecureASTExtractor(app_file, app_variable="service").extract_endpoints()

        assert [endpoint.identifier for endpoint in endpoints] == ["POST /renamed"]

    @pytest.mark.parametrize(
        "conditional",
        [
            "if flag:\n    app = FastAPI()",
            "if flag:\n    app = FastAPI()\nelse:\n    app = object()",
            "if flag:\n    app = FastAPI()\nelse:\n    app = APIRouter()",
            "if flag:\n    app = FastAPI()\nelse:\n    router = FastAPI()",
            "if flag:\n    app = FastAPI()\n    configure(app)\nelse:\n    app = FastAPI()",
            "if flag:\n    app = other\nelse:\n    app = other",
            "if (selected := flag):\n    app = FastAPI()\nelse:\n    app = FastAPI()",
            (
                "if flag:\n"
                "    if nested:\n"
                "        app = FastAPI()\n"
                "    else:\n"
                "        app = FastAPI()\n"
                "else:\n"
                "    app = FastAPI()"
            ),
        ],
    )
    def test_rejects_unsupported_conditional_app_bindings(
        self, tmp_path: Path, conditional: str
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            f"""from fastapi import APIRouter, FastAPI
other = FastAPI()
{conditional}
@app.get("/unsafe")
def unsafe():
    return {{}}
"""
        )

        assert SecureASTExtractor(app_file).extract_endpoints() == []

    def test_unsupported_conditional_reassignment_invalidates_stale_app(
        self, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI
app = FastAPI()
@app.get("/before")
def before():
    return {}

if flag:
    app = FastAPI()

@app.get("/after")
def after():
    return {}
"""
        )

        assert SecureASTExtractor(app_file).extract_endpoints() == []

    def test_supported_conditional_rebinding_preserves_source_cutoff(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI
app = FastAPI()
@app.get("/old")
def old():
    return {}

if flag:
    app = FastAPI()
else:
    app = FastAPI()

@app.get("/new")
def new():
    return {}
"""
        )

        endpoints = SecureASTExtractor(app_file).extract_endpoints()

        assert [endpoint.identifier for endpoint in endpoints] == ["GET /new"]

    def test_unrelated_conditional_binding_does_not_invalidate_app(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI
app = FastAPI()
if flag:
    value = 1
else:
    value = 2
@app.get("/safe")
def safe():
    return {}
"""
        )

        endpoints = SecureASTExtractor(app_file).extract_endpoints()

        assert [endpoint.identifier for endpoint in endpoints] == ["GET /safe"]

    def test_nested_conditional_scopes_do_not_invalidate_module_bindings(
        self, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI
app = FastAPI()
if flag:
    def helper():
        app = object()
        FastAPI = object
        return app
    values = [app for app in ()]
else:
    values = []
@app.get("/safe")
def safe():
    return {}
"""
        )

        endpoints = SecureASTExtractor(app_file).extract_endpoints()

        assert [endpoint.identifier for endpoint in endpoints] == ["GET /safe"]

    def test_module_loop_registration_makes_inventory_conditional(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI
app = FastAPI()
@app.get('/known')
def known(): return None
for route in configured_routes:
    app.router.include_routes(route)
"""
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /known"]
        assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.ESTABLISHED
        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.limitations[0].source_line == 6
        assert "module-level control flow" in inventory.limitations[0].reason

    def test_module_conditional_decorator_makes_empty_inventory_conditional(
        self, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI
app = FastAPI()
if enabled:
    @app.get('/optional')
    def optional(): return None
"""
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.endpoints == []
        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.limitations[0].source_line == 4

    def test_module_conditional_helper_object_escape_is_conditional(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI
app = FastAPI()
if enabled:
    configure(app)
"""
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert "unresolved call" in inventory.limitations[0].reason

    def test_conditional_router_mutation_after_copy_does_not_weaken_parent_inventory(
        self, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import APIRouter, FastAPI
app = FastAPI()
router = APIRouter()
@router.get('/known')
def known(): return None
def late(): return None
app.include_router(router)
if enabled:
    router.add_api_route('/late', late)
"""
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /known"]
        assert inventory.status == InventoryStatus.ESTABLISHED
        assert inventory.limitations == ()

    def test_conditional_router_mutation_before_copy_weakens_parent_inventory(
        self, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import APIRouter, FastAPI
app = FastAPI()
router = APIRouter()
@router.get('/known')
def known(): return None
def optional(): return None
if enabled:
    router.add_api_route('/optional', optional)
app.include_router(router)
"""
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /known"]
        assert inventory.status == InventoryStatus.CONDITIONAL

    def test_conditional_child_mutation_after_live_mount_weakens_parent_inventory(
        self, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI
app = FastAPI()
child = FastAPI()
@child.get('/known')
def known(): return None
def optional(): return None
app.mount('/child', child)
if enabled:
    child.add_api_route('/optional', optional)
"""
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /child/known"]
        assert inventory.status == InventoryStatus.CONDITIONAL

    def test_deferred_function_body_does_not_weaken_module_inventory(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI
app = FastAPI()
@app.get('/known')
def known(): return None
if enabled:
    def configure_later():
        app.add_api_route('/not-executed', handler)
"""
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /known"]
        assert inventory.status == InventoryStatus.ESTABLISHED

    @pytest.mark.parametrize(
        "body",
        [
            "if enabled:\n    target = app\n    target.add_api_route('/optional', handler)",
            "for target in [app]:\n    target.add_api_route('/optional', handler)",
            "target = app\nif enabled:\n    target.add_api_route('/optional', handler)",
            (
                "registry = [app]\nfor target in registry:\n"
                "    target.add_api_route('/optional', handler)"
            ),
            ("registry = [app]\nif enabled:\n    registry[0].add_api_route('/optional', handler)"),
            (
                "registry = {'primary': app}\nif enabled:\n"
                "    registry['primary'].add_api_route('/optional', handler)"
            ),
        ],
    )
    def test_control_flow_alias_of_app_is_conservatively_conditional(
        self, tmp_path: Path, body: str
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            f"""from fastapi import FastAPI
app = FastAPI()
def handler(): return None
{body}
"""
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.limitations

    @pytest.mark.parametrize(
        "expression",
        [
            "[app.add_api_route(path, handler) for path in plugin_paths]",
            "app.add_api_route('/optional', handler) if enabled else None",
            "enabled and app.add_api_route('/optional', handler)",
            "(app if enabled else other).add_api_route('/optional', handler)",
        ],
    )
    def test_expression_form_control_flow_is_conditional(
        self, tmp_path: Path, expression: str
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            f"""from fastapi import FastAPI
app = FastAPI()
def handler(): return None
{expression}
"""
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL

    def test_cross_module_limitation_is_not_filtered_by_local_copy_cutoff(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "main.py").write_text(
            """from fastapi import APIRouter, FastAPI
app = FastAPI()
router = APIRouter()
import plugin
app.include_router(router)
"""
        )
        (tmp_path / "plugin.py").write_text(
            """from main import router










if enabled:
    @router.get('/conditional')
    def conditional(): return None
"""
        )

        inventory = SecureASTExtractor(tmp_path, app_entry="main:app").extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.limitations[0].source_path.name == "plugin.py"

    def test_unresolved_registration_receiver_does_not_taint_child_router(
        self, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import APIRouter, FastAPI
app = FastAPI()
router = APIRouter()
@router.get('/known')
def known(): return None
if enabled:
    client.include_router(router)
app.include_router(router)
"""
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /known"]
        assert inventory.status == InventoryStatus.ESTABLISHED

    @pytest.mark.parametrize(
        "body",
        [
            "if enabled:\n    configure(app.router)",
            "routes = app.routes\nif enabled:\n    routes.clear()",
            "if enabled:\n    app.router.routes[0].path = '/changed'",
        ],
    )
    def test_nested_route_state_escape_or_mutation_is_conditional(
        self, tmp_path: Path, body: str
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            f"""from fastapi import FastAPI
app = FastAPI()
{body}
"""
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.limitations

    def test_unknown_route_object_method_tracks_receiver_and_object_arguments(
        self, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import APIRouter, FastAPI
app = FastAPI()
router = APIRouter()
if enabled:
    router.configure(app)
"""
        )

        inventory = SecureASTExtractor(app_file, app_entry="app:app").extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert any("unresolved call" in item.reason for item in inventory.limitations)

    def test_unknown_nested_route_state_method_is_conditional(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI
app = FastAPI()
if enabled:
    app.router.configure()
"""
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert "route-state method" in inventory.limitations[0].reason

    @pytest.mark.parametrize(
        "mutation",
        [
            "app.router.routes[0] = replacement",
            "del app.router.routes[:]",
        ],
    )
    def test_conditional_route_collection_subscript_mutation_is_conditional(
        self, tmp_path: Path, mutation: str
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            f"""from fastapi import FastAPI
app = FastAPI()
if enabled:
    {mutation}
"""
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert "replace route state" in inventory.limitations[0].reason

    def test_unknown_direct_app_method_is_conditional(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI
app = FastAPI()
if enabled:
    app.configure()
"""
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert "unresolved route-state method" in inventory.limitations[0].reason

    def test_unrelated_conditional_app_attribute_read_does_not_weaken_inventory(
        self, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            """from fastapi import FastAPI
app = FastAPI()
@app.get('/known')
def known(): return None
if enabled:
    print(app.title)
    app.state.client.get('/health')
"""
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.ESTABLISHED

    def test_configured_parse_failure_never_selects_sibling_app(self, tmp_path: Path) -> None:
        app_file = tmp_path / "broken.py"
        app_file.write_text("from fastapi import FastAPI\napp = FastAPI(\n")
        (tmp_path / "sibling.py").write_text(
            "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/wrong')\ndef wrong(): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.UNAVAILABLE
        assert inventory.endpoints == []
        assert len(inventory.limitations) == 1
        assert inventory.limitations[0].source_path == app_file
        assert inventory.limitations[0].source_line == 2

    def test_missing_configured_source_never_selects_sibling_app(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.py"
        (tmp_path / "sibling.py").write_text(
            "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/wrong')\ndef wrong(): pass\n"
        )

        inventory = SecureASTExtractor(missing).extract_inventory()

        assert inventory.status == InventoryStatus.UNAVAILABLE
        assert inventory.endpoints == []
        assert inventory.limitations[0].source_path == missing
        assert "does not exist" in inventory.limitations[0].reason

    def test_all_malformed_directory_retains_parse_evidence(self, tmp_path: Path) -> None:
        first = tmp_path / "first.py"
        second = tmp_path / "second.py"
        first.write_text("def broken(\n")
        second.write_bytes(b"\xff")

        inventory = SecureASTExtractor(tmp_path).extract_inventory()

        assert inventory.status == InventoryStatus.UNAVAILABLE
        assert inventory.endpoints == []
        assert {item.source_path for item in inventory.limitations} == {first, second}

    def test_python_source_encoding_cookie_is_honored(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_bytes(
            "# -*- coding: latin-1 -*-\n"
            "from fastapi import FastAPI\n"
            "app = FastAPI(title='café')\n"
            "@app.get('/known')\n"
            "def known(): pass\n".encode("latin-1")
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.ESTABLISHED
        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /known"]

    def test_directory_parse_failure_is_reported_as_conditional(self, tmp_path: Path) -> None:
        (tmp_path / "main.py").write_text(
            "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/known')\ndef known(): pass\n"
        )
        broken = tmp_path / "plugin.py"
        broken.write_bytes(b"\xff")

        inventory = SecureASTExtractor(tmp_path, app_entry="main:app").extract_inventory()

        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /known"]
        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.limitations[0].source_path == broken

    def test_direct_route_clear_downgrades_existing_endpoint(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/stale')\n"
            "def stale(): pass\n"
            "app.routes.clear()\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /stale"]
        assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL
        assert inventory.limitations[0].source_line == 5

    def test_conditional_route_clear_downgrades_existing_endpoint(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/known')\n"
            "def known(): pass\n"
            "if enabled:\n"
            "    app.routes.clear()\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL
        assert inventory.endpoints[0].discovery_conditions[0].source_line == 6

    def test_unresolved_addition_preserves_known_endpoint_strength(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/known')\n"
            "def known(): pass\n"
            "app.router.add_api_route(dynamic_path, missing_handler)\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /known"]
        assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.ESTABLISHED

    def test_nested_router_exact_add_api_route_is_established(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "def handler(): pass\n"
            "app.router.add_api_route('/nested', handler, methods=('POST',))\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.ESTABLISHED
        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["POST /nested"]

    def test_cross_module_clear_downgrades_imported_router_endpoint(self, tmp_path: Path) -> None:
        (tmp_path / "routes.py").write_text(
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "\n\n\n\n\n\n\n\n"
            "@router.get('/stale')\n"
            "def stale(): pass\n"
        )
        (tmp_path / "plugin.py").write_text("from routes import router\nrouter.routes.clear()\n")
        (tmp_path / "main.py").write_text(
            "from fastapi import FastAPI\n"
            "from routes import router\n"
            "import plugin\n"
            "app = FastAPI()\n"
            "app.include_router(router)\n"
        )

        inventory = SecureASTExtractor(tmp_path, app_entry="main:app").extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL
        assert inventory.endpoints[0].discovery_conditions[0].source_path.name == "plugin.py"

    def test_imported_router_clear_after_copy_preserves_parent_snapshot(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "routes.py").write_text(
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/known')\n"
            "def known(): pass\n"
        )
        (tmp_path / "main.py").write_text(
            "from fastapi import FastAPI\n"
            "from routes import router\n"
            "app = FastAPI()\n"
            "app.include_router(router)\n"
            "router.routes.clear()\n"
        )

        inventory = SecureASTExtractor(tmp_path, app_entry="main:app").extract_inventory()

        assert inventory.status == InventoryStatus.ESTABLISHED
        assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.ESTABLISHED

    @pytest.mark.parametrize(
        "setup,effect",
        [
            ("import builtins", 'builtins.exec("app.routes.clear()")'),
            ("from builtins import eval as run", 'run("app.routes.clear()")'),
        ],
    )
    def test_qualified_dynamic_execution_fails_closed(
        self, tmp_path: Path, setup: str, effect: str
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            f"{setup}\n"
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/known')\n"
            "def known(): pass\n"
            f"{effect}\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL

    def test_assigned_dynamic_execution_alias_fails_closed(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "run = exec\n"
            "app = FastAPI()\n"
            "@app.get('/known')\n"
            "def known(): pass\n"
            'run("app.routes.clear()")\n'
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL

    def test_conditional_rebinding_preserves_possible_dynamic_alias(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "run = exec\n"
            "app = FastAPI()\n"
            "@app.get('/known')\n"
            "def known(): pass\n"
            "if flag:\n"
            "    run = lambda source: None\n"
            'run("app.routes.clear()")\n'
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL

    def test_destructured_dynamic_execution_alias_fails_closed(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "(run,) = (exec,)\n"
            "app = FastAPI()\n"
            "@app.get('/known')\n"
            "def known(): pass\n"
            'run("app.routes.clear()")\n'
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL

    def test_dynamic_execution_tracks_imported_router(self, tmp_path: Path) -> None:
        (tmp_path / "routes.py").write_text(
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/known')\n"
            "def known(): pass\n"
        )
        (tmp_path / "main.py").write_text(
            "from fastapi import FastAPI\n"
            "from routes import router\n"
            'exec("router.routes.clear()")\n'
            "app = FastAPI()\n"
            "app.include_router(router)\n"
        )

        inventory = SecureASTExtractor(tmp_path, app_entry="main:app").extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL

    @pytest.mark.parametrize(
        "statement",
        [
            "app.get('/unused')",
            "app.add_event_handler('startup', lambda: None)",
            "app.add_exception_handler(Exception, lambda: None)",
            "app.add_middleware(object)",
            "setattr(app, 'title', 'changed')",
            "app.router.redirect_slashes = False",
        ],
    )
    def test_inventory_neutral_setup_does_not_weaken_known_route(
        self, tmp_path: Path, statement: str
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/known')\n"
            "def known(): pass\n"
            f"{statement}\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.ESTABLISHED
        assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.ESTABLISHED

    def test_nested_lambda_comprehension_body_does_not_rebind_app(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "callbacks = [lambda: (app := object()) for _ in ()]\n"
            "@app.get('/known')\n"
            "def known(): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.ESTABLISHED
        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /known"]

    def test_deferred_handler_expression_control_does_not_weaken_inventory(
        self, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/known')\n"
            "def known(flag):\n"
            "    return 'a' if flag else 'b'\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.ESTABLISHED

    @pytest.mark.parametrize(
        "header",
        [
            "other = (app := object())",
            "def helper(value=(app := object())): pass",
            "def helper(value: (app := object())): pass",
            "class Helper((app := object())): pass",
        ],
    )
    def test_executed_expression_rebinding_invalidates_stale_app(
        self, tmp_path: Path, header: str
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            f"{header}\n"
            "@app.get('/phantom')\n"
            "def phantom(): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.UNAVAILABLE
        assert inventory.endpoints == []

    @pytest.mark.parametrize(
        "annotation",
        [
            "marker: mutate(app)",
            "class Markers:\n    marker: mutate(app)",
        ],
    )
    def test_postponed_module_and_class_annotations_do_not_execute(
        self, tmp_path: Path, annotation: str
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from __future__ import annotations\n"
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            f"{annotation}\n"
            "@app.get('/known')\n"
            "def known(): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.ESTABLISHED
        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /known"]

    def test_postponed_annotation_does_not_execute_rebinding(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from __future__ import annotations\n"
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "def helper(value: (app := object())): pass\n"
            "@app.get('/known')\n"
            "def known(): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.ESTABLISHED
        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /known"]

    @pytest.mark.parametrize(
        "method_setup",
        [
            "METHODS = ['GET']\nMETHODS.append('POST')",
            "METHODS = ('GET',)\nCAPTURED = METHODS\nMETHODS = ('POST',)",
        ],
    )
    def test_named_route_methods_fail_closed(self, tmp_path: Path, method_setup: str) -> None:
        selected = "CAPTURED" if "CAPTURED" in method_setup else "METHODS"
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            f"{method_setup}\n"
            f"@app.api_route('/item', methods={selected})\n"
            "def item(): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.endpoints == []
        assert inventory.status == InventoryStatus.CONDITIONAL

    @pytest.mark.parametrize(
        "effect",
        [
            "configure(app)",
            "app.configure()",
            "setattr(app, 'routes', [])",
            "def header(value: mutate(app)): pass",
            "class Header(mutate(app)): pass",
            'exec("app.routes.clear()")',
            'eval("app.routes.clear()")',
        ],
    )
    def test_direct_unknown_route_effects_fail_closed(self, tmp_path: Path, effect: str) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/known')\n"
            "def known(): pass\n"
            f"{effect}\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL
        assert inventory.limitations

    @pytest.mark.parametrize(
        "rebind",
        [
            "match value:\n    case _: app = object()",
            "(app := object())",
            "while (app := object()):\n    break",
            "try:\n    app = object()\nexcept Exception:\n    pass",
            "with manager() as app:\n    pass",
            "try:\n    pass\nexcept Exception as app:\n    pass",
        ],
    )
    def test_compound_and_walrus_rebinding_invalidates_stale_app(
        self, tmp_path: Path, rebind: str
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            f"{rebind}\n"
            "@app.get('/phantom')\n"
            "def phantom(): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.UNAVAILABLE
        assert inventory.endpoints == []

    @pytest.mark.parametrize(
        "alias_binding",
        [
            "other = (alias := app)",
            "def header(value=(alias := app)): pass",
        ],
    )
    def test_named_expression_route_alias_propagates_destructive_effect(
        self, tmp_path: Path, alias_binding: str
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/known')\n"
            "def known(): pass\n"
            f"{alias_binding}\n"
            "alias.routes.clear()\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL

    def test_class_global_rebinding_invalidates_module_app(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/old')\n"
            "def old(): pass\n"
            "class Rebind:\n"
            "    global app\n"
            "    app = FastAPI()\n"
            "@app.get('/new')\n"
            "def new(): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.UNAVAILABLE
        assert inventory.endpoints == []

    @pytest.mark.parametrize(
        "header",
        [
            "def helper(value=(app := FastAPI())): pass",
            "helper = lambda value=(app := FastAPI()): None",
        ],
    )
    def test_class_global_header_rebinding_invalidates_module_app(
        self, tmp_path: Path, header: str
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/old')\n"
            "def old(): pass\n"
            "class Rebind:\n"
            "    global app\n"
            f"    {header}\n"
            "@app.get('/new')\n"
            "def new(): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.UNAVAILABLE
        assert inventory.endpoints == []

    @pytest.mark.parametrize(
        "class_body",
        [
            ("    try:\n        raise ValueError()\n    except ValueError as app:\n        pass"),
            "    match FastAPI():\n        case app:\n            pass",
        ],
    )
    def test_class_global_string_binding_invalidates_module_app(
        self, tmp_path: Path, class_body: str
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/old')\n"
            "def old(): pass\n"
            "class Rebind:\n"
            "    global app\n"
            f"{class_body}\n"
            "@app.get('/new')\n"
            "def new(): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.UNAVAILABLE
        assert inventory.endpoints == []

    @pytest.mark.skipif(sys.version_info < (3, 11), reason="except* requires Python 3.11")
    def test_try_star_rebinding_invalidates_stale_app(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "try:\n"
            "    raise ExceptionGroup('errors', [ValueError()])\n"
            "except* ValueError:\n"
            "    app = FastAPI()\n"
            "@app.get('/phantom')\n"
            "def phantom(): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.UNAVAILABLE
        assert inventory.endpoints == []

    @pytest.mark.parametrize(
        "statement",
        [
            "match value:\n    case other: pass",
            "(other := object())",
            "try:\n    other = object()\nexcept Exception:\n    pass",
        ],
    )
    def test_unrelated_compound_binding_preserves_exact_app(
        self, tmp_path: Path, statement: str
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            f"{statement}\n"
            "@app.get('/known')\n"
            "def known(): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.ESTABLISHED
        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /known"]

    def test_router_clear_after_copy_does_not_weaken_parent_snapshot(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import APIRouter, FastAPI\n"
            "app = FastAPI()\n"
            "router = APIRouter()\n"
            "@router.get('/known')\n"
            "def known(): pass\n"
            "app.include_router(router)\n"
            "router.routes.clear()\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.ESTABLISHED
        assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.ESTABLISHED

    def test_router_clear_before_copy_downgrades_copied_endpoint(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import APIRouter, FastAPI\n"
            "app = FastAPI()\n"
            "router = APIRouter()\n"
            "@router.get('/known')\n"
            "def known(): pass\n"
            "router.routes.clear()\n"
            "app.include_router(router)\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL

    def test_cyclic_named_route_methods_fail_closed(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "METHODS = METHODS\n"
            "@app.api_route('/unknown', methods=METHODS)\n"
            "def unknown(): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.endpoints == []

    @pytest.mark.parametrize(
        "replacement,registration",
        [
            ("app.get = no_route", "@app.get('/phantom')\ndef phantom(): pass"),
            (
                "app.include_router = no_op",
                "router = APIRouter()\n"
                "@router.get('/phantom')\n"
                "def phantom(): pass\n"
                "app.include_router(router)",
            ),
        ],
    )
    def test_registration_method_replacement_downgrades_subsequent_routes(
        self, tmp_path: Path, replacement: str, registration: str
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import APIRouter, FastAPI\n"
            "app = FastAPI()\n"
            "def no_route(*args, **kwargs): return lambda handler: handler\n"
            "def no_op(*args, **kwargs): return None\n"
            f"{replacement}\n"
            f"{registration}\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.endpoints
        assert all(
            endpoint.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
            for endpoint in inventory.endpoints
        )

    def test_exact_route_method_alias_fails_closed_instead_of_established_empty(
        self, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "route = app.get\n"
            "@route('/hidden')\n"
            "def hidden(): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.endpoints == []
        assert inventory.status == InventoryStatus.CONDITIONAL
        assert "unresolved alias" in inventory.limitations[0].reason

    def test_class_body_route_fails_closed_without_flattening_namespace(
        self, tmp_path: Path
    ) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "other = FastAPI()\n"
            "class Routes:\n"
            "    app = other\n"
            "    @app.get('/other-only')\n"
            "    def items(self): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.endpoints == []
        assert inventory.status == InventoryStatus.CONDITIONAL

    def test_static_fstring_route_is_established(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "resource = 'items'\n"
            "@app.get(f'/{resource}')\n"
            "def items(): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.ESTABLISHED
        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /items"]

    @pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 695 requires Python 3.12")
    def test_type_alias_value_is_not_executed_eagerly(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "type Alias = mutate(app)\n"
            "@app.get('/known')\n"
            "def known(): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.ESTABLISHED
        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /known"]

    @pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 695 requires Python 3.12")
    def test_type_alias_binding_invalidates_stale_app(self, tmp_path: Path) -> None:
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "type app = int\n"
            "@app.get('/phantom')\n"
            "def phantom(): pass\n"
        )

        inventory = SecureASTExtractor(app_file).extract_inventory()

        assert inventory.status == InventoryStatus.UNAVAILABLE
        assert inventory.endpoints == []

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

    def test_include_is_copy_but_mount_is_live(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import APIRouter, FastAPI
app = FastAPI()
router = APIRouter()
child = FastAPI()
def before(): return None
def after(): return None
router.add_api_route('/before', before)
app.include_router(router, prefix='/first')
router.add_api_route('/after', after)
app.include_router(router, prefix='/second')
child.add_api_route('/before', before)
app.mount('/live', child)
child.add_api_route('/after', after)
"""
        )

        identifiers = [
            endpoint.identifier for endpoint in SecureASTExtractor(main).extract_endpoints()
        ]

        assert identifiers == [
            "GET /first/before",
            "GET /live/after",
            "GET /live/before",
            "GET /second/after",
            "GET /second/before",
        ]

    def test_same_line_composition_preserves_source_order_and_occurrences(
        self, tmp_path: Path
    ) -> None:
        main = tmp_path / "main.py"
        router_line = (
            "router.add_api_route('/one', one); "
            "app.include_router(router, prefix='/first'); "
            "router.add_api_route('/two', two); "
            "app.include_router(router, prefix='/second')"
        )
        mount_line = (
            "child.add_api_route('/one', one); "
            "app.mount('/live', child); "
            "child.add_api_route('/two', two); "
            "app.mount('/live', child)"
        )
        main.write_text(
            f"""from fastapi import APIRouter, FastAPI
app = FastAPI()
router = APIRouter()
child = FastAPI()
def one(): return None
def two(): return None
{router_line}
{mount_line}
"""
        )

        identifiers = [
            endpoint.identifier for endpoint in SecureASTExtractor(main).extract_endpoints()
        ]

        assert identifiers.count("GET /live/one") == 2
        assert identifiers.count("GET /live/two") == 2
        assert "GET /first/one" in identifiers
        assert "GET /first/two" not in identifiers
        assert "GET /second/one" in identifiers
        assert "GET /second/two" in identifiers

    def test_factory_call_same_line_preserves_include_cutoff(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import APIRouter, FastAPI
router = APIRouter()
def before(): return None
def after(): return None
def create_app():
    app = FastAPI()
    app.include_router(router)
    return app
router.add_api_route('/before', before); app = create_app(); router.add_api_route('/after', after)
"""
        )

        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(main).extract_endpoints()
        ] == ["GET /before"]

    def test_mount_retains_child_identity_across_name_rebinding(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI
app = FastAPI()
def old(): return None
def new(): return None
child = FastAPI()
child.add_api_route('/old', old)
app.mount('/mounted', child)
child = FastAPI()
child.add_api_route('/new', new)
"""
        )

        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(main).extract_endpoints()
        ] == ["GET /mounted/old"]

    def test_imperative_websocket_registration_module_and_factory_parity(
        self, tmp_path: Path
    ) -> None:
        module_app = tmp_path / "module_app.py"
        module_app.write_text(
            """from fastapi import FastAPI
app = FastAPI()
async def first(websocket): pass
async def second(websocket): pass
app.add_api_websocket_route('/api', first)
app.add_websocket_route(path='/plain', endpoint=second)
"""
        )
        factory_app = tmp_path / "factory_app.py"
        factory_app.write_text(
            """from fastapi import FastAPI
def create_app():
    app = FastAPI()
    async def first(websocket): pass
    async def second(websocket): pass
    app.add_api_websocket_route('/api', first)
    app.add_websocket_route(path='/plain', endpoint=second)
    return app
app = create_app()
"""
        )

        expected = ["WEBSOCKET /api", "WEBSOCKET /plain"]
        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(module_app).extract_endpoints()
        ] == expected
        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(factory_app).extract_endpoints()
        ] == expected

    def test_imperative_websocket_dynamic_values_fail_closed_or_conditional(
        self, tmp_path: Path
    ) -> None:
        module_app = tmp_path / "module_app.py"
        module_app.write_text(
            """from fastapi import FastAPI
app = FastAPI()
@app.get('/known')
def known(): return None
async def handler(websocket): pass
app.add_api_websocket_route(dynamic_path, handler)
app.add_websocket_route('/missing', unknown_handler)
"""
        )
        module_inventory = SecureASTExtractor(module_app).extract_inventory()
        assert [endpoint.identifier for endpoint in module_inventory.endpoints] == ["GET /known"]
        assert all(
            endpoint.discovery_status == EndpointDiscoveryStatus.ESTABLISHED
            for endpoint in module_inventory.endpoints
        )
        assert module_inventory.status == InventoryStatus.CONDITIONAL
        assert module_inventory.limitations

        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI
def create_app():
    app = FastAPI()
    async def handler(websocket): pass
    app.add_api_websocket_route(dynamic_path, handler)
    app.add_websocket_route('/missing', unknown_handler)
    return app
"""
        )

        assert SecureASTExtractor(main).extract_endpoints() == []
        inventory = SecureASTExtractor(main, app_entry="main:create_app").extract_inventory()
        assert inventory.endpoints == []
        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.limitations

    def test_factory_mount_observes_routes_added_after_mount(self, tmp_path: Path) -> None:
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI
def create_app():
    app = FastAPI()
    child = FastAPI()
    def before(): return None
    def after(): return None
    child.add_api_route('/before', before)
    app.mount('/live', child)
    child.add_api_route('/after', after)
    return app
app = create_app()
"""
        )

        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(main).extract_endpoints()
        ] == ["GET /live/after", "GET /live/before"]

    def test_resolves_transitive_absolute_router_reexports(self, tmp_path: Path) -> None:
        (tmp_path / "routes.py").write_text(
            """from fastapi import APIRouter
origin = APIRouter()
@origin.get('/items')
def items(): return []
"""
        )
        (tmp_path / "exports.py").write_text("from routes import origin as middle\n")
        (tmp_path / "public.py").write_text("from exports import middle as surface\n")
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI
from public import surface as renamed
application = FastAPI()
application.include_router(renamed, prefix='/api')
"""
        )

        endpoints = SecureASTExtractor(main, app_variable="application").extract_endpoints()

        assert [endpoint.identifier for endpoint in endpoints] == ["GET /api/items"]

    def test_resolves_relative_reexport_through_module_attribute(self, tmp_path: Path) -> None:
        package = tmp_path / "pkg"
        (package / "v1").mkdir(parents=True)
        (package / "__init__.py").write_text("")
        (package / "routes.py").write_text(
            """from fastapi import APIRouter
source = APIRouter()
@source.post('/submit')
def submit(): return None
"""
        )
        (package / "v1" / "__init__.py").write_text("from ..routes import source as intermediate\n")
        (package / "api.py").write_text("from .v1 import intermediate as published\n")
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI
from pkg import api as renamed_module
root = FastAPI()
root.include_router(renamed_module.published, prefix='/v1')
"""
        )

        endpoints = SecureASTExtractor(main, app_variable="root").extract_endpoints()

        assert [endpoint.identifier for endpoint in endpoints] == ["POST /v1/submit"]

    @pytest.mark.parametrize(
        "public_source",
        [
            "from other import exported\n",
            "from other import exported\ndel exported\n",
            "from other import exported\nexported = object()\n",
            "from routes import *\n",
            "from routes import first as exported, second as exported\n",
        ],
    )
    def test_transitive_reexports_fail_closed_on_unproven_bindings(
        self, tmp_path: Path, public_source: str
    ) -> None:
        (tmp_path / "routes.py").write_text(
            """from fastapi import APIRouter
first = APIRouter()
second = APIRouter()
@first.get('/false')
def false(): return None
"""
        )
        (tmp_path / "other.py").write_text("from public import exported\n")
        (tmp_path / "public.py").write_text(public_source)
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI
from public import exported
app = FastAPI()
app.include_router(exported)
"""
        )

        assert SecureASTExtractor(main).extract_endpoints() == []

    @pytest.mark.parametrize(
        "rebind",
        ["exported = exported = object()", "for exported in [object()]:\n    pass"],
    )
    def test_transitive_reexport_does_not_survive_compound_rebinding(
        self, tmp_path: Path, rebind: str
    ) -> None:
        (tmp_path / "routes.py").write_text(
            "from fastapi import APIRouter\nrouter = APIRouter()\n"
            "@router.get('/false')\ndef false(): return None\n"
        )
        (tmp_path / "public.py").write_text(f"from routes import router as exported\n{rebind}\n")
        main = tmp_path / "main.py"
        main.write_text(
            "from fastapi import FastAPI\nfrom public import exported\n"
            "app = FastAPI()\napp.include_router(exported)\n"
        )

        assert SecureASTExtractor(main).extract_endpoints() == []

    def test_package_export_dominates_same_named_submodule(self, tmp_path: Path) -> None:
        package = tmp_path / "pkg"
        package.mkdir()
        (package / "real.py").write_text(
            "from fastapi import APIRouter\nrouter = APIRouter()\n"
            "@router.get('/real')\ndef real(): return None\n"
        )
        (package / "api.py").write_text(
            "from fastapi import APIRouter\napi = APIRouter()\n"
            "@api.get('/false')\ndef false(): return None\n"
        )
        (package / "__init__.py").write_text("from .real import router as api\n")
        main = tmp_path / "main.py"
        main.write_text(
            "from fastapi import FastAPI\nfrom pkg import api\n"
            "app = FastAPI()\napp.include_router(api)\n"
        )

        assert [
            endpoint.identifier for endpoint in SecureASTExtractor(main).extract_endpoints()
        ] == ["GET /real"]

    @pytest.mark.parametrize(
        "package_source",
        ["from .exports import *\n", "if flag:\n    from .exports import api\n"],
    )
    def test_package_submodule_resolution_fails_on_possible_dynamic_export(
        self, tmp_path: Path, package_source: str
    ) -> None:
        package = tmp_path / "pkg"
        package.mkdir()
        (package / "exports.py").write_text(
            "from fastapi import APIRouter\napi = APIRouter()\n"
            "@api.get('/real')\ndef real(): return None\n"
        )
        (package / "api.py").write_text(
            "from fastapi import APIRouter\nrouter = APIRouter()\n"
            "@router.get('/false')\ndef false(): return None\n"
        )
        (package / "__init__.py").write_text(package_source)
        main = tmp_path / "main.py"
        main.write_text(
            "from fastapi import FastAPI\nfrom pkg import api\n"
            "app = FastAPI()\napp.include_router(api.router)\n"
        )

        assert SecureASTExtractor(main).extract_endpoints() == []

    def test_transitive_reexport_kind_mismatch_fails_closed(self, tmp_path: Path) -> None:
        (tmp_path / "child.py").write_text("from fastapi import FastAPI\nchild = FastAPI()\n")
        (tmp_path / "public.py").write_text("from child import child as exported\n")
        main = tmp_path / "main.py"
        main.write_text(
            """from fastapi import FastAPI
from public import exported
app = FastAPI()
app.include_router(exported)
"""
        )

        assert SecureASTExtractor(main).extract_endpoints() == []

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


def test_bounded_native_methods_require_a_flat_container_and_canonicalize(
    tmp_path: Path,
) -> None:
    too_many = ", ".join(repr("GET") for _ in range(33))
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.api_route('/ok', methods=['post', 'GET', 'GET'])\n"
        "def ok(): pass\n"
        "@app.api_route('/scalar', methods='GET')\n"
        "def scalar(): pass\n"
        "@app.api_route('/nested', methods=[['GET']])\n"
        "def nested(): pass\n"
        f"@app.api_route('/many', methods=[{too_many}])\n"
        "def many(): pass\n"
        "@app.api_route('/custom', methods=['CUSTOM'])\n"
        "def custom(): pass\n"
        "@app.api_route('/websocket', methods=['WEBSOCKET'])\n"
        "def websocket(): pass\n"
        "@app.api_route('/empty', methods=[])\n"
        "def empty(): pass\n",
        encoding="utf-8",
    )

    inventory = SecureASTExtractor(tmp_path).extract_inventory()

    assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET,POST /ok"]
    assert inventory.status == InventoryStatus.CONDITIONAL


def test_unresolved_native_constructor_prefix_never_becomes_empty(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI, APIRouter\n"
        "app = FastAPI()\n"
        "bad = APIRouter(prefix=unknown)\n"
        "@bad.get('/constructor')\n"
        "def constructor(): pass\n"
        "@app.get('/safe')\n"
        "def safe(): pass\n"
        "app.include_router(bad)\n",
        encoding="utf-8",
    )

    inventory = SecureASTExtractor(tmp_path).extract_inventory()

    assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /safe"]
    assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.ESTABLISHED
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("native route prefix is unresolved" in item.reason for item in inventory.limitations)


def test_unresolved_native_include_prefix_never_becomes_empty(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI, APIRouter\n"
        "app = FastAPI()\n"
        "included = APIRouter()\n"
        "@included.get('/include')\n"
        "def include(): pass\n"
        "@app.get('/safe')\n"
        "def safe(): pass\n"
        "app.include_router(included, prefix=unknown)\n",
        encoding="utf-8",
    )

    inventory = SecureASTExtractor(tmp_path).extract_inventory()

    assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /safe"]
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any(
        "included router prefix could not be resolved" in item.reason
        for item in inventory.limitations
    )


def test_bootstrap_assignment_evaluates_rhs_before_replacing_string_binding(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "def first(): pass\n"
        "def second(): pass\n"
        "def run():\n"
        "    path = '/a'\n"
        "    path = path + '/b'\n"
        "    app.add_api_route(path, first)\n"
        "    path = dynamic()\n"
        "    app.add_api_route(path, second)\n",
        encoding="utf-8",
    )

    inventory = SecureASTExtractor(tmp_path, bootstrap_entry="main:run").extract_inventory()

    assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /a/b"]
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("bootstrap route is unresolved" in item.reason for item in inventory.limitations)


def test_native_static_string_limit_omits_only_over_budget_route(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        f"@app.get({'/' + 'x' * 4095!r})\n"
        "def exact(): pass\n"
        f"@app.get({'/' + 'x' * 4096!r})\n"
        "def exceeded(): pass\n",
        encoding="utf-8",
    )

    inventory = SecureASTExtractor(tmp_path).extract_inventory()

    assert len(inventory.endpoints) == 1
    assert len(inventory.endpoints[0].path) == 4096
    assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.ESTABLISHED
    assert inventory.status == InventoryStatus.CONDITIONAL


@pytest.mark.parametrize("explicit", [False, True], ids=["implicit", "explicit"])
@pytest.mark.parametrize("style", ["decorator", "imperative"])
def test_factory_additive_route_failure_preserves_unrelated_established_route(
    tmp_path: Path,
    explicit: bool,
    style: str,
) -> None:
    bad_path = "/" + "x" * 4096
    bad_registration = (
        f"    @app.get({bad_path!r})\n    def bad(): pass\n"
        if style == "decorator"
        else f"    app.add_api_route({bad_path!r}, bad)\n"
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "def create():\n"
        "    app = FastAPI()\n"
        "    def bad(): pass\n"
        f"{bad_registration}"
        "    @app.get('/safe')\n"
        "    def safe(): pass\n"
        "    return app\n"
        "app = create()\n",
        encoding="utf-8",
    )

    inventory = SecureASTExtractor(
        tmp_path,
        app_entry="main:create" if explicit else None,
    ).extract_inventory()

    assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /safe"]
    assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.ESTABLISHED
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any(
        "factory" in item.reason and "route" in item.reason for item in inventory.limitations
    )


@pytest.mark.parametrize("explicit", [False, True], ids=["implicit", "explicit"])
@pytest.mark.parametrize(
    "registration",
    [
        "app.include_router(dynamic())",
        "app.include_router(router, prefix=dynamic())",
        "app.mount(dynamic(), child)",
        "app.mount('/bad', dynamic())",
    ],
    ids=["include-child", "include-prefix", "mount-path", "mount-child"],
)
def test_factory_additive_composition_failure_preserves_unrelated_established_route(
    tmp_path: Path,
    explicit: bool,
    registration: str,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "def dynamic(): return object()\n"
        "def create():\n"
        "    app = FastAPI()\n"
        "    router = APIRouter()\n"
        "    child = FastAPI()\n"
        f"    {registration}\n"
        "    @app.get('/safe')\n"
        "    def safe(): pass\n"
        "    return app\n"
        "app = create()\n",
        encoding="utf-8",
    )

    inventory = SecureASTExtractor(
        tmp_path,
        app_entry="main:create" if explicit else None,
    ).extract_inventory()

    assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /safe"]
    assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.ESTABLISHED
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any(
        "factory" in item.reason and "unresolved" in item.reason for item in inventory.limitations
    )


@pytest.mark.parametrize(
    "registration",
    [
        "app.add_api_route(dynamic(), bad)",
        "app.add_api_route(*dynamic())",
        "app.add_api_route('/bad', bad, path='/other')",
        "app.include_router(dynamic())",
        "app.mount(dynamic(), child)",
    ],
    ids=["route", "starred", "ambiguous", "include", "mount"],
)
def test_bootstrap_additive_failure_preserves_unrelated_established_route(
    tmp_path: Path,
    registration: str,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "child = FastAPI()\n"
        "def dynamic(): return object()\n"
        "def bad(): pass\n"
        "def safe(): pass\n"
        "def run():\n"
        f"    {registration}\n"
        "    app.add_api_route('/safe', safe)\n",
        encoding="utf-8",
    )

    inventory = SecureASTExtractor(
        tmp_path,
        bootstrap_entry="main:run",
    ).extract_inventory()

    assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /safe"]
    assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.ESTABLISHED
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("bootstrap" in item.reason for item in inventory.limitations)


def test_factory_and_bootstrap_local_literals_use_bounded_evaluation(tmp_path: Path) -> None:
    bomb = " + ".join(repr("x") for _ in range(40))
    (tmp_path / "factory.py").write_text(
        "from fastapi import FastAPI\n"
        "def create():\n"
        "    app = FastAPI()\n"
        f"    path = {bomb}\n"
        "    @app.get(path)\n"
        "    def route(): pass\n"
        "    return app\n",
        encoding="utf-8",
    )
    factory_inventory = SecureASTExtractor(tmp_path, app_entry="factory:create").extract_inventory()

    assert factory_inventory.endpoints == []
    assert factory_inventory.status == InventoryStatus.CONDITIONAL
    assert any(
        "factory decorated route path" in item.reason for item in factory_inventory.limitations
    )

    (tmp_path / "bootstrap.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "def route(): pass\n"
        "def run():\n"
        f"    path = {bomb}\n"
        "    app.add_api_route(path, route)\n",
        encoding="utf-8",
    )
    bootstrap_inventory = SecureASTExtractor(
        tmp_path, app_entry="bootstrap:app", bootstrap_entry="bootstrap:run"
    ).extract_inventory()

    assert bootstrap_inventory.endpoints == []
    assert bootstrap_inventory.status == InventoryStatus.CONDITIONAL
    assert any(
        "bootstrap route is unresolved" in item.reason for item in bootstrap_inventory.limitations
    )


def test_parser_accepted_deep_native_decorator_expression_fails_closed(
    tmp_path: Path,
) -> None:
    expression = " + ".join(repr("x") for _ in range(1_200))
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        f"@app.get({expression})\n"
        "def route(): pass\n",
        encoding="utf-8",
    )

    inventory = SecureASTExtractor(tmp_path).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.limitations


def test_secure_module_parser_recursion_error_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "main.py"
    source.write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")

    def fail_parse(*_args: object, **_kwargs: object) -> object:
        raise RecursionError("bounded parser probe")

    monkeypatch.setattr(
        "fastapi_endpoint_detector.parser.secure_ast_extractor.ast.parse", fail_parse
    )

    inventory = SecureASTExtractor(source).extract_inventory()

    assert inventory.status == InventoryStatus.UNAVAILABLE
    assert inventory.endpoints == []
    assert "could not be read, decoded, or parsed" in inventory.limitations[0].reason
