"""Exact FastAPI and Starlette lifecycle/middleware surface contracts."""

import asyncio
import re
from importlib.metadata import version
from pathlib import Path

import pytest
from fastapi import APIRouter, FastAPI

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


def _extract(tmp_path: Path, *, app_entry: str | None = None) -> EndpointInventory:
    return CustomSurfaceExtractor(
        tmp_path,
        load_surface_preset("framework-v1"),
        app_entry=app_entry,
    ).extract_inventory()


def test_framework_preset_versions_explicit_registration_multiplicity() -> None:
    loaded = load_surface_preset("framework-v1")
    assert loaded.document.preset.version == "8"
    assert all(
        contract.multiplicity is not None and contract.multiplicity.value != "unknown"
        for contract in loaded.document.contracts
        if contract.surface.kind.startswith("framework.")
    )
    assert {
        contract.surface.kind: contract.multiplicity.value
        for contract in loaded.document.contracts
        if contract.surface.kind in {"framework.lifecycle", "framework.middleware"}
    } == {"framework.lifecycle": "all_execute", "framework.middleware": "all_execute"}
    assert all(
        contract.multiplicity.value == "last_wins"
        for contract in loaded.document.contracts
        if contract.surface.kind == "framework.exception_handler"
    )


def _expected_late_nested_calls(callback: str) -> list[str]:
    installed_version = version("fastapi")
    release = re.match(r"^(\d+)\.(\d+)", installed_version)
    assert release is not None
    major_minor = (int(release.group(1)), int(release.group(2)))
    if major_minor <= (0, 100):
        return []
    if major_minor >= (0, 139):
        return [callback]
    pytest.skip(f"nested lifecycle copy behavior is not calibrated for FastAPI {installed_version}")


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


def test_module_qualified_lifespan_selected_and_literal_none_is_absent(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from contextlib import asynccontextmanager\n"
        "import fastapi\n\n"
        "@asynccontextmanager\n"
        "async def lifespan(app):\n"
        "    yield\n\n"
        "unused = fastapi.FastAPI(lifespan=None)\n"
        "app = fastapi.FastAPI(lifespan=lifespan)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "FRAMEWORK.LIFECYCLE lifespan:shutdown",
        "FRAMEWORK.LIFECYCLE lifespan:startup",
    ]
    assert inventory.status == InventoryStatus.ESTABLISHED


@pytest.mark.parametrize(
    "registration",
    [
        "register = app.add_event_handler\nregister('startup', initialize)",
        "getattr(app, 'add_event_handler')('startup', initialize)",
    ],
)
def test_unresolved_or_aliased_selected_lifecycle_registration_is_limited(
    tmp_path: Path, registration: str
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "unused = FastAPI()\n"
        f"{registration.replace('initialize)', 'missing_callback)')}\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.CONDITIONAL
    assert not inventory.endpoints
    assert any("callback identity is unresolved" in item.reason for item in inventory.limitations)


@pytest.mark.parametrize(
    "registration",
    [
        "register = app.add_event_handler\nregister('startup', selected)",
        "getattr(app, 'add_event_handler')('startup', selected)",
    ],
)
def test_selected_lifecycle_registration_keeps_alias_receiver_identity(
    tmp_path: Path, registration: str
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "async def selected(): pass\n"
        "async def unrelated(): pass\n"
        "unused = FastAPI()\n"
        "unused.add_event_handler('startup', unrelated)\n"
        "app = FastAPI()\n"
        f"{registration}\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [item.handler.name for item in inventory.endpoints] == ["selected"]


def test_dynamic_unselected_lifecycle_alias_does_not_limit_selected_graph(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "def event_name(): return 'startup'\n"
        "async def selected(): pass\n"
        "unused = FastAPI()\n"
        "register = unused.add_event_handler\n"
        "register(event_name(), selected)\n"
        "app = FastAPI()\n"
        "app.add_event_handler('startup', selected)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [item.handler.name for item in inventory.endpoints] == ["selected"]
    assert inventory.limitations == ()


def test_dynamic_selected_lifecycle_alias_remains_an_explicit_limit(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "def event_name(): return 'startup'\n"
        "async def selected(): pass\n"
        "app = FastAPI()\n"
        "register = app.add_event_handler\n"
        "register(event_name(), selected)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.endpoints == []
    assert len(inventory.limitations) == 1
    assert inventory.limitations[0].source_line == 6
    assert "resource set was not finite literal data" in inventory.limitations[0].reason


def test_shadowed_getattr_lambda_is_not_treated_as_builtin_alias(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "async def selected(): pass\n"
        "app = FastAPI()\n"
        "getattr = lambda *args: None\n"
        "getattr(app, 'add_event_handler')('startup', selected)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.endpoints == []
    assert inventory.limitations


def test_dynamic_lifecycle_constructor_expansion_limits_selected_app_only(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "def config(): return {'lifespan': initialize}\n"
        "def initialize(app):\n"
        "    yield\n"
        "unused = FastAPI(**config())\n"
        "app = FastAPI(**config())\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("dynamic keyword expansion" in item.reason for item in inventory.limitations)
    assert {item.source_line for item in inventory.limitations} == {6}


def test_unselected_lifecycle_alias_and_custom_same_spelling_do_not_limit(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "class Custom:\n"
        "    def add_event_handler(self, event, callback): pass\n"
        "app = FastAPI()\n"
        "unused = FastAPI()\n"
        "register = unused.add_event_handler\n"
        "custom = Custom()\n"
        "custom.add_event_handler('startup', missing)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert inventory.limitations == ()


def test_constructor_lifecycle_lists_keep_all_selected_app_callbacks(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import APIRouter, FastAPI\n\n"
        "async def first(): pass\n"
        "async def second(): pass\n"
        "async def unused_only(): pass\n"
        "unused = FastAPI(on_startup=[unused_only])\n"
        "router = APIRouter(on_startup=[first, second], on_shutdown=[second])\n"
        "app = FastAPI(on_startup=[first, second], on_shutdown=[second])\n"
        "app.include_router(router)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [(item.identifier, item.handler.name) for item in inventory.endpoints] == [
        ("FRAMEWORK.LIFECYCLE event:shutdown", "second"),
        ("FRAMEWORK.LIFECYCLE event:shutdown", "second"),
        ("FRAMEWORK.LIFECYCLE event:startup", "first"),
        ("FRAMEWORK.LIFECYCLE event:startup", "first"),
        ("FRAMEWORK.LIFECYCLE event:startup", "second"),
        ("FRAMEWORK.LIFECYCLE event:startup", "second"),
    ]
    assert "unused_only" not in {item.handler.name for item in inventory.endpoints}
    assert inventory.status == InventoryStatus.ESTABLISHED
    assert all(
        item.surface is not None and item.discovery_status == EndpointDiscoveryStatus.ESTABLISHED
        for item in inventory.endpoints
    )


def test_keyword_add_event_handler_resolves_positional_or_keyword_parameters(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "async def startup(): pass\n"
        "app = FastAPI()\n"
        "app.add_event_handler(event_type='startup', handler=startup)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert len(inventory.endpoints) == 1
    assert inventory.endpoints[0].identifier == "FRAMEWORK.LIFECYCLE event:startup"
    assert inventory.endpoints[0].handler.name == "startup"
    assert inventory.status == InventoryStatus.ESTABLISHED


@pytest.mark.parametrize(
    "registration",
    [
        "register = app.add_event_handler\nregister(event_type='startup', func=startup)",
        "getattr(app, 'add_event_handler')(event_type='startup', func=startup)",
    ],
)
def test_keyword_add_event_handler_uses_resolved_registration_identity(
    tmp_path: Path, registration: str
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "async def startup(): pass\n"
        "app = FastAPI()\n"
        f"{registration}\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [(item.identifier, item.handler.name) for item in inventory.endpoints] == [
        ("FRAMEWORK.LIFECYCLE event:startup", "startup")
    ]


def test_literal_non_lifecycle_constructor_expansion_does_not_limit_inventory(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI(**{'debug': True})\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert inventory.endpoints == []
    assert inventory.limitations == ()


def test_literal_lifecycle_constructor_expansion_resolves_callbacks(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "async def startup(): pass\n"
        "app = FastAPI(**{'on_startup': [startup]})\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [(item.identifier, item.handler.name) for item in inventory.endpoints] == [
        ("FRAMEWORK.LIFECYCLE event:startup", "startup")
    ]


def test_literal_kwargs_duplicate_dict_key_uses_last_callback(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "async def bad(): pass\n"
        "async def good(): pass\n"
        "app = FastAPI(**{'on_startup': [bad], 'on_startup': [good]})\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [item.handler.name for item in inventory.endpoints] == ["good"]


def test_literal_kwargs_capture_callback_in_original_entry_order(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "async def bad(): pass\n"
        "async def good(): pass\n"
        "app = FastAPI(**{'on_startup': [bad], 'debug': (chosen := good), "
        "'on_startup': [chosen]})\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [item.handler.name for item in inventory.endpoints] == ["good"]


def test_literal_kwargs_uses_selected_value_before_later_rebinding(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "async def bad(): pass\n"
        "async def good(): pass\n"
        "chosen = bad\n"
        "app = FastAPI(**{'on_startup': [chosen], 'debug': (chosen := good)})\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [item.handler.name for item in inventory.endpoints] == ["bad"]


def test_invalid_duplicate_mapping_for_unselected_app_does_not_taint_inventory(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "other = FastAPI(**{'on_startup': []}, **{'on_startup': []})\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert inventory.endpoints == []
    assert inventory.limitations == ()


def test_duplicate_keyword_from_separate_expansions_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "async def startup(): pass\n"
        "app = FastAPI(**{'on_startup': [startup]}, **{'on_startup': []})\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.CONDITIONAL
    assert not inventory.endpoints
    assert any("duplicate keyword names" in item.reason for item in inventory.limitations)


@pytest.mark.parametrize("entrypoint", ["factory", "bootstrap"])
def test_selected_deferred_entrypoint_duplicate_keyword_calls_fail_closed(
    tmp_path: Path, entrypoint: str
) -> None:
    source = (
        "from fastapi import FastAPI\n"
        "async def startup(): pass\n"
        "app = FastAPI()\n"
        "def selected():\n"
        + (
            "    app = FastAPI(**{'on_startup': []}, **{'on_startup': []})\n    return app\n"
            if entrypoint == "factory"
            else "    app.add_event_handler('startup', startup, "
            "**{'name': 'one'}, **{'name': 'two'})\n"
        )
    )
    (tmp_path / "main.py").write_text(source, encoding="utf-8")
    extractor = CustomSurfaceExtractor(
        tmp_path,
        load_surface_preset("framework-v1"),
        app_entry="main:selected" if entrypoint == "factory" else None,
        bootstrap_entry="main:selected" if entrypoint == "bootstrap" else None,
    )

    inventory = extractor.extract_inventory()

    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.endpoints == []
    assert any("duplicate keyword names" in item.reason for item in inventory.limitations)


@pytest.mark.parametrize("entrypoint", ["factory", "bootstrap"])
@pytest.mark.parametrize(
    ("factory_kwargs", "bootstrap_kwargs"),
    [
        (
            "**{'on_startup': []}, **{'debug': True}",
            "**{'event_type': 'startup'}, **{'handler': startup}",
        ),
        ("**{}", "**{'event_type': 'startup', 'handler': startup}"),
    ],
)
def test_selected_deferred_entrypoint_valid_kwargs_remain_complete(
    tmp_path: Path, entrypoint: str, factory_kwargs: str, bootstrap_kwargs: str
) -> None:
    kwargs = factory_kwargs if entrypoint == "factory" else bootstrap_kwargs
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "async def startup(): pass\n"
        "def selected():\n"
        + (
            f"    app = FastAPI({kwargs})\n    return app\n"
            if entrypoint == "factory"
            else f"    app.add_event_handler({kwargs})\n"
        ),
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_preset("framework-v1"),
        app_entry="main:selected" if entrypoint == "factory" else None,
        bootstrap_entry="main:selected" if entrypoint == "bootstrap" else None,
    ).extract_inventory()

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert inventory.limitations == ()


@pytest.mark.parametrize(
    "expression",
    [
        "getattr(app, 'add_event_handler', None, None)('startup', startup)",
        "getattr(app, 'add_event_handler', default=None)('startup', startup)",
        "getattr(object=app, name='add_event_handler')('startup', startup)",
    ],
)
def test_invalid_builtin_getattr_lifecycle_call_is_not_exactly_resolved(
    tmp_path: Path, expression: str
) -> None:
    (tmp_path / "main.py").write_text(
        f"from fastapi import FastAPI\nasync def startup(): pass\napp = FastAPI()\n{expression}\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("getattr lifecycle method" in item.reason for item in inventory.limitations)


def test_builtin_getattr_with_default_still_resolves_selected_lifecycle_method(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "async def startup(): pass\n"
        "app = FastAPI()\n"
        "getattr(app, 'add_event_handler', None)('startup', startup)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [item.handler.name for item in inventory.endpoints] == ["startup"]


def test_invalid_getattr_on_unselected_app_does_not_taint_selected_inventory(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "unused = FastAPI()\n"
        "getattr(unused, 'add_event_handler', None, None)('startup', missing)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert inventory.limitations == ()


def test_exception_handlers_are_keyed_and_selected_app_scoped(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "unused = FastAPI()\n"
        "@unused.exception_handler(KeyError)\n"
        "async def unused_error(request, exc): return None\n\n"
        "app = FastAPI()\n"
        "@app.exception_handler(ValueError)\n"
        "async def value_error(request, exc): return None\n"
        "async def type_error(request, exc): return None\n"
        "app.add_exception_handler(exc_class=TypeError, handler=type_error)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [(item.identifier, item.handler.name) for item in inventory.endpoints] == [
        ("FRAMEWORK.EXCEPTION_HANDLER exception:builtins.TypeError", "type_error"),
        ("FRAMEWORK.EXCEPTION_HANDLER exception:builtins.ValueError", "value_error"),
    ]
    assert inventory.status == InventoryStatus.ESTABLISHED


def test_exception_handler_decorator_accepts_fastapi_keyword_selector(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "@app.exception_handler(exc_class_or_status_code=ValueError)\n"
        "async def value_error(request, exc): return None\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [(item.identifier, item.handler.name) for item in inventory.endpoints] == [
        ("FRAMEWORK.EXCEPTION_HANDLER exception:builtins.ValueError", "value_error")
    ]
    assert inventory.status == InventoryStatus.ESTABLISHED


def test_exception_handler_contract_uses_last_wins_multiplicity(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "@app.exception_handler(ValueError)\n"
        "async def replaced(request, exc): return None\n"
        "@app.exception_handler(ValueError)\n"
        "async def effective(request, exc): return None\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [(item.identifier, item.handler.name) for item in inventory.endpoints] == [
        ("FRAMEWORK.EXCEPTION_HANDLER exception:builtins.ValueError", "effective")
    ]


def test_unknown_exception_override_does_not_leave_stale_handler_established(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "@app.exception_handler(ValueError)\n"
        "async def stale(request, exc): return None\n"
        "async def unresolved(request, exc): return None\n"
        "app.add_exception_handler(dynamic_exception_type, unresolved)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert not any(
        item.surface and item.surface.surface_kind == "framework.exception_handler"
        for item in inventory.endpoints
    )
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("may override an earlier key" in item.reason for item in inventory.limitations)


def test_unknown_exception_override_in_unused_app_does_not_taint_selected_app(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "unused = FastAPI()\n"
        "async def unused_handler(request, exc): return None\n"
        "unused.add_exception_handler(dynamic_exception_type, unused_handler)\n"
        "app = FastAPI()\n"
        "@app.exception_handler(ValueError)\n"
        "async def selected_handler(request, exc): return None\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [(item.identifier, item.handler.name) for item in inventory.endpoints] == [
        ("FRAMEWORK.EXCEPTION_HANDLER exception:builtins.ValueError", "selected_handler")
    ]
    assert inventory.status == InventoryStatus.ESTABLISHED


def test_pure_asgi_middleware_resolves_local_call_protocol(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "class AuditMiddleware:\n"
        "    async def __call__(self, scope, receive, send): pass\n\n"
        "app = FastAPI()\n"
        "app.add_middleware(AuditMiddleware)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert len(inventory.endpoints) == 1
    assert inventory.endpoints[0].identifier == "FRAMEWORK.MIDDLEWARE protocol:http"
    assert inventory.endpoints[0].handler.name == "__call__"


def test_untrusted_extra_lifespan_decorator_does_not_split_phases(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n\n"
        "def replace(fn): return other\n\n"
        "@replace\n"
        "@asynccontextmanager\n"
        "async def lifespan(app):\n"
        "    yield\n\n"
        "app = FastAPI(lifespan=lifespan)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any(
        "trusted contextlib.asynccontextmanager" in item.reason for item in inventory.limitations
    )


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


def test_runtime_oracle_mount_excludes_child_lifespan_and_router_include_copies() -> None:
    calls: list[str] = []
    child = FastAPI()

    @child.on_event("startup")
    async def child_startup() -> None:
        calls.append("child")

    parent = FastAPI()
    parent.mount("/child", child)

    router = APIRouter()

    @router.on_event("startup")
    async def copied() -> None:
        calls.append("copied")

    parent.include_router(router)

    @router.on_event("startup")
    async def too_late() -> None:
        calls.append("too-late")

    async def enter_lifespan() -> None:
        async with parent.router.lifespan_context(parent):
            pass

    asyncio.run(enter_lifespan())

    # Mounted applications do not contribute child lifespan execution. Router
    # lifecycle behavior after inclusion differs across supported FastAPI versions,
    # so the static adapter treats that later registration as conditional.
    assert "child" not in calls
    assert "copied" in calls


def test_runtime_oracle_late_nested_router_include_is_version_dependent() -> None:
    calls: list[str] = []
    child = APIRouter()
    parent = APIRouter()
    app = FastAPI()
    app.include_router(parent)

    @child.on_event("startup")
    async def child_startup() -> None:
        calls.append("child")

    parent.include_router(child)

    async def enter_lifespan() -> None:
        async with app.router.lifespan_context(app):
            pass

    asyncio.run(enter_lifespan())

    assert calls == _expected_late_nested_calls("child")


def test_runtime_oracle_late_nested_known_leaf_is_version_dependent() -> None:
    calls: list[str] = []
    leaf = APIRouter()

    @leaf.on_event("startup")
    async def leaf_startup() -> None:
        calls.append("leaf")

    child = APIRouter()
    parent = APIRouter()
    app = FastAPI()
    app.include_router(parent)
    child.include_router(leaf)
    parent.include_router(child)

    async def enter_lifespan() -> None:
        async with app.router.lifespan_context(app):
            pass

    asyncio.run(enter_lifespan())

    assert calls == _expected_late_nested_calls("leaf")


def test_framework_surfaces_are_scoped_to_selected_app_not_mounted_lifespan(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "child = FastAPI()\n"
        "@child.on_event('startup')\n"
        "async def child_startup(): pass\n\n"
        "app = FastAPI()\n"
        "@app.on_event('startup')\n"
        "async def parent_startup(): pass\n"
        "app.mount('/child', child)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.handler.name for endpoint in inventory.endpoints] == ["parent_startup"]


def test_background_tasks_follow_selected_route_ownership_and_preserve_task_identity(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import BackgroundTasks, FastAPI\n\n"
        "async def selected_work(): pass\n"
        "async def unused_work(): pass\n\n"
        "unused = FastAPI()\n"
        "@unused.post('/unused')\n"
        "async def unused_route(tasks: BackgroundTasks):\n"
        "    tasks.add_task(unused_work)\n\n"
        "app = FastAPI()\n"
        "@app.post('/selected')\n"
        "async def selected_route(tasks: BackgroundTasks):\n"
        "    tasks.add_task(selected_work)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    task_endpoints = [
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.surface is not None
        and endpoint.surface.surface_kind == "framework.background_task"
    ]
    assert [(item.identifier, item.handler.name) for item in task_endpoints] == [
        ("FRAMEWORK.BACKGROUND_TASK background:main.selected_work", "selected_work")
    ]
    assert task_endpoints[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL
    assert (
        "only if this selected route executes" in task_endpoints[0].discovery_conditions[0].reason
    )


def test_background_tasks_follow_trusted_lexical_aliases_and_nested_helper_control(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import BackgroundTasks as TaskBatch, FastAPI\n\n"
        "async def send(): pass\n"
        "app = FastAPI()\n"
        "@app.post('/selected')\n"
        "async def selected_route(tasks: TaskBatch):\n"
        "    queue = tasks\n"
        "    queue.add_task(send)\n"
        "    for receiver in (tasks,):\n"
        "        receiver.add_task(send)\n"
        "    for item in dynamic_values():\n"
        "        pass\n"
        "    tasks.add_task(send)\n"
        "    def schedule(queue):\n"
        "        if enabled():\n"
        "            queue.add_task(send)\n"
        "    schedule(tasks)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    tasks = [
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.surface is not None
        and endpoint.surface.surface_kind == "framework.background_task"
    ]
    assert [item.handler.name for item in tasks] == ["send", "send", "send", "send"]
    assert len({item.surface.registration_line for item in tasks if item.surface}) == 4


def test_untrusted_dynamic_and_rebound_task_receivers_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import BackgroundTasks, FastAPI\n\n"
        "async def send(): pass\n"
        "app = FastAPI()\n"
        "@app.post('/selected')\n"
        "async def selected_route(tasks: BackgroundTasks):\n"
        "    queue = choose(tasks)\n"
        "    queue.add_task(send)\n"
        "@app.post('/rebound')\n"
        "async def rebound_route(tasks: BackgroundTasks):\n"
        "    queue = tasks\n"
        "    queue = choose(queue)\n"
        "    queue.add_task(send)\n"
        "@app.post('/untrusted')\n"
        "async def untrusted_route(tasks):\n"
        "    tasks.add_task(send)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert not any(
        endpoint.surface is not None
        and endpoint.surface.surface_kind == "framework.background_task"
        for endpoint in inventory.endpoints
    )
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("untrusted, dynamic, or rebound" in item.reason for item in inventory.limitations)


def test_background_task_alias_branch_joins_remain_conditional(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import BackgroundTasks, FastAPI\n\n"
        "async def send(): pass\n"
        "app = FastAPI()\n"
        "@app.post('/one-sided')\n"
        "async def one_sided(tasks: BackgroundTasks):\n"
        "    if flag:\n"
        "        queue = tasks\n"
        "    queue.add_task(send)\n"
        "@app.post('/conflicting')\n"
        "async def conflicting(tasks: BackgroundTasks):\n"
        "    if flag:\n"
        "        queue = tasks\n"
        "    else:\n"
        "        queue = object()\n"
        "    queue.add_task(send)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert not any(
        endpoint.surface is not None
        and endpoint.surface.surface_kind == "framework.background_task"
        for endpoint in inventory.endpoints
    )
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("untrusted, dynamic, or rebound" in item.reason for item in inventory.limitations)


def test_background_task_alias_match_join_remains_conditional(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import BackgroundTasks, FastAPI\n\n"
        "async def send(): pass\n"
        "app = FastAPI()\n"
        "@app.post('/selected')\n"
        "async def selected(tasks: BackgroundTasks, mode: str):\n"
        "    match mode:\n"
        "        case 'send':\n"
        "            queue = tasks\n"
        "        case _:\n"
        "            queue = object()\n"
        "    queue.add_task(send)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert not any(
        endpoint.surface is not None
        and endpoint.surface.surface_kind == "framework.background_task"
        for endpoint in inventory.endpoints
    )
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("untrusted, dynamic, or rebound" in item.reason for item in inventory.limitations)


def test_background_task_alias_try_and_dynamic_loop_joins_remain_conditional(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import BackgroundTasks, FastAPI\n\n"
        "async def send(): pass\n"
        "app = FastAPI()\n"
        "@app.post('/try')\n"
        "async def try_join(tasks: BackgroundTasks):\n"
        "    try:\n"
        "        queue = tasks\n"
        "    except Exception:\n"
        "        pass\n"
        "    queue.add_task(send)\n"
        "@app.post('/try-known')\n"
        "async def try_known(tasks: BackgroundTasks):\n"
        "    try:\n"
        "        queue = tasks\n"
        "    except Exception:\n"
        "        queue = tasks\n"
        "    queue.add_task(send)\n"
        "@app.post('/while')\n"
        "async def while_join(tasks: BackgroundTasks):\n"
        "    while should_continue():\n"
        "        queue = tasks\n"
        "    queue.add_task(send)\n"
        "@app.post('/for')\n"
        "async def for_join(tasks: BackgroundTasks):\n"
        "    for _ in dynamic_values():\n"
        "        queue = tasks\n"
        "    queue.add_task(send)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    task_endpoints = [
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.surface is not None
        and endpoint.surface.surface_kind == "framework.background_task"
    ]
    assert [
        (endpoint.handler.name, endpoint.surface.registration_line) for endpoint in task_endpoints
    ] == [("send", 18)]
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert (
        sum("untrusted, dynamic, or rebound" in item.reason for item in inventory.limitations) >= 3
    )


def test_literal_task_receiver_loop_preserves_alias_and_empty_loop_is_inert(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import BackgroundTasks, FastAPI\n\n"
        "async def send(): pass\n"
        "app = FastAPI()\n"
        "@app.post('/known')\n"
        "async def known(tasks: BackgroundTasks):\n"
        "    for queue in (tasks,):\n"
        "        pass\n"
        "    queue.add_task(send)\n"
        "@app.post('/empty')\n"
        "async def empty(tasks: BackgroundTasks):\n"
        "    for queue in ():\n"
        "        queue = tasks\n"
        "    queue.add_task(send)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    task_endpoints = [
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.surface is not None
        and endpoint.surface.surface_kind == "framework.background_task"
    ]
    assert [
        (endpoint.handler.name, endpoint.surface.registration_line) for endpoint in task_endpoints
    ] == [("send", 9)]
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert not any(
        "untrusted, dynamic, or rebound" in item.reason for item in inventory.limitations
    )


def test_arbitrary_queue_add_task_is_not_inferred_from_its_name(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "async def send(): pass\n"
        "app = FastAPI()\n"
        "@app.post('/selected')\n"
        "async def selected_route(queue):\n"
        "    queue.add_task(send)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert not any(
        endpoint.surface is not None
        and endpoint.surface.surface_kind == "framework.background_task"
        for endpoint in inventory.endpoints
    )
    assert inventory.status == InventoryStatus.ESTABLISHED


def test_nested_import_shadow_does_not_inherit_trusted_task_alias(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import BackgroundTasks, FastAPI\n\n"
        "async def send(): pass\n"
        "app = FastAPI()\n"
        "@app.post('/selected')\n"
        "async def selected_route(tasks: BackgroundTasks):\n"
        "    def helper():\n"
        "        import queue as tasks\n"
        "        tasks.add_task(send)\n"
        "    helper()\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert not any(
        endpoint.surface is not None
        and endpoint.surface.surface_kind == "framework.background_task"
        for endpoint in inventory.endpoints
    )
    assert inventory.status == InventoryStatus.CONDITIONAL


def test_background_task_dynamic_callback_fails_closed_for_selected_route(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import BackgroundTasks, FastAPI\n\n"
        "app = FastAPI()\n"
        "@app.post('/selected')\n"
        "async def selected_route(tasks: BackgroundTasks, callback):\n"
        "    tasks.add_task(callback)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert not any(
        endpoint.surface is not None
        and endpoint.surface.surface_kind == "framework.background_task"
        for endpoint in inventory.endpoints
    )
    assert any(
        "callback is unresolved or not an executable" in item.reason
        for item in inventory.limitations
    )
    assert inventory.status == InventoryStatus.CONDITIONAL


def test_response_background_task_is_conditional_on_selected_route(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from starlette.background import BackgroundTask\n"
        "from starlette.responses import Response\n\n"
        "async def after_response(): pass\n\n"
        "app = FastAPI()\n"
        "@app.get('/selected')\n"
        "async def selected_route():\n"
        "    return Response('ok', background=BackgroundTask(after_response))\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    tasks = [
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.surface is not None
        and endpoint.surface.surface_kind == "framework.background_task"
    ]
    assert [(item.handler.name, item.surface.contract_id) for item in tasks] == [
        ("after_response", "starlette-background-task-response")
    ]
    assert tasks[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL


def test_mounted_app_route_tasks_belong_to_parent_even_when_registered_later(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import BackgroundTasks, FastAPI\n\n"
        "child = FastAPI()\n"
        "app = FastAPI()\n"
        "app.mount('/child', child)\n\n"
        "async def work(): pass\n"
        "@child.post('/run')\n"
        "async def child_route(tasks: BackgroundTasks):\n"
        "    tasks.add_task(work)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    tasks = [
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.surface is not None
        and endpoint.surface.surface_kind == "framework.background_task"
    ]
    assert [item.handler.name for item in tasks] == ["work"]


def test_router_lifecycle_uses_copy_at_include_order(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import APIRouter, FastAPI\n\n"
        "router = APIRouter()\n"
        "@router.on_event('startup')\n"
        "async def copied(): pass\n\n"
        "app = FastAPI()\n"
        "app.include_router(router=router)\n\n"
        "@router.on_event('shutdown')\n"
        "async def too_late(): pass\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.handler.name for endpoint in inventory.endpoints] == ["copied"]
    assert inventory.endpoints[0].identifier == "FRAMEWORK.LIFECYCLE event:startup"
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("runtime-version-dependent" in item.reason for item in inventory.limitations)


def test_nested_router_lifecycle_late_registration_reaches_selected_app(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import APIRouter, FastAPI\n\n"
        "child = APIRouter()\n"
        "@child.on_event('startup')\n"
        "async def copied(): pass\n\n"
        "parent = APIRouter()\n"
        "parent.include_router(child)\n"
        "app = FastAPI()\n"
        "app.include_router(parent)\n\n"
        "@child.on_event('shutdown')\n"
        "async def too_late(): pass\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.handler.name for endpoint in inventory.endpoints] == ["copied"]
    assert inventory.endpoints[0].identifier == "FRAMEWORK.LIFECYCLE event:startup"
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("runtime-version-dependent" in item.reason for item in inventory.limitations)


def test_late_nested_router_include_reaches_every_existing_ancestor(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import APIRouter, FastAPI\n\n"
        "child = APIRouter()\n"
        "parent = APIRouter()\n"
        "root = APIRouter()\n"
        "root.include_router(parent)\n"
        "app = FastAPI()\n"
        "app.include_router(root)\n\n"
        "@child.on_event('startup')\n"
        "async def version_dependent(): pass\n"
        "parent.include_router(child)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("runtime-version-dependent" in item.reason for item in inventory.limitations)


def test_rebound_default_app_does_not_leave_stale_framework_surface(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n"
        "@app.on_event('startup')\n"
        "async def stale(): pass\n"
        "app = build_app()\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("unresolved or was rebound" in item.reason for item in inventory.limitations)


def test_explicit_factory_root_selects_only_returned_app_surfaces(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "unused = FastAPI()\n"
        "@unused.on_event('startup')\n"
        "async def unused_startup(): pass\n\n"
        "def create_app():\n"
        "    selected = FastAPI()\n"
        "    @selected.on_event('startup')\n"
        "    async def selected_startup(): pass\n"
        "    return selected\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path, app_entry="main:create_app")

    assert [endpoint.handler.name for endpoint in inventory.endpoints] == ["selected_startup"]
    assert inventory.status == InventoryStatus.ESTABLISHED


def test_dynamic_include_on_selected_app_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\napp = FastAPI()\napp.include_router(build_router())\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("include_router target is dynamic" in item.reason for item in inventory.limitations)


def test_nested_dynamic_include_reaches_already_included_selected_app(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import APIRouter, FastAPI\n\n"
        "parent = APIRouter()\n"
        "app = FastAPI()\n"
        "app.include_router(parent)\n"
        "parent.include_router(build_router())\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("inventory is incomplete" in item.reason for item in inventory.limitations)


def test_late_resolved_nested_include_propagates_child_limitation(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import APIRouter, FastAPI\n\n"
        "child = APIRouter()\n"
        "parent = APIRouter()\n"
        "app = FastAPI()\n"
        "app.include_router(parent)\n"
        "child.include_router(build_router())\n"
        "parent.include_router(child)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("inventory is incomplete" in item.reason for item in inventory.limitations)


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


def test_fastapi_class_middleware_resolves_bounded_indirect_base_method(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from starlette.middleware.base import BaseHTTPMiddleware\n\n"
        "class BaseAudit(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next):\n"
        "        return await call_next(request)\n\n"
        "class AuditMiddleware(BaseAudit):\n"
        "    pass\n\n"
        "app = FastAPI()\n"
        "app.add_middleware(AuditMiddleware)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "FRAMEWORK.MIDDLEWARE protocol:http"
    ]
    assert inventory.endpoints[0].handler.name == "dispatch"


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
    assert len(inventory.limitations) == 20


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


def test_duplicate_middleware_protocol_retains_physical_handlers_as_all_execute(
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

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [endpoint.handler.name for endpoint in inventory.endpoints] == ["first", "second"]
    assert all(
        endpoint.discovery_status == EndpointDiscoveryStatus.ESTABLISHED
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


def test_parser_accepted_deep_startup_route_expression_fails_closed(tmp_path: Path) -> None:
    expression = " + ".join(repr("x") for _ in range(1_200))
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        f"    app.add_api_route({expression}, late)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "FRAMEWORK.LIFECYCLE event:startup"
    ]
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("startup route path" in item.reason for item in inventory.limitations)


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

    assert inventory.endpoints == []
    assert any("unresolved or was rebound" in item.reason for item in inventory.limitations)


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


def test_startup_route_arguments_require_scalar_path_and_flat_bounded_methods(
    tmp_path: Path,
) -> None:
    too_many = ", ".join(repr("GET") for _ in range(33))
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        "    app.add_api_route(['/container'], late, methods=['GET'])\n"
        "    app.add_api_route('/scalar', late, methods='GET')\n"
        "    app.add_api_route('/nested', late, methods=[['GET']])\n"
        f"    app.add_api_route('/many', late, methods=[{too_many}])\n"
        "    app.add_api_route('/valid', late, methods=['post', 'GET', 'GET'])\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "FRAMEWORK.LIFECYCLE event:startup",
        "GET,POST /valid",
    ]
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.route_conditions == ()
    argument_limitations = [
        item
        for item in inventory.limitations
        if "startup route registration" in item.reason or "startup route methods" in item.reason
    ]
    assert len(argument_limitations) == 4
    assert any("values limit exceeded" in item.reason for item in argument_limitations)


def test_startup_over_budget_reason_is_local_and_lifecycle_evidence_remains(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "async def late(): return None\n\n"
        "@app.on_event('startup')\n"
        "async def startup() -> None:\n"
        f"    app.add_api_route({'/' + 'x' * 4096!r}, late, methods=['POST'])\n"
        "    app.add_api_route('/valid', late, methods=['POST'])\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "FRAMEWORK.LIFECYCLE event:startup",
        "POST /valid",
    ]
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.route_conditions == ()
    budget_limitations = [
        item
        for item in inventory.limitations
        if "bounded static evaluation string limit exceeded" in item.reason
    ]
    assert len(budget_limitations) == 1
    assert budget_limitations[0].source_line == 9
