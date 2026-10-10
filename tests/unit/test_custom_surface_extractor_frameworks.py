"""Regression coverage for exact selected FastAPI lifecycle uncertainty."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.models.endpoint import InventoryStatus
from fastapi_endpoint_detector.models.surface_contract import load_surface_preset
from fastapi_endpoint_detector.parser.custom_surface_extractor import CustomSurfaceExtractor


def _extract(tmp_path: Path):
    return CustomSurfaceExtractor(tmp_path, load_surface_preset("framework-v1")).extract_inventory()


def test_duplicate_lifecycle_keywords_on_included_router_limit_selected_app(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI, APIRouter\n"
        "router = APIRouter()\n"
        "async def callback(): pass\n"
        "router.add_event_handler(**{'event_type': 'startup'}, "
        "**{'event_type': 'shutdown', 'handler': callback})\n"
        "app = FastAPI()\n"
        "app.include_router(router)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("duplicate keyword" in item.reason for item in inventory.limitations)


def test_duplicate_nonregistration_app_method_does_not_limit_inventory(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\napp.openapi(**{'x': 1}, **{'x': 2})\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert inventory.limitations == ()


def test_duplicate_lifecycle_keywords_on_unselected_app_do_not_limit_selected(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "unused = FastAPI()\n"
        "app = FastAPI()\n"
        "async def selected(): pass\n"
        "unused.add_event_handler(**{'event_type': 'startup'}, "
        "**{'event_type': 'shutdown', 'handler': selected})\n"
        "app.add_event_handler('startup', selected)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [item.handler.name for item in inventory.endpoints] == ["selected"]
    assert inventory.limitations == ()


@pytest.mark.parametrize("registration", ["direct", "bound alias"])
def test_getattr_default_walrus_preserves_receiver_captured_first(
    tmp_path: Path, registration: str
) -> None:
    if registration == "bound alias":
        invocation = (
            "method = getattr(receiver, 'add_event_handler', (receiver := unused))\n"
            "method('startup', selected)\n"
        )
    else:
        invocation = (
            "getattr(receiver, 'add_event_handler', (receiver := unused))('startup', selected)\n"
        )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "unused = FastAPI()\n"
        "async def selected(): pass\n"
        "async def unrelated(): pass\n"
        "receiver = app\n"
        f"{invocation}"
        "unused.add_event_handler('shutdown', unrelated)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [item.handler.name for item in inventory.endpoints] == ["selected"]


@pytest.mark.parametrize("receiver", ["app", "unused"])
def test_getattr_receiver_walrus_captures_after_object_evaluation(
    tmp_path: Path, receiver: str
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "unused = FastAPI()\n"
        "async def selected(): pass\n"
        "async def unrelated(): pass\n"
        "receiver = unused\n"
        f"getattr((receiver := {receiver}), 'add_event_handler')('startup', selected)\n"
        "unused.add_event_handler('shutdown', unrelated)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    if receiver == "app":
        assert inventory.status == InventoryStatus.ESTABLISHED
        assert [item.handler.name for item in inventory.endpoints] == ["selected"]
    else:
        assert inventory.status == InventoryStatus.ESTABLISHED
        assert inventory.endpoints == []
        assert inventory.limitations == ()


def test_imported_bound_lifecycle_alias_resolves_project_receiver(tmp_path: Path) -> None:
    (tmp_path / "registrations.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\nregister = app.add_event_handler\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from registrations import app, register\n"
        "async def selected(): pass\n"
        "register('startup', selected)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [item.handler.name for item in inventory.endpoints] == ["selected"]


def test_project_bound_alias_shadowed_at_import_site_does_not_register(
    tmp_path: Path,
) -> None:
    (tmp_path / "registrations.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\nregister = app.add_event_handler\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from registrations import app, register\n"
        "async def selected(): pass\n"
        "def register(*args): pass\n"
        "register('startup', selected)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert inventory.endpoints == []
    assert inventory.limitations == ()


def test_imported_bound_alias_on_unselected_receiver_does_not_taint_inventory(
    tmp_path: Path,
) -> None:
    (tmp_path / "registrations.py").write_text(
        "from fastapi import FastAPI\nunused = FastAPI()\nregister = unused.add_event_handler\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from registrations import register\n"
        "app = FastAPI()\n"
        "async def selected(): pass\n"
        "register('startup', selected)\n"
        "app.add_event_handler('startup', selected)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [item.handler.name for item in inventory.endpoints] == ["selected"]
    assert inventory.limitations == ()


def test_ambiguous_project_app_bindings_remain_conditional(tmp_path: Path) -> None:
    (tmp_path / "first.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "async def first(): pass\n"
        "app.add_event_handler('startup', first)\n",
        encoding="utf-8",
    )
    (tmp_path / "second.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "async def second(): pass\n"
        "app.add_event_handler('startup', second)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.endpoints == []
    assert any("ambiguous" in item.reason for item in inventory.limitations)


def test_module_del_getattr_restores_builtin_but_function_del_is_local(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "getattr = custom_getattr\n"
        "del getattr\n"
        "app = FastAPI()\n"
        "async def selected(): pass\n"
        "async def local_selected(): pass\n"
        "getattr(app, 'add_event_handler', None)('startup', selected)\n"
        "@app.on_event('startup')\n"
        "async def local_case():\n"
        "    getattr = custom_getattr\n"
        "    del getattr\n"
        "    getattr(app, 'add_event_handler', None)('startup', local_selected)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.CONDITIONAL
    assert {item.handler.name for item in inventory.endpoints} == {"local_case", "selected"}


@pytest.mark.parametrize("entry", ["bootstrap", "factory"])
def test_selected_function_global_delete_restores_builtin_getattr(
    tmp_path: Path, entry: str
) -> None:
    header = (
        "from fastapi import FastAPI\n"
        "def custom_getattr(*args): pass\n"
        "getattr = custom_getattr\n"
        "async def callback(): pass\n"
    )
    if entry == "bootstrap":
        body = (
            "app = FastAPI()\n"
            "def initialize():\n"
            "    global getattr\n"
            "    del getattr\n"
            "    getattr(app, 'add_event_handler')('startup', callback)\n"
        )
        options = {"bootstrap_entry": "main:initialize"}
    else:
        body = (
            "def create_app():\n"
            "    global getattr\n"
            "    del getattr\n"
            "    app = FastAPI()\n"
            "    getattr(app, 'add_event_handler')('startup', callback)\n"
            "    return app\n"
        )
        options = {"app_entry": "main:create_app"}
    (tmp_path / "main.py").write_text(header + body, encoding="utf-8")
    inventory = CustomSurfaceExtractor(
        tmp_path, load_surface_preset("framework-v1"), **options
    ).extract_inventory()
    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [endpoint.handler.name for endpoint in inventory.endpoints] == ["callback"]
    assert inventory.limitations == ()


@pytest.mark.parametrize("receiver", ["app", "unused"])
def test_unknown_exception_override_through_alias_invalidates_only_receiver(
    tmp_path: Path, receiver: str
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\nunused = FastAPI()\n"
        "async def original(request, exc): pass\n"
        "def choose(): pass\n"
        "app.add_exception_handler(ValueError, original)\n"
        f"register = {receiver}.add_exception_handler\n"
        "register(ValueError, choose())\n",
        encoding="utf-8",
    )
    inventory = _extract(tmp_path)
    if receiver == "app":
        assert inventory.status == InventoryStatus.CONDITIONAL
        assert inventory.endpoints == []
        assert any("may override" in item.reason for item in inventory.limitations)
    else:
        assert inventory.status == InventoryStatus.ESTABLISHED
        assert [endpoint.handler.name for endpoint in inventory.endpoints] == ["original"]
        assert inventory.limitations == ()


@pytest.mark.parametrize("registration", ["direct", "bound alias"])
def test_unknown_exception_override_invalidates_only_exact_exception_key(
    tmp_path: Path, registration: str
) -> None:
    if registration == "bound alias":
        replacement = "register = app.add_exception_handler\nregister(ValueError, choose())\n"
    else:
        replacement = "app.add_exception_handler(ValueError, choose())\n"
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "async def value_handler(request, exc): pass\n"
        "async def key_handler(request, exc): pass\n"
        "def choose(): pass\n"
        "app.add_exception_handler(ValueError, value_handler)\n"
        "app.add_exception_handler(KeyError, key_handler)\n" + replacement,
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.CONDITIONAL
    assert [endpoint.handler.name for endpoint in inventory.endpoints] == ["key_handler"]
    assert {endpoint.surface.resource for endpoint in inventory.endpoints} == {"builtins.KeyError"}
    assert any("may override" in item.reason for item in inventory.limitations)


def test_unknown_exception_override_dynamic_key_invalidates_all_possible_keys(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "async def value_handler(request, exc): pass\n"
        "async def key_handler(request, exc): pass\n"
        "def choose(): pass\n"
        "def get_exception_type(): pass\n"
        "exception_type = get_exception_type()\n"
        "app.add_exception_handler(ValueError, value_handler)\n"
        "app.add_exception_handler(KeyError, key_handler)\n"
        "app.add_exception_handler(exception_type, choose())\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.CONDITIONAL
    assert inventory.endpoints == []
    assert any("may override" in item.reason for item in inventory.limitations)
