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
