"""Physical registration occurrences survive framework multiplicity normalization."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from fastapi_endpoint_detector.models.endpoint import Endpoint, InventoryStatus
from fastapi_endpoint_detector.models.surface_contract import (
    load_surface_contracts,
    load_surface_preset,
)
from fastapi_endpoint_detector.parser.custom_surface_extractor import CustomSurfaceExtractor


@pytest.mark.parametrize(
    "registrations",
    [
        "app = FastAPI()\n"
        "app.add_event_handler('startup', cb); app.add_event_handler('startup', cb)\n",
        "app = FastAPI()\n"
        "app.add_event_handler('startup', cb)\napp.add_event_handler('startup', cb)\n",
        "app = FastAPI(on_startup=[cb, cb])\n",
        "app = FastAPI(on_startup=(cb, cb))\n",
    ],
)
def test_all_execute_preserves_repeated_callback_occurrences(
    tmp_path: Path, registrations: str
) -> None:
    source = tmp_path / "main.py"
    source.write_text(
        "from fastapi import FastAPI\nasync def cb(): pass\n" + registrations,
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path, load_surface_preset("framework-v1")
    ).extract_inventory()

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert len(inventory.endpoints) == 2
    assert {item.handler.name for item in inventory.endpoints} == {"cb"}
    occurrences = []
    for endpoint in inventory.endpoints:
        surface = endpoint.surface
        assert surface is not None and surface.callback_reference_span is not None
        callback = surface.callback_reference_span
        assert callback.file_path == source
        occurrences.append(
            (
                surface.registration_line,
                surface.registration_column,
                callback.start_line,
                callback.start_column,
            )
        )
        replayed = Endpoint.model_validate_json(endpoint.model_dump_json())
        assert replayed.surface == surface
    assert len(set(occurrences)) == 2


def test_last_wins_still_replaces_same_line_exception_registration(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "async def first(request, exc): pass\n"
        "async def second(request, exc): pass\n"
        "app = FastAPI()\n"
        "app.add_exception_handler(ValueError, first); "
        "app.add_exception_handler(ValueError, second)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path, load_surface_preset("framework-v1")
    ).extract_inventory()
    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [endpoint.handler.name for endpoint in inventory.endpoints] == ["second"]


def test_all_execute_preserves_identical_coordinates_in_separate_modules(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "import registrations_a\nimport registrations_b\n",
        encoding="utf-8",
    )
    (tmp_path / "callbacks.py").write_text("async def cb(): pass\n", encoding="utf-8")
    for name in ("registrations_a", "registrations_b"):
        (tmp_path / f"{name}.py").write_text(
            "from main import app\nfrom callbacks import cb\n"
            "app.add_event_handler('startup', cb)\n",
            encoding="utf-8",
        )
    inventory = CustomSurfaceExtractor(
        tmp_path, load_surface_preset("framework-v1"), app_entry="main:app"
    ).extract_inventory()

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert len(inventory.endpoints) == 2
    assert {endpoint.handler.name for endpoint in inventory.endpoints} == {"cb"}
    registration_files = set()
    for endpoint in inventory.endpoints:
        surface = endpoint.surface
        assert surface is not None and surface.callback_reference_span is not None
        assert surface.registration_line == 3 and surface.registration_column == 0
        assert surface.callback_reference_span.file_path == surface.registration_file
        registration_files.add(surface.registration_file.name)
        assert Endpoint.model_validate_json(endpoint.model_dump_json()).surface == surface
    assert registration_files == {"registrations_a.py", "registrations_b.py"}


def test_callback_alias_keyword_and_expanded_arguments_preserve_occurrences(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "async def cb(): pass\n"
        "alias = cb\n"
        "app = FastAPI()\n"
        "app.add_event_handler(event_type='startup', func=alias)\n"
        "app.add_event_handler(**{'event_type': 'startup', 'func': alias})\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path, load_surface_preset("framework-v1")
    ).extract_inventory()

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert len(inventory.endpoints) == 2
    assert {endpoint.handler.name for endpoint in inventory.endpoints} == {"cb"}
    assert (
        len(
            {
                (
                    endpoint.surface.registration_line,
                    endpoint.surface.registration_column,
                    endpoint.surface.callback_reference_span.start_line,
                    endpoint.surface.callback_reference_span.start_column,
                )
                for endpoint in inventory.endpoints
                if endpoint.surface is not None
                and endpoint.surface.callback_reference_span is not None
            }
        )
        == 2
    )


def test_repeated_router_include_copies_are_distinct_all_execute_occurrences(
    tmp_path: Path,
) -> None:
    source = tmp_path / "main.py"
    source.write_text(
        "from fastapi import FastAPI, APIRouter\n"
        "async def cb(): pass\n"
        "router = APIRouter(on_startup=[cb])\n"
        "app = FastAPI()\n"
        "app.include_router(router)\n"
        "app.include_router(router)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path, load_surface_preset("framework-v1")
    ).extract_inventory()

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert len(inventory.endpoints) == 2
    assert all(endpoint.handler.name == "cb" for endpoint in inventory.endpoints)
    assert all(
        endpoint.surface is not None
        and endpoint.surface.registration_file == source
        and endpoint.surface.registration_line == 3
        for endpoint in inventory.endpoints
    )


def test_nested_repeated_router_copies_retain_full_include_path(tmp_path: Path) -> None:
    source = tmp_path / "main.py"
    source.write_text(
        "from fastapi import FastAPI, APIRouter\n"
        "async def cb(): pass\n"
        "inner = APIRouter(on_startup=[cb])\n"
        "outer = APIRouter()\n"
        "outer.include_router(inner); outer.include_router(inner)\n"
        "app = FastAPI()\n"
        "app.include_router(outer); app.include_router(outer)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path, load_surface_preset("framework-v1")
    ).extract_inventory()
    assert inventory.status == InventoryStatus.ESTABLISHED
    assert len(inventory.endpoints) == 4
    paths = set()
    for endpoint in inventory.endpoints:
        assert endpoint.surface is not None
        spans = endpoint.surface.include_reference_spans
        assert len(spans) == 2
        assert [span.start_line for span in spans] == [5, 7]
        assert all(span.file_path == source for span in spans)
        paths.add(tuple((span.start_line, span.start_column) for span in spans))
        assert Endpoint.model_validate_json(endpoint.model_dump_json()).surface == endpoint.surface
    assert len(paths) == 4


def test_exact_contract_overlap_deduplicates_each_physical_registration(tmp_path: Path) -> None:
    preset = load_surface_preset("framework-v1")
    payload = preset.document.model_dump(mode="json")
    exact = next(row for row in payload["contracts"] if row["id"] == "starlette-add-event-handler")
    wildcard = deepcopy(exact)
    wildcard["id"] = "wildcard-event-handler"
    wildcard["registration"]["symbol"] = "starlette.applications.*.add_event_handler"
    payload["contracts"].append(wildcard)
    contract_path = tmp_path / "contracts.yaml"
    contract_path.write_text(json.dumps(payload), encoding="utf-8")
    (tmp_path / "main.py").write_text(
        "from starlette.applications import Starlette\nasync def cb(): pass\napp = Starlette()\n"
        "app.add_event_handler('startup', cb); app.add_event_handler('startup', cb)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path, load_surface_contracts(contract_path)
    ).extract_inventory()
    assert inventory.status == InventoryStatus.ESTABLISHED
    assert len(inventory.endpoints) == 2
    assert all(
        endpoint.surface is not None
        and endpoint.surface.contract_id == "starlette-add-event-handler"
        and endpoint.surface.match_kind.value == "exact"
        for endpoint in inventory.endpoints
    )


@pytest.mark.parametrize(
    ("method", "expected"),
    [("openapi", InventoryStatus.ESTABLISHED), ("add_event_handler", InventoryStatus.CONDITIONAL)],
)
def test_malformed_getattr_only_limits_relevant_registration(
    tmp_path: Path, method: str, expected: InventoryStatus
) -> None:
    (tmp_path / "main.py").write_text(
        f"from fastapi import FastAPI\napp = FastAPI()\ngetattr(app, '{method}', None, None)()\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path, load_surface_preset("framework-v1")
    ).extract_inventory()
    assert inventory.status == expected
    assert bool(inventory.limitations) == (expected == InventoryStatus.CONDITIONAL)
    assert len(inventory.endpoints) == 0


@pytest.mark.parametrize("receiver", ["app", "unused"])
def test_aliased_exception_failure_is_scoped_to_receiver(tmp_path: Path, receiver: str) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\nunused = FastAPI()\n"
        "def choose(): pass\n"
        f"register = {receiver}.add_exception_handler\n"
        "register(ValueError, choose())\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path, load_surface_preset("framework-v1")
    ).extract_inventory()
    expected = InventoryStatus.CONDITIONAL if receiver == "app" else InventoryStatus.ESTABLISHED
    assert inventory.status == expected
    assert bool(inventory.limitations) == (receiver == "app")
    assert len(inventory.endpoints) == 0
