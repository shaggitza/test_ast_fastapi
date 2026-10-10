"""Registration uncertainty belongs to the physical selected receiver call."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.models.endpoint import InventoryStatus
from fastapi_endpoint_detector.models.surface_contract import load_surface_preset
from fastapi_endpoint_detector.parser.custom_surface_extractor import CustomSurfaceExtractor


@pytest.mark.parametrize("receiver", ["app", "unused"])
@pytest.mark.parametrize("call", ["{receiver}.add_event_handler", "register"])
def test_unknown_expansion_beside_keyword_selectors_is_receiver_scoped(
    tmp_path: Path, receiver: str, call: str
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "async def cb(): pass\n"
        "app = FastAPI()\nunused = FastAPI()\n"
        f"register = {receiver}.add_event_handler\n"
        f"{call.format(receiver=receiver)}(event_type='startup', func=cb, **options)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path, load_surface_preset("framework-v1"), app_entry="main:app"
    ).extract_inventory()
    assert inventory.status == (
        InventoryStatus.CONDITIONAL if receiver == "app" else InventoryStatus.ESTABLISHED
    )
    assert not inventory.endpoints
    assert bool(inventory.limitations) == (receiver == "app")


@pytest.mark.parametrize("known_receiver", ["app", "unused"])
def test_same_line_success_preserves_other_middleware_call_uncertainty(
    tmp_path: Path, known_receiver: str
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from starlette.middleware.base import BaseHTTPMiddleware\n"
        "class Known(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next): return await call_next(request)\n"
        "app = FastAPI()\nunused = FastAPI()\n"
        f"app.add_middleware(Dynamic); {known_receiver}.add_middleware(Known)\n",
        encoding="utf-8",
    )
    inventory = CustomSurfaceExtractor(
        tmp_path, load_surface_preset("framework-v1"), app_entry="main:app"
    ).extract_inventory()
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any(
        "matched but handler was unresolved" in item.reason for item in inventory.limitations
    )
    assert len(inventory.endpoints) == (1 if known_receiver == "app" else 0)
