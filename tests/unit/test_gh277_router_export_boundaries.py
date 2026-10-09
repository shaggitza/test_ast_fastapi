"""Boundary tests for secure-AST router re-export provenance."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from fastapi_endpoint_detector.models.endpoint import InventoryStatus
from fastapi_endpoint_detector.parser.secure_ast_extractor import (
    SecureASTExtractor,
    native_route_structural_owners,
)


def _write_reverse_ordered_export_chain(
    tmp_path: Path, import_hops: int, *, module_qualified: bool = False
) -> tuple[Path, list[Path]]:
    """Write a route reached through imports that run opposite lexical file order."""
    assert import_hops >= 2
    origin = tmp_path / "a_origin.py"
    origin.write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/deep')\n"
        "def deep(): pass\n",
        encoding="utf-8",
    )
    wrappers = [
        f"z_surface_{import_hops:02d}",
        *(f"m_{index:03d}" for index in reversed(range(import_hops - 2))),
    ]
    wrapper_paths = [tmp_path / f"{name}.py" for name in wrappers]
    for index, (_name, path) in enumerate(zip(wrappers, wrapper_paths, strict=True)):
        target = wrappers[index + 1] if index + 1 < len(wrappers) else "a_origin"
        path.write_text(
            f"from {target} import router\n__all__ = ['router']\n",
            encoding="utf-8",
        )

    main = tmp_path / "main.py"
    if module_qualified:
        target_import = f"import {wrappers[0]} as surface\n"
        target_reference = "surface.router"
    else:
        target_import = f"from {wrappers[0]} import router as deep_router\n"
        target_reference = "deep_router"
    main.write_text(
        "from fastapi import APIRouter, FastAPI\n"
        f"{target_import}"
        "local = APIRouter()\n"
        "@local.get('/local')\n"
        "def local_route(): pass\n"
        "app = FastAPI()\n"
        f"app.include_router({target_reference})\n"
        "app.include_router(local)\n",
        encoding="utf-8",
    )
    return main, wrapper_paths


def test_reverse_ordered_export_chain_resolves_at_64_import_hops(tmp_path: Path) -> None:
    # 65 project modules exceed the module-derived budget, so the fixed cap of 64 applies.
    main, wrapper_paths = _write_reverse_ordered_export_chain(tmp_path, import_hops=64)
    assert len(wrapper_paths) + 2 == 65

    inventory = SecureASTExtractor(main).extract_inventory()

    assert inventory.status is InventoryStatus.ESTABLISHED
    assert {endpoint.identifier for endpoint in inventory.endpoints} == {
        "GET /deep",
        "GET /local",
    }
    assert all(not endpoint.discovery_conditions for endpoint in inventory.endpoints)
    deep = next(endpoint for endpoint in inventory.endpoints if endpoint.identifier == "GET /deep")
    local = next(
        endpoint for endpoint in inventory.endpoints if endpoint.identifier == "GET /local"
    )
    provenance = deep.native_provenance
    assert provenance is not None
    reexports = [owner for owner in provenance.source_owners if owner.owner_kind == "reexport"]
    all_exports = [owner for owner in provenance.source_owners if owner.owner_kind == "all_export"]
    assert len(reexports) == len(wrapper_paths)
    assert len(all_exports) == len(wrapper_paths)
    assert {owner.qualified_binding for owner in all_exports} == {
        f"{path.stem}.router" for path in wrapper_paths
    }
    assert all(
        native_route_structural_owners(deep, path, {1, 2})
        and not native_route_structural_owners(local, path, {1, 2})
        for path in wrapper_paths
    )


def test_export_chain_past_64_import_hops_is_limited_without_hiding_local_route(
    tmp_path: Path,
) -> None:
    # 66 project modules still use the fixed cap of 64; the 65th import edge is not followed.
    main, wrapper_paths = _write_reverse_ordered_export_chain(tmp_path, import_hops=65)
    assert len(wrapper_paths) + 2 == 66

    inventory = SecureASTExtractor(main).extract_inventory()

    assert inventory.status is InventoryStatus.CONDITIONAL
    assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /local"]
    assert inventory.endpoints[0].native_provenance is not None
    assert not inventory.endpoints[0].discovery_conditions
    assert any(
        limitation.source_path == main
        and limitation.reason == "included router could not be resolved"
        for limitation in inventory.limitations
    )


@pytest.mark.parametrize("import_hops", [64, 65], ids=["64-hops", "65-hops"])
def test_module_qualified_router_import_obeys_transition_budget(
    tmp_path: Path, import_hops: int
) -> None:
    main, _wrapper_paths = _write_reverse_ordered_export_chain(
        tmp_path, import_hops=import_hops, module_qualified=True
    )
    inventory = SecureASTExtractor(main).extract_inventory()

    if import_hops == 64:
        assert inventory.status is InventoryStatus.ESTABLISHED
        assert {endpoint.identifier for endpoint in inventory.endpoints} == {
            "GET /deep",
            "GET /local",
        }
        assert all(not endpoint.discovery_conditions for endpoint in inventory.endpoints)
    else:
        assert inventory.status is InventoryStatus.CONDITIONAL
        assert [endpoint.identifier for endpoint in inventory.endpoints] == ["GET /local"]
        assert any(
            limitation.source_path == main
            and limitation.reason == "included router could not be resolved"
            for limitation in inventory.limitations
        )


def test_reexport_cycle_is_limited_and_all_export_ownership_stays_descendant_only(
    tmp_path: Path,
) -> None:
    implementation = tmp_path / "implementation.py"
    implementation.write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/public')\n"
        "def public_route(): pass\n",
        encoding="utf-8",
    )
    public = tmp_path / "public.py"
    public.write_text(
        "from implementation import router as public_router\n__all__ = ['public_router']\n",
        encoding="utf-8",
    )
    (tmp_path / "cycle_a.py").write_text(
        "from cycle_b import router\n__all__ = ['router']\n",
        encoding="utf-8",
    )
    (tmp_path / "cycle_b.py").write_text(
        "from cycle_a import router\n__all__ = ['router']\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "from public import public_router\n"
        "from cycle_a import router as cyclic_router\n"
        "local = APIRouter()\n"
        "@local.get('/local')\n"
        "def local_route(): pass\n"
        "app = FastAPI()\n"
        "app.include_router(public_router)\n"
        "app.include_router(cyclic_router)\n"
        "app.include_router(local)\n",
        encoding="utf-8",
    )

    inventory = SecureASTExtractor(main).extract_inventory()

    assert inventory.status is InventoryStatus.CONDITIONAL
    assert {endpoint.identifier for endpoint in inventory.endpoints} == {
        "GET /local",
        "GET /public",
    }
    assert all(not endpoint.discovery_conditions for endpoint in inventory.endpoints)
    public_endpoint = next(
        endpoint for endpoint in inventory.endpoints if endpoint.identifier == "GET /public"
    )
    local_endpoint = next(
        endpoint for endpoint in inventory.endpoints if endpoint.identifier == "GET /local"
    )
    public_provenance = public_endpoint.native_provenance
    assert public_provenance is not None
    public_all_exports = [
        owner for owner in public_provenance.source_owners if owner.owner_kind == "all_export"
    ]
    assert [owner.qualified_binding for owner in public_all_exports] == ["public.public_router"]
    assert any(
        owner.owner_kind == "all_export"
        for owner in native_route_structural_owners(public_endpoint, public, {2})
    )
    assert native_route_structural_owners(local_endpoint, public, {2}) == ()
    assert any(
        limitation.source_path == main
        and limitation.reason == "included router could not be resolved"
        for limitation in inventory.limitations
    )
