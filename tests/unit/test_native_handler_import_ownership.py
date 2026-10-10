"""Live handler imports own their route occurrences on the matching snapshot."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.endpoint_registry import EndpointRegistry
from fastapi_endpoint_detector.models.endpoint import SnapshotSide
from fastapi_endpoint_detector.parser.secure_ast_extractor import (
    SecureASTExtractor,
    native_route_structural_owners,
)


@pytest.mark.parametrize("side", [SnapshotSide.BASELINE, SnapshotSide.TARGET])
@pytest.mark.parametrize(
    ("binding", "expression"),
    [
        ("from routes import read as selected", "selected"),
        ("import routes as selected", "selected.read"),
    ],
)
def test_only_live_handler_import_owns_route(
    tmp_path: Path, side: SnapshotSide, binding: str, expression: str
) -> None:
    (tmp_path / "routes.py").write_text("def read(): return 1\n", encoding="utf-8")
    main = tmp_path / "main.py"
    main.write_text(
        "from fastapi import FastAPI\n"
        f"{binding}\n"
        "from routes import read as unused\n"
        "app = FastAPI()\n"
        f"app.add_api_route('/read', {expression}, methods=['GET'])\n",
        encoding="utf-8",
    )
    endpoint = SecureASTExtractor(tmp_path, snapshot_side=side).extract_endpoints()[0]
    owners = native_route_structural_owners(endpoint, main, {2})
    assert len(owners) == 1
    assert owners[0].owner_kind == "import_binding"
    assert owners[0].related_binding == "routes.read"
    assert owners[0].side == side
    assert not native_route_structural_owners(endpoint, main, {3})
    registry = EndpointRegistry()
    registry.register(endpoint)
    overlap = registry.get_structural_overlaps(Path("main.py"), {2})
    assert len(overlap) == 1
    assert overlap[0][1] == ("source_import_binding",)
    assert overlap[0][2] == {2}
    assert not registry.get_structural_overlaps(Path("main.py"), {3})


def test_rebound_handler_does_not_own_stale_import(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text("def read(): return 1\n", encoding="utf-8")
    main = tmp_path / "main.py"
    main.write_text(
        "from fastapi import FastAPI\n"
        "from routes import read\n"
        "def read(): return 2\n"
        "app = FastAPI()\n"
        "app.add_api_route('/read', read, methods=['GET'])\n",
        encoding="utf-8",
    )
    endpoint = SecureASTExtractor(tmp_path).extract_endpoints()[0]
    assert endpoint.handler.module == "main"
    assert not native_route_structural_owners(endpoint, main, {2})
