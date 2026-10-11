"""Explicit app entries resolve only proven project-local symbol re-exports."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.models.endpoint import EndpointInventory
from fastapi_endpoint_detector.parser.secure_ast_extractor import (
    SecureASTExtractor,
    SecureASTExtractorError,
)


def _inventory(
    tmp_path: Path, sources: dict[str, str], *, entry: str = "main:app"
) -> EndpointInventory:
    for relative, source in sources.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    return SecureASTExtractor(tmp_path, app_entry=entry).extract_inventory()


@pytest.mark.parametrize(
    ("sources", "entry", "route_path"),
    (
        (
            {
                "routes.py": (
                    "from fastapi import FastAPI\napp = FastAPI()\n"
                    "@app.get('/from-routes')\ndef route(): return {}\n"
                ),
                "main.py": "from routes import app\n",
            },
            "main:app",
            "/from-routes",
        ),
        (
            {
                "routes.py": (
                    "from fastapi import FastAPI\napp = FastAPI()\n"
                    "@app.get('/from-alias')\ndef route(): return {}\n"
                ),
                "main.py": "from routes import app as selected\n",
            },
            "main:selected",
            "/from-alias",
        ),
        (
            {
                "routes.py": (
                    "from fastapi import FastAPI\napp = FastAPI()\n"
                    "@app.get('/two-hop')\ndef route(): return {}\n"
                ),
                "facade.py": "from routes import app\n",
                "main.py": "from facade import app\n",
            },
            "main:app",
            "/two-hop",
        ),
    ),
    ids=("direct-reexport", "aliased-reexport", "two-hop-reexport"),
)
def test_explicit_app_entry_resolves_project_reexports(
    tmp_path: Path, sources: dict[str, str], entry: str, route_path: str
) -> None:
    inventory = _inventory(tmp_path, sources, entry=entry)
    assert [endpoint.identifier for endpoint in inventory.endpoints] == [f"GET {route_path}"]
    endpoint = inventory.endpoints[0]
    assert endpoint.handler.module == "routes"
    assert endpoint.handler.file_path == (tmp_path / "routes.py").resolve()


@pytest.mark.parametrize(
    "sources",
    (
        {
            "routes.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "main.py": "from routes import app\napp = object()\n",
        },
        {
            "routes.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "main.py": "from routes import app; from routes import app\n",
        },
        {
            "main.py": "from facade import app\n",
            "facade.py": "from main import app\n",
        },
        {"main.py": "from absent_external_package import app\n"},
        {
            "main.py": (
                "from typing import TYPE_CHECKING\n"
                "if TYPE_CHECKING:\n    from absent_type_only_package import app\n"
            )
        },
    ),
    ids=("rebound", "duplicate-same-line", "cycle", "missing-foreign-module", "type-only"),
)
def test_explicit_app_entry_rejects_unproven_reexports(
    tmp_path: Path, sources: dict[str, str]
) -> None:
    with pytest.raises(SecureASTExtractorError, match="absent, ambiguous, or rebound"):
        _inventory(tmp_path, sources)
