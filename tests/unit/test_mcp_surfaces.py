"""Exact FastMCP/MCP tool, resource, and prompt surface adapters."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from fastapi_endpoint_detector.config import AnalysisConfig, Config
from fastapi_endpoint_detector.models.endpoint import (
    EndpointDiscoveryStatus,
    EndpointInventory,
    InventoryStatus,
)
from fastapi_endpoint_detector.models.surface_contract import load_surface_preset
from fastapi_endpoint_detector.parser.custom_surface_extractor import CustomSurfaceExtractor


def _extract(tmp_path: Path) -> EndpointInventory:
    return CustomSurfaceExtractor(tmp_path, load_surface_preset("mcp-v1")).extract_inventory()


def test_fastmcp_decorators_create_distinct_deterministic_surface_kinds(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastmcp import Context, FastMCP\n\n"
        "mcp = FastMCP('server')\n\n"
        "@mcp.tool\n"
        "async def lookup(ctx: Context) -> str: return 'ok'\n\n"
        "@mcp.tool(name='catalog.search')\n"
        "def internal_search(query: str) -> str: return query\n\n"
        "@mcp.resource('weather://{city}')\n"
        "async def weather(city: str, ctx: Context) -> str: return city\n\n"
        "@mcp.prompt\n"
        "def explain(topic: str) -> str: return topic\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "MCP.PROMPT prompt:explain",
        "MCP.RESOURCE resource:weather://{city}",
        "MCP.TOOL tool:catalog.search",
        "MCP.TOOL tool:lookup",
    ]
    assert {endpoint.handler.name for endpoint in inventory.endpoints} == {
        "explain",
        "internal_search",
        "lookup",
        "weather",
    }
    assert all(
        endpoint.discovery_status == EndpointDiscoveryStatus.ESTABLISHED
        for endpoint in inventory.endpoints
    )


def test_official_mcp_sdk_fastmcp_identity_is_supported(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n\n"
        "mcp = FastMCP('server')\n\n"
        "@mcp.tool()\n"
        "def ping() -> str: return 'pong'\n\n"
        "@mcp.resource(uri='config://app')\n"
        "def config() -> str: return 'config'\n\n"
        "@mcp.prompt(name='review')\n"
        "async def review_prompt() -> str: return 'review'\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "MCP.PROMPT prompt:review",
        "MCP.RESOURCE resource:config://app",
        "MCP.TOOL tool:ping",
    ]


def test_imperative_tool_and_prompt_registration_resolve_exact_functions(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastmcp import FastMCP\n\n"
        "mcp = FastMCP('server')\n\n"
        "async def refresh() -> str: return 'ok'\n"
        "def summarize() -> str: return 'ok'\n\n"
        "mcp.add_tool(refresh)\n"
        "mcp.add_prompt(summarize)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "MCP.PROMPT prompt:summarize",
        "MCP.TOOL tool:refresh",
    ]


def test_duplicate_mcp_ids_retain_physical_handlers_as_conditional(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastmcp import FastMCP\n\n"
        "mcp = FastMCP('server')\n\n"
        "@mcp.tool(name='duplicate')\n"
        "def first() -> str: return 'first'\n\n"
        "@mcp.tool(name='duplicate')\n"
        "def second() -> str: return 'second'\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.CONDITIONAL
    assert len(inventory.endpoints) == 2
    assert {endpoint.handler.name for endpoint in inventory.endpoints} == {"first", "second"}
    assert {endpoint.identifier for endpoint in inventory.endpoints} == {"MCP.TOOL tool:duplicate"}
    assert all(
        endpoint.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
        for endpoint in inventory.endpoints
    )


def test_dynamic_mcp_name_fails_closed_without_handler_name_fallback(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastmcp import FastMCP\n\n"
        "mcp = FastMCP('server')\n"
        "dynamic_name = get_name()\n\n"
        "@mcp.tool(name=dynamic_name)\n"
        "def internal() -> str: return 'value'\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert "resource set was not finite literal data" in inventory.limitations[0].reason


def test_dynamic_mcp_plugin_registry_remains_unresolved(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "plugin = load_plugin()\n\n@plugin.tool()\ndef dynamic_tool() -> str: return 'value'\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert "unresolved callable identity" in inventory.limitations[0].reason


def test_config_loads_mcp_preset_once_and_forbids_custom_mix(tmp_path: Path) -> None:
    config = Config(analysis=AnalysisConfig(surface_preset="mcp-v1"))

    first = config.load_surface_contract_snapshot()
    second = config.load_surface_contract_snapshot()

    assert first is second
    assert first is not None and first.document.preset.id == "mcp-surfaces"
    with pytest.raises(ValidationError, match="mutually exclusive"):
        AnalysisConfig(
            surface_preset="mcp-v1",
            surface_contracts=tmp_path / "surfaces.yaml",
        )
