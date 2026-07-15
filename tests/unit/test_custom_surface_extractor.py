"""Execution-free custom surface discovery tests."""

import json
import re
from pathlib import Path

import yaml

from fastapi_endpoint_detector.models.endpoint import EndpointDiscoveryStatus, InventoryStatus
from fastapi_endpoint_detector.models.report import (
    AffectedEndpoint,
    AnalysisReport,
    ConfidenceLevel,
)
from fastapi_endpoint_detector.models.surface_contract import load_surface_contracts
from fastapi_endpoint_detector.output.formatters import get_formatter
from fastapi_endpoint_detector.parser.custom_surface_extractor import CustomSurfaceExtractor


def _contracts(
    tmp_path: Path,
    *,
    symbol: str = "framework.Reactor.listen",
    callback_mode: str = "async",
    handler: dict[str, object] | None = None,
    receiver_type: str = "framework.Reactor",
) -> Path:
    path = tmp_path / "surfaces.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "preset": {
                    "id": "fixture",
                    "version": "1",
                    "provenance": {"kind": "user", "source": "tests"},
                },
                "contracts": [
                    {
                        "id": "listener",
                        "registration": {
                            "symbol": symbol,
                            "invocation": "instance_method",
                            "receiver_type": receiver_type,
                        },
                        "handler": handler or {"kind": "decorated_function"},
                        "surface": {
                            "kind": "reactor",
                            "id_template": "topic:{resource}",
                            "resource": {"kind": "argument", "index": 0},
                        },
                        "callback_mode": callback_mode,
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return path


def test_exact_decorator_registration_has_complete_provenance(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "@reactor.listen('orders')\n"
        "async def process_order():\n"
        "    return None\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path))

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [item.identifier for item in inventory.endpoints] == ["REACTOR topic:orders"]
    endpoint = inventory.endpoints[0]
    assert endpoint.handler.name == "process_order"
    assert endpoint.discovery_status == EndpointDiscoveryStatus.ESTABLISHED
    assert endpoint.surface is not None
    assert endpoint.surface.registration_symbol == "framework.Reactor.listen"
    assert endpoint.surface.contract_id == "listener"
    assert endpoint.surface.registration_line == 4
    assert endpoint.surface.config_hash == loaded.config_hash
    assert endpoint.surface.registration_source_hash.startswith("sha256:")
    assert endpoint.surface.handler_source_hash.startswith("sha256:")


def test_nested_generator_does_not_change_callback_mode(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "@reactor.listen('orders')\n"
        "async def process():\n"
        "    async def nested():\n"
        "        yield 1\n"
        "    return nested\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, callback_mode="async"))

    endpoints = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory().endpoints

    assert [item.handler.name for item in endpoints] == ["process"]


def test_unrelated_same_method_name_never_matches(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "from unrelated import Other\n"
        "reactor = Reactor()\n"
        "other = Other()\n\n"
        "@other.listen('wrong')\n"
        "async def wrong(): pass\n\n"
        "@reactor.listen('right')\n"
        "async def right(): pass\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path))

    endpoints = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory().endpoints

    assert [item.identifier for item in endpoints] == ["REACTOR topic:right"]


def test_dynamic_registration_is_omitted_with_inventory_limitation(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import make_reactor\n\n"
        "@make_reactor().listen('orders')\n"
        "async def process(): pass\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path))

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert "unresolved callable identity" in inventory.limitations[0].reason


def test_augmented_receiver_rebinding_fails_closed_with_limitation(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "reactor += other\n\n"
        "@reactor.listen('orders')\n"
        "async def process(): pass\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path))

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL


def test_receiver_rebinding_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n"
        "reactor = object()\n\n"
        "@reactor.listen('orders')\n"
        "async def process(): pass\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path))

    assert CustomSurfaceExtractor(tmp_path, loaded).extract_inventory().endpoints == []


def test_registration_inside_uncalled_method_is_not_a_surface(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "async def process(): pass\n\n"
        "class NeverInstantiated:\n"
        "    def configure(self):\n"
        "        reactor.listen('orders', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    assert CustomSurfaceExtractor(tmp_path, loaded).extract_inventory().endpoints == []


def test_registration_inside_uncalled_function_is_not_a_surface(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "async def process(): pass\n\n"
        "def configure():\n"
        "    reactor.listen('orders', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    assert CustomSurfaceExtractor(tmp_path, loaded).extract_inventory().endpoints == []


def test_explicit_bootstrap_executes_registration_body(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "async def process(): pass\n\n"
        "def configure():\n"
        "    reactor.listen('orders', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    endpoints = (
        CustomSurfaceExtractor(
            tmp_path,
            loaded,
            bootstrap_entry="main:configure",
        )
        .extract_inventory()
        .endpoints
    )

    assert [item.identifier for item in endpoints] == ["REACTOR topic:orders"]


def test_callback_argument_requires_one_unambiguous_project_function(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "async def process(): pass\n\n"
        "reactor.listen('orders', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    endpoints = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory().endpoints

    assert [item.handler.name for item in endpoints] == ["process"]


def test_wildcard_match_is_always_conditional_low_only(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from vendor.framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "@reactor.listen('orders')\n"
        "async def process(): pass\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(
        _contracts(
            tmp_path,
            symbol="vendor.*.Reactor.listen",
            receiver_type="vendor.framework.Reactor",
        )
    )

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    endpoint = inventory.endpoints[0]
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert endpoint.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
    assert endpoint.surface is not None and endpoint.surface.match_kind.value == "wildcard"
    assert "LOW-only wildcard" in endpoint.discovery_conditions[0].reason


def test_surface_provenance_is_visible_in_all_output_formats(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "@reactor.listen('orders')\n"
        "async def process(): pass\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path))
    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()
    endpoint = inventory.endpoints[0]
    affected = AffectedEndpoint(
        endpoint=endpoint,
        confidence=ConfidenceLevel.HIGH,
        reason="changed handler",
    )
    report = AnalysisReport(
        app_path=str(tmp_path),
        diff_source="change.diff",
        total_endpoints=1,
        affected_endpoints=[affected],
        candidate_endpoints=[affected],
    )

    rendered = {
        name: get_formatter(name).format(report)
        for name in ("json", "yaml", "text", "markdown", "html")
    }
    payload = json.loads(rendered["json"])

    assert payload["affected_endpoints"][0]["endpoint"]["surface"]["contract_id"] == "listener"
    for name, output in rendered.items():
        plain = re.sub(r"\x1b\[[0-9;]*m", "", output)
        assert "listener" in plain, name
        assert loaded.config_hash in plain, name
    for name in ("json", "yaml", "text", "markdown", "html"):
        inventory_output = get_formatter(name).format_inventory(inventory)
        assert "listener" in inventory_output, name


def test_exact_match_dominates_overlapping_wildcard_without_duplication(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from vendor.framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "@reactor.listen('orders')\n"
        "async def process(): pass\n",
        encoding="utf-8",
    )
    path = _contracts(
        tmp_path,
        symbol="vendor.framework.Reactor.listen",
        receiver_type="vendor.framework.Reactor",
    )
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    wildcard = dict(payload["contracts"][0])
    wildcard["id"] = "wildcard-listener"
    wildcard["registration"] = dict(wildcard["registration"])
    wildcard["registration"]["symbol"] = "vendor.*.Reactor.listen"
    payload["contracts"].append(wildcard)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    loaded = load_surface_contracts(path)

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert len(inventory.endpoints) == 1
    assert inventory.endpoints[0].surface is not None
    assert inventory.endpoints[0].surface.contract_id == "listener"
    assert inventory.endpoints[0].discovery_status == EndpointDiscoveryStatus.ESTABLISHED


def test_handler_redefinition_is_ambiguous_and_inventory_is_conditional(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "async def process(): pass\n"
        "async def process(): pass\n\n"
        "reactor.listen('orders', process)\n",
        encoding="utf-8",
    )
    loaded = load_surface_contracts(_contracts(tmp_path, handler={"kind": "argument", "index": 1}))

    inventory = CustomSurfaceExtractor(tmp_path, loaded).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert "handler was unresolved" in inventory.limitations[0].reason
