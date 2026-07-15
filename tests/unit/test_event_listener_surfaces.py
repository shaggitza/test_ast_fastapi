"""Bundled event-listener adapter contracts and finite resource tests."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from fastapi_endpoint_detector.config import AnalysisConfig, Config
from fastapi_endpoint_detector.models.endpoint import EndpointDiscoveryStatus, InventoryStatus
from fastapi_endpoint_detector.models.surface_contract import (
    SurfaceContractError,
    load_surface_preset,
)
from fastapi_endpoint_detector.parser.custom_surface_extractor import CustomSurfaceExtractor


def test_faststream_rabbit_and_kafka_decorators_have_exact_finite_surfaces(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from faststream.kafka import KafkaBroker\n"
        "from faststream.rabbit import RabbitBroker\n\n"
        "kafka = KafkaBroker()\n"
        "rabbit = RabbitBroker()\n\n"
        "@rabbit.subscriber('orders')\n"
        "async def consume_order(): pass\n\n"
        "@kafka.subscriber('payments', 'audit')\n"
        "async def consume_payment(): pass\n",
        encoding="utf-8",
    )

    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_preset("event-listeners-v1"),
    ).extract_inventory()

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "KAFKA topic:audit",
        "KAFKA topic:payments",
        "RABBITMQ queue:orders",
    ]
    assert all(
        endpoint.discovery_status == EndpointDiscoveryStatus.ESTABLISHED
        for endpoint in inventory.endpoints
    )
    assert {
        endpoint.surface.registration_symbol
        for endpoint in inventory.endpoints
        if endpoint.surface is not None
    } == {
        "faststream.kafka.KafkaBroker.subscriber",
        "faststream.rabbit.RabbitBroker.subscriber",
    }


def test_aio_pika_imperative_consumer_is_conditional_without_queue_fanout(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from aio_pika.queue import Queue\n\n"
        "queue = Queue()\n\n"
        "async def process_order(message): pass\n\n"
        "queue.consume(process_order)\n",
        encoding="utf-8",
    )

    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_preset("event-listeners-v1"),
    ).extract_inventory()

    assert inventory.status == InventoryStatus.CONDITIONAL
    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "RABBITMQ handler:process_order"
    ]
    endpoint = inventory.endpoints[0]
    assert endpoint.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
    assert endpoint.surface is not None
    assert endpoint.surface.resource == "process_order"
    assert "queue identity is receiver-bound" in endpoint.discovery_conditions[0].reason


def test_event_preset_rejects_sync_callbacks_for_async_consumers(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from faststream.rabbit import RabbitBroker\n\n"
        "broker = RabbitBroker()\n\n"
        "@broker.subscriber('orders')\n"
        "def consume_order(): pass\n",
        encoding="utf-8",
    )

    inventory = CustomSurfaceExtractor(
        tmp_path,
        load_surface_preset("event-listeners-v1"),
    ).extract_inventory()

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert "handler was unresolved" in inventory.limitations[0].reason


def test_config_loads_named_event_listener_preset_once() -> None:
    config = Config(analysis=AnalysisConfig(surface_preset="event-listeners-v1"))

    first = config.load_surface_contract_snapshot()
    second = config.load_surface_contract_snapshot()

    assert first is second
    assert first is not None
    assert first.document.preset.id == "event-listeners"


def test_config_forbids_mixing_preset_and_custom_document(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="mutually exclusive"):
        AnalysisConfig(
            surface_preset="event-listeners-v1",
            surface_contracts=tmp_path / "surfaces.yaml",
        )


def test_unknown_event_preset_name_fails_closed() -> None:
    with pytest.raises(SurfaceContractError, match="event-listeners-v1"):
        load_surface_preset("unknown")
