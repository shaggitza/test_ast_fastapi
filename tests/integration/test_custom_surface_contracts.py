"""End-to-end custom surface inventory and impact analysis."""

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper, ChangeMapperError
from fastapi_endpoint_detector.cli import cli
from fastapi_endpoint_detector.config import load_config
from fastapi_endpoint_detector.models.report import ConfidenceLevel


def _project(tmp_path: Path) -> tuple[Path, Path]:
    app = tmp_path / "app"
    app.mkdir()
    main = app / "main.py"
    main.write_text(
        "from framework import Reactor\n"
        "reactor = Reactor()\n\n"
        "@reactor.listen('orders')\n"
        "async def process_order():\n"
        "    return 1\n",
        encoding="utf-8",
    )
    contracts = tmp_path / "surfaces.yaml"
    contracts.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "preset": {
                    "id": "reactor",
                    "version": "1",
                    "provenance": {"kind": "user", "source": "integration"},
                },
                "contracts": [
                    {
                        "id": "listen",
                        "registration": {
                            "symbol": "framework.Reactor.listen",
                            "invocation": "instance_method",
                            "receiver_type": "framework.Reactor",
                        },
                        "handler": {"kind": "decorated_function"},
                        "surface": {
                            "kind": "reactor",
                            "id_template": "topic:{resource}",
                            "resource": {"kind": "argument", "index": 0},
                        },
                        "callback_mode": "async",
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    config = tmp_path / ".endpoint-detector.yaml"
    config.write_text("analysis:\n  surface_contracts: surfaces.yaml\n", encoding="utf-8")
    diff = tmp_path / "change.diff"
    diff.write_text(
        "diff --git a/main.py b/main.py\n"
        "--- a/main.py\n"
        "+++ b/main.py\n"
        "@@ -4,3 +4,3 @@\n"
        " @reactor.listen('orders')\n"
        " async def process_order():\n"
        "-    return 1\n"
        "+    return 2\n",
        encoding="utf-8",
    )
    return config, diff


def test_config_relative_custom_surface_reaches_changed_handler(tmp_path: Path) -> None:
    config_path, diff = _project(tmp_path)
    config = load_config(config_path)
    first_snapshot = config.load_surface_contract_snapshot()
    assert first_snapshot is not None

    mapper = ChangeMapper(
        app_path=tmp_path / "app",
        config=config,
        secure_ast=True,
        use_cache=False,
    )
    report = mapper.analyze_diff(diff)

    assert config.load_surface_contract_snapshot() is first_snapshot
    assert [item.endpoint.identifier for item in report.candidate_endpoints] == [
        "REACTOR topic:orders"
    ]
    endpoint = report.candidate_endpoints[0].endpoint
    assert endpoint.surface is not None
    assert endpoint.surface.contract_id == "listen"
    assert endpoint.surface.config_hash == first_snapshot.config_hash
    assert report.total_endpoints == 1


def test_custom_surfaces_are_present_in_scip_target_and_baseline_registries(
    tmp_path: Path,
) -> None:
    config_path, _diff = _project(tmp_path)
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    (baseline / "main.py").write_text(
        (tmp_path / "app" / "main.py").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    mapper = ChangeMapper(
        app_path=tmp_path / "app",
        baseline_app_path=baseline,
        config=load_config(config_path),
        secure_ast=True,
        use_scip=True,
    )

    assert [item.identifier for item in mapper.registry] == ["REACTOR topic:orders"]
    assert [item.identifier for item in mapper.baseline_registry] == ["REACTOR topic:orders"]


def test_custom_surface_cache_round_trip_preserves_candidates(tmp_path: Path) -> None:
    config_path, diff = _project(tmp_path)
    first = ChangeMapper(
        app_path=tmp_path / "app",
        config=load_config(config_path),
        secure_ast=True,
        use_cache=True,
    ).analyze_diff(diff)
    second = ChangeMapper(
        app_path=tmp_path / "app",
        config=load_config(config_path),
        secure_ast=True,
        use_cache=True,
    ).analyze_diff(diff)

    assert second.candidate_endpoints == first.candidate_endpoints


def test_list_endpoints_cli_includes_configured_custom_surfaces(tmp_path: Path) -> None:
    config_path, _diff = _project(tmp_path)

    result = CliRunner().invoke(
        cli,
        [
            "--config",
            str(config_path),
            "list",
            "--app",
            str(tmp_path / "app"),
            "--secure-ast",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    start = result.output.find("{")
    payload = json.loads(result.output[start:])
    assert payload["endpoints"][0]["surface"]["contract_id"] == "listen"


def test_bundled_event_listener_preset_reaches_changed_handler(tmp_path: Path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "main.py").write_text(
        "from faststream.rabbit import RabbitBroker\n"
        "broker = RabbitBroker()\n\n"
        "@broker.subscriber('orders')\n"
        "async def process_order():\n"
        "    return 2\n",
        encoding="utf-8",
    )
    config_path = tmp_path / ".endpoint-detector.yaml"
    config_path.write_text(
        "analysis:\n  surface_preset: event-listeners-v1\n",
        encoding="utf-8",
    )
    diff = tmp_path / "change.diff"
    diff.write_text(
        "diff --git a/main.py b/main.py\n"
        "--- a/main.py\n"
        "+++ b/main.py\n"
        "@@ -4,3 +4,3 @@\n"
        " @broker.subscriber('orders')\n"
        " async def process_order():\n"
        "-    return 1\n"
        "+    return 2\n",
        encoding="utf-8",
    )

    report = ChangeMapper(
        app_path=app,
        config=load_config(config_path),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    assert [candidate.endpoint.identifier for candidate in report.candidate_endpoints] == [
        "RABBITMQ queue:orders"
    ]
    surface = report.candidate_endpoints[0].endpoint.surface
    assert surface is not None
    assert surface.contract_id == "faststream-rabbit-subscriber"
    assert surface.resource == "orders"


def test_conditional_aio_pika_consumer_is_capped_low(tmp_path: Path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "main.py").write_text(
        "from aio_pika.queue import Queue\n"
        "queue = Queue()\n\n"
        "async def process_order(message):\n"
        "    return 2\n\n"
        "queue.consume(process_order)\n",
        encoding="utf-8",
    )
    config_path = tmp_path / ".endpoint-detector.yaml"
    config_path.write_text(
        "analysis:\n  surface_preset: event-listeners-v1\n",
        encoding="utf-8",
    )
    diff = tmp_path / "change.diff"
    diff.write_text(
        "diff --git a/main.py b/main.py\n"
        "--- a/main.py\n"
        "+++ b/main.py\n"
        "@@ -4,2 +4,2 @@\n"
        " async def process_order(message):\n"
        "-    return 1\n"
        "+    return 2\n",
        encoding="utf-8",
    )

    report = ChangeMapper(
        app_path=app,
        config=load_config(config_path),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    assert len(report.candidate_endpoints) == 1
    candidate = report.candidate_endpoints[0]
    assert candidate.endpoint.identifier == "RABBITMQ handler:process_order"
    assert candidate.confidence == ConfidenceLevel.LOW


def test_custom_surfaces_require_secure_ast(tmp_path: Path) -> None:
    config_path, _diff = _project(tmp_path)

    try:
        ChangeMapper(app_path=tmp_path / "app", config=load_config(config_path))
    except ChangeMapperError as exc:
        assert "secure_ast" in str(exc)
    else:
        raise AssertionError("custom surfaces must reject runtime discovery")
