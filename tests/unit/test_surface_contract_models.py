"""Strict custom-surface contract schema and loader tests."""

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner
from pydantic import ValidationError

from fastapi_endpoint_detector.cli import cli
from fastapi_endpoint_detector.models.surface_contract import (
    SurfaceContractDocument,
    SurfaceContractError,
    load_surface_contracts,
)


def _document(*, symbol: str = "framework.Reactor.listen") -> dict[str, object]:
    return {
        "schema_version": 1,
        "preset": {
            "id": "generic-reactor",
            "version": "1",
            "provenance": {"kind": "user", "source": "fixture"},
        },
        "contracts": [
            {
                "id": "listener",
                "registration": {
                    "symbol": symbol,
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
    }


def test_surface_contract_loader_hashes_yaml_json_and_toml(tmp_path: Path) -> None:
    yaml_path = tmp_path / "surfaces.yaml"
    json_path = tmp_path / "surfaces.json"
    toml_path = tmp_path / "surfaces.toml"
    yaml_path.write_text(yaml.safe_dump(_document(), sort_keys=False), encoding="utf-8")
    json_path.write_text(json.dumps(_document()), encoding="utf-8")
    toml_path.write_text(
        "schema_version = 1\n"
        '[preset]\nid = "generic-reactor"\nversion = "1"\n'
        '[preset.provenance]\nkind = "user"\nsource = "fixture"\n'
        '[[contracts]]\nid = "listener"\ncallback_mode = "async"\n'
        '[contracts.registration]\nsymbol = "framework.Reactor.listen"\n'
        'invocation = "instance_method"\nreceiver_type = "framework.Reactor"\n'
        '[contracts.handler]\nkind = "decorated_function"\n'
        '[contracts.surface]\nkind = "reactor"\nid_template = "topic:{resource}"\n'
        '[contracts.surface.resource]\nkind = "argument"\nindex = 0\n',
        encoding="utf-8",
    )

    yaml_loaded = load_surface_contracts(yaml_path)
    json_loaded = load_surface_contracts(json_path)
    toml_loaded = load_surface_contracts(toml_path)

    assert yaml_loaded.config_hash == json_loaded.config_hash == toml_loaded.config_hash
    assert yaml_loaded.preset_hash == json_loaded.preset_hash == toml_loaded.preset_hash
    assert yaml_loaded.contract_hashes == json_loaded.contract_hashes == toml_loaded.contract_hashes
    assert yaml_loaded.raw_hash != json_loaded.raw_hash


def test_surface_contract_hash_is_order_independent() -> None:
    first = SurfaceContractDocument.model_validate(_document())
    payload = _document()
    payload["contracts"] = [
        {
            "id": "task",
            "registration": {
                "symbol": "framework.register",
                "invocation": "function",
            },
            "handler": {"kind": "argument", "index": 1},
            "surface": {
                "kind": "task",
                "id_template": "task:{resource}",
                "resource": {"kind": "argument", "index": 0},
            },
        },
        *payload["contracts"],  # type: ignore[misc]
    ]
    second = SurfaceContractDocument.model_validate(payload)
    payload["contracts"] = list(reversed(payload["contracts"]))  # type: ignore[arg-type]
    reversed_document = SurfaceContractDocument.model_validate(payload)

    assert second.config_hash == reversed_document.config_hash
    assert first.config_hash != second.config_hash


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(schema_version=True),
        lambda value: value.update(extra="forbidden"),
        lambda value: value["contracts"][0]["registration"].update(symbol="listen"),
        lambda value: value["contracts"][0]["registration"].update(
            invocation="constructor", receiver_type=None
        ),
        lambda value: value["contracts"][0]["registration"].update(symbol="*.Reactor.listen"),
        lambda value: value["contracts"][0]["registration"].update(symbol="framework.Reactor.*"),
        lambda value: value["contracts"][0]["surface"].update(id_template="topic:{other}"),
    ],
)
def test_surface_contract_rejects_unsafe_shapes(mutation) -> None:
    payload = _document()
    mutation(payload)
    with pytest.raises(ValidationError):
        SurfaceContractDocument.model_validate(payload)


def test_surface_contract_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.yaml"
    path.write_text("schema_version: 1\nschema_version: 1\n", encoding="utf-8")

    with pytest.raises(SurfaceContractError):
        load_surface_contracts(path)


def test_validate_surface_contracts_cli_reports_hashes(tmp_path: Path) -> None:
    path = tmp_path / "surfaces.json"
    path.write_text(json.dumps(_document()), encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        ["validate-surface-contracts", "--contracts", str(path), "--format", "json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["config_hash"].startswith("sha256:")
    assert payload["contract_hashes"]["listener"].startswith("sha256:")


def test_surface_contract_size_limit(tmp_path: Path) -> None:
    path = tmp_path / "huge.json"
    path.write_bytes(b" " * 1_048_577)

    with pytest.raises(SurfaceContractError, match="1 MiB"):
        load_surface_contracts(path)
