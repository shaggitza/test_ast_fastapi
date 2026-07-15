from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
import yaml
from pydantic import ValidationError

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.config import AnalysisConfig, Config, load_config
from fastapi_endpoint_detector.models.effect_contract import (
    CallResolutionStatus,
    EffectContractDocument,
    EffectContractError,
    InvocationKind,
    ResolvedCallSite,
    load_effect_contracts,
)

if TYPE_CHECKING:
    from pathlib import Path


def _document(*, contracts: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "schema_version": 1,
        "preset": {
            "id": "example-effects",
            "version": "1.0.0",
            "provenance": {"kind": "user", "source": ".effect-contracts.yaml"},
        },
        "contracts": contracts
        or [
            {
                "id": "redis-set",
                "symbol": "redis.client.Redis.set",
                "invocation": "instance_method",
                "operation": "write",
                "channel": "redis",
                "resource": {"kind": "argument", "index": 0},
                "value": {"kind": "argument", "index": 1},
                "behavior": {"async_mode": "either", "timing": "immediate"},
                "package": {"distribution": "redis", "version": ">=5,<6"},
            }
        ],
    }


def _write_yaml(path: Path, document: dict[str, object]) -> None:
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def test_loads_strict_document_and_emits_semantic_hashes(tmp_path: Path) -> None:
    path = tmp_path / "effects.yaml"
    _write_yaml(path, _document())

    loaded = load_effect_contracts(path)

    assert loaded.document.contracts[0].symbol == "redis.client.Redis.set"
    assert loaded.config_hash.startswith("sha256:")
    assert loaded.preset_hash.startswith("sha256:")
    assert loaded.raw_hash.startswith("sha256:")
    assert loaded.contract_hashes["redis-set"].startswith("sha256:")


def test_semantic_hashes_ignore_yaml_key_and_contract_order(tmp_path: Path) -> None:
    contracts = [
        _document()["contracts"][0],  # type: ignore[index]
        {
            "id": "audit-publish",
            "symbol": "company.audit.publish",
            "invocation": "function",
            "operation": "publish",
            "channel": "message_bus",
        },
    ]
    first = tmp_path / "first.yaml"
    second = tmp_path / "second.json"
    _write_yaml(first, _document(contracts=contracts))
    reordered = _document(contracts=list(reversed(contracts)))
    second.write_text(json.dumps(reordered, sort_keys=True), encoding="utf-8")

    left = load_effect_contracts(first)
    right = load_effect_contracts(second)

    assert left.raw_hash != right.raw_hash
    assert left.config_hash == right.config_hash
    assert left.preset_hash == right.preset_hash
    assert left.contract_hashes == right.contract_hashes


def test_loads_toml_document(tmp_path: Path) -> None:
    path = tmp_path / "effects.toml"
    path.write_text(
        """schema_version = 1
[preset]
id = "toml-effects"
version = "1.0.0"
[preset.provenance]
kind = "user"
source = "effects.toml"
[[contracts]]
id = "publish"
symbol = "company.events.publish"
invocation = "function"
operation = "publish"
channel = "message_bus"
""",
        encoding="utf-8",
    )

    loaded = load_effect_contracts(path)

    assert loaded.document.contracts[0].id == "publish"


def test_semantic_change_changes_hash(tmp_path: Path) -> None:
    first = tmp_path / "first.yaml"
    second = tmp_path / "second.yaml"
    _write_yaml(first, _document())
    changed = _document()
    changed["contracts"][0]["operation"] = "delete"  # type: ignore[index]
    _write_yaml(second, changed)

    assert load_effect_contracts(first).config_hash != load_effect_contracts(second).config_hash


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda data: data.update(schema_version=2), "schema_version"),
        (lambda data: data.update(unknown=True), "Extra inputs"),
        (
            lambda data: data["contracts"][0].update(symbol="redis.client.Redis.*"),
            "exact dotted Python identifier",
        ),
        (
            lambda data: data["contracts"][0].update(symbol="set"),
            "module and callable",
        ),
        (
            lambda data: data["contracts"][0].update(resource={"kind": "argument", "name": "key"}),
            "non-negative index",
        ),
    ],
)
def test_rejects_unsafe_or_malformed_contracts(mutation: object, match: str) -> None:
    data = _document()
    mutation(data)  # type: ignore[operator]

    with pytest.raises(ValidationError, match=match):
        EffectContractDocument.model_validate(data)


@pytest.mark.parametrize("value", [True, 1.0, "1"])
def test_schema_version_is_strict_integer(value: object) -> None:
    data = _document()
    data["schema_version"] = value

    with pytest.raises(ValidationError, match="integer 1"):
        EffectContractDocument.model_validate(data)


@pytest.mark.parametrize("value", [True, 1.0, "1"])
def test_selector_index_is_strict_integer(value: object) -> None:
    data = _document()
    data["contracts"][0]["resource"] = {"kind": "argument", "index": value}  # type: ignore[index]

    with pytest.raises(ValidationError):
        EffectContractDocument.model_validate(data)


def test_rejects_duplicate_ids_and_exact_match_keys() -> None:
    base = _document()["contracts"][0]  # type: ignore[index]
    duplicate_id = _document(contracts=[base, {**base, "symbol": "other.module.call"}])
    with pytest.raises(ValidationError, match="duplicate contract id"):
        EffectContractDocument.model_validate(duplicate_id)

    duplicate_key = _document(contracts=[base, {**base, "id": "other-id"}])
    with pytest.raises(ValidationError, match="duplicate exact symbol"):
        EffectContractDocument.model_validate(duplicate_key)


@pytest.mark.parametrize("field", ["resource", "value"])
@pytest.mark.parametrize("invocation", ["function", "constructor"])
def test_receiver_selector_requires_an_invocation_with_receiver(
    field: str, invocation: str
) -> None:
    data = _document()
    contract = data["contracts"][0]  # type: ignore[index]
    contract["invocation"] = invocation
    contract[field] = {"kind": "receiver"}

    with pytest.raises(ValidationError, match="cannot select a receiver"):
        EffectContractDocument.model_validate(data)


def test_package_applicability_accepts_python_only_and_rejects_partial_distribution() -> None:
    data = _document()
    data["contracts"][0]["package"] = {"python": ">=3.10,<3.14"}  # type: ignore[index]

    document = EffectContractDocument.model_validate(data)

    assert document.contracts[0].package is not None
    assert document.contracts[0].package.python == ">=3.10,<3.14"
    data["contracts"][0]["package"] = {"distribution": "redis"}  # type: ignore[index]
    with pytest.raises(ValidationError, match="provided together"):
        EffectContractDocument.model_validate(data)


def test_method_requires_class_qualified_symbol() -> None:
    data = _document()
    data["contracts"][0]["symbol"] = "client.set"  # type: ignore[index]

    with pytest.raises(ValidationError, match="class-qualified"):
        EffectContractDocument.model_validate(data)


def test_serialized_duplicate_keys_are_rejected(tmp_path: Path) -> None:
    yaml_path = tmp_path / "duplicate.yaml"
    yaml_path.write_text(
        "schema_version: 1\nschema_version: 1\npreset: {}\ncontracts: []\n",
        encoding="utf-8",
    )
    with pytest.raises(EffectContractError, match="duplicate mapping key"):
        load_effect_contracts(yaml_path)

    json_path = tmp_path / "duplicate.json"
    json_path.write_text(
        '{"schema_version":1,"schema_version":1,"preset":{},"contracts":[]}',
        encoding="utf-8",
    )
    with pytest.raises(EffectContractError, match="duplicate mapping key"):
        load_effect_contracts(json_path)


def test_resolved_call_site_requires_exact_identity_and_columns() -> None:
    site = ResolvedCallSite(
        file_path="service.py",
        line=10,
        column=4,
        source_spelling="client.set",
        canonical_symbol="redis.client.Redis.set",
        invocation=InvocationKind.INSTANCE_METHOD,
        status=CallResolutionStatus.EXACT,
        resolver="mypy",
        resolver_version="1.19.1",
        receiver_candidates=("redis.client.Redis",),
    )

    assert site.status == CallResolutionStatus.EXACT
    with pytest.raises(ValidationError, match="class-qualified"):
        ResolvedCallSite(
            file_path="service.py",
            line=10,
            column=4,
            source_spelling="client.set",
            canonical_symbol="client.set",
            invocation=InvocationKind.INSTANCE_METHOD,
            status=CallResolutionStatus.EXACT,
            resolver="mypy",
            resolver_version="1.19.1",
        )
    with pytest.raises(ValidationError, match="provided together"):
        ResolvedCallSite.model_validate({**site.model_dump(), "end_column": 9})
    with pytest.raises(ValidationError, match="cannot precede"):
        ResolvedCallSite.model_validate({**site.model_dump(), "end_line": 9, "end_column": 1})
    with pytest.raises(ValidationError, match="must not be blank"):
        ResolvedCallSite.model_validate({**site.model_dump(), "file_path": "  "})
    with pytest.raises(ValidationError, match="reason code"):
        ResolvedCallSite(
            file_path="service.py",
            line=10,
            column=4,
            source_spelling="client.set",
            status=CallResolutionStatus.AMBIGUOUS,
            resolver="mypy",
            resolver_version="1.19.1",
        )


def test_config_resolves_relative_contract_path_and_validates_document(tmp_path: Path) -> None:
    contracts = tmp_path / "effects.yaml"
    _write_yaml(contracts, _document())
    config_path = tmp_path / "detector.yaml"
    config_path.write_text("analysis:\n  effect_contracts: effects.yaml\n", encoding="utf-8")

    config = load_config(config_path)

    assert config.analysis.effect_contracts == contracts.resolve()


def test_config_rejects_duplicate_serialized_keys(tmp_path: Path) -> None:
    config_path = tmp_path / "detector.yaml"
    config_path.write_text(
        "analysis: {track_transitive: true}\nanalysis: {track_transitive: false}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate mapping key"):
        load_config(config_path)


def test_config_rejects_unknown_nested_keys(tmp_path: Path) -> None:
    config_path = tmp_path / "detector.yaml"
    config_path.write_text("integrations:\n  use_mypy: true\n  typo: true\n", encoding="utf-8")

    with pytest.raises(ValueError, match="typo"):
        load_config(config_path)


def test_programmatic_analysis_rejects_missing_contract_document(tmp_path: Path) -> None:
    app = tmp_path / "app.py"
    app.write_text("value = 1\n", encoding="utf-8")
    config = Config(analysis=AnalysisConfig(effect_contracts=tmp_path / "effects.yaml"))

    with pytest.raises(EffectContractError, match="file not found"):
        ChangeMapper(app_path=app, config=config, secure_ast=True)


def test_loader_rejects_unsupported_extension_and_large_documents(tmp_path: Path) -> None:
    unsupported = tmp_path / "effects.txt"
    unsupported.write_text("{}", encoding="utf-8")
    with pytest.raises(EffectContractError, match="YAML, JSON, or TOML"):
        load_effect_contracts(unsupported)

    large = tmp_path / "effects.yaml"
    large.write_bytes(b"x" * (1_048_576 + 1))
    with pytest.raises(EffectContractError, match="1 MiB"):
        load_effect_contracts(large)
