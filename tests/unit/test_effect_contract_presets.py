"""Package-owned exact effect preset validation."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from fastapi_endpoint_detector.config import AnalysisConfig, Config
from fastapi_endpoint_detector.models.effect_contract import (
    BUNDLED_EFFECT_PRESETS,
    AsyncMode,
    EffectContractError,
    EffectTiming,
    InvocationKind,
    ProvenanceKind,
    SelectorKind,
    load_effect_preset,
)

if TYPE_CHECKING:
    from pathlib import Path


_EXPECTED_PRESET_HASHES = {
    "filesystem-v1": "sha256:8e09b0a197a523b701bd18ce042b72bf8e8d5cc5c0741d18e7c1c61937712c40",
    "http-clients-v1": "sha256:c1f6bcb56e06525f20e2eac5a68c9bc5812c281c054209fb6feb3c7df63cc890",
    "message-bus-v1": "sha256:05c2d745da13fc39984d20b6cd260221eeac40ba7049a492cef6979488ac81a1",
    "mongodb-v1": "sha256:1541057fa430ee8ced171b379aa9dab1f4007156fd9b8632784c0ccdfd2f2032",
    "object-storage-v1": "sha256:e105008879ac0fdccec5dd03b0eb9a031749539713b617de089d8d82a796683c",
    "sqlalchemy-v1": "sha256:132982ba61f04626df531dc80c71ce5d21c12ec583a932d21c220486785c8d04",
}

_EXPECTED_CONTRACT_IDS = {
    "filesystem-v1": {
        "io-buffered-read",
        "io-buffered-write",
        "io-text-read",
        "io-text-write",
        "os-makedirs",
        "os-mkdir",
        "os-remove",
        "os-rename",
        "os-replace",
        "os-rmdir",
        "os-unlink",
        "pathlib-mkdir",
        "pathlib-read-bytes",
        "pathlib-read-text",
        "pathlib-rename",
        "pathlib-replace",
        "pathlib-rmdir",
        "pathlib-touch",
        "pathlib-unlink",
        "pathlib-write-bytes",
        "pathlib-write-text",
        "shutil-copy",
        "shutil-copy2",
        "shutil-copyfile",
        "shutil-move",
        "shutil-rmtree",
    },
    "http-clients-v1": {
        "aiohttp-session-delete",
        "aiohttp-session-get",
        "aiohttp-session-head",
        "aiohttp-session-options",
        "aiohttp-session-patch",
        "aiohttp-session-post",
        "aiohttp-session-put",
        "httpx-async-client-delete",
        "httpx-async-client-get",
        "httpx-async-client-head",
        "httpx-async-client-options",
        "httpx-async-client-patch",
        "httpx-async-client-post",
        "httpx-async-client-put",
        "httpx-client-delete",
        "httpx-client-get",
        "httpx-client-head",
        "httpx-client-options",
        "httpx-client-patch",
        "httpx-client-post",
        "httpx-client-put",
        "httpx-delete",
        "httpx-get",
        "httpx-head",
        "httpx-options",
        "httpx-patch",
        "httpx-post",
        "httpx-put",
        "requests-api-delete",
        "requests-api-get",
        "requests-api-head",
        "requests-api-options",
        "requests-api-patch",
        "requests-api-post",
        "requests-api-put",
        "requests-session-delete",
        "requests-session-get",
        "requests-session-head",
        "requests-session-options",
        "requests-session-patch",
        "requests-session-post",
        "requests-session-put",
    },
    "message-bus-v1": {"confluent-kafka-produce"},
    "mongodb-v1": {
        "motor-delete-many",
        "motor-delete-one",
        "motor-find-one",
        "motor-insert-many",
        "motor-insert-one",
        "motor-replace-one",
        "motor-update-many",
        "motor-update-one",
        "pymongo-delete-many",
        "pymongo-delete-one",
        "pymongo-find-one",
        "pymongo-insert-many",
        "pymongo-insert-one",
        "pymongo-replace-one",
        "pymongo-update-many",
        "pymongo-update-one",
    },
    "object-storage-v1": {
        "typed-s3-copy-object",
        "typed-s3-create-bucket",
        "typed-s3-delete-bucket",
        "typed-s3-delete-object",
        "typed-s3-get-object",
        "typed-s3-head-object",
        "typed-s3-list-objects-v2",
        "typed-s3-put-object",
    },
    "sqlalchemy-v1": {
        "sqlalchemy-async-session-add",
        "sqlalchemy-async-session-add-all",
        "sqlalchemy-async-session-begin",
        "sqlalchemy-async-session-begin-nested",
        "sqlalchemy-async-session-commit",
        "sqlalchemy-async-session-delete",
        "sqlalchemy-async-session-flush",
        "sqlalchemy-async-session-merge",
        "sqlalchemy-async-session-rollback",
        "sqlalchemy-session-add",
        "sqlalchemy-session-add-all",
        "sqlalchemy-session-begin",
        "sqlalchemy-session-begin-nested",
        "sqlalchemy-session-commit",
        "sqlalchemy-session-delete",
        "sqlalchemy-session-flush",
        "sqlalchemy-session-merge",
        "sqlalchemy-session-rollback",
    },
}


@pytest.mark.parametrize("name", sorted(BUNDLED_EFFECT_PRESETS))
def test_bundled_effect_presets_are_strict_versioned_snapshots(name: str) -> None:
    loaded = load_effect_preset(name)

    assert loaded.source_path == BUNDLED_EFFECT_PRESETS[name].resolve()
    expected_version = {
        "filesystem-v1": "3.0.0",
        "http-clients-v1": "3.0.0",
        "mongodb-v1": "2.0.0",
        "object-storage-v1": "2.0.0",
        "sqlalchemy-v1": "3.0.0",
    }.get(name, "1.0.0")
    expected_revision = {
        "filesystem-v1": "3",
        "http-clients-v1": "3",
        "mongodb-v1": "2",
        "object-storage-v1": "2",
        "sqlalchemy-v1": "3",
    }.get(name, "1")
    assert loaded.document.preset.version == expected_version
    assert loaded.document.preset.provenance.kind == ProvenanceKind.PRESET
    assert loaded.document.preset.provenance.revision == expected_revision
    assert {contract.id for contract in loaded.document.contracts} == _EXPECTED_CONTRACT_IDS[name]
    assert set(loaded.contract_hashes) == _EXPECTED_CONTRACT_IDS[name]
    assert loaded.raw_hash.startswith("sha256:")
    assert loaded.config_hash.startswith("sha256:")
    assert loaded.preset_hash == _EXPECTED_PRESET_HASHES[name]


def test_presets_never_contain_bare_or_generic_method_symbols() -> None:
    forbidden = {"get", "set", "read", "write", "send", "publish", "request"}

    for name in BUNDLED_EFFECT_PRESETS:
        loaded = load_effect_preset(name)
        for contract in loaded.document.contracts:
            parts = contract.symbol.split(".")
            assert len(parts) >= 2
            assert contract.symbol not in forbidden
            if contract.invocation != InvocationKind.FUNCTION:
                assert len(parts) >= 3
            if parts[-1] in forbidden and contract.invocation != InvocationKind.FUNCTION:
                assert len(parts) >= 4 or parts[0] == "_io"
            assert contract.package is not None
            assert contract.package.python is not None or (
                contract.package.distribution is not None and contract.package.version is not None
            )


def test_http_client_preset_declares_exact_methods_for_each_supported_client() -> None:
    loaded = load_effect_preset("http-clients-v1")
    methods_by_class: dict[str, set[str]] = {}
    for contract in loaded.document.contracts:
        class_symbol = contract.symbol.rsplit(".", maxsplit=1)[0]
        assert contract.http_method is not None
        methods_by_class.setdefault(class_symbol, set()).add(contract.http_method)

    expected = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    assert methods_by_class == {
        "aiohttp.client.ClientSession": expected,
        "httpx._api": expected,
        "httpx._client.AsyncClient": expected,
        "httpx._client.Client": expected,
        "requests.api": expected,
        "requests.sessions.Session": expected,
    }


def test_dynamic_or_generic_surfaces_are_not_preset_contracts() -> None:
    symbols = {
        contract.symbol
        for name in BUNDLED_EFFECT_PRESETS
        for contract in load_effect_preset(name).document.contracts
    }

    assert symbols.isdisjoint(
        {
            "builtins.open",  # mode-dependent until a predicate schema exists
            "requests.api.request",  # method argument is not modeled by schema v3
            "httpx.request",
            "httpx.get",  # public spelling resolves to the declaration owner below the facade
            "aiohttp.client.request",
            "boto3.client",
            "redis.commands.core.BasicKeyCommands.get",  # shared sync/async owner
            "redis.Redis.get",
            "motor.motor_asyncio.AsyncIOMotorCollection.find",
            "pymongo.collection.Collection.update_one",
            "pymongo.synchronous.collection.Collection.find",
            "redis.commands.core.BasicKeyCommands.incr",
            "aiokafka.producer.producer.AIOKafkaProducer.send_and_wait",
            "kafka.producer.kafka.KafkaProducer.send",
            "pika.channel.Channel.basic_publish",
            "kombu.messaging.Producer.publish",
        }
    )


def test_receiver_http_clients_abstain_from_incomplete_url_identity() -> None:
    loaded = load_effect_preset("http-clients-v1")
    contracts = {contract.id: contract for contract in loaded.document.contracts}

    receiver_ids = {
        contract_id
        for contract_id in contracts
        if contract_id.startswith(("httpx-client-", "httpx-async-client-", "aiohttp-session-"))
    }
    assert receiver_ids
    assert all(contracts[item].resource.kind == SelectorKind.NONE for item in receiver_ids)
    assert contracts["httpx-get"].resource.kind == SelectorKind.ARGUMENT
    assert contracts["requests-api-get"].resource.kind == SelectorKind.ARGUMENT
    assert contracts["requests-api-get"].package is not None
    assert contracts["requests-api-get"].package.version == ">=2.34,<3"


def test_object_storage_abstains_from_false_key_only_object_identity() -> None:
    loaded = load_effect_preset("object-storage-v1")
    object_contracts = {
        contract.id: contract
        for contract in loaded.document.contracts
        if contract.id
        in {
            "typed-s3-copy-object",
            "typed-s3-delete-object",
            "typed-s3-get-object",
            "typed-s3-head-object",
            "typed-s3-put-object",
        }
    }

    assert object_contracts
    assert all(
        contract.resource.kind == SelectorKind.NONE for contract in object_contracts.values()
    )
    assert all(contract.resource.name is None for contract in object_contracts.values())


def test_async_presets_declare_only_supported_effect_timing() -> None:
    mongodb = load_effect_preset("mongodb-v1")
    motor = {
        contract.id: contract
        for contract in mongodb.document.contracts
        if contract.id.startswith("motor-")
    }
    assert all(contract.behavior.async_mode == AsyncMode.ASYNC for contract in motor.values())
    assert all(contract.behavior.timing == EffectTiming.AWAIT for contract in motor.values())

    http = load_effect_preset("http-clients-v1")
    aiohttp = [
        contract for contract in http.document.contracts if contract.id.startswith("aiohttp-")
    ]
    assert aiohttp
    assert all(contract.behavior.async_mode == AsyncMode.ASYNC for contract in aiohttp)
    assert all(contract.behavior.timing == EffectTiming.AWAIT for contract in aiohttp)

    messages = load_effect_preset("message-bus-v1")
    assert len(messages.document.contracts) == 1
    confluent = messages.document.contracts[0]
    assert confluent.id == "confluent-kafka-produce"
    assert confluent.symbol == "confluent_kafka.cimpl.Producer.produce"
    assert confluent.behavior.async_mode == AsyncMode.SYNC
    assert confluent.behavior.timing == EffectTiming.STAGED
    assert confluent.package is not None
    assert confluent.package.version == ">=2.13,<3"


def test_sqlalchemy_preset_declares_exact_transaction_and_savepoint_scopes() -> None:
    loaded = load_effect_preset("sqlalchemy-v1")
    scopes = {
        contract.id: (
            contract.behavior.transaction_scope.value
            if contract.behavior.transaction_scope is not None
            else None
        )
        for contract in loaded.document.contracts
        if contract.operation.value == "begin"
    }

    assert scopes == {
        "sqlalchemy-session-begin": "transaction",
        "sqlalchemy-session-begin-nested": "savepoint",
        "sqlalchemy-async-session-begin": "transaction",
        "sqlalchemy-async-session-begin-nested": "savepoint",
    }
    exits = {
        contract.id: (
            contract.behavior.context_exit.value
            if contract.behavior.context_exit is not None
            else None
        )
        for contract in loaded.document.contracts
        if contract.operation.value == "begin"
    }
    assert exits == {
        "sqlalchemy-session-begin": "transaction_commit_rollback",
        "sqlalchemy-session-begin-nested": "savepoint_release_rollback",
        "sqlalchemy-async-session-begin": "transaction_commit_rollback",
        "sqlalchemy-async-session-begin-nested": "savepoint_release_rollback",
    }


def test_unknown_effect_preset_fails_closed() -> None:
    with pytest.raises(EffectContractError, match="unknown effect preset"):
        load_effect_preset("latest")


def test_effect_preset_and_user_document_are_mutually_exclusive(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        AnalysisConfig(
            effect_contracts=tmp_path / "effects.yaml",
            effect_preset="filesystem-v1",
        )


def test_config_loads_effect_preset_once() -> None:
    config = Config(analysis=AnalysisConfig(effect_preset="filesystem-v1"))

    first = config.load_effect_contract_snapshot()

    assert first is config.load_effect_contract_snapshot()
    assert first is not None
    assert first.document.preset.id == "stdlib-filesystem-effects"
