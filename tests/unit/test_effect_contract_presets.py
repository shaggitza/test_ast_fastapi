"""Package-owned exact effect preset validation."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from fastapi_endpoint_detector.config import AnalysisConfig, Config
from fastapi_endpoint_detector.models.effect_contract import (
    BUNDLED_EFFECT_PRESETS,
    EffectContractError,
    ProvenanceKind,
    load_effect_preset,
)

if TYPE_CHECKING:
    from pathlib import Path


_EXPECTED_PRESET_HASHES = {
    "filesystem-v1": "sha256:5acc35da9d989ccafda0960090efefbbaa52ca5b70894882c24c4bf1355c2b96",
    "http-clients-v1": "sha256:ab3d88b368db24f4c6c0879c8104105b09f23997997e63dd232856886bca6e2e",
    "mongodb-v1": "sha256:7e0f41e452ac61b7340f02215963e8aa765333988b67d441b7aece9dfa53191c",
    "object-storage-v1": "sha256:53a918b63f7813f54a23b502c68dfea40246d2a8a465275fb221bce018420996",
    "redis-v1": "sha256:ce681490563300ce01dec68cd42af26c5fe8e06c7d5d45ae652dfce73c531ca2",
    "sqlalchemy-v1": "sha256:132982ba61f04626df531dc80c71ce5d21c12ec583a932d21c220486785c8d04",
}

_EXPECTED_CONTRACT_IDS = {
    "filesystem-v1": {
        "io-buffered-read",
        "io-buffered-write",
        "io-text-read",
        "io-text-write",
        "pathlib-read-bytes",
        "pathlib-read-text",
        "pathlib-write-bytes",
        "pathlib-write-text",
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
        "requests-session-delete",
        "requests-session-get",
        "requests-session-head",
        "requests-session-options",
        "requests-session-patch",
        "requests-session-post",
        "requests-session-put",
    },
    "mongodb-v1": {
        "pymongo-delete-one",
        "pymongo-find-one",
        "pymongo-insert-one",
        "pymongo-update-one",
    },
    "object-storage-v1": {
        "typed-s3-delete-object",
        "typed-s3-get-object",
        "typed-s3-put-object",
    },
    "redis-v1": {"redis-delete", "redis-get", "redis-publish", "redis-set"},
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
        "filesystem-v1": "2.0.0",
        "http-clients-v1": "2.0.0",
        "sqlalchemy-v1": "3.0.0",
    }.get(name, "1.0.0")
    expected_revision = {
        "filesystem-v1": "2",
        "http-clients-v1": "2",
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
            assert len(parts) >= 3
            assert contract.symbol not in forbidden
            if parts[-1] in forbidden:
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
        "httpx._client.AsyncClient": expected,
        "httpx._client.Client": expected,
        "requests.sessions.Session": expected,
    }


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
            effect_preset="redis-v1",
        )


def test_config_loads_effect_preset_once() -> None:
    config = Config(analysis=AnalysisConfig(effect_preset="filesystem-v1"))

    first = config.load_effect_contract_snapshot()

    assert first is config.load_effect_contract_snapshot()
    assert first is not None
    assert first.document.preset.id == "stdlib-filesystem-effects"
