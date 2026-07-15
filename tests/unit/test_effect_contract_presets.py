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
    "filesystem-v1": "sha256:50349f86ac9ba5d5e447b16e10b30803ed7f8abb978fe911772b42eb31701eb1",
    "http-clients-v1": "sha256:1b8e1ab42990da2a25df798eb9921410f676c92b3d3305aea73922c5086731a7",
    "mongodb-v1": "sha256:7e0f41e452ac61b7340f02215963e8aa765333988b67d441b7aece9dfa53191c",
    "object-storage-v1": "sha256:53a918b63f7813f54a23b502c68dfea40246d2a8a465275fb221bce018420996",
    "redis-v1": "sha256:ce681490563300ce01dec68cd42af26c5fe8e06c7d5d45ae652dfce73c531ca2",
    "sqlalchemy-v1": "sha256:139fe41076b28730e8d24395ba684f421e8698bcf4d14a037e40064c9a69bf9e",
}

_EXPECTED_CONTRACT_IDS = {
    "filesystem-v1": {
        "pathlib-read-bytes",
        "pathlib-read-text",
        "pathlib-write-bytes",
        "pathlib-write-text",
    },
    "http-clients-v1": {
        "aiohttp-session-get",
        "httpx-async-client-get",
        "httpx-client-get",
        "requests-session-get",
        "requests-session-post",
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
    assert loaded.document.preset.version == "1.0.0"
    assert loaded.document.preset.provenance.kind == ProvenanceKind.PRESET
    assert loaded.document.preset.provenance.revision == "1"
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
                assert len(parts) >= 4
            assert contract.package is not None
            assert contract.package.python is not None or (
                contract.package.distribution is not None and contract.package.version is not None
            )


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
