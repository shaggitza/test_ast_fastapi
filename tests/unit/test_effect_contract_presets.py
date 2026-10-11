"""Package-owned exact effect preset validation."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from zipfile import ZipFile

import pytest

from fastapi_endpoint_detector.config import AnalysisConfig, Config
from fastapi_endpoint_detector.models.effect_contract import (
    BUNDLED_EFFECT_PRESETS,
    CompositeEffectSelector,
    EffectContractError,
    EffectSelector,
    ProvenanceKind,
    load_effect_preset,
)

_EXPECTED_PRESET_HASHES = {
    "message-bus-v1": "sha256:875790c0d08b0f6cb2e8681bf56a9066d67bee39225dd7160cb51a447d18ebc3",
    "filesystem-v1": "sha256:066c93f8a569d996bac3f01b3d244f0b7d43a5223050563ad327404e7bad049b",
    "http-clients-v1": "sha256:ab3d88b368db24f4c6c0879c8104105b09f23997997e63dd232856886bca6e2e",
    "mongodb-v1": "sha256:87b8ef6b0ccd3ef4862fb78ffad20cc88ddf55fa1580e286d87ab5c17f0070c9",
    "object-storage-v1": "sha256:1d465f50407ef3d4a168d12646e894fb4d363dc97874e1a3fb140c9bcf7b5523",
    "redis-v1": "sha256:ce681490563300ce01dec68cd42af26c5fe8e06c7d5d45ae652dfce73c531ca2",
    "sqlalchemy-v1": "sha256:132982ba61f04626df531dc80c71ce5d21c12ec583a932d21c220486785c8d04",
}

_EXPECTED_CONTRACT_IDS = {
    "message-bus-v1": {"typed-sqs-send-message", "typed-sqs-send-message-batch"},
    "filesystem-v1": {
        "io-buffered-read",
        "io-buffered-write",
        "io-text-read",
        "io-text-write",
        "pathlib-read-bytes",
        "pathlib-read-text",
        "pathlib-touch",
        "pathlib-mkdir",
        "pathlib-unlink",
        "pathlib-rmdir",
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
        "motor-delete-many",
        "motor-delete-one",
        "motor-find-one",
        "motor-insert-one",
        "motor-insert-many",
        "motor-replace-one",
        "motor-update-one",
        "motor-update-many",
        "pymongo-delete-one",
        "pymongo-find-one",
        "pymongo-insert-one",
        "pymongo-insert-many",
        "pymongo-replace-one",
        "pymongo-update-one",
        "pymongo-update-many",
        "pymongo-delete-many",
    },
    "object-storage-v1": {
        "typed-s3-copy-object",
        "typed-s3-create-bucket",
        "typed-s3-delete-object",
        "typed-s3-delete-bucket",
        "typed-s3-get-object",
        "typed-s3-head-object",
        "typed-s3-list-objects-v2",
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
        "mongodb-v1": "1.3.0",
        "filesystem-v1": "3.0.0",
        "http-clients-v1": "2.0.0",
        "object-storage-v1": "3.0.0",
        "sqlalchemy-v1": "3.0.0",
    }.get(name, "1.0.0")
    expected_revision = {
        "mongodb-v1": "4",
        "filesystem-v1": "3",
        "http-clients-v1": "2",
        "object-storage-v1": "3",
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
                assert (
                    len(parts) >= 4
                    or parts[0] == "_io"
                    or (parts[0] == "httpx" and parts[1] == "_api")
                )
            assert contract.package is not None
            assert contract.package.python is not None or (
                contract.package.distribution is not None and contract.package.version is not None
            )


def test_object_storage_preset_uses_bucket_key_composite_identity() -> None:
    loaded = load_effect_preset("object-storage-v1")

    assert loaded.document.schema_version == 4
    for contract in loaded.document.contracts:
        if contract.id in {
            "typed-s3-list-objects-v2",
            "typed-s3-create-bucket",
            "typed-s3-delete-bucket",
        }:
            assert contract.resource.model_dump(
                mode="json", exclude_none=True, exclude_defaults=True
            ) == {"kind": "keyword", "name": "Bucket"}
            continue
        assert contract.resource.model_dump(
            mode="json", exclude_none=True, exclude_defaults=True
        ) == {
            "kind": "composite",
            "components": [
                {"kind": "keyword", "name": "Bucket"},
                {"kind": "keyword", "name": "Key"},
            ],
        }
    copy = next(
        contract for contract in loaded.document.contracts if contract.id == "typed-s3-copy-object"
    )
    assert copy.value is not None
    assert copy.value.model_dump(mode="json", exclude_none=True, exclude_defaults=True) == {
        "kind": "keyword",
        "name": "CopySource",
    }


def test_mongodb_write_contracts_select_document_arguments() -> None:
    loaded = load_effect_preset("mongodb-v1")
    contracts = {contract.id: contract for contract in loaded.document.contracts}
    expected_value_indexes = {
        "pymongo-insert-many": 0,
        "pymongo-replace-one": 1,
        "pymongo-update-many": 1,
        "pymongo-delete-many": 0,
        "motor-find-one": 0,
        "motor-insert-many": 0,
        "motor-replace-one": 1,
        "motor-update-many": 1,
        "motor-delete-many": 0,
    }
    for contract_id, index in expected_value_indexes.items():
        value = contracts[contract_id].value
        resource = contracts[contract_id].resource
        assert value is not None and value.index == index
        assert isinstance(resource, EffectSelector)
        assert resource.kind.value == "receiver"
    for contract_id in (
        "motor-find-one",
        "motor-insert-many",
        "motor-replace-one",
        "motor-update-many",
        "motor-delete-many",
    ):
        contract = contracts[contract_id]
        assert contract.behavior.async_mode.value == "async"
        assert contract.behavior.timing.value == "await"
        assert contract.package is not None
        assert contract.package.version == "==3.6.0"
        package = contract.package
        baseline_package = contracts["motor-insert-one"].package
        assert package is not None and baseline_package is not None
        assert package.source_hashes == baseline_package.source_hashes


def test_added_rows_have_source_signatures_in_supplied_official_wheels() -> None:  # noqa: PLR0912, PLR0915
    """Inspect wheel source only; synthetic resolver fixtures are tested separately."""
    artifacts = Path("/tmp/gh97-wheel-audit")
    wheels = {
        "httpx": artifacts / "httpx-0.28.1-py3-none-any.whl",
        "pymongo": next(artifacts.glob("pymongo-4.10.1-*.whl"), None),
        "s3": artifacts / "mypy_boto3_s3-1.35.92-py3-none-any.whl",
        "motor": artifacts / "motor-3.6.0-py3-none-any.whl",
    }
    if any(path is None or not path.is_file() for path in wheels.values()):
        pytest.skip("supplied official source wheels are unavailable")

    expected = {
        "httpx": (
            "httpx/_api.py",
            "sha256:aff660b388c8a5c3c92ea2b975b6d26b2aa8fe254c2856b164277ea0e1f12c4b",
            (
                "def get(",
                "def post(",
                "def put(",
                "def patch(",
                "def delete(",
                "def head(",
                "def options(",
            ),
        ),
        "pymongo": (
            "pymongo/synchronous/collection.py",
            "sha256:6615eeda9469b9c401d3441c3fd5a815fa46f16f748dab13e2aca9775fe4139d",
            ("def insert_many(", "def replace_one(", "def update_many(", "def delete_many("),
        ),
        "s3": (
            "mypy_boto3_s3/client.pyi",
            "sha256:62d89319b2079132d342cbb26b0ceb7957e30762e7c1bb57d448c61453871123",
            (
                "def head_object(",
                "def copy_object(",
                "def list_objects_v2(",
                "def create_bucket(",
                "def delete_bucket(",
            ),
        ),
        "motor": (
            "motor/core.pyi",
            "sha256:648fa05c34b81d6510b0cc672ac041e9ebfbb88c7ffbb5573e6d40c8571dcde0",
            (
                "async def find_one(",
                "async def insert_many(",
                "async def replace_one(",
                "async def update_many(",
                "async def delete_many(",
            ),
        ),
    }
    for family, (member, expected_hash, signatures) in expected.items():
        wheel = wheels[family]
        assert wheel is not None
        with ZipFile(wheel) as archive:
            source = archive.read(member)
        assert f"sha256:{hashlib.sha256(source).hexdigest()}" == expected_hash
        text = source.decode("utf-8")
        assert all(signature in text for signature in signatures), family

    # Bind every YAML method row to a declaration owned by the expected source
    # class and verify the selector points at the declared argument position.
    selector_sources = {
        "httpx": (wheels["httpx"], "httpx/_api.py", "httpx._api", None),
        "pymongo": (
            wheels["pymongo"],
            "pymongo/synchronous/collection.py",
            "pymongo.synchronous.collection.Collection",
            None,
        ),
        "s3": (wheels["s3"], "mypy_boto3_s3/client.pyi", "mypy_boto3_s3.client.S3Client", None),
        "motor": (wheels["motor"], "motor/core.pyi", "motor.core.AgnosticCollection", "async"),
    }
    expected_methods: dict[str, dict[str, tuple[str, int | str]]] = {
        "httpx": dict.fromkeys(
            ("get", "post", "put", "patch", "delete", "head", "options"), ("url", 0)
        ),
        "pymongo": {
            "insert_many": ("documents", 0),
            "replace_one": ("replacement", 1),
            "update_many": ("update", 1),
            "delete_many": ("filter", 0),
        },
        "s3": {
            "head_object": ("Bucket", "HeadObjectRequestRequestTypeDef"),
            "copy_object": ("CopySource", "CopyObjectRequestRequestTypeDef"),
            "list_objects_v2": ("Bucket", "ListObjectsV2RequestRequestTypeDef"),
            "create_bucket": ("Bucket", "CreateBucketRequestRequestTypeDef"),
            "delete_bucket": ("Bucket", "DeleteBucketRequestRequestTypeDef"),
        },
        "motor": {
            "find_one": ("filter", 0),
            "insert_many": ("documents", 0),
            "replace_one": ("replacement", 1),
            "update_many": ("update", 1),
            "delete_many": ("filter", 0),
        },
    }
    preset_for_family = {
        "httpx": "http-clients-v1",
        "pymongo": "mongodb-v1",
        "s3": "object-storage-v1",
        "motor": "mongodb-v1",
    }
    for family, (wheel, member, qualified_owner, async_prefix) in selector_sources.items():
        assert wheel is not None
        with ZipFile(wheel) as archive:
            tree = ast.parse(archive.read(member).decode("utf-8"))
        owner_parts = qualified_owner.split(".")
        owner_name = owner_parts[-1]
        class_node = (
            next(
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.ClassDef) and node.name == owner_name
            )
            if owner_name != "_api"
            else None
        )
        declarations = {
            node.name: node
            for node in (class_node.body if class_node else tree.body)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        loaded = load_effect_preset(preset_for_family[family])
        for method, (argument, index) in expected_methods[family].items():
            declaration = declarations[method]
            if async_prefix == "async":
                assert isinstance(declaration, ast.AsyncFunctionDef)
            elif family != "httpx":
                assert isinstance(declaration, ast.FunctionDef)
            args = declaration.args
            positional = [*args.posonlyargs, *args.args]
            if family in {"s3"}:
                unpack = args.kwonlyargs  # request fields are carried by Unpack[TypedDict]
                assert not unpack
                kwargs = args.kwarg
                assert kwargs is not None and isinstance(kwargs.annotation, ast.Subscript)
                typed_dict = kwargs.annotation.slice
                assert isinstance(typed_dict, ast.Name) and typed_dict.id == index
                with ZipFile(wheel) as archive:
                    type_defs_source = archive.read("mypy_boto3_s3/type_defs.pyi")
                assert (
                    f"sha256:{hashlib.sha256(type_defs_source).hexdigest()}"
                    == "sha256:0c4ccd56dccdeaca6deec1c35016a8fd"
                    "087a4c1456670bb3d8ab30acd8faa111"
                )
                type_defs = ast.parse(type_defs_source.decode("utf-8"))
                fields = next(
                    node
                    for node in type_defs.body
                    if isinstance(node, ast.ClassDef) and node.name == index
                )
                assert argument in {
                    node.target.id
                    for node in fields.body
                    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
                }
            else:
                assert isinstance(index, int)
                assert (
                    positional[index + (1 if family in {"pymongo", "motor"} else 0)].arg == argument
                )
            contract_id = (
                f"{family}-api-{method}"
                if family == "httpx"
                else (
                    f"pymongo-{method.replace('_', '-')}"
                    if family == "pymongo"
                    else f"typed-s3-{method.replace('_', '-')}"
                    if family == "s3"
                    else f"motor-{method.replace('_', '-')}"
                )
            )
            if family == "httpx":
                # Candidate HTTPX module rows remain out of the public preset
                # until the exact-symbol mutation guard is independently approved.
                assert argument == "url" and index == 0
                assert contract_id == f"httpx-api-{method.replace('_', '-')}"
                continue
            contract = next(item for item in loaded.document.contracts if item.id == contract_id)
            if family == "s3":
                selectors: list[EffectSelector] = []
                for selected in (contract.resource, contract.value):
                    if selected is None:
                        continue
                    if isinstance(selected, CompositeEffectSelector):
                        selectors.extend(selected.components)
                    else:
                        selectors.append(selected)
                assert isinstance(index, str)
                assert any(
                    selected.kind.value == "keyword" and selected.name == argument
                    for selected in selectors
                )
            else:
                selector = contract.value
                assert isinstance(index, int)
                assert selector is not None and selector.index == index
            assert contract.symbol == f"{qualified_owner}.{method}"

    motor_wheel = wheels["motor"]
    assert motor_wheel is not None
    motor_pins = {
        "motor/core.pyi": "sha256:648fa05c34b81d6510b0cc672ac041e9ebfbb88c7ffbb5573e6d40c8571dcde0",
        "motor/motor_asyncio.pyi": (
            "sha256:6103c4af1c7c81ba3f7bccbfb478f897982eb0e38fef6592a111a22e41eee736"
        ),
        "motor-3.6.0.dist-info/METADATA": (
            "sha256:dce8b401625d673eed6b2c0c66d9d196a13de0649c0788da8b3e2a72edb2965d"
        ),
    }
    with ZipFile(motor_wheel) as archive:
        for member, expected_hash in motor_pins.items():
            assert f"sha256:{hashlib.sha256(archive.read(member)).hexdigest()}" == expected_hash

    loaded = load_effect_preset("mongodb-v1")
    motor_rows = [c for c in loaded.document.contracts if c.id.startswith("motor-")]
    assert len(motor_rows) == 8
    assert all(c.package is not None and c.package.source_hashes for c in motor_rows)
    assert all(c.symbol.startswith("motor.core.AgnosticCollection.") for c in motor_rows)


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


def test_config_selects_typed_sqs_preset() -> None:
    config = Config(analysis=AnalysisConfig(effect_preset="message-bus-v1"))

    loaded = config.load_effect_contract_snapshot()

    assert loaded is not None
    assert loaded.document.preset.id == "typed-sqs-effects"
    assert {contract.id for contract in loaded.document.contracts} == {
        "typed-sqs-send-message",
        "typed-sqs-send-message-batch",
    }
