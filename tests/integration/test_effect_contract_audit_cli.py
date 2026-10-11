from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml
from benchmarks.gh97_motor_binding.run import (
    ARTIFACTS as MOTOR_PROBE_ARTIFACTS,
)
from benchmarks.gh97_motor_binding.run import (
    bounded_python_sources,
    verify_artifact_hash,
)
from click.testing import CliRunner

from fastapi_endpoint_detector.cli import cli


def _project(root: Path) -> tuple[Path, Path]:
    (root / "helpers.py").write_text(
        "def emit(resource: str) -> int:\n    return 1\n",
        encoding="utf-8",
    )
    (root / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from helpers import emit\n\n"
        "app = FastAPI()\n\n"
        "@app.get('/')\n"
        "def handler() -> int:\n"
        "    return emit('orders')\n",
        encoding="utf-8",
    )
    contracts = root / "effects.yaml"
    contracts.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "preset": {
                    "id": "cli-audit",
                    "version": "1.0.0",
                    "provenance": {"kind": "user", "source": "effects.yaml"},
                },
                "contracts": [
                    {
                        "id": "emit",
                        "symbol": "helpers.emit",
                        "invocation": "function",
                        "operation": "publish",
                        "channel": "message_bus",
                        "resource": {"kind": "argument", "index": 0},
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return root / "main.py", contracts


def test_validate_effect_preset_and_reject_dual_cli_sources(tmp_path: Path) -> None:
    _app, contracts = _project(tmp_path)
    runner = CliRunner()

    valid = runner.invoke(
        cli,
        ["validate-effect-contracts", "--preset", "redis-v1", "--format", "json"],
    )
    conflict = runner.invoke(
        cli,
        [
            "validate-effect-contracts",
            "--preset",
            "redis-v1",
            "--contracts",
            str(contracts),
        ],
    )

    assert valid.exit_code == 0, valid.output
    assert json.loads(valid.output)["preset"]["id"] == "redis-py-effects"
    assert conflict.exit_code != 0
    assert "exactly one" in conflict.output


def test_filesystem_preset_matches_exact_sink_through_wrapper(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from pathlib import Path\n"
        "from typing import Any\n"
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "def store() -> None:\n"
        "    Path('result.txt').write_text('value')\n\n"
        "@app.get('/')\n"
        "def handler() -> None:\n"
        "    store()\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        cli,
        [
            "audit-effect-contracts",
            "--app",
            str(tmp_path),
            "--preset",
            "filesystem-v1",
            "--format",
            "json",
            "--no-cache",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    matches = [item for item in data["occurrences"] if item["audit_status"] == "matched"]
    assert [(item["canonical_symbol"], item["contract_id"]) for item in matches] == [
        ("pathlib.Path.write_text", "pathlib-write-text")
    ]
    expected_hash = f"sha256:{hashlib.sha256(b'result.txt').hexdigest()}"
    expected_identity = {
        "schema_version": 1,
        "status": "exact",
        "value_hashes": [expected_hash],
    }
    assert matches[0]["receiver_origin"] == expected_identity
    assert matches[0]["resource_identity"] == expected_identity


def test_filesystem_mutation_rows_match_only_exact_pathlib_symbols(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from pathlib import Path\n"
        "from typing import Any\n"
        "from fastapi import FastAPI\n\n"
        "class ForeignPath:\n"
        "    def touch(self) -> None: ...\n"
        "    def mkdir(self) -> None: ...\n"
        "    def unlink(self) -> None: ...\n"
        "    def rmdir(self) -> None: ...\n\n"
        "app = FastAPI()\n"
        "@app.get('/')\n"
        "def handler() -> None:\n"
        "    path = Path('data/item')\n"
        "    path.touch()\n"
        "    path.mkdir()\n"
        "    path.unlink()\n"
        "    path.rmdir()\n"
        "    foreign = ForeignPath()\n"
        "    foreign.touch()\n"
        "    foreign.mkdir()\n"
        "    foreign.unlink()\n"
        "    foreign.rmdir()\n"
        "    dynamic: Any = object()\n"
        "    dynamic.touch()\n"
        "    dynamic.mkdir()\n"
        "    dynamic.unlink()\n"
        "    dynamic.rmdir()\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        cli,
        [
            "audit-effect-contracts",
            "--app",
            str(tmp_path),
            "--preset",
            "filesystem-v1",
            "--format",
            "json",
            "--no-cache",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    matched = [item for item in data["occurrences"] if item["audit_status"] == "matched"]
    assert {item["contract_id"] for item in matched} == {
        "pathlib-touch",
        "pathlib-mkdir",
        "pathlib-unlink",
        "pathlib-rmdir",
    }
    assert len(matched) == 4
    assert all(item["canonical_symbol"].startswith("pathlib.Path.") for item in matched)


def test_added_non_http_typed_preset_rows_resolve_from_public_stub_fixtures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Synthetic stubs exercise selectors; they do not claim upstream provenance."""
    stubs = tmp_path / "stubs"
    (stubs / "pymongo" / "synchronous").mkdir(parents=True)
    (stubs / "pymongo" / "__init__.pyi").write_text("", encoding="utf-8")
    (stubs / "pymongo" / "synchronous" / "__init__.pyi").write_text("", encoding="utf-8")
    (stubs / "pymongo" / "synchronous" / "collection.pyi").write_text(
        "class Collection:\n"
        "    def update_many(self, filter: object, update: object) -> object: ...\n",
        encoding="utf-8",
    )
    (stubs / "mypy_boto3_s3").mkdir(parents=True)
    (stubs / "mypy_boto3_s3" / "__init__.pyi").write_text("", encoding="utf-8")
    (stubs / "mypy_boto3_s3" / "client.pyi").write_text(
        "class S3Client:\n"
        "    def put_object(self, *, Bucket: str, Key: str, Body: bytes) -> object: ...\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MYPYPATH", str(stubs))

    cases = (
        (
            "mongodb-v1",
            "from typing import Any\n"
            "from pymongo.synchronous.collection import Collection\n"
            "class Foreign:\n"
            "    def update_many(self, filter: object, update: object) -> object: ...\n"
            "def handler(collection: Collection) -> None:\n"
            "    collection.update_many({}, {'$set': {'ok': True}})\n"
            "    Foreign().update_many({}, {})\n"
            "    dynamic: Any = object()\n"
            "    dynamic.update_many({}, {})\n",
            {"pymongo-update-many"},
        ),
        (
            "object-storage-v1",
            "from typing import Any\n"
            "from mypy_boto3_s3.client import S3Client\n"
            "class Foreign:\n"
            "    def put_object(self, *, Bucket: str, Key: str, Body: bytes) -> object: ...\n"
            "def handler(client: S3Client) -> None:\n"
            "    client.put_object(Bucket='exact', Key='item', Body=b'x')\n"
            "    Foreign().put_object(Bucket='foreign', Key='item', Body=b'x')\n"
            "    dynamic: Any = object()\n"
            "    dynamic.put_object(Bucket='dynamic', Key='item', Body=b'x')\n",
            {"typed-s3-put-object"},
        ),
    )
    for preset, body, expected in cases:
        case_root = tmp_path / preset
        case_root.mkdir()
        (case_root / "main.py").write_text(
            "from fastapi import FastAPI\n"
            + body.replace("def handler(", "app = FastAPI()\n@app.get('/')\ndef handler(", 1),
            encoding="utf-8",
        )
        result = CliRunner().invoke(
            cli,
            [
                "audit-effect-contracts",
                "--app",
                str(case_root),
                "--preset",
                preset,
                "--format",
                "json",
                "--no-cache",
            ],
        )

        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        matched = [item for item in data["occurrences"] if item["audit_status"] == "matched"]
        assert {item["contract_id"] for item in matched} == expected
        assert len(matched) == 1


def test_motor_added_rows_fail_closed_in_public_cli_for_source_only_wheels(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resolve source-only wheels as external typed dependencies, without importing them."""
    artifacts = Path("/tmp/gh97-wheel-audit")
    wheel_paths = {name: artifacts / details[0] for name, details in MOTOR_PROBE_ARTIFACTS.items()}
    if any(not path.is_file() for path in wheel_paths.values()):
        pytest.skip("supplied Motor and PyMongo source wheels are unavailable")
    app_root = tmp_path / "app"
    app_root.mkdir()
    stubs = tmp_path / "typed-dependencies"
    stubs.mkdir()
    for distribution, wheel in wheel_paths.items():
        verify_artifact_hash(wheel, distribution)
        bounded_python_sources(wheel.read_bytes(), stubs, wheel.name)
    monkeypatch.setenv("MYPYPATH", str(stubs))
    (app_root / "main.py").write_text(
        "from typing import Any\n"
        "from fastapi import FastAPI\n"
        "from motor.motor_asyncio import AsyncIOMotorClient as MotorClientAlias\n"
        "from motor.motor_asyncio import AsyncIOMotorCollection\n"
        "app = FastAPI()\n"
        "client: MotorClientAlias\n"
        "motor_alias = client\n"
        "collection: AsyncIOMotorCollection = motor_alias['database']['collection']\n"
        "class ForeignCollection:\n"
        "    async def find_one(self, filter: object = ...) -> object: ...\n"
        "    async def insert_many(self, documents: object) -> object: ...\n"
        "    async def replace_one(self, filter: object, replacement: object) -> object: ...\n"
        "    async def update_many(self, filter: object, update: object) -> object: ...\n"
        "    async def delete_many(self, filter: object) -> object: ...\n"
        "@app.get('/')\n"
        "async def handler() -> None:\n"
        "    await collection.find_one({'kind': 'exact'})\n"
        "    await collection.insert_many([{'kind': 'exact'}])\n"
        "    await collection.replace_one({'kind': 'exact'}, {'kind': 'replacement'})\n"
        "    await collection.update_many({'kind': 'exact'}, {'$set': {'ok': True}})\n"
        "    await collection.delete_many({'kind': 'exact'})\n"
        "    foreign = ForeignCollection()\n"
        "    await foreign.find_one({'kind': 'foreign'})\n"
        "    await foreign.insert_many([{'kind': 'foreign'}])\n"
        "    await foreign.replace_one({}, {})\n"
        "    await foreign.update_many({}, {})\n"
        "    await foreign.delete_many({})\n"
        "    dynamic: Any = object()\n"
        "    await dynamic.find_one({})\n"
        "    await dynamic.insert_many([{}])\n"
        "    await dynamic.replace_one({}, {})\n"
        "    await dynamic.update_many({}, {})\n"
        "    await dynamic.delete_many({})\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        cli,
        [
            "audit-effect-contracts",
            "--app",
            str(app_root),
            "--preset",
            "mongodb-v1",
            "--format",
            "json",
            "--no-cache",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    added_calls = [item for item in data["occurrences"] if item["line"] in range(17, 22)]
    assert len(added_calls) == 5
    assert {item["contract_id"] for item in added_calls if item["audit_status"] == "matched"} == {
        "motor-find-one",
        "motor-insert-many",
        "motor-replace-one",
        "motor-update-many",
        "motor-delete-many",
    }
    negatives = [item for item in data["occurrences"] if item["line"] in range(23, 34)]
    assert all(item["audit_status"] != "matched" for item in negatives)


def test_audit_effect_contracts_json_is_separate_from_impact_results(tmp_path: Path) -> None:
    _app, contracts = _project(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "audit-effect-contracts",
            "--app",
            str(tmp_path),
            "--contracts",
            str(contracts),
            "--format",
            "json",
            "--no-cache",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["matching_status"] == "complete"
    assert data["scope"]["kind"] == "endpoint_reachable_calls"
    assert data["summary"]["matched_calls"] == 1
    assert data["summary"]["matched_contracts"] == 1
    matched = [item for item in data["occurrences"] if item.get("contract_id") == "emit"]
    assert len(matched) == 1
    assert matched[0]["endpoints"][0]["path"] == "/"
    expected_hash = f"sha256:{hashlib.sha256(b'orders').hexdigest()}"
    assert matched[0]["resource_identity"] == {
        "schema_version": 1,
        "status": "exact",
        "value_hashes": [expected_hash],
    }
    assert "orders" not in result.output
    assert "candidate_endpoints" not in data
    assert "confidence" not in result.output
    assert "effect_evidence" not in result.output


def test_audit_uses_config_relative_contracts_and_rejects_dual_sources(
    tmp_path: Path,
) -> None:
    _app, contracts = _project(tmp_path)
    config = tmp_path / "detector.yaml"
    config.write_text(
        "analysis:\n  effect_contracts: effects.yaml\n",
        encoding="utf-8",
    )
    runner = CliRunner()

    configured = runner.invoke(
        cli,
        [
            "--config",
            str(config),
            "audit-effect-contracts",
            "--app",
            str(tmp_path),
            "--format",
            "json",
            "--no-cache",
        ],
    )
    conflict = runner.invoke(
        cli,
        [
            "--config",
            str(config),
            "audit-effect-contracts",
            "--app",
            str(tmp_path),
            "--contracts",
            str(contracts),
        ],
    )

    assert configured.exit_code == 0, configured.output
    assert json.loads(configured.output)["summary"]["matched_calls"] == 1
    assert conflict.exit_code != 0
    assert "conflicts" in conflict.output


def test_audit_resolves_src_package_identity_without_checkout_fallback(tmp_path: Path) -> None:
    project = tmp_path / "unrelated_checkout_name"
    package = project / "src" / "orders_api"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "helpers.py").write_text(
        "def emit(resource: str) -> int:\n    return 1\n",
        encoding="utf-8",
    )
    (package / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from orders_api.helpers import emit\n\n"
        "app = FastAPI()\n\n"
        "@app.get('/')\n"
        "def handler() -> int:\n"
        "    return emit('orders')\n",
        encoding="utf-8",
    )
    contracts = project / "effects.yaml"
    contracts.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "preset": {
                    "id": "src-layout-audit",
                    "version": "1.0.0",
                    "provenance": {"kind": "user", "source": "effects.yaml"},
                },
                "contracts": [
                    {
                        "id": "exact-package",
                        "symbol": "orders_api.helpers.emit",
                        "invocation": "function",
                        "operation": "publish",
                        "channel": "message_bus",
                        "resource": {"kind": "argument", "index": 0},
                    },
                    {
                        "id": "checkout-prefixed-decoy",
                        "symbol": "unrelated_checkout.orders_api.helpers.emit",
                        "invocation": "function",
                        "operation": "publish",
                        "channel": "message_bus",
                        "resource": {"kind": "argument", "index": 0},
                    },
                    {
                        "id": "wrong-package-decoy",
                        "symbol": "wrong_package.helpers.emit",
                        "invocation": "function",
                        "operation": "publish",
                        "channel": "message_bus",
                        "resource": {"kind": "argument", "index": 0},
                    },
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    for app_path in (project, project / "src", package):
        result = runner.invoke(
            cli,
            [
                "audit-effect-contracts",
                "--app",
                str(app_path),
                "--contracts",
                str(contracts),
                "--format",
                "json",
                "--no-cache",
            ],
        )

        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["summary"]["matched_calls"] == 1
        assert data["summary"]["matched_contracts"] == 1
        assert data["summary"]["unmatched_contracts"] == 2
        matched = [item for item in data["occurrences"] if item.get("contract_id")]
        assert [(item["canonical_symbol"], item["contract_id"]) for item in matched] == [
            ("orders_api.helpers.emit", "exact-package")
        ]


def test_audit_loads_configured_effect_preset(tmp_path: Path) -> None:
    _project(tmp_path)
    config = tmp_path / "detector.yaml"
    config.write_text(
        "analysis:\n  effect_preset: filesystem-v1\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        [
            "--config",
            str(config),
            "audit-effect-contracts",
            "--app",
            str(tmp_path),
            "--format",
            "json",
            "--no-cache",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["summary"]["contracts"] == 12
    assert data["provenance"]["preset_hash"].startswith("sha256:")


def test_audit_requires_contracts_and_text_discloses_scope(tmp_path: Path) -> None:
    _app, contracts = _project(tmp_path)
    runner = CliRunner()

    missing = runner.invoke(
        cli,
        ["audit-effect-contracts", "--app", str(tmp_path)],
    )
    text = runner.invoke(
        cli,
        [
            "audit-effect-contracts",
            "--app",
            str(tmp_path),
            "--contracts",
            str(contracts),
            "--no-cache",
        ],
    )

    assert missing.exit_code != 0
    assert "effect contracts are required" in missing.output
    assert text.exit_code == 0, text.output
    assert "Scope: endpoint-reachable calls" in text.output
    assert "Package applicability: not evaluated" in text.output
    assert "do not alter endpoint candidates or confidence" in text.output


def test_audit_yaml_preserves_the_complete_json_structure(tmp_path: Path) -> None:
    _app, contracts = _project(tmp_path)
    runner = CliRunner()
    base = [
        "audit-effect-contracts",
        "--app",
        str(tmp_path),
        "--contracts",
        str(contracts),
        "--no-cache",
    ]

    json_result = runner.invoke(cli, [*base, "--format", "json"])
    yaml_result = runner.invoke(cli, [*base, "--format", "yaml"])

    assert json_result.exit_code == 0, json_result.output
    assert yaml_result.exit_code == 0, yaml_result.output
    assert json.loads(json_result.output) == yaml.safe_load(yaml_result.output)


def test_audit_cache_cold_and_warm_json_are_identical(tmp_path: Path) -> None:
    _app, contracts = _project(tmp_path)
    runner = CliRunner()
    arguments = [
        "audit-effect-contracts",
        "--app",
        str(tmp_path),
        "--contracts",
        str(contracts),
        "--format",
        "json",
    ]

    cold = runner.invoke(cli, [*arguments, "--clear-cache"])
    warm = runner.invoke(cli, arguments)

    assert cold.exit_code == 0, cold.output
    assert warm.exit_code == 0, warm.output
    assert json.loads(cold.output) == json.loads(warm.output)
