from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

import yaml
from click.testing import CliRunner

from fastapi_endpoint_detector.cli import cli

if TYPE_CHECKING:
    from pathlib import Path


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
                        "symbol": f"{root.name}.helpers.emit",
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
    assert matches[0]["resource_identity"] == {
        "schema_version": 1,
        "status": "unavailable",
        "value_hashes": [],
        "reason_code": "receiver_origin_unavailable",
    }


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
    assert data["summary"]["contracts"] == 4
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
