from __future__ import annotations

import json
from typing import TYPE_CHECKING

from click.testing import CliRunner

from fastapi_endpoint_detector.cli import cli

if TYPE_CHECKING:
    from pathlib import Path


def test_public_cli_validates_sqs_preset() -> None:
    result = CliRunner().invoke(
        cli, ["validate-effect-contracts", "--preset", "message-bus-v1", "--format", "json"]
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["preset"]["id"] == "typed-sqs-effects"
    assert {contract["id"] for contract in data["contracts"]} == {
        "typed-sqs-send-message",
        "typed-sqs-send-message-batch",
    }
    contracts = {contract["id"]: contract for contract in data["contracts"]}
    assert {
        contract_id: (
            contract["symbol"],
            contract["operation"],
            contract["channel"],
            contract["resource"],
            contract["value"],
            contract["package"],
        )
        for contract_id, contract in contracts.items()
    } == {
        "typed-sqs-send-message": (
            "mypy_boto3_sqs.client.SQSClient.send_message",
            "publish",
            "message_bus",
            {"kind": "keyword", "name": "QueueUrl", "path": []},
            {"kind": "keyword", "name": "MessageBody", "path": []},
            {"distribution": "mypy-boto3-sqs", "version": "==1.35.91"},
        ),
        "typed-sqs-send-message-batch": (
            "mypy_boto3_sqs.client.SQSClient.send_message_batch",
            "publish",
            "message_bus",
            {"kind": "keyword", "name": "QueueUrl", "path": []},
            {"kind": "keyword", "name": "Entries", "path": []},
            {"distribution": "mypy-boto3-sqs", "version": "==1.35.91"},
        ),
    }


def test_public_audit_loads_configured_sqs_preset(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/')\ndef handler(): return 1\n",
        encoding="utf-8",
    )
    config = tmp_path / "detector.yaml"
    config.write_text("analysis:\n  effect_preset: message-bus-v1\n", encoding="utf-8")

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
    assert data["summary"]["contracts"] == 2
    assert data["summary"]["matched_calls"] == 0
    assert data["provenance"]["preset_hash"] == (
        "sha256:875790c0d08b0f6cb2e8681bf56a9066d67bee39225dd7160cb51a447d18ebc3"
    )
