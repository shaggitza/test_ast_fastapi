"""Opt-in controlled resolver checks against the inspected SQS stub wheel."""

from __future__ import annotations

import hashlib
import os
import stat
import zipfile
from pathlib import Path, PurePosixPath

import pytest

from fastapi_endpoint_detector.analyzer.effect_contract_auditor import audit_effect_contracts
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.effect_contract import EffectSelector, load_effect_preset
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointInventory,
    EndpointMethod,
    HandlerInfo,
)


@pytest.mark.skipif(not os.environ.get("GH97_SQS_WHEEL"), reason="supply the exact SQS stub wheel")
def test_exact_sqs_preset_matches_typed_calls_and_wrapper_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = Path(os.environ["GH97_SQS_WHEEL"])
    assert hashlib.sha256(wheel.read_bytes()).hexdigest() == (
        "346a87bc0a447bb4c005b04d3efa0008bfa0ddd498cadd97e0e53a58752f84e9"
    )
    stub_root = tmp_path / "stubs"
    with zipfile.ZipFile(wheel) as archive:
        for info in archive.infolist():
            path = PurePosixPath(info.filename)
            assert not path.is_absolute() and ".." not in path.parts
            assert "\\" not in info.filename
            assert not stat.S_ISLNK(info.external_attr >> 16)
            assert info.file_size < 8 * 1024 * 1024
            if (
                not path.parts
                or path.parts[0] != "mypy_boto3_sqs"
                or (path.suffix not in {".py", ".pyi"} and path.name != "py.typed")
            ):
                continue
            target = stub_root.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(info))
    # The analyzer's import root is the app tree. Point mypy at the separately
    # extracted, hash-verified stub tree so the declared public package can be
    # resolved without installing or importing it.
    monkeypatch.setenv("MYPYPATH", str(stub_root))
    app = tmp_path / "fixture"
    app.mkdir()
    source = app / "main.py"
    source.write_text(
        "from mypy_boto3_sqs.client import SQSClient\n"
        "class Foreign:\n"
        "    def send_message(self, **kwargs: object) -> None: pass\n"
        "def publish(client: SQSClient) -> None:\n"
        "    client.send_message(QueueUrl='queue', MessageBody='wrapped')\n"
        "def handler(client: SQSClient, foreign: Foreign) -> None:\n"
        "    client.send_message(QueueUrl='queue', MessageBody='single')\n"
        "    client.send_message_batch(QueueUrl='queue', "
        "Entries=[{'Id': '1', 'MessageBody': 'batch'}])\n"
        "    publish(client)\n"
        "    foreign.send_message(QueueUrl='queue', MessageBody='foreign')\n",
        encoding="utf-8",
    )
    endpoint = Endpoint(
        path="/publish",
        methods=[EndpointMethod.POST],
        handler=HandlerInfo(name="handler", module="fixture.main", file_path=source, line_number=6),
    )
    analyzer = MypyAnalyzer(app, max_depth=3)
    calls = analyzer.analyze_endpoint(endpoint).get_resolved_call_sites()
    audit = audit_effect_contracts(
        load_effect_preset("message-bus-v1"),
        source_root=app,
        inventory=EndpointInventory(endpoints=[endpoint]),
        endpoint_call_sites=[(endpoint, calls)],
        track_transitive=True,
        max_depth=3,
        cache_enabled=False,
        resolver_versions=(f"mypy@{analyzer.resolver_version}",),
    )
    matched = [item for item in audit.occurrences if item.contract_id is not None]
    assert len(matched) == 3
    assert sorted(item.source_spelling for item in matched) == [
        "client.send_message",
        "client.send_message",
        "client.send_message_batch",
    ]
    assert {item.contract_id for item in matched} == {
        "typed-sqs-send-message",
        "typed-sqs-send-message-batch",
    }
    assert {item.canonical_symbol for item in matched} == {
        "mypy_boto3_sqs.client.SQSClient.send_message",
        "mypy_boto3_sqs.client.SQSClient.send_message_batch",
    }
    contracts = {item.id: item for item in load_effect_preset("message-bus-v1").document.contracts}
    single = contracts["typed-sqs-send-message"]
    batch = contracts["typed-sqs-send-message-batch"]
    assert isinstance(single.resource, EffectSelector)
    assert isinstance(single.value, EffectSelector)
    assert isinstance(batch.resource, EffectSelector)
    assert isinstance(batch.value, EffectSelector)
    assert single.resource.name == batch.resource.name == "QueueUrl"
    assert single.value.name == "MessageBody"
    assert batch.value.name == "Entries"
    foreign = [item for item in audit.occurrences if item.source_spelling == "foreign.send_message"]
    assert len(foreign) == 1 and foreign[0].contract_id is None
