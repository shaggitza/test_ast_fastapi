from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from benchmarks.real_world import ground_truth_broker_bundle_v1 as bundle_v1
from benchmarks.real_world import ground_truth_pre_readiness_recovery_official_v2 as official
from benchmarks.real_world.ground_truth_v2.schema import canonical_json

_BROKER_MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "benchmarks/real_world/production_v1/extensions/pre-readiness-recovery-v1/"
    "ground_truth_retry_broker_v2.py"
)
_BROKER_SPEC = importlib.util.spec_from_file_location("retry_broker_v2_test", _BROKER_MODULE_PATH)
assert _BROKER_SPEC and _BROKER_SPEC.loader
retry_broker_v2 = importlib.util.module_from_spec(_BROKER_SPEC)
_BROKER_SPEC.loader.exec_module(retry_broker_v2)

NOW = datetime(2026, 10, 11, 12, tzinfo=timezone.utc)
ATTEMPT = "prod-v1-i001-rank001-pr149-A"
ACQUIRE_BROKER_BUNDLE_LEASE = official.acquire_broker_bundle_lease


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def test_v2_bindings_reconcile_official_custody_and_distinct_retry_identity() -> None:
    custody = b'{"synthetic-custody":true}'
    attestation = {
        "entry_hash": _sha(b"official-runtime-event"),
        "runtime_custody_receipt_sha256": _sha(custody),
    }
    attestation_raw = canonical_json(attestation)
    run_id = str(uuid.uuid4())
    hashes = {
        "extension_profile_sha256": _sha(b"extension-profile"),
        "bundle_manifest_sha256": _sha(b"bundle-manifest"),
        "source_closure_sha256": _sha(b"source-closure"),
        "launch_profile_sha256": _sha(b"launch-profile"),
        "toolchain_sha256": _sha(b"toolchain"),
        "campaign_attempt_id": ATTEMPT,
        "grant_entry_hash": _sha(b"grant"),
        "retry_ordinal": 1,
        "run_id": run_id,
        "official_binding_sha256": _sha(b"v1-binding"),
    }
    raw = official.produce_runtime_binding_v2(
        runtime_attestation=attestation,
        runtime_attestation_raw=attestation_raw,
        custody_receipt_raw=custody,
        **hashes,
    )
    accepted = official.validate_runtime_binding_v2(
        raw,
        runtime_attestation=attestation,
        runtime_attestation_raw=attestation_raw,
        custody_receipt_raw=custody,
        expected=hashes,
    )
    overlay = official.produce_overlay_binding_v2(
        campaign_attempt_id=ATTEMPT,
        run_id=run_id,
        retry_ordinal=1,
        grant_entry_hash=hashes["grant_entry_hash"],
        runtime_binding_sha256=_sha(raw),
        official_binding_sha256=hashes["official_binding_sha256"],
        rank=1,
        lane="A",
    )
    overlay_expected = {
        "campaign_attempt_id": ATTEMPT,
        "run_id": run_id,
        "retry_ordinal": 1,
        "grant_entry_hash": hashes["grant_entry_hash"],
        "runtime_binding_sha256": _sha(raw),
        "official_binding_sha256": hashes["official_binding_sha256"],
        "rank": 1,
        "lane": "A",
    }
    assert accepted["campaign_attempt_id"] == ATTEMPT
    assert accepted["run_id"] != ATTEMPT
    validated_overlay = official.validate_overlay_binding_v2(
        overlay, expected=overlay_expected
    )
    assert validated_overlay["run_id"] == run_id
    with pytest.raises(official.OfficialRecoveryError, match="custody/profile"):
        official.validate_runtime_binding_v2(
            raw,
            runtime_attestation=attestation,
            runtime_attestation_raw=attestation_raw,
            custody_receipt_raw=b'{"forged":true}',
            expected=hashes,
        )
    with pytest.raises(official.OfficialRecoveryError, match="identity or hash"):
        official.validate_overlay_binding_v2(overlay, expected=overlay_expected | {"lane": "B"})


def test_committed_broker_source_profile_matches_derived_closure() -> None:
    root = Path(__file__).resolve().parents[2]
    profile, profile_sha256 = official.authenticate_broker_source_profile_v2(root)
    assert profile["entrypoint"].endswith("ground_truth_retry_broker_v2.py")
    assert profile["external_imports"] == ["pydantic"]
    assert profile_sha256 == _sha(
        (root / "benchmarks/real_world/production_v1/extensions/pre-readiness-recovery-v1/"
         "broker-source-profile-v2.json").read_bytes()
    )


def test_retry_validator_requires_authenticated_explicit_project_root(tmp_path: Path) -> None:
    fixture_path = Path(__file__).with_name("test_ground_truth_submit_v1.py")
    spec = importlib.util.spec_from_file_location("synthetic_submit_fixture_root", fixture_path)
    assert spec and spec.loader
    fixture_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture_module)
    submit = retry_broker_v2.submit_v1
    record = fixture_module._packet_and_record(tmp_path)
    bindings_path = tmp_path / "binding.json"
    value = submit.SubmissionBindings(
        schema_version=1,
        protocol="ground-truth-review-submit-v1",
        records=(submit.SubmissionBinding.model_validate(record.model_dump(mode="json")),),
    )
    bindings_path.write_bytes(canonical_json(value.model_dump(mode="json")))
    bindings_path.chmod(0o400)
    with pytest.raises(TypeError):
        submit.load_bindings(bindings_path)  # type: ignore[call-arg]
    with pytest.raises(submit.GroundTruthSubmitError, match="profile binding changed"):
        forged = record.model_copy(update={"profile_checksum_sha256": _sha(b"forged")})
        submit._authenticate_record(
            submit.SubmissionBinding.model_validate(forged.model_dump(mode="json")),
            project_root=Path(__file__).resolve().parents[2],
        )
    symlink_root = tmp_path / "root-link"
    symlink_root.symlink_to(Path(__file__).resolve().parents[2], target_is_directory=True)
    with pytest.raises(submit.GroundTruthSubmitError, match="symlink"):
        submit._authenticate_record(
            submit.SubmissionBinding.model_validate(record.model_dump(mode="json")),
            project_root=symlink_root,
        )


def test_sibling_broker_runs_v1_escrow_and_v2_lease_lifecycle(  # noqa: PLR0915
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture_path = Path(__file__).with_name("test_ground_truth_submit_v1.py")
    spec = importlib.util.spec_from_file_location("synthetic_submit_fixture", fixture_path)
    assert spec and spec.loader
    fixture_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture_module)
    record = fixture_module._packet_and_record(tmp_path)
    record = record.model_copy(
        update={"attempt_id": ATTEMPT, "escrow_path": str(tmp_path / "escrow" / "review.json")}
    )
    submit = retry_broker_v2.submit_v1
    monkeypatch.setattr(
        submit, "_evidence_validator", lambda _record: fixture_module.FakeEvidence()
    )
    monkeypatch.setattr(
        submit,
        "_authenticate_record",
        lambda _record, **_kwargs: {
            ("baseline", "src/main.py"): fixture_module.BASE_BLOB,
            ("target", "src/main.py"): fixture_module.TARGET_BLOB,
        },
    )
    bindings_path = tmp_path / "binding.json"
    record = submit.SubmissionBinding.model_validate(record.model_dump(mode="json"))
    bindings_value = submit.SubmissionBindings(
        schema_version=1, protocol="ground-truth-review-submit-v1", records=(record,)
    )
    bindings_raw = canonical_json(bindings_value.model_dump(mode="json"))
    bindings_path.write_bytes(bindings_raw)
    bindings_path.chmod(0o400)
    binding_sha = _sha(bindings_raw)

    custody_raw = b'{"synthetic":"official-custody"}'
    runtime_value = {
        "schema_version": 1,
        "protocol": "synthetic-authenticated-v1-runtime",
        "entry_hash": _sha(b"synthetic-official-runtime-entry"),
        "runtime_custody_receipt_sha256": _sha(custody_raw),
    }
    runtime_raw = canonical_json(runtime_value)
    runtime_path = tmp_path / "runtime-attestation.json"
    runtime_path.write_bytes(runtime_raw)
    runtime_path.chmod(0o400)
    custody_path = tmp_path / "custody-receipt.json"
    custody_path.write_bytes(custody_raw)
    custody_path.chmod(0o400)

    source_root = tmp_path / "bundle-source"
    source_root.mkdir()
    (source_root / "entry.py").write_text("print('sealed retry broker test')\n")
    toolchain_sha = bundle_v1.compute_toolchain_sha256(())
    bundle = bundle_v1.materialize_bundle(
        source_root,
        tmp_path / "bundle",
        ("entry.py",),
        profile_sha256=_sha(b"production-profile"),
        toolchain_sha256=toolchain_sha,
        entrypoint="entry.py",
    )
    launch_profile_value = {
        "schema_version": 2,
        "protocol": bundle_v1.LAUNCH_PROFILE_PROTOCOL,
        "production_profile_sha256": bundle.profile_sha256,
        "toolchain_sha256": toolchain_sha,
        "entrypoint": "entry.py",
        "external_imports": [],
    }
    launch_profile_raw = canonical_json(launch_profile_value)
    launch_profile_path = tmp_path / "launch-profile.json"
    launch_profile_path.write_bytes(launch_profile_raw)
    launch_profile_path.chmod(0o400)
    run_id = str(uuid.uuid4())
    grant_hash = _sha(b"synthetic-recovery-grant")
    runtime_binding_raw = official.produce_runtime_binding_v2(
        runtime_attestation=runtime_value,
        runtime_attestation_raw=runtime_raw,
        custody_receipt_raw=custody_raw,
        extension_profile_sha256=_sha(b"source-committed-extension-profile"),
        bundle_manifest_sha256=bundle.digest,
        source_closure_sha256=_sha(canonical_json(["entry.py"])),
        launch_profile_sha256=_sha(launch_profile_raw),
        toolchain_sha256=toolchain_sha,
        campaign_attempt_id=ATTEMPT,
        grant_entry_hash=grant_hash,
        retry_ordinal=1,
        run_id=run_id,
        official_binding_sha256=binding_sha,
    )
    runtime_binding_path = tmp_path / "runtime-binding-v2.json"
    runtime_binding_path.write_bytes(runtime_binding_raw)
    runtime_binding_path.chmod(0o400)
    runtime_expected = {
        "extension_profile_sha256": _sha(b"source-committed-extension-profile"),
        "bundle_manifest_sha256": bundle.digest,
        "source_closure_sha256": _sha(canonical_json(["entry.py"])),
        "launch_profile_sha256": _sha(launch_profile_raw),
        "toolchain_sha256": toolchain_sha,
        "campaign_attempt_id": ATTEMPT,
        "grant_entry_hash": grant_hash,
        "retry_ordinal": 1,
        "run_id": run_id,
        "official_binding_sha256": binding_sha,
    }
    overlay_expected = {
        "campaign_attempt_id": ATTEMPT,
        "run_id": run_id,
        "retry_ordinal": 1,
        "grant_entry_hash": grant_hash,
        "runtime_binding_sha256": _sha(runtime_binding_raw),
        "official_binding_sha256": binding_sha,
        "rank": 1,
        "lane": "A",
    }
    overlay_raw = official.produce_overlay_binding_v2(**overlay_expected)
    overlay_path = tmp_path / "overlay-binding-v2.json"
    overlay_path.write_bytes(overlay_raw)
    overlay_path.chmod(0o400)
    freeze_receipt = {
        "schema_version": 1,
        "protocol": bundle_v1.RECEIPT_PROTOCOL,
        "runtime_attestation_path": str(runtime_path),
        "runtime_attestation_sha256": _sha(runtime_raw),
        "bundle_manifest_path": str(bundle.root / "bundle-manifest-v1.json"),
        "bundle_sha256": bundle.digest,
        "binding_path": str(runtime_binding_path),
        "binding_sha256": _sha(runtime_binding_raw),
        "launch_profile_path": str(launch_profile_path),
        "launch_profile_protocol": bundle_v1.LAUNCH_PROFILE_PROTOCOL,
        "launch_profile_sha256": _sha(launch_profile_raw),
        "toolchain_sha256": toolchain_sha,
        "lease_path": str(tmp_path / "freeze.lock"),
        "hold_until": "escrow_finalized",
    }
    freeze_raw = canonical_json(freeze_receipt)
    freeze_path = tmp_path / "freeze-receipt.json"
    freeze_path.write_bytes(freeze_raw)
    freeze_path.chmod(0o400)
    lease = bundle_v1.acquire_launch_lease(
        receipt_path=freeze_path,
        receipt_sha256=_sha(freeze_raw),
        bundle_root=bundle.root,
        source_root=source_root,
        expected_bundle_sha256=bundle.digest,
        runtime_attestation_path=runtime_path,
        runtime_attestation_sha256=_sha(runtime_raw),
        binding_path=runtime_binding_path,
        binding_sha256=_sha(runtime_binding_raw),
        launch_profile_path=launch_profile_path,
        launch_profile_sha256=_sha(launch_profile_raw),
        toolchain_sha256=toolchain_sha,
        require_exclusive_freeze=True,
        hold_until="escrow_finalized",
    )
    packet_socket = tmp_path / "retry.sock"
    claim_path = tmp_path / "claim-receipt-v2.json"
    escrow_path = tmp_path / "escrow-receipt-v2.json"
    deadline = fixture_module.END + timedelta(minutes=1)
    result: dict[str, Any] = {}

    def serve() -> None:
        result.update(
            retry_broker_v2.serve_one_retry(
                binding_path=bindings_path,
                runtime_binding_path=runtime_binding_path,
                overlay_binding_path=overlay_path,
                socket_path=packet_socket,
                claim_receipt_path=claim_path,
                escrow_receipt_path=escrow_path,
                runtime_expected=runtime_expected,
                overlay_expected=overlay_expected,
                runtime_attestation_path=runtime_path,
                custody_receipt_path=custody_path,
                freeze_receipt_path=freeze_path,
                freeze_receipt_sha256=_sha(freeze_raw),
                bundle_root=bundle.root,
                source_root=source_root,
                freeze_fd=lease.lease.fd,
                deadline=deadline,
                clock=lambda: fixture_module.END,
            )
        )

    server = threading.Thread(target=serve)
    server.start()
    for _ in range(500):
        if claim_path.exists():
            break
        if not server.is_alive():
            pytest.fail("synthetic retry broker exited before readiness")
        time.sleep(0.01)
    draft = fixture_module._negative()
    request = json.dumps(
        {
            "protocol_version": 1,
            "capability": record.capability,
            "cwd": record.packet_path,
            "draft": draft,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    child_code = (
        "import json,socket,struct,sys;"
        "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(sys.argv[1]);"
        "b=sys.argv[2].encode();s.sendall(struct.pack('!I',len(b))+b);"
        "h=s.recv(4);n=struct.unpack('!I',h)[0];d=b'';"
        "exec('while len(d)<n: d+=s.recv(n-len(d))');print(d.decode())"
    )
    client = subprocess.run(
        [sys.executable, "-c", child_code, str(packet_socket), request],
        cwd=record.packet_path,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    server.join(timeout=10)
    assert not server.is_alive()
    response = json.loads(client.stdout)
    assert response["ok"] is True
    assert result["protocol"] == "ground-truth-review-retry-escrow-receipt-v2"
    assert json.loads(escrow_path.read_bytes())["submission_receipt"]["attempt_id"] == ATTEMPT
    assert lease.phase == "prepared"  # child/adopted owner closed the shared descriptor

    execution_root = tmp_path / "execution"
    run_root = execution_root / "recovery" / "runs" / run_id
    run_root.mkdir(mode=0o700, parents=True)
    (run_root / "binding.json").write_bytes(bindings_raw)
    (run_root / "binding.json").chmod(0o400)
    (run_root / "claim-receipt-v2.json").write_bytes(claim_path.read_bytes())
    (run_root / "claim-receipt-v2.json").chmod(0o400)
    (run_root / "escrow-receipt-v2.json").write_bytes(escrow_path.read_bytes())
    (run_root / "escrow-receipt-v2.json").chmod(0o400)
    state = {
        "schema_version": 1,
        "protocol": official._RETRY_PROTOCOL,
        "phase": "broker_ready",
        "run_id": run_id,
        "retry_ordinal": 1,
        "campaign_attempt_id": ATTEMPT,
        "rank": 1,
        "lane": "A",
        "binding": str(run_root / "binding.json"),
        "binding_sha256": binding_sha,
        "broker_bundle_lease_receipt_sha256": _sha(freeze_raw),
        "broker_pid": os.getpid(),
        "broker_start_identity": "synthetic-start",
        "socket": str(packet_socket),
        "registry": str(tmp_path / "registry.json"),
        "runtime_attestation_entry_hash": runtime_value["entry_hash"],
        "recovery_grant_entry_hash": grant_hash,
        "prepared_at": fixture_module.START.isoformat().replace("+00:00", "Z"),
    }
    run_v1 = official.run_v1
    run_v1._atomic(run_root / "retry-state.json", state)
    journal = execution_root / "recovery" / "runs" / "journal"
    official._append_retry_event(
        journal,
        "retry_consumed",
        {
            "attempt_id": ATTEMPT,
            "grant_entry_hash": grant_hash,
            "retry_ordinal": 1,
            "run_id": run_id,
            "allocated_at": fixture_module.START.isoformat().replace("+00:00", "Z"),
        },
    )
    official._append_retry_event(
        journal,
        "retry_prepared",
        {
            "attempt_id": ATTEMPT,
            "grant_entry_hash": grant_hash,
            "run_id": run_id,
            "binding_sha256": binding_sha,
            "broker_bundle_lease_receipt_sha256": _sha(freeze_raw),
            "runtime_attestation_entry_hash": runtime_value["entry_hash"],
            "prepared_at": fixture_module.START.isoformat().replace("+00:00", "Z"),
        },
    )
    official._append_retry_event(
        journal,
        "retry_claimed",
        {
            "attempt_id": ATTEMPT,
            "grant_entry_hash": grant_hash,
            "run_id": run_id,
            "binding_sha256": binding_sha,
            "claim_receipt_sha256": _sha(claim_path.read_bytes()),
            "claimed_at": json.loads(claim_path.read_bytes())["claimed_at"],
        },
    )
    finalized = official.finalize_authorized_retry(
        execution_root, run_id, project_root=Path(__file__).resolve().parents[2]
    )
    assert finalized["escrow_receipt_sha256"] == _sha(escrow_path.read_bytes())
    assert [row["kind"] for row in official._retry_rows(journal, create=False)] == [
        "retry_consumed",
        "retry_prepared",
        "retry_claimed",
        "retry_escrow_finalized",
    ]


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:  # noqa: PLR0915
    campaign_path = tmp_path / "campaign.json"
    campaign_raw = b'{"campaign":"synthetic"}'
    campaign_path.write_bytes(campaign_raw)
    campaign_path.chmod(0o400)
    private = tmp_path / "official-ledger"
    (private / "events").mkdir(parents=True)
    execution = tmp_path / "execution"
    execution.mkdir(mode=0o700)
    slots = execution / "slots"
    slots.mkdir(mode=0o700)
    lock_path = slots / ".lock"
    lock_path.touch(mode=0o600)
    lock_path.chmod(0o600)
    source_path = tmp_path / "source.json"
    source_path.write_bytes(b"source")
    source_path.chmod(0o400)
    cache_path = tmp_path / "cache"
    cache_path.mkdir(mode=0o700)
    ledger_path = tmp_path / "ledger"
    ledger_path.mkdir(mode=0o700)
    packets_path = tmp_path / "packets"
    packets_path.mkdir(mode=0o700)
    profile_hash = _sha(b"profile")
    auth_hash = _sha(b"authorization")
    failed_hash = _sha(b"failed-event")
    event = {
        "sequence": 1,
        "kind": "operational_failed",
        "attempt_id": ATTEMPT,
        "reason": "runtime custody paths or profile changed",
        "entry_hash": failed_hash,
    }
    event_path = private / "events" / f"000001-operational_failed-{ATTEMPT}.json"
    event_path.write_bytes(canonical_json(event))
    event_path.chmod(0o400)
    genesis = {
        "campaign_manifest_path": str(campaign_path),
        "campaign_manifest_sha256": _sha(campaign_raw),
    }
    genesis_path = private / "ledger-genesis.json"
    genesis_path.write_bytes(canonical_json(genesis))
    genesis_path.chmod(0o400)
    lane = {
        "attempt_id": ATTEMPT,
        "rank": 1,
        "lane": "A",
        "reviewer": {"name": "blind-reviewer-A"},
    }
    authorization = {
        "entry_hash": auth_hash,
        "issued_at": "2026-10-10T00:00:00Z",
        "expires_at": "2026-10-12T00:00:00Z",
        "lanes": [lane],
    }
    current = {
        "authorization": authorization,
        "states": {ATTEMPT: "operational_failed"},
        "events": [event],
        "head": _sha(b"head"),
        "launched_attempts": set(),
        "native_results": {},
        "batches": {},
    }
    campaign = {
        "id": "synthetic-campaign",
        "corpus": {"manifest_sha256": _sha(b"corpus")},
        "lanes": [lane],
    }
    custody = {
        "source": {"sha256": _sha(b"source")},
        "packet": {"publication_entry_hash": _sha(b"packet-publication")},
    }
    profile = SimpleNamespace(checksum_sha256=profile_hash)
    runtime_dir = execution / "runtime"
    runtime_dir.mkdir(mode=0o700)
    receipt = {
        "campaign_path": str(campaign_path),
        "source_bindings_path": str(source_path),
        "cache": {"cache_root": str(cache_path)},
        "ledger_root": str(ledger_path),
        "packets": {"packets_root": str(packets_path)},
    }
    receipt_raw = canonical_json(receipt)
    receipt_path = runtime_dir / "custody-receipt.json"
    receipt_path.write_bytes(receipt_raw)
    receipt_path.chmod(0o400)
    lease_path = runtime_dir / "synthetic-broker-lease.json"
    lease_path.write_bytes(b'{"synthetic":"lease"}')
    lease_path.chmod(0o400)
    attestation = {
        "entry_hash": _sha(b"runtime"),
        "runtime_custody_receipt_path": str(receipt_path),
        "runtime_custody_receipt_sha256": _sha(receipt_raw),
    }
    runtime_attestation_path = execution / "runtime-attestation.json"
    runtime_attestation_path.write_bytes(canonical_json(attestation))
    runtime_attestation_path.chmod(0o400)
    monkeypatch.setattr(
        official.run_v1, "_custody", lambda *_args: (campaign, campaign_raw, custody, profile)
    )
    monkeypatch.setattr(official.run_v1.campaign_v1, "_private_root", lambda _path: private)
    monkeypatch.setattr(official.run_v1.campaign_v1, "_ledger_lock", lambda _path: nullcontext())
    monkeypatch.setattr(official.run_v1, "_locked_slots", lambda _path: nullcontext(slots))
    monkeypatch.setattr(official, "_active_broker_processes", lambda _attempt: [])
    monkeypatch.setattr(official.run_v1, "_extended_ledger", lambda *_args: current)
    monkeypatch.setattr(
        official, "authenticate_extension_profile", lambda _root: _sha(b"extension-profile")
    )
    monkeypatch.setattr(official, "_profile_file", lambda _path: b"synthetic-launch-profile")
    monkeypatch.setattr(
        official,
        "_broker_bundle_api",
        lambda: SimpleNamespace(
            acquire_launch_lease=lambda **_kwargs: object(),
            launch_with_escrow_lease=lambda **_kwargs: 345678,
        ),
    )
    monkeypatch.setattr(official.run_v1, "_runtime_attestation", lambda *_args: attestation)
    monkeypatch.setattr(
        official.run_v1,
        "_installed_agent",
        lambda *_args: {"runtime_attestation_entry_hash": _sha(b"runtime")},
    )
    monkeypatch.setattr(
        official.run_v1,
        "_runtime_boundary",
        lambda _root, _execution, _current, attestation, installation: (attestation, installation),
    )
    monkeypatch.setattr(official, "acquire_broker_bundle_lease", lambda **_kwargs: object())
    return {
        "campaign_path": campaign_path,
        "campaign_raw": campaign_raw,
        "private": private,
        "execution": execution,
        "current": current,
        "campaign": campaign,
        "custody": custody,
        "profile": profile,
        "event": event,
        "source_path": source_path,
        "cache_path": cache_path,
        "ledger_path": ledger_path,
        "packets_path": packets_path,
        "lease_path": lease_path,
        "runtime_attestation_path": runtime_attestation_path,
    }


def _issue(fixture: dict[str, Any]) -> dict[str, Any]:
    return official.issue_official_grant(
        Path("/synthetic/root"),
        fixture["campaign_path"],
        fixture["source_path"],
        fixture["cache_path"],
        fixture["ledger_path"],
        fixture["packets_path"],
        fixture["execution"],
        ATTEMPT,
        now=NOW,
    )


def test_identical_bytes_at_wrong_campaign_path_rejected_before_any_claim_or_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    wrong = tmp_path / "byte-identical-copy.json"
    wrong.write_bytes(fixture["campaign_raw"])
    wrong.chmod(0o400)
    with pytest.raises(official.OfficialRecoveryError, match="canonical custody"):
        official.issue_official_grant(
            Path("/synthetic/root"),
            wrong,
            Path("/synthetic/source"),
            Path("/synthetic/cache"),
            Path("/synthetic/ledger"),
            Path("/synthetic/packets"),
            fixture["execution"],
            ATTEMPT,
            now=NOW,
        )
    assert not (fixture["execution"] / "recovery").exists()
    assert not (fixture["execution"] / "slots" / f"{ATTEMPT}.json").exists()
    assert fixture["current"]["head"]


def test_official_adapter_derives_failure_and_archives_before_append(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    result = _issue(fixture)
    grant = result["grant"]
    assert result["operational_prepare_performed"] is False
    assert grant["failed_event_entry_hash"] == fixture["event"]["entry_hash"]
    assert grant["failure_phase"] == "prebinding"
    assert {item["kind"] for item in grant["evidence"]} == {
        "failed_event",
        "no_launch_census",
        "cleanup_inventory",
    }
    for item in grant["evidence"]:
        path = fixture["execution"] / "recovery" / item["archive_path"]
        assert _sha(path.read_bytes()) == item["sha256"]
    rows = official.validate_official_grants(
        Path("/synthetic/root"),
        fixture["execution"],
        {
            ATTEMPT: {
                key: grant[key]
                for key in (
                    "campaign_id",
                    "campaign_manifest_sha256",
                    "canonical_campaign_path",
                    "corpus_sha256",
                    "attempt_id",
                    "lane",
                    "reviewer_id",
                    "source_bindings_sha256",
                    "packet_publication_entry_hash",
                    "runtime_attestation_entry_hash",
                    "production_profile_sha256",
                    "prior_authorization_entry_hash",
                    "prior_authorization_expires_at",
                    "failed_event_entry_hash",
                    "failed_event_kind",
                    "failure_phase",
                    "failure_reason",
                )
            }
        },
        now=NOW,
    )
    assert len(rows) == 1
    with pytest.raises(official.OfficialRecoveryError, match="already exists"):
        _issue(fixture)


def test_extension_profile_authenticates_versioned_adapter_and_frozen_parent() -> None:
    root = Path(__file__).resolve().parents[2]
    digest = official.authenticate_extension_profile(root)
    assert digest.startswith("sha256:")
    profile = (
        root
        / "benchmarks/real_world/production_v1/extensions/pre-readiness-recovery-v1"
        / "checksums-v2.json"
    )
    manifest = json.loads(profile.read_bytes())
    assert (
        "benchmarks/real_world/ground_truth_pre_readiness_recovery_official_v2.py"
        in manifest["files"]
    )
    assert "benchmarks/real_world/production_v1/checksums-v1.json" in manifest["files"]
    assert (
        "benchmarks/real_world/production_v1/extensions/pre-readiness-recovery-v1/retry-run-schema-v1.json"
        in manifest["files"]
    )


def test_official_slot_claim_blocks_grant_before_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    claim = fixture["execution"] / "slots" / f"{ATTEMPT}.json"
    claim.write_text("{}")
    claim.chmod(0o400)
    with pytest.raises(official.OfficialRecoveryError, match="durable slot claim"):
        _issue(fixture)
    assert not (fixture["execution"] / "recovery" / "evidence" / ATTEMPT).exists()
    assert not (fixture["execution"] / "recovery" / "ledger").exists()


def test_archived_failed_event_mutation_invalidates_official_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    result = _issue(fixture)
    row = result["grant"]
    expected = {
        key: row[key]
        for key in (
            "campaign_id",
            "campaign_manifest_sha256",
            "canonical_campaign_path",
            "corpus_sha256",
            "attempt_id",
            "lane",
            "reviewer_id",
            "source_bindings_sha256",
            "packet_publication_entry_hash",
            "runtime_attestation_entry_hash",
            "production_profile_sha256",
            "prior_authorization_entry_hash",
            "prior_authorization_expires_at",
            "failed_event_entry_hash",
            "failed_event_kind",
            "failure_phase",
            "failure_reason",
        )
    }
    archived = fixture["execution"] / "recovery" / "evidence" / ATTEMPT / "failed_event.json"
    archived.chmod(0o600)
    archived.write_bytes(b"{}")
    archived.chmod(0o400)
    with pytest.raises(official.OfficialRecoveryError, match="evidence hash mismatch"):
        official.validate_official_grants(
            Path("/synthetic/root"), fixture["execution"], {ATTEMPT: expected}, now=NOW
        )


def test_invalid_broker_profile_consumes_one_allocated_retry_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    _issue(fixture)
    submit = official.run_v1.submit_v1

    def synthetic_prepare_binding(*args: Any, **kwargs: Any) -> None:
        attempt_root = args[9]
        attempt_root.mkdir(mode=0o700)
        (attempt_root / "packet").mkdir(mode=0o700)
        binding = attempt_root / "binding.json"
        binding.write_bytes(b'{"synthetic":"binding"}')
        binding.chmod(0o400)

    monkeypatch.setattr(submit, "prepare_binding", synthetic_prepare_binding)
    monkeypatch.setattr(
        submit, "load_bindings", lambda _path: SimpleNamespace(records=[SimpleNamespace()])
    )
    with pytest.raises(
        official.OfficialRecoveryError, match="broker source profile v2 is malformed"
    ):
        official.prepare_authorized_retry(
            Path("/synthetic/root"),
            fixture["campaign_path"],
            fixture["source_path"],
            fixture["cache_path"],
            fixture["ledger_path"],
            fixture["packets_path"],
            fixture["execution"],
            ATTEMPT,
            broker_lease_receipt=fixture["lease_path"],
            now=NOW,
        )
    journal = fixture["execution"] / "recovery" / "runs" / "journal"
    rows = official._retry_rows(journal, create=False)
    assert [row["kind"] for row in rows] == ["retry_consumed", "retry_failed"]
    assert rows[0]["run_id"] != ATTEMPT


def test_wrong_path_at_retry_preflight_does_not_consume_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    _issue(fixture)
    wrong = tmp_path / "same-bytes-wrong-path.json"
    wrong.write_bytes(fixture["campaign_raw"])
    wrong.chmod(0o400)
    with pytest.raises(official.OfficialRecoveryError, match="canonical custody"):
        official.prepare_authorized_retry(
            Path("/synthetic/root"),
            wrong,
            fixture["source_path"],
            fixture["cache_path"],
            fixture["ledger_path"],
            fixture["packets_path"],
            fixture["execution"],
            ATTEMPT,
            broker_lease_receipt=fixture["lease_path"],
            now=NOW,
        )
    assert not (fixture["execution"] / "recovery" / "runs" / "journal").exists()


def test_missing_bundle_lease_rejects_before_consuming_or_allocating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    _issue(fixture)
    with pytest.raises(official.OfficialRecoveryError, match="broker bundle lease is required"):
        official.prepare_authorized_retry(
            Path("/synthetic/root"),
            fixture["campaign_path"],
            fixture["source_path"],
            fixture["cache_path"],
            fixture["ledger_path"],
            fixture["packets_path"],
            fixture["execution"],
            ATTEMPT,
            now=NOW,
        )
    assert not (fixture["execution"] / "recovery" / "runs" / "journal").exists()


def test_unavailable_bundle_validator_rejects_before_consuming_or_allocating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    _issue(fixture)
    monkeypatch.setattr(
        official,
        "_broker_bundle_api",
        lambda: (_ for _ in ()).throw(
            official.OfficialRecoveryError("the broker bundle lease validator is unavailable")
        ),
    )
    with pytest.raises(official.OfficialRecoveryError, match="validator is unavailable"):
        official.prepare_authorized_retry(
            Path("/synthetic/root"),
            fixture["campaign_path"],
            fixture["source_path"],
            fixture["cache_path"],
            fixture["ledger_path"],
            fixture["packets_path"],
            fixture["execution"],
            ATTEMPT,
            broker_lease_receipt=fixture["lease_path"],
            now=NOW,
        )
    assert not (fixture["execution"] / "recovery" / "runs" / "journal").exists()


def test_failed_retry_is_consumed_and_cannot_be_replayed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    _issue(fixture)
    monkeypatch.setattr(
        official.run_v1.submit_v1,
        "prepare_binding",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("synthetic binding failure")),
    )
    with pytest.raises(RuntimeError, match="synthetic binding failure"):
        official.prepare_authorized_retry(
            Path("/synthetic/root"),
            fixture["campaign_path"],
            fixture["source_path"],
            fixture["cache_path"],
            fixture["ledger_path"],
            fixture["packets_path"],
            fixture["execution"],
            ATTEMPT,
            broker_lease_receipt=fixture["lease_path"],
            now=NOW,
        )
    journal = fixture["execution"] / "recovery" / "runs" / "journal"
    rows = official._retry_rows(journal, create=False)
    assert [row["kind"] for row in rows] == ["retry_consumed", "retry_failed"]
    with pytest.raises(official.OfficialRecoveryError, match="already consumed"):
        official.prepare_authorized_retry(
            Path("/synthetic/root"),
            fixture["campaign_path"],
            fixture["source_path"],
            fixture["cache_path"],
            fixture["ledger_path"],
            fixture["packets_path"],
            fixture["execution"],
            ATTEMPT,
            broker_lease_receipt=fixture["lease_path"],
            now=NOW,
        )
