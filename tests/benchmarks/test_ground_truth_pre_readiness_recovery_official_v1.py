from __future__ import annotations

import hashlib
import json
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from benchmarks.real_world import ground_truth_pre_readiness_recovery_official_v1 as official
from benchmarks.real_world.ground_truth_v2.schema import canonical_json

NOW = datetime(2026, 10, 11, 12, tzinfo=timezone.utc)
ATTEMPT = "prod-v1-i001-rank001-pr149-A"
ACQUIRE_BROKER_BUNDLE_LEASE = official.acquire_broker_bundle_lease


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


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
        / "checksums-v1.json"
    )
    manifest = json.loads(profile.read_bytes())
    assert (
        "benchmarks/real_world/ground_truth_pre_readiness_recovery_official_v1.py"
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


def test_prepare_retry_consumes_one_grant_and_allocates_overlay_run_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    issued = _issue(fixture)
    run_v1 = official.run_v1
    lease_calls: list[dict[str, Any]] = []

    def fake_acquire(**kwargs: Any) -> object:
        lease_calls.append(kwargs)
        return object()

    def fake_launch(**kwargs: Any) -> int:
        lease_calls.append(kwargs)
        return 345678

    monkeypatch.setattr(
        official,
        "_broker_bundle_api",
        lambda: SimpleNamespace(
            acquire_launch_lease=fake_acquire,
            launch_with_escrow_lease=fake_launch,
        ),
    )
    monkeypatch.setattr(official, "acquire_broker_bundle_lease", ACQUIRE_BROKER_BUNDLE_LEASE)

    def fake_prepare_binding(*args: Any, **kwargs: Any) -> None:
        attempt_root = args[9]
        (attempt_root / "packet").mkdir(mode=0o700)
        binding = attempt_root / "binding.json"
        binding.write_bytes(b'{"synthetic":"binding"}')
        binding.chmod(0o400)

    monkeypatch.setattr(run_v1.submit_v1, "prepare_binding", fake_prepare_binding)
    monkeypatch.setattr(
        run_v1.submit_v1,
        "load_bindings",
        lambda _path: SimpleNamespace(records=[SimpleNamespace()]),
    )
    monkeypatch.setattr(run_v1, "_broker_socket_path", lambda _run: tmp_path / "broker.sock")
    monkeypatch.setattr(run_v1, "_registry", lambda *_args: tmp_path / "registry.json")
    monkeypatch.setattr(run_v1, "_attested_broker_path", lambda _attestation: "/synthetic/bin")
    monkeypatch.setattr(run_v1, "_proc_identity", lambda _pid: "synthetic-start")
    monkeypatch.setattr(run_v1, "_slot_update_broker", lambda *_args: None)
    monkeypatch.setattr(run_v1, "_wait_socket", lambda *_args: None)

    result = official.prepare_authorized_retry(
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
    assert result["run_id"] != ATTEMPT
    assert result["retry_ordinal"] == 1
    assert result["native_or_model_launch_performed"] is False
    assert (
        fixture["execution"] / "recovery" / "runs" / result["run_id"] / "retry-state.json"
    ).exists()
    rows = official._retry_rows(
        fixture["execution"] / "recovery" / "runs" / "journal", create=False
    )
    assert [row["kind"] for row in rows] == ["retry_consumed", "retry_prepared"]
    assert rows[0]["grant_entry_hash"] == issued["grant"]["entry_hash"]
    assert lease_calls[0]["receipt_path"] == fixture["lease_path"]
    assert lease_calls[0]["binding_sha256"] == _sha(b'{"synthetic":"binding"}')
    assert lease_calls[0]["require_exclusive_freeze"] is True
    assert lease_calls[0]["hold_until"] == "escrow_finalized"
    assert lease_calls[1]["hold_until"] == "escrow_finalized"
    assert lease_calls[1]["binding_sha256"] == _sha(b'{"synthetic":"binding"}')
    assert rows[1]["broker_bundle_lease_receipt_sha256"] == _sha(fixture["lease_path"].read_bytes())
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
