from __future__ import annotations

import ast
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from benchmarks.real_world import ground_truth_pre_readiness_recovery_v1 as recovery

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 11, 12, tzinfo=timezone.utc)
HASH = "sha256:" + "a" * 64


def _expected() -> dict[str, Any]:
    return {
        "campaign_id": "campaign-149",
        "campaign_manifest_sha256": HASH,
        "canonical_campaign_path": "/custody/campaign-149.json",
        "corpus_sha256": HASH,
        "attempt_id": "prod-v1-i001-rank001-pr149-A",
        "lane": "A",
        "reviewer_id": "reviewer-A",
        "source_bindings_sha256": HASH,
        "packet_publication_entry_hash": HASH,
        "runtime_attestation_entry_hash": HASH,
        "production_profile_sha256": HASH,
        "prior_authorization_entry_hash": HASH,
        "prior_authorization_expires_at": "2026-10-12T00:00:00Z",
        "failed_event_entry_hash": HASH,
        "failed_event_kind": "operational_failed",
        "failure_phase": "prebinding",
        "failure_reason": "canonical campaign path mismatch",
    }


def _record(phase: str = "prebinding") -> dict[str, Any]:
    expected = _expected()
    if phase == "binding_created_broker_not_ready":
        expected["failure_phase"] = phase
        expected["failure_reason"] = "broker failed before readiness"
        kinds = ["failed_event", "binding", "broker_log", "no_launch_census", "cleanup_inventory"]
    else:
        kinds = ["failed_event", "no_launch_census", "cleanup_inventory"]
    evidence = [
        {"kind": kind, "sha256": HASH, "archive_path": f"evidence/{kind}.json"} for kind in kinds
    ]
    proof = dict.fromkeys(recovery._PROOF_KEYS, True)
    row = {
        **expected,
        "schema_version": 1,
        "protocol": "ground-truth-review-canary-pre-readiness-recovery-v1",
        "sequence": 1,
        "evidence": evidence,
        "no_launch_proof": proof,
        "custody_inventory_sha256": HASH,
        "issued_at": "2026-10-11T11:00:00Z",
        "expires_at": "2026-10-11T13:00:00Z",
        "previous_hash": "sha256:" + "0" * 64,
        "entry_hash": "",
    }
    row["entry_hash"] = recovery._entry_hash(row)
    return row


def test_grant_writer_and_validator_append_once(tmp_path: Path) -> None:
    root = tmp_path / "recovery-ledger"
    root.mkdir(mode=0o700)
    grant = recovery.append_grant(root, _record(), expected=_expected(), now=NOW)
    assert grant["sequence"] == 1
    assert grant["attempt_id"] == _expected()["attempt_id"]
    assert (
        len(
            recovery.validate_chain(
                root, expected_by_attempt={grant["attempt_id"]: _expected()}, now=NOW
            )
        )
        == 1
    )
    with pytest.raises(recovery.RecoveryError, match="already has"):
        recovery.append_grant(root, _record(), expected=_expected(), now=NOW)


def test_broker_not_ready_requires_binding_and_broker_evidence(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    root.mkdir(mode=0o700)
    row = _record("binding_created_broker_not_ready")
    recovery.validate_grant(
        row,
        expected=_expected()
        | {
            "failure_phase": "binding_created_broker_not_ready",
            "failure_reason": "broker failed before readiness",
        },
        previous_hash=row["previous_hash"],
        sequence=1,
        now=NOW,
    )
    row["evidence"].pop()
    row["entry_hash"] = recovery._entry_hash(row)
    with pytest.raises(recovery.RecoveryError, match="cardinality"):
        recovery.validate_grant(
            row,
            expected=_expected()
            | {
                "failure_phase": "binding_created_broker_not_ready",
                "failure_reason": "broker failed before readiness",
            },
            previous_hash=row["previous_hash"],
            sequence=1,
            now=NOW,
        )


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda r: r.update(reviewer_id="other"), "binding mismatch"),
        (lambda r: r["no_launch_proof"].update(broker_dead=False), "no-launch"),
        (lambda r: r.update(failure_reason="unknown cause"), "phase and reason"),
        (lambda r: r.update(expires_at="2026-10-11T10:00:00Z"), "expired"),
        (lambda r: r.update(canonical_campaign_path="/wrong/campaign.json"), "binding mismatch"),
    ],
)
def test_invalid_grants_fail_closed(mutate: Any, message: str) -> None:
    row = _record()
    mutate(row)
    row["entry_hash"] = recovery._entry_hash(row)
    with pytest.raises(recovery.RecoveryError, match=message):
        recovery.validate_grant(
            row, expected=_expected(), previous_hash=row["previous_hash"], sequence=1, now=NOW
        )


def test_chain_head_replay_and_expiry_rejected(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    root.mkdir(mode=0o700)
    grant = recovery.append_grant(root, _record(), expected=_expected(), now=NOW)
    with pytest.raises(recovery.RecoveryError, match="out-of-scope"):
        recovery.validate_chain(root, expected_by_attempt={}, now=NOW)
    with pytest.raises(recovery.RecoveryError, match="expired"):
        recovery.validate_chain(
            root,
            expected_by_attempt={grant["attempt_id"]: _expected()},
            now=NOW + timedelta(hours=3),
        )
    altered = dict(grant, previous_hash=HASH)
    altered["entry_hash"] = recovery._entry_hash(altered)
    with pytest.raises(recovery.RecoveryError, match="head mismatch"):
        recovery.validate_grant(
            altered, expected=_expected(), previous_hash="sha256:" + "0" * 64, sequence=1, now=NOW
        )


def test_exact_path_preflight_precedes_durable_claim(tmp_path: Path) -> None:
    canonical = tmp_path / "canonical.json"
    duplicate = tmp_path / "duplicate.json"
    canonical.write_bytes(b"identical bytes")
    duplicate.write_bytes(b"identical bytes")
    other = {name: tmp_path / name for name in ("source", "cache", "ledger", "packet")}
    for path in other.values():
        path.mkdir()
    paths = {"campaign": duplicate, **other}
    authenticated_paths = {
        name: str(path.resolve()) for name, path in {"campaign": canonical, **other}.items()
    }
    hashes = dict.fromkeys(paths, HASH)
    # A simulated durable state must stay byte-identical when preflight rejects.
    ledger = tmp_path / "durable-ledger.json"
    ledger.write_text('{"events":[]}')
    before = ledger.read_bytes()
    slot = tmp_path / "slot"
    with pytest.raises(recovery.RecoveryError, match="campaign path"):
        recovery.validate_prepare_preflight(paths, hashes, authenticated_paths, hashes)
    assert ledger.read_bytes() == before and not slot.exists()
    paths["campaign"] = canonical
    recovery.validate_prepare_preflight(paths, hashes, authenticated_paths, hashes)
    assert ledger.read_bytes() == before and not slot.exists()


def test_new_profile_checksums_and_frozen_v1_profile_unchanged() -> None:
    profile = ROOT / "benchmarks/real_world/production_v1/extensions/pre-readiness-recovery-v1"
    checksums = json.loads((profile / "checksums-v1.json").read_bytes())
    for path, digest in checksums["files"].items():
        assert "sha256:" + hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == digest
    base = ROOT / "benchmarks/real_world/production_v1/checksums-v1.json"
    assert hashlib.sha256(base.read_bytes()).hexdigest() == (
        "7248217e4f24675007b0e6994d65b64901ff9fab4c09798125893efce600812f"
    )


def test_new_grant_schema_is_closed_and_matches_writer_contract() -> None:
    schema_path = (
        ROOT
        / "benchmarks/real_world/production_v1/extensions/pre-readiness-recovery-v1"
        / "grant-schema-v1.json"
    )
    schema = json.loads(schema_path.read_bytes())
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == recovery._REQUIRED
    assert schema["properties"]["failure_phase"]["enum"] == [
        "prebinding",
        "binding_created_broker_not_ready",
    ]


def test_extension_has_no_launch_or_process_surface() -> None:
    source = ROOT / "benchmarks/real_world/ground_truth_pre_readiness_recovery_v1.py"
    tree = ast.parse(source.read_text())
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    assert not imported.intersection({"subprocess", "socket", "signal", "resource"})
    assert (
        '"launch_authorized_by_grant": false'
        in (
            ROOT
            / "benchmarks/real_world/production_v1/extensions/pre-readiness-recovery-v1"
            / "policy-v1.json"
        ).read_text()
    )
