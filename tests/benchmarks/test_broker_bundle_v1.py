"""Hermetic governance tests for immutable broker execution bundles."""

from __future__ import annotations

import json
import stat
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import pytest
from benchmarks.real_world import broker_bundle_v1 as bundle
from benchmarks.real_world.ground_truth_v2.schema import canonical_json

if TYPE_CHECKING:
    from pathlib import Path

DIGEST_A = "sha256:" + "a" * 64


def _write(path: Path, value: dict[str, Any] | bytes) -> None:
    raw = value if isinstance(value, bytes) else canonical_json(value)
    path.write_bytes(raw)
    path.chmod(0o644)


def _unlock(root: Path) -> None:
    if not root.exists():
        return
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            path.chmod(0o700)
        else:
            path.chmod(0o600)
    root.chmod(0o700)


def _inputs(tmp_path: Path) -> dict[str, Path]:
    tmp_path.chmod(0o700)
    profile = tmp_path / "production-profile.json"
    _write(profile, {"schema_version": 1, "files": {}})
    profile_sha = bundle._sha(profile.read_bytes())
    runtime = tmp_path / "runtime-attestation.json"
    _write(
        runtime,
        {
            "schema_version": 2,
            "entry_hash": DIGEST_A,
            "production_profile_sha256": profile_sha,
        },
    )
    binding = tmp_path / "binding.json"
    _write(
        binding,
        {
            "schema_version": 1,
            "protocol": "ground-truth-review-submit-v1",
            "records": [
                {
                    "runtime_attestation_entry_hash": DIGEST_A,
                    "profile_checksum_sha256": profile_sha,
                }
            ],
        },
    )
    broker = tmp_path / "broker.py"
    helper = tmp_path / "helper.py"
    broker_raw = b"def main():\n    return 0\n"
    _write(broker, broker_raw)
    _write(helper, b"VALUE = 1\n")
    launch = tmp_path / "launch-profile.json"
    _write(
        launch,
        {
            "schema_version": 1,
            "protocol": "ground-truth-broker-launch-profile-v1",
            "provider": "provider",
            "model": "model",
            "model_version": "model-v1",
            "client_version": "client-v1",
            "decoding": {"temperature": 0},
            "tools": ["read", "submit_blind_review"],
            "agent_sha256": "sha256:" + "b" * 64,
            "broker_entrypoint": "runner.py",
            "broker_entrypoint_sha256": bundle._sha(broker_raw),
        },
    )
    return {
        "runtime": runtime,
        "binding": binding,
        "profile": profile,
        "launch": launch,
        "broker": broker,
        "helper": helper,
    }


def _materialize(tmp_path: Path) -> tuple[dict[str, Path], Path, Path]:
    inputs = _inputs(tmp_path)
    output = tmp_path / "bundle"
    receipt = output.with_name("bundle.receipt.json")
    bundle.materialize_bundle(
        inputs["runtime"],
        inputs["binding"],
        inputs["profile"],
        inputs["launch"],
        {"runner.py": inputs["broker"], "pkg/helper.py": inputs["helper"]},
        output,
        lineage_id="campaign-v8",
    )
    return inputs, output, receipt


def test_bundle_and_prepare_freeze_round_trip_grants_no_authority(tmp_path: Path) -> None:
    inputs, output, receipt_path = _materialize(tmp_path)
    freeze_path = tmp_path / "prepare-freeze.json"
    try:
        receipt = bundle.verify_bundle(receipt_path)
        freeze = bundle.prepare_freeze(
            receipt_path,
            inputs["runtime"],
            inputs["binding"],
            inputs["profile"],
            inputs["launch"],
            freeze_path,
            clock=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        for phase in ("prepared", "launch_claimed", "pre_escrow"):
            assert (
                bundle.verify_freeze(
                    freeze_path,
                    inputs["runtime"],
                    inputs["binding"],
                    inputs["profile"],
                    inputs["launch"],
                    phase=phase,
                )
                == freeze
            )
        assert receipt["bundle_id"] == freeze["bundle_id"]
        assert receipt["runtime_attestation_entry_hash"] == DIGEST_A
        assert receipt["authorizations"] == {
            "review_launch": False,
            "escrow": False,
            "adjudication": False,
            "canonical_import": False,
        }
        assert freeze["authorizations"] == receipt["authorizations"]
        assert freeze["prepared_at"] == "2026-01-01T00:00:00Z"
        assert stat.S_IMODE(output.stat().st_mode) == 0o500
        assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o400
        assert stat.S_IMODE(freeze_path.stat().st_mode) == 0o400
        assert not list(tmp_path.rglob("*escrow*"))
        assert not list(tmp_path.rglob("*review.json"))
        assert not list(tmp_path.rglob("*label*"))
    finally:
        _unlock(output)


@pytest.mark.parametrize("target", ["runtime", "binding", "profile", "launch"])
def test_prepare_to_escrow_freeze_rejects_control_mutation(tmp_path: Path, target: str) -> None:
    inputs, output, receipt_path = _materialize(tmp_path)
    freeze_path = tmp_path / "prepare-freeze.json"
    try:
        bundle.prepare_freeze(
            receipt_path,
            inputs["runtime"],
            inputs["binding"],
            inputs["profile"],
            inputs["launch"],
            freeze_path,
            clock=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        path = inputs[target]
        path.write_bytes(path.read_bytes() + b" ")
        with pytest.raises(bundle.BrokerBundleError):
            bundle.verify_freeze(
                freeze_path,
                inputs["runtime"],
                inputs["binding"],
                inputs["profile"],
                inputs["launch"],
                phase="pre_escrow",
            )
    finally:
        _unlock(output)


def test_bundle_mutation_after_readiness_or_launch_claim_is_rejected(tmp_path: Path) -> None:
    inputs, output, receipt_path = _materialize(tmp_path)
    freeze_path = tmp_path / "prepare-freeze.json"
    try:
        bundle.prepare_freeze(
            receipt_path,
            inputs["runtime"],
            inputs["binding"],
            inputs["profile"],
            inputs["launch"],
            freeze_path,
            clock=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        bundle.verify_freeze(
            freeze_path,
            inputs["runtime"],
            inputs["binding"],
            inputs["profile"],
            inputs["launch"],
            phase="launch_claimed",
        )
        copied = output / "broker/runner.py"
        copied.chmod(0o600)
        copied.write_bytes(b"MUTATED\n")
        copied.chmod(0o400)
        with pytest.raises(bundle.BrokerBundleError, match="bundle file identity changed"):
            bundle.verify_freeze(
                freeze_path,
                inputs["runtime"],
                inputs["binding"],
                inputs["profile"],
                inputs["launch"],
                phase="pre_escrow",
            )
    finally:
        _unlock(output)


def test_runtime_binding_and_profile_must_be_exactly_coupled(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    binding = json.loads(inputs["binding"].read_bytes())
    binding["records"][0]["runtime_attestation_entry_hash"] = "sha256:" + "c" * 64
    _write(inputs["binding"], binding)

    with pytest.raises(bundle.BrokerBundleError, match="not exactly coupled"):
        bundle.materialize_bundle(
            inputs["runtime"],
            inputs["binding"],
            inputs["profile"],
            inputs["launch"],
            {"runner.py": inputs["broker"]},
            tmp_path / "bundle",
            lineage_id="campaign-v8",
        )
    assert not (tmp_path / "bundle").exists()
    assert not (tmp_path / "bundle.receipt.json").exists()


def test_no_clobber_and_symlink_sources_fail_before_publication(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    output = tmp_path / "bundle"
    output.mkdir()
    with pytest.raises(bundle.BrokerBundleError, match="already exists"):
        bundle.materialize_bundle(
            inputs["runtime"],
            inputs["binding"],
            inputs["profile"],
            inputs["launch"],
            {"runner.py": inputs["broker"]},
            output,
            lineage_id="campaign-v8",
        )
    output.rmdir()
    alias = tmp_path / "alias.py"
    alias.symlink_to(inputs["broker"])
    with pytest.raises(bundle.BrokerBundleError, match="exact input"):
        bundle.materialize_bundle(
            inputs["runtime"],
            inputs["binding"],
            inputs["profile"],
            inputs["launch"],
            {"runner.py": alias},
            output,
            lineage_id="campaign-v8",
        )
    assert not output.exists()
    assert not (tmp_path / "bundle.receipt.json").exists()


def test_extra_empty_directory_and_entrypoint_mismatch_fail_closed(tmp_path: Path) -> None:
    _inputs_used_by_bundle, output, receipt_path = _materialize(tmp_path)
    try:
        output.chmod(0o700)
        extra = output / "unmanifested"
        extra.mkdir(mode=0o500)
        output.chmod(0o500)
        with pytest.raises(bundle.BrokerBundleError, match="bundle inventory changed"):
            bundle.verify_bundle(receipt_path)
    finally:
        _unlock(output)

    second = tmp_path / "second"
    second.mkdir(mode=0o700)
    other = _inputs(second)
    launch = json.loads(other["launch"].read_bytes())
    launch["broker_entrypoint_sha256"] = "sha256:" + "f" * 64
    _write(other["launch"], launch)
    with pytest.raises(bundle.BrokerBundleError, match="entrypoint is not exactly bundled"):
        bundle.materialize_bundle(
            other["runtime"],
            other["binding"],
            other["profile"],
            other["launch"],
            {"runner.py": other["broker"]},
            second / "bundle",
            lineage_id="campaign-v8",
        )
    assert not (second / "bundle").exists()


def test_receipt_and_freeze_are_new_lineage_only_not_ledger_events(tmp_path: Path) -> None:
    inputs, output, receipt_path = _materialize(tmp_path)
    freeze_path = tmp_path / "prepare-freeze.json"
    try:
        bundle.prepare_freeze(
            receipt_path,
            inputs["runtime"],
            inputs["binding"],
            inputs["profile"],
            inputs["launch"],
            freeze_path,
            clock=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        names = {path.name for path in tmp_path.iterdir()}
        assert "lane-events" not in names
        assert "ledger-v7" not in names
        assert "escrow" not in names
        assert "review-canary-authorization.json" not in names
        assert "runtime-attestation-supersession-001.json" not in names
        assert receipt_path.parent.samefile(freeze_path.parent)
    finally:
        _unlock(output)
