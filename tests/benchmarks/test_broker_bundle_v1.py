"""Hermetic governance tests for immutable broker execution bundles."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, cast

import pytest
from benchmarks.real_world import broker_bundle_v1 as bundle
from benchmarks.real_world.ground_truth_v2.schema import canonical_json

if TYPE_CHECKING:
    import os
    from pathlib import Path

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def _write(path: Path, value: dict[str, Any] | bytes) -> None:
    raw = value if isinstance(value, bytes) else canonical_json(value)
    path.write_bytes(raw)
    path.chmod(0o644)


def _unlock(root: Path) -> None:
    if not root.exists():
        return
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_dir():
            path.chmod(0o700)
        else:
            path.chmod(0o600)
    root.chmod(0o700)


def _runtime_identity() -> dict[str, Any]:
    identity = {"path": "/runtime/file", "sha256": DIGEST_A, "bytes": 1}
    roots = [
        {"kind": kind, "path": f"/roots/{kind}", "exists": False}
        for kind in ("project-old", "project-new", "user-old", "user-new", "builtin")
    ]
    census = {
        "roots": {
            "userDir": "/user",
            "projectDir": "/project",
            "userSettingsPath": "/user/settings.json",
            "projectSettingsPath": "/project/settings.json",
        },
        "effective": [],
        "builtin": [],
        "package": [],
        "user": [],
        "project": [],
    }
    return {
        "schema_version": 1,
        "pi_subagents_version": "0.35.1",
        "pi_version": "0.80.10",
        "pi_package": identity,
        "runtime_files": dict.fromkeys(
            (
                "package",
                "agents",
                "schemas",
                "pi_args",
                "foreground_execution",
                "foreground_executor",
            ),
            identity,
        ),
        "config": {**identity, "intercom_mode": "off"},
        "roots": roots,
        "resolver_census": census,
        "resolver_census_sha256": bundle._sha(canonical_json(census)),
        "resolver_execution": {
            "node_path": "/usr/bin/node",
            "node_sha256": DIGEST_A,
            "script_sha256": DIGEST_A,
            "argv_sha256": DIGEST_A,
            "timeout_seconds": 30,
            "network_authorized": False,
            "shell": False,
        },
    }


def _binding(runtime_hash: str, profile_hash: str, profile_files_hash: str) -> dict[str, Any]:
    selection = {
        "schema_version": 1,
        "protocol": "ground-truth-packet-selection-receipt-v1",
        "runtime_attestation_entry_hash": runtime_hash,
        "runtime_custody_receipt_sha256": DIGEST_A,
        "rank": 1,
        "repository": "owner/repo",
        "pr": 1,
        "packet_root_sha256": DIGEST_A,
        "aggregate_root_sha256": DIGEST_A,
        "publication_entry_hash": DIGEST_A,
        "cache_inventory_sha256": DIGEST_A,
        "packet_inventory_sha256": DIGEST_A,
        "commands": 5,
        "authorizations": {
            "review_launch": False,
            "adjudication": False,
            "canonical_import": False,
        },
    }
    names = (
        "packet_manifest",
        "source_structure",
        "review_prompt",
        "model_policy",
        "tool_policy",
        "source_policy",
    )
    record = {
        "schema_version": 1,
        "generation": 1,
        "attempt_id": "attempt-1",
        "capability": "a" * 64,
        "packet_path": "/private/packet",
        "packet_device": 1,
        "packet_inode": 1,
        "packet_manifest_sha256": DIGEST_A,
        "packet_root_sha256": DIGEST_A,
        "blob_inventory_sha256": DIGEST_A,
        "source_structure_sha256": DIGEST_A,
        "packet_inventory_sha256": DIGEST_A,
        "original_packet_path": "/private/original",
        "campaign_path": "/private/campaign.json",
        "source_bindings_path": "/private/source-bindings.json",
        "ledger_root": "/private/ledger",
        "packets_root": "/private/packets",
        "runtime_attestation_entry_hash": runtime_hash,
        "runtime_custody_receipt_path": "/private/custody.json",
        "runtime_custody_receipt_sha256": DIGEST_A,
        "selection_custody": selection,
        "original_packet_root_sha256": DIGEST_A,
        "aggregate_root_sha256": DIGEST_A,
        "publication_entry_hash": DIGEST_A,
        "source_bindings_sha256": DIGEST_A,
        "cache_device": 1,
        "cache_inode": 1,
        "cache_inventory_sha256": DIGEST_A,
        "authenticated_inputs": [
            {"name": name, "path": f"/private/{name}", "sha256": DIGEST_A, "bytes": 1, "mode": 256}
            for name in names
        ],
        "profile_checksum_sha256": profile_hash,
        "profile_files_sha256": profile_files_hash,
        "escrow_path": "/private/escrow/review.json",
        "cache_root": "/private/cache",
        "corpus_id": "fixture",
        "repository": "owner/repo",
        "pr": 1,
        "rank": 1,
        "lane": "A",
        "snapshots": {"baseline_commit": "1" * 40, "target_commit": "2" * 40},
        "baseline_tree": "3" * 40,
        "target_tree": "4" * 40,
        "reviewer": {"kind": "agent", "name": "reviewer", "version": "v1"},
        "run": {
            "prompt_sha256": DIGEST_A,
            "model_policy_sha256": DIGEST_A,
            "tool_policy_sha256": DIGEST_A,
            "source_policy_sha256": DIGEST_A,
            "started_at": "2026-01-01T00:00:00Z",
            "limits": {
                "max_tokens": 1,
                "max_tool_calls": 1,
                "max_seconds": 1,
                "max_output_bytes": 1,
            },
        },
        "max_validation_attempts": 1,
    }
    return {
        "schema_version": 1,
        "protocol": "ground-truth-review-submit-v1",
        "records": [record],
    }


def _inputs(tmp_path: Path) -> dict[str, Path]:
    tmp_path.chmod(0o700)
    profile = tmp_path / "production-profile.json"
    profile_value = {
        "schema_version": 1,
        "id": "ground-truth-production-checksums-v1",
        "files": {"broker/runtime.py": DIGEST_A},
    }
    _write(profile, profile_value)
    profile_hash = bundle._sha(profile.read_bytes())
    profile_files_hash = bundle._sha(canonical_json(profile_value["files"]))
    runtime = tmp_path / "runtime-attestation.json"
    runtime_value = {
        "schema_version": 2,
        "protocol": "ground-truth-runtime-attestation-v1",
        "campaign_id": "fixture",
        "campaign_manifest_sha256": DIGEST_A,
        "campaign_lanes_sha256": DIGEST_A,
        "source_bindings_sha256": DIGEST_A,
        "packet_publication_entry_hash": DIGEST_A,
        "runtime_custody_receipt_path": "/private/custody.json",
        "runtime_custody_receipt_sha256": DIGEST_A,
        "production_profile_sha256": profile_hash,
        "production_files_sha256": profile_files_hash,
        "runtime_identity": _runtime_identity(),
        "extension_sha256": DIGEST_A,
        "extension_schema_sha256": DIGEST_A,
        "agent_source_sha256": DIGEST_A,
        "execution_root": "/private/execution",
        "execution_device": 1,
        "execution_inode": 1,
        "attested_at": "2026-01-01T00:00:00Z",
        "authorizations": {
            "review_launch": False,
            "adjudication": False,
            "canonical_import": False,
        },
        "previous_hash": DIGEST_A,
    }
    runtime_value["entry_hash"] = bundle._sha(
        b"ground-truth-runtime-attestation-v1\0" + canonical_json(runtime_value)
    )
    _write(runtime, runtime_value)
    binding = tmp_path / "binding.json"
    _write(
        binding,
        _binding(cast("str", runtime_value["entry_hash"]), profile_hash, profile_files_hash),
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
            "agent_sha256": DIGEST_B,
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
    bundle.materialize_bundle(
        inputs["runtime"],
        inputs["binding"],
        inputs["profile"],
        inputs["launch"],
        {"runner.py": inputs["broker"], "pkg/helper.py": inputs["helper"]},
        output,
        lineage_id="campaign-v8",
    )
    return inputs, output, output / bundle._RECEIPT_NAME


def _prepare(tmp_path: Path) -> tuple[dict[str, Path], Path, Path, Path]:
    inputs, output, receipt = _materialize(tmp_path)
    freeze = tmp_path / "prepare-freeze.json"
    bundle.prepare_freeze(
        receipt,
        inputs["runtime"],
        inputs["binding"],
        inputs["profile"],
        inputs["launch"],
        freeze,
        clock=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    return inputs, output, receipt, freeze


def test_atomic_bundle_and_monotonic_freeze_grant_no_authority(tmp_path: Path) -> None:
    inputs, output, receipt_path, freeze_path = _prepare(tmp_path)
    try:
        receipt = bundle.verify_bundle(receipt_path)
        with pytest.raises(bundle.BrokerBundleError, match="replay or out-of-order"):
            bundle.verify_freeze(
                freeze_path,
                inputs["runtime"],
                inputs["binding"],
                inputs["profile"],
                inputs["launch"],
                phase="prepared",
            )
        for phase in ("launch_claimed", "pre_escrow"):
            bundle.verify_freeze(
                freeze_path,
                inputs["runtime"],
                inputs["binding"],
                inputs["profile"],
                inputs["launch"],
                phase=phase,
            )
        with pytest.raises(bundle.BrokerBundleError, match="replay or out-of-order"):
            bundle.verify_freeze(
                freeze_path,
                inputs["runtime"],
                inputs["binding"],
                inputs["profile"],
                inputs["launch"],
                phase="pre_escrow",
            )
        assert receipt_path.parent == output
        assert all(value is False for value in receipt["authorizations"].values())
        assert all(
            all(
                value is False
                for value in json.loads(
                    bundle._phase_path(freeze_path, phase).read_bytes()
                )["authorizations"].values()
            )
            for phase in bundle._FREEZE_PHASES
        )
        assert not (tmp_path / "escrow").exists()
        assert not list(tmp_path.rglob("*review.json"))
        assert not list(tmp_path.rglob("*label*"))
    finally:
        _unlock(output)


def test_out_of_order_phase_and_concurrent_replay_are_rejected(tmp_path: Path) -> None:
    inputs, output, _receipt, freeze = _prepare(tmp_path)
    try:
        with pytest.raises(bundle.BrokerBundleError, match="out-of-order"):
            bundle.verify_freeze(
                freeze,
                inputs["runtime"],
                inputs["binding"],
                inputs["profile"],
                inputs["launch"],
                phase="pre_escrow",
            )

        def claim() -> bool:
            try:
                bundle.verify_freeze(
                    freeze,
                    inputs["runtime"],
                    inputs["binding"],
                    inputs["profile"],
                    inputs["launch"],
                    phase="launch_claimed",
                )
            except bundle.BrokerBundleError:
                return False
            return True

        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(lambda _: claim(), range(2))) == [False, True]
    finally:
        _unlock(output)


def test_verify_revalidates_descriptors_after_active_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _inputs_used, output, receipt = _materialize(tmp_path)
    copied = output / "control/runtime-attestation.json"
    original = bundle._read_fd
    mutated = False

    def mutate_after_read(descriptor: int, status: os.stat_result, label: str) -> bytes:
        nonlocal mutated
        raw = original(descriptor, status, label)
        if label == "control/runtime-attestation.json" and not mutated:
            mutated = True
            copied.chmod(0o600)
            copied.write_bytes(b"MUTATED\n")
            copied.chmod(0o400)
        return raw

    monkeypatch.setattr(bundle, "_read_fd", mutate_after_read)
    try:
        with pytest.raises(bundle.BrokerBundleError):
            bundle.verify_bundle(receipt)
        assert mutated
    finally:
        _unlock(output)


def test_concurrent_builders_publish_exactly_one_enclosing_object(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    output = tmp_path / "bundle"

    def build() -> bool:
        try:
            bundle.materialize_bundle(
                inputs["runtime"],
                inputs["binding"],
                inputs["profile"],
                inputs["launch"],
                {"runner.py": inputs["broker"]},
                output,
                lineage_id="campaign-v8",
            )
        except bundle.BrokerBundleError:
            return False
        return True

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(lambda _: build(), range(2))) == [False, True]
        assert (output / bundle._RECEIPT_NAME).is_file()
    finally:
        _unlock(output)


def test_publication_crash_window_exposes_neither_bundle_nor_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    output = tmp_path / "bundle"

    def crash(*_args: object) -> None:
        raise OSError("simulated crash")

    monkeypatch.setattr(bundle, "_rename_noreplace_at", crash)
    with pytest.raises(bundle.BrokerBundleError, match="simulated crash"):
        bundle.materialize_bundle(
            inputs["runtime"],
            inputs["binding"],
            inputs["profile"],
            inputs["launch"],
            {"runner.py": inputs["broker"]},
            output,
            lineage_id="campaign-v8",
        )
    assert not output.exists()
    assert not list(tmp_path.glob(".bundle.*"))


def test_cross_lineage_rehash_is_rejected(tmp_path: Path) -> None:
    _inputs_used, output, receipt_path = _materialize(tmp_path)
    try:
        receipt_path.chmod(0o600)
        receipt = json.loads(receipt_path.read_bytes())
        receipt["lineage_id"] = "other-lineage"
        body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        receipt["receipt_sha256"] = bundle._sha(canonical_json(body))
        receipt_path.write_bytes(canonical_json(receipt))
        receipt_path.chmod(0o400)
        with pytest.raises(bundle.BrokerBundleError, match=r"manifest and receipt|lineage root"):
            bundle.verify_bundle(receipt_path)
    finally:
        _unlock(output)


def test_rehashed_freeze_cannot_cross_lineage(tmp_path: Path) -> None:
    inputs, output, _receipt_path, freeze_path = _prepare(tmp_path)
    try:
        freeze_path.chmod(0o600)
        freeze = json.loads(freeze_path.read_bytes())
        freeze["lineage_id"] = "other-lineage"
        body = {key: value for key, value in freeze.items() if key != "freeze_sha256"}
        freeze["freeze_sha256"] = bundle._sha(canonical_json(body))
        freeze_path.write_bytes(canonical_json(freeze))
        freeze_path.chmod(0o400)
        with pytest.raises(bundle.BrokerBundleError, match="lineage root"):
            bundle.verify_freeze(
                freeze_path,
                inputs["runtime"],
                inputs["binding"],
                inputs["profile"],
                inputs["launch"],
                phase="launch_claimed",
            )
    finally:
        _unlock(output)


@pytest.mark.parametrize("target", ["runtime", "binding", "profile", "launch"])
def test_unknown_control_versions_are_rejected(tmp_path: Path, target: str) -> None:
    inputs = _inputs(tmp_path)
    value = json.loads(inputs[target].read_bytes())
    value["schema_version"] = 999
    _write(inputs[target], value)
    with pytest.raises(bundle.BrokerBundleError):
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


def test_exact_manifest_receipt_and_freeze_schemas_reject_extra_keys(tmp_path: Path) -> None:
    inputs, output, receipt, freeze = _prepare(tmp_path)
    manifest = output / "manifest.json"
    try:
        for path, verifier in (
            (manifest, lambda: bundle.verify_bundle(receipt)),
            (receipt, lambda: bundle.verify_bundle(receipt)),
            (
                freeze,
                lambda: bundle.verify_freeze(
                    freeze,
                    inputs["runtime"],
                    inputs["binding"],
                    inputs["profile"],
                    inputs["launch"],
                    phase="launch_claimed",
                ),
            ),
        ):
            original = path.read_bytes()
            path.chmod(0o600)
            value = json.loads(original)
            value["unexpected"] = False
            path.write_bytes(canonical_json(value))
            path.chmod(0o400)
            with pytest.raises(bundle.BrokerBundleError, match="keys are invalid"):
                verifier()
            path.chmod(0o600)
            path.write_bytes(original)
            path.chmod(0o400)
    finally:
        _unlock(output)


def test_ancestor_alias_and_protected_destination_are_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    inputs = _inputs(real)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(bundle.BrokerBundleError, match="descriptor walk"):
        bundle.materialize_bundle(
            inputs["runtime"],
            inputs["binding"],
            inputs["profile"],
            inputs["launch"],
            {"runner.py": inputs["broker"]},
            alias / "bundle",
            lineage_id="campaign-v8",
        )
    protected = tmp_path / "production_v1"
    protected.mkdir(mode=0o700)
    with pytest.raises(bundle.BrokerBundleError, match="protected historical"):
        bundle.materialize_bundle(
            inputs["runtime"],
            inputs["binding"],
            inputs["profile"],
            inputs["launch"],
            {"runner.py": inputs["broker"]},
            protected / "bundle",
            lineage_id="campaign-v8",
        )


def test_active_lineage_root_replacement_exposes_nothing_at_live_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    output = tmp_path / "bundle"
    displaced = tmp_path.with_name(f"{tmp_path.name}-displaced")
    original = bundle._sync_staged_directories
    replaced = False

    def replace_after_staging(staging_fd: int, directories: set[str]) -> None:
        nonlocal replaced
        original(staging_fd, directories)
        tmp_path.rename(displaced)
        tmp_path.mkdir(mode=0o700)
        replaced = True

    monkeypatch.setattr(bundle, "_sync_staged_directories", replace_after_staging)
    try:
        with pytest.raises(bundle.BrokerBundleError, match="lineage root changed"):
            bundle.materialize_bundle(
                inputs["runtime"],
                inputs["binding"],
                inputs["profile"],
                inputs["launch"],
                {"runner.py": inputs["broker"]},
                output,
                lineage_id="campaign-v8",
            )
        assert replaced
        assert not (tmp_path / "bundle").exists()
        assert not (tmp_path / bundle._ROOT_MARKER).exists()
        assert not (tmp_path / bundle._RECEIPT_NAME).exists()
        assert not (displaced / "bundle").exists()
        assert not list(displaced.glob(".bundle.*"))
    finally:
        _unlock(displaced)
        tmp_path.rmdir()
        displaced.rename(tmp_path)


@pytest.mark.parametrize(
    "protected_name", ["production_v1", "ledger-v7", "ledger_v7", "escrow", "reviews", "labels"]
)
def test_protected_final_bundle_component_is_rejected_before_root_state(
    tmp_path: Path, protected_name: str
) -> None:
    inputs = _inputs(tmp_path)
    with pytest.raises(bundle.BrokerBundleError, match="protected historical"):
        bundle.materialize_bundle(
            inputs["runtime"],
            inputs["binding"],
            inputs["profile"],
            inputs["launch"],
            {"runner.py": inputs["broker"]},
            tmp_path / protected_name,
            lineage_id="campaign-v8",
        )
    assert not (tmp_path / protected_name).exists()
    assert not (tmp_path / bundle._ROOT_MARKER).exists()
    assert not (tmp_path / bundle._ROOT_LOCK).exists()


def test_protected_freeze_basename_and_derived_phases_are_never_created(tmp_path: Path) -> None:
    inputs, output, receipt = _materialize(tmp_path)
    freeze = tmp_path / "escrow"
    try:
        with pytest.raises(bundle.BrokerBundleError, match="protected historical"):
            bundle.prepare_freeze(
                receipt,
                inputs["runtime"],
                inputs["binding"],
                inputs["profile"],
                inputs["launch"],
                freeze,
            )
        assert not freeze.exists()
        assert not any(
            bundle._phase_path(freeze, phase).exists() for phase in bundle._FREEZE_PHASES
        )
    finally:
        _unlock(output)


def test_authority_rebinding_and_mutation_cannot_authorize_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attacker_map = bundle._false_authority_map()
    attacker_map["escrow"] = True
    monkeypatch.setattr(bundle, "_FALSE_AUTHORITY", attacker_map, raising=False)
    inputs, output, receipt, freeze = _prepare(tmp_path)
    try:
        bundle.verify_freeze(
            freeze,
            inputs["runtime"],
            inputs["binding"],
            inputs["profile"],
            inputs["launch"],
            phase="launch_claimed",
        )
        artifacts = [
            tmp_path / bundle._ROOT_MARKER,
            output / "manifest.json",
            receipt,
            freeze,
            *(bundle._phase_path(freeze, phase) for phase in ("prepared", "launch_claimed")),
        ]
        for path in artifacts:
            authority = json.loads(path.read_bytes())["authorizations"]
            assert set(authority) == {
                "review_launch",
                "escrow",
                "adjudication",
                "canonical_import",
            }
            assert all(value is False for value in authority.values())
        fresh = bundle._false_authority_map()
        assert fresh is not attacker_map
        assert all(value is False for value in fresh.values())
        for invalid in (
            {**fresh, "escrow": True},
            {**fresh, "escrow": 0},
            {key: False for key in fresh if key != "escrow"},
        ):
            with pytest.raises(bundle.BrokerBundleError, match="authority map is invalid"):
                bundle._false_authority(invalid, "probe")
    finally:
        _unlock(output)


def test_staged_bundle_and_atomic_documents_follow_durability_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    original_sync = bundle._fsync
    original_rename = bundle._rename_noreplace_at

    def record_sync(descriptor: int, label: str) -> None:
        events.append(label)
        original_sync(descriptor, label)

    def record_rename(parent_fd: int, source: str, target: str) -> None:
        events.append(f"rename:{target}")
        original_rename(parent_fd, source, target)

    monkeypatch.setattr(bundle, "_fsync", record_sync)
    monkeypatch.setattr(bundle, "_rename_noreplace_at", record_rename)
    _inputs_used, output, _receipt, freeze = _prepare(tmp_path)
    try:
        bundle_start = next(
            index for index, event in enumerate(events) if event.startswith("staged-file:")
        )
        bundle_rename = events.index("rename:bundle")
        publication = events[bundle_start : bundle_rename + 2]
        file_positions = [
            index for index, event in enumerate(publication) if event.startswith("staged-file:")
        ]
        directory_positions = [
            index
            for index, event in enumerate(publication)
            if event.startswith("staged-directory:")
        ]
        assert len(file_positions) == 8
        assert file_positions and directory_positions
        assert max(file_positions) < min(directory_positions)
        assert max(directory_positions) < publication.index("rename:bundle")
        assert publication[-1] == f"directory:{tmp_path}"
        assert publication.index("staged-directory:broker/pkg") < publication.index(
            "staged-directory:broker"
        )
        for name in (
            bundle._ROOT_MARKER,
            freeze.name,
            bundle._phase_path(freeze, "prepared").name,
        ):
            rename_index = events.index(f"rename:{name}")
            assert events[rename_index - 1] == f"file:{name}"
            assert events[rename_index + 1] == f"directory:{tmp_path}"
    finally:
        _unlock(output)


def test_orphan_freeze_state_fails_closed_without_clobber(tmp_path: Path) -> None:
    inputs, output, receipt = _materialize(tmp_path)
    freeze = tmp_path / "prepare-freeze.json"
    orphan = bundle._phase_path(freeze, "prepared")
    orphan.write_bytes(canonical_json({"orphan": True}))
    orphan.chmod(0o400)
    try:
        with pytest.raises(bundle.BrokerBundleError, match="orphan freeze phase"):
            bundle.prepare_freeze(
                receipt,
                inputs["runtime"],
                inputs["binding"],
                inputs["profile"],
                inputs["launch"],
                freeze,
            )
        assert not freeze.exists()
    finally:
        _unlock(output)
