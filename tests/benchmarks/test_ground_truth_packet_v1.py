from __future__ import annotations

import copy
import hashlib
import json
import shutil
import stat
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from benchmarks.real_world import ground_truth_campaign_v1 as campaign
from benchmarks.real_world import ground_truth_packet_v1 as packet
from benchmarks.real_world import ground_truth_source_v1 as source
from benchmarks.real_world import pilot_packet_v2 as packet_primitives
from benchmarks.real_world.ground_truth_v2.schema import canonical_json

ROOT = Path(__file__).resolve().parents[2]


def _git(git_dir: Path, *args: str, data: bytes | None = None) -> str:
    result = subprocess.run(
        ["git", "--git-dir", str(git_dir), *args],
        input=data,
        capture_output=True,
        check=True,
    )
    return result.stdout.decode().strip()


def _bare_fixture(tmp_path: Path) -> tuple[Path, list[dict[str, Any]]]:
    cache = tmp_path / "source.git"
    subprocess.run(["git", "init", "--bare", str(cache)], capture_output=True, check=True)
    empty_tree = _git(cache, "mktree", data=b"")
    gitlink = _git(cache, "commit-tree", empty_tree, "-m", "gitlink")
    regular = _git(cache, "hash-object", "-w", "--stdin", data=b"regular\n")
    executable = _git(cache, "hash-object", "-w", "--stdin", data=b"#!/bin/sh\n")
    link = _git(cache, "hash-object", "-w", "--stdin", data=b"regular.txt")
    baseline_tree = _git(
        cache,
        "mktree",
        data=(
            f"100644 blob {regular}\tregular.txt\n"
            f"100755 blob {executable}\texecutable.sh\n"
            f"120000 blob {link}\tlink\n"
            f"160000 commit {gitlink}\tvendor\n"
        ).encode(),
    )
    baseline = _git(cache, "commit-tree", baseline_tree, "-m", "baseline")
    changed = _git(cache, "hash-object", "-w", "--stdin", data=b"changed\n")
    target_tree = _git(
        cache,
        "mktree",
        data=(
            f"100644 blob {changed}\tregular.txt\n"
            f"100755 blob {executable}\texecutable.sh\n"
            f"120000 blob {link}\tlink\n"
            f"160000 commit {gitlink}\tvendor\n"
        ).encode(),
    )
    target = _git(cache, "commit-tree", target_tree, "-p", baseline, "-m", "target")
    records = [
        {
            "rank": index + 1,
            "repository": "owner/repository",
            "pr": 1000 + index,
            "baseline_commit": baseline,
            "baseline_tree": baseline_tree,
            "target_commit": target,
            "target_tree": target_tree,
            "diff_sha256": "sha256:" + f"{index + 1:064x}",
            "diff_bytes": index + 1,
            "diff_content_type": "text/plain; charset=utf-8",
            "diff_final_url": f"https://example.invalid/{1000 + index}.diff",
        }
        for index in range(50)
    ]
    return cache, records


def _freeze(path: Path) -> None:
    packet._freeze(path)


def test_build_packet_modes_symlink_gitlink_and_diff_distinction(tmp_path: Path) -> None:
    cache, records = _bare_fixture(tmp_path)
    staging = tmp_path / "staging"
    staging.mkdir()
    budget = packet.AggregateBudget(staging, packet._STAGING_LIMIT)
    profile = packet._profile(ROOT)
    counter = [0]
    manifest, commands = packet._build_packet(
        cache,
        staging / "packet",
        records[0],
        "sha256:" + "a" * 64,
        time.monotonic() + 60,
        budget,
        profile.files,
        counter,
    )
    assert commands == 5
    assert manifest["remote_diff"]["payload_present"] is False
    assert manifest["local_snapshot"]["relation_to_remote"] == "not_compared"
    assert manifest["local_snapshot"]["sha256"] != records[0]["diff_sha256"]
    structure = json.loads((staging / "packet/source-structure.json").read_bytes())
    assert structure["baseline"]["symlinks"][0]["target_hex"] == b"regular.txt".hex()
    assert structure["baseline"]["gitlinks"] == [
        {
            "path": "vendor",
            "commit": structure["baseline"]["gitlinks"][0]["commit"],
            "contents_omitted": True,
        }
    ]
    assert not (staging / "packet/baseline/link").exists()
    assert not (staging / "packet/baseline/vendor").exists()
    assert stat.S_IMODE((staging / "packet/baseline/executable.sh").stat().st_mode) == 0o444
    _freeze(staging / "packet")
    packet._validate_one_packet(staging / "packet", records[0], "sha256:" + "a" * 64, profile.files)


def test_exact_fifty_build_uses_250_commands_and_validates_aggregate(tmp_path: Path) -> None:
    cache, records = _bare_fixture(tmp_path)
    staging = tmp_path / "aggregate"
    staging.mkdir()
    budget = packet.AggregateBudget(staging, packet._STAGING_LIMIT)
    commands = 0
    packet_rows: list[dict[str, Any]] = []
    deadline = time.monotonic() + 300
    bindings_raw = canonical_json({"records": records})
    profile = packet._profile(ROOT)
    counter = [0]
    for record in records:
        name = packet._packet_name(record)
        manifest, used = packet._build_packet(
            cache,
            staging / name,
            record,
            packet._sha(bindings_raw),
            deadline,
            budget,
            profile.files,
            counter,
        )
        commands += used
        packet_rows.append(
            {
                "rank": record["rank"],
                "repository": record["repository"],
                "pr": record["pr"],
                "directory": name,
                "packet_root_sha256": manifest["packet_root_sha256"],
            }
        )
    assert commands == 250
    assert len({packet._packet_name(row) for row in records}) == 50
    campaign_value = {"id": "campaign", "records": records}
    campaign_raw = canonical_json(campaign_value)
    receipt = {"entry_hash": "sha256:" + "c" * 64}
    inventory = packet._inventory(
        staging,
        limit=packet._MAX_AGGREGATE_PAYLOAD,
        max_entries=packet._MAX_AGGREGATE_ENTRIES,
    )
    aggregate = packet._aggregate_manifest(
        campaign_value,
        campaign_raw,
        bindings_raw,
        receipt,
        packet_rows,
        "2026-01-01T00:00:00Z",
        inventory,
    )
    (staging / "aggregate-manifest.json").write_bytes(canonical_json(aggregate))
    packet._freeze(staging)
    validated = packet._validate_published(
        campaign_value,
        campaign_raw,
        {"records": records},
        bindings_raw,
        cache,
        staging,
        receipt,
        profile,
        regenerate=False,
    )
    assert validated["packets"] == packet_rows
    aggregate_path = staging / "aggregate-manifest.json"
    staging.chmod(0o700)
    aggregate_path.chmod(0o600)
    tampered = copy.deepcopy(aggregate)
    tampered["packets"].reverse()
    tampered["aggregate_root_sha256"] = packet._aggregate_root(tampered)
    aggregate_path.write_bytes(canonical_json(tampered))
    aggregate_path.chmod(0o400)
    staging.chmod(0o500)
    with pytest.raises(packet.PacketV1Error, match="ordering"):
        packet._validate_published(
            campaign_value,
            campaign_raw,
            {"records": records},
            bindings_raw,
            cache,
            staging,
            receipt,
            profile,
            regenerate=False,
        )


@pytest.mark.parametrize("count", [49, 51])
def test_aggregate_manifest_cardinality_is_rejected(tmp_path: Path, count: int) -> None:
    value = {
        "schema_version": 1,
        "id": packet._AGGREGATE_ID,
        "campaign_id": "campaign",
        "campaign_manifest_sha256": "sha256:" + "1" * 64,
        "source_bindings_sha256": "sha256:" + "2" * 64,
        "authorization_entry_hash": "sha256:" + "3" * 64,
        "publication_timestamp": "2026-01-01T00:00:00Z",
        "packet_count": count,
        "packets": [{}] * count,
        "payload_bytes": 0,
        "payload_entries": 1,
        "aggregate_root_sha256": "",
    }
    value["aggregate_root_sha256"] = packet._aggregate_root(value)
    with pytest.raises(packet.PacketV1Error, match="cardinality"):
        packet._validate_aggregate_header(value)


def test_forbidden_reviewer_keys_and_host_paths_fail() -> None:
    with pytest.raises(packet.PacketV1Error, match="forbidden key"):
        packet._forbidden_scan({"lane": "A"})
    with pytest.raises(packet.PacketV1Error, match="host path"):
        packet._forbidden_scan({"path": "/home/user/cache"})


def test_unsafe_tree_paths_fail() -> None:
    with pytest.raises(Exception, match=r"escapes|invalid|conflicts"):
        packet_primitives._parse_tree(b"100644 blob " + b"1" * 40 + b"\t../bad\0")


def _ledger_campaign(tmp_path: Path) -> tuple[Path, Path, dict[str, Any]]:
    manifest = (tmp_path / "campaign.json").resolve()
    value = campaign.build_manifest(ROOT, 149, "fastapi/full-stack-fastapi-template")
    campaign._publish(manifest, value)
    ledger = tmp_path / "ledger"
    ledger.mkdir(mode=0o700)
    campaign.init_ledger(ledger.resolve(), manifest, ROOT)
    return manifest, ledger.resolve(), value


def test_campaign_ledger_accepts_exact_one_packet_transition(tmp_path: Path) -> None:
    manifest, ledger, value = _ledger_campaign(tmp_path)
    genesis = campaign.validate_ledger(ledger, ROOT)
    base = {
        "schema_version": 1,
        "protocol": packet._AUTH_PROTOCOL,
        "campaign_id": value["id"],
        "campaign_manifest_sha256": genesis["campaign_manifest_sha256"],
        "source_bindings_sha256": "sha256:" + "1" * 64,
        "cache_content_sha256": "sha256:" + "2" * 64,
        "cache_device": 1,
        "cache_inode": 2,
        "issue": 149,
        "repository": "fastapi/full-stack-fastapi-template",
        "pr_count": 50,
        "lane_count": 100,
        "production_profile_sha256": "sha256:" + "3" * 64,
        "output_parent": str(tmp_path),
        "output_basename": "packets",
        "output_parent_device": tmp_path.stat().st_dev,
        "output_parent_inode": tmp_path.stat().st_ino,
        "limits": packet._limits(),
        "authorizations": {
            "packet_materialization": True,
            "live_launch": False,
            "canonical_import": False,
        },
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-02T00:00:00Z",
        "previous_hash": genesis["entry_hash"],
    }
    transition = {**base, "entry_hash": packet._authorization_hash(base)}
    campaign._publish(ledger / packet._AUTH_FILE, transition)
    validated = campaign.validate_ledger(ledger, ROOT)
    assert validated["packet_authorization_present"] is True
    assert validated["packet_publication_present"] is False
    assert validated["entry_hash"] == transition["entry_hash"]
    publication_base = {
        "schema_version": 1,
        "protocol": packet._PUBLICATION_PROTOCOL,
        "campaign_id": value["id"],
        "campaign_manifest_sha256": genesis["campaign_manifest_sha256"],
        "authorization_entry_hash": transition["entry_hash"],
        "source_bindings_sha256": transition["source_bindings_sha256"],
        "output_path": str(tmp_path / "packets"),
        "output_device": 1,
        "output_inode": 2,
        "aggregate_manifest_sha256": "sha256:" + "4" * 64,
        "aggregate_root_sha256": "sha256:" + "5" * 64,
        "inventory_sha256": "sha256:" + "6" * 64,
        "payload_entries": 1,
        "payload_bytes": 0,
        "publication_timestamp": "2026-01-01T12:00:00Z",
        "previous_hash": transition["entry_hash"],
    }
    publication = {
        **publication_base,
        "entry_hash": packet._publication_hash(publication_base),
    }
    campaign._publish(ledger / packet._PUBLICATION_FILE, publication)
    published = campaign.validate_ledger(ledger, ROOT)
    assert published["packet_publication_present"] is True
    assert published["entry_hash"] == publication["entry_hash"]
    tampered = copy.deepcopy(transition)
    tampered["authorizations"]["live_launch"] = True
    (ledger / packet._AUTH_FILE).chmod(0o600)
    (ledger / packet._AUTH_FILE).write_bytes(canonical_json(tampered))
    (ledger / packet._AUTH_FILE).chmod(0o400)
    with pytest.raises(campaign.CampaignV1Error, match="transition"):
        campaign.validate_ledger(ledger, ROOT)
    assert manifest.exists()


def test_authorize_layered_receipt_duplicate_and_output_parent_binding(  # noqa: PLR0915
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    ledger = private / "ledger"
    ledger.mkdir(mode=0o700)
    cache = private / "cache"
    cache.mkdir(mode=0o500)
    output = private / "packets"
    campaign_value = {
        "id": "campaign",
        "assignment": {"issue": 149, "repository": "owner/repository"},
        "records": [{}] * 50,
        "lanes": [{}] * 100,
    }
    campaign_raw = canonical_json(campaign_value)
    bindings = {
        "authorization": {
            "packet_materialization_authorized": False,
            "live_launch_authorized": False,
            "canonical_import_authorized": False,
        },
        "corpus_id": "oss-expansion-50x50-lock-v2",
        "cache": {"inventory_sha256": "sha256:" + "4" * 64},
        "records": [{}] * 50,
    }
    bindings_raw = canonical_json(bindings)
    cache_summary = {
        "content_sha256": "sha256:" + "5" * 64,
        "cache_device": cache.stat().st_dev,
        "cache_inode": cache.stat().st_ino,
    }
    inventory = {"inventory_sha256": "sha256:" + "4" * 64}
    profile = packet.ProfileSnapshot({}, b"profile\n", {})
    monkeypatch.setattr(packet, "_profile", lambda _root: profile)
    monkeypatch.setattr(packet, "_historical_profile", lambda _root: profile)
    monkeypatch.setattr(packet, "_campaign", lambda _root, _path: (campaign_value, campaign_raw))
    monkeypatch.setattr(packet, "_bindings", lambda *_args: (bindings, bindings_raw, cache_summary))
    inventory_calls = 0
    drift_inventory = True

    def inventory_value(_cache: Path) -> dict[str, Any]:
        nonlocal inventory_calls
        inventory_calls += 1
        if drift_inventory and inventory_calls == 2:
            return {"inventory_sha256": "sha256:" + "9" * 64}
        return inventory

    monkeypatch.setattr(source, "_inventory", inventory_value)
    monkeypatch.setattr(campaign, "_private_root", lambda path: path)
    genesis_hash = "sha256:" + "6" * 64
    published_state = False

    def ledger_state(path: Path, _root: Path) -> dict[str, Any]:
        receipt_path = path / packet._AUTH_FILE
        return {
            "entry_hash": (
                json.loads(receipt_path.read_bytes())["entry_hash"]
                if receipt_path.exists()
                else genesis_hash
            ),
            "genesis_entry_hash": genesis_hash,
            "packet_authorization_present": receipt_path.exists(),
            "packet_authorization_entry_hash": (
                json.loads(receipt_path.read_bytes())["entry_hash"]
                if receipt_path.exists()
                else None
            ),
            "packet_publication_present": published_state,
            "packet_publication_entry_hash": ("sha256:" + "7" * 64 if published_state else None),
        }

    monkeypatch.setattr(campaign, "_validate_ledger_unlocked", ledger_state)
    monkeypatch.setattr(campaign, "validate_ledger", ledger_state)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(packet.PacketV1Error, match="precondition drifted"):
        packet.authorize_packets(
            ROOT, private / "campaign", private / "bindings", cache, ledger, output, now=now
        )
    assert not (ledger / packet._AUTH_FILE).exists()
    drift_inventory = False
    inventory_calls = 0
    result = packet.authorize_packets(
        ROOT, private / "campaign", private / "bindings", cache, ledger, output, now=now
    )
    assert result["authorized"] is True
    receipt = json.loads((ledger / packet._AUTH_FILE).read_bytes())
    assert receipt["authorizations"] == {
        "packet_materialization": True,
        "live_launch": False,
        "canonical_import": False,
    }
    assert receipt["production_profile_sha256"] == packet._sha(profile.raw)
    assert receipt["output_parent_device"] == private.stat().st_dev
    assert receipt["expires_at"] == "2026-01-02T00:00:00Z"
    with pytest.raises(packet.PacketV1Error, match="already exists"):
        packet.authorize_packets(
            ROOT, private / "campaign", private / "bindings", cache, ledger, output, now=now
        )
    expired = now + timedelta(days=2)
    with pytest.raises(packet.PacketV1Error, match="expired"):
        packet._receipt(
            ROOT,
            private / "campaign",
            private / "bindings",
            cache,
            ledger,
            output,
            require_unused=True,
            allow_expired=False,
            now=expired,
        )
    recovered = packet._receipt(
        ROOT,
        private / "campaign",
        private / "bindings",
        cache,
        ledger,
        output,
        require_unused=True,
        allow_expired=True,
        publication_timestamp="2026-01-01T12:00:00Z",
        now=expired,
    )
    assert recovered[0]["entry_hash"] == receipt["entry_hash"]
    published_state = True
    after_expiry = packet._receipt(
        ROOT,
        private / "campaign",
        private / "bindings",
        cache,
        ledger,
        output,
        require_unused=False,
        allow_expired=True,
        publication_timestamp="2026-01-01T12:00:00Z",
        now=expired,
    )
    assert after_expiry[0]["entry_hash"] == receipt["entry_hash"]
    with pytest.raises(packet.PacketV1Error, match="already been consumed"):
        packet._receipt(
            ROOT,
            private / "campaign",
            private / "bindings",
            cache,
            ledger,
            output,
            require_unused=True,
            allow_expired=True,
            publication_timestamp="2026-01-01T12:00:00Z",
            now=expired,
        )
    published_state = False
    with pytest.raises(packet.PacketV1Error, match="did not occur"):
        packet._receipt(
            ROOT,
            private / "campaign",
            private / "bindings",
            cache,
            ledger,
            output,
            require_unused=True,
            allow_expired=True,
            publication_timestamp="2026-01-03T00:00:00Z",
            now=expired,
        )


def test_build_existing_output_requires_finalize(tmp_path: Path) -> None:
    output = tmp_path / "packets"
    output.mkdir()
    with pytest.raises(packet.PacketV1Error, match="finalize-packets"):
        packet.build_packets(
            ROOT,
            tmp_path / "campaign",
            tmp_path / "bindings",
            tmp_path / "cache",
            tmp_path / "ledger",
            output,
        )


def test_finalize_packets_recovery_path_appends_successor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "packets"
    output.mkdir()
    aggregate = {
        "publication_timestamp": "2026-01-01T12:00:00Z",
        "aggregate_root_sha256": "sha256:" + "1" * 64,
    }
    (output / "aggregate-manifest.json").write_bytes(canonical_json(aggregate))
    (output / "aggregate-manifest.json").chmod(0o400)
    receipt = {"entry_hash": "sha256:" + "2" * 64}
    campaign_value = {"id": "campaign"}
    campaign_raw = canonical_json(campaign_value)
    bindings: dict[str, Any] = {"records": []}
    bindings_raw = canonical_json(bindings)
    profile = packet.ProfileSnapshot({}, b"profile", {})
    monkeypatch.setattr(
        packet,
        "_receipt",
        lambda *_args, **_kwargs: (
            receipt,
            campaign_value,
            campaign_raw,
            bindings,
            bindings_raw,
            {},
            profile,
            {},
        ),
    )
    monkeypatch.setattr(source, "_inventory", lambda _cache: {"sha256": "bound"})
    monkeypatch.setattr(
        packet,
        "_validate_published",
        lambda *_args, **_kwargs: aggregate,
    )
    monkeypatch.setattr(packet, "_reauthenticate_boundary", lambda *_args: None)
    appended: list[Path] = []

    def append(*args: Any) -> dict[str, Any]:
        appended.append(args[-1])
        return {"entry_hash": "sha256:" + "3" * 64}

    monkeypatch.setattr(packet, "_append_publication", append)
    result = packet.finalize_packets(
        ROOT,
        tmp_path / "campaign",
        tmp_path / "bindings",
        tmp_path / "cache",
        tmp_path / "ledger",
        output,
        now=datetime(2026, 1, 3, tzinfo=timezone.utc),
    )
    assert result["finalized"] is True
    assert appended == [output]


def test_publication_boundary_rejects_profile_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = packet.ProfileSnapshot({}, b"one", {})
    monkeypatch.setattr(
        packet,
        "_profile_by_hash",
        lambda _root, _digest: packet.ProfileSnapshot({}, b"two", {}),
    )
    monkeypatch.setattr(packet, "_bindings", lambda *_args: ({}, b"bindings", {}))
    monkeypatch.setattr(source, "_inventory", lambda _cache: {"inventory": "same"})
    with pytest.raises(packet.PacketV1Error, match="drifted at publication boundary"):
        packet._reauthenticate_boundary(
            ROOT,
            tmp_path / "campaign",
            tmp_path / "bindings",
            tmp_path / "cache",
            expected,
            {},
            b"bindings",
            {},
            {"inventory": "same"},
        )


def test_bindings_reject_bytes_changed_after_authenticated_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "bindings.json"
    value = {
        "authorization": {
            "packet_materialization_authorized": False,
            "live_launch_authorized": False,
            "canonical_import_authorized": False,
        },
        "corpus_id": "oss-expansion-50x50-lock-v2",
    }
    raw = canonical_json(value)
    path.write_bytes(raw)
    path.chmod(0o400)
    status = path.stat(follow_symlinks=False)
    monkeypatch.setattr(
        source,
        "validate_source_bindings",
        lambda *_args: {"sha256": "sha256:" + "0" * 64},
    )
    monkeypatch.setattr(source, "validate_cache", lambda *_args: {})
    monkeypatch.setattr(source, "_read_json", lambda *_args, **_kwargs: (value, raw, status))
    with pytest.raises(packet.PacketV1Error, match="changed after authenticated"):
        packet._bindings(ROOT, tmp_path / "campaign", tmp_path / "cache", path)


def test_authorization_timestamp_interval() -> None:
    issued = packet._parse_timestamp("2026-01-01T00:00:00Z")
    expires = packet._parse_timestamp("2026-01-02T00:00:00Z")
    assert expires - issued == timedelta(seconds=86400)
    with pytest.raises(packet.PacketV1Error, match="timestamp"):
        packet._parse_timestamp("2026-01-01T00:00:00+00:00")


def test_checksum_bound_pilot_dependency_api_shape() -> None:
    for name in (
        "GitRunner",
        "_snapshot_from_cache",
        "_hash_file",
        "_parse_tree",
    ):
        assert hasattr(packet_primitives, name)
    assert packet_primitives.GitRunner().commands == 0


def test_production_runner_refreshes_each_command_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [100.0]
    observed: list[float] = []

    def fake_run(self: Any, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        observed.append(self.deadline)

    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(packet_primitives.GitRunner, "run_to_path", fake_run)
    counter = [0]
    runner = packet.ProductionGitRunner(aggregate_deadline=1000.0, aggregate_counter=counter)
    runner.run_to_path(None)
    clock[0] = 500.0
    runner.run_to_path(None)
    assert observed == [280.0, 680.0]
    assert runner.deadline == 1000.0
    assert counter == [2]


def test_snapshot_entry_limit_precedes_blob_materialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class ListingRunner:
        def run_to_path(self, _cache: Path, _args: Any, output: Path, **_kwargs: Any) -> None:
            output.write_bytes(b"")

    blobs = [
        {"path": f"f{index}", "mode": "100644", "oid": "1" * 40}
        for index in range(packet._MAX_FILES_PACKET + 1)
    ]
    monkeypatch.setattr(packet_primitives, "_parse_tree", lambda _raw: (blobs, []))

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("cat-file must not run after oversized ls-tree")

    monkeypatch.setattr(packet_primitives, "_materialize_blobs", forbidden)
    root = tmp_path / "staging"
    root.mkdir()
    budget = packet.AggregateBudget(root, packet._STAGING_LIMIT)
    with pytest.raises(packet.PacketV1Error, match="before blob materialization"):
        packet._snapshot(
            ListingRunner(),  # type: ignore[arg-type]
            tmp_path / "cache",
            "1" * 40,
            root / "snapshot",
            budget,
        )


def test_inventory_payload_bound_precedes_hashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "large").write_bytes(b"12")

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("oversized file must not be hashed")

    monkeypatch.setattr(packet_primitives, "_hash_file", forbidden)
    with pytest.raises(packet.PacketV1Error, match="inventory bound"):
        packet._inventory(payload, limit=1, max_entries=10)


def test_rename_noreplace_rejects_collision(tmp_path: Path) -> None:
    source_path = tmp_path / "source"
    target = tmp_path / "target"
    source_path.mkdir()
    target.mkdir()
    with pytest.raises(packet.PacketV1Error, match="already exists"):
        packet._rename_noreplace(source_path, target)
    assert source_path.exists() and target.exists()


def test_frozen_packet_profile_exact_hash_selection_and_unknown_rejection() -> None:
    historical_path = ROOT / packet._HISTORICAL_CHECKSUMS
    assert packet._sha(historical_path.read_bytes()) == (
        "sha256:4f1ffa49a7c864a71fb7ad76a1c44cdf129935e46e83bf943b8b7ee9193d8e50"
    )
    historical = packet._historical_profile(ROOT)
    assert packet._profile_by_hash(ROOT, packet._sha(historical.raw)) == historical
    assert historical.files[packet._MODULE] == (ROOT / packet._MODULE).read_bytes()
    with pytest.raises(packet.PacketV1Error, match="unknown production profile"):
        packet._profile_by_hash(ROOT, "sha256:" + "f" * 64)


def test_edited_frozen_packet_profile_fails_current_profile_authentication(tmp_path: Path) -> None:
    current = json.loads((ROOT / packet._CHECKSUMS).read_bytes())
    copied = tmp_path / "repo"
    for relative in current["files"]:
        source_path = ROOT / relative
        target = copied / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, target)
    checksum_target = copied / packet._CHECKSUMS
    checksum_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / packet._CHECKSUMS, checksum_target)
    historical = copied / packet._HISTORICAL_CHECKSUMS
    historical.write_bytes(historical.read_bytes() + b" ")
    with pytest.raises(packet.PacketV1Error, match="current-profile authenticated"):
        packet._historical_profile(copied)


def test_profile_checksums_and_dependency_are_exact() -> None:
    profile = json.loads((ROOT / packet._CHECKSUMS).read_bytes())
    for relative, expected in profile["files"].items():
        assert "sha256:" + hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == expected
    assert packet._DEPENDENCY in profile["files"]


def test_no_network_model_checkout_or_pilot_mutation_surface() -> None:
    text = Path(packet.__file__).read_text()
    for token in ("subagent(", "pi -p", "fetch", "checkout", "worktree", "archive", "git clone"):
        assert token not in text
    assert packet._DEPENDENCY == "benchmarks/real_world/pilot_packet_v2.py"
