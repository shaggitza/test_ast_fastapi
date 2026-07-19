from __future__ import annotations

import ast
import copy
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from benchmarks.real_world import expansion_protocol_v2
from benchmarks.real_world import ground_truth_campaign_v1 as campaign
from benchmarks.real_world.ground_truth_v2.schema import canonical_json

ROOT = Path(__file__).resolve().parents[2]


def _manifest() -> dict[str, Any]:
    return campaign.build_manifest(ROOT, 149, "fastapi/full-stack-fastapi-template")


def _publish_manifest(tmp_path: Path) -> Path:
    path = (tmp_path / "campaign.json").resolve()
    campaign._publish(path, _manifest())
    return path


def _private(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path.resolve()


def _copied_source_root(tmp_path: Path) -> Path:
    copied = tmp_path / "source-root"
    profile = json.loads(
        (ROOT / "benchmarks/real_world/production_v1/checksums-v1.json").read_bytes()
    )
    relatives = set(profile["files"]) | {
        "benchmarks/real_world/production_v1/checksums-v1.json",
        "benchmarks/real_world/expansion/pr-lock-2500-v2.json",
        "benchmarks/real_world/expansion/projects-50x50-v2.json",
        "benchmarks/real_world/expansion/checksums-50x50-v2.json",
    }
    for relative in relatives:
        destination = copied / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    return copied


def test_assignment_exactly_matches_authenticated_lock_order() -> None:
    lock, _ = expansion_protocol_v2.load_lock_authenticated(
        ROOT / "benchmarks/real_world/expansion/pr-lock-2500-v2.json",
        ROOT / "benchmarks/real_world/expansion/projects-50x50-v2.json",
        ROOT / "benchmarks/real_world/expansion/checksums-50x50-v2.json",
    )
    assignments = json.loads(
        (ROOT / "benchmarks/real_world/production_v1/assignments-v1.json").read_bytes()
    )["assignments"]
    assert assignments == [
        {"ordinal": ordinal, "issue": 148 + ordinal, "repository": project["repository"]}
        for ordinal, project in enumerate(lock["projects"], 1)
    ]


def test_issue_149_manifest_is_exact_and_offline() -> None:
    value = _manifest()
    assert len(value["records"]) == 50
    assert [row["rank"] for row in value["records"]] == list(range(1, 51))
    assert len(value["lanes"]) == 100
    assert len({row["lane_key"] for row in value["lanes"]}) == 100
    assert len({row["attempt_id"] for row in value["lanes"]}) == 100
    assert (
        len({(row["reviewer"]["name"], row["reviewer"]["version"]) for row in value["lanes"]})
        == 100
    )
    assert {row["source_packet_state"] for row in value["records"]} == {"pending"}
    assert value["authorization"] == {
        "canonical_import_authorized": False,
        "live_launch_authorized": False,
        "source_packet_materialization_authorized": False,
    }
    assert value["protocol"]["max_global_concurrency"] == 3
    assert value["protocol"]["pi_subagents_version"] == "0.35.1"


def test_wrong_issue_repository_and_incomplete_assignment_fail() -> None:
    with pytest.raises(campaign.CampaignV1Error, match="frozen assignment"):
        campaign.build_manifest(ROOT, 149, "Kludex/starlette")
    lock, _, _, _ = campaign._load_sources(ROOT)
    assignment = json.loads(
        (ROOT / "benchmarks/real_world/production_v1/assignments-v1.json").read_bytes()
    )
    assignment["assignments"].pop()
    with pytest.raises(campaign.CampaignV1Error, match="cardinality"):
        campaign._validate_assignments(assignment, lock)


def test_source_authentication_rejects_lock_byte_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copied = _copied_source_root(tmp_path)
    original = expansion_protocol_v2.load_lock_authenticated

    def mutate_then_load(lock_path: Path, manifest_path: Path, checksums_path: Path) -> Any:
        lock_path.write_bytes(lock_path.read_bytes() + b"\n")
        return original(lock_path, manifest_path, checksums_path)

    monkeypatch.setattr(expansion_protocol_v2, "load_lock_authenticated", mutate_then_load)
    with pytest.raises(campaign.CampaignV1Error, match="drifted during authentication"):
        campaign._load_sources(copied)


def test_source_authentication_rejects_manifest_same_byte_inode_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copied = _copied_source_root(tmp_path)
    manifest_path = copied / "benchmarks/real_world/expansion/projects-50x50-v2.json"
    original = expansion_protocol_v2.load_lock_authenticated

    def replace_then_load(lock_path: Path, source_path: Path, checksums_path: Path) -> Any:
        replacement = source_path.with_name("replacement-manifest.json")
        replacement.write_bytes(source_path.read_bytes())
        replacement.replace(source_path)
        return original(lock_path, source_path, checksums_path)

    original_inode = manifest_path.stat().st_ino
    monkeypatch.setattr(expansion_protocol_v2, "load_lock_authenticated", replace_then_load)
    with pytest.raises(campaign.CampaignV1Error, match="drifted during authentication"):
        campaign._load_sources(copied)
    assert manifest_path.stat().st_ino != original_inode


def test_source_authentication_rejects_checksum_same_byte_aba(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copied = _copied_source_root(tmp_path)
    checksums_path = copied / "benchmarks/real_world/expansion/checksums-50x50-v2.json"
    original = expansion_protocol_v2.load_manifest
    replaced = False

    def replace_checksum_then_load(manifest_path: Path) -> Any:
        nonlocal replaced
        if not replaced:
            replacement = checksums_path.with_name("replacement-checksums.json")
            replacement.write_bytes(checksums_path.read_bytes())
            replacement.replace(checksums_path)
            replaced = True
        return original(manifest_path)

    original_inode = checksums_path.stat().st_ino
    monkeypatch.setattr(expansion_protocol_v2, "load_manifest", replace_checksum_then_load)
    with pytest.raises(campaign.CampaignV1Error, match="drifted during authentication"):
        campaign._load_sources(copied)
    assert checksums_path.stat().st_ino != original_inode


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["records"].pop(),
        lambda value: value["records"].__setitem__(1, value["records"][0]),
        lambda value: value["records"].reverse(),
        lambda value: value["corpus"].__setitem__("id", "wrong-corpus"),
        lambda value: value.__setitem__("extra", True),
        lambda value: value["protocol"].__setitem__("max_global_concurrency", 3.0),
        lambda value: value["lanes"].__setitem__(1, value["lanes"][0]),
    ],
)
def test_manifest_tamper_fails(mutation: Any) -> None:
    value = copy.deepcopy(_manifest())
    mutation(value)
    with pytest.raises(campaign.CampaignV1Error):
        campaign.validate_manifest(ROOT, value)


def test_json_duplicate_extra_and_float_fail(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":1,"schema_version":1}\n')
    with pytest.raises(campaign.CampaignV1Error, match="duplicate JSON key"):
        campaign._json(duplicate)
    floating = tmp_path / "float.json"
    floating.write_text('{"value":1.5}\n')
    with pytest.raises(campaign.CampaignV1Error, match="floats"):
        campaign._json(floating)


def test_manifest_and_ledger_no_clobber_modes_and_validation(tmp_path: Path) -> None:
    manifest = _publish_manifest(tmp_path)
    assert manifest.stat().st_mode & 0o777 == 0o400
    with pytest.raises(campaign.CampaignV1Error, match="overwrite"):
        campaign._publish(manifest, _manifest())
    ledger = _private(tmp_path / "ledger")
    result = campaign.init_ledger(ledger, manifest, ROOT)
    assert result["planned"] == 100
    assert (ledger / "lane-states.json").stat().st_mode & 0o777 == 0o400
    assert (ledger / "ledger-genesis.json").stat().st_mode & 0o777 == 0o400
    assert (ledger / ".ledger.lock").stat().st_mode & 0o777 == 0o600
    assert campaign.validate_ledger(ledger, ROOT) == result
    assert result["packet_authorization_present"] is False
    assert result["genesis_entry_hash"] == result["entry_hash"]
    with pytest.raises(campaign.CampaignV1Error, match="overwrite"):
        campaign.init_ledger(ledger, manifest, ROOT)


def test_ledger_rejects_nonprivate_and_symlink_root(tmp_path: Path) -> None:
    manifest = _publish_manifest(tmp_path)
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    public.chmod(0o755)
    with pytest.raises(campaign.CampaignV1Error, match="mode-0700"):
        campaign.init_ledger(public.resolve(), manifest, ROOT)
    real = _private(tmp_path / "real")
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(campaign.CampaignV1Error, match="symlink"):
        campaign.init_ledger(link.absolute(), manifest, ROOT)


def test_ledger_rejects_manifest_inode_swap(tmp_path: Path) -> None:
    manifest = _publish_manifest(tmp_path)
    ledger = _private(tmp_path / "ledger")
    campaign.init_ledger(ledger, manifest, ROOT)
    raw = manifest.read_bytes()
    original_inode = manifest.stat().st_ino
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(raw)
    replacement.chmod(0o400)
    replacement.replace(manifest)
    assert manifest.stat().st_ino != original_inode
    with pytest.raises(campaign.CampaignV1Error, match="binding or hash chain"):
        campaign.validate_ledger(ledger, ROOT)


def test_ledger_rejects_state_tamper(tmp_path: Path) -> None:
    manifest = _publish_manifest(tmp_path)
    ledger = _private(tmp_path / "ledger")
    campaign.init_ledger(ledger, manifest, ROOT)
    states_path = ledger / "lane-states.json"
    states = json.loads(states_path.read_bytes())
    states["states"][0]["state"] = "running"
    states_path.chmod(0o600)
    states_path.write_bytes(canonical_json(states))
    states_path.chmod(0o400)
    with pytest.raises(campaign.CampaignV1Error, match="differ from campaign"):
        campaign.validate_ledger(ledger, ROOT)


def test_profile_checksums_cover_all_offline_files() -> None:
    profile = json.loads(
        (ROOT / "benchmarks/real_world/production_v1/checksums-v1.json").read_bytes()
    )
    assert set(profile["files"]) == {
        "benchmarks/real_world/production_v1/assignments-v1.json",
        "benchmarks/real_world/production_v1/campaign-policy-v1.json",
        "benchmarks/real_world/production_v1/campaign-manifest-schema-v1.json",
        "benchmarks/real_world/production_v1/README.md",
        "benchmarks/real_world/ground_truth_campaign_v1.py",
        "benchmarks/real_world/ground_truth_source_v1.py",
        "benchmarks/real_world/production_v1/source-policy-v1.json",
        "benchmarks/real_world/production_v1/source-bindings-schema-v1.json",
        "benchmarks/real_world/ground_truth_packet_v1.py",
        "benchmarks/real_world/pilot_packet_v2.py",
        "benchmarks/real_world/production_v1/packet-policy-v1.json",
        "benchmarks/real_world/production_v1/packet-manifest-schema-v1.json",
        "benchmarks/real_world/production_v1/packet-authorization-schema-v1.json",
        "benchmarks/real_world/production_v1/packet-publication-schema-v1.json",
        "benchmarks/real_world/production_v1/packet-aggregate-schema-v1.json",
        "benchmarks/real_world/ground_truth_submit_v1.py",
        "benchmarks/real_world/production_v1/submission-policy-v1.json",
        "benchmarks/real_world/production_v1/submission-binding-schema-v1.json",
        "benchmarks/real_world/production_v1/review-prompt-v1.md",
        "benchmarks/real_world/production_v1/model-policy-review-v1.json",
        "benchmarks/real_world/production_v1/tool-policy-review-v1.json",
        "benchmarks/real_world/production_v1/review-source-policy-v1.json",
        "benchmarks/real_world/production_v1/extensions/ground-truth-review-submit/index.ts",
        "benchmarks/real_world/production_v1/extensions/ground-truth-review-submit/review-schema.ts",
        "benchmarks/real_world/ground_truth_run_v1.py",
        "benchmarks/real_world/production_v1/runtime-policy-v1.json",
        "benchmarks/real_world/production_v1/runtime-attestation-schema-v1.json",
        "benchmarks/real_world/production_v1/runtime-custody-receipt-schema-v1.json",
        "benchmarks/real_world/production_v1/review-canary-authorization-schema-v1.json",
        "benchmarks/real_world/production_v1/lane-event-schema-v1.json",
        "benchmarks/real_world/production_v1/session-audit-schema-v1.json",
        "benchmarks/real_world/production_v1/checksums-packet-v1.json",
        "benchmarks/real_world/production_v1/checksums-packet-selection-v1.json",
        "benchmarks/real_world/production_v1/checksums-runtime-migration-v1.json",
        "benchmarks/real_world/production_v1/prelaunch-migration-policy-v1.json",
        "benchmarks/real_world/production_v1/prelaunch-migration-schema-v1.json",
        "benchmarks/real_world/production_v1/selection-validation-policy-v1.json",
    }
    for relative, expected in profile["files"].items():
        actual = "sha256:" + hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        assert actual == expected


def test_module_has_no_process_model_launch_or_network_code() -> None:
    source = (ROOT / "benchmarks/real_world/ground_truth_campaign_v1.py").read_text()
    tree = ast.parse(source)
    forbidden_imports = {"subprocess", "socket", "urllib", "requests", "httpx"}
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imported.isdisjoint(forbidden_imports)
    forbidden_calls = {"exec", "eval", "compile", "system", "popen", "spawn", "fork"}
    calls = {
        node.func.id.casefold()
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert calls.isdisjoint(forbidden_calls)
    assert "subagent(" not in source
    assert 'live_launch_authorized": True' not in source


def test_assignment_bytes_are_checksum_authenticated(tmp_path: Path) -> None:
    copied = tmp_path / "repo"
    copied.mkdir()
    target = copied / "benchmarks/real_world/production_v1"
    target.mkdir(parents=True)
    profile = json.loads(
        (ROOT / "benchmarks/real_world/production_v1/checksums-v1.json").read_bytes()
    )
    for relative in profile["files"]:
        destination = copied / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    assignment = ROOT / "benchmarks/real_world/production_v1/assignments-v1.json"
    tampered = json.loads(assignment.read_bytes())
    tampered["assignments"][0]["repository"] = "wrong/repository"
    (target / "assignments-v1.json").write_bytes(canonical_json(tampered))
    (target / "checksums-v1.json").write_bytes(canonical_json(profile))
    with pytest.raises(campaign.CampaignV1Error, match="checksum mismatch"):
        campaign._authenticate_profile(copied)
