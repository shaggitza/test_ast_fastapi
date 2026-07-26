from __future__ import annotations

import ast
import contextlib
import fcntl
import inspect
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, cast

import pytest
from benchmarks.real_world import ground_truth_campaign_v1 as campaign
from benchmarks.real_world import ground_truth_packet_v1 as packet
from benchmarks.real_world import ground_truth_run_v1 as run
from benchmarks.real_world import ground_truth_source_v1 as source
from benchmarks.real_world import ground_truth_submit_v1 as submit
from benchmarks.real_world.ground_truth_v2.schema import canonical_json
from tests.benchmarks.test_ground_truth_submit_v1 import (
    _packet_and_record as _submit_packet_and_record,
)

ROOT = Path(__file__).resolve().parents[2]
BASE = "sha256:" + "1" * 64
A = "prod-v1-i149-rank001-pr2330-A"
B = "prod-v1-i149-rank001-pr2330-B"


def _file_identity(name: str, index: int) -> dict[str, Any]:
    return {
        "path": f"/fixture/runtime/{name}",
        "sha256": "sha256:" + f"{index:064x}",
        "bytes": index + 1,
    }


def _fixture_runtime_identity() -> dict[str, Any]:
    """Return a schema-valid runtime identity for hermetic ledger tests."""
    census = {
        "roots": {
            "userDir": "/fixture/user/agents",
            "projectDir": "/fixture/project/agents",
            "userSettingsPath": "/fixture/user/settings.json",
            "projectSettingsPath": "/fixture/project/settings.json",
        },
        "effective": [],
        "builtin": [],
        "package": [],
        "user": [],
        "project": [],
    }
    runtime_files = {
        name: _file_identity(name, index)
        for index, name in enumerate(
            (
                "package",
                "agents",
                "schemas",
                "pi_args",
                "foreground_execution",
                "foreground_executor",
            ),
            1,
        )
    }
    root_kinds = ("project-old", "project-new", "user-old", "user-new", "builtin")
    return {
        "schema_version": 1,
        "pi_subagents_version": "0.35.1",
        "pi_version": "0.80.10",
        "pi_package": _file_identity("pi-package", 7),
        "runtime_files": runtime_files,
        "config": {
            **_file_identity("config", 8),
            "intercom_mode": "off",
        },
        "roots": [
            {"kind": kind, "path": f"/fixture/roots/{kind}", "exists": False} for kind in root_kinds
        ],
        "resolver_census": census,
        "resolver_census_sha256": run._sha(canonical_json(census)),
        "resolver_execution": {
            "node_path": "/fixture/bin/node",
            "node_sha256": "sha256:" + "9" * 64,
            "script_sha256": "sha256:" + "a" * 64,
            "argv_sha256": "sha256:" + "b" * 64,
            "timeout_seconds": 30,
            "network_authorized": False,
            "shell": False,
        },
    }


def _actual_runtime_identity_or_skip() -> dict[str, Any]:
    """Load the certification runtime only where that pinned installation exists."""
    subagents, _resolver, pi_package, _config = run._package_paths()
    if not (subagents / "package.json").is_file() or not pi_package.is_file():
        pytest.skip("pinned production runtime is not installed in general CI")
    try:
        return run._runtime_identity(ROOT)
    except run.GroundTruthRunError as exc:
        message = str(exc)
        if message.startswith("pinned ") and message.endswith(" is unavailable"):
            pytest.skip("exact production runtime version is not installed")
        raise


def _private(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _mock_migration_custody(monkeypatch: pytest.MonkeyPatch, source_sha256: str) -> None:
    profile = submit.ProfileSnapshot(
        checksum_raw=b"{}\n",
        checksum_sha256="sha256:" + "a" * 64,
        files={},
        digests={},
        files_sha256="sha256:" + "b" * 64,
    )
    monkeypatch.setattr(source, "_inventory", lambda *_args: {"stable": "source"})
    monkeypatch.setattr(packet, "_inventory", lambda *_args, **_kwargs: {"stable": "packet"})
    monkeypatch.setattr(
        run,
        "_custody",
        lambda *_args: (
            {
                "id": "campaign",
                "lanes": [
                    {"rank": 1, "attempt_id": A},
                    {"rank": 1, "attempt_id": B},
                ],
            },
            b"campaign\n",
            {
                "source": {"sha256": source_sha256},
                "packet": {"publication_entry_hash": "sha256:" + "4" * 64},
            },
            profile,
        ),
    )


def _publish(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.write_bytes(canonical_json(value))
    path.chmod(0o400)


def _reviewer(attempt: str) -> dict[str, str]:
    suffix = attempt.removeprefix("prod-v1-")
    return {
        "name": f"production-blind-reviewer-{suffix}",
        "version": f"ground-truth-production-v1-{suffix}",
    }


def _authorization_lanes() -> list[dict[str, Any]]:
    return [
        {"lane_key": "owner/repo#2330:A", "attempt_id": A, "reviewer": _reviewer(A)},
        {"lane_key": "owner/repo#2330:B", "attempt_id": B, "reviewer": _reviewer(B)},
    ]


def _runtime(previous: str = BASE) -> dict[str, Any]:
    body = {
        "schema_version": 1,
        "protocol": "ground-truth-runtime-attestation-v1",
        "campaign_id": "campaign",
        "campaign_manifest_sha256": "sha256:" + "2" * 64,
        "campaign_lanes_sha256": run._sha(canonical_json(_authorization_lanes())),
        "source_bindings_sha256": "sha256:" + "3" * 64,
        "packet_publication_entry_hash": "sha256:" + "4" * 64,
        "production_profile_sha256": "sha256:" + "5" * 64,
        "production_files_sha256": "sha256:" + "6" * 64,
        "runtime_identity": _fixture_runtime_identity(),
        "extension_sha256": "sha256:" + "7" * 64,
        "extension_schema_sha256": "sha256:" + "8" * 64,
        "agent_source_sha256": "sha256:" + "9" * 64,
        "execution_root": "/private/execution",
        "execution_device": 1,
        "execution_inode": 2,
        "attested_at": "2026-01-01T00:00:00Z",
        "authorizations": {
            "review_launch": False,
            "adjudication": False,
            "canonical_import": False,
        },
        "previous_hash": previous,
    }
    return {**body, "entry_hash": run._entry_hash(b"ground-truth-runtime-attestation-v1\0", body)}


def _supersession(runtime: dict[str, Any]) -> dict[str, Any]:
    body = {
        **{
            key: value
            for key, value in runtime.items()
            if key not in {"protocol", "previous_hash", "entry_hash"}
        },
        "protocol": run._RUNTIME_SUPERSESSION_PROTOCOL,
        "supersedes_entry_hash": runtime["entry_hash"],
        "previous_hash": runtime["entry_hash"],
    }
    return {
        **body,
        "entry_hash": run._entry_hash(run._RUNTIME_SUPERSESSION_DOMAIN, body),
    }


def _auth(runtime: dict[str, Any]) -> dict[str, Any]:
    body = {
        "schema_version": 1,
        "protocol": "ground-truth-review-canary-authorization-v1",
        "campaign_id": "campaign",
        "campaign_manifest_sha256": "sha256:" + "2" * 64,
        "runtime_attestation_entry_hash": runtime["entry_hash"],
        "agent_installation_sha256": "sha256:" + "a" * 64,
        "production_profile_sha256": "sha256:" + "5" * 64,
        "lanes": _authorization_lanes(),
        "limits": {"max_global_active": 3, "max_processes_per_lane": 1, "replacement_attempts": 0},
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-02T00:00:00Z",
        "authorizations": {"review_launch": True, "adjudication": False, "canonical_import": False},
        "previous_hash": runtime["entry_hash"],
    }
    return {
        **body,
        "entry_hash": run._entry_hash(b"ground-truth-review-canary-authorization-v1\0", body),
    }


def _ledger(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, dict[str, Any]]:
    ledger = _private(tmp_path / "ledger")
    runtime, auth = _runtime(), _auth(_runtime())
    # rebuild auth against the exact published runtime
    auth = _auth(runtime)
    _publish(ledger / "runtime-attestation.json", runtime)
    _publish(ledger / "review-canary-authorization.json", auth)
    monkeypatch.setattr(
        campaign,
        "_validate_ledger_unlocked",
        lambda *_: {
            "entry_hash": BASE,
            "packet_publication_present": True,
            "campaign_id": "campaign",
            "campaign_manifest_sha256": "sha256:" + "2" * 64,
            "campaign_canary_lanes": _authorization_lanes(),
            "campaign_canary_lanes_sha256": run._sha(canonical_json(_authorization_lanes())),
            "packet_publication_entry_hash": "sha256:" + "4" * 64,
        },
    )
    return ledger, auth


def _event(
    ledger: Path, previous: str, sequence: int, kind: str, identifier: str, fields: dict[str, Any]
) -> dict[str, Any]:
    body = {
        "schema_version": 1,
        "protocol": "ground-truth-review-lane-event-v1",
        "sequence": sequence,
        "kind": kind,
        **fields,
        "previous_hash": previous,
    }
    value = {**body, "entry_hash": run._entry_hash(b"ground-truth-review-lane-event-v1\0", body)}
    _publish(ledger / "lane-events" / f"{sequence:06d}-{kind}-{identifier}.json", value)
    return value


def _special_event(
    ledger: Path,
    previous: str,
    sequence: int,
    kind: str,
    identifier: str,
    fields: dict[str, Any],
    protocol: str,
    domain: bytes,
    *,
    schema_version: int = 1,
) -> dict[str, Any]:
    body = {
        "schema_version": schema_version,
        "protocol": protocol,
        "sequence": sequence,
        "kind": kind,
        **fields,
        "previous_hash": previous,
    }
    value = {**body, "entry_hash": run._entry_hash(domain, body)}
    _publish(ledger / "lane-events" / f"{sequence:06d}-{kind}-{identifier}.json", value)
    return value


def _prepared(attempt: str) -> dict[str, Any]:
    return {
        "attempt_id": attempt,
        "rank": 1,
        "lane": attempt[-1],
        "lane_key": "owner/repo#2330:" + attempt[-1],
        "binding_sha256": "sha256:" + "b" * 64,
        "runtime_attestation_entry_hash": _runtime()["entry_hash"],
        "packet_root_sha256": "sha256:" + "d" * 64,
        "broker_pid": 10,
        "broker_start_identity": "20",
        "prepared_at": "2026-01-01T01:00:00Z",
    }


def test_actual_runtime_identity_and_config_are_exact() -> None:
    identity = _actual_runtime_identity_or_skip()
    assert identity["pi_subagents_version"] == "0.35.1"
    assert identity["pi_version"] == "0.80.10"
    assert identity["config"]["intercom_mode"] in {"fork-only", "off"}
    assert set(identity["runtime_files"]) == {
        "package",
        "agents",
        "schemas",
        "pi_args",
        "foreground_execution",
        "foreground_executor",
    }
    assert identity["resolver_execution"]["network_authorized"] is False


def test_actual_resolver_resolves_exact_flat_user_agent_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _actual_runtime_identity_or_skip()
    resolver = Path(identity["runtime_files"]["agents"]["path"])
    agent_dir = tmp_path / "agent-home"
    agents = agent_dir / "agents"
    agents.mkdir(parents=True)
    flat = agents / "ground-truth-production-reviewer-v1.md"
    extension = tmp_path / "index.ts"
    flat.write_bytes(run._agent_body(extension, "fixture\n"))
    nested = agents / "nested"
    nested.mkdir()
    (nested / "resolver-nested-fixture.md").write_text(
        "---\nname: resolver-nested-fixture\n"
        "description: nested fixture\ntools: [read]\n---\nfixture\n"
    )
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(agent_dir))
    census, execution = run._resolver_census(project, resolver)
    user_names = {row["name"] for row in census["user"] if isinstance(row, dict)}
    assert run._AGENT_NAME in user_names
    flat_rows = [row for row in census["user"] if row.get("name") == run._AGENT_NAME]
    assert len(flat_rows) == 1
    assert flat_rows[0]["filePath"] == str(flat)
    assert flat_rows[0]["extensions"] == []
    assert flat_rows[0]["subagentOnlyExtensions"] == [str(extension)]
    # The pinned resolver also sees nested files, so production deliberately
    # requires the exact flat path rather than relying on directory privacy.
    assert "resolver-nested-fixture" in user_names
    assert execution["network_authorized"] is False
    assert execution["shell"] is False


def test_broker_readiness_budget_is_bounded_and_below_attempt_deadline() -> None:
    policy = json.loads(
        (ROOT / "benchmarks/real_world/production_v1/runtime-policy-v1.json").read_bytes()
    )
    assert run._BROKER_READY_SECONDS == policy["max_broker_readiness_seconds"] == 900
    assert run._BROKER_READY_SECONDS < run._MAX_WALL


def test_zombie_broker_is_not_same_process() -> None:
    process = subprocess.Popen(["/bin/sleep", "0.05"], start_new_session=True)
    identity = run._proc_identity(process.pid)
    try:
        time.sleep(0.1)
        assert run._same_process(process.pid, identity) is False
    finally:
        process.wait()


def test_broker_readiness_rejects_dead_process_before_socket_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(run, "_same_process", lambda *_args: False)
    with pytest.raises(run.GroundTruthRunError, match="failed before readiness"):
        run._wait_socket(tmp_path / "stale.sock", 123, "identity")


def test_broker_socket_path_is_short_private_and_attempt_bound() -> None:
    pr = 900_000_000 + os.getpid()
    attempt_a = f"prod-v1-i149-rank001-pr{pr}-A"
    attempt_b = f"prod-v1-i149-rank001-pr{pr}-B"
    first = run._broker_socket_path(attempt_a)
    second = run._broker_socket_path(attempt_b)
    assert first != second
    assert len(os.fsencode(first)) < 100
    first.touch()
    try:
        with pytest.raises(run.GroundTruthRunError, match="already exists"):
            run._broker_socket_path(attempt_a)
    finally:
        first.unlink(missing_ok=True)


def test_fast_prepare_avoids_full_custody_and_receipt_publication_is_no_clobber(
    tmp_path: Path,
) -> None:
    prepare_source = inspect.getsource(run.prepare_attempt)
    attest_source = inspect.getsource(run.attest_runtime)
    assert "_custody(" not in prepare_source
    assert "source_inventory_before" in attest_source
    assert "packet_inventory_before" in attest_source
    assert "runtime_custody_receipt_sha256" in attest_source
    assert '"schema_version": 2' in attest_source
    assert "source_inventory_final" in attest_source
    assert "packet_inventory_final" in attest_source
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    receipt = runtime / "custody-receipt.json"
    value = {
        "schema_version": 1,
        "protocol": "ground-truth-runtime-custody-receipt-v1",
    }
    run._atomic(receipt, value)
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o400
    with pytest.raises(run.GroundTruthRunError, match="already exists"):
        run._atomic(receipt, value)


def test_broker_process_limit_allows_bounded_evidence_child() -> None:
    script = (
        "import subprocess; "
        "from benchmarks.real_world.ground_truth_run_v1 import _broker_limits; "
        "_broker_limits(); "
        "subprocess.run(['/usr/bin/prlimit','--fsize=5368709120','--nofile=256',"
        "'--nproc=512','--','/bin/true'], check=True)"
    )
    subprocess.run([sys.executable, "-c", script], check=True, cwd=ROOT)


def test_agent_disables_ambient_extensions_and_pinned_pi_args_supports_it(tmp_path: Path) -> None:
    body = run._agent_body(tmp_path / "index.ts", "prompt\n").decode()
    assert "extensions:\n" in body
    assert "extensions: []" not in body
    assert "subagentOnlyExtensions:" in body
    pi_args = Path(
        _actual_runtime_identity_or_skip()["runtime_files"]["pi_args"]["path"]
    ).read_text()
    assert 'args.push("--no-extensions")' in pi_args


def test_authorization_exact_rank1_ab_and_missing_reviewer_rejected() -> None:
    value = _auth(_runtime())
    assert run._authorized_attempts(value) == {A, B}
    bad = json.loads(json.dumps(value))
    bad["lanes"][0].pop("reviewer")
    with pytest.raises(run.GroundTruthRunError, match="lane"):
        run._authorized_attempts(bad)
    bad = json.loads(json.dumps(value))
    bad["lanes"][0]["attempt_id"] = "prod-v1-i149-rank002-pr9-A"
    with pytest.raises(run.GroundTruthRunError, match="lane identity"):
        run._authorized_attempts(bad)


def _replace(path: Path, value: dict[str, Any]) -> None:
    path.chmod(0o600)
    path.write_bytes(canonical_json(value))
    path.chmod(0o400)


def test_ledger_rejects_incomplete_runtime_identity_and_unrelated_campaign_lane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger, _ = _ledger(tmp_path / "identity", monkeypatch)
    runtime = _runtime()
    runtime["runtime_identity"]["unexpected"] = True
    runtime_body = {key: value for key, value in runtime.items() if key != "entry_hash"}
    runtime["entry_hash"] = run._entry_hash(b"ground-truth-runtime-attestation-v1\0", runtime_body)
    auth = _auth(runtime)
    _replace(ledger / "runtime-attestation.json", runtime)
    _replace(ledger / "review-canary-authorization.json", auth)
    with pytest.raises(run.GroundTruthRunError, match="runtime identity keys"):
        run._extended_ledger(ledger, ROOT)

    ledger, _ = _ledger(tmp_path / "lane", monkeypatch)
    runtime = _runtime()
    auth = _auth(runtime)
    auth["lanes"][0]["lane_key"] = "unrelated/repo#2330:A"
    auth_body = {key: value for key, value in auth.items() if key != "entry_hash"}
    auth["entry_hash"] = run._entry_hash(
        b"ground-truth-review-canary-authorization-v1\0", auth_body
    )
    _replace(ledger / "review-canary-authorization.json", auth)
    with pytest.raises(run.GroundTruthRunError, match="authenticated campaign lanes"):
        run._extended_ledger(ledger, ROOT)

    ledger, _ = _ledger(tmp_path / "coupled-lane", monkeypatch)
    tampered_lanes = _authorization_lanes()
    tampered_lanes[0]["lane_key"] = "unrelated/repo#2330:A"
    runtime = _runtime()
    runtime["campaign_lanes_sha256"] = run._sha(canonical_json(tampered_lanes))
    runtime_body = {key: value for key, value in runtime.items() if key != "entry_hash"}
    runtime["entry_hash"] = run._entry_hash(b"ground-truth-runtime-attestation-v1\0", runtime_body)
    auth = _auth(runtime)
    auth["lanes"] = tampered_lanes
    auth_body = {key: value for key, value in auth.items() if key != "entry_hash"}
    auth["entry_hash"] = run._entry_hash(
        b"ground-truth-review-canary-authorization-v1\0", auth_body
    )
    _replace(ledger / "runtime-attestation.json", runtime)
    _replace(ledger / "review-canary-authorization.json", auth)
    with pytest.raises(run.GroundTruthRunError, match="runtime attestation ledger"):
        run._extended_ledger(ledger, ROOT)


def test_historical_runtime_profiles_are_exactly_current_authenticated() -> None:
    for relative in (
        packet._SELECTION_CHECKSUMS,
        run._RUNTIME_MIGRATION_CHECKSUMS,
        run._RUNTIME_REPAIR_CHECKSUMS,
    ):
        raw = (ROOT / relative).read_bytes()
        files, profile_hash, files_hash = run._historical_runtime_profile(ROOT, run._sha(raw))
        assert set(files) == {
            run._EXTENSION,
            run._EXTENSION_SCHEMA,
            f"{run._PROFILE}/review-prompt-v1.md",
        }
        assert profile_hash == run._sha(raw)
        assert files_hash.startswith("sha256:")


def test_receipt_runtime_shape_survives_profile_rollover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch)
    (ledger / "review-canary-authorization.json").unlink()
    receipt_runtime = _runtime()
    receipt_runtime["schema_version"] = 2
    receipt_runtime["runtime_custody_receipt_path"] = (
        "/private/execution/runtime/custody-receipt.json"
    )
    receipt_runtime["runtime_custody_receipt_sha256"] = "sha256:" + "a" * 64
    body = {key: value for key, value in receipt_runtime.items() if key != "entry_hash"}
    receipt_runtime["entry_hash"] = run._entry_hash(run._RUNTIME_DOMAIN, body)
    _replace(ledger / "runtime-attestation.json", receipt_runtime)
    state = run._extended_ledger(ledger, ROOT)
    assert state["runtime"] == receipt_runtime


def test_runtime_supersession_is_single_monotonic_no_authority_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger, _ = _ledger(tmp_path / "valid", monkeypatch)
    (ledger / "review-canary-authorization.json").unlink()
    first = _runtime()
    supersession = _supersession(first)
    _publish(ledger / run._RUNTIME_SUPERSESSION_FILE, supersession)
    state = run._extended_ledger(ledger, ROOT)
    assert state["first_runtime"] == first
    assert state["runtime"] == supersession
    assert state["runtime_superseded"] is True
    assert state["authorization"] is None
    assert supersession["authorizations"] == {
        "review_launch": False,
        "adjudication": False,
        "canonical_import": False,
    }

    tampered = dict(supersession)
    tampered["supersedes_entry_hash"] = "sha256:" + "f" * 64
    body = {key: value for key, value in tampered.items() if key != "entry_hash"}
    tampered["entry_hash"] = run._entry_hash(run._RUNTIME_SUPERSESSION_DOMAIN, body)
    _replace(ledger / run._RUNTIME_SUPERSESSION_FILE, tampered)
    with pytest.raises(run.GroundTruthRunError, match="runtime attestation ledger"):
        run._extended_ledger(ledger, ROOT)

    _replace(ledger / run._RUNTIME_SUPERSESSION_FILE, supersession)
    _publish(ledger / "runtime-attestation-supersession-002.json", supersession)
    with pytest.raises(run.GroundTruthRunError, match="supersession cardinality"):
        run._extended_ledger(ledger, ROOT)


def test_runtime_supersession_publication_rejects_auth_activity_and_second() -> None:
    first = _runtime()
    base: dict[str, Any] = {
        "runtime": first,
        "authorization": None,
        "events": [],
        "runtime_superseded": False,
    }
    assert run._runtime_attestation_publication(base) == (
        run._RUNTIME_SUPERSESSION_FILE,
        run._RUNTIME_SUPERSESSION_PROTOCOL,
        run._RUNTIME_SUPERSESSION_DOMAIN,
        {"supersedes_entry_hash": first["entry_hash"]},
    )
    for changed in (
        {**base, "authorization": _auth(first)},
        {**base, "events": [{"kind": "prepared"}]},
        {**base, "runtime_superseded": True},
    ):
        with pytest.raises(run.GroundTruthRunError, match="cannot be superseded"):
            run._runtime_attestation_publication(changed)


def test_strict_complete_ledger_chain_and_lost_plan_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger, auth = _ledger(tmp_path, monkeypatch)
    e1 = _event(ledger, auth["entry_hash"], 1, "prepared", A, _prepared(A))
    e2 = _event(ledger, e1["entry_hash"], 2, "prepared", B, _prepared(B))
    e3 = _event(
        ledger,
        e2["entry_hash"],
        3,
        "launch_claimed",
        "batch1",
        {
            "batch_id": "batch1",
            "attempt_ids": [A, B],
            "task_indices": [0, 1],
            "runtime_attestation_entry_hash": _runtime()["entry_hash"],
            "plan_sha256": "sha256:" + "e" * 64,
            "claimed_at": "2026-01-01T02:00:00Z",
        },
    )
    value = run._extended_ledger(ledger, ROOT)
    assert value["states"] == {A: "launch_claimed", B: "launch_claimed"}
    assert value["batches"] == {"batch1": {A: 0, B: 1}}
    # A claimed batch cannot be launched/prepared again after output loss.
    _event(ledger, e3["entry_hash"], 4, "prepared", A, _prepared(A))
    with pytest.raises(run.GroundTruthRunError):
        run._extended_ledger(ledger, ROOT)


def test_prelaunch_migration_rejects_unattested_execution_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supplied = _private(tmp_path / "supplied-execution")
    ledger = _private(tmp_path / "ledger")
    bindings = tmp_path / "source-bindings.json"
    bindings.write_bytes(canonical_json({"records": []}))
    bindings.chmod(0o400)
    runtime = _runtime()
    runtime["source_bindings_sha256"] = run._sha(bindings.read_bytes())
    runtime_body = {key: value for key, value in runtime.items() if key != "entry_hash"}
    runtime["entry_hash"] = run._entry_hash(run._RUNTIME_DOMAIN, runtime_body)
    authorization = _auth(runtime)
    current: dict[str, Any] = {
        "migration": None,
        "runtime_superseded": False,
        "runtime": runtime,
        "authorization": authorization,
        "active": 0,
        "events": [],
        "states": {},
        "base": {"packet_publication_entry_hash": "sha256:" + "4" * 64},
    }
    _mock_migration_custody(monkeypatch, run._sha(bindings.read_bytes()))
    monkeypatch.setattr(
        run,
        "_campaign",
        lambda *_args: (
            {
                "id": "campaign",
                "lanes": [
                    {"rank": 1, "attempt_id": A},
                    {"rank": 1, "attempt_id": B},
                ],
            },
            b"campaign\n",
        ),
    )
    monkeypatch.setattr(campaign, "_private_root", lambda path: path)
    monkeypatch.setattr(campaign, "_ledger_lock", lambda _path: contextlib.nullcontext())
    monkeypatch.setattr(run, "_extended_ledger", lambda *_args: current)
    with pytest.raises(run.GroundTruthRunError, match="differs from prior runtime"):
        run.authorize_prelaunch_migration(
            ROOT,
            tmp_path / "campaign.json",
            bindings,
            tmp_path / "cache",
            ledger,
            tmp_path / "packets",
            supplied,
        )


@pytest.mark.parametrize("tamper", ["pid", "artifact"])
def test_prelaunch_migration_rejects_pid_or_artifact_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tamper: str
) -> None:
    execution = _private(tmp_path / "execution")
    ledger = _private(tmp_path / "ledger")
    bindings = tmp_path / "source-bindings.json"
    bindings.write_bytes(canonical_json({"records": []}))
    bindings.chmod(0o400)
    runtime = _runtime()
    status = execution.stat()
    runtime.update(
        {
            "source_bindings_sha256": run._sha(bindings.read_bytes()),
            "execution_root": str(execution),
            "execution_device": status.st_dev,
            "execution_inode": status.st_ino,
        }
    )
    runtime_body = {key: value for key, value in runtime.items() if key != "entry_hash"}
    runtime["entry_hash"] = run._entry_hash(run._RUNTIME_DOMAIN, runtime_body)
    authorization = _auth(runtime)
    events: list[dict[str, Any]] = []
    states: dict[str, str] = {}
    _private(execution / "attempts")
    for attempt in (A, B):
        prepared = {
            "kind": "prepared",
            "attempt_id": attempt,
            "broker_pid": 101,
            "broker_start_identity": "start",
        }
        failed = {
            "kind": "operational_failed",
            "attempt_id": attempt,
            "reason": "never-launched broker exited",
        }
        events.extend([prepared, failed])
        states[attempt] = "operational_failed"
        attempt_root = _private(execution / "attempts" / attempt)
        for directory in ("escrow", "logs"):
            _private(attempt_root / directory)
        packet_dir = _private(attempt_root / "packet")
        packet_dir.chmod(0o500)
        for name in ("binding.json", "native-state.json"):
            path = attempt_root / name
            path.write_text("{}\n")
            path.chmod(0o400)
        for name in ("broker.stderr", "broker.stdout"):
            path = attempt_root / "logs" / name
            path.write_text("")
            path.chmod(0o600)
    if tamper == "artifact":
        (execution / "attempts" / A / "session.jsonl").write_text("forbidden\n")
    current = {
        "migration": None,
        "runtime_superseded": False,
        "runtime": runtime,
        "authorization": authorization,
        "active": 0,
        "events": events,
        "states": states,
        "base": {"packet_publication_entry_hash": "sha256:" + "4" * 64},
    }
    _mock_migration_custody(monkeypatch, run._sha(bindings.read_bytes()))
    monkeypatch.setattr(
        run,
        "_campaign",
        lambda *_args: (
            {
                "id": "campaign",
                "lanes": [{"rank": 1, "attempt_id": A}, {"rank": 1, "attempt_id": B}],
            },
            b"campaign\n",
        ),
    )
    monkeypatch.setattr(campaign, "_private_root", lambda path: path)
    monkeypatch.setattr(campaign, "_ledger_lock", lambda _path: contextlib.nullcontext())
    monkeypatch.setattr(run, "_extended_ledger", lambda *_args: current)
    monkeypatch.setattr(run, "_same_process", lambda *_args: False)
    monkeypatch.setattr(
        run,
        "_state",
        lambda _root, attempt: {
            "broker_pid": 202 if tamper == "pid" and attempt == A else 101,
            "broker_start_identity": "start",
            "socket": str(tmp_path / f"{attempt}.sock"),
            "registry": str(tmp_path / f"{attempt}.registry"),
        },
    )
    expected = "broker state" if tamper == "pid" else "attempt inventory"
    with pytest.raises(run.GroundTruthRunError, match=expected):
        run.authorize_prelaunch_migration(
            ROOT,
            tmp_path / "campaign.json",
            bindings,
            tmp_path / "cache",
            ledger,
            tmp_path / "packets",
            execution,
        )


def test_migrated_agent_body_uses_final_root_not_random_staging(tmp_path: Path) -> None:
    parent = _private(tmp_path / "private")
    final = parent / "repaired-execution"
    staging = run._prepare_runtime_staging(final)
    final_extension = final / "runtime/extension/index.ts"
    body = run._agent_body(final_extension, "Review exactly.")
    assert str(final_extension).encode() in body
    assert str(staging).encode() not in body


def test_random_runtime_staging_leaves_crashed_partial_inert(tmp_path: Path) -> None:
    parent = _private(tmp_path / "private")
    final = parent / "new-execution"
    first = run._prepare_runtime_staging(final)
    second = run._prepare_runtime_staging(final)
    assert first != second
    assert first.exists() and second.exists()
    assert (first / ".runtime-staging-owner.json").is_file()
    assert (second / ".runtime-staging-owner.json").is_file()
    assert not final.exists()


@pytest.mark.parametrize("ledger_already_published", [False, True])
def test_migrated_runtime_recovers_pending_local_and_ledger_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ledger_already_published: bool,
) -> None:
    ledger = _private(tmp_path / "ledger")
    final = _private(tmp_path / "new-execution")
    prior = _private(tmp_path / "prior-execution")
    prior_status = prior.stat()
    prior_runtime = _runtime()
    migration = {
        "entry_hash": "sha256:" + "a" * 64,
        "prior_runtime_entry_hash": prior_runtime["entry_hash"],
        "prior_execution_root": str(prior),
        "prior_execution_device": prior_status.st_dev,
        "prior_execution_inode": prior_status.st_ino,
        "source_bindings_sha256": prior_runtime["source_bindings_sha256"],
        "production_profile_sha256": "sha256:" + "d" * 64,
    }
    current: dict[str, Any] = {
        "events": [],
        "head": migration["entry_hash"],
        "migration": migration,
        "generation": 1,
        "runtime": prior_runtime,
        "authorization": None,
        "base": {
            "campaign_id": "campaign",
            "campaign_manifest_sha256": "sha256:" + "2" * 64,
            "campaign_canary_lanes_sha256": prior_runtime["campaign_lanes_sha256"],
            "packet_publication_entry_hash": "sha256:" + "4" * 64,
        },
    }
    fields = {
        **{
            key: value
            for key, value in prior_runtime.items()
            if key not in {"schema_version", "protocol", "previous_hash", "entry_hash"}
        },
        "execution_root": str(final),
        "execution_device": final.stat().st_dev,
        "execution_inode": final.stat().st_ino,
        "production_profile_sha256": migration["production_profile_sha256"],
        "migration_entry_hash": migration["entry_hash"],
        "supersedes_entry_hash": prior_runtime["entry_hash"],
        "runtime_custody_receipt_path": str(final / "runtime/custody-receipt.json"),
        "runtime_custody_receipt_sha256": "sha256:" + "e" * 64,
    }
    candidate = run._event_value(current, "runtime_migrated", fields)
    pending = final / "runtime-attestation.pending.json"
    pending.write_bytes(canonical_json(candidate))
    pending.chmod(0o400)
    if ledger_already_published:
        current = {**current, "runtime": candidate, "head": candidate["entry_hash"]}
    if not ledger_already_published:
        tampered = {**candidate, "entry_hash": "sha256:" + "f" * 64}
        with pytest.raises(run.GroundTruthRunError, match="candidate"):
            run._validate_migrated_event_candidate(current, tampered)
    monkeypatch.setattr(run, "_migrated_candidate_files", lambda *_args: None)
    monkeypatch.setattr(campaign, "_private_root", lambda path: path)
    monkeypatch.setattr(campaign, "_ledger_lock", lambda _path: contextlib.nullcontext())

    def extended(*_args: Any) -> dict[str, Any]:
        event = ledger / f"lane-events/{candidate['sequence']:06d}-runtime_migrated-runtime.json"
        return {**current, "runtime": candidate} if event.exists() else current

    monkeypatch.setattr(run, "_extended_ledger", extended)
    recovered = run._recover_migrated_runtime(ROOT, ledger, final)
    assert recovered is not None
    assert (final / "runtime-attestation.json").read_bytes() == canonical_json(candidate)
    assert not pending.exists()
    if not ledger_already_published:
        assert (ledger / "lane-events/000001-runtime_migrated-runtime.json").exists()


def test_repaired_agent_replaces_only_bad_bytes_and_recovers_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = _private(tmp_path / "ledger")
    prior = _private(tmp_path / "prior")
    bad = _private(tmp_path / "bad")
    repaired = _private(tmp_path / "repaired")
    output_root = _private(tmp_path / "agents")
    output = output_root / "ground-truth-production-reviewer-v1.md"
    bad_body = b"bad migrated agent\n"
    repaired_body = b"repaired agent\n"
    output.write_bytes(bad_body)
    output.chmod(0o400)
    bad_runtime = _private(bad / "runtime")
    (bad_runtime / "agent-source.md").write_bytes(bad_body)
    (bad_runtime / "agent-source.md").chmod(0o400)
    old = b"old exact agent\n"
    (bad / "prior-agent-source.md").write_bytes(old)
    (bad / "prior-agent-source.md").chmod(0o400)
    repaired_runtime = _private(repaired / "runtime")
    (repaired_runtime / "agent-source.md").write_bytes(repaired_body)
    (repaired_runtime / "agent-source.md").chmod(0o400)
    prior_receipt = {
        "runtime_attestation_entry_hash": "sha256:" + "1" * 64,
        "path": str(output),
        "sha256": run._sha(old),
    }
    _publish(prior / "agent-installation.json", prior_receipt)
    prior_status = prior.stat()
    attestation: dict[str, Any] = {
        "kind": "runtime_migrated_repair",
        "entry_hash": "sha256:" + "3" * 64,
        "supersedes_entry_hash": "sha256:" + "2" * 64,
        "bad_execution_root": str(bad),
        "bad_agent_source_sha256": run._sha(bad_body),
    }
    migration = {
        "prior_runtime_entry_hash": "sha256:" + "1" * 64,
        "prior_execution_root": str(prior),
        "prior_execution_device": prior_status.st_dev,
        "prior_execution_inode": prior_status.st_ino,
    }
    current = {
        "migration": migration,
        "runtime": attestation,
        "generation": 1,
        "authorization": None,
    }
    identity = {
        "roots": [{"kind": "user-old", "path": str(output_root)}],
        "resolver_census_sha256": "sha256:" + "4" * 64,
        "resolver_census": {
            "builtin": [],
            "package": [],
            "project": [],
            "user": [{"name": run._AGENT_NAME, "filePath": str(output)}],
            "effective": [
                {
                    "name": run._AGENT_NAME,
                    "model": run._MODEL,
                    "thinking": run._THINKING,
                    "tools": list(run._TOOLS),
                    "extensions": [],
                    "subagentOnlyExtensions": [str(repaired / "runtime/extension/index.ts")],
                }
            ],
        },
    }
    attestation["runtime_identity"] = identity
    monkeypatch.setattr(campaign, "_private_root", lambda path: path)
    monkeypatch.setattr(campaign, "_ledger_lock", lambda _path: contextlib.nullcontext())
    monkeypatch.setattr(run, "_extended_ledger", lambda *_args: current)
    monkeypatch.setattr(run, "_runtime_attestation", lambda *_args, **_kwargs: attestation)
    monkeypatch.setattr(run, "_runtime_identity", lambda *_args: identity)
    first = run.create_native_agent(ROOT, repaired, output, ledger=ledger)
    second = run.create_native_agent(ROOT, repaired, output, ledger=ledger)
    assert first == second
    assert output.read_bytes() == repaired_body
    assert (repaired / "prior-agent-source.md").read_bytes() == old
    assert (repaired / "superseded-agent-source.md").read_bytes() == bad_body
    assert first["schema_version"] == 3


def test_migrated_agent_replaces_exact_prior_and_recovers_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = _private(tmp_path / "ledger")
    prior = _private(tmp_path / "prior")
    new = _private(tmp_path / "new")
    output_root = _private(tmp_path / "agents")
    output = output_root / "ground-truth-production-reviewer-v1.md"
    old = b"old exact agent\n"
    new_body = b"new exact agent\n"
    output.write_bytes(old)
    output.chmod(0o400)
    source = _private(new / "runtime") / "agent-source.md"
    source.write_bytes(new_body)
    source.chmod(0o400)
    prior_attestation = {"entry_hash": "sha256:" + "1" * 64}
    new_attestation: dict[str, Any] = {
        "entry_hash": "sha256:" + "2" * 64,
        "kind": "runtime_migrated",
    }
    prior_receipt = {
        "schema_version": 1,
        "protocol": "ground-truth-native-agent-installation-v1",
        "runtime_attestation_entry_hash": prior_attestation["entry_hash"],
        "agent_name": run._AGENT_NAME,
        "path": str(output),
        "sha256": run._sha(old),
        "bytes": len(old),
        "resolver_census_sha256": "sha256:" + "4" * 64,
        "runtime_identity": {},
    }
    _publish(prior / "agent-installation.json", prior_receipt)
    prior_status = prior.stat()
    migration = {
        "entry_hash": "sha256:" + "3" * 64,
        "prior_runtime_entry_hash": prior_attestation["entry_hash"],
        "prior_execution_root": str(prior),
        "prior_execution_device": prior_status.st_dev,
        "prior_execution_inode": prior_status.st_ino,
    }
    current = {
        "migration": migration,
        "runtime": new_attestation,
        "generation": 1,
        "authorization": None,
    }
    identity = {
        "roots": [{"kind": "user-old", "path": str(output_root)}],
        "resolver_census_sha256": "sha256:" + "4" * 64,
        "resolver_census": {
            "builtin": [],
            "package": [],
            "project": [],
            "user": [{"name": run._AGENT_NAME, "filePath": str(output)}],
            "effective": [
                {
                    "name": run._AGENT_NAME,
                    "model": run._MODEL,
                    "thinking": run._THINKING,
                    "tools": list(run._TOOLS),
                    "extensions": [],
                    "subagentOnlyExtensions": [str(new / "runtime/extension/index.ts")],
                }
            ],
        },
    }
    monkeypatch.setattr(campaign, "_private_root", lambda path: path)
    monkeypatch.setattr(campaign, "_ledger_lock", lambda _path: contextlib.nullcontext())
    monkeypatch.setattr(run, "_extended_ledger", lambda *_args: current)
    monkeypatch.setattr(
        run,
        "_runtime_attestation",
        lambda _root, path, **_kwargs: prior_attestation if path == prior else new_attestation,
    )
    monkeypatch.setattr(run, "_installed_agent", lambda *_args: prior_receipt)
    new_attestation["runtime_identity"] = identity

    def runtime_identity(*_args: object) -> dict[str, Any]:
        value = json.loads(json.dumps(identity))
        extension_root = prior if output.read_bytes() == old else new
        value["resolver_census"]["effective"][0]["subagentOnlyExtensions"] = [
            str(extension_root / "runtime/extension/index.ts")
        ]
        return cast("dict[str, Any]", value)

    monkeypatch.setattr(run, "_runtime_identity", runtime_identity)
    first = run.create_native_agent(ROOT, new, output, ledger=ledger)
    second = run.create_native_agent(ROOT, new, output, ledger=ledger)
    assert first == second
    assert output.read_bytes() == new_body
    assert (new / "prior-agent-source.md").read_bytes() == old
    assert first["schema_version"] == 2


def test_runtime_repair_incident_requires_exact_bad_global_and_absent_staging(
    tmp_path: Path,
) -> None:
    parent = _private(tmp_path / "private")
    prior = _private(parent / "prior")
    bad = _private(parent / "bad")
    runtime_dir = _private(bad / "runtime")
    staging = parent / f".{bad.name}.runtime-staging-deadbeef"
    bad_body = run._agent_body(staging / "runtime/extension/index.ts", "Review exactly.")
    agent_source = runtime_dir / "agent-source.md"
    agent_source.write_bytes(bad_body)
    agent_source.chmod(0o400)
    (bad / "runtime-attestation.json").write_bytes(b"{}\n")
    (bad / "runtime-attestation.json").chmod(0o400)
    output_root = _private(parent / "agents")
    output = output_root / "ground-truth-production-reviewer-v1.md"
    output.write_bytes(bad_body)
    output.chmod(0o400)
    old = b"old exact agent\n"
    old_archive = bad / "prior-agent-source.md"
    old_archive.write_bytes(old)
    old_archive.chmod(0o400)
    prior_receipt = {
        "runtime_attestation_entry_hash": "sha256:" + "1" * 64,
        "path": str(output),
        "sha256": run._sha(old),
    }
    _publish(prior / "agent-installation.json", prior_receipt)
    runtime = {
        "kind": "runtime_migrated",
        "entry_hash": "sha256:" + "2" * 64,
        "execution_root": str(bad),
        "agent_source_sha256": run._sha(bad_body),
    }
    current = {
        "migration": {
            "prior_execution_root": str(prior),
            "prior_runtime_entry_hash": "sha256:" + "1" * 64,
        },
        "runtime": runtime,
        "events": [runtime],
        "generation": 1,
        "authorization": None,
    }
    with pytest.raises(run.GroundTruthRunError, match="protocol"):
        run._validate_repair_incident(current)


def test_runtime_repair_candidate_is_one_shot_and_head_bound() -> None:
    migration = {
        "entry_hash": "sha256:" + "a" * 64,
        "source_bindings_sha256": "sha256:" + "3" * 64,
        "prior_execution_root": "/private/prior",
    }
    bad = {
        "schema_version": 2,
        "kind": "runtime_migrated",
        "entry_hash": "sha256:" + "b" * 64,
        "execution_root": "/private/bad",
        "production_profile_sha256": "sha256:" + "c" * 64,
        "agent_source_sha256": "sha256:" + "d" * 64,
    }
    current = {
        "migration": migration,
        "runtime": bad,
        "base": {
            "campaign_id": "campaign",
            "campaign_manifest_sha256": "sha256:" + "2" * 64,
            "campaign_canary_lanes_sha256": run._sha(canonical_json(_authorization_lanes())),
            "packet_publication_entry_hash": "sha256:" + "4" * 64,
        },
        "events": [bad],
        "head": bad["entry_hash"],
        "generation": 1,
        "authorization": None,
    }
    fields = {
        "campaign_id": "campaign",
        "campaign_manifest_sha256": "sha256:" + "2" * 64,
        "campaign_lanes_sha256": run._sha(canonical_json(_authorization_lanes())),
        "source_bindings_sha256": "sha256:" + "3" * 64,
        "packet_publication_entry_hash": "sha256:" + "4" * 64,
        "runtime_custody_receipt_path": "/private/repaired/runtime/custody-receipt.json",
        "runtime_custody_receipt_sha256": "sha256:" + "5" * 64,
        "production_profile_sha256": "sha256:" + "6" * 64,
        "production_files_sha256": "sha256:" + "7" * 64,
        "runtime_identity": _runtime()["runtime_identity"],
        "extension_sha256": "sha256:" + "8" * 64,
        "extension_schema_sha256": "sha256:" + "9" * 64,
        "agent_source_sha256": "sha256:" + "0" * 64,
        "execution_root": "/private/repaired",
        "execution_device": 5,
        "execution_inode": 6,
        "attested_at": "2026-01-01T04:00:00Z",
        "authorizations": {
            "review_launch": False,
            "adjudication": False,
            "canonical_import": False,
        },
        "supersedes_entry_hash": bad["entry_hash"],
        "migration_entry_hash": migration["entry_hash"],
        "bad_execution_root": bad["execution_root"],
        "bad_production_profile_sha256": bad["production_profile_sha256"],
        "bad_agent_source_sha256": bad["agent_source_sha256"],
    }
    candidate = run._event_value(current, "runtime_migrated_repair", fields)
    run._validate_repaired_event_candidate(current, candidate)
    altered = dict(current, events=[bad, {"entry_hash": "sha256:" + "e" * 64}])
    with pytest.raises(run.GroundTruthRunError, match="repair candidate"):
        run._validate_repaired_event_candidate(altered, candidate)
    repeated = dict(current, runtime={**bad, "kind": "runtime_migrated_repair"})
    with pytest.raises(run.GroundTruthRunError, match="repair candidate"):
        run._validate_repaired_event_candidate(repeated, candidate)


def test_exact_prelaunch_migration_runtime_authorization_and_reset_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger, auth = _ledger(tmp_path, monkeypatch)
    e1 = _event(ledger, auth["entry_hash"], 1, "prepared", A, _prepared(A))
    e2 = _event(ledger, e1["entry_hash"], 2, "prepared", B, _prepared(B))

    def failure(attempt: str) -> dict[str, Any]:
        return {
            "attempt_id": attempt,
            "reason": "never-launched broker exited",
            "failed_at": "2026-01-01T02:00:00Z",
            "relaunch_authorized": False,
        }

    e3 = _event(ledger, e2["entry_hash"], 3, "operational_failed", A, failure(A))
    e4 = _event(ledger, e3["entry_hash"], 4, "operational_failed", B, failure(B))
    prior = [e1, e2, e3, e4]
    migration = _special_event(
        ledger,
        e4["entry_hash"],
        5,
        "prelaunch_migration",
        "prelaunch",
        {
            "prior_runtime_entry_hash": _runtime()["entry_hash"],
            "prior_execution_root": _runtime()["execution_root"],
            "prior_execution_device": _runtime()["execution_device"],
            "prior_execution_inode": _runtime()["execution_inode"],
            "prior_authorization_entry_hash": auth["entry_hash"],
            "prior_events_sha256": run._sha(canonical_json(prior)),
            "prior_event_count": 4,
            "campaign_manifest_sha256": "sha256:" + "2" * 64,
            "source_bindings_sha256": "sha256:" + "3" * 64,
            "packet_publication_entry_hash": "sha256:" + "4" * 64,
            "production_profile_sha256": "sha256:" + "a" * 64,
            "attempt_ids": sorted([A, B]),
            "model_launch_count": 0,
            "migrated_at": "2026-01-01T03:00:00Z",
            "authorizations": {
                "review_launch": False,
                "adjudication": False,
                "canonical_import": False,
            },
        },
        run._MIGRATION_PROTOCOL,
        run._MIGRATION_DOMAIN,
    )
    runtime_fields = {
        key: value
        for key, value in _runtime().items()
        if key not in {"schema_version", "protocol", "previous_hash", "entry_hash"}
    }
    runtime_fields.update(
        {
            "production_profile_sha256": "sha256:" + "a" * 64,
            "execution_root": "/private/new",
            "execution_device": 3,
            "execution_inode": 4,
            "runtime_custody_receipt_path": "/private/new/runtime/custody-receipt.json",
            "runtime_custody_receipt_sha256": "sha256:" + "c" * 64,
            "supersedes_entry_hash": _runtime()["entry_hash"],
            "migration_entry_hash": migration["entry_hash"],
        }
    )
    migrated_runtime = _special_event(
        ledger,
        migration["entry_hash"],
        6,
        "runtime_migrated",
        "runtime",
        runtime_fields,
        run._MIGRATION_RUNTIME_PROTOCOL,
        run._MIGRATION_RUNTIME_DOMAIN,
        schema_version=2,
    )
    repaired_fields = {
        **runtime_fields,
        "execution_root": "/private/repaired",
        "execution_device": 5,
        "execution_inode": 6,
        "runtime_custody_receipt_path": "/private/repaired/runtime/custody-receipt.json",
        "supersedes_entry_hash": migrated_runtime["entry_hash"],
        "bad_execution_root": runtime_fields["execution_root"],
        "bad_production_profile_sha256": runtime_fields["production_profile_sha256"],
        "bad_agent_source_sha256": runtime_fields["agent_source_sha256"],
    }
    repaired_runtime = _special_event(
        ledger,
        migrated_runtime["entry_hash"],
        7,
        "runtime_migrated_repair",
        "runtime-repair",
        repaired_fields,
        run._MIGRATION_REPAIR_PROTOCOL,
        run._MIGRATION_REPAIR_DOMAIN,
        schema_version=2,
    )
    _special_event(
        ledger,
        repaired_runtime["entry_hash"],
        8,
        "canary_reauthorized",
        "canary",
        {
            "campaign_id": "campaign",
            "campaign_manifest_sha256": "sha256:" + "2" * 64,
            "runtime_attestation_entry_hash": repaired_runtime["entry_hash"],
            "agent_installation_sha256": "sha256:" + "d" * 64,
            "production_profile_sha256": "sha256:" + "a" * 64,
            "lanes": _authorization_lanes(),
            "attempt_ids": sorted([A, B]),
            "limits": {
                "max_global_active": 3,
                "max_processes_per_lane": 1,
                "replacement_attempts": 0,
            },
            "issued_at": "2026-01-01T03:00:00Z",
            "expires_at": "2026-01-02T03:00:00Z",
            "authorizations": {
                "review_launch": True,
                "adjudication": False,
                "canonical_import": False,
            },
            "migration_entry_hash": migration["entry_hash"],
            "generation": 2,
        },
        run._MIGRATED_AUTH_PROTOCOL,
        run._MIGRATED_AUTH_DOMAIN,
    )
    state = run._extended_ledger(ledger, ROOT)
    assert state["generation"] == 2
    assert state["states"] == {A: "authorized", B: "authorized"}
    assert state["runtime"] == repaired_runtime
    _special_event(
        ledger,
        state["head"],
        9,
        "runtime_migrated_repair",
        "runtime-repair",
        repaired_fields,
        run._MIGRATION_REPAIR_PROTOCOL,
        run._MIGRATION_REPAIR_DOMAIN,
        schema_version=2,
    )
    with pytest.raises(run.GroundTruthRunError, match="repair"):
        run._extended_ledger(ledger, ROOT)
    (ledger / "lane-events/000009-runtime_migrated_repair-runtime-repair.json").unlink()
    prepared_generation2 = _prepared(A)
    prepared_generation2.update(
        {"generation": 2, "runtime_attestation_entry_hash": repaired_runtime["entry_hash"]}
    )
    prepared2 = _special_event(
        ledger,
        state["head"],
        9,
        "prepared",
        A,
        prepared_generation2,
        "ground-truth-review-lane-event-v1",
        b"ground-truth-review-lane-event-v1\0",
    )
    failed2 = _special_event(
        ledger,
        prepared2["entry_hash"],
        10,
        "operational_failed",
        A,
        {"generation": 2, **failure(A)},
        "ground-truth-review-lane-event-v1",
        b"ground-truth-review-lane-event-v1\0",
    )
    archive_summary = {
        "archive_device": 1,
        "archive_inode": 2,
        "archive_inventory_sha256": "sha256:" + "1" * 64,
        "archive_entries": 5,
        "archive_bytes": 10,
        "binding_sha256": prepared2["binding_sha256"],
        "broker_pid": prepared2["broker_pid"],
        "broker_start_identity": prepared2["broker_start_identity"],
        "broker_stdout_sha256": "sha256:" + "2" * 64,
        "broker_stdout_bytes": 0,
        "broker_stderr_sha256": "sha256:" + "3" * 64,
        "broker_stderr_bytes": 1,
    }

    def replay_archive_summary(path: Path, _attempt: str, **kwargs: bool) -> dict[str, Any]:
        assert kwargs.get("historical_replay") is True
        if "generation3" in str(path):
            return {
                **archive_summary,
                "broker_pid": 0,
                "broker_start_identity": "pre-readiness-unpublished",
            }
        return archive_summary

    monkeypatch.setattr(run, "_validate_final_recovery_binding", lambda *_args: None)
    monkeypatch.setattr(run, "_recovery_archive_summary", replay_archive_summary)
    monkeypatch.setattr(run, "_require_no_live_broker_for_binding", pytest.fail)
    prior_events = run._extended_ledger(ledger, ROOT)["events"]
    recovery = _special_event(
        ledger,
        failed2["entry_hash"],
        11,
        "canary_prelaunch_recovery",
        "canary-recovery",
        {
            "campaign_id": "campaign",
            "campaign_manifest_sha256": "sha256:" + "2" * 64,
            "runtime_attestation_entry_hash": repaired_runtime["entry_hash"],
            "prior_authorization_entry_hash": state["authorization"]["entry_hash"],
            "agent_installation_sha256": "sha256:" + "d" * 64,
            "production_profile_sha256": "sha256:" + "a" * 64,
            "lanes": _authorization_lanes(),
            "attempt_ids": sorted([A, B]),
            "failed_attempt_id": A,
            "prepared_entry_hash": prepared2["entry_hash"],
            "failure_entry_hash": failed2["entry_hash"],
            "prior_events_sha256": run._sha(canonical_json(prior_events)),
            "prior_event_count": len(prior_events),
            "archive_path": f"/private/repaired/prelaunch-failures/generation2/{A}",
            **archive_summary,
            "limits": {
                "max_global_active": 3,
                "max_processes_per_lane": 1,
                "replacement_attempts": 0,
            },
            "model_launch_count": 0,
            "issued_at": "2026-01-01T04:00:00Z",
            "expires_at": "2026-01-02T04:00:00Z",
            "recovered_at": "2026-01-01T04:00:00Z",
            "authorizations": {
                "review_launch": True,
                "adjudication": False,
                "canonical_import": False,
            },
            "generation": 3,
        },
        run._PRELAUNCH_RECOVERY_PROTOCOL,
        run._PRELAUNCH_RECOVERY_DOMAIN,
    )
    recovered = run._extended_ledger(ledger, ROOT)
    assert recovered["generation"] == 3
    assert recovered["states"] == {A: "authorized", B: "authorized"}
    failed3 = _special_event(
        ledger,
        recovery["entry_hash"],
        12,
        "operational_failed",
        A,
        {
            "generation": 3,
            "attempt_id": A,
            "reason": "broker failed before readiness",
            "failed_at": "2026-01-01T05:00:00Z",
            "relaunch_authorized": False,
        },
        "ground-truth-review-lane-event-v1",
        b"ground-truth-review-lane-event-v1\0",
    )
    prior_events = run._extended_ledger(ledger, ROOT)["events"]
    final_recovery = _special_event(
        ledger,
        failed3["entry_hash"],
        13,
        "canary_final_prelaunch_recovery",
        "canary-final-recovery",
        {
            "campaign_id": "campaign",
            "campaign_manifest_sha256": "sha256:" + "2" * 64,
            "runtime_attestation_entry_hash": repaired_runtime["entry_hash"],
            "prior_authorization_entry_hash": recovery["entry_hash"],
            "agent_installation_sha256": "sha256:" + "d" * 64,
            "production_profile_sha256": "sha256:" + "a" * 64,
            "lanes": _authorization_lanes(),
            "attempt_ids": sorted([A, B]),
            "failed_attempt_id": A,
            "prepared_entry_hash": run._ZERO_HASH,
            "failure_entry_hash": failed3["entry_hash"],
            "prior_events_sha256": run._sha(canonical_json(prior_events)),
            "prior_event_count": len(prior_events),
            "archive_path": f"/private/repaired/prelaunch-failures/generation3/{A}",
            **{
                **archive_summary,
                "broker_pid": 0,
                "broker_start_identity": "pre-readiness-unpublished",
            },
            "limits": {
                "max_global_active": 3,
                "max_processes_per_lane": 1,
                "replacement_attempts": 0,
            },
            "model_launch_count": 0,
            "issued_at": "2026-01-01T05:00:00Z",
            "expires_at": "2026-01-02T05:00:00Z",
            "recovered_at": "2026-01-01T05:00:00Z",
            "authorizations": {
                "review_launch": True,
                "adjudication": False,
                "canonical_import": False,
            },
            "generation": 4,
        },
        run._FINAL_PRELAUNCH_RECOVERY_PROTOCOL,
        run._FINAL_PRELAUNCH_RECOVERY_DOMAIN,
    )
    recovered4 = run._extended_ledger(ledger, ROOT)
    assert recovered4["generation"] == 4
    assert recovered4["states"] == {A: "authorized", B: "authorized"}
    prepared_generation4 = {**prepared_generation2, "generation": 4}
    _special_event(
        ledger,
        final_recovery["entry_hash"],
        14,
        "prepared",
        A,
        prepared_generation4,
        "ground-truth-review-lane-event-v1",
        b"ground-truth-review-lane-event-v1\0",
    )
    assert run._extended_ledger(ledger, ROOT)["states"][A] == "prepared"


def test_ledger_rejects_unrelated_runtime_hash_and_task_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger, auth = _ledger(tmp_path / "runtime", monkeypatch)
    prepared = _prepared(A)
    prepared["runtime_attestation_entry_hash"] = "sha256:" + "f" * 64
    _event(ledger, auth["entry_hash"], 1, "prepared", A, prepared)
    with pytest.raises(run.GroundTruthRunError, match="prepared"):
        run._extended_ledger(ledger, ROOT)

    ledger, auth = _ledger(tmp_path / "tasks", monkeypatch)
    e1 = _event(ledger, auth["entry_hash"], 1, "prepared", A, _prepared(A))
    e2 = _event(ledger, e1["entry_hash"], 2, "prepared", B, _prepared(B))
    _event(
        ledger,
        e2["entry_hash"],
        3,
        "launch_claimed",
        "batch1",
        {
            "batch_id": "batch1",
            "attempt_ids": [A, B],
            "task_indices": [1, 0],
            "runtime_attestation_entry_hash": _runtime()["entry_hash"],
            "plan_sha256": "sha256:" + "e" * 64,
            "claimed_at": "2026-01-01T02:00:00Z",
        },
    )
    with pytest.raises(run.GroundTruthRunError, match="batch launch"):
        run._extended_ledger(ledger, ROOT)


def test_ledger_rejects_event_missing_required_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger, auth = _ledger(tmp_path, monkeypatch)
    fields = _prepared(A)
    fields.pop("binding_sha256")
    _event(ledger, auth["entry_hash"], 1, "prepared", A, fields)
    with pytest.raises(run.GroundTruthRunError, match="keys"):
        run._extended_ledger(ledger, ROOT)


def test_prepare_runtime_boundary_rejects_attestation_or_installation_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attestation = {"entry_hash": "sha256:" + "1" * 64}
    installation = {
        "runtime_attestation_entry_hash": attestation["entry_hash"],
        "sha256": "sha256:" + "2" * 64,
    }
    current = {
        "runtime": attestation,
        "authorization": {
            "runtime_attestation_entry_hash": attestation["entry_hash"],
            "agent_installation_sha256": run._sha(canonical_json(installation)),
        },
    }
    monkeypatch.setattr(run, "_runtime_attestation", lambda *_: dict(attestation))
    monkeypatch.setattr(run, "_installed_agent", lambda *_: dict(installation))
    assert run._runtime_boundary(ROOT, tmp_path, current, attestation, installation) == (
        attestation,
        installation,
    )
    monkeypatch.setattr(
        run,
        "_installed_agent",
        lambda *_: {**installation, "sha256": "sha256:" + "3" * 64},
    )
    with pytest.raises(run.GroundTruthRunError, match="drifted at lane boundary"):
        run._runtime_boundary(ROOT, tmp_path, current, attestation, installation)


def _generation2_attempt(execution: Path) -> tuple[Path, dict[str, Any]]:
    attempts = _private(execution / "attempts")
    attempt = _private(attempts / A)
    packet_dir = _private(attempt / "packet")
    packet_dir.chmod(0o500)
    _private(attempt / "escrow")
    logs = _private(attempt / "logs")
    stdout = logs / "broker.stdout"
    stderr = logs / "broker.stderr"
    stdout.write_bytes(b"")
    stderr.write_bytes(b"attestation startup failure\n")
    stdout.chmod(0o600)
    stderr.chmod(0o600)
    binding = attempt / "binding.json"
    binding.write_bytes(b'{"bound":true}\n')
    binding.chmod(0o400)
    state = {
        "schema_version": 1,
        "generation": 2,
        "attempt_id": A,
        "rank": 1,
        "lane": "A",
        "packet": str(attempt / "packet"),
        "binding": str(binding),
        "binding_sha256": run._sha(binding.read_bytes()),
        "broker_pid": 999_999_999,
        "broker_start_identity": "1",
        "socket": str(execution / "absent.sock"),
        "registry": str(execution / "absent-registry.json"),
        "deadline_unix_ms": 1,
        "runtime_attestation_entry_hash": "sha256:" + "a" * 64,
        "packet_root_sha256": "sha256:" + "b" * 64,
        "reviewer": {"name": "reviewer", "version": "v1"},
    }
    _publish(attempt / "native-state.json", state)
    slots = _private(execution / "slots")
    lock = slots / ".lock"
    lock.write_bytes(b"")
    lock.chmod(0o600)
    return attempt, state


def test_generation3_prelaunch_recovery_archives_once_and_is_crash_resumable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution = _private(tmp_path / "execution")
    attempt, state = _generation2_attempt(execution)
    binding_sha = run._sha((attempt / "binding.json").read_bytes())
    attestation = {
        "entry_hash": "sha256:" + "a" * 64,
        "kind": "runtime_migrated_repair",
        "production_profile_sha256": "sha256:" + "c" * 64,
        "execution_root": str(execution),
    }
    installation = {"runtime_attestation_entry_hash": attestation["entry_hash"]}
    installation_sha = run._sha(canonical_json(installation))
    lanes = _authorization_lanes()
    authorization = {
        "kind": "canary_reauthorized",
        "entry_hash": "sha256:" + "d" * 64,
        "agent_installation_sha256": installation_sha,
        "lanes": lanes,
    }
    prepared = {
        "kind": "prepared",
        "attempt_id": A,
        "generation": 2,
        "entry_hash": "sha256:" + "e" * 64,
        "binding_sha256": binding_sha,
        "broker_pid": state["broker_pid"],
        "broker_start_identity": state["broker_start_identity"],
    }
    failed = {
        "kind": "operational_failed",
        "attempt_id": A,
        "generation": 2,
        "entry_hash": "sha256:" + "f" * 64,
        "reason": "never-launched broker exited",
        "relaunch_authorized": False,
    }
    current: dict[str, Any] = {
        "generation": 2,
        "prelaunch_recovery": None,
        "runtime": attestation,
        "authorization": authorization,
        "active": 0,
        "launched_attempts": set(),
        "native_results": {},
        "states": {A: "operational_failed", B: "authorized"},
        "events": [prepared, failed],
    }
    verified = {**current, "generation": 3, "states": {A: "authorized", B: "authorized"}}
    appended: list[dict[str, Any]] = []
    phase = 0

    def ledger(*_args: object) -> dict[str, Any]:
        return current if phase == 0 else verified

    def append(*args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal phase
        appended.append(cast("dict[str, Any]", args[-1]))
        phase = 1
        return {"entry_hash": "sha256:" + "1" * 64}

    monkeypatch.setattr(run, "_runtime_attestation", lambda *_args: attestation)
    monkeypatch.setattr(run, "_installed_agent", lambda *_args: installation)
    monkeypatch.setattr(campaign, "_private_root", lambda path: path)
    monkeypatch.setattr(campaign, "_ledger_lock", lambda _path: contextlib.nullcontext())
    monkeypatch.setattr(run, "_extended_ledger", ledger)
    monkeypatch.setattr(run, "_append_event_locked", append)
    monkeypatch.setattr(
        run,
        "_campaign",
        lambda *_args: (
            {
                "id": "campaign",
                "lanes": [
                    {"rank": 1, "lane": "A", **lanes[0]},
                    {"rank": 1, "lane": "B", **lanes[1]},
                ],
            },
            b"campaign\n",
        ),
    )
    result = run.authorize_prelaunch_canary_recovery(
        ROOT, tmp_path / "campaign.json", tmp_path / "ledger", execution
    )
    archive = execution / "prelaunch-failures/generation2" / A
    assert result["generation"] == 3
    assert not attempt.exists() and archive.is_dir()
    assert (
        appended[0]["archive_inventory_sha256"]
        == run._recovery_archive_summary(archive, A)["archive_inventory_sha256"]
    )
    assert appended[0]["model_launch_count"] == 0

    # A crash after rename but before append is resumable from the exact archive.
    phase = 0
    current["prelaunch_recovery"] = None
    resumed = run.authorize_prelaunch_canary_recovery(
        ROOT, tmp_path / "campaign.json", tmp_path / "ledger", execution
    )
    assert resumed["generation"] == 3 and archive.is_dir()
    stderr = archive / "logs/broker.stderr"
    stderr.chmod(0o644)
    with pytest.raises(submit.GroundTruthSubmitError):
        run._recovery_archive_summary(archive, A)
    stderr.chmod(0o600)

    phase = 0
    current["prelaunch_recovery"] = {"already": True}
    with pytest.raises(run.GroundTruthRunError, match="not eligible"):
        run.authorize_prelaunch_canary_recovery(
            ROOT, tmp_path / "campaign.json", tmp_path / "ledger", execution
        )


def test_generation3_prelaunch_recovery_rejects_launch_or_wrong_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution = _private(tmp_path / "execution")
    _generation2_attempt(execution)
    attestation = {"entry_hash": "sha256:" + "a" * 64, "kind": "runtime_migrated_repair"}
    installation = {"runtime_attestation_entry_hash": attestation["entry_hash"]}
    base: dict[str, Any] = {
        "generation": 2,
        "prelaunch_recovery": None,
        "runtime": attestation,
        "authorization": {"kind": "canary_reauthorized", "lanes": _authorization_lanes()},
        "active": 0,
        "native_results": {},
        "states": {A: "operational_failed", B: "authorized"},
        "events": [],
    }
    monkeypatch.setattr(run, "_runtime_attestation", lambda *_args: attestation)
    monkeypatch.setattr(run, "_installed_agent", lambda *_args: installation)
    monkeypatch.setattr(campaign, "_private_root", lambda path: path)
    monkeypatch.setattr(campaign, "_ledger_lock", lambda _path: contextlib.nullcontext())
    monkeypatch.setattr(
        run,
        "_campaign",
        lambda *_args: ({"id": "campaign", "lanes": []}, b"campaign\n"),
    )
    for launched, states in [({A}, base["states"]), (set(), {A: "authorized", B: "authorized"})]:
        monkeypatch.setattr(
            run,
            "_extended_ledger",
            lambda *_args, launched=launched, states=states: {
                **base,
                "launched_attempts": launched,
                "states": states,
            },
        )
        with pytest.raises(run.GroundTruthRunError, match=r"not eligible|exact recoverable pair"):
            run.authorize_prelaunch_canary_recovery(
                ROOT, tmp_path / "campaign.json", tmp_path / "ledger", execution
            )


def test_terminal_generation4_prelaunch_recovery_is_exact_and_crash_resumable(  # noqa: PLR0915
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution = _private(tmp_path / "execution")
    attempt, _ = _generation2_attempt(execution)
    (attempt / "native-state.json").unlink()
    failures = _private(execution / "prelaunch-failures")
    _private(_private(failures / "generation2") / A)
    attestation = {
        "entry_hash": "sha256:" + "a" * 64,
        "kind": "runtime_migrated_repair",
        "production_profile_sha256": "sha256:" + "c" * 64,
        "execution_root": str(execution),
    }
    installation = {"runtime_attestation_entry_hash": attestation["entry_hash"]}
    lanes = _authorization_lanes()
    authorization = {
        "kind": "canary_prelaunch_recovery",
        "entry_hash": "sha256:" + "d" * 64,
        "agent_installation_sha256": run._sha(canonical_json(installation)),
        "lanes": lanes,
    }
    failed = {
        "kind": "operational_failed",
        "attempt_id": A,
        "generation": 3,
        "entry_hash": "sha256:" + "f" * 64,
        "reason": "broker failed before readiness",
        "relaunch_authorized": False,
    }
    current: dict[str, Any] = {
        "generation": 3,
        "prelaunch_recovery": authorization,
        "final_prelaunch_recovery": None,
        "runtime": attestation,
        "authorization": authorization,
        "active": 0,
        "launched_attempts": set(),
        "native_results": {},
        "states": {A: "operational_failed", B: "authorized"},
        "events": [failed],
    }
    verified = {**current, "generation": 4, "states": {A: "authorized", B: "authorized"}}
    appended: list[dict[str, Any]] = []
    broker_checks: list[Path] = []
    publication_lock_checks: list[bool] = []
    phase = 0

    def ledger(*_args: object) -> dict[str, Any]:
        return current if phase == 0 else verified

    def append(*args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal phase
        descriptor = os.open(execution / "slots/.lock", os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            publication_lock_checks.append(True)
        finally:
            os.close(descriptor)
        appended.append(cast("dict[str, Any]", args[-1]))
        phase = 1
        return {"entry_hash": "sha256:" + "1" * 64}

    monkeypatch.setattr(run, "_runtime_attestation", lambda *_args: attestation)
    monkeypatch.setattr(run, "_installed_agent", lambda *_args: installation)
    monkeypatch.setattr(campaign, "_private_root", lambda path: path)
    monkeypatch.setattr(campaign, "_ledger_lock", lambda _path: contextlib.nullcontext())
    monkeypatch.setattr(run, "_extended_ledger", ledger)

    def record_broker_check(path: Path) -> None:
        broker_checks.append(path)

    monkeypatch.setattr(run, "_append_event_locked", append)
    monkeypatch.setattr(run, "_validate_final_recovery_binding", lambda *_args: None)
    monkeypatch.setattr(run, "_require_no_live_broker_for_binding", record_broker_check)
    monkeypatch.setattr(
        run,
        "_campaign",
        lambda *_args: (
            {
                "id": "campaign",
                "lanes": [
                    {"rank": 1, "lane": "A", **lanes[0]},
                    {"rank": 1, "lane": "B", **lanes[1]},
                ],
            },
            b"campaign\n",
        ),
    )
    installation_calls = 0

    def drift_at_publication(*_args: object) -> dict[str, Any]:
        nonlocal installation_calls
        installation_calls += 1
        if installation_calls >= 3:
            return {**installation, "unexpected_drift": True}
        return installation

    monkeypatch.setattr(run, "_installed_agent", drift_at_publication)
    with pytest.raises(run.GroundTruthRunError, match="drifted before final recovery publication"):
        run.authorize_final_prelaunch_canary_recovery(
            ROOT, tmp_path / "campaign.json", tmp_path / "ledger", execution
        )
    assert not appended
    monkeypatch.setattr(run, "_installed_agent", lambda *_args: installation)

    result = run.authorize_final_prelaunch_canary_recovery(
        ROOT, tmp_path / "campaign.json", tmp_path / "ledger", execution
    )
    archive = execution / "prelaunch-failures/generation3" / A
    assert result["generation"] == 4
    assert not attempt.exists() and archive.is_dir()
    assert appended[0]["broker_pid"] == 0
    assert appended[0]["prepared_entry_hash"] == run._ZERO_HASH
    assert appended[0]["model_launch_count"] == 0
    source_binding = attempt / "binding.json"
    archive_binding = archive / "binding.json"
    assert broker_checks == [
        source_binding,
        source_binding,
        source_binding,
        archive_binding,
        archive_binding,
    ]
    assert publication_lock_checks == [True]

    phase = 0
    resumed = run.authorize_final_prelaunch_canary_recovery(
        ROOT, tmp_path / "campaign.json", tmp_path / "ledger", execution
    )
    assert resumed["generation"] == 4 and archive.is_dir()

    phase = 0
    current["launched_attempts"] = {A}
    with pytest.raises(run.GroundTruthRunError, match="not eligible"):
        run.authorize_final_prelaunch_canary_recovery(
            ROOT, tmp_path / "campaign.json", tmp_path / "ledger", execution
        )


def test_final_recovery_binding_requires_exact_frozen_generation3_identity(
    tmp_path: Path,
) -> None:
    archive = _private(tmp_path / "archive")
    runtime_hash = "sha256:" + "a" * 64
    profile_checksum, profile_files = run._final_recovery_profile_identity(ROOT)
    original = _submit_packet_and_record(tmp_path)
    selection = original.selection_custody.model_copy(
        update={"runtime_attestation_entry_hash": runtime_hash}
    )
    record = original.model_copy(
        update={
            "generation": 3,
            "attempt_id": A,
            "runtime_attestation_entry_hash": runtime_hash,
            "selection_custody": selection,
            "profile_checksum_sha256": profile_checksum,
            "profile_files_sha256": profile_files,
        }
    )
    document = submit.SubmissionBindings(
        schema_version=1,
        protocol="ground-truth-review-submit-v1",
        records=(record,),
    )
    binding = archive / "binding.json"
    binding.write_bytes(canonical_json(document.model_dump(mode="json")))
    binding.chmod(0o400)
    digest = run._sha(binding.read_bytes())
    run._validate_final_recovery_binding(ROOT, archive, A, runtime_hash, digest)

    generation4 = document.model_copy(
        update={"records": (record.model_copy(update={"generation": 4}),)}
    )
    binding.chmod(0o600)
    binding.write_bytes(canonical_json(generation4.model_dump(mode="json")))
    binding.chmod(0o400)
    with pytest.raises(run.GroundTruthRunError, match="exact generation3 lane"):
        run._validate_final_recovery_binding(
            ROOT, archive, A, runtime_hash, run._sha(binding.read_bytes())
        )


def test_historical_recovery_replay_ignores_live_reused_attempt_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive, _ = _generation2_attempt(tmp_path)
    (archive / "native-state.json").unlink()
    unrelated_live_socket = tmp_path / "generation4.sock"
    unrelated_live_socket.write_bytes(b"live generation4")
    monkeypatch.setattr(run, "_require_no_live_broker_for_binding", pytest.fail)
    monkeypatch.setattr(run, "_same_process", pytest.fail)

    summary = run._recovery_archive_summary(
        archive,
        A,
        allow_missing_state=True,
        historical_replay=True,
    )
    assert summary["broker_pid"] == 0
    assert unrelated_live_socket.exists()


def test_broker_path_uses_exact_attested_node_parent() -> None:
    attestation = {"runtime_identity": {"resolver_execution": {"node_path": "/usr/local/bin/node"}}}
    assert run._attested_broker_path(attestation) == "/usr/local/bin:/usr/bin:/bin"
    attestation["runtime_identity"]["resolver_execution"]["node_path"] = "/tmp/node"
    with pytest.raises(run.GroundTruthRunError, match="Node path is invalid"):
        run._attested_broker_path(attestation)


def test_stale_prepare_authority_is_rejected_and_its_attempt_is_removed(tmp_path: Path) -> None:
    old_hash = "sha256:" + "1" * 64
    old = {
        "generation": 3,
        "authorization": {"entry_hash": old_hash},
        "states": {A: "authorized"},
    }
    assert run._lane_authority_matches(old, A, 3, old_hash, "authorized")
    transitioned = {
        "generation": 4,
        "authorization": {"entry_hash": "sha256:" + "2" * 64},
        "states": {A: "authorized"},
    }
    with pytest.raises(run._LaneAuthorityChanged, match="authorization changed"):
        run._require_lane_authority(transitioned, A, 3, old_hash, "authorized")

    attempts = _private(tmp_path / "attempts")
    attempt = _private(attempts / A)
    payload = attempt / "binding.json"
    payload.write_bytes(b"stale\n")
    payload.chmod(0o400)
    run._remove_stale_attempt(attempt, attempts)
    assert not attempt.exists()


def test_prepare_attempt_cannot_cross_authorization_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution = _private(tmp_path / "execution")
    old_hash = "sha256:" + "1" * 64
    new_hash = "sha256:" + "2" * 64
    lane = {"lane_key": "rank001-A", "attempt_id": A, "reviewer": {}}
    old = {
        "generation": 3,
        "authorization": {"entry_hash": old_hash, "lanes": [lane]},
        "states": {A: "authorized"},
    }
    transitioned = {
        "generation": 4,
        "authorization": {"entry_hash": new_hash, "lanes": [lane]},
        "states": {A: "authorized"},
    }
    states = iter([old, transitioned, transitioned])
    attestation = {
        "entry_hash": "sha256:" + "3" * 64,
        "runtime_custody_receipt_path": str(tmp_path / "receipt.json"),
        "runtime_custody_receipt_sha256": "sha256:" + "4" * 64,
    }
    installation: dict[str, Any] = {}
    monkeypatch.setattr(run, "_runtime_attestation", lambda *_args: attestation)
    monkeypatch.setattr(run, "_installed_agent", lambda *_args: installation)
    monkeypatch.setattr(campaign, "_private_root", lambda path: path)
    monkeypatch.setattr(campaign, "_ledger_lock", lambda _path: contextlib.nullcontext())
    monkeypatch.setattr(run, "_extended_ledger", lambda *_args: next(states))
    monkeypatch.setattr(run, "_authorization", lambda current, _now=None: current["authorization"])
    monkeypatch.setattr(run, "_runtime_boundary", lambda *_args: (attestation, installation))
    monkeypatch.setattr(
        run,
        "_campaign",
        lambda *_args: (
            {"lanes": [{"attempt_id": A, "rank": 1, "lane": "A"}]},
            b"campaign\n",
        ),
    )
    monkeypatch.setattr(submit, "prepare_binding", pytest.fail)
    monkeypatch.setattr(run, "_operational_failure", pytest.fail)

    with pytest.raises(run._LaneAuthorityChanged, match="authorization changed"):
        run.prepare_attempt(
            ROOT,
            tmp_path / "campaign.json",
            tmp_path / "bindings.json",
            tmp_path / "cache.git",
            tmp_path / "ledger",
            tmp_path / "packets",
            execution,
            rank=1,
            lane="A",
            attempt_id=A,
        )
    assert not (execution / "attempts" / A).exists()
    assert {path.name for path in (execution / "slots").iterdir()} == {".lock"}


def test_runtime_boundary_binds_authorized_agent_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attestation = {"entry_hash": "sha256:" + "1" * 64}
    installation = {"runtime_attestation_entry_hash": attestation["entry_hash"]}
    current = {
        "runtime": attestation,
        "authorization": {
            "runtime_attestation_entry_hash": attestation["entry_hash"],
            "agent_installation_sha256": run._sha(canonical_json(installation)),
        },
    }
    monkeypatch.setattr(run, "_runtime_attestation", lambda *_args: attestation)
    monkeypatch.setattr(run, "_installed_agent", lambda *_args: installation)
    assert run._runtime_boundary(ROOT, ROOT, current, attestation, installation) == (
        attestation,
        installation,
    )
    current["authorization"]["agent_installation_sha256"] = "sha256:" + "f" * 64
    with pytest.raises(run.GroundTruthRunError, match="installation drifted"):
        run._runtime_boundary(ROOT, ROOT, current, attestation, installation)


def test_slots_bind_owner_lane_and_broker(tmp_path: Path) -> None:
    execution = _private(tmp_path / "execution")
    path = run._slot_claim(execution, A, 1, "A")
    value = json.loads(path.read_bytes())
    assert value["owner_start_identity"] == run._proc_identity(os.getpid())
    assert value["lane"] == "A" and value["broker_pid"] is None
    run._slot_update_broker(execution, A, os.getpid(), run._proc_identity(os.getpid()))
    assert json.loads(path.read_bytes())["broker_pid"] == os.getpid()
    run._slot_release(execution, A)


def _usage() -> dict[str, Any]:
    return {
        "input": 10,
        "output": 5,
        "cacheRead": 2,
        "cacheWrite": 0,
        "reasoning": 1,
        "totalTokens": 17,
        "cost": {
            "input": 0.001,
            "output": 0.002,
            "cacheRead": 0.0,
            "cacheWrite": 0.0,
            "total": 0.003,
        },
    }


def _session(
    path: Path, packet: Path, receipt: dict[str, Any], *, extra_user: bool = False
) -> None:
    rows: list[dict[str, Any]] = [
        {
            "type": "session",
            "version": 3,
            "id": "session123",
            "timestamp": "2026-01-01T00:00:00.000Z",
            "cwd": str(packet),
        },
        {
            "type": "model_change",
            "id": "model1",
            "parentId": None,
            "timestamp": "2026-01-01T00:00:01.000Z",
            "provider": "openai-codex",
            "modelId": "gpt-5.6-luna",
        },
        {
            "type": "thinking_level_change",
            "id": "think1",
            "parentId": "model1",
            "timestamp": "2026-01-01T00:00:02.000Z",
            "thinkingLevel": "medium",
        },
        {
            "type": "message",
            "id": "user1",
            "parentId": "think1",
            "timestamp": "2026-01-01T00:00:03.000Z",
            "message": {
                "role": "user",
                "content": [{"type": "text", "text": run._TASK_TEXT}],
                "timestamp": 1,
            },
        },
    ]
    parent = "user1"
    if extra_user:
        rows.append(
            {
                "type": "message",
                "id": "user2",
                "parentId": parent,
                "timestamp": "2026-01-01T00:00:04.000Z",
                "message": {
                    "role": "user",
                    "content": [{"type": "text", "text": "steer"}],
                    "timestamp": 2,
                },
            }
        )
        parent = "user2"
    rows.extend(
        [
            {
                "type": "message",
                "id": "assistant1",
                "parentId": parent,
                "timestamp": "2026-01-01T00:00:05.000Z",
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "toolCall",
                            "id": "call1",
                            "name": "submit_blind_review",
                            "arguments": {},
                        }
                    ],
                    "api": "openai-codex-responses",
                    "provider": "openai-codex",
                    "model": "gpt-5.6-luna",
                    "usage": _usage(),
                    "stopReason": "toolUse",
                    "timestamp": 3,
                    "responseId": "resp1",
                },
            },
            {
                "type": "message",
                "id": "result1",
                "parentId": "assistant1",
                "timestamp": "2026-01-01T00:00:06.000Z",
                "message": {
                    "role": "toolResult",
                    "toolCallId": "call1",
                    "toolName": "submit_blind_review",
                    "content": [{"type": "text", "text": "submitted"}],
                    "details": receipt,
                    "isError": False,
                    "timestamp": 4,
                },
            },
            {
                "type": "message",
                "id": "assistant2",
                "parentId": "result1",
                "timestamp": "2026-01-01T00:00:07.000Z",
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": "SUBMISSION_COMPLETE", "textSignature": "signed"}
                    ],
                    "api": "openai-codex-responses",
                    "provider": "openai-codex",
                    "model": "gpt-5.6-luna",
                    "usage": _usage(),
                    "stopReason": "stop",
                    "timestamp": 5,
                    "responseId": "resp2",
                },
            },
        ]
    )
    path.write_bytes(
        b"".join(
            (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode() for row in rows
        )
    )
    path.chmod(0o600)


def test_realistic_session_grammar_and_extra_user_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _private(tmp_path / "agent")
    config = _private(agent / "extensions" / "subagent") / "config.json"
    config.write_text("{}")
    sessions = _private(agent / "sessions")
    monkeypatch.setattr(
        run, "_package_paths", lambda: (Path("/unused"), Path("/unused"), Path("/unused"), config)
    )
    packet = _private(tmp_path / "packet").resolve()
    receipt = {"attempt_id": A, "ok": True}
    session = sessions / "session.jsonl"
    _session(session, packet, receipt)
    status = session.stat()
    bound = {
        "session_path": str(session),
        "session_device": status.st_dev,
        "session_inode": status.st_ino,
        "session_uid": status.st_uid,
        "session_mode": 0o600,
        "session_sha256": run._sha(session.read_bytes()),
        "parent_status": "success",
    }
    assert run._audit_session_data(session, packet, receipt, bound)["submit_calls"] == 1
    session.chmod(0o600)
    _session(session, packet, receipt, extra_user=True)
    bound["session_sha256"] = run._sha(session.read_bytes())
    with pytest.raises(run.GroundTruthRunError, match="user task"):
        run._audit_session_data(session, packet, receipt, bound)


def test_session_event_ids_are_unique_and_parent_chain_is_linear(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _private(tmp_path / "agent")
    config = _private(agent / "extensions" / "subagent") / "config.json"
    config.write_text("{}")
    sessions = _private(agent / "sessions")
    monkeypatch.setattr(
        run, "_package_paths", lambda: (Path("/unused"), Path("/unused"), Path("/unused"), config)
    )
    packet = _private(tmp_path / "packet").resolve()
    receipt = {"attempt_id": A, "ok": True}
    session = sessions / "session.jsonl"
    _session(session, packet, receipt)
    rows = [json.loads(line) for line in session.read_text().splitlines()]
    status = session.stat()
    bound = {
        "session_path": str(session),
        "session_device": status.st_dev,
        "session_inode": status.st_ino,
        "session_uid": status.st_uid,
        "session_mode": 0o600,
        "session_sha256": "",
        "parent_status": "success",
    }
    rows[2]["id"] = rows[1]["id"]
    rows[2]["parentId"] = rows[1]["id"]
    session.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows))
    bound["session_sha256"] = run._sha(session.read_bytes())
    with pytest.raises(run.GroundTruthRunError, match="duplicated"):
        run._audit_session_data(session, packet, receipt, bound)

    _session(session, packet, receipt)
    rows = [json.loads(line) for line in session.read_text().splitlines()]
    rows[2]["parentId"] = rows[2]["id"]
    session.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows))
    bound["session_sha256"] = run._sha(session.read_bytes())
    with pytest.raises(run.GroundTruthRunError, match="duplicated"):
        run._audit_session_data(session, packet, receipt, bound)


def test_session_layout_is_exactly_bound_to_native_run_and_task(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _private(tmp_path / "agent")
    config = _private(agent / "extensions" / "subagent") / "config.json"
    config.write_text("{}")
    session = _private(agent / "sessions" / "parent" / "deadbeef" / "run-1") / "session.jsonl"
    session.write_text("{}\n")
    monkeypatch.setattr(
        run, "_package_paths", lambda: (Path("/unused"), Path("/unused"), Path("/unused"), config)
    )
    run._validate_session_layout(session, "deadbeef", 1)
    with pytest.raises(run.GroundTruthRunError, match="claimed native batch task"):
        run._validate_session_layout(session, "deadbeef", 0)
    with pytest.raises(run.GroundTruthRunError, match="claimed native batch task"):
        run._validate_session_layout(session, "cafebabe", 1)


def test_native_plan_shape_is_schema_validated_before_one_batch_claim(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ledger, execution = _private(tmp_path / "ledger"), _private(tmp_path / "execution")
    packet = _private(tmp_path / "packet")
    runtime = _runtime()
    current = {
        "runtime": runtime,
        "authorization": _auth(runtime),
        "states": {A: "prepared"},
        "batches": {},
        "head": BASE,
    }
    state = {
        "broker_pid": os.getpid(),
        "broker_start_identity": run._proc_identity(os.getpid()),
        "deadline_unix_ms": 9_999_999_999_999,
        "packet": str(packet),
        "binding": "/binding",
    }
    monkeypatch.setattr(run, "_installed_agent", lambda *_: {})
    monkeypatch.setattr(campaign, "_private_root", lambda value: value)
    monkeypatch.setattr(campaign, "_ledger_lock", lambda _: contextlib.nullcontext())
    monkeypatch.setattr(run, "_extended_ledger", lambda *_: current)
    monkeypatch.setattr(run, "_authorization", lambda value, *_, **__: value["authorization"])
    monkeypatch.setattr(run, "_state", lambda *_: state)
    monkeypatch.setattr(run, "_same_process", lambda *_: True)
    monkeypatch.setattr(
        submit,
        "load_bindings",
        lambda _: type(
            "B",
            (),
            {
                "records": [
                    type(
                        "R",
                        (),
                        {
                            "packet_device": packet.stat().st_dev,
                            "packet_inode": packet.stat().st_ino,
                        },
                    )()
                ]
            },
        )(),
    )
    validated: list[dict[str, Any]] = []

    def validate_plan(_root: Path, plan: dict[str, Any]) -> str:
        validated.append(plan)
        return "sha256:" + "f" * 64

    monkeypatch.setattr(run, "_validate_native_plan_schema", validate_plan)
    appended: list[tuple[Any, ...]] = []

    def append_event(*args: Any) -> dict[str, Any]:
        appended.append(args)
        return {"entry_hash": BASE}

    monkeypatch.setattr(run, "_append_event_locked", append_event)
    result = run.native_launch_plan(ROOT, ledger, execution, [A])
    plan = result["subagent_call"]
    assert validated == [plan] and len(appended) == 1
    assert appended[0][5]["attempt_ids"] == [A]
    assert appended[0][5]["task_indices"] == [0]
    assert set(plan) == {
        "tasks",
        "context",
        "concurrency",
        "artifacts",
        "includeProgress",
        "async",
        "timeoutMs",
    }
    assert "thinking" not in plan["tasks"][0] and "artifacts" not in plan["tasks"][0]
    assert plan["artifacts"] is False and plan["includeProgress"] is False


def test_only_bounded_node_and_broker_spawn_are_process_surfaces() -> None:
    tree = ast.parse(Path(run.__file__).read_text())
    run_calls: list[str] = []
    spawn_calls: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "run":
                run_calls.append(getattr(node.func.value, "id", ""))
            if node.func.attr == "posix_spawn":
                spawn_calls.append(getattr(node.func.value, "id", ""))
    assert run_calls == ["subprocess"]
    assert spawn_calls == ["os"]
    source = Path(run.__file__).read_text()
    assert "pi -p" not in source and "shell=True" not in source


def test_runtime_schemas_are_strict_and_checksums_match() -> None:
    profile = json.loads(
        (ROOT / "benchmarks/real_world/production_v1/checksums-v1.json").read_bytes()
    )
    for name in (
        "runtime-attestation-schema-v1.json",
        "review-canary-authorization-schema-v1.json",
        "lane-event-schema-v1.json",
        "session-audit-schema-v1.json",
        "prelaunch-migration-schema-v1.json",
    ):
        schema = json.loads((ROOT / "benchmarks/real_world/production_v1" / name).read_bytes())
        assert schema.get("additionalProperties") is False or "oneOf" in schema
    for relative, digest in profile["files"].items():
        assert run._sha((ROOT / relative).read_bytes()) == digest
