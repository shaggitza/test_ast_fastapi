from __future__ import annotations

import ast
import contextlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from benchmarks.real_world import ground_truth_campaign_v1 as campaign
from benchmarks.real_world import ground_truth_run_v1 as run
from benchmarks.real_world import ground_truth_submit_v1 as submit
from benchmarks.real_world.ground_truth_v2.schema import canonical_json

ROOT = Path(__file__).resolve().parents[2]
BASE = "sha256:" + "1" * 64
A = "prod-v1-i149-rank001-pr2330-A"
B = "prod-v1-i149-rank001-pr2330-B"


def _private(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


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
        "runtime_identity": run._runtime_identity(ROOT),
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
    identity = run._runtime_identity(ROOT)
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
    identity = run._runtime_identity(ROOT)
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
    first = run._broker_socket_path(A)
    second = run._broker_socket_path(B)
    assert first != second
    assert len(os.fsencode(first)) < 100
    first.touch()
    try:
        with pytest.raises(run.GroundTruthRunError, match="already exists"):
            run._broker_socket_path(A)
    finally:
        first.unlink(missing_ok=True)


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
    pi_args = Path(run._runtime_identity(ROOT)["runtime_files"]["pi_args"]["path"]).read_text()
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
        "authorization": {"runtime_attestation_entry_hash": attestation["entry_hash"]},
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
    ):
        schema = json.loads((ROOT / "benchmarks/real_world/production_v1" / name).read_bytes())
        assert schema.get("additionalProperties") is False or "oneOf" in schema
    for relative, digest in profile["files"].items():
        assert run._sha((ROOT / relative).read_bytes()) == digest
