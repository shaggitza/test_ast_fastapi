from __future__ import annotations

import hashlib
import json
import stat
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from benchmarks.real_world import pilot_adjudicate_v3 as adjudicate
from benchmarks.real_world import pilot_submit_v3 as submit
from benchmarks.real_world import pilot_typed_run_v3 as review_run
from benchmarks.real_world.ground_truth_v2.schema import (
    ReviewArtifactV1,
    artifact_sha256,
    canonical_json,
)

SHA1 = "1" * 40
SHA2 = "2" * 40


def _location(line: int = 1) -> dict[str, object]:
    return {
        "side": "target",
        "commit_sha": SHA2,
        "blob_sha": SHA1,
        "path": "src/main.py",
        "start_line": line,
        "end_line": line,
        "symbol": "public",
    }


def _review(
    repository: str,
    pr: int,
    lane: str,
    terminal: str,
    *,
    public_ids: tuple[str, ...] = (),
    recommendation: str = "include",
    unknowns: bool = False,
) -> ReviewArtifactV1:
    claims = []
    for index, public_id in enumerate(public_ids):
        claims.append(
            {
                "claim_id": f"claim-{lane}-{index}",
                "claim_kind": "entrypoint",
                "recommendation": recommendation,
                "summary": f"summary {index}",
                "entrypoint": {"public_id": public_id, "kind": "sdk", "confidence": "confirmed"},
                "evidence": [
                    {
                        "ordinal": 0,
                        "relation": "direct",
                        "from_location": _location(index + 1),
                        "to_location": _location(index + 1),
                    }
                ],
            }
        )
    payload: dict[str, Any] = {
        "schema_version": 1,
        "artifact_type": "ground_truth_review",
        "corpus_id": "pilot",
        "repository": repository,
        "pr": pr,
        "lane": lane,
        "snapshots": {"baseline_commit": SHA1, "target_commit": SHA2},
        "reviewer": {"kind": "agent", "name": "reviewer", "version": "v1"},
        "run": {
            "prompt_sha256": "sha256:" + "a" * 64,
            "model_policy_sha256": "sha256:" + "b" * 64,
            "tool_policy_sha256": "sha256:" + "c" * 64,
            "source_policy_sha256": "sha256:" + "d" * 64,
            "started_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
            "completed_at": datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
            "limits": {
                "max_tokens": 100,
                "max_tool_calls": 100,
                "max_seconds": 100,
                "max_output_bytes": 10000,
            },
        },
        "terminal_recommendation": terminal,
        "changed_symbols": [
            {"symbol_id": "symbol-0", "canonical_name": "module.changed", "location": _location()}
        ],
        "claims": claims,
        "unknowns": (
            [
                {
                    "unknown_id": "unknown-0",
                    "category": "dynamic",
                    "description": "not established",
                    "evidence_limit": "source only",
                }
            ]
            if unknowns
            else []
        ),
        "negative_assessment": (
            {
                "changed_symbol_census_complete": True,
                "searched_entrypoint_families": ["sdk"],
                "limitations": ["source only"],
            }
            if terminal == "negative_control"
            else None
        ),
        "notes": "",
    }
    return ReviewArtifactV1.model_validate(payload)


def _raw(review: ReviewArtifactV1) -> bytes:
    return canonical_json(review.model_dump(mode="json"))


def _execution(tmp_path: Path) -> Path:
    root = tmp_path / "execution"
    (root / "attempts").mkdir(parents=True, mode=0o700)
    return root


def _add_attempt(root: Path, name: str) -> None:
    attempt = root / "attempts" / name
    attempt.mkdir(mode=0o700)
    (attempt / "native-result.json").write_text("{}")


def test_normalization_ignores_ids_summaries_and_evidence_order() -> None:
    first = _review("owner/repo", 1, "A", "positive", public_ids=("sdk.b", "sdk.a"))
    second = _review("owner/repo", 1, "B", "positive", public_ids=("sdk.a", "sdk.b"))
    second_payload = second.model_dump(mode="json")
    for index, claim in enumerate(second_payload["claims"]):
        claim["claim_id"] = f"other-{index}"
        claim["summary"] = "different prose"
    second = ReviewArtifactV1.model_validate(second_payload)
    assert adjudicate._review_atom_rows(first) == adjudicate._review_atom_rows(second)


def test_normalization_rejects_internal_conflict() -> None:
    first = _review("owner/repo", 1, "A", "positive", public_ids=("sdk.a",))
    claims = [first.claims[0], first.claims[0].model_copy(update={"recommendation": "exclude"})]
    with pytest.raises(adjudicate.PilotAdjudicationError, match="conflicting"):
        adjudicate._claim_atoms(claims)


def test_pair_hash_binds_lane_order() -> None:
    assert adjudicate._pair_hash(
        "sha256:" + "a" * 64, "sha256:" + "b" * 64
    ) != adjudicate._pair_hash("sha256:" + "b" * 64, "sha256:" + "a" * 64)


def test_compare_current_shape_two_agreements_one_consumed_disagreement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _execution(tmp_path)
    reviews: dict[str, ReviewArtifactV1] = {
        "one-A": _review("owner/one", 1, "A", "negative_control"),
        "one-B": _review("owner/one", 1, "B", "negative_control"),
        "two-A": _review("owner/two", 2, "A", "negative_control"),
        "two-B": _review("owner/two", 2, "B", "negative_control"),
        "three-A": _review("owner/three", 3, "A", "positive", public_ids=("sdk.a",)),
        "three-B": _review("owner/three", 3, "B", "negative_control"),
    }
    for name in reviews:
        _add_attempt(root, name)
    monkeypatch.setattr(
        review_run,
        "_reauthenticate_execution",
        lambda _root: {"source_root": str(Path(__file__).resolve().parents[2])},
    )
    monkeypatch.setattr(
        adjudicate,
        "_authenticated_review",
        lambda _root, name: (reviews[name], _raw(reviews[name])),
    )
    three_pair = adjudicate._pair_hash(
        _sha_review(reviews["three-A"]), _sha_review(reviews["three-B"])
    )
    monkeypatch.setattr(adjudicate, "_consumed_pairs", lambda _root: {three_pair})
    result = adjudicate.compare_execution(root)
    assert result["totals"] == {"pairs": 3, "agreements": 2, "xhigh_required": 1}
    pair = next(row for row in cast("list[dict[str, Any]]", result["pairs"]) if row["pr"] == 3)
    assert pair["fallback_consumed"] is True
    assert pair["trigger_reasons"] == [
        "normalized_claim_atom_disagreement",
        "terminal_recommendation_disagreement",
    ]


def _sha_review(review: ReviewArtifactV1) -> str:
    return "sha256:" + hashlib.sha256(_raw(review)).hexdigest()


@pytest.mark.parametrize(
    ("terminal", "recommendation", "reason"),
    [
        ("unknown", "include", "terminal_unknown_or_not_evaluable"),
        ("not_evaluable", "include", "terminal_unknown_or_not_evaluable"),
        ("positive", "unknown", "claim_recommendation_unknown"),
    ],
)
def test_unresolved_triggers_are_fixed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal: str,
    recommendation: str,
    reason: str,
) -> None:
    root = _execution(tmp_path)
    _add_attempt(root, "A")
    _add_attempt(root, "B")
    if terminal in {"unknown", "not_evaluable"}:
        a = _review("owner/repo", 1, "A", terminal, unknowns=True)
        b = _review("owner/repo", 1, "B", terminal, unknowns=True)
    else:
        a = _review(
            "owner/repo", 1, "A", terminal, public_ids=("sdk.a",), recommendation=recommendation
        )
        b = _review(
            "owner/repo", 1, "B", terminal, public_ids=("sdk.a",), recommendation=recommendation
        )
    values = {"A": a, "B": b}
    monkeypatch.setattr(
        review_run,
        "_reauthenticate_execution",
        lambda _root: {"source_root": str(tmp_path)},
    )
    monkeypatch.setattr(
        adjudicate, "_authenticated_review", lambda _root, name: (values[name], _raw(values[name]))
    )
    monkeypatch.setattr(adjudicate, "_consumed_pairs", lambda _root: set())
    pair = cast("list[dict[str, Any]]", adjudicate.compare_execution(root)["pairs"])[0]
    assert reason in pair["trigger_reasons"]


def test_duplicate_finalized_lane_invalidates_entire_pr_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _execution(tmp_path)
    reviews = {
        "A1": _review("owner/repo", 1, "A", "negative_control"),
        "A2": _review("owner/repo", 1, "A", "negative_control"),
        "B": _review("owner/repo", 1, "B", "negative_control"),
    }
    for name in reviews:
        _add_attempt(root, name)
    monkeypatch.setattr(
        review_run,
        "_reauthenticate_execution",
        lambda _root: {"source_root": str(tmp_path)},
    )
    monkeypatch.setattr(
        adjudicate,
        "_authenticated_review",
        lambda _root, name: (reviews[name], _raw(reviews[name])),
    )
    monkeypatch.setattr(adjudicate, "_consumed_pairs", lambda _root: set())
    result = adjudicate.compare_execution(root)
    assert result["pairs"] == []
    assert result["totals"] == {"pairs": 0, "agreements": 0, "xhigh_required": 0}
    assert any(
        row.get("error") == "DuplicateFinalizedLane"
        for row in cast("list[dict[str, Any]]", result["operational_failures"])
    )


def test_operational_validation_failure_never_creates_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _execution(tmp_path)
    _add_attempt(root, "bad")
    monkeypatch.setattr(
        review_run,
        "_reauthenticate_execution",
        lambda _root: {"source_root": str(tmp_path)},
    )
    monkeypatch.setattr(
        adjudicate, "_authenticated_review", lambda *_args: adjudicate._fail("schema")
    )
    monkeypatch.setattr(adjudicate, "_consumed_pairs", lambda _root: set())
    result = adjudicate.compare_execution(root)
    assert result["pairs"] == []
    assert cast("list[object]", result["operational_failures"])


@pytest.mark.parametrize(
    ("required", "consumed", "match"),
    [
        (False, False, "must not launch"),
        (True, True, "already consumed"),
    ],
)
def test_prepare_rejects_agreement_or_consumed_pair_without_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    required: bool,
    consumed: bool,
    match: str,
) -> None:
    execution = tmp_path / "execution"
    packet_root = tmp_path / "packets"
    execution.mkdir(mode=0o700)
    packet_root.mkdir(mode=0o700)
    monkeypatch.setattr(
        adjudicate,
        "_select_pair",
        lambda *_args: {"xhigh_required": required, "fallback_consumed": consumed},
    )
    with pytest.raises(adjudicate.PilotAdjudicationError, match=match):
        adjudicate.prepare_adjudication(
            execution_root=execution,
            packet_root=packet_root,
            adjudication_root=tmp_path / "adjudications",
            repository="owner/repo",
            pr=1,
            attempt_id="attempt",
        )
    assert not (tmp_path / "adjudications").exists()


def _adjudication_root(tmp_path: Path) -> Path:
    root = tmp_path / "adjudications"
    return adjudicate._private_root(root)


def _state(
    root: Path, *, status: str = "launched", deadline_offset: int = 600_000
) -> tuple[str, Path]:
    pair_sha = "sha256:" + "f" * 64
    pair_dir = root / "pairs" / ("f" * 64)
    pair_dir.mkdir(mode=0o700)
    packet = pair_dir / "packet"
    packet.mkdir(mode=0o700)
    state = {
        "schema_version": 1,
        "protocol": "blind-review-adjudication-state-v3",
        "pair_sha256": pair_sha,
        "pair_dir": str(pair_dir),
        "attempt_id": "attempt",
        "packet": str(packet),
        "packet_sha256": "sha256:" + "1" * 64,
        "source_packet_root_sha256": "sha256:" + "2" * 64,
        "source_packet_manifest_sha256": "sha256:" + "3" * 64,
        "review_policy_hashes": {
            "packet_manifest": "sha256:" + "3" * 64,
            "review_prompt": "sha256:" + "4" * 64,
            "model_policy": "sha256:" + "5" * 64,
            "tool_policy": "sha256:" + "6" * 64,
            "source_policy": "sha256:" + "7" * 64,
        },
        "execution_root": str(root / "execution"),
        "packet_root": str(root / "packets"),
        "repository": "owner/repo",
        "pr": 1,
        "review_a_sha256": "sha256:" + "a" * 64,
        "review_b_sha256": "sha256:" + "b" * 64,
        "attempt_a": "A",
        "attempt_b": "B",
        "status": status,
        "deadline_unix_ms": int(__import__("time").time() * 1000) + deadline_offset,
        "environment_attestation_sha256": adjudicate._sha(
            canonical_json({"schema_version": 1, "fresh_bridge_active": False})
        ),
        "native_call_sha256": "sha256:" + "9" * 64,
    }
    adjudicate._atomic(pair_dir / "state.json", canonical_json(state), mode=0o600)
    return pair_sha, pair_dir


def _valid_output() -> dict[str, object]:
    return {
        "terminal_recommendation": "positive",
        "decision": "The SDK entrypoint changed.",
        "claims": [
            {
                "claim_kind": "entrypoint",
                "recommendation": "include",
                "entrypoint": {"kind": "sdk", "public_id": "sdk.a", "confidence": "confirmed"},
                "summary": "changed",
                "evidence": [
                    {"side": "target", "path": "src/main.py", "start_line": 1, "end_line": 1}
                ],
            }
        ],
        "unknowns": [],
    }


def test_launch_plan_is_one_shot_chain_with_step_output_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _adjudication_root(tmp_path)
    pair_sha, _pair_dir = _state(root, status="prepared")
    monkeypatch.setattr(adjudicate, "_authenticate_packet", lambda _state: None)
    monkeypatch.setattr(
        adjudicate,
        "_installed_agent",
        lambda _root: {"sha256": "sha256:" + "9" * 64},
    )
    monkeypatch.setattr(
        adjudicate,
        "_environment_attestation",
        lambda _root: {"schema_version": 1, "fresh_bridge_active": False},
    )
    plan = adjudicate.native_adjudication_launch_plan(root, pair_sha)
    call = cast("dict[str, Any]", plan["subagent_call"])
    assert "outputSchema" not in call
    assert call["chain"][0]["outputSchema"]["additionalProperties"] is False
    assert "tools" not in call["chain"][0]
    assert "thinking" not in call["chain"][0]
    assert "model" not in call["chain"][0]
    assert adjudicate._validate_native_call(call).startswith("sha256:")
    with pytest.raises(adjudicate.PilotAdjudicationError, match="already claimed"):
        adjudicate.native_adjudication_launch_plan(root, pair_sha)


def test_launch_plan_claim_is_atomic_across_threads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _adjudication_root(tmp_path)
    pair_sha, _pair_dir = _state(root, status="prepared")
    monkeypatch.setattr(adjudicate, "_authenticate_packet", lambda _state: None)
    monkeypatch.setattr(
        adjudicate,
        "_installed_agent",
        lambda _root: {"sha256": "sha256:" + "9" * 64},
    )
    monkeypatch.setattr(
        adjudicate,
        "_environment_attestation",
        lambda _root: {"schema_version": 1, "fresh_bridge_active": False},
    )

    def launch() -> str:
        try:
            adjudicate.native_adjudication_launch_plan(root, pair_sha)
        except adjudicate.PilotAdjudicationError:
            return "rejected"
        return "launched"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(lambda _index: launch(), range(2)))
    assert outcomes == ["launched", "rejected"]


def test_launch_plan_deadline_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _adjudication_root(tmp_path)
    pair_sha, _pair_dir = _state(root, status="prepared", deadline_offset=-1)
    monkeypatch.setattr(adjudicate, "_authenticate_packet", lambda _state: None)
    monkeypatch.setattr(adjudicate, "_installed_agent", lambda _root: {})
    monkeypatch.setattr(adjudicate, "_environment_attestation", lambda _root: {})
    with pytest.raises(adjudicate.PilotAdjudicationError, match="deadline"):
        adjudicate.native_adjudication_launch_plan(root, pair_sha)


def _write_session_audit(pair_dir: Path, pair_sha: str, payload: dict[str, object]) -> None:
    audit = {
        "pair_sha256": pair_sha,
        "structured_output_sha256": "sha256:" + hashlib.sha256(canonical_json(payload)).hexdigest(),
        "environment_attestation_sha256": adjudicate._sha(
            canonical_json({"schema_version": 1, "fresh_bridge_active": False})
        ),
    }
    adjudicate._atomic(pair_dir / "session-audit.json", canonical_json(audit), mode=0o400)


def _write_completion_artifacts(
    pair_dir: Path, pair_sha: str, output_sha: str
) -> dict[str, object]:
    completion = {
        "schema_version": 1,
        "pair_sha256": pair_sha,
        "output_sha256": output_sha,
        "terminal_recommendation": "positive",
    }
    completion_raw = canonical_json(completion)
    adjudicate._atomic(pair_dir / "pilot-completion.json", completion_raw, mode=0o400)
    adjudicate._atomic(
        pair_dir / "receipt.json",
        canonical_json(
            {
                "schema_version": 1,
                "pair_sha256": pair_sha,
                "completion_sha256": adjudicate._sha(completion_raw),
                "output_sha256": output_sha,
            }
        ),
        mode=0o400,
    )
    return completion


def test_finalize_valid_completion_and_lost_response_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _adjudication_root(tmp_path)
    pair_sha, pair_dir = _state(root)
    output = tmp_path / "output.json"
    payload = _valid_output()
    output.write_bytes(canonical_json(payload))
    output.chmod(0o600)
    _write_session_audit(pair_dir, pair_sha, payload)
    monkeypatch.setattr(adjudicate, "_authenticate_packet", lambda _state: None)
    monkeypatch.setattr(adjudicate, "_validate_output", lambda *_args: None)
    first = adjudicate.finalize_adjudication(root, pair_sha, output)
    second = adjudicate.finalize_adjudication(root, pair_sha, output)
    assert first == second
    assert first["terminal_recommendation"] == "positive"
    assert stat.S_IMODE((pair_dir / "pilot-completion.json").stat().st_mode) == 0o400
    output.chmod(0o600)
    output.write_bytes(canonical_json({**_valid_output(), "decision": "changed"}))
    with pytest.raises(adjudicate.PilotAdjudicationError, match="binding mismatch"):
        adjudicate.finalize_adjudication(root, pair_sha, output)


def test_terminal_unknown_marker_permanently_wins_over_completion_artifacts(
    tmp_path: Path,
) -> None:
    root = _adjudication_root(tmp_path)
    pair_sha, pair_dir = _state(root, status="launched")
    output_sha = "sha256:" + "8" * 64
    _write_completion_artifacts(pair_dir, pair_sha, output_sha)
    state = adjudicate._json(pair_dir / "state.json", 100_000, modes={0o600})
    adjudicate._terminal_unknown(pair_dir, state, "crash_after_completion_publication")

    reconciled = adjudicate._json(pair_dir / "state.json", 100_000, modes={0o600})
    with pytest.raises(adjudicate.PilotAdjudicationError, match="terminal unknown"):
        adjudicate._reconcile_completion(pair_dir, reconciled, output_sha)
    final = adjudicate._json(pair_dir / "state.json", 100_000, modes={0o600})
    assert final["status"] == "terminal_unknown"
    assert final["terminal_contradiction"] == "completion_artifacts_present_with_terminal_unknown"
    assert (
        cast("list[dict[str, Any]]", adjudicate.summarize(root)["pairs"])[0][
            "terminal_contradiction"
        ]
        == "completion_artifacts_present_with_terminal_unknown"
    )

    final["status"] = "completed"
    adjudicate._write_state(pair_dir, final)
    adjudicate._reconcile_terminal_marker(pair_dir, final)
    final = adjudicate._json(pair_dir / "state.json", 100_000, modes={0o600})
    assert final["status"] == "terminal_unknown"
    with pytest.raises(adjudicate.PilotAdjudicationError, match="terminal unknown"):
        adjudicate._reconcile_completion(pair_dir, final, output_sha)
    assert (
        adjudicate._json(pair_dir / "state.json", 100_000, modes={0o600})["status"]
        == "terminal_unknown"
    )


def test_completed_state_refuses_later_terminal_unknown_without_marker(tmp_path: Path) -> None:
    root = _adjudication_root(tmp_path)
    pair_sha, pair_dir = _state(root, status="completed")
    output_sha = "sha256:" + "7" * 64
    expected = _write_completion_artifacts(pair_dir, pair_sha, output_sha)
    state = adjudicate._json(pair_dir / "state.json", 100_000, modes={0o600})

    with pytest.raises(adjudicate.PilotAdjudicationError, match="cannot transition"):
        adjudicate._terminal_unknown(pair_dir, state, "late_failure")
    assert not (pair_dir / "terminal-unknown.json").exists()
    recovered = adjudicate._reconcile_completion(pair_dir, state, output_sha)
    assert recovered == expected
    assert (
        adjudicate._json(pair_dir / "state.json", 100_000, modes={0o600})["status"] == "completed"
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"bad": True},
        {
            **_valid_output(),
            "claims": [
                {**cast("list[dict[str, Any]]", _valid_output()["claims"])[0], "evidence": []}
            ],
        },
    ],
)
def test_invalid_schema_or_evidence_is_terminal_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
) -> None:
    root = _adjudication_root(tmp_path)
    pair_sha, pair_dir = _state(root)
    output = tmp_path / "output.json"
    output.write_bytes(canonical_json(payload))
    output.chmod(0o600)
    _write_session_audit(pair_dir, pair_sha, payload)
    monkeypatch.setattr(adjudicate, "_authenticate_packet", lambda _state: None)
    monkeypatch.setattr(adjudicate, "_validate_output", lambda *_args: adjudicate._fail("evidence"))
    with pytest.raises(adjudicate.PilotAdjudicationError, match="terminal invalid"):
        adjudicate.finalize_adjudication(root, pair_sha, output)
    state = adjudicate._json(pair_dir / "state.json", 100_000, modes={0o600})
    assert state["status"] == "terminal_unknown"
    assert (pair_dir / "terminal-unknown.json").is_file()


def _session(packet: Path, output: dict[str, object], *, tool: str = "structured_output") -> bytes:
    events = [
        {"type": "session", "cwd": str(packet)},
        {"type": "model_change", "modelId": "gpt-5.6-luna"},
        {"type": "thinking_level_change", "thinkingLevel": "xhigh"},
        {"type": "session_info", "name": "adjudicator"},
        {
            "type": "message",
            "message": {
                "role": "user",
                "content": [{"type": "text", "text": "Adjudicate the frozen pair."}],
            },
        },
        {
            "type": "message",
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "toolCall",
                        "id": "final",
                        "name": tool,
                        "arguments": {"value": output} if tool == "structured_output" else output,
                    }
                ],
            },
        },
        {
            "type": "message",
            "message": {
                "role": "toolResult",
                "toolCallId": "final",
                "isError": False,
                "content": [],
            },
        },
    ]
    return b"".join(canonical_json(event) for event in events)


def test_session_audit_requires_typed_terminal_and_rejects_intercom(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _adjudication_root(tmp_path)
    pair_sha, pair_dir = _state(root, status="launched")
    monkeypatch.setattr(adjudicate, "_authenticate_packet", lambda _state: None)
    monkeypatch.setattr(
        adjudicate,
        "_environment_attestation",
        lambda _root: {"schema_version": 1, "fresh_bridge_active": False},
    )
    session = tmp_path / "session.jsonl"
    session.write_bytes(_session(pair_dir / "packet", _valid_output()))
    result = adjudicate.audit_adjudication_session(root, pair_sha, session)
    assert result["structured_output_calls"] == 1
    bad = tmp_path / "bad.jsonl"
    bad.write_bytes(_session(pair_dir / "packet", {}, tool="contact_supervisor"))
    with pytest.raises(adjudicate.PilotAdjudicationError, match="terminal invalid"):
        adjudicate.audit_adjudication_session(root, pair_sha, bad)
    assert (pair_dir / "terminal-unknown.json").is_file()


def test_session_audit_requires_launched_and_consumes_invalid_attempt(tmp_path: Path) -> None:
    root = _adjudication_root(tmp_path)
    pair_sha, pair_dir = _state(root, status="prepared")
    session = tmp_path / "unused.jsonl"
    session.write_text("")
    with pytest.raises(adjudicate.PilotAdjudicationError, match="terminal invalid"):
        adjudicate.audit_adjudication_session(root, pair_sha, session)
    assert (
        adjudicate._json(pair_dir / "state.json", 100_000, modes={0o600})["status"]
        == "terminal_unknown"
    )


def test_session_audit_is_concurrent_idempotent_under_state_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _adjudication_root(tmp_path)
    pair_sha, pair_dir = _state(root, status="launched")
    monkeypatch.setattr(adjudicate, "_authenticate_packet", lambda _state: None)
    monkeypatch.setattr(
        adjudicate,
        "_environment_attestation",
        lambda _root: {"schema_version": 1, "fresh_bridge_active": False},
    )
    session = tmp_path / "session.jsonl"
    session.write_bytes(_session(pair_dir / "packet", _valid_output()))
    with ThreadPoolExecutor(max_workers=2) as pool:
        rows = list(
            pool.map(
                lambda _index: adjudicate.audit_adjudication_session(root, pair_sha, session),
                range(2),
            )
        )
    assert rows[0] == rows[1]
    assert (pair_dir / "session-audit.json").is_file()


@pytest.mark.parametrize(
    "mutation",
    ["unknown_event", "model_drift", "unknown_role", "extra_wrapper", "missing_result"],
)
def test_strict_session_grammar_failure_is_terminal_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    root = _adjudication_root(tmp_path)
    pair_sha, pair_dir = _state(root, status="launched")
    monkeypatch.setattr(adjudicate, "_authenticate_packet", lambda _state: None)
    monkeypatch.setattr(
        adjudicate,
        "_environment_attestation",
        lambda _root: {"schema_version": 1, "fresh_bridge_active": False},
    )
    events = [
        json.loads(line) for line in _session(pair_dir / "packet", _valid_output()).splitlines()
    ]
    if mutation == "unknown_event":
        events.insert(3, {"type": "mystery"})
    elif mutation == "model_drift":
        events.insert(-1, {"type": "model_change", "modelId": "gpt-5.6-luna"})
    elif mutation == "unknown_role":
        events.insert(-1, {"type": "message", "message": {"role": "system", "content": []}})
    elif mutation == "extra_wrapper":
        events[-2]["message"]["content"][0]["arguments"]["extra"] = True
    else:
        events.pop()
    session = tmp_path / "bad-session.jsonl"
    session.write_bytes(b"".join(canonical_json(event) for event in events))
    with pytest.raises(adjudicate.PilotAdjudicationError, match="terminal invalid"):
        adjudicate.audit_adjudication_session(root, pair_sha, session)
    state = adjudicate._json(pair_dir / "state.json", 100_000, modes={0o600})
    assert state["status"] == "terminal_unknown"


def test_expired_prepared_or_launched_state_is_terminal_unknown(tmp_path: Path) -> None:
    for index, status in enumerate(("prepared", "launched")):
        root = adjudicate._private_root(tmp_path / f"root-{index}")
        _pair_sha, pair_dir = _state(root, status=status, deadline_offset=-1)
        result = adjudicate.summarize(root)
        assert cast("list[dict[str, Any]]", result["pairs"])[0]["status"] == "terminal_unknown"
        assert (pair_dir / "terminal-unknown.json").is_file()


def test_finalize_partial_publication_is_terminal_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _adjudication_root(tmp_path)
    pair_sha, pair_dir = _state(root, status="launched")
    output = tmp_path / "output.json"
    output.write_bytes(canonical_json(_valid_output()))
    output.chmod(0o600)
    _atomic = adjudicate._atomic
    _atomic(
        pair_dir / "pilot-completion.json",
        canonical_json(
            {"pair_sha256": pair_sha, "output_sha256": adjudicate._sha(output.read_bytes())}
        ),
        mode=0o400,
    )
    monkeypatch.setattr(adjudicate, "_authenticate_packet", lambda _state: None)
    with pytest.raises(adjudicate.PilotAdjudicationError, match="partial"):
        adjudicate.finalize_adjudication(root, pair_sha, output)
    assert (
        adjudicate._json(pair_dir / "state.json", 100_000, modes={0o600})["status"]
        == "terminal_unknown"
    )


@pytest.mark.parametrize("tamper_target", ["payload", "review"])
def test_packet_authentication_rejects_review_or_payload_swap(  # noqa: PLR0915
    tmp_path: Path, tamper_target: str
) -> None:
    root = _adjudication_root(tmp_path)
    pair_sha, pair_dir = _state(root)
    packet = pair_dir / "packet"
    source = packet / "source"
    source.mkdir(mode=0o700)
    reviews = packet / "reviews"
    reviews.mkdir(mode=0o700)
    raw_a, raw_b = b"review-a\n", b"review-b\n"
    for path, raw in ((reviews / "review-a.json", raw_a), (reviews / "review-b.json", raw_b)):
        path.write_bytes(raw)
        path.chmod(0o444)
    payload = source / "source.txt"
    payload.write_text("source\n")
    payload.chmod(0o444)
    policy_names = {
        "review_prompt": "review-prompt-v1.md",
        "model_policy": "model-policy-v1.json",
        "tool_policy": "tool-policy-v1.json",
        "source_policy": "source-policy-v1.json",
    }
    policies = source / "policies-v3"
    policies.mkdir(mode=0o700)
    state = adjudicate._json(pair_dir / "state.json", 100_000, modes={0o600})
    for index, (name, filename) in enumerate(policy_names.items(), start=4):
        raw = f"policy-{index}\n".encode()
        path = policies / filename
        path.write_bytes(raw)
        path.chmod(0o444)
        state["review_policy_hashes"][name] = adjudicate._sha(raw)
    source_payload = [
        {"path": "source.txt", "bytes": 7, "sha256": adjudicate._sha(b"source\n")},
        *[
            {
                "path": f"policies-v3/{filename}",
                "bytes": (policies / filename).stat().st_size,
                "sha256": adjudicate._sha((policies / filename).read_bytes()),
            }
            for filename in policy_names.values()
        ],
    ]
    source_manifest = {
        "repository": "owner/repo",
        "pr": 1,
        "payload_files": source_payload,
        "payload_bytes": sum(cast("int", row["bytes"]) for row in source_payload),
        "packet_root_sha256": "",
    }
    source_manifest["packet_root_sha256"] = submit._manifest_root(source_manifest)
    source_manifest_raw = canonical_json(source_manifest)
    source_manifest_path = source / "packet-manifest.json"
    source_manifest_path.write_bytes(source_manifest_raw)
    source_manifest_path.chmod(0o444)
    state["source_packet_root_sha256"] = source_manifest["packet_root_sha256"]
    state["source_packet_manifest_sha256"] = adjudicate._sha(source_manifest_raw)
    state["review_policy_hashes"]["packet_manifest"] = adjudicate._sha(source_manifest_raw)
    state["review_a_sha256"] = artifact_sha256(raw_a)
    state["review_b_sha256"] = artifact_sha256(raw_b)
    freeze = {
        "pair_sha256": pair_sha,
        "review_a_sha256": state["review_a_sha256"],
        "review_b_sha256": state["review_b_sha256"],
    }
    freeze_path = packet / "pair-freeze.json"
    freeze_path.write_bytes(canonical_json(freeze))
    freeze_path.chmod(0o444)
    rows, digest = adjudicate._inventory_hash(packet)
    manifest = {
        "protocol": "blind-review-adjudication-packet-v3",
        "pair_sha256": pair_sha,
        "source_packet_root_sha256": state["source_packet_root_sha256"],
        "files": rows,
        "packet_sha256": digest,
    }
    manifest_path = packet / "adjudication-manifest.json"
    manifest_path.write_bytes(canonical_json(manifest))
    manifest_path.chmod(0o444)
    state["packet_sha256"] = digest
    adjudicate._write_state(pair_dir, state)
    adjudicate._authenticate_packet(state)
    target = payload if tamper_target == "payload" else reviews / "review-a.json"
    target.chmod(0o600)
    target.write_text("swapped\n")
    target.chmod(0o444)
    with pytest.raises(adjudicate.PilotAdjudicationError, match=r"authentication|Review A"):
        adjudicate._authenticate_packet(state)


def test_source_packet_is_bound_to_both_recovered_review_bindings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet = tmp_path / "packet"
    policies = packet / "policies-v3"
    policies.mkdir(parents=True)
    policy_names = {
        "review_prompt": "review-prompt-v1.md",
        "model_policy": "model-policy-v1.json",
        "tool_policy": "tool-policy-v1.json",
        "source_policy": "source-policy-v1.json",
    }
    hashes: dict[str, str] = {}
    for name, filename in policy_names.items():
        raw = f"{name}\n".encode()
        (policies / filename).write_bytes(raw)
        (policies / filename).chmod(0o444)
        hashes[name] = adjudicate._sha(raw)
    manifest = {
        "repository": "owner/repo",
        "pr": 1,
        "baseline_commit": SHA1,
        "target_commit": SHA2,
        "baseline_tree": "3" * 40,
        "target_tree": "4" * 40,
        "payload_files": [],
        "payload_bytes": 0,
        "packet_root_sha256": "",
    }
    manifest["packet_root_sha256"] = submit._manifest_root(manifest)
    manifest_path = packet / "packet-manifest.json"
    manifest_raw = canonical_json(manifest)
    manifest_path.write_bytes(manifest_raw)
    manifest_path.chmod(0o444)
    hashes["packet_manifest"] = adjudicate._sha(manifest_raw)
    inputs = tuple(SimpleNamespace(name=name, sha256=value) for name, value in hashes.items())
    snapshots = SimpleNamespace(baseline_commit=SHA1, target_commit=SHA2)
    binding = SimpleNamespace(
        repository="owner/repo",
        pr=1,
        snapshots=snapshots,
        baseline_tree="3" * 40,
        target_tree="4" * 40,
        packet_manifest_sha256=hashes["packet_manifest"],
        packet_root_sha256=manifest["packet_root_sha256"],
        authenticated_inputs=inputs,
    )
    monkeypatch.setattr(submit, "_verify_payload", lambda *_args: None)
    adjudicate._authenticate_source_packet_for_pair(
        packet, "owner/repo", 1, cast("Any", binding), cast("Any", binding)
    )
    manifest["pr"] = 2
    manifest["packet_root_sha256"] = submit._manifest_root(manifest)
    manifest_path.chmod(0o600)
    manifest_path.write_bytes(canonical_json(manifest))
    manifest_path.chmod(0o444)
    with pytest.raises(adjudicate.PilotAdjudicationError, match=r"snapshots|disagree"):
        adjudicate._authenticate_source_packet_for_pair(
            packet, "owner/repo", 1, cast("Any", binding), cast("Any", binding)
        )


def test_intercom_environment_requires_off_or_fork_only_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"intercomBridge": {"mode": "always"}}))
    config.chmod(0o600)
    monkeypatch.setattr(adjudicate, "_subagent_config_path", lambda: config)
    before = config.read_bytes()
    with pytest.raises(adjudicate.PilotAdjudicationError, match="off or fork-only"):
        adjudicate._intercom_config()
    assert config.read_bytes() == before
    config.write_text(json.dumps({"intercomBridge": {"mode": "fork-only"}}))
    result = adjudicate._intercom_config()
    assert result["fresh_bridge_active"] is False
    assert json.loads(config.read_text())["intercomBridge"]["mode"] == "fork-only"
    assert before != config.read_bytes()


def test_host_pair_claim_rejects_secondary_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    claims = tmp_path / "claims"
    monkeypatch.setattr(adjudicate, "_claim_directory", lambda: claims)
    first = adjudicate._private_root(tmp_path / "first")
    second = adjudicate._private_root(tmp_path / "second")
    pair = "sha256:" + "a" * 64
    adjudicate._claim_pair(first, pair)
    adjudicate._claim_pair(first, pair)
    with pytest.raises(adjudicate.PilotAdjudicationError, match="another adjudication root"):
        adjudicate._claim_pair(second, pair)


def test_historical_consumed_report_is_checksum_authenticated(tmp_path: Path) -> None:
    profile = tmp_path / "benchmarks/real_world/pilot_v3"
    profile.mkdir(parents=True)
    report = {
        "xhigh_terminal_fallback": {"attempts_launched": 1},
        "medium_review": {
            "attempts": [
                {
                    "repository": "PrefectHQ/prefect",
                    "pr": 22189,
                    "lane": "A",
                    "artifact_sha256": "sha256:" + "a" * 64,
                },
                {
                    "repository": "PrefectHQ/prefect",
                    "pr": 22189,
                    "lane": "B",
                    "artifact_sha256": "sha256:" + "b" * 64,
                },
            ]
        },
    }
    raw = canonical_json(report)
    (profile / "native-pilot-report-v1.json").write_bytes(raw)
    relative = "benchmarks/real_world/pilot_v3/native-pilot-report-v1.json"
    (profile / "checksums-v1.json").write_bytes(
        canonical_json({"files": {relative: adjudicate._sha(raw)}})
    )
    assert len(adjudicate._consumed_pairs(tmp_path)) == 1
    (profile / "native-pilot-report-v1.json").write_text("{}")
    with pytest.raises(adjudicate.PilotAdjudicationError, match="checksum"):
        adjudicate._consumed_pairs(tmp_path)


def test_agent_install_is_no_clobber_and_resolver_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _adjudication_root(tmp_path)
    output = tmp_path / "agents" / "agent.md"
    monkeypatch.setattr(
        adjudicate,
        "_agent_discovery",
        lambda _source: {
            "resolver_sha256": "sha256:" + "1" * 64,
            "candidates": [str(output.resolve())],
            "effective": [str(output.resolve())],
        },
    )
    monkeypatch.setattr(
        adjudicate,
        "_effective_agent_config",
        lambda _source: {
            "filePath": str(output.resolve()),
            "model": adjudicate._MODEL,
            "thinking": "xhigh",
            "tools": ["read", "grep", "find", "ls"],
            "extensions": [],
            "inheritProjectContext": False,
            "inheritSkills": False,
            "completionGuard": False,
        },
    )
    receipt = adjudicate.create_native_adjudicator(root, output)
    assert receipt["path"] == str(output.resolve())
    with pytest.raises(adjudicate.PilotAdjudicationError, match="already exists"):
        adjudicate.create_native_adjudicator(root, output)


def test_summary_preserves_terminal_state(tmp_path: Path) -> None:
    root = _adjudication_root(tmp_path)
    pair_sha, _pair_dir = _state(root, status="terminal_unknown")
    result = adjudicate.summarize(root)
    assert result["pairs"] == [
        {"pair_sha256": pair_sha, "repository": "owner/repo", "pr": 1, "status": "terminal_unknown"}
    ]
