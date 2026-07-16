"""Offline provenance and selection tests for blind-review pilot v1."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from benchmarks.real_world import pilot_protocol_v2 as protocol
from benchmarks.real_world.ground_truth_v2.schema import ReviewArtifactV1
from tests.benchmarks.ground_truth_helpers import review

_ROOT = Path(__file__).resolve().parents[2]
_PILOT = _ROOT / "benchmarks/real_world/pilot_v2"
_EXPECTED: list[dict[str, object]] = [
    {
        "repository": "fastapi/full-stack-fastapi-template",
        "number": 2164,
        "merged_at": "2026-02-02T10:56:30Z",
        "identity_sha256": (
            "sha256:a57c7c0f023c6f1a16d82d66846782c02c429f4dbc8f3dd91da1e33b131679a3"
        ),
    },
    {
        "repository": "Kludex/starlette",
        "number": 3257,
        "merged_at": "2026-04-30T16:58:50Z",
        "identity_sha256": (
            "sha256:e98e51a456b142823fb46deb20fb3051f90cfbc88835bd14284416c4e98f7d96"
        ),
    },
    {
        "repository": "PrefectHQ/prefect",
        "number": 22189,
        "merged_at": "2026-06-01T20:02:05Z",
        "identity_sha256": (
            "sha256:8214960a5da4a822f0a088df7fb3e3c6f6fd79e5fb277e7cad90cb44df325b48"
        ),
    },
]


def _project(repository: str, selected: int, candidates: list[tuple[int, str]]) -> dict[str, Any]:
    return {
        "repository": repository,
        "records": [{"pr": selected}],
        "selection_evidence": [
            {
                "candidates": [
                    {
                        "pr": number,
                        "merged_at": merged_at,
                        "html_url": f"https://github.com/{repository}/pull/{number}",
                        "ignored_content": "untrusted",
                    }
                    for number, merged_at in candidates
                ]
            }
        ],
    }


def test_committed_preregistration_authenticates_and_is_fresh() -> None:
    summary = protocol.validate_preregistration(_ROOT)
    assert summary == {
        "id": "blind-review-pilot-v1",
        "phase": "preregistered_not_run",
        "pilot_prs": 3,
        "evaluation_prs": 2500,
        "prior_labeled_prs": 60,
        "evaluation_overlap": 0,
        "prior_label_overlap": 0,
        "selected": _EXPECTED,
        "live_reviews_claimed": False,
    }


def test_selection_uses_project_order_identity_and_merged_timestamp_only() -> None:
    lock = {
        "projects": [
            _project("Owner/First", 10, [(9, "2025-01-01T00:00:00Z")]),
            _project(
                "Owner/Second",
                20,
                [(19, "2025-01-01T00:00:00Z"), (18, "2025-01-02T00:00:00Z")],
            ),
            _project("Owner/Third", 30, [(29, "2025-01-03T00:00:00Z")]),
            _project("Owner/Fourth", 40, [(39, "2025-01-04T00:00:00Z")]),
        ]
    }
    selected = protocol.select_pilot_identities(lock, set())
    assert [(item["repository"], item["number"]) for item in selected] == [
        ("Owner/First", 9),
        ("Owner/Second", 18),
        ("Owner/Third", 29),
    ]
    excluded = {("owner/first", 9), ("owner/second", 18)}
    replacement = protocol.select_pilot_identities(lock, excluded)
    assert [(item["repository"], item["number"]) for item in replacement] == [
        ("Owner/Second", 19),
        ("Owner/Third", 29),
        ("Owner/Fourth", 39),
    ]


def test_duplicate_nesting_and_nonfinite_json_fail_closed(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"id":1,"id":2}', encoding="utf-8")
    with pytest.raises(protocol.PilotProtocolError, match="duplicate JSON key"):
        protocol._load_json(duplicate)

    nested = tmp_path / "nested.json"
    nested.write_text("[" * 101 + "]" * 101, encoding="utf-8")
    with pytest.raises(protocol.PilotProtocolError, match="nesting"):
        protocol._load_json(nested)

    for value in ("NaN", "Infinity", "-Infinity"):
        nonfinite = tmp_path / f"{value.replace('-', 'minus')}.json"
        nonfinite.write_text(f'{{"value":{value}}}', encoding="utf-8")
        with pytest.raises(protocol.PilotProtocolError, match="non-finite"):
            protocol._load_json(nonfinite)


def test_checksum_profile_rejects_policy_tampering(tmp_path: Path) -> None:
    copied = tmp_path / "pilot_v2"
    shutil.copytree(_PILOT, copied)
    policy = copied / "tool-policy-v1.json"
    policy.write_bytes(
        policy.read_bytes().replace(b'"child_writes": false', b'"child_writes": true')
    )
    with pytest.raises(protocol.PilotProtocolError, match="artifact hash mismatch"):
        protocol._validate_profile(copied)


def test_checksum_profile_itself_is_anchored(tmp_path: Path) -> None:
    copied = tmp_path / "pilot_v2"
    shutil.copytree(_PILOT, copied)
    profile = copied / "checksums-v1.json"
    profile.write_bytes(profile.read_bytes().replace(b"sha256:", b"sha257:", 1))
    with pytest.raises(protocol.PilotProtocolError, match="profile hash mismatch"):
        protocol._validate_profile(copied)


def test_policy_validation_consumes_authenticated_payload_without_reopen(tmp_path: Path) -> None:
    copied = tmp_path / "pilot_v2"
    shutil.copytree(_PILOT, copied)
    artifacts = protocol._validate_profile(copied)
    policy = artifacts["pilot-policy-v1.json"].payload
    assert policy is not None
    (copied / "pilot-policy-v1.json").write_text("{}\n", encoding="utf-8")
    protocol._validate_policy(policy, _EXPECTED)


def test_prior_label_parser_is_strict_and_deduplicated() -> None:
    with pytest.raises(protocol.PilotProtocolError, match="duplicate prior-label"):
        protocol._parse_prior_jsonl(
            b'{"repository":"owner/repo","pr":1}\n{"repository":"OWNER/REPO","pr":1}\n',
            "prior.jsonl",
        )
    with pytest.raises(protocol.PilotProtocolError, match="non-finite"):
        protocol._parse_prior_jsonl(
            b'{"repository":"owner/repo","pr":1,"bad":NaN}\n', "prior.jsonl"
        )


def test_positive_review_requires_semantic_include() -> None:
    payload = json.loads(review("A"))
    payload["claims"][0]["recommendation"] = "exclude"
    parsed = ReviewArtifactV1.model_validate(payload)
    with pytest.raises(protocol.PilotProtocolError, match="requires an included claim"):
        protocol.validate_review_semantics(parsed)


def test_scope_binding_and_classification_are_concrete() -> None:
    artifacts = protocol._validate_profile(_PILOT)
    scope = artifacts["scope-policy-v1.json"].payload
    assert scope is not None
    assert scope["scope_binding"] == {
        "scope_id": "fastapi-adapter-v1",
        "scope_version": 1,
        "product": "fastapi-endpoint-detector",
        "definition_sha256_source": (
            "Exact SHA-256 of this scope-policy-v1.json byte stream authenticated by "
            "checksums-v1.json"
        ),
    }
    assert scope["in_scope_kinds"] == ["http"]
    assert set(scope["out_of_scope_kinds"]) == {
        "graphql",
        "task",
        "event",
        "cli",
        "cron",
        "sdk",
        "other",
    }
    assert "sha256:" + hashlib.sha256(artifacts["scope-policy-v1.json"].raw).hexdigest() == (
        "sha256:bd0bee2531070516ab1d7408f2d5dbbce0bc139a593d2ed4065fb3ac58111b48"
    )


def test_telemetry_has_exact_role_sources_and_mandatory_go_fields() -> None:
    artifacts = protocol._validate_profile(_PILOT)
    telemetry = artifacts["telemetry-contract-v1.json"].payload
    assert telemetry is not None
    assert telemetry["attempt_source_variants"]["review_a_and_adjudication"]["source_kind"] == (
        "pi_subagents_lifecycle_v1"
    )
    assert telemetry["attempt_source_variants"]["review_b"]["source_kind"] == (
        "supervisor_session_interval_v1"
    )
    mandatory = set(telemetry["mandatory_go_fields"])
    assert {
        "wall_milliseconds",
        "input_tokens",
        "tool_calls",
        "input_bytes",
        "sampled_peak_process_tree_rss_bytes",
        "disk_bytes_before",
        "is_retry",
        "succeeded",
        "cost_micro_usd",
    } <= mandatory
    assert "GO forbids null" in telemetry["unavailable_rule"]


def test_metrics_freeze_integer_projection_and_jaccard_operands() -> None:
    artifacts = protocol._validate_profile(_PILOT)
    metrics = artifacts["metrics-spec-v1.json"].payload
    execution = artifacts["execution-manifest-schema-v1.json"].payload
    assert metrics is not None and execution is not None
    assert "ceil_div" in metrics["projection_2500"]["role_attempts"]
    assert "micro_usd" in metrics["projection_2500"]["role_cost_micro_usd"]
    assert "intersection_count" in metrics["agreement"]["per_pr_jaccard"]
    assert "union_count" in metrics["agreement"]["per_pr_jaccard"]
    assert "approved_role_concurrency" in metrics["resource_and_concurrency"]
    assert "pricing_micro_usd_per_million_tokens" in execution["required_fields"]
    assert "budget_micro_usd" in execution["required_fields"]


def test_incident_prompts_produce_no_schema_artifact() -> None:
    review_prompt = (_PILOT / "review-prompt-v1.md").read_text(encoding="utf-8")
    adjudication_prompt = (_PILOT / "adjudication-prompt-v1.md").read_text(encoding="utf-8")
    for prompt in (review_prompt, adjudication_prompt):
        assert "CUSTODY_INCIDENT_NO_ARTIFACT" in prompt
        assert "produce no" in prompt
        assert "external supervisor-owned sidecars" in prompt


def test_bounded_reader_rejects_oversized_input(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * 11)
    with pytest.raises(protocol.PilotProtocolError, match="byte limit"):
        protocol._read_bounded(oversized, 10)
