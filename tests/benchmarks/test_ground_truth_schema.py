from __future__ import annotations

import json

import pytest
from benchmarks.real_world.ground_truth_v2 import GroundTruthError
from benchmarks.real_world.ground_truth_v2.schema import ReviewArtifactV1, parse_artifact

H = "sha256:" + "a" * 64
S = "1" * 40


def review_payload(*, lane: str = "A", recommendation: str = "unknown") -> dict[str, object]:
    return {
        "schema_version": 1,
        "artifact_type": "ground_truth_review",
        "corpus_id": "synthetic-v2",
        "repository": "owner/repo",
        "pr": 1,
        "lane": lane,
        "snapshots": {"baseline_commit": S, "target_commit": "2" * 40},
        "reviewer": {"kind": "human", "name": f"reviewer-{lane}", "version": "1"},
        "run": {
            "prompt_sha256": H,
            "model_policy_sha256": H,
            "tool_policy_sha256": H,
            "source_policy_sha256": H,
            "started_at": "2025-01-01T00:00:00Z",
            "completed_at": "2025-01-01T00:01:00Z",
            "limits": {
                "max_tokens": 10,
                "max_tool_calls": 1,
                "max_seconds": 10,
                "max_output_bytes": 10000,
            },
        },
        "terminal_recommendation": recommendation,
        "changed_symbols": [],
        "claims": [],
        "unknowns": [
            {
                "unknown_id": "u1",
                "category": "dynamic",
                "description": "cannot resolve",
                "evidence_limit": "offline only",
            }
        ],
        "negative_assessment": None,
        "notes": "",
    }


def encoded(payload: dict[str, object]) -> bytes:
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode()


def test_duplicate_nested_key_and_unknown_field_fail_closed() -> None:
    raw = encoded(review_payload()).replace(b'"max_tokens":10', b'"max_tokens":10,"max_tokens":11')
    with pytest.raises(GroundTruthError, match="duplicate JSON key"):
        parse_artifact(raw, ReviewArtifactV1)
    payload = review_payload()
    payload["prediction"] = []
    with pytest.raises(GroundTruthError, match="extra_forbidden"):
        parse_artifact(encoded(payload), ReviewArtifactV1)


def test_bool_is_not_an_integer_and_empty_is_not_negative() -> None:
    payload = review_payload()
    payload["pr"] = True
    with pytest.raises(GroundTruthError):
        parse_artifact(encoded(payload), ReviewArtifactV1)
    negative = review_payload(recommendation="negative_control")
    negative["unknowns"] = []
    with pytest.raises(GroundTruthError, match="negative review requires"):
        parse_artifact(encoded(negative), ReviewArtifactV1)


def test_wrong_snapshot_hash_and_path_traversal_are_rejected() -> None:
    payload = review_payload(recommendation="positive")
    payload["unknowns"] = []
    payload["claims"] = [
        {
            "claim_id": "c1",
            "claim_kind": "entrypoint",
            "recommendation": "include",
            "summary": "direct",
            "entrypoint": {"public_id": "HTTP GET /x", "kind": "http", "confidence": "confirmed"},
            "evidence": [
                {
                    "ordinal": 0,
                    "relation": "direct",
                    "from_location": {
                        "side": "target",
                        "commit_sha": "2" * 40,
                        "blob_sha": "3" * 40,
                        "path": "../app.py",
                        "start_line": 1,
                        "end_line": 1,
                        "symbol": "x",
                    },
                    "to_location": {
                        "side": "target",
                        "commit_sha": "2" * 40,
                        "blob_sha": "3" * 40,
                        "path": "app.py",
                        "start_line": 1,
                        "end_line": 1,
                        "symbol": "x",
                    },
                }
            ],
        }
    ]
    with pytest.raises(GroundTruthError, match="path"):
        parse_artifact(encoded(payload), ReviewArtifactV1)
