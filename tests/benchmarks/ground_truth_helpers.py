from __future__ import annotations

import json
from typing import Any

from benchmarks.real_world.ground_truth_v2.schema import CorpusDefinition

H = "sha256:" + "a" * 64
BASE = "1" * 40
TARGET = "2" * 40
BLOB = "3" * 40
TREE1 = "4" * 40
TREE2 = "5" * 40


def corpus() -> CorpusDefinition:
    return CorpusDefinition.model_validate(
        {
            "schema_version": 2,
            "corpus_id": "synthetic-v2",
            "lock_sha256": "sha256:" + "9" * 64,
            "source": "strict_synthetic_fixture",
            "repositories": [
                {
                    "full_name": "owner/repo",
                    "partition": "fixture",
                    "terminal_status": "underfilled",
                    "pull_requests": [
                        {
                            "number": 1,
                            "rank": 1,
                            "merged_at": "2025-01-01T00:00:00Z",
                            "base_sha": BASE,
                            "head_sha": TARGET,
                            "merge_commit_sha": "6" * 40,
                            "baseline": {
                                "commit_sha": BASE,
                                "tree_sha": TREE1,
                                "rule": "first_parent_of_merge_commit",
                            },
                            "target": {"commit_sha": TARGET, "tree_sha": TREE2, "rule": "head_sha"},
                            "remote_diff": {
                                "sha256": "sha256:" + "7" * 64,
                                "byte_count": 10,
                                "final_url": "https://github.com/owner/repo/pull/1.diff",
                                "content_type": "text/plain",
                            },
                        }
                    ],
                }
            ],
        }
    )


def location() -> dict[str, Any]:
    return {
        "side": "target",
        "commit_sha": TARGET,
        "blob_sha": BLOB,
        "path": "app.py",
        "start_line": 1,
        "end_line": 1,
        "symbol": "handler",
    }


def edge() -> dict[str, Any]:
    return {
        "ordinal": 0,
        "relation": "direct",
        "from_location": location(),
        "to_location": location(),
    }


def run() -> dict[str, Any]:
    return {
        "prompt_sha256": H,
        "model_policy_sha256": H,
        "tool_policy_sha256": H,
        "source_policy_sha256": H,
        "started_at": "2025-01-01T00:00:00Z",
        "completed_at": "2025-01-01T00:01:00Z",
        "limits": {
            "max_tokens": 10,
            "max_tool_calls": 2,
            "max_seconds": 10,
            "max_output_bytes": 100000,
        },
    }


def review(lane: str) -> bytes:
    payload = {
        "schema_version": 1,
        "artifact_type": "ground_truth_review",
        "corpus_id": "synthetic-v2",
        "repository": "owner/repo",
        "pr": 1,
        "lane": lane,
        "snapshots": {"baseline_commit": BASE, "target_commit": TARGET},
        "reviewer": {"kind": "human", "name": f"reviewer-{lane}", "version": "1"},
        "run": run(),
        "terminal_recommendation": "positive",
        "changed_symbols": [
            {"symbol_id": "s1", "canonical_name": "app.handler", "location": location()}
        ],
        "claims": [
            {
                "claim_id": "c1",
                "claim_kind": "entrypoint",
                "recommendation": "include",
                "summary": "direct",
                "entrypoint": {
                    "public_id": "HTTP GET /x",
                    "kind": "http",
                    "confidence": "confirmed",
                },
                "evidence": [edge()],
            }
        ],
        "unknowns": [],
        "negative_assessment": None,
        "notes": "",
    }
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode()


def adjudication(a_hash: str, b_hash: str) -> bytes:
    payload = {
        "schema_version": 1,
        "artifact_type": "ground_truth_adjudication",
        "corpus_id": "synthetic-v2",
        "repository": "owner/repo",
        "pr": 1,
        "snapshots": {"baseline_commit": BASE, "target_commit": TARGET},
        "review_a_sha256": a_hash,
        "review_b_sha256": b_hash,
        "adjudicator": {"kind": "human", "name": "adjudicator", "version": "1"},
        "run": run(),
        "version": 1,
        "supersedes_sha256": None,
        "terminal_status": "positive",
        "reason": "both agree",
        "decisions": [
            {
                "decision_id": "d1",
                "decision_kind": "entrypoint",
                "outcome": "include",
                "attribution": "both",
                "sources": [
                    {"lane": "A", "source_kind": "claim", "source_id": "c1"},
                    {"lane": "A", "source_kind": "terminal", "source_id": None},
                    {"lane": "B", "source_kind": "claim", "source_id": "c1"},
                    {"lane": "B", "source_kind": "terminal", "source_id": None},
                ],
                "canonical_entrypoint": {
                    "public_id": "HTTP GET /x",
                    "kind": "http",
                    "confidence": "confirmed",
                },
                "rationale": "both source claims show direct registration",
                "evidence": [],
            }
        ],
        "scope_memberships": [
            {
                "scope_id": "endpoint-detector",
                "scope_version": 1,
                "product": "endpoint-detector",
                "definition_sha256": H,
                "decision_id": "d1",
                "status": "in_scope",
                "rationale": "HTTP endpoint is in product scope",
            }
        ],
        "unknowns": [],
        "negative_assessment": None,
    }
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode()


class AcceptEvidence:
    def validate_location(self, location: object) -> None:
        del location

    def validate_edges(self, edges: object) -> None:
        del edges


def validator_factory(pr_id: str) -> Any:
    assert pr_id.startswith("pr:")
    return AcceptEvidence()
