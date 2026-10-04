from __future__ import annotations

import hashlib
import json
from copy import deepcopy

import pytest
from benchmarks.real_world.compare_evaluations import compare


def reports(*, attested: bool = True, n: int = 40):
    rows_a, rows_b, keys = [], [], []
    for pr in range(1, n + 1):
        key = {"repository": "owner/repo", "pr": pr}
        keys.append(key)
        base = {
            **key,
            "truth_status": "adjudicated",
            "truth_sha256": f"{pr:064x}",
            "prediction_status": "completed",
            "unresolved_count": 0,
            "raw": {"tp": 10, "fp": 0, "fn": 1},
            "normalized": {"tp": 10, "fp": 0, "fn": 1},
        }
        cand = deepcopy(base)
        cand["raw"] = {"tp": 8, "fp": 2, "fn": 3}
        cand["normalized"] = {"tp": 8, "fp": 2, "fn": 3}
        rows_a.append(base)
        rows_b.append(cand)

    def report(rows, prediction_hash):
        return {
            "integrity": {
                "fully_attested": attested,
                "official_scoring_eligible": attested,
            },
            "comparison_evidence": {
                "schema_version": 1,
                "scope": "fastapi-adapter-v1",
                "normalization_version": "aliases-v1",
                "truth_sha256": "a" * 64,
                "selection_sha256": hashlib.sha256(
                    json.dumps(keys, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
                "selection_keys": keys,
                "per_pr": rows,
                "prediction_sha256": prediction_hash,
                "attested": attested,
            },
        }

    return report(rows_a, "c" * 64), report(rows_b, "d" * 64)


def test_known_precision_regression_fails_and_repeats_with_seed():
    baseline, candidate = reports()
    first = compare(baseline, candidate, seed=17)
    second = compare(baseline, candidate, seed=17)
    assert first == second
    assert first["samples"] == 10_000
    assert first["metrics"]["raw"]["decision"] == "fail"
    assert first["gate_decision"] == "report_only"
    assert first["attested"] is False


def test_two_point_tie_passes_threshold():
    baseline, candidate = reports(n=7)
    for report, tp, fp, fn in ((baseline, 49, 51, 51), (candidate, 47, 53, 53)):
        for row in report["comparison_evidence"]["per_pr"]:
            row["raw"] = {"tp": tp, "fp": fp, "fn": fn}
            row["normalized"] = {"tp": tp, "fp": fp, "fn": fn}
    result = compare(baseline, candidate)
    assert result["metrics"]["raw"]["interval"][0] == pytest.approx(-0.02)
    assert result["metrics"]["raw"]["decision"] == "pass"
    assert result["gate_decision"] == "report_only"
    assert result["attested"] is False


def test_changed_pairing_truth_and_unresolved_coverage_fail_closed():
    baseline, candidate = reports()
    candidate["comparison_evidence"]["per_pr"][0]["truth_sha256"] = "e" * 64
    with pytest.raises(ValueError, match="truth identity changed"):
        compare(baseline, candidate)
    baseline, candidate = reports()
    candidate["comparison_evidence"]["per_pr"][0]["unresolved_count"] = 1
    with pytest.raises(ValueError, match="unresolved prediction coverage"):
        compare(baseline, candidate)


def test_missing_rows_and_not_evaluable_coverage_fail_closed():
    baseline, candidate = reports()
    candidate["comparison_evidence"]["per_pr"].pop()
    with pytest.raises(ValueError, match="evidence rows differ"):
        compare(baseline, candidate)
    baseline, candidate = reports()
    candidate["comparison_evidence"]["per_pr"][0]["truth_status"] = "not_evaluable"
    with pytest.raises(ValueError, match="not-evaluable"):
        compare(baseline, candidate)


def test_unattested_artifacts_are_report_only():
    baseline, candidate = reports(attested=False)
    result = compare(baseline, candidate)
    assert result["metrics"]["raw"]["decision"] == "fail"
    assert result["gate_decision"] == "report_only"


@pytest.mark.parametrize(
    ("field", "value"),
    [("unresolved_count", False), ("unresolved_count", -1), ("prediction_status", "unresolved")],
)
def test_malformed_prediction_completion_metadata_fails_closed(field, value):
    baseline, candidate = reports()
    candidate["comparison_evidence"]["per_pr"][0][field] = value
    with pytest.raises(ValueError, match="unresolved prediction"):
        compare(baseline, candidate)


def test_paired_metric_truth_denominators_must_match():
    baseline, candidate = reports()
    candidate["comparison_evidence"]["per_pr"][0]["raw"]["fn"] += 1
    with pytest.raises(ValueError, match="truth denominators differ"):
        compare(baseline, candidate)


@pytest.mark.parametrize("mutation", ["duplicate", "bad_type", "bad_digest"])
def test_selection_keys_are_typed_unique_and_digest_bound(mutation):
    baseline, candidate = reports()
    evidence = candidate["comparison_evidence"]
    if mutation == "duplicate":
        evidence["selection_keys"].append(deepcopy(evidence["selection_keys"][0]))
    elif mutation == "bad_type":
        evidence["selection_keys"][0]["pr"] = True
    else:
        evidence["selection_sha256"] = "b" * 64
    with pytest.raises(ValueError, match=r"selected PR identity|selection digest"):
        compare(baseline, candidate)


def test_all_negative_corpus_has_undefined_precision_and_fails_closed():
    baseline, candidate = reports(n=4)
    for report in (baseline, candidate):
        for row in report["comparison_evidence"]["per_pr"]:
            row["raw"] = {"tp": 0, "fp": 0, "fn": 3}
            row["normalized"] = {"tp": 0, "fp": 0, "fn": 3}
    result = compare(baseline, candidate)
    assert result["metrics"]["raw"] == {
        "supported": False,
        "reason": "undefined aggregate precision",
    }
    assert result["gate_decision"] == "report_only"


def test_self_asserted_attestation_claims_cannot_enable_official_gate():
    baseline, candidate = reports(attested=True)
    for report in (baseline, candidate):
        report["integrity"]["fully_attested"] = True
        report["integrity"]["official_scoring_eligible"] = True
        report["comparison_evidence"]["attested"] = True
    result = compare(baseline, candidate)
    assert result["attested"] is False
    assert result["gate_decision"] == "report_only"
    assert "no independently trusted attestation" in result["report_only_reason"]


def test_changed_rows_without_changed_artifact_hash_remain_report_only():
    baseline, candidate = reports(attested=True)
    original_prediction_hash = candidate["comparison_evidence"]["prediction_sha256"]
    candidate["comparison_evidence"]["per_pr"][0]["raw"] = {
        "tp": 10,
        "fp": 0,
        "fn": 1,
    }
    result = compare(baseline, candidate)
    assert candidate["comparison_evidence"]["prediction_sha256"] == original_prediction_hash
    assert result["provenance"]["candidate_prediction_sha256"] == original_prediction_hash
    assert result["attested"] is False
    assert result["gate_decision"] == "report_only"
