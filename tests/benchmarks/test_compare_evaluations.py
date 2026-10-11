from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import TYPE_CHECKING

import pytest
from benchmarks.real_world import compare_evaluations as comparison
from benchmarks.real_world.compare_evaluations import _load, compare
from benchmarks.real_world.semantic_normalization import ALIAS_VERSION

if TYPE_CHECKING:
    from pathlib import Path


def reports(*, attested: bool = True, n: int = 40):
    rows_a, rows_b, keys = [], [], []
    for pr in range(1, n + 1):
        key = {"repository": "owner/repo", "pr": pr}
        keys.append(key)
        base = {
            **key,
            "truth_status": "adjudicated",
            "truth_positive": True,
            "terminal_status": "evaluable",
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
                "schema_version": 2,
                "scope": "fastapi-adapter-v1",
                "normalization_version": ALIAS_VERSION,
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
    assert first["metrics"]["raw"]["measures"]["precision"]["decision"] == "fail"
    assert first["metrics"]["raw"]["method"].startswith("paired repository-cluster")
    assert first["gate_decision"] == "report_only"
    assert first["attested"] is False


def test_two_point_tie_passes_threshold():
    baseline, candidate = reports(n=7)
    for report, tp, fp, fn in ((baseline, 49, 51, 51), (candidate, 47, 53, 53)):
        for row in report["comparison_evidence"]["per_pr"]:
            row["raw"] = {"tp": tp, "fp": fp, "fn": fn}
            row["normalized"] = {"tp": tp, "fp": fp, "fn": fn}
    result = compare(baseline, candidate)
    assert result["metrics"]["raw"]["measures"]["precision"]["interval"][0] == pytest.approx(-0.02)
    assert result["metrics"]["raw"]["measures"]["precision"]["decision"] == "pass"
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
    with pytest.raises(ValueError, match="truth status"):
        compare(baseline, candidate)


def test_unattested_artifacts_are_report_only():
    baseline, candidate = reports(attested=False)
    result = compare(baseline, candidate)
    assert result["metrics"]["raw"]["measures"]["precision"]["decision"] == "fail"
    assert result["gate_decision"] == "report_only"


@pytest.mark.parametrize(
    ("field", "value"),
    [("unresolved_count", False), ("unresolved_count", -1), ("prediction_status", "bogus")],
)
def test_malformed_prediction_completion_metadata_fails_closed(field, value):
    baseline, candidate = reports()
    candidate["comparison_evidence"]["per_pr"][0][field] = value
    with pytest.raises(ValueError, match="prediction"):
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
    assert result["metrics"]["raw"]["measures"]["precision"]["decision"] == "unsupported"
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


@pytest.mark.parametrize("version", [True, False, 1.0, "2", None, 1])
def test_direct_comparison_rejects_untyped_schema_version(version):
    baseline, candidate = reports(n=1)
    for report in (baseline, candidate):
        report["comparison_evidence"]["schema_version"] = version
    with pytest.raises(ValueError, match="unsupported comparison evidence schema"):
        compare(baseline, candidate)


@pytest.mark.parametrize("field", ["scope"])
@pytest.mark.parametrize("value", [None, "", " ", [], {}, True, 1])
def test_equal_invalid_provenance_does_not_make_reports_compatible(field, value):
    baseline, candidate = reports(n=1)
    for report in (baseline, candidate):
        report["comparison_evidence"][field] = value
    with pytest.raises(ValueError, match=f"invalid or missing {field} provenance"):
        compare(baseline, candidate)


@pytest.mark.parametrize("extra", ['"x": NaN', '"x": Infinity', '"x": -Infinity', '"x": 1, "x": 2'])
def test_serialized_report_rejects_nonfinite_and_duplicate_fields(tmp_path: Path, extra):
    baseline, _ = reports(n=1)
    serialized = json.dumps(baseline)
    path = tmp_path / "report.json"
    path.write_text(serialized[:-1] + ", " + extra + "}", encoding="utf-8")
    with pytest.raises(ValueError, match=r"non-finite JSON constant|duplicate JSON key"):
        _load(path)


@pytest.mark.parametrize("value", [None, "aliases-v1", [], {}, True, False, 0, -1, 1.0])
def test_normalization_version_uses_the_evaluators_positive_integer_contract(value):
    baseline, candidate = reports(n=1)
    for report in (baseline, candidate):
        report["comparison_evidence"]["normalization_version"] = value
    with pytest.raises(ValueError, match="invalid or missing normalization_version provenance"):
        compare(baseline, candidate)


def test_serialized_evaluator_version_can_be_loaded_and_compared(tmp_path: Path):
    baseline, candidate = reports(n=1)
    paths = [tmp_path / "baseline.json", tmp_path / "candidate.json"]
    for path, report in zip(paths, (baseline, candidate), strict=True):
        path.write_text(json.dumps(report), encoding="utf-8")
    result = compare(_load(paths[0]), _load(paths[1]))
    assert result["metrics"]["raw"]["measures"]["precision"]["baseline"] == 1.0
    assert result["metrics"]["raw"]["measures"]["precision"]["candidate"] == 0.8
    assert result["gate_decision"] == "report_only"


def test_repository_cluster_bootstrap_reports_fp_and_recall_gates():
    baseline, candidate = reports(n=4)
    for report in (baseline, candidate):
        rows = report["comparison_evidence"]["per_pr"]
        for index, row in enumerate(rows):
            repository = f"owner/repo-{index % 2}"
            row["repository"] = repository
            report["comparison_evidence"]["selection_keys"][index]["repository"] = repository
    keys = sorted(
        report["comparison_evidence"]["selection_keys"],
        key=lambda item: (item["repository"], item["pr"]),
    )
    serialized_keys = json.dumps(keys, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(serialized_keys).hexdigest()
    for report in (baseline, candidate):
        report["comparison_evidence"]["selection_sha256"] = digest
    result = compare(baseline, candidate, seed=5)
    measures = result["metrics"]["raw"]["measures"]
    assert set(measures) == {"precision", "recall", "f1", "false_positive_pr_rate"}
    assert measures["recall"]["delta"] == pytest.approx(-2 / 11)
    assert measures["recall"]["decision"] == "fail"
    assert measures["false_positive_pr_rate"]["bound_test"] == "upper_at_most"


def test_micro_bootstrap_excludes_selected_repositories_outside_quality_subset():
    baseline, candidate = reports(n=2)
    for report in (baseline, candidate):
        evidence = report["comparison_evidence"]
        row = evidence["per_pr"][1]
        key = evidence["selection_keys"][1]
        row["repository"] = key["repository"] = "owner/noncompleted"
        row["prediction_status"] = "partial"
        row["unresolved_count"] = 1
        row["raw"] = row["normalized"] = None
        canonical_keys = sorted(
            evidence["selection_keys"], key=lambda item: (item["repository"], item["pr"])
        )
        evidence["selection_sha256"] = hashlib.sha256(
            json.dumps(canonical_keys, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    result = compare(baseline, candidate, seed=37)
    measures = result["metrics"]["raw"]["measures"]
    assert result["denominators"]["total"] == 2
    assert result["denominators"]["paired_completed_evaluable"] == 1
    assert result["per_run"]["baseline"]["counts"]["partial"] == 1
    assert measures["precision"]["decision"] != "unsupported"
    assert measures["recall"]["decision"] != "unsupported"
    assert measures["f1"]["decision"] != "unsupported"
    assert (
        result["macro_metrics"]["raw"]["repository_macro"]["recall"]["interval_status"]
        == "supported"
    )


def test_unknown_and_missing_predictions_remain_terminal_denominators_not_negatives():
    baseline, candidate = reports(n=3)
    for report in (baseline, candidate):
        rows = report["comparison_evidence"]["per_pr"]
        rows[1].update(
            truth_status="unknown",
            truth_positive=None,
            terminal_status="unknown",
            prediction_status="missing",
            unresolved_count=None,
            raw=None,
            normalized=None,
        )
        rows[2]["prediction_status"] = "partial"
        rows[2]["unresolved_count"] = 1
        rows[2]["raw"] = rows[2]["normalized"] = None
    result = compare(baseline, candidate)
    assert result["denominators"]["total"] == 3
    assert result["denominators"]["unknown"] == 1
    assert result["denominators"]["negative"] == 0
    assert result["per_run"]["baseline"]["counts"]["missing"] == 1
    assert result["denominators"]["paired_completed_evaluable"] == 1
    assert result["gate_decision"] == "report_only"


def test_all_unresolved_terminals_are_reported_with_unsupported_scores():
    baseline, candidate = reports(n=3)
    for report in (baseline, candidate):
        for row in report["comparison_evidence"]["per_pr"]:
            row["prediction_status"] = "unresolved"
            row["unresolved_count"] = 1
            row["raw"] = row["normalized"] = None
    result = compare(baseline, candidate)
    assert result["per_run"]["baseline"]["counts"]["unresolved"] == 3
    assert result["denominators"]["paired_completed_evaluable"] == 0
    assert result["diagnostics"]["baseline"]["failure"] == 1.0
    assert result["macro_metrics"]["raw"]["pr_macro"]["recall"]["interval_status"].startswith(
        "unsupported"
    )


def test_unequal_repository_clusters_macro_intervals_and_leave_one_out_are_deterministic():
    baseline, candidate = reports(n=5)
    rows_a = baseline["comparison_evidence"]["per_pr"]
    rows_b = candidate["comparison_evidence"]["per_pr"]
    keys = baseline["comparison_evidence"]["selection_keys"]
    for index, (left, right, key) in enumerate(zip(rows_a, rows_b, keys, strict=True)):
        repo = "owner/small" if index == 0 else "owner/large"
        left["repository"] = right["repository"] = key["repository"] = repo
    canonical = sorted(keys, key=lambda item: (item["repository"], item["pr"]))
    digest = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    for report in (baseline, candidate):
        report["comparison_evidence"]["selection_sha256"] = digest
    first = compare(baseline, candidate, seed=91)
    second = compare(baseline, candidate, seed=91)
    assert first == second
    macro = first["macro_metrics"]["normalized"]["repository_macro"]["recall"]
    assert macro["paired_repository_cluster_interval"] is not None
    assert set(first["leave_one_repository_out"]) == {"owner/small", "owner/large"}


def test_cluster_bootstrap_repeats_and_negative_control_fp_gate_is_numeric():
    baseline, candidate = reports(n=6)
    rows_a = baseline["comparison_evidence"]["per_pr"]
    rows_b = candidate["comparison_evidence"]["per_pr"]
    keys = baseline["comparison_evidence"]["selection_keys"]
    for index, (left, right, key) in enumerate(zip(rows_a, rows_b, keys, strict=True)):
        repository = f"owner/repo-{index // 3}"
        left["repository"] = right["repository"] = key["repository"] = repository
        if index in {0, 3}:
            for row in (left, right):
                row["truth_positive"] = False
                row["raw"] = row["normalized"] = {"tp": 0, "fp": 0, "fn": 0}
            right["raw"] = right["normalized"] = {"tp": 0, "fp": 1, "fn": 0}
    canonical_keys = sorted(keys, key=lambda item: (item["repository"], item["pr"]))
    digest = hashlib.sha256(
        json.dumps(canonical_keys, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    for report in (baseline, candidate):
        report["comparison_evidence"]["selection_sha256"] = digest
    first = compare(baseline, candidate, seed=91)
    second = compare(baseline, candidate, seed=91)
    assert first == second
    fp_gate = first["metrics"]["raw"]["measures"]["false_positive_pr_rate"]
    assert fp_gate["delta"] == pytest.approx(1.0)
    assert fp_gate["decision"] == "fail"


@pytest.mark.parametrize(
    ("baseline_status", "candidate_status", "baseline_unresolved", "candidate_unresolved"),
    [
        ("missing", "completed", None, 0),
        ("partial", "completed", 1, 0),
        ("unresolved", "completed", 1, 0),
    ],
)
def test_per_run_terminal_outcomes_pair_truth_without_becoming_confusion_counts(
    baseline_status, candidate_status, baseline_unresolved, candidate_unresolved
):
    baseline, candidate = reports(n=2)
    base_row = baseline["comparison_evidence"]["per_pr"][0]
    candidate_row = candidate["comparison_evidence"]["per_pr"][0]
    for row, status, unresolved in (
        (base_row, baseline_status, baseline_unresolved),
        (candidate_row, candidate_status, candidate_unresolved),
    ):
        row["prediction_status"] = status
        row["unresolved_count"] = unresolved
        if status != "completed":
            row["raw"] = row["normalized"] = None

    result = compare(baseline, candidate, seed=11)
    assert result["denominators"]["positive"] == 2
    assert result["denominators"]["negative"] == 0
    assert result["denominators"]["paired_completed_evaluable"] == 1
    assert result["per_run"]["baseline"]["counts"][baseline_status] == 1
    assert result["per_run"]["candidate"]["counts"][candidate_status] == 2
    assert result["per_run_deltas"]["counts"][baseline_status] == -1
    assert result["metrics"]["raw"]["measures"]["precision"]["baseline"] == 1.0
    assert result["metrics"]["raw"]["measures"]["precision"]["candidate"] == pytest.approx(0.8)
    assert result["gate_decision"] == "report_only"


def test_all_partial_quality_subset_reports_terminal_counts_and_unsupported_metrics():
    baseline, candidate = reports(n=3)
    for report in (baseline, candidate):
        for row in report["comparison_evidence"]["per_pr"]:
            row["prediction_status"] = "partial"
            row["unresolved_count"] = 1
            row["raw"] = row["normalized"] = None

    result = compare(baseline, candidate, seed=29)
    assert result["denominators"]["total"] == 3
    assert result["denominators"]["evaluable"] == 3
    assert result["denominators"]["paired_completed_evaluable"] == 0
    assert result["per_run"]["baseline"]["counts"]["partial"] == 3
    assert result["per_run"]["candidate"]["counts"]["partial"] == 3
    assert result["per_run"]["baseline"]["abstention"] == 1.0
    for metric in ("raw", "normalized"):
        assert result["metrics"][metric]["supported"] is False
        for measure in result["metrics"][metric]["measures"].values():
            assert measure["decision"] == "unsupported"
            assert measure["baseline"] is measure["candidate"] is measure["delta"] is None
            assert measure["interval"] is None
            assert measure["undefined_samples"] == 10_000
    assert result["macro_metrics"]["raw"]["pr_macro"]["recall"]["interval_status"].startswith(
        "unsupported"
    )


@pytest.mark.parametrize("truth_status", ["unknown", "not_evaluable"])
def test_non_evaluable_only_selection_keeps_denominators_without_quality_scores(truth_status):
    baseline, candidate = reports(n=2)
    for report in (baseline, candidate):
        for row in report["comparison_evidence"]["per_pr"]:
            row.update(
                truth_status=truth_status,
                truth_positive=None,
                terminal_status=truth_status,
                raw=None,
                normalized=None,
            )

    result = compare(baseline, candidate, seed=31)
    assert result["denominators"]["total"] == 2
    assert result["denominators"]["evaluable"] == 0
    assert result["denominators"]["unknown"] == (2 if truth_status == "unknown" else 0)
    assert result["denominators"]["not_evaluable"] == (2 if truth_status == "not_evaluable" else 0)
    assert result["denominators"]["paired_completed_evaluable"] == 0
    assert result["per_run"]["baseline"]["counts"]["completed"] == 2
    for metric in ("raw", "normalized"):
        assert result["metrics"][metric]["supported"] is False
        for measure in result["metrics"][metric]["measures"].values():
            assert measure["decision"] == "unsupported"
            assert measure["baseline"] is measure["candidate"] is measure["delta"] is None
            assert measure["interval"] is None
            assert measure["undefined_samples"] == 10_000


def _refresh_selected_identities(report):
    evidence = report["comparison_evidence"]
    evidence["selection_keys"] = sorted(
        [{"repository": row["repository"], "pr": row["pr"]} for row in evidence["per_pr"]],
        key=lambda item: (item["repository"], item["pr"]),
    )
    evidence["selection_sha256"] = hashlib.sha256(
        json.dumps(evidence["selection_keys"], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def test_repository_macro_preserves_repeated_repository_draws(monkeypatch):
    monkeypatch.setattr(comparison, "SAMPLES", 1)
    monkeypatch.setattr(comparison, "_sample_repositories", lambda _repos, _rng: ["A", "A", "B"])
    keys = [("A", 1), ("B", 2)]
    baseline, candidate = {}, {}
    for mapping in (baseline, candidate):
        for repository, pr in keys:
            mapping[(repository, pr)] = {
                "repository": repository,
                "pr": pr,
                "truth_positive": True,
                "terminal_status": "evaluable",
                "prediction_status": "completed",
                "raw": {"tp": 1, "fp": 0, "fn": 1},
                "normalized": {"tp": 1, "fp": 0, "fn": 1},
            }
    baseline[("B", 2)]["raw"] = baseline[("B", 2)]["normalized"] = {"tp": 1, "fp": 0, "fn": 0}
    candidate[("A", 1)]["raw"] = candidate[("A", 1)]["normalized"] = {"tp": 1, "fp": 0, "fn": 0}
    result = comparison._macro_metrics(baseline, candidate, keys, seed=13)
    for metric in ("raw", "normalized"):
        recall = result[metric]["repository_macro"]["recall"]
        assert recall["baseline"] == pytest.approx(0.75)
        assert recall["candidate"] == pytest.approx(0.75)
        assert recall["delta"] == pytest.approx(0.0)
        assert recall["paired_repository_cluster_interval"] == pytest.approx([1 / 6, 1 / 6])


def test_negative_control_fp_does_not_enter_positive_macro(monkeypatch):
    monkeypatch.setattr(comparison, "SAMPLES", 16)
    baseline, candidate = reports(n=2)
    for report in (baseline, candidate):
        for row in report["comparison_evidence"]["per_pr"]:
            row["repository"] = f"owner/repo-{row['pr']}"
        _refresh_selected_identities(report)
    without_control = compare(baseline, candidate, seed=23)
    for report in (baseline, candidate):
        report["comparison_evidence"]["per_pr"].append(
            {
                "repository": "owner/control",
                "pr": 99,
                "truth_status": "adjudicated",
                "truth_positive": False,
                "terminal_status": "evaluable",
                "truth_sha256": "f" * 64,
                "prediction_status": "completed",
                "unresolved_count": 0,
                "raw": {"tp": 0, "fp": int(report is candidate), "fn": 0},
                "normalized": {"tp": 0, "fp": int(report is candidate), "fn": 0},
            }
        )
        _refresh_selected_identities(report)
    with_control = compare(baseline, candidate, seed=23)
    assert with_control["macro_metrics"] == without_control["macro_metrics"]
    assert with_control["metrics"]["raw"]["measures"]["false_positive_pr_rate"]["delta"] == 1
    assert with_control["diagnostics"]["macro_subset_count"] == 2


@pytest.mark.parametrize("eligible_repository_count", [0, 1, 2])
def test_fp_interval_uses_eligible_negative_repository_clusters(
    monkeypatch, eligible_repository_count
):
    monkeypatch.setattr(comparison, "SAMPLES", 24)
    baseline, candidate = reports(n=3)
    for report in (baseline, candidate):
        rows = report["comparison_evidence"]["per_pr"]
        for row in rows:
            row["repository"] = f"owner/repo-{row['pr']}"
        for index in range(1, eligible_repository_count + 1):
            rows.append(
                {
                    "repository": f"owner/repo-{index}",
                    "pr": index + 10,
                    "truth_status": "adjudicated",
                    "truth_positive": False,
                    "terminal_status": "evaluable",
                    "truth_sha256": f"{index + 10:064x}",
                    "prediction_status": "completed",
                    "unresolved_count": 0,
                    "raw": {"tp": 0, "fp": int(report is candidate), "fn": 0},
                    "normalized": {"tp": 0, "fp": int(report is candidate), "fn": 0},
                }
            )
        _refresh_selected_identities(report)
    result = compare(baseline, candidate, seed=31)
    for metric in ("raw", "normalized"):
        measures = result["metrics"][metric]["measures"]
        fp = measures["false_positive_pr_rate"]
        assert fp["eligible_repository_clusters"] == eligible_repository_count
        assert all(
            measures[name]["decision"] != "unsupported" for name in ("precision", "recall", "f1")
        )
        if eligible_repository_count == 2:
            assert fp["baseline"] == 0 and fp["candidate"] == 1
            assert fp["decision"] == "fail"
            assert fp["interval"] == [1.0, 1.0]
        else:
            assert fp["decision"] == "unsupported"
            assert fp["interval"] is None
            assert fp["unsupported_reason"] == (
                "no_negative_control_rows"
                if not eligible_repository_count
                else "fewer_than_two_negative_control_repositories"
            )
            if eligible_repository_count:
                assert fp["baseline"] == 0 and fp["candidate"] == 1
            else:
                assert fp["baseline"] is None and fp["candidate"] is None


def test_normalized_zero_denominator_does_not_relabel_positive_truth_as_control(monkeypatch):
    monkeypatch.setattr(comparison, "SAMPLES", 8)
    baseline, candidate = reports(n=2)
    for report in (baseline, candidate):
        for row in report["comparison_evidence"]["per_pr"]:
            row["repository"] = f"owner/repo-{row['pr']}"
            row["normalized"] = {"tp": 0, "fp": 0, "fn": 0}
        _refresh_selected_identities(report)
    fp = compare(baseline, candidate)["metrics"]["normalized"]["measures"]["false_positive_pr_rate"]
    assert fp["baseline"] is None and fp["candidate"] is None
    assert fp["unsupported_reason"] == "no_negative_control_rows"


def test_comparator_result_schema_is_distinct_from_input_evidence(monkeypatch):
    monkeypatch.setattr(comparison, "SAMPLES", 8)
    report, _ = reports(n=2)
    result = comparison.compare(report, report)
    assert report["comparison_evidence"]["schema_version"] == 2
    assert result["schema_version"] == 4


def _quality_cluster_reports(*, control_fp=0):
    baseline, candidate = reports(n=3)
    for report in (baseline, candidate):
        rows = report["comparison_evidence"]["per_pr"]
        for row in rows:
            row["repository"] = f"owner/repo-{row['pr']}"
        rows[-1].update(
            truth_positive=False,
            raw={"tp": 0, "fp": control_fp, "fn": 0},
            normalized={"tp": 0, "fp": control_fp, "fn": 0},
        )
        _refresh_selected_identities(report)
    return baseline, candidate


@pytest.mark.parametrize("control_fp", [0, 1])
def test_quality_intervals_use_their_denominator_bearing_clusters(monkeypatch, control_fp):
    monkeypatch.setattr(comparison, "SAMPLES", 24)
    baseline, candidate = _quality_cluster_reports(control_fp=control_fp)
    result = compare(baseline, candidate, seed=19)
    assert result["denominators"]["total"] == 3
    assert result["gate_decision"] == "report_only"
    for metric in ("raw", "normalized"):
        measures = result["metrics"][metric]["measures"]
        for name in ("precision", "recall", "f1"):
            measure = measures[name]
            expected = 3 if control_fp and name in {"precision", "f1"} else 2
            assert measure["eligible_repository_clusters"] == expected
            assert measure["undefined_samples"] == 0
            assert measure["decision"] != "unsupported"
            assert measure["interval"] is not None
            assert measure["interval_scope"] == "paired denominator-bearing repository clusters"
            assert measure["degenerate_single_cluster"] is False
        assert measures["false_positive_pr_rate"]["eligible_repository_clusters"] == 1
        assert measures["false_positive_pr_rate"]["decision"] == "unsupported"


def test_quality_intervals_retain_one_sided_denominator_contributions(monkeypatch):
    monkeypatch.setattr(comparison, "SAMPLES", 8)
    baseline, candidate = reports(n=2)
    for report in (baseline, candidate):
        rows = report["comparison_evidence"]["per_pr"]
        for row in rows:
            row["repository"] = f"owner/repo-{row['pr']}"
            row["raw"] = row["normalized"] = {"tp": 0, "fp": 0, "fn": 1}
        _refresh_selected_identities(report)
    baseline["comparison_evidence"]["per_pr"][0]["raw"] = {"tp": 1, "fp": 0, "fn": 0}
    candidate["comparison_evidence"]["per_pr"][1]["raw"] = {"tp": 1, "fp": 0, "fn": 0}
    monkeypatch.setattr(
        comparison, "_sample_repositories", lambda repos, _rng: [repos[0], repos[0]]
    )
    result = compare(baseline, candidate)
    precision = result["metrics"]["raw"]["measures"]["precision"]
    assert precision["eligible_repository_clusters"] == 2
    assert precision["undefined_samples"] == 8
    assert precision["decision"] == "unsupported"
    assert precision["interval"] is None
    assert precision["unsupported_reason"] == "zero_denominator_bootstrap_replicate"


def test_clean_negative_only_quality_has_no_fabricated_f1(monkeypatch):
    monkeypatch.setattr(comparison, "SAMPLES", 8)
    baseline, candidate = reports(n=2)
    for report in (baseline, candidate):
        for row in report["comparison_evidence"]["per_pr"]:
            row["repository"] = f"owner/repo-{row['pr']}"
            row.update(
                truth_positive=False,
                raw={"tp": 0, "fp": 0, "fn": 0},
                normalized={"tp": 0, "fp": 0, "fn": 0},
            )
        _refresh_selected_identities(report)
    result = compare(baseline, candidate)
    for metric in ("raw", "normalized"):
        for name in ("precision", "recall", "f1"):
            measure = result["metrics"][metric]["measures"][name]
            assert measure["eligible_repository_clusters"] == 0
            assert measure["baseline"] is measure["candidate"] is measure["interval"] is None
            assert measure["decision"] == "unsupported"
            assert measure["undefined_samples"] == 8
            assert measure["unsupported_reason"] == "no_denominator_bearing_repositories"


def test_single_denominator_cluster_is_explicitly_degenerate(monkeypatch):
    monkeypatch.setattr(comparison, "SAMPLES", 8)
    baseline, candidate = _quality_cluster_reports()
    for report in (baseline, candidate):
        rows = report["comparison_evidence"]["per_pr"]
        rows[1]["repository"] = rows[0]["repository"]
        _refresh_selected_identities(report)
    result = compare(baseline, candidate)
    for metric in ("raw", "normalized"):
        for name in ("precision", "recall", "f1"):
            measure = result["metrics"][metric]["measures"][name]
            assert measure["eligible_repository_clusters"] == 1
            assert measure["undefined_samples"] == 0
            assert measure["interval"] is not None
            assert measure["degenerate_single_cluster"] is True
