"""Paired PR bootstrap gate for evaluator JSON reports.

Run with ``python -m benchmarks.real_world.compare_evaluations BASELINE CANDIDATE``.
Artifacts are report-only because this comparator has no independent trust anchor
for report claims or their embedded per-PR evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from collections import defaultdict
from pathlib import Path
from typing import Any, cast

SAMPLES = 10_000
THRESHOLD = 0.02
CONFIDENCE = 0.95


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def _evidence(report: object) -> dict[str, Any]:
    if not isinstance(report, dict) or not isinstance(report.get("comparison_evidence"), dict):
        raise ValueError("missing comparison_evidence; regenerate with evaluate.py")
    evidence = report["comparison_evidence"]
    if type(evidence.get("schema_version")) is not int or evidence["schema_version"] != 2:
        raise ValueError("unsupported comparison evidence schema")
    scope = evidence.get("scope")
    if not isinstance(scope, str) or not scope.strip():
        raise ValueError("invalid or missing scope provenance")
    normalization_version = evidence.get("normalization_version")
    if type(normalization_version) is not int or normalization_version < 1:
        raise ValueError("invalid or missing normalization_version provenance")
    return cast("dict[str, Any]", evidence)


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_unique_pairs,
        parse_constant=_reject_constant,
    )
    _evidence(value)
    return cast("dict[str, Any]", value)


def _rows(report: dict[str, Any]) -> dict[tuple[str, int], dict[str, Any]]:
    rows = report["comparison_evidence"].get("per_pr")
    if not isinstance(rows, list):
        raise ValueError("per_pr evidence must be a list")
    mapped: dict[tuple[str, int], dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("malformed per_pr evidence row")
        repository, pr = row.get("repository"), row.get("pr")
        if (
            not isinstance(repository, str)
            or not repository.strip()
            or type(pr) is not int
            or pr < 1
        ):
            raise ValueError("malformed PR identity")
        key = (repository, pr)
        if key in mapped:
            raise ValueError(f"duplicate PR evidence row: {key}")
        mapped[key] = row
    return mapped


def _rates(rows: list[dict[str, Any]], metric: str) -> dict[str, float | None]:
    rows = [
        row
        for row in rows
        if row.get("terminal_status") == "evaluable" and row.get("prediction_status") == "completed"
    ]
    if not rows:
        return {"precision": None, "recall": None, "f1": None, "false_positive_pr_rate": None}
    tp = sum(row[metric]["tp"] for row in rows)
    fp = sum(row[metric]["fp"] for row in rows)
    fn = sum(row[metric]["fn"] for row in rows)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else 0.0
    negative = [row for row in rows if row.get("truth_positive") is False]
    fp_rate = sum(row[metric]["fp"] > 0 for row in negative) / len(negative) if negative else None
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_pr_rate": fp_rate,
    }


def _status_counts(rows: dict[tuple[str, int], dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    counts = {
        status: sum(row.get("prediction_status") == status for row in rows.values())
        for status in ("completed", "partial", "unresolved", "missing")
    }
    return {
        "counts": counts,
        "coverage": counts["completed"] / total if total else None,
        "abstention": counts["partial"] / total if total else None,
        "failure": (counts["unresolved"] + counts["missing"]) / total if total else None,
    }


def _sample_repositories(repositories: list[str], rng: random.Random) -> list[str]:
    return [repositories[rng.randrange(len(repositories))] for _ in repositories]


def _interval(deltas: list[float]) -> list[float]:
    deltas.sort()
    return [
        deltas[max(0, int((1 - CONFIDENCE) / 2 * len(deltas)) - 1)],
        deltas[min(len(deltas) - 1, int((1 + CONFIDENCE) / 2 * len(deltas)) - 1)],
    ]


def _sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _pr_rates(row: dict[str, Any], metric: str) -> dict[str, float | None]:
    counts = row[metric]
    tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else (0.0 if recall == 0 else None)
    )
    return {"precision": precision, "recall": recall, "f1": f1}


def _macro_values(
    rows: list[dict[str, Any]],
    metric: str,
    *,
    repository_clusters: list[str | int] | None = None,
) -> dict[str, Any]:
    pr_values = [_pr_rates(row, metric) for row in rows]
    names = ("precision", "recall", "f1")

    def mean(values: list[dict[str, float | None]], name: str) -> float | None:
        defined = [cast("float", value[name]) for value in values if value[name] is not None]
        return sum(defined) / len(defined) if defined else None

    pr_macro = {name: mean(pr_values, name) for name in names}
    clusters = (
        [row["repository"] for row in rows] if repository_clusters is None else repository_clusters
    )
    if len(clusters) != len(rows):
        raise ValueError("repository cluster labels must match the sampled rows")
    by_repository: dict[str | int, list[dict[str, float | None]]] = defaultdict(list)
    for cluster, values in zip(clusters, pr_values, strict=True):
        by_repository[cluster].append(values)
    repo_values = [
        {name: mean(values, name) for name in names} for values in by_repository.values()
    ]
    repository_macro = {name: mean(repo_values, name) for name in names}
    return {"pr_macro": pr_macro, "repository_macro": repository_macro}


def _macro_metrics(
    baseline: dict[tuple[str, int], dict[str, Any]],
    candidate: dict[tuple[str, int], dict[str, Any]],
    keys: list[tuple[str, int]],
    seed: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if not keys:
        return {
            metric: {
                aggregation: {
                    name: {
                        "baseline": None,
                        "candidate": None,
                        "delta": None,
                        "paired_repository_cluster_interval": None,
                        "interval_status": (
                            "unsupported: no paired completed evaluable positive predictions"
                        ),
                    }
                    for name in ("precision", "recall", "f1")
                }
                for aggregation in ("pr_macro", "repository_macro")
            }
            for metric in ("raw", "normalized")
        }
    repositories = sorted({baseline[key]["repository"] for key in keys})
    rng = random.Random(seed)
    for raw_metric in ("raw", "normalized"):
        base = _macro_values([baseline[key] for key in keys], raw_metric)
        cand = _macro_values([candidate[key] for key in keys], raw_metric)
        intervals: dict[str, dict[str, list[float]]] = {
            aggregation: {name: [] for name in ("precision", "recall", "f1")}
            for aggregation in ("pr_macro", "repository_macro")
        }
        by_repository = {
            repository: [key for key in keys if key[0] == repository] for repository in repositories
        }
        if len(repositories) == 1:
            for aggregation in ("pr_macro", "repository_macro"):
                for name in ("precision", "recall", "f1"):
                    left, right = base[aggregation][name], cand[aggregation][name]
                    if left is not None and right is not None:
                        intervals[aggregation][name] = [right - left] * SAMPLES
        else:
            for _ in range(SAMPLES):
                sampled = _sample_repositories(repositories, rng)
                sampled_pairs = [
                    (key, draw_index)
                    for draw_index, repository in enumerate(sampled)
                    for key in by_repository[repository]
                ]
                sampled_keys = [key for key, _cluster in sampled_pairs]
                sampled_clusters = [cluster for _key, cluster in sampled_pairs]
                left_values = _macro_values(
                    [baseline[key] for key in sampled_keys],
                    raw_metric,
                    repository_clusters=sampled_clusters,
                )
                right_values = _macro_values(
                    [candidate[key] for key in sampled_keys],
                    raw_metric,
                    repository_clusters=sampled_clusters,
                )
                for aggregation in ("pr_macro", "repository_macro"):
                    for name in ("precision", "recall", "f1"):
                        left = left_values[aggregation][name]
                        right = right_values[aggregation][name]
                        if left is not None and right is not None:
                            intervals[aggregation][name].append(right - left)
        result[raw_metric] = {
            aggregation: {
                name: {
                    "baseline": base[aggregation][name],
                    "candidate": cand[aggregation][name],
                    "delta": cand[aggregation][name] - base[aggregation][name]
                    if cand[aggregation][name] is not None and base[aggregation][name] is not None
                    else None,
                    "paired_repository_cluster_interval": _interval(intervals[aggregation][name])
                    if len(intervals[aggregation][name]) == SAMPLES
                    else None,
                    "interval_status": "supported"
                    if len(intervals[aggregation][name]) == SAMPLES
                    else "unsupported: zero-denominator bootstrap replicate",
                }
                for name in ("precision", "recall", "f1")
            }
            for aggregation in ("pr_macro", "repository_macro")
        }
    return result


def _leave_one_repository_out(
    baseline: dict[tuple[str, int], dict[str, Any]],
    candidate: dict[tuple[str, int], dict[str, Any]],
    keys: list[tuple[str, int]],
) -> dict[str, Any]:
    repositories = sorted({repository for repository, _ in keys})
    output: dict[str, Any] = {}
    for omitted in repositories:
        retained = [
            key
            for key in keys
            if key[0] != omitted
            and baseline[key].get("terminal_status") == "evaluable"
            and baseline[key].get("prediction_status") == "completed"
            and candidate[key].get("prediction_status") == "completed"
        ]
        if not retained:
            output[omitted] = {"status": "unsupported: no repositories remain"}
            continue
        baseline_rates = {
            metric: _rates([baseline[key] for key in retained], metric)
            for metric in ("raw", "normalized")
        }
        candidate_rates = {
            metric: _rates([candidate[key] for key in retained], metric)
            for metric in ("raw", "normalized")
        }
        output[omitted] = {
            "status": "report_only",
            **{
                metric: {
                    "baseline": baseline_rates[metric],
                    "candidate": candidate_rates[metric],
                    "delta": {
                        name: cast("float", candidate_rates[metric][name])
                        - cast("float", baseline_rates[metric][name])
                        if candidate_rates[metric][name] is not None
                        and baseline_rates[metric][name] is not None
                        else None
                        for name in baseline_rates[metric]
                    },
                }
                for metric in ("raw", "normalized")
            },
        }
    return output


def _selection_keys(evidence: dict[str, Any]) -> list[tuple[str, int]]:
    raw_keys = evidence.get("selection_keys")
    if not isinstance(raw_keys, list):
        raise ValueError("selection_keys must be a list")
    keys: list[tuple[str, int]] = []
    for item in raw_keys:
        if not isinstance(item, dict):
            raise ValueError("malformed selected PR identity")
        repository, pr = item.get("repository"), item.get("pr")
        if (
            not isinstance(repository, str)
            or not repository.strip()
            or type(pr) is not int
            or pr <= 0
        ):
            raise ValueError("malformed selected PR identity")
        keys.append((repository, pr))
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate selected PR identity")
    canonical = [{"repository": repository, "pr": pr} for repository, pr in sorted(keys)]
    digest = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if evidence.get("selection_sha256") != digest:
        raise ValueError("selection digest does not match selected PR identities")
    return keys


def compare(  # noqa: PLR0912, PLR0915
    baseline: dict[str, Any], candidate: dict[str, Any], *, seed: int = 283
) -> dict[str, Any]:
    left, right = _evidence(baseline), _evidence(candidate)
    left_selection = _selection_keys(left)
    right_selection = _selection_keys(right)
    compatibility_fields = ("scope", "normalization_version", "truth_sha256", "selection_sha256")
    mismatches = [name for name in compatibility_fields if left.get(name) != right.get(name)]
    if mismatches:
        raise ValueError("incompatible comparison evidence: " + ", ".join(mismatches))
    for side_name, evidence in (("baseline", left), ("candidate", right)):
        for name in ("truth_sha256", "selection_sha256", "prediction_sha256"):
            if not _sha256(evidence.get(name)):
                raise ValueError(f"{side_name} has invalid or missing {name} provenance")
    if set(left_selection) != set(right_selection):
        raise ValueError("selected PR identities differ")
    a, b = _rows(baseline), _rows(candidate)
    if set(a) != set(b):
        raise ValueError("baseline and candidate PR evidence rows differ")
    keys = sorted(a)
    if not keys:
        raise ValueError("no paired PR evidence")
    if set(keys) != set(left_selection):
        raise ValueError("per-PR evidence does not exactly cover selected PRs")
    for key in keys:
        if not _sha256(a[key].get("truth_sha256")):
            raise ValueError(f"missing per-PR truth provenance for {key}")
        if a[key].get("truth_sha256") != b[key].get("truth_sha256"):
            raise ValueError(f"truth identity changed for {key}")
        allowed_truth = {"adjudicated", "unknown", "not_evaluable"}
        if a[key].get("truth_status") not in allowed_truth or a[key].get("truth_status") != b[
            key
        ].get("truth_status"):
            raise ValueError(f"invalid or mismatched truth status for {key}")
        if a[key].get("terminal_status") not in {"evaluable", "unknown", "not_evaluable"}:
            raise ValueError(f"invalid terminal truth status for {key}")
        if a[key].get("terminal_status") != b[key].get("terminal_status"):
            raise ValueError(f"terminal truth status differs for {key}")
        expected_terminal = {
            "adjudicated": "evaluable",
            "unknown": "unknown",
            "not_evaluable": "not_evaluable",
        }[a[key]["truth_status"]]
        if a[key].get("terminal_status") != expected_terminal:
            raise ValueError(f"terminal status does not match truth status for {key}")
        polarity = a[key].get("truth_positive")
        if (expected_terminal == "evaluable" and type(polarity) is not bool) or (
            expected_terminal != "evaluable" and polarity is not None
        ):
            raise ValueError(f"invalid truth polarity for {key}")
        if a[key].get("truth_positive") != b[key].get("truth_positive"):
            raise ValueError(f"paired truth polarity differs for {key}")
        for row in (a[key], b[key]):
            unresolved_count = row.get("unresolved_count")
            status = row.get("prediction_status")
            if status not in {"completed", "partial", "unresolved", "missing"}:
                raise ValueError(f"invalid prediction terminal status for {key}")
            if status == "missing":
                if unresolved_count is not None:
                    raise ValueError(f"missing prediction has invalid terminal metadata for {key}")
            elif type(unresolved_count) is not int or unresolved_count < 0:
                raise ValueError(f"invalid unresolved prediction count for {key}")
            elif status == "completed" and unresolved_count != 0:
                raise ValueError(f"unresolved prediction coverage for {key}")
            if row.get("terminal_status") != "evaluable":
                if row.get("raw") is not None or row.get("normalized") is not None:
                    raise ValueError(
                        f"non-evaluable truth must not carry confusion counts for {key}"
                    )
            elif status != "completed" and (
                row.get("raw") is not None or row.get("normalized") is not None
            ):
                raise ValueError(
                    f"non-completed prediction must not carry confusion counts for {key}"
                )
        for row in (a[key], b[key]):
            for metric in ("raw", "normalized"):
                counts = row.get(metric)
                if (
                    row.get("terminal_status") != "evaluable"
                    or row.get("prediction_status") != "completed"
                ):
                    continue
                if not isinstance(counts, dict) or any(
                    type(counts.get(name)) is not int or counts[name] < 0
                    for name in ("tp", "fp", "fn")
                ):
                    raise ValueError(f"invalid {metric} confusion evidence for {key}")
            raw_counts = row.get("raw")
            if raw_counts is not None and (
                (polarity is False and raw_counts["tp"] + raw_counts["fn"] != 0)
                or (polarity is True and raw_counts["tp"] + raw_counts["fn"] == 0)
            ):
                raise ValueError(f"truth polarity conflicts with raw denominator for {key}")
        for metric in ("raw", "normalized"):
            if (
                a[key].get("terminal_status") != "evaluable"
                or a[key].get("prediction_status") != "completed"
                or b[key].get("prediction_status") != "completed"
            ):
                continue
            if (
                a[key][metric]["tp"] + a[key][metric]["fn"]
                != b[key][metric]["tp"] + b[key][metric]["fn"]
            ):
                raise ValueError(f"paired {metric} truth denominators differ for {key}")
    # Reports are the only inputs available here. Their attestation and integrity
    # booleans are self-asserted, and the comparator cannot verify them against an
    # independent trust root or the original artifact bytes.
    attested = False
    rng = random.Random(seed)
    scoring_keys = [
        key
        for key in keys
        if a[key].get("terminal_status") == "evaluable"
        and a[key].get("prediction_status") == "completed"
        and b[key].get("prediction_status") == "completed"
    ]
    # Resample only whole clusters represented in the paired completed quality
    # subset. Selected repositories with no eligible rows belong in the full
    # terminal denominators, but must not create empty quality bootstrap draws.
    repositories = sorted({repository for repository, _ in scoring_keys})
    macro_keys = [key for key in scoring_keys if a[key]["truth_positive"] is True]
    negative_keys = [key for key in scoring_keys if a[key]["truth_positive"] is False]
    negative_repositories = sorted({repository for repository, _ in negative_keys})
    # FP draws use their own eligible whole repository clusters and RNG. The
    # quality draws and their seed sequence remain independent of this measure.
    fp_rng = random.Random(seed)
    intervals: dict[str, dict[str, Any]] = {}
    for metric in ("raw", "normalized"):
        base_rates = _rates([a[key] for key in scoring_keys], metric)
        candidate_rates = _rates([b[key] for key in scoring_keys], metric)
        deltas: dict[str, list[float]] = {
            name: [] for name in ("precision", "recall", "f1", "false_positive_pr_rate")
        }
        undefined: dict[str, int] = dict.fromkeys(deltas, 0)
        if not repositories:
            # With no quality clusters, every quality interval is unsupported.
            # Retain terminal denominators instead of fabricating zero scores.
            undefined = dict.fromkeys(deltas, SAMPLES)
        else:
            for _ in range(SAMPLES):
                sampled_repos = _sample_repositories(repositories, rng)
                sampled_keys = [
                    key
                    for repository in sampled_repos
                    for key in scoring_keys
                    if key[0] == repository
                ]
                sampled_a = [a[key] for key in sampled_keys]
                sampled_b = [b[key] for key in sampled_keys]
                left_rates, right_rates = _rates(sampled_a, metric), _rates(sampled_b, metric)
                for name, samples in deltas.items():
                    if name == "false_positive_pr_rate":
                        continue
                    left_value, right_value = left_rates[name], right_rates[name]
                    if left_value is None or right_value is None:
                        undefined[name] += 1
                    else:
                        samples.append(right_value - left_value)
        if len(negative_repositories) < 2:
            undefined["false_positive_pr_rate"] = SAMPLES
        else:
            for _ in range(SAMPLES):
                sampled_repos = _sample_repositories(negative_repositories, fp_rng)
                sampled_keys = [
                    key
                    for repository in sampled_repos
                    for key in scoring_keys
                    if key[0] == repository
                ]
                left_fp = _rates([a[key] for key in sampled_keys], metric)["false_positive_pr_rate"]
                right_fp = _rates([b[key] for key in sampled_keys], metric)[
                    "false_positive_pr_rate"
                ]
                if left_fp is None or right_fp is None:
                    undefined["false_positive_pr_rate"] += 1
                else:
                    deltas["false_positive_pr_rate"].append(right_fp - left_fp)
        measures: dict[str, Any] = {}
        for name, samples in deltas.items():
            supported = not undefined[name] and len(samples) == SAMPLES
            bounds = _interval(samples) if samples else None
            threshold = -THRESHOLD if name in {"precision", "recall", "f1"} else THRESHOLD
            bound = None
            if bounds:
                bound = bounds[1] if name == "false_positive_pr_rate" else bounds[0]
            passed = False
            if supported and bound is not None:
                passed = (
                    bound >= threshold if name != "false_positive_pr_rate" else bound <= threshold
                )
            if supported and bound is not None and math.isclose(bound, threshold, abs_tol=1e-12):
                passed = True
            baseline_rate, candidate_rate = base_rates[name], candidate_rates[name]
            measures[name] = {
                "baseline": base_rates[name],
                "candidate": candidate_rates[name],
                "delta": (
                    candidate_rate - baseline_rate
                    if baseline_rate is not None and candidate_rate is not None
                    else None
                ),
                "confidence": CONFIDENCE,
                "interval": bounds,
                "threshold": threshold,
                "bound_test": (
                    "upper_at_most" if name == "false_positive_pr_rate" else "lower_at_least"
                ),
                "decision": "pass" if passed else "fail" if supported else "unsupported",
                "undefined_samples": undefined[name],
            }
            if name == "false_positive_pr_rate":
                measures[name]["eligible_repository_clusters"] = len(negative_repositories)
                if not supported:
                    measures[name]["unsupported_reason"] = (
                        "no_negative_control_rows"
                        if not negative_keys
                        else "fewer_than_two_negative_control_repositories"
                        if len(negative_repositories) < 2
                        else "zero_denominator_bootstrap_replicate"
                    )
        intervals[metric] = {
            "method": "paired repository-cluster bootstrap percentile interval",
            "supported": all(item["decision"] != "unsupported" for item in measures.values()),
            "measures": measures,
        }
    baseline_status = _status_counts(a)
    candidate_status = _status_counts(b)
    rate_deltas = {
        name: cast("float", candidate_status[name]) - cast("float", baseline_status[name])
        for name in ("coverage", "abstention", "failure")
    }
    missing_delta = candidate_status["counts"]["missing"] - baseline_status["counts"]["missing"]
    return {
        "schema_version": 3,
        "method": "paired repository-cluster bootstrap percentile interval",
        "samples": SAMPLES,
        "seed": seed,
        "pairing": "same selected repository/PR identities and truth record hashes",
        "metrics": intervals,
        "denominators": {
            "total": len(keys),
            "terminal": len(keys),
            "evaluable": sum(a[key].get("terminal_status") == "evaluable" for key in keys),
            "positive": sum(a[key].get("truth_positive") is True for key in keys),
            "negative": sum(a[key].get("truth_positive") is False for key in keys),
            "unknown": sum(a[key].get("truth_status") == "unknown" for key in keys),
            "not_evaluable": sum(a[key].get("truth_status") == "not_evaluable" for key in keys),
            "paired_completed_evaluable": len(scoring_keys),
        },
        "per_run": {"baseline": baseline_status, "candidate": candidate_status},
        "per_run_deltas": {
            "counts": {
                status: candidate_status["counts"][status] - baseline_status["counts"][status]
                for status in ("completed", "partial", "unresolved", "missing")
            },
            **rate_deltas,
        },
        "macro_metrics": _macro_metrics(a, b, macro_keys, seed),
        "leave_one_repository_out": _leave_one_repository_out(a, b, keys),
        "diagnostics": {
            "quality_subset": "evaluable truth identities with completed predictions in both runs",
            "quality_subset_count": len(scoring_keys),
            "macro_subset": "paired completed evaluable truth-positive identities",
            "macro_subset_count": len(macro_keys),
            "fp_repository_cluster_count": len(negative_repositories),
            "baseline": baseline_status,
            "candidate": candidate_status,
            "deltas_candidate_minus_baseline": {
                **rate_deltas,
                "missing_count": missing_delta,
            },
            "failure_phase_rates": {"unsupported": None, "timeout": None, "execution": None},
            "stress_breakdown": "unsupported: no stress partition identity in evaluation evidence",
            "heldout_breakdown": (
                "unsupported: no held-out partition identity in evaluation evidence"
            ),
            "calibration": "unsupported: terminal records contain no calibrated probability field",
        },
        "gate_decision": "report_only",
        "attested": attested,
        "provenance": {
            "baseline_prediction_sha256": left.get("prediction_sha256"),
            "candidate_prediction_sha256": right.get("prediction_sha256"),
            "baseline_prediction_manifest_sha256": left.get("prediction_manifest_sha256"),
            "candidate_prediction_manifest_sha256": right.get("prediction_manifest_sha256"),
            "baseline_evidence_sha256": hashlib.sha256(
                json.dumps(left, sort_keys=True).encode()
            ).hexdigest(),
            "candidate_evidence_sha256": hashlib.sha256(
                json.dumps(right, sort_keys=True).encode()
            ).hexdigest(),
        },
        "report_only_reason": (
            "no independently trusted attestation or artifact-byte binding is "
            "available to the comparator"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--seed", type=int, default=283)
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                compare(_load(args.baseline), _load(args.candidate), seed=args.seed), indent=2
            )
        )
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
