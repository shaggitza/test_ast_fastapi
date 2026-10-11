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
    if type(evidence.get("schema_version")) is not int or evidence["schema_version"] != 1:
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
        if not isinstance(repository, str) or type(pr) is not int:
            raise ValueError("malformed PR identity")
        key = (repository, pr)
        if key in mapped:
            raise ValueError(f"duplicate PR evidence row: {key}")
        mapped[key] = row
    return mapped


def _rates(rows: list[dict[str, Any]], metric: str) -> dict[str, float | None]:
    tp = sum(row[metric]["tp"] for row in rows)
    fp = sum(row[metric]["fp"] for row in rows)
    fn = sum(row[metric]["fn"] for row in rows)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else 0.0
    negative = [row for row in rows if row[metric]["tp"] + row[metric]["fn"] == 0]
    fp_rate = sum(row[metric]["fp"] > 0 for row in negative) / len(negative) if negative else None
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_pr_rate": fp_rate,
    }


def _sample_repositories(repositories: list[str], rng: random.Random) -> list[str]:
    return [repositories[rng.randrange(len(repositories))] for _ in repositories]


def _rows_for_clusters(
    rows_by_repository: dict[str, list[dict[str, Any]]], repositories: list[str]
) -> list[dict[str, Any]]:
    return [row for repository in repositories for row in rows_by_repository[repository]]


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
        if (
            a[key].get("truth_status") != "adjudicated"
            or b[key].get("truth_status") != "adjudicated"
        ):
            raise ValueError(f"unresolved or not-evaluable truth coverage for {key}")
        for row in (a[key], b[key]):
            unresolved_count = row.get("unresolved_count")
            if type(unresolved_count) is not int or unresolved_count < 0:
                raise ValueError(f"invalid unresolved prediction count for {key}")
            if unresolved_count != 0 or row.get("prediction_status") != "completed":
                raise ValueError(f"unresolved prediction coverage for {key}")
        for row in (a[key], b[key]):
            for metric in ("raw", "normalized"):
                counts = row.get(metric)
                if not isinstance(counts, dict) or any(
                    type(counts.get(name)) is not int or counts[name] < 0
                    for name in ("tp", "fp", "fn")
                ):
                    raise ValueError(f"invalid {metric} confusion evidence for {key}")
        for metric in ("raw", "normalized"):
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
    repositories = sorted({repository for repository, _ in a})
    baseline_by_repository: dict[str, list[dict[str, Any]]] = {
        repository: [] for repository in repositories
    }
    candidate_by_repository: dict[str, list[dict[str, Any]]] = {
        repository: [] for repository in repositories
    }
    for key in keys:
        baseline_by_repository[key[0]].append(a[key])
        candidate_by_repository[key[0]].append(b[key])
    intervals: dict[str, dict[str, Any]] = {}
    for metric in ("raw", "normalized"):
        base_rates = _rates([a[key] for key in keys], metric)
        candidate_rates = _rates([b[key] for key in keys], metric)
        deltas: dict[str, list[float]] = {
            name: [] for name in ("precision", "recall", "f1", "false_positive_pr_rate")
        }
        undefined: dict[str, int] = dict.fromkeys(deltas, 0)
        for _ in range(SAMPLES):
            sampled_repos = _sample_repositories(repositories, rng)
            sampled_a = _rows_for_clusters(baseline_by_repository, sampled_repos)
            sampled_b = _rows_for_clusters(candidate_by_repository, sampled_repos)
            left_rates, right_rates = _rates(sampled_a, metric), _rates(sampled_b, metric)
            for name, samples in deltas.items():
                left_value, right_value = left_rates[name], right_rates[name]
                if left_value is None or right_value is None:
                    undefined[name] += 1
                else:
                    samples.append(right_value - left_value)
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
        intervals[metric] = {
            "method": "paired repository-cluster bootstrap percentile interval",
            "supported": all(item["decision"] != "unsupported" for item in measures.values()),
            "measures": measures,
        }
    return {
        "schema_version": 1,
        "method": "paired repository-cluster bootstrap percentile interval",
        "samples": SAMPLES,
        "seed": seed,
        "pairing": "same selected repository/PR identities and truth record hashes",
        "metrics": intervals,
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
