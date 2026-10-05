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
from typing import Any

SAMPLES = 10_000
THRESHOLD = 0.02
CONFIDENCE = 0.95


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("comparison_evidence"), dict):
        raise ValueError(f"{path}: missing comparison_evidence; regenerate with evaluate.py")
    evidence = value["comparison_evidence"]
    if evidence.get("schema_version") != 1:
        raise ValueError(f"{path}: unsupported comparison evidence schema")
    return value


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


def _precision(rows: list[dict[str, Any]], metric: str) -> float | None:
    tp = sum(row[metric]["tp"] for row in rows)
    fp = sum(row[metric]["fp"] for row in rows)
    return tp / (tp + fp) if tp + fp else None


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
            or pr < 0
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
    left, right = baseline["comparison_evidence"], candidate["comparison_evidence"]
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
    intervals: dict[str, dict[str, Any]] = {}
    for metric in ("raw", "normalized"):
        base_precision = _precision([a[key] for key in keys], metric)
        candidate_precision = _precision([b[key] for key in keys], metric)
        if base_precision is None or candidate_precision is None:
            intervals[metric] = {"supported": False, "reason": "undefined aggregate precision"}
            continue
        deltas: list[float] = []
        undefined = 0
        for _ in range(SAMPLES):
            sample_keys = [keys[rng.randrange(len(keys))] for _ in keys]
            baseline_precision = _precision([a[key] for key in sample_keys], metric)
            candidate_sample_precision = _precision([b[key] for key in sample_keys], metric)
            if baseline_precision is None or candidate_sample_precision is None:
                undefined += 1
                continue
            deltas.append(candidate_sample_precision - baseline_precision)
        if undefined:
            intervals[metric] = {
                "supported": False,
                "reason": "bootstrap samples contained undefined precision",
                "undefined_samples": undefined,
            }
            continue
        deltas.sort()
        # Conservative nearest-rank two-sided percentile interval.
        lower = deltas[max(0, int((1 - CONFIDENCE) / 2 * SAMPLES) - 1)]
        upper = deltas[min(SAMPLES - 1, int((1 + CONFIDENCE) / 2 * SAMPLES) - 1)]
        passed = lower >= -THRESHOLD or math.isclose(lower, -THRESHOLD, abs_tol=1e-12)
        intervals[metric] = {
            "supported": True,
            "baseline_precision": base_precision,
            "candidate_precision": candidate_precision,
            "delta": candidate_precision - base_precision,
            "confidence": CONFIDENCE,
            "interval": [lower, upper],
            "threshold": -THRESHOLD,
            "decision": "pass" if passed else "fail",
            "lower_bound_equal_to_threshold_passes": True,
        }
    return {
        "schema_version": 1,
        "method": "paired PR bootstrap percentile interval",
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
