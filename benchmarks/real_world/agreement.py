#!/usr/bin/env python3
"""Report pre-adjudication agreement between two independent review files."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import median
from typing import Any


def load(path: Path) -> dict[tuple[str, int], dict[str, Any]]:
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return {(record["repository"], int(record["pr"])): record for record in records}


def endpoints(record: dict[str, Any]) -> set[str]:
    return {entrypoint["id"] for entrypoint in record.get("affected_entrypoints", [])}


def summarize(keys: list[tuple[str, int]], a: dict, b: dict) -> dict[str, Any]:
    jaccards: list[float] = []
    exact = shared = a_only = b_only = 0
    for key in keys:
        a_set, b_set = endpoints(a[key]), endpoints(b[key])
        union = a_set | b_set
        intersection = a_set & b_set
        exact += a_set == b_set
        shared += len(intersection)
        a_only += len(a_set - b_set)
        b_only += len(b_set - a_set)
        jaccards.append(len(intersection) / len(union) if union else 1.0)
    denominator = shared + a_only + b_only
    return {
        "prs": len(keys),
        "exact_endpoint_set_matches": exact,
        "exact_endpoint_set_match_rate": exact / len(keys) if keys else 0.0,
        "mean_per_pr_exact_id_jaccard": sum(jaccards) / len(jaccards) if jaccards else 0.0,
        "median_per_pr_exact_id_jaccard": median(jaccards) if jaccards else 0.0,
        "per_entrypoint_exact_id_agreement": {
            "shared": shared,
            "review_a_only": a_only,
            "review_b_only": b_only,
            "positive_jaccard": shared / denominator if denominator else 1.0,
        },
        "status_matches": sum(a[key]["status"] == b[key]["status"] for key in keys),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("review_a", type=Path)
    parser.add_argument("review_b", type=Path)
    args = parser.parse_args()
    a, b = load(args.review_a), load(args.review_b)
    if set(a) != set(b):
        raise ValueError("Review files do not contain identical PR keys")
    keys = sorted(a)
    repositories = sorted({repository for repository, _ in keys})
    result = {
        "method": "Raw entrypoint IDs before semantic alias adjudication; empty/empty PRs have Jaccard 1.0.",
        "overall": summarize(keys, a, b),
        "repositories": {
            repository: summarize([key for key in keys if key[0] == repository], a, b)
            for repository in repositories
        },
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
