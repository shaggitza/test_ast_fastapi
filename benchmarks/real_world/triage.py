#!/usr/bin/env python3
"""Create a conservative manual-review queue for the historical PR corpus.

Triage never assigns impact ground truth. It only prioritizes reviews and keeps
negative-looking changes visible, since configuration or frontend changes can
still alter externally observable behavior.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PYTHON_SUFFIXES = {".py", ".pyi"}
CONTRACT_NAMES = {
    "openapi.json",
    "openapi.yaml",
    "openapi.yml",
    "schema.graphql",
    "buf.yaml",
    "buf.yml",
}
RUNTIME_CONFIG_SUFFIXES = {".toml", ".yaml", ".yml", ".json", ".env", ".example"}


def suffix(path: str) -> str:
    return Path(path).suffix.lower()


def classify(entry: dict[str, Any]) -> tuple[str, list[str]]:
    paths = [item["path"] for item in entry["files"]]
    suffixes = {suffix(path) for path in paths}
    lines = entry["additions"] + entry["deletions"]
    reasons: list[str] = []

    if entry["changedFiles"] >= 100 or lines >= 50_000:
        reasons.append("aggregate_or_oversized_change")
        return "manual_special_handling", reasons
    if any(suffix(path) in PYTHON_SUFFIXES for path in paths):
        reasons.append("python_source_changed")
        return "high", reasons
    if any(Path(path).name.lower() in CONTRACT_NAMES for path in paths):
        reasons.append("public_contract_changed")
        return "high", reasons
    if suffixes & RUNTIME_CONFIG_SUFFIXES:
        reasons.append("runtime_or_build_configuration_possible")
        return "medium", reasons
    reasons.append("no_python_or_known_contract_file")
    return "low", reasons


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, default=HERE / "corpus.json")
    parser.add_argument("--output", type=Path, default=HERE / "review-queue.json")
    args = parser.parse_args()

    corpus = json.loads(args.corpus.read_text(encoding="utf-8"))
    queue = []
    counts: dict[str, int] = {}
    for entry in corpus["entries"]:
        priority, reasons = classify(entry)
        counts[priority] = counts.get(priority, 0) + 1
        queue.append(
            {
                "repository": entry["repository"],
                "pr": entry["number"],
                "title": entry["title"],
                "url": entry["url"],
                "priority": priority,
                "reasons": reasons,
                "changed_files": entry["changedFiles"],
                "changed_lines": entry["additions"] + entry["deletions"],
                "review_status": "pending",
            }
        )

    output = {
        "schema_version": 1,
        "warning": "Priority is not impact ground truth; every PR requires review.",
        "counts": counts,
        "entries": sorted(
            queue,
            key=lambda item: (
                {"high": 0, "medium": 1, "low": 2, "manual_special_handling": 3}[
                    item["priority"]
                ],
                item["repository"],
                -item["pr"],
            ),
        ),
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(counts, sort_keys=True))


if __name__ == "__main__":
    main()
