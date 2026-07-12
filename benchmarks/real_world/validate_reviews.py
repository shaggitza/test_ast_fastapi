#!/usr/bin/env python3
"""Validate review JSONL structure and membership in the frozen corpus."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REQUIRED = {
    "repository",
    "pr",
    "status",
    "reviewer",
    "changed_symbols",
    "affected_entrypoints",
    "affected_tests",
    "contract_changes",
    "cross_repository_consumers",
    "orphans",
    "unknowns",
    "notes",
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_number}: {error}") from error
    return records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("reviews", type=Path)
    parser.add_argument("--corpus", type=Path, default=HERE / "corpus.json")
    args = parser.parse_args()

    corpus = json.loads(args.corpus.read_text(encoding="utf-8"))
    corpus_keys = {(entry["repository"], entry["number"]) for entry in corpus["entries"]}
    records = load_jsonl(args.reviews)
    seen: set[tuple[str, int]] = set()
    for record in records:
        missing = REQUIRED - set(record)
        if missing:
            raise ValueError(f"PR record missing fields: {sorted(missing)}")
        record_key = record["repository"], int(record["pr"])
        if record_key not in corpus_keys:
            raise ValueError(f"Review is not in frozen corpus: {record_key}")
        if record_key in seen:
            raise ValueError(f"Duplicate review: {record_key}")
        seen.add(record_key)
        for endpoint in record["affected_entrypoints"]:
            if not {"id", "kind", "confidence", "evidence"} <= set(endpoint):
                raise ValueError(f"Incomplete endpoint evidence: {record_key}")
            if not endpoint["evidence"]:
                raise ValueError(f"Endpoint has no evidence: {record_key} {endpoint['id']}")

    print(
        json.dumps(
            {
                "valid_records": len(records),
                "corpus_records": len(corpus_keys),
                "remaining": len(corpus_keys) - len(records),
            }
        )
    )


if __name__ == "__main__":
    main()
