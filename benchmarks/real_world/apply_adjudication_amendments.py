#!/usr/bin/env python3
"""Apply evidence-backed post-adjudication additions without replacing raw reviews."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--adjudicated", type=Path, required=True)
    parser.add_argument("--amendments", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    records = read_jsonl(args.adjudicated)
    amendments = {
        (item["repository"], int(item["pr"])): item for item in read_jsonl(args.amendments)
    }
    seen_amendments: set[tuple[str, int]] = set()
    for record in records:
        key = (record["repository"], int(record["pr"]))
        amendment = amendments.get(key)
        if amendment is None:
            continue
        seen_amendments.add(key)
        entrypoints = record.setdefault("affected_entrypoints", [])
        existing = {item["id"] for item in entrypoints}
        additions = [
            item for item in amendment["affected_entrypoints"] if item["id"] not in existing
        ]
        entrypoints.extend(additions)
        if additions:
            audit = record.setdefault("post_adjudication_audits", [])
            audit.append(
                {
                    "reason": amendment["reason"],
                    "added_entrypoints": len(additions),
                    "source": str(args.amendments),
                }
            )
    missing = set(amendments) - seen_amendments
    if missing:
        raise SystemExit(f"amendments reference absent adjudication records: {sorted(missing)}")
    args.output.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records))


if __name__ == "__main__":
    main()
