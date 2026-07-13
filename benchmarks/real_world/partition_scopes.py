#!/usr/bin/env python3
"""Materialize auditable membership sidecars for benchmark scopes."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.real_world.benchmark_scope import entrypoint_in_scope

SCOPE_VERSION = "fastapi-adapter-v1"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    records = read_jsonl(args.input)
    source_hash = hashlib.sha256(args.input.read_bytes()).hexdigest()
    summary: dict[str, Any] = {
        "source": str(args.input),
        "source_sha256": source_hash,
        "classifier": SCOPE_VERSION,
        "scopes": {},
    }
    for scope, directory in (
        ("fastapi", "fastapi_adapter_v1"),
        ("out-of-scope", "out_of_scope"),
    ):
        membership: list[dict[str, Any]] = []
        kinds: Counter[str] = Counter()
        positive_prs: set[tuple[str, int]] = set()
        for record in records:
            if record.get("status") != "adjudicated":
                continue
            for item in record.get("affected_entrypoints", []):
                if not entrypoint_in_scope(item, scope):
                    continue
                positive_prs.add((record["repository"], int(record["pr"])))
                kinds[str(item.get("kind", "unknown")).lower()] += 1
                membership.append(
                    {
                        "repository": record["repository"],
                        "pr": int(record["pr"]),
                        "id": item["id"],
                        "kind": item.get("kind", "unknown"),
                        "reason": (
                            "finite FastAPI HTTP/WebSocket output contract"
                            if scope == "fastapi"
                            else "not representable by FastAPI adapter v1"
                        ),
                    }
                )
        scope_summary = {
            "entrypoints": len(membership),
            "truth_positive_prs": len(positive_prs),
            "negative_control_prs": 58 - len(positive_prs),
            "by_adjudicated_kind": dict(sorted(kinds.items())),
        }
        destination = args.output / directory
        write_jsonl(destination / "membership.jsonl", membership)
        (destination / "manifest.json").write_text(
            json.dumps(
                {
                    "scope": SCOPE_VERSION if scope == "fastapi" else "out-of-scope-v1",
                    "source": str(args.input),
                    "source_sha256": source_hash,
                    **scope_summary,
                },
                indent=2,
            )
            + "\n"
        )
        summary["scopes"][scope] = scope_summary
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    main()
