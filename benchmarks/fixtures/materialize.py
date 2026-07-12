#!/usr/bin/env python3
"""Materialize controlled benchmark cases into before/after directory trees."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent


def validate_case(case: dict[str, Any]) -> None:
    required = {"id", "language", "framework", "before", "after", "expected"}
    missing = required - set(case)
    if missing:
        raise ValueError(f"{case.get('id', '<unknown>')}: missing {sorted(missing)}")
    if not set(case["before"]) <= set(case["after"]):
        raise ValueError(f"{case['id']}: deleted files must be represented explicitly")
    if not case["expected"].get("affected_entrypoints") and not case["expected"].get("orphans"):
        raise ValueError(f"{case['id']}: case has neither impact nor orphan expectation")


def write_tree(root: Path, files: dict[str, str]) -> None:
    for relative_path, content in files.items():
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, default=HERE / "cases.json")
    parser.add_argument("--output", type=Path, default=HERE / "generated")
    parser.add_argument("--clean", action="store_true")
    args = parser.parse_args()

    data = json.loads(args.cases.read_text(encoding="utf-8"))
    if args.clean and args.output.exists():
        shutil.rmtree(args.output)

    for case in data["cases"]:
        validate_case(case)
        root = args.output / case["id"]
        write_tree(root / "before", case["before"])
        write_tree(root / "after", case["after"])
        (root / "expected.json").write_text(
            json.dumps(case["expected"], indent=2) + "\n",
            encoding="utf-8",
        )
    print(f"Materialized {len(data['cases'])} cases in {args.output}")


if __name__ == "__main__":
    main()
