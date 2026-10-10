#!/usr/bin/env python3
"""Compare paired secure/runtime artifacts without treating runtime as truth."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.real_world._secure_publish import (
    SecurePathError,
    ensure_publishable,
    publish_exclusive_bytes,
)

from fastapi_endpoint_detector.analyzer.runtime_artifact_comparison import (
    ComparisonError,
    _validate,
    compare,
    compare_target_baseline,
)

__all__ = ["ComparisonError", "_validate", "compare", "compare_target_baseline", "main"]

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parents[1]
_FROZEN_FILES = (
    HERE / "corpus.json",
    HERE / "adjudicated.jsonl",
    HERE / "review-a.jsonl",
    HERE / "review-b.jsonl",
)
_FROZEN_ROOTS = (PROJECT_ROOT / "benchmarks" / "results",)


def _write_output(
    path: Path,
    result: dict[str, Any],
    *,
    input_paths: tuple[Path, ...],
) -> None:
    forbidden_files = (*_FROZEN_FILES, *input_paths)
    try:
        absolute = path.expanduser().absolute()
        if absolute in {item.expanduser().absolute() for item in forbidden_files} or any(
            absolute == root.expanduser().absolute()
            or absolute.is_relative_to(root.expanduser().absolute())
            for root in _FROZEN_ROOTS
        ):
            raise SecurePathError(f"refusing to target frozen benchmark artifact: {path}")
        ensure_publishable(
            path,
            forbidden_files=forbidden_files,
            forbidden_roots=_FROZEN_ROOTS,
        )
        content = (json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
            "utf-8"
        )
        publish_exclusive_bytes(
            path,
            content,
            forbidden_files=forbidden_files,
            forbidden_roots=_FROZEN_ROOTS,
        )
    except (SecurePathError, TypeError, ValueError) as error:
        raise ComparisonError(f"could not write {path}: {error}") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secure", type=Path)
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--secure-target", type=Path)
    parser.add_argument("--runtime-target", type=Path)
    parser.add_argument("--secure-baseline", type=Path)
    parser.add_argument("--runtime-baseline", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    legacy = (args.secure, args.runtime)
    matrix = (
        args.secure_target,
        args.runtime_target,
        args.secure_baseline,
        args.runtime_baseline,
    )
    input_paths: tuple[Path, ...]
    try:
        if all(value is not None for value in legacy) and all(value is None for value in matrix):
            result = compare(args.secure, args.runtime)
            input_paths = (args.secure, args.runtime)
        elif all(value is None for value in legacy) and all(value is not None for value in matrix):
            result = compare_target_baseline(
                secure_target_path=args.secure_target,
                runtime_target_path=args.runtime_target,
                secure_baseline_path=args.secure_baseline,
                runtime_baseline_path=args.runtime_baseline,
            )
            input_paths = matrix
        else:
            parser.error(
                "pass either --secure/--runtime or all four target/baseline artifact arguments"
            )
        _write_output(args.output, result, input_paths=input_paths)
    except ComparisonError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
