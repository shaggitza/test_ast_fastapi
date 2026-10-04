#!/usr/bin/env python3
"""Read-only integrity gate for canonical ground-truth v2 release directories."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.real_world.ground_truth_v2 import GroundTruthError
from benchmarks.real_world.ground_truth_v2.schema import canonical_json

TERMINAL = {"positive", "negative_control", "unknown", "not_evaluable"}
COUNTS = set(TERMINAL)


def _fail(message: str) -> None:
    raise GroundTruthError(message)


def verify_release(directory: Path) -> dict[str, Any]:  # noqa: PLR0912, PLR0915
    """Validate release self-hash, every declared file, and terminal denominators."""
    root = directory.resolve(strict=True)
    if not root.is_dir() or directory.is_symlink():
        _fail("release path must be a real directory")
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        _fail("release manifest is missing or not a regular file")
    raw_manifest = manifest_path.read_bytes()
    try:
        manifest = json.loads(raw_manifest)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GroundTruthError("release manifest is invalid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        _fail("expected ground-truth release schema version 1")
    if manifest.get("content_root_algorithm") != "sha256-canonical-manifest-payload-v2":
        _fail("unsupported release content-root algorithm")
    root_hash = manifest.get("content_root")
    payload = {key: value for key, value in manifest.items() if key != "content_root"}
    expected_root = "sha256:" + hashlib.sha256(
        b"ground-truth-release-manifest-v2\0" + canonical_json(payload)
    ).hexdigest()
    if root_hash != expected_root:
        _fail("release manifest content root mismatch")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        _fail("release manifest file inventory is missing")
    expected_names = {"manifest.json"} | set(files)
    observed_names: set[str] = set()
    for name, metadata in files.items():
        relative = PurePosixPath(name) if isinstance(name, str) else None
        if (
            relative is None
            or relative.is_absolute()
            or ".." in relative.parts
            or not relative.parts
            or not isinstance(metadata, dict)
        ):
            _fail("release manifest contains an unsafe file entry")
        path = root.joinpath(*relative.parts)
        try:
            resolved = path.resolve(strict=True)
        except FileNotFoundError as exc:
            raise GroundTruthError(f"release file is missing: {name}") from exc
        if root not in resolved.parents or path.is_symlink() or not resolved.is_file():
            _fail(f"release file is not a contained regular file: {name}")
        content = resolved.read_bytes()
        if (
            metadata.get("bytes") != len(content)
            or metadata.get("sha256") != "sha256:" + hashlib.sha256(content).hexdigest()
            or metadata.get("rows") != content.count(b"\n")
        ):
            _fail(f"release file metadata mismatch: {name}")
        observed_names.add(name)
    actual_names = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual_names != expected_names:
        _fail("release directory has undeclared or missing files")

    counts = manifest.get("terminal_counts")
    selected = manifest.get("selected_prs")
    if (
        not isinstance(counts, dict)
        or set(counts) != COUNTS
        or any(type(value) is not int or value < 0 for value in counts.values())
        or type(selected) is not int
        or selected < 1
        or sum(counts.values()) != selected
    ):
        _fail("release terminal denominators are incomplete")
    truth_path = root / "broad-truth.jsonl"
    records: dict[tuple[str, int], str] = {}
    for line_number, line in enumerate(truth_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            _fail(f"blank broad-truth row at line {line_number}")
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise GroundTruthError(f"invalid broad-truth JSON at line {line_number}") from exc
        if not isinstance(row, dict):
            _fail(f"malformed broad-truth row at line {line_number}")
        repo, pr, status, terminal = (
            row.get("repository"), row.get("pr"), row.get("status"), row.get("terminal_status")
        )
        if (
            not isinstance(repo, str)
            or not repo
            or type(pr) is not int
            or pr < 1
            or terminal not in TERMINAL
            or status
            != ("adjudicated" if terminal in {"positive", "negative_control"} else terminal)
        ):
            _fail(f"invalid terminal truth row at line {line_number}")
        key = (repo, pr)
        if key in records:
            _fail(f"duplicate broad-truth record: {key}")
        records[key] = terminal
    actual_counts = {terminal: list(records.values()).count(terminal) for terminal in TERMINAL}
    if len(records) != selected or actual_counts != counts:
        _fail("broad-truth rows do not match selected and terminal denominators")
    return {
        "release_id": manifest.get("release_id"),
        "content_root": root_hash,
        "selected_prs": selected,
        "terminal_counts": counts,
        "files_verified": len(files),
        "truth_rows_verified": len(records),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release", type=Path, help="directory containing manifest.json")
    args = parser.parse_args()
    print(json.dumps(verify_release(args.release), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
