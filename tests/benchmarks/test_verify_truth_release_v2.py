from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from benchmarks.real_world.ground_truth_v2 import GroundTruthError
from benchmarks.real_world.ground_truth_v2.schema import artifact_sha256, canonical_json
from benchmarks.real_world.ground_truth_v2.store import (
    import_adjudications,
    import_reviews,
    initialize_database,
    release,
)
from benchmarks.real_world.verify_truth_release_v2 import verify_release
from tests.benchmarks.ground_truth_helpers import (
    adjudication,
    corpus,
    review,
    validator_factory,
)


def _publication() -> bytes:
    return canonical_json(
        {
            "schema_version": 1,
            "artifact_type": "ground_truth_publication_review",
            "release_id": "release-1",
            "reviewer": {"kind": "human", "name": "publisher", "version": "1"},
            "reviewed_at": "2025-01-02T00:00:00Z",
            "secrets_reviewed": True,
            "pii_reviewed": True,
            "security_findings_reviewed": True,
            "scanner_findings_disposition": "none found",
        }
    )


def _release(tmp_path: Path) -> Path:
    db = tmp_path / "truth.sqlite"
    initialize_database(db, corpus(), allow_synthetic=True)
    a, b = review("A"), review("B")
    import_reviews(db, [a, b], validator_factory=validator_factory)
    import_adjudications(
        db,
        [adjudication(artifact_sha256(a), artifact_sha256(b))],
        imported_at="2025-01-02T01:00:00Z",
    )
    release(
        db,
        tmp_path / "published",
        _publication(),
        release_id="release-1",
        created_at="2025-01-03T00:00:00Z",
    )
    return tmp_path / "published" / "release-1"


def _reseal(root: Path, manifest: dict[str, object]) -> None:
    files = manifest["files"]
    assert isinstance(files, dict)
    for name, metadata in files.items():
        content = (root / name).read_bytes()
        assert isinstance(metadata, dict)
        metadata["bytes"] = len(content)
        metadata["rows"] = content.count(b"\n")
        metadata["sha256"] = "sha256:" + hashlib.sha256(content).hexdigest()
    _resign(root, manifest)


def _resign(root: Path, manifest: dict[str, object]) -> None:
    payload = {key: value for key, value in manifest.items() if key != "content_root"}
    manifest["content_root"] = "sha256:" + hashlib.sha256(
        b"ground-truth-release-manifest-v2\0" + canonical_json(payload)
    ).hexdigest()
    (root / "manifest.json").write_bytes(canonical_json(manifest))


def test_verify_release_checks_manifest_and_files(tmp_path: Path) -> None:
    root = _release(tmp_path)
    result = verify_release(root)
    assert result["selected_prs"] == 1
    assert result["terminal_counts"]["positive"] == 1
    assert result["truth_rows_verified"] == 1


def test_verify_release_rejects_tampered_declared_file(tmp_path: Path) -> None:
    root = _release(tmp_path)
    with (root / "broad-truth.jsonl").open("ab") as handle:
        handle.write(b" ")
    with pytest.raises(GroundTruthError, match="metadata mismatch"):
        verify_release(root)


def test_verify_release_rejects_manifest_root_tampering(tmp_path: Path) -> None:
    root = _release(tmp_path)
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["selected_prs"] = 2
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(GroundTruthError, match="content root mismatch"):
        verify_release(root)


def test_rejects_duplicate_manifest_and_truth_keys(tmp_path: Path) -> None:
    root = _release(tmp_path)
    manifest_raw = (root / "manifest.json").read_text()
    duplicate_key_manifest = manifest_raw.replace(
        '"schema_version":1', '"schema_version":1,"schema_version":1'
    )
    (root / "manifest.json").write_text(duplicate_key_manifest)
    with pytest.raises(GroundTruthError):
        verify_release(root)

    root = _release(tmp_path / "second")
    truth = (root / "broad-truth.jsonl").read_text().strip()
    row = json.loads(truth)
    (root / "broad-truth.jsonl").write_text(truth[:-1] + ',"pr":' + str(row["pr"]) + "}\n")
    manifest = json.loads((root / "manifest.json").read_text())
    _reseal(root, manifest)
    with pytest.raises(GroundTruthError, match="duplicate JSON object key"):
        verify_release(root)


@pytest.mark.parametrize("field,value", [("bytes", True), ("rows", True)])
def test_rejects_boolean_file_metadata(tmp_path: Path, field: str, value: object) -> None:
    root = _release(tmp_path)
    manifest = json.loads((root / "manifest.json").read_text())
    _reseal(root, manifest)
    manifest["files"]["broad-truth.jsonl"][field] = value
    _resign(root, manifest)
    with pytest.raises(GroundTruthError, match="metadata mismatch"):
        verify_release(root)


@pytest.mark.parametrize("terminal,status", [([], "positive"), ("positive", [])])
def test_malformed_truth_scalars_fail_closed(
    tmp_path: Path, terminal: object, status: object
) -> None:
    root = _release(tmp_path)
    row = json.loads((root / "broad-truth.jsonl").read_text())
    row["terminal_status"] = terminal
    row["status"] = status
    (root / "broad-truth.jsonl").write_bytes(canonical_json(row) + b"\n")
    manifest = json.loads((root / "manifest.json").read_text())
    _reseal(root, manifest)
    with pytest.raises(GroundTruthError, match="invalid terminal truth row"):
        verify_release(root)


@pytest.mark.parametrize(
    "entrypoints",
    [None, "not-a-list", [{"id": ""}]],
    ids=["missing", "wrong-type", "malformed-item"],
)
def test_self_consistent_release_rejects_invalid_truth_entrypoints(
    tmp_path: Path, entrypoints: object
) -> None:
    root = _release(tmp_path)
    row = json.loads((root / "broad-truth.jsonl").read_text())
    if entrypoints is None:
        row.pop("affected_entrypoints", None)
    else:
        row["affected_entrypoints"] = entrypoints
    (root / "broad-truth.jsonl").write_bytes(canonical_json(row))
    manifest = json.loads((root / "manifest.json").read_text())
    _reseal(root, manifest)
    with pytest.raises(GroundTruthError, match="invalid broad-truth record"):
        verify_release(root)


def test_expected_content_root_and_symlink_aliases(tmp_path: Path) -> None:
    root = _release(tmp_path)
    with pytest.raises(GroundTruthError, match="trusted expected root"):
        verify_release(root, expected_content_root="sha256:" + "0" * 64)
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(GroundTruthError, match="symlinks"):
        verify_release(alias)


def test_duplicate_truth_identity_and_distinct_unknown_counts(tmp_path: Path) -> None:
    root = _release(tmp_path)
    first = json.loads((root / "broad-truth.jsonl").read_text())
    duplicate = dict(first)
    (root / "broad-truth.jsonl").write_bytes(
        canonical_json(first).rstrip(b"\n")
        + b"\n"
        + canonical_json(duplicate).rstrip(b"\n")
        + b"\n"
    )
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["selected_prs"] = 2
    manifest["terminal_counts"] = {
        "positive": 2,
        "negative_control": 0,
        "unknown": 0,
        "not_evaluable": 0,
    }
    _reseal(root, manifest)
    with pytest.raises(GroundTruthError, match="duplicate broad-truth record"):
        verify_release(root)

    first["pr"] = 1
    first["terminal_status"] = "unknown"
    first["status"] = "unknown"
    second = dict(first, pr=2, terminal_status="not_evaluable", status="not_evaluable")
    (root / "broad-truth.jsonl").write_bytes(
        canonical_json(first).rstrip(b"\n")
        + b"\n"
        + canonical_json(second).rstrip(b"\n")
        + b"\n"
    )
    manifest["terminal_counts"] = {
        "positive": 0,
        "negative_control": 0,
        "unknown": 1,
        "not_evaluable": 1,
    }
    _reseal(root, manifest)
    result = verify_release(root)
    assert result["terminal_counts"]["unknown"] == 1
    assert result["terminal_counts"]["not_evaluable"] == 1
