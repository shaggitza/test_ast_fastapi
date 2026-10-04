from __future__ import annotations

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
