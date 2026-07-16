from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path
from benchmarks.real_world.ground_truth_v2 import GroundTruthError
from benchmarks.real_world.ground_truth_v2.schema import (
    PublicationReviewV1,
    artifact_sha256,
    parse_artifact,
)
from benchmarks.real_world.ground_truth_v2.store import (
    import_adjudications,
    import_reviews,
    initialize_database,
    release,
)
from tests.benchmarks.ground_truth_helpers import adjudication, corpus, review, validator_factory


def publication(*, affirmed: bool = True) -> bytes:
    payload = {
        "schema_version": 1,
        "artifact_type": "ground_truth_publication_review",
        "release_id": "release-1",
        "reviewer": {"kind": "human", "name": "publisher", "version": "1"},
        "reviewed_at": "2025-01-02T00:00:00Z",
        "secrets_reviewed": affirmed,
        "pii_reviewed": True,
        "security_findings_reviewed": True,
        "scanner_findings_disposition": "No findings in bounded textual scan",
    }
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode()


def ready_database(path: Path) -> None:
    initialize_database(path, corpus(), allow_synthetic=True)
    a, b = review("A"), review("B")
    import_reviews(
        path, [a, b], validator_factory=validator_factory, imported_at="2025-01-01T01:00:00Z"
    )
    import_adjudications(
        path,
        [adjudication(artifact_sha256(a), artifact_sha256(b))],
        imported_at="2025-01-01T02:00:00Z",
    )


def test_publication_gate_and_deterministic_no_clobber_release(tmp_path: Path) -> None:
    with pytest.raises(GroundTruthError, match="affirmative"):
        parse_artifact(publication(affirmed=False), PublicationReviewV1)
    first_db, second_db = tmp_path / "a.sqlite", tmp_path / "b.sqlite"
    ready_database(first_db)
    ready_database(second_db)
    first = release(
        first_db,
        tmp_path / "one",
        publication(),
        release_id="release-1",
        created_at="2025-01-03T00:00:00Z",
    )
    second = release(
        second_db,
        tmp_path / "two",
        publication(),
        release_id="release-1",
        created_at="2025-01-03T00:00:00Z",
    )
    assert first == second
    first_root = tmp_path / "one" / "release-1"
    second_root = tmp_path / "two" / "release-1"
    first_files = {
        str(path.relative_to(first_root)): path.read_bytes()
        for path in first_root.rglob("*")
        if path.is_file()
    }
    second_files = {
        str(path.relative_to(second_root)): path.read_bytes()
        for path in second_root.rglob("*")
        if path.is_file()
    }
    assert first_files == second_files
    broad = json.loads(first_files["broad-truth.jsonl"])
    assert broad["terminal_status"] == "positive"
    assert first["terminal_counts"] == {
        "positive": 1,
        "negative_control": 0,
        "unknown": 0,
        "not_evaluable": 0,
    }
    with pytest.raises(GroundTruthError, match="overwrite"):
        release(
            first_db,
            tmp_path / "one",
            publication(),
            release_id="release-1",
            created_at="2025-01-03T00:00:00Z",
        )
