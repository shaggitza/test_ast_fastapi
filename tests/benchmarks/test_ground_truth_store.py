from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path
from benchmarks.real_world.ground_truth_v2 import GroundTruthError
from benchmarks.real_world.ground_truth_v2.schema import artifact_sha256
from benchmarks.real_world.ground_truth_v2.store import (
    import_adjudications,
    import_reviews,
    initialize_database,
    validate_database,
)
from tests.benchmarks.ground_truth_helpers import adjudication, corpus, review, validator_factory


def test_synthetic_opt_in_and_atomic_complete_review_import(tmp_path: Path) -> None:
    database = tmp_path / "truth.sqlite"
    with pytest.raises(GroundTruthError, match="test-only opt-in"):
        initialize_database(database, corpus())
    initialize_database(database, corpus(), allow_synthetic=True)
    with pytest.raises(GroundTruthError, match="exactly one A and B"):
        import_reviews(database, [review("A")], validator_factory=validator_factory)
    assert validate_database(database)["reviewer_runs"] == 0
    import_reviews(database, [review("B"), review("A")], validator_factory=validator_factory)
    assert validate_database(database) == {
        "selected_prs": 1,
        "reviewer_runs": 2,
        "adjudications": 0,
        "releases": 0,
    }


def test_wrong_snapshot_duplicate_and_partial_fail_without_rows(tmp_path: Path) -> None:
    database = tmp_path / "truth.sqlite"
    initialize_database(database, corpus(), allow_synthetic=True)
    wrong = review("B").replace(b'"target_commit":"' + b"2" * 40, b'"target_commit":"' + b"8" * 40)
    with pytest.raises(GroundTruthError, match="snapshot"):
        import_reviews(database, [review("A"), wrong], validator_factory=validator_factory)
    assert validate_database(database)["reviewer_runs"] == 0
    with pytest.raises(GroundTruthError, match="exactly one A and B"):
        import_reviews(database, [review("A"), review("A")], validator_factory=validator_factory)


def test_decision_provenance_append_only_and_blob_validation(tmp_path: Path) -> None:
    database = tmp_path / "truth.sqlite"
    initialize_database(database, corpus(), allow_synthetic=True)
    a, b = review("A"), review("B")
    import_reviews(database, [a, b], validator_factory=validator_factory)
    raw = adjudication(artifact_sha256(a), artifact_sha256(b))
    import_adjudications(database, [raw])
    assert validate_database(database)["adjudications"] == 1
    connection = sqlite3.connect(database)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute("UPDATE reviewer_run SET reviewer_name='changed'")
    connection.close()


def test_adjudication_requires_exact_frozen_hashes_and_rolls_back(tmp_path: Path) -> None:
    database = tmp_path / "truth.sqlite"
    initialize_database(database, corpus(), allow_synthetic=True)
    a, b = review("A"), review("B")
    import_reviews(database, [a, b], validator_factory=validator_factory)
    raw = adjudication("sha256:" + "0" * 64, artifact_sha256(b))
    with pytest.raises(GroundTruthError, match="exact frozen"):
        import_adjudications(database, [raw])
    assert validate_database(database)["adjudications"] == 0
