from __future__ import annotations

import json
import multiprocessing
import sqlite3
from pathlib import Path
from typing import Any, cast

import pytest
from benchmarks.real_world.ground_truth_v2 import GroundTruthError
from benchmarks.real_world.ground_truth_v2.schema import (
    CorpusDefinition,
    CorpusRepository,
    ReviewArtifactV1,
    artifact_sha256,
    parse_artifact,
)
from benchmarks.real_world.ground_truth_v2.store import (
    import_adjudications,
    import_reviews,
    initialize_database,
    release,
    validate_database,
)
from tests.benchmarks.ground_truth_helpers import (
    TREE1,
    TREE2,
    H,
    adjudication,
    corpus,
    review,
    validator_factory,
)
from tests.benchmarks.test_ground_truth_release import publication, ready_database


def _json(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw)
    assert isinstance(value, dict)
    return value


def _raw(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode()


def _multi_corpus() -> CorpusDefinition:
    payload = corpus().model_dump(mode="json")
    first = payload["repositories"][0]["pull_requests"][0]
    second = dict(first)
    second["number"] = 2
    second["rank"] = 2
    second["merged_at"] = "2025-01-02T00:00:00Z"
    second["remote_diff"] = dict(first["remote_diff"])
    second["remote_diff"]["final_url"] = "https://github.com/owner/repo/pull/2.diff"
    payload["repositories"][0]["pull_requests"].append(second)
    return CorpusDefinition.model_validate(payload)


def _review_for(pr: int, lane: str, terminal: str = "positive") -> bytes:
    payload = _json(review(lane))
    payload["pr"] = pr
    if terminal == "negative_control":
        payload["terminal_recommendation"] = terminal
        payload["claims"] = []
        payload["unknowns"] = []
        payload["negative_assessment"] = {
            "changed_symbol_census_complete": True,
            "searched_entrypoint_families": ["http", "task"],
            "limitations": ["offline pinned snapshots only"],
        }
    elif terminal in {"unknown", "not_evaluable"}:
        payload["terminal_recommendation"] = terminal
        payload["changed_symbols"] = []
        payload["claims"] = []
        payload["unknowns"] = [
            {
                "unknown_id": "u1",
                "category": "dynamic",
                "description": "registration cannot be resolved statically",
                "evidence_limit": "offline source only",
            }
        ]
        payload["negative_assessment"] = None
    return _raw(payload)


def _adjudication_for(pr: int, a: bytes, b: bytes, terminal: str = "positive") -> bytes:
    payload = _json(adjudication(artifact_sha256(a), artifact_sha256(b)))
    payload["pr"] = pr
    if terminal == "negative_control":
        payload["terminal_status"] = terminal
        payload["decisions"] = [
            {
                "decision_id": "terminal-negative",
                "decision_kind": "terminal",
                "outcome": "exclude",
                "attribution": "both",
                "sources": [
                    {"lane": lane, "source_kind": kind, "source_id": None}
                    for lane in ("A", "B")
                    for kind in ("terminal", "negative_assessment")
                ],
                "canonical_entrypoint": None,
                "rationale": "both complete censuses found no entrypoint",
                "evidence": [],
            }
        ]
        payload["scope_memberships"] = []
        payload["unknowns"] = []
        payload["negative_assessment"] = {
            "changed_symbol_census_complete": True,
            "searched_entrypoint_families": ["http", "task"],
            "limitations": ["offline pinned snapshots only"],
        }
    elif terminal in {"unknown", "not_evaluable"}:
        payload["terminal_status"] = terminal
        payload["decisions"] = [
            {
                "decision_id": "terminal-unknown",
                "decision_kind": "unknown",
                "outcome": "exclude",
                "attribution": "both",
                "sources": [
                    {"lane": lane, "source_kind": kind, "source_id": source_id}
                    for lane in ("A", "B")
                    for kind, source_id in (("terminal", None), ("unknown", "u1"))
                ],
                "canonical_entrypoint": None,
                "rationale": "both reviews reached the same bounded uncertainty",
                "evidence": [],
            }
        ]
        payload["scope_memberships"] = []
        payload["unknowns"] = [
            {
                "unknown_id": "u-final",
                "category": "dynamic",
                "description": "registration cannot be resolved statically",
                "evidence_limit": "offline source only",
            }
        ]
        payload["negative_assessment"] = None
    return _raw(payload)


def _initialize_worker(path: str, start: Any, results: Any) -> None:
    start.wait()
    try:
        initialize_database(Path(path), corpus(), allow_synthetic=True)
    except Exception as exc:  # pragma: no cover - exercised in child process
        results.put(type(exc).__name__)
    else:
        results.put("ok")


def _release_worker(database: str, destination: str, start: Any, results: Any) -> None:
    start.wait()
    try:
        release(
            Path(database),
            Path(destination),
            publication(),
            release_id="release-1",
            created_at="2025-01-03T00:00:00Z",
        )
    except Exception as exc:  # pragma: no cover - exercised in child process
        results.put(type(exc).__name__)
    else:
        results.put("ok")


def _run_two_processes(target: Any, args: tuple[str, ...]) -> list[str]:
    context = multiprocessing.get_context("fork")
    start = context.Event()
    results = context.Queue()
    processes = [context.Process(target=target, args=(*args, start, results)) for _ in range(2)]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(20)
        if process.is_alive():
            process.kill()
            pytest.fail("concurrency worker exceeded bounded timeout")
        assert process.exitcode == 0
    return sorted(results.get(timeout=2) for _ in processes)


def test_production_initialization_authenticates_inside_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forged = corpus().model_copy(update={"source": "authenticated_v2_lock"})
    with pytest.raises(GroundTruthError, match="production initialization requires"):
        initialize_database(tmp_path / "forged.sqlite", forged)

    source = corpus().repositories[0].pull_requests[0]
    lock = {
        "id": "authenticated-corpus",
        "projects": [
            {
                "repository": "owner/repo",
                "status": "underfilled",
                "records": [
                    {
                        "pr": source.number,
                        "rank": source.rank,
                        "merged_at": "2025-01-01T00:00:00Z",
                        "base_sha": source.base_sha,
                        "head_sha": source.head_sha,
                        "merge_commit_sha": source.merge_commit_sha,
                        "baseline_sha": source.baseline.commit_sha,
                        "target_sha": source.target.commit_sha,
                        "baseline_rule": source.baseline.rule,
                        "target_rule": source.target.rule,
                        "diff_sha256": source.remote_diff.sha256,
                        "diff_bytes": source.remote_diff.byte_count,
                        "diff_final_url": source.remote_diff.final_url,
                        "diff_content_type": source.remote_diff.content_type,
                    }
                ],
            }
        ],
    }
    manifest = {"projects": [{"repository": "owner/repo", "partition": "fixture"}]}
    called: list[tuple[Path, Path, Path]] = []

    def authenticated(lock_path: Path, manifest_path: Path, checksums_path: Path) -> Any:
        called.append((lock_path, manifest_path, checksums_path))
        return lock, "sha256:" + "9" * 64

    monkeypatch.setattr(
        "benchmarks.real_world.ground_truth_v2.store.load_lock_authenticated", authenticated
    )
    monkeypatch.setattr(
        "benchmarks.real_world.ground_truth_v2.store.load_manifest", lambda _path: (manifest, H)
    )
    paths = tuple(tmp_path / name for name in ("lock.json", "manifest.json", "checksums.json"))
    initialize_database(
        tmp_path / "authenticated.sqlite",
        lock_path=paths[0],
        manifest_path=paths[1],
        checksums_path=paths[2],
        tree_resolver=lambda _repository, commit: TREE1 if commit == source.base_sha else TREE2,
    )
    assert called == [paths]


def test_frozen_real_repository_names_and_whitespace_validation() -> None:
    manifest = json.loads(
        Path("benchmarks/real_world/expansion/projects-50x50-v2.json").read_bytes()
    )
    names = [row["repository"] for row in manifest["projects"]]
    assert len(names) == 50
    for name in names:
        CorpusRepository.model_validate(
            {
                "full_name": name,
                "partition": "real-frozen-v2",
                "terminal_status": "unavailable",
                "pull_requests": [],
            }
        )
    for invalid in ("foo /bar", "foo/bar baz", "foo\t/bar"):
        with pytest.raises(ValueError):
            CorpusRepository.model_validate(
                {
                    "full_name": invalid,
                    "partition": "invalid",
                    "terminal_status": "unavailable",
                    "pull_requests": [],
                }
            )


def test_multi_pr_partial_adjudication_is_atomic(tmp_path: Path) -> None:
    database = tmp_path / "multi.sqlite"
    initialize_database(database, _multi_corpus(), allow_synthetic=True)
    reviews = [_review_for(pr, lane) for pr in (1, 2) for lane in ("A", "B")]
    import_reviews(database, reviews, validator_factory=validator_factory)
    a1, b1, a2, b2 = reviews
    first = _adjudication_for(1, a1, b1)
    second = _adjudication_for(2, a2, b2)
    with pytest.raises(GroundTruthError, match="exactly one artifact"):
        import_adjudications(database, [first])
    assert validate_database(database)["adjudications"] == 0
    import_adjudications(database, [second, first])
    assert validate_database(database)["adjudications"] == 2


def test_duplicate_entrypoint_and_source_reuse_fail_closed(tmp_path: Path) -> None:
    database = tmp_path / "duplicates.sqlite"
    initialize_database(database, corpus(), allow_synthetic=True)
    a, b = review("A"), review("B")
    import_reviews(database, [a, b], validator_factory=validator_factory)
    payload = _json(adjudication(artifact_sha256(a), artifact_sha256(b)))
    first = payload["decisions"][0]
    first["attribution"] = "A"
    first["sources"] = first["sources"][:2]
    second = json.loads(json.dumps(first))
    second["decision_id"] = "d2"
    second["attribution"] = "B"
    second["sources"] = [
        {"lane": "B", "source_kind": "claim", "source_id": "c1"},
        {"lane": "B", "source_kind": "terminal", "source_id": None},
    ]
    payload["decisions"].append(second)
    payload["scope_memberships"].append({**payload["scope_memberships"][0], "decision_id": "d2"})
    with pytest.raises(GroundTruthError, match="duplicate canonical entrypoint"):
        import_adjudications(database, [_raw(payload)])

    reused = _json(adjudication(artifact_sha256(a), artifact_sha256(b)))
    extra = {
        "decision_id": "d-terminal",
        "decision_kind": "terminal",
        "outcome": "exclude",
        "attribution": "A",
        "sources": [{"lane": "A", "source_kind": "terminal", "source_id": None}],
        "canonical_entrypoint": None,
        "rationale": "duplicate resolution must be rejected",
        "evidence": [],
    }
    reused["decisions"].append(extra)
    with pytest.raises(GroundTruthError, match="exactly once"):
        import_adjudications(database, [_raw(reused)])
    assert validate_database(database)["adjudications"] == 0


def test_schema_raw_projection_and_cross_pr_tamper_fail_closed(tmp_path: Path) -> None:
    database = tmp_path / "tamper.sqlite"
    initialize_database(database, _multi_corpus(), allow_synthetic=True)
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA foreign_keys=ON")
    pr_rows = connection.execute("SELECT pr_id FROM pull_request ORDER BY number").fetchall()
    second_snapshot = connection.execute(
        "SELECT snapshot_id FROM snapshot WHERE pr_id=? LIMIT 1", (pr_rows[1][0],)
    ).fetchone()[0]
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        connection.execute(
            "INSERT INTO evidence_location VALUES(?,?,?,?,?,?,?,?)",
            ("cross", pr_rows[0][0], second_snapshot, "a" * 40, "x.py", 1, 1, "x"),
        )
    connection.close()

    single = tmp_path / "projection.sqlite"
    initialize_database(single, corpus(), allow_synthetic=True)
    a, b = review("A"), review("B")
    import_reviews(single, [a, b], validator_factory=validator_factory)
    connection = sqlite3.connect(single)
    trigger_sql = connection.execute(
        "SELECT sql FROM sqlite_schema WHERE name='reviewer_run_no_update'"
    ).fetchone()[0]
    connection.execute("DROP TRIGGER reviewer_run_no_update")
    connection.execute("UPDATE reviewer_run SET reviewer_name='tampered' WHERE lane='A'")
    connection.execute(trigger_sql)
    connection.commit()
    connection.close()
    with pytest.raises(GroundTruthError, match="normalized metadata"):
        validate_database(single)


def test_initialization_and_release_concurrency_never_delete_winner(tmp_path: Path) -> None:
    database = tmp_path / "concurrent.sqlite"
    assert _run_two_processes(_initialize_worker, (str(database),)) == [
        "GroundTruthError",
        "ok",
    ]
    assert database.exists()
    assert validate_database(database)["selected_prs"] == 1

    ready = tmp_path / "ready.sqlite"
    ready_database(ready)
    destination = tmp_path / "release"
    assert _run_two_processes(_release_worker, (str(ready), str(destination))) == [
        "GroundTruthError",
        "ok",
    ]
    assert (destination / "release-1" / "manifest.json").is_file()
    assert validate_database(ready)["releases"] == 1


@pytest.mark.parametrize("terminal", ["negative_control", "unknown", "not_evaluable"])
def test_distinct_terminal_states_release_end_to_end(tmp_path: Path, terminal: str) -> None:
    database = tmp_path / f"{terminal}.sqlite"
    initialize_database(database, corpus(), allow_synthetic=True)
    a, b = _review_for(1, "A", terminal), _review_for(1, "B", terminal)
    import_reviews(database, [a, b], validator_factory=validator_factory)
    import_adjudications(database, [_adjudication_for(1, a, b, terminal)])
    manifest = release(
        database,
        tmp_path / f"out-{terminal}",
        publication(),
        release_id="release-1",
        created_at="2025-01-03T00:00:00Z",
    )
    terminal_counts = cast("dict[str, int]", manifest["terminal_counts"])
    assert terminal_counts[terminal] == 1
    broad = json.loads(
        (tmp_path / f"out-{terminal}" / "release-1" / "broad-truth.jsonl").read_bytes()
    )
    assert broad["terminal_status"] == terminal


def test_manifest_provenance_root_canonical_tables_sidecar_and_timestamp(tmp_path: Path) -> None:
    first_db, second_db = tmp_path / "first.sqlite", tmp_path / "second.sqlite"
    ready_database(first_db)
    ready_database(second_db)
    with pytest.raises(GroundTruthError, match="timestamp"):
        release(
            first_db,
            tmp_path / "bad",
            publication(),
            release_id="release-1",
            created_at="NOT-A-TIMESTAMP",
        )
    first = release(
        first_db,
        tmp_path / "first",
        publication(),
        release_id="release-1",
        created_at="2025-01-03T00:00:00Z",
    )
    second = release(
        second_db,
        tmp_path / "second",
        publication(),
        release_id="release-1",
        created_at="2025-01-04T00:00:00Z",
    )
    assert first["content_root"] != second["content_root"]
    canonical_tables = cast("dict[str, dict[str, object]]", first["canonical_tables"])
    assert "repository" in canonical_tables
    table_meta = canonical_tables["repository"]
    table_raw = (tmp_path / "first" / "release-1" / "tables" / "repository.jsonl").read_bytes()
    assert table_meta == {
        "rows": 1,
        "bytes": len(table_raw),
        "sha256": artifact_sha256(table_raw),
    }
    assert (
        tmp_path / "first" / "release-1" / "product-scopes" / "endpoint-detector-v1.jsonl"
    ).is_file()


def test_raw_review_identity_is_reconciled_to_canonical_pr(tmp_path: Path) -> None:
    database = tmp_path / "binding.sqlite"
    ready_database(database)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER reviewer_run_no_update")
        row = connection.execute(
            "SELECT run_id,artifact_bytes FROM reviewer_run WHERE lane='A'"
        ).fetchone()
        payload = _json(row[1])
        payload["repository"] = "other/repo"
        raw = _raw(payload)
        connection.execute(
            "UPDATE reviewer_run SET artifact_sha256=?,artifact_bytes=? WHERE run_id=?",
            (artifact_sha256(raw), raw, row[0]),
        )
        connection.execute(
            "CREATE TRIGGER reviewer_run_no_update BEFORE UPDATE ON reviewer_run "
            "BEGIN SELECT RAISE(ABORT,'append-only'); END"
        )
    with pytest.raises(GroundTruthError, match="PR/snapshot binding"):
        validate_database(database)


def test_second_release_exports_complete_release_tables(tmp_path: Path) -> None:
    database = tmp_path / "releases.sqlite"
    destination = tmp_path / "published"
    ready_database(database)
    first_manifest = release(
        database,
        destination,
        publication(),
        release_id="release-1",
        created_at="2025-01-03T00:00:00Z",
    )
    second_publication = _json(publication())
    second_publication["release_id"] = "release-2"
    release(
        database,
        destination,
        _raw(second_publication),
        release_id="release-2",
        predecessor_release_id="release-1",
        created_at="2025-01-04T00:00:00Z",
    )

    tables = destination / "release-2" / "tables"
    table_rows: dict[str, list[dict[str, Any]]] = {}
    for name in ("release", "publication_review", "release_pr"):
        table_rows[name] = [
            json.loads(line)
            for line in (tables / f"{name}.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        assert len(table_rows[name]) == 2
    historical = table_rows["release"][0]
    assert historical["release_id"] == "release-1"
    assert historical["content_root"] == first_manifest["content_root"]
    first_manifest_raw = (destination / "release-1" / "manifest.json").read_bytes()
    assert historical["manifest_bytes"] == {
        "sha256": artifact_sha256(first_manifest_raw),
        "bytes": len(first_manifest_raw),
    }
    assert table_rows["release"][1]["content_root"] == {
        "self_reference": "manifest.json#content_root"
    }


def test_deep_json_is_translated_to_domain_error() -> None:
    raw = ("{" * 1000 + "}" * 1000).encode()
    with pytest.raises(GroundTruthError, match="nesting"):
        parse_artifact(raw, ReviewArtifactV1)
