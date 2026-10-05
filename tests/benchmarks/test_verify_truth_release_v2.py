from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

from benchmarks.real_world.ground_truth_v2 import GroundTruthError
from benchmarks.real_world.ground_truth_v2.schema import artifact_sha256, canonical_json
from benchmarks.real_world.ground_truth_v2.store import (
    import_adjudications,
    import_reviews,
    initialize_database,
    release,
)
from benchmarks.real_world.verify_truth_release_v2 import main, verify_release
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


def _release_with_superseding_adjudication(tmp_path: Path) -> Path:
    db = tmp_path / "truth.sqlite"
    initialize_database(db, corpus(), allow_synthetic=True)
    a, b = review("A"), review("B")
    import_reviews(db, [a, b], validator_factory=validator_factory)
    first = adjudication(artifact_sha256(a), artifact_sha256(b))
    import_adjudications(db, [first], imported_at="2025-01-02T01:00:00Z")
    latest_payload = json.loads(first)
    latest_payload["version"] = 2
    latest_payload["supersedes_sha256"] = artifact_sha256(first)
    import_adjudications(
        db,
        [canonical_json(latest_payload)],
        imported_at="2025-01-02T02:00:00Z",
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
        if name.startswith("tables/"):
            table = name.removeprefix("tables/").removesuffix(".jsonl")
            manifest["canonical_tables"][table] = dict(metadata)
    _resign(root, manifest)


def _resign(root: Path, manifest: dict[str, object]) -> None:
    payload = {key: value for key, value in manifest.items() if key != "content_root"}
    manifest["content_root"] = (
        "sha256:"
        + hashlib.sha256(
            b"ground-truth-release-manifest-v2\0" + canonical_json(payload)
        ).hexdigest()
    )
    (root / "manifest.json").write_bytes(canonical_json(manifest))


def test_verify_release_checks_manifest_and_files(tmp_path: Path) -> None:
    root = _release(tmp_path)
    result = verify_release(root)
    assert result["selected_prs"] == 1
    assert result["terminal_counts"]["positive"] == 1
    assert result["truth_rows_verified"] == 1
    assert result["verification_mode"] == "integrity_only"


def test_verify_release_rejects_tampered_declared_file(tmp_path: Path) -> None:
    root = _release(tmp_path)
    with (root / "broad-truth.jsonl").open("ab") as handle:
        handle.write(b" ")
    with pytest.raises(GroundTruthError, match="metadata mismatch"):
        verify_release(root)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda row: row.clear(),
        lambda row: row.update(secrets_reviewed=False),
        lambda row: row.update(release_id="different-release"),
    ],
    ids=["malformed", "non-affirmative", "wrong-release"],
)
def test_rejects_invalid_publication_review(
    tmp_path: Path, mutate: Callable[[dict[str, object]], None]
) -> None:
    root = _release(tmp_path)
    review_path = root / "publication-review.json"
    row = json.loads(review_path.read_text())
    mutate(row)
    review_path.write_bytes(canonical_json(row))
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["publication_review_sha256"] = artifact_sha256(review_path.read_bytes())
    _reseal(root, manifest)
    with pytest.raises(GroundTruthError, match="publication review"):
        verify_release(root)


def test_publication_review_hash_must_match_manifest(tmp_path: Path) -> None:
    root = _release(tmp_path)
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["publication_review_sha256"] = "sha256:" + "0" * 64
    _resign(root, manifest)
    with pytest.raises(GroundTruthError, match="publication review hash"):
        verify_release(root)


def test_broad_truth_is_parsed_from_verified_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _release(tmp_path)
    truth_path = root / "broad-truth.jsonl"
    original_read_text = type(truth_path).read_text

    def replaced_read_text(path: Path, *args: object, **kwargs: object) -> str:
        if path == truth_path:
            return "{}\\n"
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(type(truth_path), "read_text", replaced_read_text)
    result = verify_release(root)
    assert result["truth_rows_verified"] == 1


def test_verify_release_rejects_manifest_root_tampering(tmp_path: Path) -> None:
    root = _release(tmp_path)
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["selected_prs"] = 2
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(GroundTruthError, match="content root mismatch"):
        verify_release(root)


@pytest.mark.parametrize(
    "member",
    [
        "publication-review.json",
        "reviews.jsonl",
        "adjudications.jsonl",
        "artifact-index.jsonl",
        "tables/release_pr.jsonl",
    ],
)
def test_self_consistent_release_requires_mandatory_members(tmp_path: Path, member: str) -> None:
    root = _release(tmp_path)
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["files"].pop(member)
    (root / member).unlink()
    if member.startswith("tables/"):
        manifest["canonical_tables"].pop("release_pr")
    _resign(root, manifest)
    with pytest.raises(GroundTruthError, match="mandatory"):
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


@pytest.mark.parametrize("constant", [b"NaN", b"Infinity", b"-Infinity"])
def test_rejects_non_finite_constants_in_self_consistent_truth(
    tmp_path: Path, constant: bytes
) -> None:
    root = _release(tmp_path)
    truth_path = root / "broad-truth.jsonl"
    row = truth_path.read_bytes().rstrip(b"\n")
    truth_path.write_bytes(row[:-1] + b',"extension":' + constant + b"}\n")
    manifest = json.loads((root / "manifest.json").read_text())
    _reseal(root, manifest)
    with pytest.raises(GroundTruthError, match="non-finite JSON constant"):
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


@pytest.mark.parametrize("mutation", ["added", "removed", "changed"])
def test_self_consistent_release_rejects_entrypoints_changed_from_canonical(
    tmp_path: Path, mutation: str
) -> None:
    root = _release(tmp_path)
    truth_path = root / "broad-truth.jsonl"
    row = json.loads(truth_path.read_text())
    assert row["affected_entrypoints"]
    if mutation == "removed":
        row["affected_entrypoints"] = []
    elif mutation == "added":
        row["affected_entrypoints"].append(
            {"id": "HTTP GET /forged", "kind": "http", "confidence": "high"}
        )
    else:
        row["affected_entrypoints"][0]["confidence"] = "low"
    truth_path.write_bytes(canonical_json(row))
    manifest = json.loads((root / "manifest.json").read_text())
    _reseal(root, manifest)
    with pytest.raises(GroundTruthError, match="entrypoints do not match canonical adjudication"):
        verify_release(root)


def test_release_membership_rejects_pull_request_from_another_corpus(tmp_path: Path) -> None:
    root = _release(tmp_path)
    pull_requests_path = root / "tables/pull_request.jsonl"
    pull_request = json.loads(pull_requests_path.read_text())
    pull_request["corpus_id"] = "different-corpus"
    pull_requests_path.write_bytes(canonical_json(pull_request))
    manifest = json.loads((root / "manifest.json").read_text())
    _reseal(root, manifest)
    with pytest.raises(GroundTruthError, match="foreign corpus identity"):
        verify_release(root)


@pytest.mark.parametrize("terminal", ["negative_control", "unknown", "not_evaluable"])
def test_truth_terminal_must_match_canonical_adjudication(tmp_path: Path, terminal: str) -> None:
    root = _release(tmp_path)
    truth = json.loads((root / "broad-truth.jsonl").read_text())
    truth["terminal_status"] = terminal
    truth["status"] = "adjudicated" if terminal == "negative_control" else terminal
    (root / "broad-truth.jsonl").write_bytes(canonical_json(truth))
    adjudication_projection = root / "adjudications.jsonl"
    adjudication = json.loads(adjudication_projection.read_text())
    adjudication["terminal_status"] = terminal
    adjudication_projection.write_bytes(canonical_json(adjudication))
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["terminal_counts"] = {
        "positive": 0,
        "negative_control": int(terminal == "negative_control"),
        "unknown": int(terminal == "unknown"),
        "not_evaluable": int(terminal == "not_evaluable"),
    }
    _reseal(root, manifest)
    with pytest.raises(GroundTruthError, match="terminal status does not match canonical"):
        verify_release(root)


def test_release_membership_denominator_must_match_canonical_corpus(tmp_path: Path) -> None:
    root = _release(tmp_path)
    corpus_path = root / "tables/corpus.jsonl"
    corpus_row = json.loads(corpus_path.read_text())
    corpus_row["selected_count"] = 0
    corpus_path.write_bytes(canonical_json(corpus_row))
    manifest = json.loads((root / "manifest.json").read_text())
    _reseal(root, manifest)
    with pytest.raises(GroundTruthError, match="canonical corpus table"):
        verify_release(root)


def test_product_scope_projection_must_match_canonical_membership(tmp_path: Path) -> None:
    root = _release(tmp_path)
    sidecar = next((root / "product-scopes").glob("*.jsonl"))
    row = json.loads(sidecar.read_text())
    row["affected_entrypoints"] = []
    sidecar.write_bytes(canonical_json(row))
    manifest = json.loads((root / "manifest.json").read_text())
    _reseal(root, manifest)
    with pytest.raises(GroundTruthError, match="product-scope projection"):
        verify_release(root)


def test_product_scope_memberships_cover_every_selected_entrypoint(tmp_path: Path) -> None:
    root = _release(tmp_path)
    memberships = root / "tables/scope_membership.jsonl"
    memberships.write_bytes(b"")
    manifest = json.loads((root / "manifest.json").read_text())
    sidecar = next((root / "product-scopes").glob("*.jsonl"))
    sidecar.unlink()
    manifest["files"].pop(sidecar.relative_to(root).as_posix())
    _reseal(root, manifest)
    with pytest.raises(GroundTruthError, match="do not cover every selected canonical entrypoint"):
        verify_release(root)


@pytest.mark.parametrize(
    "member,field,value,expected",
    [
        ("adjudications.jsonl", "version", 77, "adjudication projection"),
        ("adjudications.jsonl", "artifact_sha256", "sha256:" + "0" * 64, "adjudication projection"),
        ("reviews.jsonl", "lane", "A-forged", "review projection"),
        ("artifact-index.jsonl", "bytes", 1, "artifact index"),
    ],
)
def test_self_consistent_released_projections_match_canonical_tables(
    tmp_path: Path, member: str, field: str, value: object, expected: str
) -> None:
    root = _release(tmp_path)
    projection = root / member
    rows = [json.loads(line) for line in projection.read_text().splitlines()]
    rows[0][field] = value
    projection.write_bytes(b"".join(canonical_json(row) for row in rows))
    manifest = json.loads((root / "manifest.json").read_text())
    _reseal(root, manifest)
    with pytest.raises(GroundTruthError, match=expected):
        verify_release(root)


def test_release_membership_requires_latest_canonical_adjudication(tmp_path: Path) -> None:
    root = _release_with_superseding_adjudication(tmp_path)
    membership_path = root / "tables/release_pr.jsonl"
    membership = json.loads(membership_path.read_text())
    adjudications = [
        json.loads(line) for line in (root / "tables/adjudication.jsonl").read_text().splitlines()
    ]
    first = min(adjudications, key=lambda row: row["version"])
    membership["adjudication_id"] = first["adjudication_id"]
    membership_path.write_bytes(canonical_json(membership))
    manifest = json.loads((root / "manifest.json").read_text())
    _reseal(root, manifest)
    with pytest.raises(GroundTruthError, match="invalid canonical adjudication"):
        verify_release(root)


def test_manifest_provenance_matches_canonical_release_row(tmp_path: Path) -> None:
    root = _release(tmp_path)
    release_path = root / "tables/release.jsonl"
    row = json.loads(release_path.read_text())
    row["created_at"] = "2025-01-04T00:00:00Z"
    release_path.write_bytes(canonical_json(row))
    manifest = json.loads((root / "manifest.json").read_text())
    _reseal(root, manifest)
    with pytest.raises(GroundTruthError, match="manifest provenance"):
        verify_release(root)


@pytest.mark.parametrize(
    "member",
    [
        "adjudications.jsonl",
        "tables/corpus.jsonl",
        "tables/release_pr.jsonl",
        "tables/adjudication.jsonl",
        "tables/canonical_entrypoint.jsonl",
        "tables/reviewer_run.jsonl",
        "tables/scope_definition.jsonl",
        "tables/scope_membership.jsonl",
        "reviews.jsonl",
        "artifact-index.jsonl",
        "product-scopes/endpoint-detector-v1.jsonl",
    ],
)
def test_reconciliation_uses_verified_member_snapshots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, member: str
) -> None:
    root = _release(tmp_path)
    manifest = json.loads((root / "manifest.json").read_text())
    trusted_root = manifest["content_root"]
    path_type = type(root)
    original_read_bytes = path_type.read_bytes

    def replace_after_read(path: Path) -> bytes:
        content = original_read_bytes(path)
        if path == root / member:
            path.write_bytes(b"{}\n")
        return content

    monkeypatch.setattr(path_type, "read_bytes", replace_after_read)
    result = verify_release(root, expected_content_root=trusted_root)
    assert result["truth_rows_verified"] == 1
    assert result["verification_mode"] == "anchored"


def test_zero_selected_corpus_can_be_verified(tmp_path: Path) -> None:
    empty = corpus().model_copy(
        update={
            "repositories": tuple(
                repository.model_copy(update={"pull_requests": ()})
                for repository in corpus().repositories
            )
        }
    )
    db = tmp_path / "empty.sqlite"
    initialize_database(db, empty, allow_synthetic=True)
    import_reviews(db, [], validator_factory=validator_factory)
    import_adjudications(db, [])
    release(
        db,
        tmp_path / "empty-published",
        _publication(),
        release_id="release-1",
        created_at="2025-01-03T00:00:00Z",
    )
    result = verify_release(tmp_path / "empty-published" / "release-1")
    assert result["selected_prs"] == 0
    assert result["truth_rows_verified"] == 0


def test_expected_content_root_and_symlink_aliases(tmp_path: Path) -> None:
    root = _release(tmp_path)
    with pytest.raises(GroundTruthError, match="trusted expected root"):
        verify_release(root, expected_content_root="sha256:" + "0" * 64)
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(GroundTruthError, match="symlinks"):
        verify_release(alias)


def test_rejects_truth_identity_not_in_released_corpus(tmp_path: Path) -> None:
    root = _release(tmp_path)
    row = json.loads((root / "broad-truth.jsonl").read_text())
    row["pr"] = 999
    (root / "broad-truth.jsonl").write_bytes(canonical_json(row))
    manifest = json.loads((root / "manifest.json").read_text())
    _reseal(root, manifest)
    with pytest.raises(GroundTruthError, match="identities do not match release membership"):
        verify_release(root)


@pytest.mark.parametrize("member", ["publication-review.json", "tables/release_pr.jsonl"])
def test_rejects_missing_mandatory_release_members(tmp_path: Path, member: str) -> None:
    root = _release(tmp_path)
    (root / member).unlink()
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["files"].pop(member)
    if member.startswith("tables/"):
        table = member.removeprefix("tables/").removesuffix(".jsonl")
        manifest["canonical_tables"].pop(table)
    _resign(root, manifest)
    with pytest.raises(GroundTruthError, match="mandatory"):
        verify_release(root)


def test_cli_accepts_independently_trusted_content_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _release(tmp_path)
    manifest = json.loads((root / "manifest.json").read_text())
    monkeypatch.setattr(
        "sys.argv",
        [
            "verify_truth_release_v2.py",
            str(root),
            "--expected-content-root",
            manifest["content_root"],
        ],
    )
    main()
    assert json.loads(capsys.readouterr().out)["content_root"] == manifest["content_root"]

    monkeypatch.setattr(
        "sys.argv",
        ["verify_truth_release_v2.py", str(root), "--expected-content-root", "sha256:wrong"],
    )
    with pytest.raises(GroundTruthError, match="trusted expected root"):
        main()


def test_duplicate_truth_identity_and_membership_substitution_rejected(tmp_path: Path) -> None:
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
