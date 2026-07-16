"""Append-only SQLite store, parent atomic importer, validator, and release exporter."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from benchmarks.real_world.expansion_protocol_v2 import (
    CorpusV2Error,
    load_lock_authenticated,
    load_manifest,
)

from . import SCHEMA_VERSION, GroundTruthError
from .evidence import EvidenceValidator
from .schema import (
    AdjudicationArtifactV1,
    CorpusDefinition,
    EvidenceEdge,
    EvidenceLocation,
    PublicationReviewV1,
    ReviewArtifactV1,
    artifact_sha256,
    canonical_json,
    parse_artifact,
)

PACKAGE = Path(__file__).parent
MIGRATION_MANIFEST = PACKAGE / "migrations" / "manifest.json"
IMPORTER_SHA256 = "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
ValidatorFactory = Callable[[str], EvidenceValidator]
TreeResolver = Callable[[str, str], str]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _id(domain: str, *parts: object) -> str:
    raw = "\0".join((domain, *(str(item) for item in parts))).encode()
    return f"{domain}:{hashlib.sha256(raw).hexdigest()}"


def _root(domain: str, rows: Iterable[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256(domain.encode() + b"\0")
    for name, raw in sorted(rows):
        digest.update(name.encode() + b"\0" + hashlib.sha256(raw).digest())
    return "sha256:" + digest.hexdigest()


def _canonical_text(value: object) -> str:
    return canonical_json(value).decode().rstrip("\n")


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@contextmanager
def writer_lock(db_path: Path) -> Iterator[None]:
    """Serialize the sole parent writer across processes."""
    lock_path = db_path.with_suffix(db_path.suffix + ".writer.lock")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def connect(db_path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    if sqlite3.sqlite_version_info < (3, 37, 0):
        raise GroundTruthError("SQLite >=3.37 is required for STRICT tables")
    if readonly:
        uri = f"file:{db_path.resolve()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
    else:
        connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA trusted_schema=OFF")
    if readonly:
        connection.execute("PRAGMA query_only=ON")
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise GroundTruthError("SQLite foreign keys could not be enabled")
    return connection


def _migration_profile() -> list[dict[str, object]]:
    try:
        profile = json.loads(MIGRATION_MANIFEST.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise GroundTruthError("invalid migration manifest") from exc
    expected = {"schema_version", "migrations"}
    if not isinstance(profile, dict) or set(profile) != expected or profile["schema_version"] != 1:
        raise GroundTruthError("unsupported migration manifest")
    migrations = profile["migrations"]
    if not isinstance(migrations, list):
        raise GroundTruthError("migration manifest rows are invalid")
    for index, item in enumerate(migrations, 1):
        if not isinstance(item, dict) or set(item) != {"version", "name", "sha256"}:
            raise GroundTruthError("migration profile row has invalid keys")
        if item["version"] != index or item["name"] != f"{index:04d}.sql":
            raise GroundTruthError("migration sequence has a gap")
        raw = (PACKAGE / "migrations" / cast("str", item["name"])).read_bytes()
        if artifact_sha256(raw) != item["sha256"]:
            raise GroundTruthError("migration hash mismatch")
    return cast("list[dict[str, object]]", migrations)


def corpus_from_authenticated_lock(
    lock: dict[str, Any],
    lock_sha256: str,
    manifest: dict[str, Any],
    tree_resolver: TreeResolver,
) -> CorpusDefinition:
    """Convert an already authenticated v2 lock while resolving exact offline trees.

    Callers must obtain ``lock`` and ``lock_sha256`` from
    ``expansion_protocol_v2.load_lock_authenticated``. Keeping authentication in
    that established module avoids a second, weaker lock parser here.
    """
    partitions = {row["repository"]: row["partition"] for row in manifest["projects"]}
    repositories: list[dict[str, object]] = []
    for project in lock["projects"]:
        repository = project["repository"]
        if repository not in partitions:
            raise GroundTruthError("authenticated lock repository is absent from its manifest")
        pulls: list[dict[str, object]] = []
        for record in project["records"]:
            baseline_tree = tree_resolver(repository, record["baseline_sha"])
            target_tree = tree_resolver(repository, record["target_sha"])
            pulls.append(
                {
                    "number": record["pr"],
                    "rank": record["rank"],
                    "merged_at": record["merged_at"],
                    "base_sha": record["base_sha"],
                    "head_sha": record["head_sha"],
                    "merge_commit_sha": record["merge_commit_sha"],
                    "baseline": {
                        "commit_sha": record["baseline_sha"],
                        "tree_sha": baseline_tree,
                        "rule": record["baseline_rule"],
                    },
                    "target": {
                        "commit_sha": record["target_sha"],
                        "tree_sha": target_tree,
                        "rule": record["target_rule"],
                    },
                    "remote_diff": {
                        "sha256": record["diff_sha256"],
                        "byte_count": record["diff_bytes"],
                        "final_url": record["diff_final_url"],
                        "content_type": record["diff_content_type"],
                    },
                }
            )
        repositories.append(
            {
                "full_name": repository,
                "partition": partitions[repository],
                "terminal_status": project["status"],
                "pull_requests": pulls,
            }
        )
    try:
        return CorpusDefinition.model_validate(
            {
                "schema_version": 2,
                "corpus_id": lock["id"],
                "lock_sha256": lock_sha256,
                "source": "authenticated_v2_lock",
                "repositories": repositories,
            }
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise GroundTruthError(
            "authenticated lock could not be converted to canonical corpus rows"
        ) from exc


def initialize_database(
    db_path: Path,
    corpus: CorpusDefinition | None = None,
    *,
    allow_synthetic: bool = False,
    lock_path: Path | None = None,
    manifest_path: Path | None = None,
    checksums_path: Path | None = None,
    tree_resolver: TreeResolver | None = None,
) -> None:
    """Create a database from the exact #145 authenticated profile or a test fixture.

    Production callers cannot pass a self-asserted ``CorpusDefinition``. The lock,
    manifest, and independent checksum profile are authenticated by #145's loader
    inside this initialization boundary before canonical rows are created.
    """
    if corpus is not None:
        if corpus.source != "strict_synthetic_fixture" or not allow_synthetic:
            raise GroundTruthError(
                "production initialization requires exact lock/manifest/checksum paths; "
                "synthetic corpus fixtures require an explicit test-only opt-in"
            )
        if any(value is not None for value in (lock_path, manifest_path, checksums_path)):
            raise GroundTruthError("synthetic and authenticated corpus inputs cannot be mixed")
    else:
        if None in (lock_path, manifest_path, checksums_path) or tree_resolver is None:
            raise GroundTruthError(
                "production initialization requires lock, manifest, checksums, and tree resolver"
            )
        corpus = _authenticate_production_corpus(
            cast("Path", lock_path),
            cast("Path", manifest_path),
            cast("Path", checksums_path),
            tree_resolver,
        )
    db_path.parent.mkdir(parents=True, exist_ok=True)
    migrations = _migration_profile()
    with writer_lock(db_path):
        if db_path.exists():
            raise GroundTruthError("refusing to initialize an existing database")
        created_here = False
        try:
            connection = connect(db_path)
            created_here = True
            try:
                for migration in migrations:
                    raw = (PACKAGE / "migrations" / cast("str", migration["name"])).read_text()
                    connection.executescript(raw)
                    connection.execute(
                        "INSERT INTO schema_migration VALUES(?,?,?,?)",
                        (
                            migration["version"],
                            migration["name"],
                            migration["sha256"],
                            "1970-01-01T00:00:00Z",
                        ),
                    )
                    connection.execute(f"PRAGMA user_version={migration['version']}")
                with connection:
                    _insert_corpus(connection, corpus)
                    _check_connection(connection)
            finally:
                connection.close()
            db_path.chmod(0o600)
        except Exception:
            if created_here:
                db_path.unlink(missing_ok=True)
            raise


def _authenticate_production_corpus(
    lock_path: Path,
    manifest_path: Path,
    checksums_path: Path,
    tree_resolver: TreeResolver,
) -> CorpusDefinition:
    try:
        lock, lock_sha256 = load_lock_authenticated(lock_path, manifest_path, checksums_path)
        manifest, _manifest_sha256 = load_manifest(manifest_path)
        return corpus_from_authenticated_lock(lock, lock_sha256, manifest, tree_resolver)
    except (OSError, CorpusV2Error) as exc:
        raise GroundTruthError("#145 corpus authentication failed") from exc


def _insert_corpus(connection: sqlite3.Connection, corpus: CorpusDefinition) -> None:
    selected = sum(len(repo.pull_requests) for repo in corpus.repositories)
    connection.execute(
        "INSERT INTO corpus VALUES(?,?,?,?)",
        (corpus.corpus_id, corpus.lock_sha256, corpus.schema_version, selected),
    )
    for repository in corpus.repositories:
        repository_id = _id("repo", corpus.corpus_id, repository.full_name.casefold())
        connection.execute(
            "INSERT INTO repository VALUES(?,?,?,?,?,?)",
            (
                repository_id,
                corpus.corpus_id,
                repository.full_name,
                repository.full_name.casefold(),
                repository.partition,
                repository.terminal_status,
            ),
        )
        for pr in repository.pull_requests:
            pr_id = _id("pr", repository_id, pr.number)
            connection.execute(
                "INSERT INTO pull_request VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    pr_id,
                    repository_id,
                    corpus.corpus_id,
                    pr.number,
                    pr.rank,
                    _timestamp(pr.merged_at),
                    pr.base_sha,
                    pr.head_sha,
                    pr.merge_commit_sha,
                ),
            )
            snapshot_ids: list[str] = []
            for side, snapshot in (("baseline", pr.baseline), ("target", pr.target)):
                snapshot_id = _id("snapshot", pr_id, side)
                snapshot_ids.append(snapshot_id)
                connection.execute(
                    "INSERT INTO snapshot VALUES(?,?,?,?,?,?)",
                    (
                        snapshot_id,
                        pr_id,
                        side,
                        snapshot.commit_sha,
                        snapshot.tree_sha,
                        snapshot.rule,
                    ),
                )
            connection.execute(
                "INSERT INTO remote_diff VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    _id("diff", pr_id),
                    pr_id,
                    pr.remote_diff.sha256,
                    pr.remote_diff.byte_count,
                    pr.remote_diff.final_url,
                    pr.remote_diff.content_type,
                    snapshot_ids[0],
                    "baseline",
                    snapshot_ids[1],
                    "target",
                ),
            )


def import_reviews(
    db_path: Path,
    artifacts: Sequence[bytes],
    *,
    validator_factory: ValidatorFactory | None = None,
    imported_at: str | None = None,
) -> str:
    """Validate and atomically import exactly A and B for every selected PR."""
    parsed = [
        (cast("ReviewArtifactV1", parse_artifact(raw, ReviewArtifactV1)), raw) for raw in artifacts
    ]
    with writer_lock(db_path), connect(db_path) as connection:
        corpus, prs = _corpus_index(connection)
        expected = {(key, lane) for key in prs for lane in ("A", "B")}
        supplied = {(f"{item.repository.casefold()}#{item.pr}", item.lane) for item, _ in parsed}
        if len(supplied) != len(parsed) or supplied != expected:
            raise GroundTruthError(
                "review import must contain exactly one A and B artifact per selected PR"
            )
        hashes = [artifact_sha256(raw) for _, raw in parsed]
        if len(hashes) != len(set(hashes)):
            raise GroundTruthError("review artifacts must have distinct exact bytes")
        _validate_review_identities(corpus, prs, parsed, validator_factory)
        by_pr: dict[str, list[ReviewArtifactV1]] = {}
        for item, _ in parsed:
            by_pr.setdefault(f"{item.repository.casefold()}#{item.pr}", []).append(item)
        for reviews in by_pr.values():
            identities = {
                (item.reviewer.kind, item.reviewer.name, item.reviewer.version) for item in reviews
            }
            if len(identities) != 2:
                raise GroundTruthError("Review A and B must have distinct reviewer identities")
        input_root = _root(
            "ground-truth-review-import-v1",
            zip(hashes, (raw for _, raw in parsed), strict=True),
        )
        batch_id = _id("batch", input_root)
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "INSERT INTO import_batch VALUES(?,?,?,?,?,?)",
                (
                    batch_id,
                    "reviews",
                    input_root,
                    imported_at or _now(),
                    IMPORTER_SHA256,
                    _canonical_text({"artifacts": len(parsed)}),
                ),
            )
            for artifact, raw in sorted(
                parsed, key=lambda row: (row[0].repository.casefold(), row[0].pr, row[0].lane)
            ):
                _insert_review(
                    connection,
                    prs[f"{artifact.repository.casefold()}#{artifact.pr}"],
                    artifact,
                    raw,
                    batch_id,
                )
            _check_connection(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        return batch_id


def _validate_review_identities(
    corpus: sqlite3.Row,
    prs: dict[str, sqlite3.Row],
    parsed: Sequence[tuple[ReviewArtifactV1, bytes]],
    factory: ValidatorFactory | None,
) -> None:
    for item, _raw in parsed:
        if item.corpus_id != corpus["corpus_id"]:
            raise GroundTruthError("review is bound to the wrong corpus")
        key = f"{item.repository.casefold()}#{item.pr}"
        row = prs.get(key)
        if row is None:
            raise GroundTruthError("review references a PR outside the corpus")
        if (
            item.snapshots.baseline_commit != row["baseline_commit"]
            or item.snapshots.target_commit != row["target_commit"]
        ):
            raise GroundTruthError("review snapshot binding does not match corpus")
        validator = factory(row["pr_id"]) if factory is not None else None
        edges = [edge for claim in item.claims for edge in claim.evidence]
        if (edges or item.changed_symbols) and validator is None:
            raise GroundTruthError(
                "source-bearing review import requires an offline evidence validator"
            )
        assert validator is not None or not (edges or item.changed_symbols)
        if validator is not None:
            for symbol in item.changed_symbols:
                validator.validate_changed_location(symbol.location)
            for claim in item.claims:
                validator.validate_edges(claim.evidence)


def _insert_review(
    connection: sqlite3.Connection,
    pr: sqlite3.Row,
    item: ReviewArtifactV1,
    raw: bytes,
    batch_id: str,
) -> None:
    digest = artifact_sha256(raw)
    run_id = _id("review", pr["pr_id"], item.lane, digest)
    connection.execute(
        "INSERT INTO reviewer_run VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            run_id,
            pr["pr_id"],
            item.lane,
            digest,
            raw,
            item.reviewer.kind,
            item.reviewer.name,
            item.reviewer.version,
            item.run.prompt_sha256,
            item.run.model_policy_sha256,
            item.run.tool_policy_sha256,
            item.run.source_policy_sha256,
            _timestamp(item.run.started_at),
            _timestamp(item.run.completed_at),
            item.terminal_recommendation,
            batch_id,
        ),
    )
    for symbol in item.changed_symbols:
        location_id = _insert_location(connection, pr, symbol.location)
        connection.execute(
            "INSERT INTO review_changed_symbol VALUES(?,?,?,?,?,?)",
            (
                _id("review-symbol", run_id, symbol.symbol_id),
                run_id,
                pr["pr_id"],
                symbol.symbol_id,
                symbol.canonical_name,
                location_id,
            ),
        )
    for claim in item.claims:
        claim_id = _id("review-claim", run_id, claim.claim_id)
        connection.execute(
            "INSERT INTO review_claim VALUES(?,?,?,?,?,?)",
            (claim_id, run_id, pr["pr_id"], claim.claim_id, claim.recommendation, claim.summary),
        )
        connection.execute(
            "INSERT INTO review_entrypoint VALUES(?,?,?,?,?)",
            (
                _id("review-entrypoint", claim_id),
                claim_id,
                claim.entrypoint.public_id,
                claim.entrypoint.kind,
                claim.entrypoint.confidence,
            ),
        )
        _insert_edges(connection, "review", claim_id, pr, claim.evidence)
    for unknown in item.unknowns:
        connection.execute(
            "INSERT INTO review_unknown VALUES(?,?,?,?,?,?,?)",
            (
                _id("review-unknown", run_id, unknown.unknown_id),
                run_id,
                pr["pr_id"],
                unknown.unknown_id,
                unknown.category,
                unknown.description,
                unknown.evidence_limit,
            ),
        )
    if item.negative_assessment:
        negative = item.negative_assessment
        connection.execute(
            "INSERT INTO review_negative_assessment VALUES(?,?,?,?,?)",
            (
                run_id,
                pr["pr_id"],
                1,
                _canonical_text(negative.searched_entrypoint_families),
                _canonical_text(negative.limitations),
            ),
        )


def import_adjudications(
    db_path: Path,
    artifacts: Sequence[bytes],
    *,
    validator_factory: ValidatorFactory | None = None,
    imported_at: str | None = None,
) -> str:
    """Atomically append one fully provenance-covered adjudication per selected PR."""
    parsed = [
        (cast("AdjudicationArtifactV1", parse_artifact(raw, AdjudicationArtifactV1)), raw)
        for raw in artifacts
    ]
    with writer_lock(db_path), connect(db_path) as connection:
        corpus, prs = _corpus_index(connection)
        supplied = {f"{item.repository.casefold()}#{item.pr}" for item, _ in parsed}
        if len(supplied) != len(parsed) or supplied != set(prs):
            raise GroundTruthError(
                "adjudication import must contain exactly one artifact per selected PR"
            )
        prepared = [
            (
                item,
                raw,
                _prepare_adjudication(connection, corpus, prs, item, raw, validator_factory),
            )
            for item, raw in parsed
        ]
        input_root = _root(
            "ground-truth-adjudication-import-v1",
            ((artifact_sha256(raw), raw) for item, raw, _state in prepared),
        )
        batch_id = _id("batch", input_root)
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "INSERT INTO import_batch VALUES(?,?,?,?,?,?)",
                (
                    batch_id,
                    "adjudications",
                    input_root,
                    imported_at or _now(),
                    IMPORTER_SHA256,
                    _canonical_text({"artifacts": len(parsed)}),
                ),
            )
            for item, raw, state in sorted(
                prepared, key=lambda row: (row[0].repository.casefold(), row[0].pr)
            ):
                _insert_adjudication(connection, state, item, raw, batch_id)
            _check_connection(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        return batch_id


def _prepare_adjudication(  # noqa: PLR0912 - fail-closed cross-row preflight
    connection: sqlite3.Connection,
    corpus: sqlite3.Row,
    prs: dict[str, sqlite3.Row],
    item: AdjudicationArtifactV1,
    raw: bytes,
    factory: ValidatorFactory | None,
) -> dict[str, Any]:
    del raw
    if item.corpus_id != corpus["corpus_id"]:
        raise GroundTruthError("adjudication is bound to the wrong corpus")
    key = f"{item.repository.casefold()}#{item.pr}"
    pr = prs.get(key)
    if (
        pr is None
        or item.snapshots.baseline_commit != pr["baseline_commit"]
        or item.snapshots.target_commit != pr["target_commit"]
    ):
        raise GroundTruthError("adjudication PR/snapshot binding does not match corpus")
    runs = connection.execute(
        "SELECT * FROM reviewer_run WHERE pr_id=? ORDER BY lane", (pr["pr_id"],)
    ).fetchall()
    if len(runs) != 2 or [row["lane"] for row in runs] != ["A", "B"]:
        raise GroundTruthError("adjudication requires frozen Review A and Review B")
    if [item.review_a_sha256, item.review_b_sha256] != [
        runs[0]["artifact_sha256"],
        runs[1]["artifact_sha256"],
    ]:
        raise GroundTruthError("adjudication review hashes do not match exact frozen artifacts")
    source_map: dict[tuple[str, str, str], sqlite3.Row] = {}
    for run in runs:
        source_map[(run["lane"], "terminal", "")] = run
    source_queries = (
        ("claim", "review_claim", "local_claim_id"),
        ("unknown", "review_unknown", "local_unknown_id"),
    )
    for kind, table, local_column in source_queries:
        rows = connection.execute(
            f"SELECT source.*,r.lane FROM {table} source JOIN reviewer_run r "
            "ON r.run_id=source.run_id WHERE r.pr_id=?",
            (pr["pr_id"],),
        ).fetchall()
        for row in rows:
            source_map[(row["lane"], kind, row[local_column])] = row
    for run in runs:
        negative = connection.execute(
            "SELECT n.*,r.lane FROM review_negative_assessment n JOIN reviewer_run r "
            "ON r.run_id=n.run_id WHERE n.run_id=?",
            (run["run_id"],),
        ).fetchone()
        if negative is not None:
            source_map[(run["lane"], "negative_assessment", "")] = negative
    covered: set[tuple[str, str, str]] = set()
    for decision in item.decisions:
        for source in decision.sources:
            source_key = (source.lane, source.source_kind, source.source_id or "")
            if source_key not in source_map:
                raise GroundTruthError("decision cites an unknown or cross-PR review source")
            if source_key in covered:
                raise GroundTruthError("a Review A/B source may be resolved exactly once")
            covered.add(source_key)
    if covered != set(source_map):
        raise GroundTruthError(
            "adjudication decisions must resolve every claim, terminal, unknown, "
            "and negative assessment exactly once"
        )
    fresh_edges = [edge for decision in item.decisions for edge in decision.evidence]
    if fresh_edges and factory is None:
        raise GroundTruthError("new adjudication evidence requires an offline evidence validator")
    if factory is not None:
        validator = factory(pr["pr_id"])
        for decision in item.decisions:
            if decision.evidence:
                validator.validate_edges(decision.evidence)
    predecessor = None
    if item.supersedes_sha256 is not None:
        predecessor = connection.execute(
            "SELECT * FROM adjudication WHERE artifact_sha256=? AND pr_id=?",
            (item.supersedes_sha256, pr["pr_id"]),
        ).fetchone()
        if predecessor is None or predecessor["version"] >= item.version:
            raise GroundTruthError("invalid cross-PR, missing, or non-monotonic predecessor")
    elif item.version != 1:
        raise GroundTruthError("initial adjudication version must be 1")
    included = {
        decision.decision_id
        for decision in item.decisions
        if decision.decision_kind == "entrypoint" and decision.outcome == "include"
    }
    canonical_keys = [
        (decision.canonical_entrypoint.public_id, decision.canonical_entrypoint.kind)
        for decision in item.decisions
        if decision.canonical_entrypoint is not None
    ]
    if len(canonical_keys) != len(set(canonical_keys)):
        raise GroundTruthError("duplicate canonical entrypoint in one adjudication")
    if {membership.decision_id for membership in item.scope_memberships} != included:
        raise GroundTruthError("scope memberships must cover every canonical entrypoint")
    return {"pr": pr, "runs": runs, "sources": source_map, "predecessor": predecessor}


def _insert_adjudication(
    connection: sqlite3.Connection,
    state: dict[str, Any],
    item: AdjudicationArtifactV1,
    raw: bytes,
    batch_id: str,
) -> None:
    pr, runs, source_map = state["pr"], state["runs"], state["sources"]
    digest = artifact_sha256(raw)
    adjudication_id = _id("adjudication", pr["pr_id"], item.version, digest)
    connection.execute(
        "INSERT INTO adjudication VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            adjudication_id,
            pr["pr_id"],
            item.version,
            state["predecessor"]["adjudication_id"] if state["predecessor"] else None,
            digest,
            raw,
            runs[0]["run_id"],
            "A",
            runs[1]["run_id"],
            "B",
            item.adjudicator.kind,
            item.adjudicator.name,
            item.adjudicator.version,
            item.run.prompt_sha256,
            item.terminal_status,
            item.reason,
            batch_id,
        ),
    )
    for decision in item.decisions:
        decision_id = _id("decision", adjudication_id, decision.decision_id)
        connection.execute(
            "INSERT INTO adjudication_decision VALUES(?,?,?,?,?,?,?,?)",
            (
                decision_id,
                adjudication_id,
                pr["pr_id"],
                decision.decision_id,
                decision.decision_kind,
                decision.outcome,
                decision.attribution,
                decision.rationale,
            ),
        )
        for source in decision.sources:
            key = (source.lane, source.source_kind, source.source_id or "")
            source_row = source_map[key]
            if source.source_kind == "claim":
                table, source_column, source_value = (
                    "decision_source_claim",
                    "claim_id",
                    source_row["claim_id"],
                )
            elif source.source_kind == "unknown":
                table, source_column, source_value = (
                    "decision_source_unknown",
                    "unknown_id",
                    source_row["unknown_id"],
                )
            elif source.source_kind == "terminal":
                table, source_column, source_value = (
                    "decision_source_terminal",
                    "run_id",
                    source_row["run_id"],
                )
            else:
                table, source_column, source_value = (
                    "decision_source_negative",
                    "run_id",
                    source_row["run_id"],
                )
            connection.execute(
                f"INSERT INTO {table}(decision_id,adjudication_id,{source_column},pr_id) "
                "VALUES(?,?,?,?)",
                (decision_id, adjudication_id, source_value, pr["pr_id"]),
            )
        if decision.canonical_entrypoint:
            entrypoint = decision.canonical_entrypoint
            connection.execute(
                "INSERT INTO canonical_entrypoint VALUES(?,?,?,?,?,?,?)",
                (
                    _id("canonical-entrypoint", decision_id),
                    decision_id,
                    adjudication_id,
                    pr["pr_id"],
                    entrypoint.public_id,
                    entrypoint.kind,
                    entrypoint.confidence,
                ),
            )
        _insert_edges(connection, "adjudication", decision_id, pr, decision.evidence)
    for membership in item.scope_memberships:
        connection.execute(
            "INSERT OR IGNORE INTO scope_definition VALUES(?,?,?,?)",
            (
                membership.scope_id,
                membership.scope_version,
                membership.product,
                membership.definition_sha256,
            ),
        )
        definition = connection.execute(
            "SELECT product,definition_sha256 FROM scope_definition "
            "WHERE scope_id=? AND scope_version=?",
            (membership.scope_id, membership.scope_version),
        ).fetchone()
        if tuple(definition) != (membership.product, membership.definition_sha256):
            raise GroundTruthError("scope identity/version has conflicting immutable definition")
        member_decision_id = _id("decision", adjudication_id, membership.decision_id)
        connection.execute(
            "INSERT INTO scope_membership VALUES(?,?,?,?,?,?,?,?)",
            (
                _id(
                    "scope-membership",
                    member_decision_id,
                    membership.scope_id,
                    membership.scope_version,
                ),
                adjudication_id,
                member_decision_id,
                pr["pr_id"],
                membership.scope_id,
                membership.scope_version,
                membership.status,
                membership.rationale,
            ),
        )
    for unknown in item.unknowns:
        connection.execute(
            "INSERT INTO adjudication_unknown VALUES(?,?,?,?,?,?,?)",
            (
                _id("adjudication-unknown", adjudication_id, unknown.unknown_id),
                adjudication_id,
                pr["pr_id"],
                unknown.unknown_id,
                unknown.category,
                unknown.description,
                unknown.evidence_limit,
            ),
        )
    if item.negative_assessment:
        negative = item.negative_assessment
        connection.execute(
            "INSERT INTO adjudication_negative_assessment VALUES(?,?,?,?,?)",
            (
                adjudication_id,
                pr["pr_id"],
                1,
                _canonical_text(negative.searched_entrypoint_families),
                _canonical_text(negative.limitations),
            ),
        )


def _insert_location(
    connection: sqlite3.Connection, pr: sqlite3.Row, location: EvidenceLocation
) -> str:
    snapshot_id = pr[f"{location.side}_snapshot_id"]
    location_id = _id(
        "location",
        snapshot_id,
        location.blob_sha,
        location.path,
        location.start_line,
        location.end_line,
        location.symbol,
    )
    connection.execute(
        "INSERT OR IGNORE INTO evidence_location VALUES(?,?,?,?,?,?,?,?)",
        (
            location_id,
            pr["pr_id"],
            snapshot_id,
            location.blob_sha,
            location.path,
            location.start_line,
            location.end_line,
            location.symbol,
        ),
    )
    return location_id


def _insert_edges(
    connection: sqlite3.Connection,
    owner: str,
    owner_id: str,
    pr: sqlite3.Row,
    edges: Sequence[EvidenceEdge],
) -> None:
    table = "review_evidence_edge" if owner == "review" else "adjudication_evidence_edge"
    owner_column = "claim_id" if owner == "review" else "decision_id"
    for edge in edges:
        from_id = _insert_location(connection, pr, edge.from_location)
        to_id = _insert_location(connection, pr, edge.to_location)
        edge_id = _id(f"{owner}-edge", owner_id, edge.ordinal)
        connection.execute(
            f"INSERT INTO {table}(edge_id,{owner_column},pr_id,ordinal,relation,"
            "from_location_id,to_location_id) VALUES(?,?,?,?,?,?,?)",
            (edge_id, owner_id, pr["pr_id"], edge.ordinal, edge.relation, from_id, to_id),
        )


def _corpus_index(connection: sqlite3.Connection) -> tuple[sqlite3.Row, dict[str, sqlite3.Row]]:
    corpus_rows = connection.execute("SELECT * FROM corpus").fetchall()
    if len(corpus_rows) != 1:
        raise GroundTruthError("database must contain exactly one corpus")
    rows = connection.execute(
        """SELECT p.*,r.full_name,
        bs.snapshot_id baseline_snapshot_id,bs.commit_sha baseline_commit,bs.tree_sha baseline_tree,
        ts.snapshot_id target_snapshot_id,ts.commit_sha target_commit,ts.tree_sha target_tree
        FROM pull_request p JOIN repository r USING(repository_id)
        JOIN snapshot bs ON bs.pr_id=p.pr_id AND bs.side='baseline'
        JOIN snapshot ts ON ts.pr_id=p.pr_id AND ts.side='target'"""
    ).fetchall()
    index = {f"{row['full_name'].casefold()}#{row['number']}": row for row in rows}
    if len(index) != corpus_rows[0]["selected_count"]:
        raise GroundTruthError("corpus selected count or snapshot coverage is inconsistent")
    return corpus_rows[0], index


def validate_database(db_path: Path) -> dict[str, int]:
    """Read-only fail-closed validation of schema, ownership, and immutable artifacts."""
    migrations = _migration_profile()
    with connect(db_path, readonly=True) as connection:
        applied = connection.execute(
            "SELECT version,name,sha256 FROM schema_migration ORDER BY version"
        ).fetchall()
        if [tuple(row) for row in applied] != [
            (item["version"], item["name"], item["sha256"]) for item in migrations
        ]:
            raise GroundTruthError("applied migration provenance differs from source")
        if connection.execute("PRAGMA user_version").fetchone()[0] != len(migrations):
            raise GroundTruthError("database user_version differs from migration profile")
        if _schema_digest(connection) != _expected_schema_digest(migrations):
            raise GroundTruthError("live SQLite schema/trigger digest differs from migrations")
        _check_connection(connection)
        _validate_ownership_queries(connection)
        _reconcile_raw_artifacts(connection)
        for row in connection.execute(
            "SELECT artifact_sha256,artifact_bytes,release_id FROM publication_review"
        ):
            if artifact_sha256(row["artifact_bytes"]) != row["artifact_sha256"]:
                raise GroundTruthError("publication review bytes were tampered")
            publication = cast(
                "PublicationReviewV1",
                parse_artifact(row["artifact_bytes"], PublicationReviewV1),
            )
            if publication.release_id != row["release_id"]:
                raise GroundTruthError("publication review normalized identity was tampered")
        selected = connection.execute("SELECT selected_count FROM corpus").fetchone()[0]
        return {
            "selected_prs": selected,
            "reviewer_runs": connection.execute("SELECT count(*) FROM reviewer_run").fetchone()[0],
            "adjudications": connection.execute("SELECT count(*) FROM adjudication").fetchone()[0],
            "releases": connection.execute("SELECT count(*) FROM release").fetchone()[0],
        }


def _schema_digest(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        "SELECT type,name,tbl_name,coalesce(sql,'') sql FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    ).fetchall()
    return artifact_sha256(canonical_json([tuple(row) for row in rows]))


def _expected_schema_digest(migrations: Sequence[dict[str, object]]) -> str:
    expected = sqlite3.connect(":memory:")
    expected.row_factory = sqlite3.Row
    try:
        for migration in migrations:
            expected.executescript(
                (PACKAGE / "migrations" / cast("str", migration["name"])).read_text()
            )
        return _schema_digest(expected)
    finally:
        expected.close()


def _validate_ownership_queries(connection: sqlite3.Connection) -> None:
    checks = {
        "remote diff snapshot sides": """SELECT 1 FROM remote_diff d
            JOIN snapshot b ON b.snapshot_id=d.baseline_snapshot_id
            JOIN snapshot t ON t.snapshot_id=d.target_snapshot_id
            WHERE b.pr_id<>d.pr_id OR b.side<>'baseline'
               OR t.pr_id<>d.pr_id OR t.side<>'target' LIMIT 1""",
        "review evidence ownership": """SELECT 1 FROM review_evidence_edge e
            JOIN review_claim c USING(claim_id)
            JOIN evidence_location f ON f.location_id=e.from_location_id
            JOIN evidence_location t ON t.location_id=e.to_location_id
            WHERE c.pr_id<>e.pr_id OR f.pr_id<>e.pr_id OR t.pr_id<>e.pr_id LIMIT 1""",
        "adjudication evidence ownership": """SELECT 1 FROM adjudication_evidence_edge e
            JOIN adjudication_decision d USING(decision_id)
            JOIN evidence_location f ON f.location_id=e.from_location_id
            JOIN evidence_location t ON t.location_id=e.to_location_id
            WHERE d.pr_id<>e.pr_id OR f.pr_id<>e.pr_id OR t.pr_id<>e.pr_id LIMIT 1""",
        "adjudication review ownership": """SELECT 1 FROM adjudication a
            JOIN reviewer_run ra ON ra.run_id=a.review_a_run_id
            JOIN reviewer_run rb ON rb.run_id=a.review_b_run_id
            WHERE ra.pr_id<>a.pr_id OR ra.lane<>'A' OR rb.pr_id<>a.pr_id OR rb.lane<>'B' LIMIT 1""",
        "release membership ownership": """SELECT 1 FROM release_pr m
            JOIN release r USING(release_id) JOIN pull_request p USING(pr_id)
            JOIN adjudication a USING(adjudication_id)
            WHERE r.corpus_id<>m.corpus_id OR p.corpus_id<>m.corpus_id
               OR a.pr_id<>m.pr_id LIMIT 1""",
    }
    for label, query in checks.items():
        if connection.execute(query).fetchone() is not None:
            raise GroundTruthError(f"cross-PR/snapshot ownership violation: {label}")


def _location_identity(pr: sqlite3.Row, location: EvidenceLocation) -> str:
    snapshot_id = pr[f"{location.side}_snapshot_id"]
    return _id(
        "location",
        snapshot_id,
        location.blob_sha,
        location.path,
        location.start_line,
        location.end_line,
        location.symbol,
    )


def _reconcile_raw_artifacts(  # noqa: PLR0912 - full immutable-artifact reconciliation
    connection: sqlite3.Connection,
) -> None:
    corpus, prs = _corpus_index(connection)
    pr_by_id = {row["pr_id"]: row for row in prs.values()}
    for row in connection.execute("SELECT * FROM reviewer_run ORDER BY run_id"):
        if artifact_sha256(row["artifact_bytes"]) != row["artifact_sha256"]:
            raise GroundTruthError("reviewer_run exact artifact bytes were tampered")
        item = cast("ReviewArtifactV1", parse_artifact(row["artifact_bytes"], ReviewArtifactV1))
        expected_metadata = (
            item.lane,
            item.reviewer.kind,
            item.reviewer.name,
            item.reviewer.version,
            item.run.prompt_sha256,
            item.run.model_policy_sha256,
            item.run.tool_policy_sha256,
            item.run.source_policy_sha256,
            _timestamp(item.run.started_at),
            _timestamp(item.run.completed_at),
            item.terminal_recommendation,
        )
        actual_metadata = tuple(
            row[name]
            for name in (
                "lane",
                "reviewer_kind",
                "reviewer_name",
                "reviewer_version",
                "prompt_sha256",
                "model_policy_sha256",
                "tool_policy_sha256",
                "source_policy_sha256",
                "started_at",
                "completed_at",
                "terminal_recommendation",
            )
        )
        if actual_metadata != expected_metadata:
            raise GroundTruthError("review normalized metadata differs from immutable artifact")
        pr = pr_by_id[row["pr_id"]]
        if (
            item.corpus_id,
            item.repository,
            item.pr,
            item.snapshots.baseline_commit,
            item.snapshots.target_commit,
        ) != (
            corpus["corpus_id"],
            pr["full_name"],
            pr["number"],
            pr["baseline_commit"],
            pr["target_commit"],
        ):
            raise GroundTruthError("review artifact PR/snapshot binding was tampered")
        actual_symbols = {
            (symbol["local_symbol_id"], symbol["canonical_name"], symbol["location_id"])
            for symbol in connection.execute(
                "SELECT * FROM review_changed_symbol WHERE run_id=?", (row["run_id"],)
            )
        }
        expected_symbols = {
            (symbol.symbol_id, symbol.canonical_name, _location_identity(pr, symbol.location))
            for symbol in item.changed_symbols
        }
        actual_claims = {
            (
                claim["local_claim_id"],
                claim["recommendation"],
                claim["summary"],
                claim["public_id"],
                claim["kind"],
                claim["confidence"],
            )
            for claim in connection.execute(
                "SELECT c.*,e.public_id,e.kind,e.confidence FROM review_claim c "
                "JOIN review_entrypoint e USING(claim_id) WHERE c.run_id=?",
                (row["run_id"],),
            )
        }
        expected_claims = {
            (
                claim.claim_id,
                claim.recommendation,
                claim.summary,
                claim.entrypoint.public_id,
                claim.entrypoint.kind,
                claim.entrypoint.confidence,
            )
            for claim in item.claims
        }
        actual_unknowns = {
            tuple(
                unknown[name]
                for name in ("local_unknown_id", "category", "description", "evidence_limit")
            )
            for unknown in connection.execute(
                "SELECT * FROM review_unknown WHERE run_id=?", (row["run_id"],)
            )
        }
        expected_unknowns = {
            (unknown.unknown_id, unknown.category, unknown.description, unknown.evidence_limit)
            for unknown in item.unknowns
        }
        negative = connection.execute(
            "SELECT * FROM review_negative_assessment WHERE run_id=?", (row["run_id"],)
        ).fetchone()
        expected_negative = None
        if item.negative_assessment is not None:
            expected_negative = (
                1,
                _canonical_text(item.negative_assessment.searched_entrypoint_families),
                _canonical_text(item.negative_assessment.limitations),
            )
        actual_negative = (
            None
            if negative is None
            else (
                negative["changed_symbol_census_complete"],
                negative["searched_families_json"],
                negative["limitations_json"],
            )
        )
        if (
            actual_symbols != expected_symbols
            or actual_claims != expected_claims
            or actual_unknowns != expected_unknowns
            or actual_negative != expected_negative
        ):
            raise GroundTruthError("review normalized rows differ from immutable artifact")
        for claim in item.claims:
            claim_id = _id("review-claim", row["run_id"], claim.claim_id)
            _reconcile_edges(
                connection, "review_evidence_edge", "claim_id", claim_id, pr, claim.evidence
            )
    for row in connection.execute("SELECT * FROM adjudication ORDER BY adjudication_id"):
        if artifact_sha256(row["artifact_bytes"]) != row["artifact_sha256"]:
            raise GroundTruthError("adjudication exact artifact bytes were tampered")
        adjudication_item = cast(
            "AdjudicationArtifactV1",
            parse_artifact(row["artifact_bytes"], AdjudicationArtifactV1),
        )
        expected_adjudication_metadata = (
            adjudication_item.version,
            adjudication_item.adjudicator.kind,
            adjudication_item.adjudicator.name,
            adjudication_item.adjudicator.version,
            adjudication_item.run.prompt_sha256,
            adjudication_item.terminal_status,
            adjudication_item.reason,
        )
        actual_adjudication_metadata = tuple(
            row[name]
            for name in (
                "version",
                "adjudicator_kind",
                "adjudicator_name",
                "adjudicator_version",
                "prompt_sha256",
                "terminal_status",
                "reason",
            )
        )
        if actual_adjudication_metadata != expected_adjudication_metadata:
            raise GroundTruthError(
                "adjudication normalized metadata differs from immutable artifact"
            )
        pr = pr_by_id[row["pr_id"]]
        review_a = connection.execute(
            "SELECT artifact_sha256 FROM reviewer_run WHERE run_id=?",
            (row["review_a_run_id"],),
        ).fetchone()
        review_b = connection.execute(
            "SELECT artifact_sha256 FROM reviewer_run WHERE run_id=?",
            (row["review_b_run_id"],),
        ).fetchone()
        if (
            adjudication_item.corpus_id,
            adjudication_item.repository,
            adjudication_item.pr,
            adjudication_item.snapshots.baseline_commit,
            adjudication_item.snapshots.target_commit,
            adjudication_item.review_a_sha256,
            adjudication_item.review_b_sha256,
        ) != (
            corpus["corpus_id"],
            pr["full_name"],
            pr["number"],
            pr["baseline_commit"],
            pr["target_commit"],
            review_a["artifact_sha256"],
            review_b["artifact_sha256"],
        ):
            raise GroundTruthError("adjudication artifact PR/review binding was tampered")
        actual_decisions = {
            (
                decision["local_decision_id"],
                decision["decision_kind"],
                decision["outcome"],
                decision["attribution"],
                decision["rationale"],
                decision["public_id"],
                decision["kind"],
                decision["confidence"],
            )
            for decision in connection.execute(
                "SELECT d.*,e.public_id,e.kind,e.confidence FROM adjudication_decision d "
                "LEFT JOIN canonical_entrypoint e USING(decision_id) WHERE d.adjudication_id=?",
                (row["adjudication_id"],),
            )
        }
        expected_decisions = {
            (
                decision.decision_id,
                decision.decision_kind,
                decision.outcome,
                decision.attribution,
                decision.rationale,
                decision.canonical_entrypoint.public_id if decision.canonical_entrypoint else None,
                decision.canonical_entrypoint.kind if decision.canonical_entrypoint else None,
                decision.canonical_entrypoint.confidence if decision.canonical_entrypoint else None,
            )
            for decision in adjudication_item.decisions
        }
        if actual_decisions != expected_decisions:
            raise GroundTruthError("adjudication decision rows differ from immutable artifact")
        for decision in adjudication_item.decisions:
            decision_id = _id("decision", row["adjudication_id"], decision.decision_id)
            _reconcile_edges(
                connection,
                "adjudication_evidence_edge",
                "decision_id",
                decision_id,
                pr,
                decision.evidence,
            )
        _reconcile_adjudication_children(connection, row, adjudication_item)


def _reconcile_edges(
    connection: sqlite3.Connection,
    table: str,
    owner_column: str,
    owner_id: str,
    pr: sqlite3.Row,
    edges: Sequence[EvidenceEdge],
) -> None:
    actual = [
        (row["ordinal"], row["relation"], row["from_location_id"], row["to_location_id"])
        for row in connection.execute(
            f"SELECT * FROM {table} WHERE {owner_column}=? ORDER BY ordinal", (owner_id,)
        )
    ]
    expected = [
        (
            edge.ordinal,
            edge.relation,
            _location_identity(pr, edge.from_location),
            _location_identity(pr, edge.to_location),
        )
        for edge in edges
    ]
    if actual != expected:
        raise GroundTruthError("evidence edge rows differ from immutable artifact")


def _reconcile_adjudication_children(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    item: AdjudicationArtifactV1,
) -> None:
    actual_unknowns = {
        tuple(
            unknown[name]
            for name in ("local_unknown_id", "category", "description", "evidence_limit")
        )
        for unknown in connection.execute(
            "SELECT * FROM adjudication_unknown WHERE adjudication_id=?",
            (row["adjudication_id"],),
        )
    }
    expected_unknowns = {
        (unknown.unknown_id, unknown.category, unknown.description, unknown.evidence_limit)
        for unknown in item.unknowns
    }
    negative = connection.execute(
        "SELECT * FROM adjudication_negative_assessment WHERE adjudication_id=?",
        (row["adjudication_id"],),
    ).fetchone()
    expected_negative = None
    if item.negative_assessment is not None:
        expected_negative = (
            1,
            _canonical_text(item.negative_assessment.searched_entrypoint_families),
            _canonical_text(item.negative_assessment.limitations),
        )
    actual_negative = (
        None
        if negative is None
        else (
            negative["changed_symbol_census_complete"],
            negative["searched_families_json"],
            negative["limitations_json"],
        )
    )
    actual_sources: set[tuple[str, str, str, str]] = set()
    source_specs = (
        (
            "decision_source_claim",
            "review_claim",
            "claim_id",
            "local_claim_id",
            "claim",
        ),
        (
            "decision_source_unknown",
            "review_unknown",
            "unknown_id",
            "local_unknown_id",
            "unknown",
        ),
        (
            "decision_source_terminal",
            "reviewer_run",
            "run_id",
            None,
            "terminal",
        ),
        (
            "decision_source_negative",
            "review_negative_assessment",
            "run_id",
            None,
            "negative_assessment",
        ),
    )
    for source_table, target_table, target_id, local_id, kind in source_specs:
        local_expression = f"target.{local_id}" if local_id is not None else "''"
        for source in connection.execute(
            f"SELECT d.local_decision_id,r.lane,{local_expression} local_id "
            f"FROM {source_table} source JOIN adjudication_decision d USING(decision_id) "
            f"JOIN {target_table} target ON target.{target_id}=source.{target_id} "
            "JOIN reviewer_run r ON r.run_id=target.run_id "
            "WHERE d.adjudication_id=?",
            (row["adjudication_id"],),
        ):
            actual_sources.add(
                (source["local_decision_id"], source["lane"], kind, source["local_id"])
            )
    expected_sources = {
        (
            decision.decision_id,
            source.lane,
            source.source_kind,
            source.source_id or "",
        )
        for decision in item.decisions
        for source in decision.sources
    }
    actual_scopes = {
        (
            membership["local_decision_id"],
            membership["scope_id"],
            membership["scope_version"],
            membership["product"],
            membership["definition_sha256"],
            membership["status"],
            membership["rationale"],
        )
        for membership in connection.execute(
            "SELECT m.*,d.local_decision_id,s.product,s.definition_sha256 "
            "FROM scope_membership m JOIN adjudication_decision d USING(decision_id) "
            "JOIN scope_definition s USING(scope_id,scope_version) WHERE m.adjudication_id=?",
            (row["adjudication_id"],),
        )
    }
    expected_scopes = {
        (
            membership.decision_id,
            membership.scope_id,
            membership.scope_version,
            membership.product,
            membership.definition_sha256,
            membership.status,
            membership.rationale,
        )
        for membership in item.scope_memberships
    }
    if (
        actual_unknowns != expected_unknowns
        or actual_negative != expected_negative
        or actual_sources != expected_sources
        or actual_scopes != expected_scopes
    ):
        raise GroundTruthError("adjudication child rows differ from immutable artifact")


def _check_connection(connection: sqlite3.Connection) -> None:
    fk = connection.execute("PRAGMA foreign_key_check").fetchall()
    if fk:
        raise GroundTruthError(f"foreign key check failed: {fk[0]}")
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity != "ok":
        raise GroundTruthError(f"SQLite integrity check failed: {integrity}")


@contextmanager
def _output_lock(lock_path: Path) -> Iterator[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _validate_release_timestamp(value: str) -> None:
    if not value.endswith("Z"):
        raise GroundTruthError("release timestamp must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GroundTruthError("invalid release timestamp") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise GroundTruthError("release timestamp must be UTC")
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise GroundTruthError("release timestamp must use canonical UTC encoding")


def release(  # noqa: PLR0915 - one atomic publication orchestration
    db_path: Path,
    destination: Path,
    publication_review_raw: bytes,
    *,
    release_id: str,
    created_at: str,
    predecessor_release_id: str | None = None,
) -> dict[str, object]:
    """Publish canonical tables, broad truth, and versioned product sidecars."""
    publication = cast(
        "PublicationReviewV1", parse_artifact(publication_review_raw, PublicationReviewV1)
    )
    if publication.release_id != release_id:
        raise GroundTruthError("publication review release identity mismatch")
    _validate_release_timestamp(created_at)
    created = datetime.fromisoformat(created_at[:-1] + "+00:00")
    if created < publication.reviewed_at:
        raise GroundTruthError("release cannot predate its publication review")
    destination.parent.mkdir(parents=True, exist_ok=True)
    final = destination / release_id
    lock_path = destination.parent / f".{destination.name}.{release_id}.publication.lock"
    with writer_lock(db_path), _output_lock(lock_path), connect(db_path) as connection:
        if (
            final.exists()
            or connection.execute(
                "SELECT 1 FROM release WHERE release_id=?", (release_id,)
            ).fetchone()
        ):
            raise GroundTruthError("refusing to overwrite an existing release")
        if (
            predecessor_release_id is not None
            and connection.execute(
                "SELECT 1 FROM release WHERE release_id=?", (predecessor_release_id,)
            ).fetchone()
            is None
        ):
            raise GroundTruthError("predecessor release does not exist in this canonical store")
        corpus, prs = _corpus_index(connection)
        adjudications = _latest_adjudications(connection, corpus, prs)
        files = _release_files(connection, prs, adjudications)
        files["publication-review.json"] = publication_review_raw
        planned_membership = [
            {
                "release_id": release_id,
                "corpus_id": corpus["corpus_id"],
                "pr_id": pr["pr_id"],
                "adjudication_id": {row["pr_id"]: row for row in adjudications}[pr["pr_id"]][
                    "adjudication_id"
                ],
            }
            for pr in sorted(prs.values(), key=lambda item: item["pr_id"])
        ]
        migration_rows = [
            dict(row)
            for row in connection.execute(
                "SELECT version,name,sha256 FROM schema_migration ORDER BY version"
            )
        ]
        schema_hash = _schema_digest(connection)
        prompts = sorted(
            {
                row["prompt_sha256"]
                for row in connection.execute(
                    "SELECT prompt_sha256 FROM reviewer_run "
                    "UNION SELECT prompt_sha256 FROM adjudication"
                )
            }
        )
        prompt_hash = _root(
            "ground-truth-prompt-set-v1", ((value, value.encode()) for value in prompts)
        )
        publication_hash = artifact_sha256(publication_review_raw)
        planned_release: dict[str, object] = {
            "release_id": release_id,
            "schema_version": SCHEMA_VERSION,
            "corpus_id": corpus["corpus_id"],
            "corpus_sha256": corpus["lock_sha256"],
            "schema_sha256": schema_hash,
            "prompt_set_sha256": prompt_hash,
            "publication_review_sha256": publication_hash,
            "created_at": created_at,
            "predecessor_release_id": predecessor_release_id,
            "content_root": None,
            "manifest_bytes": None,
        }
        files.update(
            _canonical_table_files(
                connection,
                release_membership=planned_membership,
                publication_review_raw=publication_review_raw,
                publication=publication,
                planned_release=planned_release,
            )
        )
        file_meta = {
            name: {
                "rows": raw.count(b"\n"),
                "bytes": len(raw),
                "sha256": artifact_sha256(raw),
            }
            for name, raw in sorted(files.items())
        }
        canonical_tables = {
            name.removeprefix("tables/").removesuffix(".jsonl"): meta
            for name, meta in file_meta.items()
            if name.startswith("tables/")
        }
        counts = dict.fromkeys(("positive", "negative_control", "unknown", "not_evaluable"), 0)
        for row in adjudications:
            counts[row["terminal_status"]] += 1
        if sum(counts.values()) != corpus["selected_count"]:
            raise GroundTruthError("terminal denominators do not sum to selected PRs")
        manifest_payload: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "release_id": release_id,
            "predecessor_release_id": predecessor_release_id,
            "created_at": created_at,
            "corpus_id": corpus["corpus_id"],
            "corpus_lock_sha256": corpus["lock_sha256"],
            "migrations": migration_rows,
            "schema_sha256": schema_hash,
            "prompt_hashes": prompts,
            "prompt_set_sha256": prompt_hash,
            "selected_prs": corpus["selected_count"],
            "terminal_counts": counts,
            "files": file_meta,
            "canonical_tables": canonical_tables,
            "publication_review_sha256": artifact_sha256(publication_review_raw),
            "content_root_algorithm": "sha256-canonical-manifest-payload-v2",
            "prediction_boundary": (
                "predictions, scores, route census, and vendor output were unavailable "
                "and are excluded"
            ),
            "raw_artifact_publication": (
                "hash and byte count only; exact immutable bytes retained in canonical store"
            ),
        }
        content_root = artifact_sha256(
            b"ground-truth-release-manifest-v2\0" + canonical_json(manifest_payload)
        )
        manifest = {**manifest_payload, "content_root": content_root}
        manifest_raw = canonical_json(manifest)
        temporary = Path(tempfile.mkdtemp(prefix=f".{release_id}.", dir=destination.parent))
        published_here = False
        try:
            output = temporary / release_id
            output.mkdir()
            for name, raw in sorted(files.items()):
                _write_fsync(output / name, raw)
            _write_fsync(output / "manifest.json", manifest_raw)
            descriptor = os.open(output, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            destination.mkdir(parents=True, exist_ok=True)
            connection.execute("BEGIN IMMEDIATE")
            try:
                pub_hash = artifact_sha256(publication_review_raw)
                connection.execute(
                    "INSERT INTO publication_review VALUES(?,?,?,?,?,?)",
                    (
                        _id("publication-review", pub_hash),
                        pub_hash,
                        publication_review_raw,
                        release_id,
                        publication.reviewer.name,
                        _timestamp(publication.reviewed_at),
                    ),
                )
                connection.execute(
                    "INSERT INTO release VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        release_id,
                        SCHEMA_VERSION,
                        corpus["corpus_id"],
                        corpus["lock_sha256"],
                        schema_hash,
                        prompt_hash,
                        pub_hash,
                        created_at,
                        predecessor_release_id,
                        content_root,
                        manifest_raw,
                    ),
                )
                for membership in planned_membership:
                    connection.execute(
                        "INSERT INTO release_pr VALUES(?,?,?,?)",
                        tuple(membership.values()),
                    )
                output.rename(final)
                published_here = True
                connection.commit()
            except Exception:
                connection.rollback()
                if published_here:
                    shutil.rmtree(final)
                raise
        finally:
            shutil.rmtree(temporary, ignore_errors=True)
        return manifest


def _latest_adjudications(
    connection: sqlite3.Connection,
    corpus: sqlite3.Row,
    prs: dict[str, sqlite3.Row],
) -> list[sqlite3.Row]:
    adjudications: list[sqlite3.Row] = []
    for pr in prs.values():
        rows = connection.execute(
            "SELECT * FROM adjudication WHERE pr_id=? ORDER BY version DESC", (pr["pr_id"],)
        ).fetchall()
        if not rows:
            raise GroundTruthError(
                "release requires one terminal adjudication for every selected PR"
            )
        latest = rows[0]
        if any(row["supersedes_id"] == latest["adjudication_id"] for row in rows):
            raise GroundTruthError("latest adjudication selection is inconsistent")
        adjudications.append(latest)
    if len(adjudications) != corpus["selected_count"]:
        raise GroundTruthError("release adjudication denominator does not match corpus")
    return adjudications


def _release_files(
    connection: sqlite3.Connection,
    prs: dict[str, sqlite3.Row],
    adjudications: Sequence[sqlite3.Row],
) -> dict[str, bytes]:
    pr_by_id = {row["pr_id"]: row for row in prs.values()}
    broad: list[dict[str, object]] = []
    adjudication_projection: list[dict[str, object]] = []
    ordered_adjudications = sorted(
        adjudications,
        key=lambda row: (
            pr_by_id[row["pr_id"]]["full_name"].casefold(),
            pr_by_id[row["pr_id"]]["rank"],
        ),
    )
    for adjudication in ordered_adjudications:
        pr = pr_by_id[adjudication["pr_id"]]
        entrypoints = [
            {"id": row["public_id"], "kind": row["kind"], "confidence": row["confidence"]}
            for row in connection.execute(
                "SELECT e.* FROM canonical_entrypoint e WHERE e.adjudication_id=? "
                "ORDER BY e.public_id,e.kind,e.entrypoint_id",
                (adjudication["adjudication_id"],),
            )
        ]
        terminal = adjudication["terminal_status"]
        broad.append(
            {
                "repository": pr["full_name"],
                "pr": pr["number"],
                "status": "adjudicated"
                if terminal in {"positive", "negative_control"}
                else terminal,
                "terminal_status": terminal,
                "affected_entrypoints": entrypoints,
            }
        )
        adjudication_projection.append(
            {
                "repository": pr["full_name"],
                "pr": pr["number"],
                "version": adjudication["version"],
                "artifact_sha256": adjudication["artifact_sha256"],
                "terminal_status": terminal,
            }
        )
    reviews = [
        {
            "repository": row["full_name"],
            "pr": row["number"],
            "lane": row["lane"],
            "artifact_sha256": row["artifact_sha256"],
            "terminal_recommendation": row["terminal_recommendation"],
        }
        for row in connection.execute(
            "SELECT r.*,p.number,x.full_name FROM reviewer_run r "
            "JOIN pull_request p USING(pr_id) JOIN repository x USING(repository_id) "
            "ORDER BY x.full_name_casefold,p.rank,r.lane"
        )
    ]
    artifacts = [
        {
            "artifact_type": "review",
            "sha256": row["artifact_sha256"],
            "bytes": len(row["artifact_bytes"]),
        }
        for row in connection.execute(
            "SELECT artifact_sha256,artifact_bytes FROM reviewer_run ORDER BY artifact_sha256"
        )
    ] + [
        {
            "artifact_type": "adjudication",
            "sha256": row["artifact_sha256"],
            "bytes": len(row["artifact_bytes"]),
        }
        for row in connection.execute(
            "SELECT artifact_sha256,artifact_bytes FROM adjudication ORDER BY artifact_sha256"
        )
    ]
    files = {
        "broad-truth.jsonl": b"".join(canonical_json(row) for row in broad),
        "reviews.jsonl": b"".join(canonical_json(row) for row in reviews),
        "adjudications.jsonl": b"".join(canonical_json(row) for row in adjudication_projection),
        "artifact-index.jsonl": b"".join(canonical_json(row) for row in artifacts),
    }
    selected_ids = {row["adjudication_id"] for row in adjudications}
    scopes = connection.execute(
        "SELECT DISTINCT s.* FROM scope_definition s JOIN scope_membership m "
        "USING(scope_id,scope_version) ORDER BY s.scope_id,s.scope_version"
    ).fetchall()
    for scope in scopes:
        sidecar: list[dict[str, object]] = []
        for adjudication in ordered_adjudications:
            pr = pr_by_id[adjudication["pr_id"]]
            entrypoints = [
                {"id": row["public_id"], "kind": row["kind"], "confidence": row["confidence"]}
                for row in connection.execute(
                    "SELECT e.* FROM scope_membership m JOIN canonical_entrypoint e "
                    "USING(decision_id) WHERE m.adjudication_id=? AND m.scope_id=? "
                    "AND m.scope_version=? "
                    "AND m.status='in_scope' ORDER BY e.public_id,e.kind,e.entrypoint_id",
                    (adjudication["adjudication_id"], scope["scope_id"], scope["scope_version"]),
                )
            ]
            sidecar.append(
                {
                    "repository": pr["full_name"],
                    "pr": pr["number"],
                    "terminal_status": adjudication["terminal_status"],
                    "scope_id": scope["scope_id"],
                    "scope_version": scope["scope_version"],
                    "product": scope["product"],
                    "definition_sha256": scope["definition_sha256"],
                    "affected_entrypoints": entrypoints,
                }
            )
        if any(
            row["adjudication_id"] in selected_ids
            for row in connection.execute(
                "SELECT DISTINCT adjudication_id FROM scope_membership "
                "WHERE scope_id=? AND scope_version=?",
                (scope["scope_id"], scope["scope_version"]),
            )
        ):
            files[f"product-scopes/{scope['scope_id']}-v{scope['scope_version']}.jsonl"] = b"".join(
                canonical_json(row) for row in sidecar
            )
    return files


def _project_table_row(db_row: sqlite3.Row) -> dict[str, object]:
    projected: dict[str, object] = {}
    for key in db_row.keys():  # noqa: SIM118 - sqlite3.Row iterates values
        value = db_row[key]
        if isinstance(value, bytes):
            projected[key] = {"sha256": artifact_sha256(value), "bytes": len(value)}
        else:
            projected[key] = value
    return projected


def _canonical_table_files(
    connection: sqlite3.Connection,
    *,
    release_membership: Sequence[dict[str, object]],
    publication_review_raw: bytes,
    publication: PublicationReviewV1,
    planned_release: dict[str, object],
) -> dict[str, bytes]:
    """Export canonical tables in PK order with explicit nonrecursive release markers."""
    tables = [
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' "
            "ORDER BY name"
        )
    ]
    result: dict[str, bytes] = {}
    for table in tables:
        info = connection.execute(f"PRAGMA table_info({table})").fetchall()
        primary = [
            row["name"] for row in sorted(info, key=lambda item: item["pk"]) if row["pk"] > 0
        ]
        order = ",".join(f'"{name}"' for name in primary) or "rowid"
        rows = [
            _project_table_row(row)
            for row in connection.execute(f'SELECT * FROM "{table}" ORDER BY {order}')
        ]
        if table == "release_pr":
            rows.extend(dict(row) for row in release_membership)
        elif table == "publication_review":
            digest = artifact_sha256(publication_review_raw)
            rows.append(
                {
                    "publication_review_id": _id("publication-review", digest),
                    "artifact_sha256": digest,
                    "artifact_bytes": {"sha256": digest, "bytes": len(publication_review_raw)},
                    "release_id": publication.release_id,
                    "reviewer_name": publication.reviewer.name,
                    "reviewed_at": _timestamp(publication.reviewed_at),
                }
            )
        elif table == "release":
            current_release = {
                **planned_release,
                "content_root": {"self_reference": "manifest.json#content_root"},
                "manifest_bytes": {"self_reference": "manifest.json"},
            }
            rows.append(current_release)
        rows.sort(key=lambda row: tuple(str(row.get(name, "")) for name in primary))
        result[f"tables/{table}.jsonl"] = b"".join(canonical_json(row) for row in rows)
    return result


def _write_fsync(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("database", type=Path)
    args = parser.parse_args(argv)
    if args.command == "validate":
        print(json.dumps(validate_database(args.database), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
