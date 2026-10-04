#!/usr/bin/env python3
"""Read-only integrity gate for canonical ground-truth v2 release directories."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, cast

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.real_world.benchmark_schema import (
    BenchmarkSchemaError,
    _validate_record,
)
from benchmarks.real_world.ground_truth_v2 import GroundTruthError
from benchmarks.real_world.ground_truth_v2.schema import (
    PublicationReviewV1,
    artifact_sha256,
    canonical_json,
    parse_artifact,
)

TERMINAL = {"positive", "negative_control", "unknown", "not_evaluable"}
COUNTS = set(TERMINAL)
REQUIRED_RELEASE_FILES = {
    "broad-truth.jsonl",
    "reviews.jsonl",
    "adjudications.jsonl",
    "artifact-index.jsonl",
    "publication-review.json",
}
REQUIRED_CANONICAL_TABLES = {
    "schema_migration",
    "corpus",
    "repository",
    "pull_request",
    "snapshot",
    "remote_diff",
    "import_batch",
    "evidence_location",
    "reviewer_run",
    "review_changed_symbol",
    "review_claim",
    "review_entrypoint",
    "review_evidence_edge",
    "review_unknown",
    "review_negative_assessment",
    "adjudication",
    "adjudication_decision",
    "decision_source_claim",
    "decision_source_terminal",
    "decision_source_unknown",
    "decision_source_negative",
    "canonical_entrypoint",
    "adjudication_evidence_edge",
    "adjudication_unknown",
    "adjudication_negative_assessment",
    "scope_definition",
    "scope_membership",
    "publication_review",
    "release",
    "release_pr",
}


def _fail(message: str) -> NoReturn:
    raise GroundTruthError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_non_finite(token: str) -> None:
    _fail(f"non-finite JSON constant: {token}")


def _loads(raw: str | bytes) -> Any:
    return json.loads(
        raw,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_non_finite,
    )


def verify_release(  # noqa: PLR0912, PLR0915
    directory: Path, *, expected_content_root: str | None = None
) -> dict[str, Any]:
    """Validate release self-hash, every declared file, and terminal denominators."""
    # Check the supplied path before resolving it: resolving first hides symlink aliases.
    supplied = Path(directory).absolute()
    if any(part.is_symlink() for part in (supplied, *supplied.parents)):
        _fail("release path and its ancestors must not be symlinks")
    try:
        root = supplied.resolve(strict=True)
    except OSError as exc:
        raise GroundTruthError("release directory is missing or inaccessible") from exc
    if not root.is_dir():
        _fail("release path must be a real directory")
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        _fail("release manifest is missing or not a regular file")
    try:
        raw_manifest = manifest_path.read_bytes()
    except OSError as exc:
        raise GroundTruthError("release manifest is missing or unreadable") from exc
    try:
        manifest = _loads(raw_manifest)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise GroundTruthError("release manifest is invalid JSON") from exc
    if (
        not isinstance(manifest, dict)
        or type(manifest.get("schema_version")) is not int
        or manifest["schema_version"] != 1
    ):
        _fail("expected ground-truth release schema version 1")
    if manifest.get("content_root_algorithm") != "sha256-canonical-manifest-payload-v2":
        _fail("unsupported release content-root algorithm")
    root_hash = manifest.get("content_root")
    payload = {key: value for key, value in manifest.items() if key != "content_root"}
    expected_root = (
        "sha256:"
        + hashlib.sha256(
            b"ground-truth-release-manifest-v2\0" + canonical_json(payload)
        ).hexdigest()
    )
    if root_hash != expected_root:
        _fail("release manifest content root mismatch")
    if expected_content_root is not None and root_hash != expected_content_root:
        _fail("release content root does not match trusted expected root")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        _fail("release manifest file inventory is missing")
    if not REQUIRED_RELEASE_FILES.issubset(files):
        _fail("release manifest is missing mandatory release members")
    canonical_tables = manifest.get("canonical_tables")
    table_names = {
        name.removeprefix("tables/").removesuffix(".jsonl")
        for name in files
        if isinstance(name, str) and name.startswith("tables/") and name.endswith(".jsonl")
    }
    if (
        not isinstance(canonical_tables, dict)
        or set(canonical_tables) != table_names
        or not REQUIRED_CANONICAL_TABLES.issubset(table_names)
    ):
        _fail("release manifest is missing mandatory canonical tables")
    if any(canonical_tables[name] != files[f"tables/{name}.jsonl"] for name in canonical_tables):
        _fail("canonical table metadata does not match the release file inventory")
    expected_names = {"manifest.json"} | set(files)
    observed_names: set[str] = set()
    verified_contents: dict[str, bytes] = {}
    for name, metadata in files.items():
        relative = PurePosixPath(name) if isinstance(name, str) else None
        if (
            relative is None
            or relative.is_absolute()
            or ".." in relative.parts
            or not relative.parts
            or relative.as_posix() != name
            or any(part in {"", "."} for part in name.split("/"))
            or not isinstance(metadata, dict)
        ):
            _fail("release manifest contains an unsafe file entry")
        path = root.joinpath(*relative.parts)
        try:
            cursor = root
            for component in relative.parts:
                cursor = cursor / component
                if cursor.is_symlink():
                    _fail(f"release path contains a symlink: {name}")
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise GroundTruthError(f"release file is missing: {name}") from exc
        if root not in resolved.parents or not resolved.is_file():
            _fail(f"release file is not a contained regular file: {name}")
        content = resolved.read_bytes()
        if (
            type(metadata.get("bytes")) is not int
            or metadata["bytes"] != len(content)
            or not isinstance(metadata.get("sha256"), str)
            or metadata.get("sha256") != "sha256:" + hashlib.sha256(content).hexdigest()
            or type(metadata.get("rows")) is not int
            or metadata["rows"] != content.count(b"\n")
        ):
            _fail(f"release file metadata mismatch: {name}")
        observed_names.add(name)
        verified_contents[name] = content
    actual_names: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            _fail("release directory contains a symlink")
        if path.is_file():
            actual_names.add(path.relative_to(root).as_posix())
    if actual_names != expected_names:
        _fail("release directory has undeclared or missing files")

    publication_raw = verified_contents.get("publication-review.json")
    if publication_raw is None:
        _fail("release publication review is missing")
    try:
        publication = cast(
            "PublicationReviewV1",
            parse_artifact(publication_raw, PublicationReviewV1),
        )
    except GroundTruthError as exc:
        raise GroundTruthError("publication review is invalid") from exc
    if publication.release_id != manifest.get("release_id"):
        _fail("publication review release identity mismatch")
    if manifest.get("publication_review_sha256") != artifact_sha256(publication_raw):
        _fail("publication review hash does not match manifest")

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
    truth_raw = verified_contents.get("broad-truth.jsonl")
    if truth_raw is None:
        _fail("release manifest does not declare broad truth")
    records: dict[tuple[str, int], str] = {}
    truth_entrypoints: dict[tuple[str, int], list[dict[str, Any]]] = {}
    try:
        truth_lines = truth_raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise GroundTruthError("broad-truth artifact is missing or unreadable") from exc
    for line_number, line in enumerate(truth_lines, 1):
        if not line:
            _fail(f"blank broad-truth row at line {line_number}")
        try:
            row = _loads(line)
        except json.JSONDecodeError as exc:
            raise GroundTruthError(f"invalid broad-truth JSON at line {line_number}") from exc
        if not isinstance(row, dict):
            _fail(f"malformed broad-truth row at line {line_number}")
        repo, pr, status, terminal = (
            row.get("repository"),
            row.get("pr"),
            row.get("status"),
            row.get("terminal_status"),
        )
        if (
            not isinstance(repo, str)
            or not repo
            or type(pr) is not int
            or pr < 1
            or not isinstance(terminal, str)
            or terminal not in TERMINAL
            or not isinstance(status, str)
            or status
            != ("adjudicated" if terminal in {"positive", "negative_control"} else terminal)
        ):
            _fail(f"invalid terminal truth row at line {line_number}")
        try:
            _validate_record(row, "ground_truth", f"broad-truth line {line_number}")
        except BenchmarkSchemaError as exc:
            raise GroundTruthError(
                f"invalid broad-truth record at line {line_number}: {exc}"
            ) from exc
        key = (repo, pr)
        if key in records:
            _fail(f"duplicate broad-truth record: {key}")
        records[key] = terminal
        truth_entrypoints[key] = row["affected_entrypoints"]
    actual_counts = {terminal: list(records.values()).count(terminal) for terminal in TERMINAL}
    if len(records) != selected or actual_counts != counts:
        _fail("broad-truth rows do not match selected and terminal denominators")
    expected_release = _release_truth(verified_contents, manifest, selected)
    _verify_product_scopes(verified_contents, manifest)
    if set(records) != set(expected_release):
        _fail("broad-truth identities do not match release membership")
    for identity, terminal in records.items():
        expected_terminal, expected_entrypoints = expected_release[identity]
        if terminal != expected_terminal:
            _fail("broad-truth terminal status does not match canonical adjudication")
        if truth_entrypoints[identity] != expected_entrypoints:
            _fail("broad-truth entrypoints do not match canonical adjudication")
    adjudication_raw = verified_contents.get("adjudications.jsonl")
    if adjudication_raw is None:
        _fail("release adjudication projection is missing")
    adjudication_records = _jsonl_adjudications(adjudication_raw)
    if adjudication_records != records:
        _fail("broad-truth rows do not match adjudication projection")
    return {
        "release_id": manifest.get("release_id"),
        "content_root": root_hash,
        "selected_prs": selected,
        "terminal_counts": counts,
        "files_verified": len(files),
        "truth_rows_verified": len(records),
        "verification_mode": "anchored" if expected_content_root is not None else "integrity_only",
    }


def _jsonl_rows(raw: bytes, name: str) -> list[dict[str, Any]]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise GroundTruthError(f"release table is missing or unreadable: {name}") from exc
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        try:
            row = _loads(line)
        except (json.JSONDecodeError, GroundTruthError) as exc:
            raise GroundTruthError(f"invalid release table row at {name}:{line_number}") from exc
        if not isinstance(row, dict):
            _fail(f"malformed release table row at {name}:{line_number}")
        rows.append(row)
    return rows


def _jsonl_adjudications(raw: bytes) -> dict[tuple[str, int], str]:
    adjudications: dict[tuple[str, int], str] = {}
    name = "adjudications.jsonl"
    for row in _jsonl_rows(raw, name):
        repository, number, terminal = (
            row.get("repository"),
            row.get("pr"),
            row.get("terminal_status"),
        )
        if (
            not isinstance(repository, str)
            or not repository
            or type(number) is not int
            or number < 1
            or not isinstance(terminal, str)
            or terminal not in TERMINAL
        ):
            _fail(f"invalid adjudication row in {name}")
        identity = (repository, number)
        if identity in adjudications:
            _fail(f"duplicate adjudication identity in {name}: {identity}")
        adjudications[identity] = terminal
    return adjudications


def _release_truth(  # noqa: PLR0912, PLR0915
    contents: dict[str, bytes], manifest: dict[str, Any], selected: int
) -> dict[tuple[str, int], tuple[str, list[dict[str, Any]]]]:
    release_id, corpus_id = manifest.get("release_id"), manifest.get("corpus_id")
    if not isinstance(release_id, str) or not release_id:
        _fail("release id is missing")
    if not isinstance(corpus_id, str) or not corpus_id:
        _fail("release corpus id is missing")
    corpus_rows = _jsonl_rows(contents["tables/corpus.jsonl"], "tables/corpus.jsonl")
    if (
        len(corpus_rows) != 1
        or corpus_rows[0].get("corpus_id") != corpus_id
        or type(corpus_rows[0].get("selected_count")) is not int
        or corpus_rows[0]["selected_count"] != selected
    ):
        _fail("canonical corpus table does not match release identity and count")
    repositories: dict[str, str] = {}
    for row in _jsonl_rows(contents["tables/repository.jsonl"], "tables/repository.jsonl"):
        repository_id, full_name = row.get("repository_id"), row.get("full_name")
        if (
            not isinstance(repository_id, str)
            or not repository_id
            or not isinstance(full_name, str)
            or not full_name
            or row.get("corpus_id") != corpus_id
            or repository_id in repositories
        ):
            _fail("canonical repository row has invalid or foreign corpus identity")
        repositories[repository_id] = full_name
    pull_requests: dict[str, tuple[str, int]] = {}
    for row in _jsonl_rows(contents["tables/pull_request.jsonl"], "tables/pull_request.jsonl"):
        pr_id = row.get("pr_id")
        repository_id = row.get("repository_id")
        repository = repositories.get(repository_id) if isinstance(repository_id, str) else None
        number = row.get("number")
        if (
            not isinstance(pr_id, str)
            or not pr_id
            or pr_id in pull_requests
            or row.get("corpus_id") != corpus_id
            or not isinstance(repository, str)
            or type(number) is not int
            or number < 1
        ):
            _fail("canonical pull-request row has invalid or foreign corpus identity")
        pull_requests[pr_id] = (repository, number)
    if len(pull_requests) != selected:
        _fail("canonical pull-request rows do not match selected corpus count")
    adjudications: dict[str, dict[str, Any]] = {}
    for row in _jsonl_rows(contents["tables/adjudication.jsonl"], "tables/adjudication.jsonl"):
        adjudication_id = row.get("adjudication_id")
        pr_id = row.get("pr_id")
        if (
            not isinstance(adjudication_id, str)
            or not adjudication_id
            or adjudication_id in adjudications
            or not isinstance(pr_id, str)
            or pr_id not in pull_requests
        ):
            _fail("canonical adjudication table contains invalid or duplicate identities")
        adjudications[adjudication_id] = row
    entrypoints: dict[str, list[dict[str, Any]]] = {}
    for row in _jsonl_rows(
        contents["tables/canonical_entrypoint.jsonl"], "tables/canonical_entrypoint.jsonl"
    ):
        adjudication_id = row.get("adjudication_id")
        public_id, kind, confidence = (
            row.get("public_id"),
            row.get("kind"),
            row.get("confidence"),
        )
        if (
            not isinstance(adjudication_id, str)
            or not isinstance(public_id, str)
            or not isinstance(kind, str)
            or not isinstance(row.get("entrypoint_id"), str)
            or not isinstance(confidence, str)
        ):
            _fail("canonical entrypoint table contains a malformed row")
        entrypoints.setdefault(adjudication_id, []).append(row)
    for rows in entrypoints.values():
        rows.sort(key=lambda item: (item["public_id"], item["kind"], item["entrypoint_id"]))
    memberships = _jsonl_rows(contents["tables/release_pr.jsonl"], "tables/release_pr.jsonl")
    expected: dict[tuple[str, int], tuple[str, list[dict[str, Any]]]] = {}
    for row in memberships:
        if row.get("release_id") != release_id:
            continue
        if row.get("corpus_id") != corpus_id:
            _fail("release membership has the wrong corpus id")
        pr_id = row.get("pr_id")
        identity = pull_requests.get(pr_id) if isinstance(pr_id, str) else None
        if (
            identity is None
            or not isinstance(identity[0], str)
            or not identity[0]
            or type(identity[1]) is not int
            or identity[1] < 1
        ):
            _fail("release membership references an unknown pull request")
        adjudication_id = row.get("adjudication_id")
        adjudication = (
            adjudications.get(adjudication_id) if isinstance(adjudication_id, str) else None
        )
        if (
            not isinstance(adjudication_id, str)
            or adjudication is None
            or adjudication.get("pr_id") != pr_id
            or not isinstance(adjudication.get("terminal_status"), str)
            or adjudication.get("terminal_status") not in TERMINAL
        ):
            _fail("release membership references an invalid canonical adjudication")
        key = (identity[0], identity[1])
        if key in expected:
            _fail(f"release membership contains duplicate pull request identities: {key}")
        expected[key] = (
            adjudication["terminal_status"],
            [
                {
                    "id": atom["public_id"],
                    "kind": atom["kind"],
                    "confidence": atom["confidence"],
                }
                for atom in entrypoints.get(adjudication_id, [])
            ],
        )
    if len(expected) != len([row for row in memberships if row.get("release_id") == release_id]):
        _fail("release membership contains duplicate pull request identities")
    return expected


def _verify_product_scopes(  # noqa: PLR0912, PLR0915
    contents: dict[str, bytes], manifest: dict[str, Any]
) -> None:
    """Reconcile public product-scope sidecars with canonical table snapshots."""
    release_id = manifest.get("release_id")
    corpus_id = manifest.get("corpus_id")
    if not isinstance(release_id, str) or not isinstance(corpus_id, str):
        _fail("release identity is missing while verifying product scopes")
    repositories: dict[str, str] = {}
    for row in _jsonl_rows(contents["tables/repository.jsonl"], "tables/repository.jsonl"):
        repository_id, full_name = row.get("repository_id"), row.get("full_name")
        if (
            not isinstance(repository_id, str)
            or not isinstance(full_name, str)
            or not full_name
            or repository_id in repositories
        ):
            _fail("repository table contains a malformed product-scope identity")
        repositories[repository_id] = full_name
    pull_requests: dict[str, tuple[str | None, object, object]] = {}
    for row in _jsonl_rows(contents["tables/pull_request.jsonl"], "tables/pull_request.jsonl"):
        pr_id, repository_id = row.get("pr_id"), row.get("repository_id")
        if (
            not isinstance(pr_id, str)
            or not isinstance(repository_id, str)
            or pr_id in pull_requests
        ):
            _fail("pull request table contains a malformed product-scope identity")
        pull_requests[pr_id] = (
            repositories.get(repository_id),
            row.get("number"),
            row.get("rank"),
        )
    selected_rows: list[tuple[str, str, int, int]] = []
    adjudications: dict[str, str] = {}
    adjudication_prs: dict[str, str] = {}
    adjudication_terminals: dict[str, str] = {}
    for row in _jsonl_rows(contents["tables/adjudication.jsonl"], "tables/adjudication.jsonl"):
        adjudication_id, terminal, pr_id = (
            row.get("adjudication_id"),
            row.get("terminal_status"),
            row.get("pr_id"),
        )
        if (
            not isinstance(adjudication_id, str)
            or not isinstance(terminal, str)
            or not isinstance(pr_id, str)
            or terminal not in TERMINAL
            or adjudication_id in adjudication_terminals
        ):
            _fail("canonical adjudication table contains a malformed or duplicate row")
        adjudication_prs[adjudication_id] = pr_id
        adjudication_terminals[adjudication_id] = terminal
    for row in _jsonl_rows(contents["tables/release_pr.jsonl"], "tables/release_pr.jsonl"):
        if row.get("release_id") != release_id:
            continue
        if row.get("corpus_id") != corpus_id:
            _fail("release product-scope membership has the wrong corpus")
        pr_id, adjudication_id = row.get("pr_id"), row.get("adjudication_id")
        if not isinstance(pr_id, str) or not isinstance(adjudication_id, str):
            _fail("release product-scope membership is malformed")
        identity = pull_requests.get(pr_id)
        if (
            identity is None
            or not isinstance(identity[0], str)
            or type(identity[1]) is not int
            or type(identity[2]) is not int
            or adjudication_id in adjudications
            or adjudication_terminals.get(adjudication_id) not in TERMINAL
        ):
            _fail("release product-scope membership is malformed")
        if adjudication_prs.get(adjudication_id) != pr_id:
            _fail("release product-scope membership references the wrong adjudication PR")
        adjudications[adjudication_id] = pr_id
        selected_rows.append((adjudication_id, identity[0], identity[1], identity[2]))
    selected_rows.sort(key=lambda item: (item[1].casefold(), item[3]))

    canonical_entrypoints: dict[str, tuple[str, str, dict[str, str]]] = {}
    for row in _jsonl_rows(
        contents["tables/canonical_entrypoint.jsonl"], "tables/canonical_entrypoint.jsonl"
    ):
        decision_id = row.get("decision_id")
        public_id, kind, confidence = (
            row.get("public_id"),
            row.get("kind"),
            row.get("confidence"),
        )
        adjudication_id, pr_id = row.get("adjudication_id"), row.get("pr_id")
        if (
            not isinstance(decision_id, str)
            or not isinstance(adjudication_id, str)
            or not isinstance(pr_id, str)
            or not isinstance(public_id, str)
            or not isinstance(kind, str)
            or not isinstance(confidence, str)
            or decision_id in canonical_entrypoints
        ):
            _fail("canonical entrypoint table contains a malformed or duplicate row")
        canonical_entrypoints[decision_id] = (
            adjudication_id,
            pr_id,
            {"id": public_id, "kind": kind, "confidence": confidence},
        )

    definitions: dict[tuple[str, int], tuple[str, str]] = {}
    for row in _jsonl_rows(
        contents["tables/scope_definition.jsonl"], "tables/scope_definition.jsonl"
    ):
        scope_id, version = row.get("scope_id"), row.get("scope_version")
        product, digest = row.get("product"), row.get("definition_sha256")
        if (
            not isinstance(scope_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", scope_id) is None
            or type(version) is not int
            or version < 1
            or not isinstance(product, str)
            or not product
            or not isinstance(digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
            or (scope_id, version) in definitions
        ):
            _fail("product scope definition table contains a malformed or duplicate row")
        definitions[(scope_id, version)] = (product, digest)

    in_scope: dict[tuple[str, int, str], list[dict[str, str]]] = {}
    defined_scopes: set[tuple[str, int]] = set()
    seen_memberships: set[tuple[str, str, str, int]] = set()
    for row in _jsonl_rows(
        contents["tables/scope_membership.jsonl"], "tables/scope_membership.jsonl"
    ):
        adjudication_id = row.get("adjudication_id")
        if not isinstance(adjudication_id, str) or adjudication_id not in adjudications:
            continue
        decision_id = row.get("decision_id")
        pr_id = row.get("pr_id")
        scope_id, version, status = (
            row.get("scope_id"),
            row.get("scope_version"),
            row.get("status"),
        )
        if (
            not isinstance(decision_id, str)
            or not isinstance(pr_id, str)
            or not isinstance(scope_id, str)
            or type(version) is not int
            or (scope_id, version) not in definitions
            or status not in {"in_scope", "out_of_scope"}
        ):
            _fail("product scope membership table contains a malformed selected row")
        membership_key = (adjudication_id, decision_id, scope_id, version)
        if membership_key in seen_memberships:
            _fail("product scope membership table contains a duplicate selected row")
        seen_memberships.add(membership_key)
        defined_scopes.add((scope_id, version))
        entrypoint_record = canonical_entrypoints.get(decision_id)
        if (
            entrypoint_record is None
            or entrypoint_record[0] != adjudication_id
            or entrypoint_record[1] != pr_id
            or adjudication_prs.get(adjudication_id) != pr_id
        ):
            _fail("product scope membership references a missing canonical entrypoint")
        if status == "in_scope":
            in_scope.setdefault((scope_id, version, adjudication_id), []).append(
                entrypoint_record[2]
            )

    expected_files: dict[str, list[dict[str, Any]]] = {}
    for scope_id, version in sorted(defined_scopes):
        product, digest = definitions[(scope_id, version)]
        filename = f"product-scopes/{scope_id}-v{version}.jsonl"
        projection: list[dict[str, Any]] = []
        for adjudication_id, repository, number, _rank in selected_rows:
            entrypoints = sorted(
                in_scope.get((scope_id, version, adjudication_id), ()),
                key=lambda item: (item["id"], item["kind"], item["confidence"]),
            )
            projection.append(
                {
                    "repository": repository,
                    "pr": number,
                    "terminal_status": adjudication_terminals.get(adjudication_id),
                    "scope_id": scope_id,
                    "scope_version": version,
                    "product": product,
                    "definition_sha256": digest,
                    "affected_entrypoints": entrypoints,
                }
            )
        expected_files[filename] = projection

    observed_names = {name for name in contents if name.startswith("product-scopes/")}
    if observed_names != set(expected_files):
        _fail("product-scope files do not match canonical scope memberships")
    for name, expected_rows in expected_files.items():
        actual_rows = _jsonl_rows(contents[name], name)
        if sorted(canonical_json(row) for row in actual_rows) != sorted(
            canonical_json(row) for row in expected_rows
        ):
            _fail("product-scope projection does not match canonical scope membership")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release", type=Path, help="directory containing manifest.json")
    parser.add_argument(
        "--expected-content-root",
        help="independently trusted sha256 content root to require",
    )
    args = parser.parse_args()
    print(
        json.dumps(
            verify_release(args.release, expected_content_root=args.expected_content_root),
            sort_keys=True,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
