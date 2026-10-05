#!/usr/bin/env python3
"""Evaluate six audited PRs and nine source-backed non-Python route atoms.

Third-party snapshots are read as strings only. Trusted scanner code is loaded
from an exact internal PR #310 commit in the local repository object database.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

SCANNER_COMMIT = "84efc3d877c2d93a25bdd2c625120e6a6d918139"
HISTORICAL_SCANNER_COMMIT = "1d9242d0d1d411b529c3227918aa2d05e98e8943"
TRUSTED_SCANNER_COMMITS = frozenset({SCANNER_COMMIT, HISTORICAL_SCANNER_COMMIT})
CLIENT_SCANNER_PATH = "src/fastapi_endpoint_detector/analyzer/client_observations.py"
DEPLOYMENT_SCANNER_PATH = "src/fastapi_endpoint_detector/analyzer/deployment_observations.py"
HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "nonpython_v1"
WORKER = r"""
import dataclasses, json, sys
from pathlib import Path
from fastapi_endpoint_detector.analyzer.client_observations import (
    EstablishedSurface, extract_client_observations, join_established_surfaces,
)
try:
    from fastapi_endpoint_detector.analyzer.deployment_observations import (
        extract_dockerfile_observations, extract_subprocess_observations,
    )
except ImportError:
    extract_dockerfile_observations = extract_subprocess_observations = None
def encode(value):
    if isinstance(value, Path): return str(value)
    if isinstance(value, tuple): return list(value)
    return value
payload=json.load(sys.stdin)
out={}
for case in payload["cases"]:
    observations=[]
    for source in case.get("client_sources", []):
        observations.extend(extract_client_observations(source["text"], source["path"]))
    observations=tuple(observations)
    surfaces=tuple(EstablishedSurface(
        surface["surface_id"], surface["path"], surface["method"],
        surface.get("origin"), surface.get("trusted", False)
    ) for surface in case.get("surfaces", []))
    joined=join_established_surfaces(observations, surfaces)
    deployment=[]
    for source in case.get("deployment_sources", []):
        if extract_dockerfile_observations is not None:
            deployment.extend(extract_dockerfile_observations(source["text"], source["path"]))
    subprocess_observations=[]
    for source in case.get("subprocess_sources", []):
        if extract_subprocess_observations is not None:
            subprocess_observations.extend(  # noqa: E501
                extract_subprocess_observations(source["text"], source["path"])
            )
    out[case["case_id"]]={
      "client_observations":[{
        "source_path":str(o.source_path),"line":o.line,"protocol":o.protocol,
        "method":o.method,"literal_url":o.literal_url,"origin":o.origin,
        "raw_route_path":o.route_path,"query_evidence":o.query,
        "normalized_route_identity":f"{o.method} {o.route_path}",
        "start_offset":o.start_offset,"end_offset":o.end_offset,
      } for o in observations],
      "joined_surface_ids":[m.surface_id for m in joined],
      "deployment_observations":[{
        "source_path":str(o.source_path),"line":o.line,"kind":o.kind,
        "key":o.key,"value":encode(o.value),"certainty":o.certainty,
        "uncertainty":o.uncertainty,
      } for o in deployment],
      "subprocess_observations":[{
        "source_path":str(o.source_path),"line":o.line,"kind":o.kind,
        "key":o.key,"value":encode(o.value),"certainty":o.certainty,
        "uncertainty":o.uncertainty,
      } for o in subprocess_observations],
    }
json.dump(out,sys.stdout,sort_keys=True)
"""


class NonPythonFixtureError(ValueError):
    """Fixture input does not match its declared immutable evidence contract."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                NonPythonFixtureError(f"non-finite JSON constant in {path}: {value}")
            ),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NonPythonFixtureError(f"invalid JSON input: {path}") from exc


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NonPythonFixtureError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def safe_relative(value: Any, what: str) -> Path:
    if not isinstance(value, str):
        raise NonPythonFixtureError(f"{what} must be a relative path string")
    parsed = PurePosixPath(value)
    if (
        not value
        or parsed.is_absolute()
        or ".." in parsed.parts
        or parsed.as_posix() != value
        or any(part in {"", "."} for part in value.split("/"))
    ):
        raise NonPythonFixtureError(f"unsafe {what}: {value}")
    return Path(*parsed.parts)


def _read_verified(base: Path, relative: Any, digest: Any, what: str) -> bytes:
    path_rel = safe_relative(relative, what)
    path = base / path_rel
    try:
        if path.is_symlink() or not path.is_file():
            raise NonPythonFixtureError(f"{what} is not a regular file: {relative}")
        payload = path.read_bytes()
    except OSError as exc:
        raise NonPythonFixtureError(f"cannot read {what}: {relative}") from exc
    actual = sha256(payload)
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise NonPythonFixtureError(f"{what} has invalid SHA-256 metadata: {relative}")
    if actual != digest:
        raise NonPythonFixtureError(f"{what} SHA-256 mismatch: {relative}")
    return payload


def _require_trusted_scanner_commit(scanner_commit: str) -> str:
    if not isinstance(scanner_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", scanner_commit):
        raise NonPythonFixtureError("scanner commit must be a full immutable Git SHA")
    if scanner_commit not in TRUSTED_SCANNER_COMMITS:
        raise NonPythonFixtureError("scanner commit is not in the approved immutable allowlist")
    return scanner_commit


def validate_fixture(  # noqa: PLR0912, PLR0915
    fixture: Path = FIXTURE, evidence_root: Path | None = None
) -> dict[str, Any]:
    """Validate fixture schemas, provenance, counts, and every evidence hash."""
    manifest = strict_json(fixture / "source_manifest.json")
    spec = strict_json(fixture / "evaluation_cases.json")
    if not isinstance(manifest, dict) or manifest.get("schema") != "nonpython-source-manifest-v1":
        raise NonPythonFixtureError("unsupported source-manifest schema")
    if not isinstance(spec, dict) or spec.get("schema") != "nonpython-evaluation-cases-v1":
        raise NonPythonFixtureError("unsupported evaluation-case schema")
    cases = spec.get("cases")
    source_cases = manifest.get("cases")
    if not isinstance(cases, list) or len(cases) != 6:
        raise NonPythonFixtureError("expected exactly six audited PR cases")
    if not isinstance(source_cases, dict) or len(source_cases) != 6:
        raise NonPythonFixtureError("source manifest must bind exactly six PR snapshots")
    if not isinstance(manifest.get("diffs"), dict) or len(manifest["diffs"]) != 6:
        raise NonPythonFixtureError("source manifest must bind six immutable PR diffs")

    by_case: dict[str, dict[str, Any]] = {}
    case_keys: dict[str, str] = {}
    audit_hashes: list[dict[str, str]] = []
    verified_sources: list[dict[str, Any]] = []
    verified_licenses: list[dict[str, Any]] = []
    verified_diffs: list[dict[str, Any]] = []
    fixture.resolve(strict=True)
    audit_root = evidence_root or Path(__file__).resolve().parents[2]
    for case in cases:
        if not isinstance(case, dict):
            raise NonPythonFixtureError("malformed evaluation case")
        case_id = case.get("case_id")
        repo, pr, commit = case.get("repository"), case.get("pr"), case.get("merge_snapshot")
        if (
            not isinstance(case_id, str)
            or not isinstance(repo, str)
            or type(pr) is not int
            or not isinstance(commit, str)
            or case_id != f"{repo}#{pr}"
            or case_id in by_case
        ):
            raise NonPythonFixtureError("malformed or duplicate audited PR identity")
        case_key = next(
            (
                key
                for key, record in source_cases.items()
                if isinstance(record, dict)
                and record.get("repository") == repo
                and record.get("merge_snapshot") == commit
            ),
            None,
        )
        if case_key is None or case_id in case_keys:
            raise NonPythonFixtureError(f"case lacks a unique pinned source snapshot: {case_id}")
        case_keys[case_id] = case_key
        record = source_cases[case_key]
        files = record.get("files")
        if not isinstance(files, list) or not files:
            raise NonPythonFixtureError(f"missing source file inventory: {case_id}")
        original_paths: set[str] = set()
        for source in files:
            if not isinstance(source, dict):
                raise NonPythonFixtureError(f"malformed source metadata: {case_id}")
            original = source.get("path")
            stored = source.get("storage_path")
            if not isinstance(original, str) or not isinstance(stored, str):
                raise NonPythonFixtureError(f"source path provenance is incomplete: {case_id}")
            safe_relative(original, "original source path")
            safe_relative(stored, "stored source path")
            if original.endswith(".py") and not stored.endswith(".py.txt"):
                raise NonPythonFixtureError(
                    "vendored Python source must use a non-.py data extension"
                )
            if stored.endswith(".py") or stored.endswith(".pyw"):
                raise NonPythonFixtureError(
                    "vendored source files must not be importable Python paths"
                )
            original_paths.add(original)
            source_bytes = _read_verified(
                fixture / "source" / case_key,
                stored,
                source.get("sha256"),
                "source",
            )
            if len(source_bytes) != source.get("bytes"):
                raise NonPythonFixtureError(f"source byte count mismatch: {case_id}:{original}")
            actual = sha256(source_bytes)
            verified_sources.append(
                {
                    "case_id": case_id,
                    "original_path": original,
                    "stored_path": stored,
                    "sha256": actual,
                    "bytes": len(source_bytes),
                }
            )
        license_record = record.get("license")
        if not isinstance(license_record, dict) or license_record.get("original_path") != "LICENSE":
            raise NonPythonFixtureError(f"license provenance missing: {case_id}")
        expected_license_url = f"https://raw.githubusercontent.com/{repo}/{commit}/LICENSE"
        if (
            license_record.get("source_commit") != commit
            or license_record.get("url") != expected_license_url
        ):
            raise NonPythonFixtureError(
                f"license provenance is not bound to the pinned PR snapshot: {case_id}"
            )
        license_bytes = _read_verified(
            fixture,
            license_record.get("storage_path"),
            license_record.get("sha256"),
            "upstream license",
        )
        if len(license_bytes) != license_record.get("bytes"):
            raise NonPythonFixtureError(f"license byte count mismatch: {case_id}")
        verified_licenses.append(
            {
                "case_id": case_id,
                "repository": repo,
                "original_path": license_record["original_path"],
                "source_commit": license_record["source_commit"],
                "sha256": license_record["sha256"],
            }
        )
        diff_key = case_id
        diff = manifest["diffs"].get(diff_key)
        if not isinstance(diff, dict) or diff.get("commit") != commit:
            raise NonPythonFixtureError(f"pinned diff provenance missing: {case_id}")
        diff_bytes = _read_verified(fixture, diff.get("path"), diff.get("sha256"), "PR diff")
        if len(diff_bytes) != diff.get("bytes"):
            raise NonPythonFixtureError(f"diff byte count mismatch: {case_id}")
        verified_diffs.append(
            {
                "case_id": case_id,
                "commit": commit,
                "path": diff["path"],
                "sha256": diff["sha256"],
                "bytes": len(diff_bytes),
            }
        )

        safe_relative(case.get("audit"), "audit path")
        audit_bytes = _read_verified(
            audit_root, case.get("audit"), case.get("audit_sha256"), "audit"
        )
        audit_hashes.append({"case_id": case_id, "sha256": sha256(audit_bytes)})
        by_case[case_id] = case
        case["_source_key"] = case_key
        case["_original_source_paths"] = original_paths

    if set(source_cases) != set(case_keys.values()):
        raise NonPythonFixtureError("source manifest and audited PR identities differ")

    client_atom_count = 0
    deployment_atom_count = 0
    for case in cases:
        atoms = case.get("atoms")
        if not isinstance(atoms, list) or not atoms:
            raise NonPythonFixtureError(f"case must have reviewed route atoms: {case['case_id']}")
        mode = case.get("mode")
        if mode not in {"typescript_client", "svelte_client", "docker_env_subprocess"}:
            raise NonPythonFixtureError(f"unsupported case mode: {mode}")
        used_paths = set(case.get("client_files", []))
        used_paths.update(case.get("deployment_files", []))
        if case.get("subprocess_file"):
            used_paths.add(case["subprocess_file"])
        if not used_paths.issubset(case["_original_source_paths"]):
            raise NonPythonFixtureError(
                f"case references source absent from hash manifest: {case['case_id']}"
            )
        route_identities: set[tuple[str, str]] = set()
        surface_ids: set[str] = set()
        for atom in atoms:
            if not isinstance(atom, dict):
                raise NonPythonFixtureError("malformed audited route atom")
            method, path, surface_id = atom.get("method"), atom.get("path"), atom.get("surface_id")
            if (
                method
                not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "WEBSOCKET"}
                or not isinstance(path, str)
                or not path.startswith("/")
                or "?" in path
                or not isinstance(surface_id, str)
                or not surface_id
                or not isinstance(atom.get("client_evidence"), str)
                or not isinstance(atom.get("server_evidence"), str)
            ):
                raise NonPythonFixtureError(f"malformed audited atom in {case['case_id']}")
            route_identity = (method, path)
            if route_identity in route_identities:
                raise NonPythonFixtureError(
                    f"duplicate audited route identity in {case['case_id']}: {method} {path}"
                )
            if surface_id in surface_ids:
                raise NonPythonFixtureError(
                    f"duplicate audited surface ID in {case['case_id']}: {surface_id}"
                )
            route_identities.add(route_identity)
            surface_ids.add(surface_id)
            if mode == "docker_env_subprocess":
                deployment_atom_count += 1
                if (
                    atom.get("impact") != "conditional_deployment_impact"
                    or atom.get("runtime_observed") is not False
                ):
                    raise NonPythonFixtureError(
                        "Docker route atom must remain explicitly conditional"
                    )
            else:
                client_atom_count += 1
    if len(by_case) != 6 or client_atom_count != 8 or deployment_atom_count != 1:
        raise NonPythonFixtureError(
            "unit-count mismatch: expected 6 PRs, 8 client atoms, and 1 conditional deployment atom"
        )
    return {
        "manifest": manifest,
        "spec": spec,
        "source_keys": case_keys,
        "verified_source_files": verified_sources,
        "verified_licenses": verified_licenses,
        "verified_diffs": verified_diffs,
        "verified_audit_hashes": audit_hashes,
        "client_atom_count": client_atom_count,
        "deployment_atom_count": deployment_atom_count,
    }


def _archive_scanner(repo_root: Path, scanner_commit: str, target: Path) -> tuple[str, str | None]:
    _require_trusted_scanner_commit(scanner_commit)
    resolved = subprocess.run(
        ["git", "rev-parse", f"{scanner_commit}^{{commit}}"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if resolved != scanner_commit:
        raise NonPythonFixtureError("scanner commit did not resolve to the requested exact SHA")
    archive = subprocess.run(
        ["git", "archive", "--format=tar", scanner_commit],
        cwd=repo_root,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tf:
        tf.extractall(target)
    client_bytes = (target / CLIENT_SCANNER_PATH).read_bytes()
    deployment_path = target / DEPLOYMENT_SCANNER_PATH
    deployment_hash = sha256(deployment_path.read_bytes()) if deployment_path.is_file() else None
    return sha256(client_bytes), deployment_hash


def _run_worker(scanner_source: Path, payload: dict[str, Any]) -> dict[str, Any]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(scanner_source / "src")
    proc = subprocess.run(
        [sys.executable, "-c", WORKER],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    if proc.returncode:
        raise NonPythonFixtureError(f"trusted scanner worker failed: {proc.stderr.strip()}")
    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise NonPythonFixtureError("trusted scanner worker returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise NonPythonFixtureError("trusted scanner worker returned an invalid result")
    return result


def scan_literal_case(
    *,
    repo_root: Path,
    scanner_commit: str,
    source_path: str,
    source_text: str,
    surfaces: list[dict[str, Any]],
) -> dict[str, Any]:
    """Run the pinned client scanner against one in-memory source and explicit surfaces."""
    with tempfile.TemporaryDirectory(prefix="nonpython-test-scanner-") as temp:
        target = Path(temp)
        _archive_scanner(repo_root, scanner_commit, target)
        return _run_worker(
            target,
            {
                "cases": [
                    {
                        "case_id": "direct-test",
                        "client_sources": [{"path": source_path, "text": source_text}],
                        "surfaces": surfaces,
                    }
                ],
            },
        )["direct-test"]


def build_result(
    fixture: Path = FIXTURE,
    scanner_commit: str = SCANNER_COMMIT,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    _require_trusted_scanner_commit(scanner_commit)
    validated = validate_fixture(fixture)
    spec = validated["spec"]
    source_root = fixture / "source"
    repo = repo_root or Path(__file__).resolve().parents[2]
    result_cases_input: list[dict[str, Any]] = []
    for case in spec["cases"]:
        case_key = validated["source_keys"][case["case_id"]]
        case_manifest = validated["manifest"]["cases"][case_key]
        source_by_original = {
            row["path"]: (source_root / case_key / row["storage_path"]).read_text(encoding="utf-8")
            for row in case_manifest["files"]
        }
        atoms = case["atoms"]
        result_cases_input.append(
            {
                "case_id": case["case_id"],
                "client_sources": [
                    {"path": path, "text": source_by_original[path]}
                    for path in case.get("client_files", [])
                ],
                "surfaces": [
                    {
                        "surface_id": atom["surface_id"],
                        "path": atom["path"],
                        "method": atom["method"],
                        "origin": None,
                        "trusted": True,
                    }
                    for atom in atoms
                ],
                "deployment_sources": [
                    {"path": path, "text": source_by_original[path]}
                    for path in case.get("deployment_files", [])
                ],
                "subprocess_sources": [
                    {
                        "path": case["subprocess_file"],
                        "text": source_by_original[case["subprocess_file"]],
                    }
                ]
                if case.get("subprocess_file")
                else [],
            }
        )

    with tempfile.TemporaryDirectory(prefix="nonpython-pr310-") as temp:
        scanner_root = Path(temp)
        client_hash, deployment_hash = _archive_scanner(repo, scanner_commit, scanner_root)
        scan = _run_worker(scanner_root, {"cases": result_cases_input})

    output_cases = []
    for case in spec["cases"]:
        scan_case = scan[case["case_id"]]
        atoms = []
        for atom in case["atoms"]:
            row = {
                "method": atom["method"],
                "path": atom["path"],
                "normalized_route_identity": f"{atom['method']} {atom['path']}",
                "query_evidence": atom.get("query_evidence"),
                "surface_id": atom["surface_id"],
                "audit_client_evidence": atom["client_evidence"],
                "audit_server_evidence": atom["server_evidence"],
            }
            if case["mode"] == "docker_env_subprocess":
                row.update(
                    {
                        "status": "conditional_deployment_impact",
                        "runtime_observed": False,
                        "assumptions": atom.get("assumptions", []),
                        "observation_refs": {
                            "docker": [
                                f"{o['source_path']}:{o['line']}"
                                for o in scan_case["deployment_observations"]
                            ],
                            "subprocess": [
                                f"{o['source_path']}:{o['line']}"
                                for o in scan_case["subprocess_observations"]
                            ],
                        },
                    }
                )
            else:
                matches = [
                    o
                    for o in scan_case["client_observations"]
                    if o["method"] == atom["method"] and o["raw_route_path"] == atom["path"]
                ]
                row.update(
                    {
                        "status": "joined"
                        if atom["surface_id"] in scan_case["joined_surface_ids"]
                        else "abstained",
                        "scanner_abstention": None
                        if matches
                        else "no_exact_literal_method_path_observation",
                        "origin_attestation_missing": bool(matches)
                        and atom["surface_id"] not in scan_case["joined_surface_ids"],
                        "matching_observations": matches,
                    }
                )
            atoms.append(row)
        output_cases.append(
            {
                "case_id": case["case_id"],
                "repository": case["repository"],
                "pr": case["pr"],
                "merge_snapshot": case["merge_snapshot"],
                "audit": case["audit"],
                "audit_sha256": case["audit_sha256"],
                "mode": case["mode"],
                "atoms": atoms,
                "raw_client_observations": scan_case["client_observations"],
                "explicit_established_surface_joins": scan_case["joined_surface_ids"],
                "raw_deployment_observations": scan_case["deployment_observations"],
                "raw_subprocess_observations": scan_case["subprocess_observations"],
            }
        )

    atom_total = sum(len(case["atoms"]) for case in output_cases)
    return {
        "schema": "nonpython-evaluation-results-v2",
        "scope_units": {
            "audited_pr_count": len(output_cases),
            "client_route_atom_count": validated["client_atom_count"],
            "conditional_deployment_atom_count": validated["deployment_atom_count"],
            "total_audited_nonpython_atom_count": atom_total,
        },
        "truth_status": spec["truth_status"],
        "acceptance_claim": "not asserted; GH108 does not define the unit of nine",
        "interpretation": (
            "Six audited PRs contain eight client route atoms plus one conditional "
            "deployment atom. These nine atoms could be the intended nine audited "
            "cases; no additional PR identities are inferred."
        ),
        "scanner": {
            "repository_commit": scanner_commit,
            "client_source_path": CLIENT_SCANNER_PATH,
            "client_source_sha256": client_hash,
            "deployment_source_path": DEPLOYMENT_SCANNER_PATH,
            "deployment_source_sha256": deployment_hash,
        },
        "source_manifest_sha256": sha256((fixture / "source_manifest.json").read_bytes()),
        "case_spec_sha256": sha256((fixture / "evaluation_cases.json").read_bytes()),
        "protocol_evidence_sha256": sha256((fixture / "protocol_evidence.json").read_bytes()),
        "verified_source_file_count": len(validated["verified_source_files"]),
        "verified_source_files": validated["verified_source_files"],
        "verified_licenses": validated["verified_licenses"],
        "verified_audit_hashes": validated["verified_audit_hashes"],
        "verified_diff_count": len(validated["manifest"]["diffs"]),
        "cases": output_cases,
    }


def run() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture-dir", type=Path, default=FIXTURE)
    parser.add_argument("--write", type=Path, default=None)
    parser.add_argument("--scanner-commit", default=SCANNER_COMMIT)
    args = parser.parse_args()
    try:
        result = build_result(args.fixture_dir, args.scanner_commit)
    except (NonPythonFixtureError, OSError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    output = args.write or args.fixture_dir / "results/evaluation.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            result["scope_units"]
            | {"scanner": result["scanner"], "acceptance_claim": result["acceptance_claim"]},
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
