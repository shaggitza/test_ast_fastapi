#!/usr/bin/env python3
"""R6 versioned source-only evaluation of GH108 non-Python evidence.

Upstream snapshots are verified inert strings. Only the exact trusted scanner
modules archived from the R6 Git commit are imported by the isolated worker.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, cast

SCANNER_COMMIT = "d4eec140bed84d3ff8cea8374f7f9e589b0e6def"
TRUSTED_SCANNER_COMMITS = frozenset({SCANNER_COMMIT})
CLIENT_SCANNER_PATH = "src/fastapi_endpoint_detector/analyzer/client_observations.py"
DEPLOYMENT_SCANNER_PATH = "src/fastapi_endpoint_detector/analyzer/deployment_observations.py"
CLIENT_SCANNER_SHA256 = "341d1d1144d6ecd60f093c25143cc6e55375adc87f0ab950e975760e1da41c52"
DEPLOYMENT_SCANNER_SHA256 = "8ac7f49a1c16fb2bedf971bec1824b2082cc2506fb71c8204863aa4b2bb4305c"
PINNED_SOURCE_MANIFEST_SHA256 = "ea78d3508776d7488077fe4ed142ea9a8fb029083c7a76c632ce17b5303ddd48"
HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "nonpython_v1"
WORKER = r"""
import dataclasses, json, sys
from pathlib import Path
sys.path.insert(0, sys.argv.pop(1))
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
out["_executed_sources"] = {}
for name, module in sorted(sys.modules.items()):
    if not name.startswith("fastapi_endpoint_detector"):
        continue
    module_file = getattr(module, "__file__", None)
    if module_file is None:
        continue
    path = Path(module_file).resolve()
    if path.suffix != ".py":
        continue
    out["_executed_sources"][name] = {
        "path": path.relative_to(Path(sys.path[0]).resolve()).as_posix(),
        "sha256": __import__("hashlib").sha256(path.read_bytes()).hexdigest()
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
    source_snapshots: dict[str, dict[str, bytes]] = {}
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
        case_source_snapshots: dict[str, bytes] = {}
        for source in files:
            if not isinstance(source, dict):
                raise NonPythonFixtureError(f"malformed source metadata: {case_id}")
            original = source.get("path")
            stored = source.get("storage_path")
            if not isinstance(original, str) or not isinstance(stored, str):
                raise NonPythonFixtureError(f"source path provenance is incomplete: {case_id}")
            if original in case_source_snapshots:
                raise NonPythonFixtureError(
                    f"duplicate original source path in manifest: {case_id}:{original}"
                )
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
            case_source_snapshots[original] = source_bytes
            verified_sources.append(
                {
                    "case_id": case_id,
                    "original_path": original,
                    "stored_path": stored,
                    "sha256": actual,
                    "bytes": len(source_bytes),
                }
            )
        source_snapshots[case_id] = case_source_snapshots
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
        "source_snapshots": source_snapshots,
        "verified_source_files": verified_sources,
        "verified_licenses": verified_licenses,
        "verified_diffs": verified_diffs,
        "verified_audit_hashes": audit_hashes,
        "client_atom_count": client_atom_count,
        "deployment_atom_count": deployment_atom_count,
    }


def _pinned_package_manifest() -> dict[str, str]:
    manifest_path = FIXTURE / "pinned_scanner" / "source_manifest.json"
    if sha256(manifest_path.read_bytes()) != PINNED_SOURCE_MANIFEST_SHA256:
        raise NonPythonFixtureError("pinned scanner source manifest SHA-256 mismatch")
    manifest = strict_json(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("commit") != SCANNER_COMMIT:
        raise NonPythonFixtureError("pinned scanner source manifest has invalid commit")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise NonPythonFixtureError("pinned scanner source manifest is empty")
    expected = {
        CLIENT_SCANNER_PATH.removeprefix("src/"),
        DEPLOYMENT_SCANNER_PATH.removeprefix("src/"),
    }
    if not expected.issubset(files):
        raise NonPythonFixtureError("pinned scanner manifest omits scanner modules")
    for relative, digest in files.items():
        if (
            not isinstance(relative, str)
            or not relative.endswith(".py")
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise NonPythonFixtureError("invalid pinned scanner source manifest entry")
    return cast("dict[str, str]", files)


def _archive_scanner(repo_root: Path, scanner_commit: str, target: Path) -> tuple[str, str | None]:
    _require_trusted_scanner_commit(scanner_commit)
    manifest = _pinned_package_manifest()
    # Establish a valid Git context before deciding that only the historical
    # object is absent. All other Git failures must remain visible.
    subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        resolved = subprocess.run(
            ["git", "rev-parse", f"{scanner_commit}^{{commit}}"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError as git_error:
        # Fallback is valid only for a valid repository whose object database
        # confirms that this trusted commit is absent.
        absent = subprocess.run(
            ["git", "cat-file", "-e", f"{scanner_commit}^{{commit}}"],
            cwd=repo_root,
            check=False,
            capture_output=True,
        )
        if absent.returncode == 0:
            raise NonPythonFixtureError(
                "scanner commit exists but could not be resolved"
            ) from git_error
        if absent.returncode != 128 or b"fatal: Not a valid object name " not in absent.stderr:
            raise subprocess.CalledProcessError(
                absent.returncode, absent.args, absent.stdout, absent.stderr
            ) from git_error
        bundled = FIXTURE / "pinned_scanner"
        for relative, expected_hash in manifest.items():
            source = bundled / relative
            if (
                source.is_symlink()
                or not source.is_file()
                or sha256(source.read_bytes()) != expected_hash
            ):
                raise NonPythonFixtureError(
                    f"pinned scanner source SHA-256 mismatch: {relative}"
                ) from git_error
            destination = target / "src" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
    else:
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
    client_hash = sha256(client_bytes)
    if client_hash != CLIENT_SCANNER_SHA256 or deployment_hash != DEPLOYMENT_SCANNER_SHA256:
        raise NonPythonFixtureError("archived scanner module SHA-256 differs from R6 pin")
    for relative, expected_hash in manifest.items():
        source = target / "src" / relative
        if (
            source.is_symlink()
            or not source.is_file()
            or sha256(source.read_bytes()) != expected_hash
        ):
            raise NonPythonFixtureError(f"pinned scanner dependency SHA-256 mismatch: {relative}")
    return client_hash, deployment_hash


def _run_worker(scanner_source: Path, payload: dict[str, Any]) -> dict[str, Any]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(scanner_source / "src")
    env["PYTHONNOUSERSITE"] = "1"
    proc = subprocess.run(
        [sys.executable, "-I", "-c", WORKER, str(scanner_source / "src")],
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
    executed = result.pop("_executed_sources", None)
    required = {
        "fastapi_endpoint_detector",
        "fastapi_endpoint_detector.analyzer.client_observations",
        "fastapi_endpoint_detector.analyzer.deployment_observations",
        "fastapi_endpoint_detector.models.endpoint",
    }
    if not isinstance(executed, dict) or not required.issubset(executed):
        raise NonPythonFixtureError("worker did not report the complete executed-source proof")
    seen_paths: set[str] = set()
    for name, proof in executed.items():
        if (
            not isinstance(proof, dict)
            or not isinstance(proof.get("path"), str)
            or not isinstance(proof.get("sha256"), str)
        ):
            raise NonPythonFixtureError(f"worker source proof is malformed: {name}")
        relative = safe_relative(proof["path"], "worker source path").as_posix()
        if relative in seen_paths:
            raise NonPythonFixtureError("worker source proof contains duplicate executed paths")
        seen_paths.add(relative)
        path = (scanner_source / "src" / relative).resolve()
        expected_hash = _pinned_package_manifest().get(relative)
        if (
            expected_hash is None
            or proof["sha256"] != expected_hash
            or not path.is_file()
            or sha256(path.read_bytes()) != expected_hash
        ):
            raise NonPythonFixtureError(f"worker executed-source hash mismatch: {name}")
    result["executed_scanner_sources"] = executed
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
        result = _run_worker(
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
        )
        return cast("dict[str, Any]", result["direct-test"])


def _decode_source_snapshot(source_bytes: bytes, source_path: str) -> str:
    """Decode the already-verified byte snapshot like Path.read_text(encoding=utf-8)."""
    try:
        return io.TextIOWrapper(io.BytesIO(source_bytes), encoding="utf-8").read()
    except UnicodeDecodeError as exc:
        raise NonPythonFixtureError(f"verified source is not UTF-8 text: {source_path}") from exc


def build_result(
    fixture: Path = FIXTURE,
    scanner_commit: str = SCANNER_COMMIT,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    _require_trusted_scanner_commit(scanner_commit)
    validated = validate_fixture(fixture)
    spec = validated["spec"]
    repo = repo_root or Path(__file__).resolve().parents[2]
    result_cases_input: list[dict[str, Any]] = []
    for case in spec["cases"]:
        source_by_original = {
            path: _decode_source_snapshot(source_bytes, path)
            for path, source_bytes in validated["source_snapshots"][case["case_id"]].items()
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
        "schema": "gh108-final-acceptance-r6-v1",
        "result_protocol": "versioned-source-only-observations-v1",
        "scope_units": {
            "audited_pr_count": len(output_cases),
            "client_route_atom_count": validated["client_atom_count"],
            "conditional_deployment_atom_count": validated["deployment_atom_count"],
            "total_audited_nonpython_atom_count": atom_total,
        },
        "truth_status": spec["truth_status"],
        "acceptance_claim": (
            "bounded source evaluation; independent R7 review required before closure"
        ),
        "interpretation": (
            "Six audited PRs contain eight client route atoms plus one conditional "
            "deployment atom. This records nine atoms independently of PR count; "
            "it does not infer the issue wording's intended unit."
        ),
        "acceptance_criteria": [
            {
                "criterion": "finite_normalized_client_url_method",
                "finding": "bounded source API verified; per-atom observations are separate",
                "source_refs": ["src/fastapi_endpoint_detector/analyzer/client_observations.py"],
            },
            {
                "criterion": "joins_only_established_explicit_surface_ids",
                "finding": (
                    "join API requires an established surface and matching origin; zero joins here"
                ),
                "source_refs": [
                    "src/fastapi_endpoint_detector/analyzer/client_observations.py",
                    "src/fastapi_endpoint_detector/analyzer/project_observations.py",
                ],
            },
            {
                "criterion": "query_evidence_excluded_from_route_identity",
                "finding": "query is retained separately from normalized method and route path",
                "source_refs": [
                    "src/fastapi_endpoint_detector/analyzer/client_observations.py",
                    "src/fastapi_endpoint_detector/analyzer/project_observations.py",
                ],
            },
            {
                "criterion": "websocket_client_support",
                "finding": "bounded WebSocket selector exists; no audited atom exercises it",
                "source_refs": ["src/fastapi_endpoint_detector/analyzer/client_observations.py"],
            },
            {
                "criterion": "docker_environment_observations",
                "finding": (
                    "Docker and environment observations are source-only and certainty-labelled"
                ),
                "source_refs": [
                    "src/fastapi_endpoint_detector/analyzer/deployment_observations.py"
                ],
            },
            {
                "criterion": "subprocess_observations",
                "finding": (
                    "UNVERIFIED: no raw subprocess observations or scanner references are present; "
                    "historical stdio.client audit citations are not scanner observations"
                ),
                "source_refs": [],
            },
            {
                "criterion": "no_cross_language_global_url_fanout",
                "finding": (
                    "UNVERIFIED: this bounded replay calls pinned extractors directly "
                    "and does not exercise project-adapter dispatch"
                ),
                "source_refs": [],
            },
            {
                "criterion": "nine_audited_cases_separately_evaluated",
                "finding": (
                    "result contains six PR records, eight client atoms and one conditional "
                    "deployment atom"
                ),
                "source_refs": [
                    "benchmarks/real_world/nonpython_v1/evaluation_cases.json",
                    "benchmarks/real_world/nonpython_v1/source_manifest.json",
                ],
            },
        ],
        "public_integration": {
            "status": "present in this base",
            "config_ref": "src/fastapi_endpoint_detector/config.py:RouteObservationConfig",
            "cli_ref": "src/fastapi_endpoint_detector/cli.py:analyze route_observations block",
            "test_ref": "tests/integration/test_route_observations_cli.py",
        },
        "scanner": {
            "repository_commit": scanner_commit,
            "client_source_path": CLIENT_SCANNER_PATH,
            "client_source_sha256": client_hash,
            "deployment_source_path": DEPLOYMENT_SCANNER_PATH,
            "deployment_source_sha256": deployment_hash,
            "executed_sources": scan["executed_scanner_sources"],
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
    output = args.write or args.fixture_dir / "results/evaluation-r6.json"
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
