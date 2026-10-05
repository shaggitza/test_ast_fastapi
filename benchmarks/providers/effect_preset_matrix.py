"""Fail-closed helpers for the frozen GH97 package/version matrix."""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
import zipfile
from pathlib import Path
from typing import Any

MATRIX_ROOT = Path(__file__).resolve().parents[1] / "results" / "effect-preset-matrix-v1"
MANIFEST_PATH = MATRIX_ROOT / "package-symbols.json"
RESULTS_PATH = MATRIX_ROOT / "controlled-results.json"


class MatrixEvidenceError(ValueError):
    """Raised when frozen matrix provenance is incomplete or inconsistent."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:  # noqa: PLR0912, PLR0915
    """Load and structurally validate the frozen manifest without network access."""
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise MatrixEvidenceError(f"cannot read package matrix manifest: {path}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise MatrixEvidenceError("unsupported package matrix schema")
    if value.get("matrix_id") != "effect-preset-package-matrix-v1":
        raise MatrixEvidenceError("unexpected package matrix identity")
    required_root = {
        "schema_version",
        "matrix_id",
        "matrix_version",
        "source_inspection_method",
        "versioned_contract_sets",
        "packages",
        "controlled_evaluation",
        "real_world_evaluation",
        "range_compatibility",
        "unsupported_cases",
    }
    if set(value) != required_root:
        raise MatrixEvidenceError("package matrix root has an unexpected field set")
    contract_sets = value.get("versioned_contract_sets")
    if not isinstance(contract_sets, list) or not contract_sets:
        raise MatrixEvidenceError("matrix has no versioned preset contract sets")
    contract_ids: set[str] = set()
    for contract_set in contract_sets:
        fields = {
            "preset_id",
            "version",
            "revision",
            "preset_path",
            "preset_sha256",
            "contract_count",
            "symbol_scope",
        }
        if not isinstance(contract_set, dict) or set(contract_set) != fields:
            raise MatrixEvidenceError("versioned preset contract row has invalid fields")
        if contract_set["preset_id"] in contract_ids:
            raise MatrixEvidenceError("duplicate versioned preset identity")
        contract_ids.add(contract_set["preset_id"])
        if (
            not isinstance(contract_set["version"], str)
            or not isinstance(contract_set["revision"], str)
            or type(contract_set["contract_count"]) is not int
            or contract_set["contract_count"] < 1
            or re.fullmatch(r"[0-9a-f]{64}", contract_set["preset_sha256"]) is None
            or not isinstance(contract_set["preset_path"], str)
            or not contract_set["preset_path"].startswith("src/fastapi_endpoint_detector/presets/")
            or not isinstance(contract_set["symbol_scope"], str)
        ):
            raise MatrixEvidenceError("invalid versioned preset contract identity")
    packages = value.get("packages")
    if not isinstance(packages, list) or not packages:
        raise MatrixEvidenceError("package matrix has no audited packages")
    required = {
        "distribution",
        "version",
        "artifact",
        "artifact_sha256",
        "artifact_url",
        "metadata_file",
        "metadata_sha256",
        "metadata_name",
        "metadata_version",
        "inspected_sources",
        "source_status",
        "declared_symbols",
        "release_source",
    }
    seen: set[str] = set()
    for package in packages:
        if not isinstance(package, dict) or set(package) != required:
            raise MatrixEvidenceError("package rows must have the exact v1 field set")
        name = package["distribution"]
        if not isinstance(name, str) or not name or name in seen:
            raise MatrixEvidenceError("package distributions must be unique non-empty strings")
        seen.add(name)
        if (
            not isinstance(package["version"], str)
            or not package["version"]
            or not isinstance(package["artifact"], str)
            or Path(package["artifact"]).name != package["artifact"]
            or not isinstance(package["artifact_url"], str)
            or not package["artifact_url"].startswith("https://")
            or not isinstance(package["release_source"], str)
            or not package["release_source"].startswith("https://")
        ):
            raise MatrixEvidenceError(f"invalid exact release identity for {name}")
        if package["metadata_file"] is not None and (
            not isinstance(package["metadata_file"], str)
            or Path(package["metadata_file"]).name != "METADATA"
            or not isinstance(package["metadata_name"], str)
            or package["metadata_version"] != package["version"]
        ):
            raise MatrixEvidenceError(f"invalid distribution metadata identity for {name}")
        digest = package["artifact_sha256"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise MatrixEvidenceError(f"invalid artifact hash for {name}")
        if package["source_status"] not in {"inspected", "partially_inspected", "unavailable"}:
            raise MatrixEvidenceError(f"invalid source status for {name}")
        if not isinstance(package["inspected_sources"], list) or not isinstance(
            package["declared_symbols"], list
        ):
            raise MatrixEvidenceError(f"invalid source or symbol list for {name}")
        for source in package["inspected_sources"]:
            if (
                not isinstance(source, dict)
                or set(source) != {"path", "sha256"}
                or not isinstance(source["path"], str)
                or not source["path"]
                or not isinstance(source["sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", source["sha256"]) is None
            ):
                raise MatrixEvidenceError(f"invalid inspected source identity for {name}")
        symbols: set[str] = set()
        declaration_fields = {
            "symbol",
            "receiver",
            "parameters",
            "resource",
            "value",
            "preset_contract",
            "source_signature",
        }
        for declaration in package["declared_symbols"]:
            if not isinstance(declaration, dict) or set(declaration) != declaration_fields:
                raise MatrixEvidenceError(f"declared symbol row has invalid fields for {name}")
            if any(
                not isinstance(declaration[field], str) or not declaration[field]
                for field in ("symbol", "receiver", "resource", "source_signature")
            ):
                raise MatrixEvidenceError(f"incomplete exact symbol evidence for {name}")
            if not isinstance(declaration["parameters"], list) or any(
                not isinstance(parameter, str) or not parameter
                for parameter in declaration["parameters"]
            ):
                raise MatrixEvidenceError(f"invalid formal parameters for {name}")
            if declaration["value"] is not None and not isinstance(declaration["value"], str):
                raise MatrixEvidenceError(f"invalid value selector for {name}")
            if declaration["preset_contract"] is not None and not isinstance(
                declaration["preset_contract"], str
            ):
                raise MatrixEvidenceError(f"invalid preset contract mapping for {name}")
            symbol = declaration["symbol"]
            if re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", symbol) is None:
                raise MatrixEvidenceError(f"matrix symbols must be exact dotted names: {symbol}")
            if symbol in symbols:
                raise MatrixEvidenceError(f"duplicate declared symbol in {name}: {symbol}")
            symbols.add(symbol)
    unsupported = value["unsupported_cases"]
    if not isinstance(unsupported, list):
        raise MatrixEvidenceError("unsupported package cases must be a list")
    for case in unsupported:
        if not isinstance(case, dict) or set(case) != {
            "distribution",
            "version",
            "status",
            "evidence",
        }:
            raise MatrixEvidenceError("unsupported package case has an invalid field set")
    return value


def verify_artifacts(artifact_dir: Path, manifest: dict[str, Any] | None = None) -> dict[str, str]:  # noqa: PLR0912
    """Verify locally supplied package artifacts against frozen PyPI hashes."""
    frozen = manifest or load_manifest()
    observed: dict[str, str] = {}
    for package in frozen["packages"]:
        path = artifact_dir / package["artifact"]
        try:
            digest = _sha256(path.read_bytes())
        except OSError as exc:
            raise MatrixEvidenceError(f"missing frozen package artifact: {path.name}") from exc
        if digest != package["artifact_sha256"]:
            raise MatrixEvidenceError(f"package artifact hash mismatch: {path.name}")
        inspected = package["inspected_sources"]
        if path.suffix == ".whl":
            try:
                with zipfile.ZipFile(path) as archive:
                    metadata_name = package["metadata_file"]
                    metadata = archive.read(metadata_name)
                    if _sha256(metadata) != package["metadata_sha256"]:
                        raise MatrixEvidenceError(
                            f"distribution metadata hash mismatch: {package['distribution']}"
                        )
                    fields = {
                        line.split(": ", 1)[0]: line.split(": ", 1)[1]
                        for line in metadata.decode("utf-8").splitlines()
                        if line.startswith(("Name: ", "Version: "))
                    }
                    if (
                        fields.get("Name") != package["metadata_name"]
                        or fields.get("Version") != package["metadata_version"]
                    ):
                        raise MatrixEvidenceError(
                            "distribution metadata does not match matrix: "
                            f"{package['distribution']}"
                        )
                    for source in inspected:
                        content = archive.read(source["path"])
                        if _sha256(content) != source["sha256"]:
                            raise MatrixEvidenceError(
                                f"inspected source hash mismatch: {package['distribution']}"
                            )
            except (OSError, KeyError, zipfile.BadZipFile) as exc:
                raise MatrixEvidenceError(f"cannot inspect wheel sources: {path.name}") from exc
        elif path.name.endswith(".tgz"):
            if package["metadata_file"] is not None or package["metadata_sha256"] is not None:
                raise MatrixEvidenceError("source archives must not claim wheel metadata")
            try:
                with tarfile.open(path, "r:gz") as archive:
                    for source in inspected:
                        member = f"Python-{package['version']}/{source['path']}"
                        stream = archive.extractfile(member)
                        if stream is None or _sha256(stream.read()) != source["sha256"]:
                            raise MatrixEvidenceError(
                                f"inspected source hash mismatch: {package['distribution']}"
                            )
            except (OSError, KeyError, tarfile.TarError) as exc:
                raise MatrixEvidenceError(f"cannot inspect source archive: {path.name}") from exc
        observed[package["distribution"]] = f"sha256:{digest}"
    return observed


def verify_preset_contracts(manifest: dict[str, Any] | None = None) -> dict[str, str]:
    """Verify preset source bytes and versions against the matrix contract inventory."""
    frozen = manifest or load_manifest()
    project_root = MANIFEST_PATH.parents[3]
    observed: dict[str, str] = {}
    for row in frozen["versioned_contract_sets"]:
        path = project_root / row["preset_path"]
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise MatrixEvidenceError(f"missing frozen preset contract: {path}") from exc
        if _sha256(raw) != row["preset_sha256"]:
            raise MatrixEvidenceError(f"preset contract source hash mismatch: {row['preset_id']}")
        observed[row["preset_id"]] = f"sha256:{row['preset_sha256']}"
    return observed


def summarize_matrix(manifest: dict[str, Any] | None = None) -> dict[str, object]:
    """Return honest evidence counts; source inspection is not analyzer evaluation."""
    frozen = manifest or load_manifest()
    packages = frozen["packages"]
    return {
        "matrix_id": frozen["matrix_id"],
        "package_releases": len(packages),
        "source_inspected": sum(row["source_status"] == "inspected" for row in packages),
        "source_partially_inspected": sum(
            row["source_status"] == "partially_inspected" for row in packages
        ),
        "source_unavailable": sum(row["source_status"] == "unavailable" for row in packages),
        "analyzer_observations": frozen.get("controlled_evaluation", {}).get(
            "analyzer_observations", 0
        ),
        "unsupported_cases": len(frozen.get("unsupported_cases", [])),
        "range_compatibility": frozen.get("range_compatibility", "not_evaluated"),
        "real_world_evaluation": frozen.get("real_world_evaluation", {}).get(
            "status", "not_evaluated"
        ),
    }


def exact_release_status(
    distribution: str,
    version: str,
    manifest: dict[str, Any] | None = None,
) -> str:
    """Report only exact releases present in the audit; never infer from a version range."""
    frozen = manifest or load_manifest()
    for package in frozen["packages"]:
        if package["distribution"] == distribution and package["version"] == version:
            return "audited_exact_release"
    return "not_audited"


def load_controlled_results(path: Path = RESULTS_PATH) -> dict[str, Any]:
    """Validate frozen analyzer observations against the matrix and fixture bytes."""
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise MatrixEvidenceError(f"cannot read controlled result file: {path}") from exc
    required = {
        "schema_version",
        "result_id",
        "status",
        "package_source_audit",
        "controlled_evaluation",
        "environment",
        "real_world_evaluation",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise MatrixEvidenceError("controlled result root has an unexpected field set")
    if value["schema_version"] != 1 or value["result_id"] != "effect-preset-controlled-results-v1":
        raise MatrixEvidenceError("unsupported controlled result identity")
    manifest = load_manifest()
    audit = value["package_source_audit"]
    actual_manifest_hash = f"sha256:{_sha256(MANIFEST_PATH.read_bytes())}"
    if audit.get("manifest_sha256") != actual_manifest_hash:
        raise MatrixEvidenceError("controlled results do not match the frozen package manifest")
    expected_artifacts = [
        {
            "distribution": row["distribution"],
            "version": row["version"],
            "artifact": row["artifact"],
            "artifact_sha256": f"sha256:{row['artifact_sha256']}",
            "metadata_sha256": (
                f"sha256:{row['metadata_sha256']}" if row["metadata_sha256"] else None
            ),
        }
        for row in manifest["packages"]
    ]
    if audit.get("release_artifacts") != expected_artifacts:
        raise MatrixEvidenceError("controlled results have a different release artifact set")
    expected_contract_sets = [
        {
            "preset_id": row["preset_id"],
            "version": row["version"],
            "revision": row["revision"],
            "preset_sha256": f"sha256:{row['preset_sha256']}",
        }
        for row in manifest["versioned_contract_sets"]
    ]
    if audit.get("versioned_contract_sets") != expected_contract_sets:
        raise MatrixEvidenceError("controlled results have a different preset contract set")
    evaluation = value["controlled_evaluation"]
    source_path = Path(evaluation.get("test_path", ""))
    if not source_path.is_file() or f"sha256:{_sha256(source_path.read_bytes())}" != evaluation.get(
        "test_file_sha256"
    ):
        raise MatrixEvidenceError("controlled test source hash is missing or stale")
    observed = evaluation.get("observed", {})
    count_keys = ("matched_calls", "unmatched_calls", "ambiguous_calls", "unresolved_calls")
    if any(type(observed.get(key)) is not int or observed[key] < 0 for key in count_keys):
        raise MatrixEvidenceError("controlled call counts must be non-negative integers")
    if sum(observed[key] for key in count_keys) != observed.get("physical_calls"):
        raise MatrixEvidenceError("controlled call totals do not equal physical calls")
    return value
