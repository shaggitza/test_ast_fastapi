"""Fail-closed helpers for the frozen GH97 package/version matrix."""

from __future__ import annotations

import ast
import hashlib
import importlib.metadata
import json
import platform
import re
import tarfile
import tempfile
import zipfile
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi_endpoint_detector.analyzer.effect_contract_auditor import audit_effect_contracts
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.effect_contract import (
    EffectContractError,
    load_effect_contracts,
    load_effect_preset,
)
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointInventory,
    EndpointMethod,
    HandlerInfo,
)


class MatrixEvidenceError(ValueError):
    """Raised when frozen matrix provenance is incomplete or inconsistent."""


MATRIX_ROOT = Path(__file__).resolve().parents[1] / "results" / "effect-preset-matrix-v4"
MANIFEST_PATH = MATRIX_ROOT / "package-symbols.json"
FIXTURE_PATH = MATRIX_ROOT / "fixtures" / "pathlib_open_handles.py"
ANALYZER_SNAPSHOT_PATH = MATRIX_ROOT / "analyzer-source-snapshots.json"
PACKAGE_CASES_PATH = MATRIX_ROOT / "package-analyzer-cases.json"
SIGNATURE_REPORT_PATH = MATRIX_ROOT / "source-signature-observations.json"
PROJECT_ROOT = MANIFEST_PATH.parents[3]
_SUPPORTED_REPLAY_ENVS = {
    ("3.10.21", "1.19.1"),
    ("3.11.16", "1.19.1"),
    ("3.12.14", "1.19.1"),
    ("3.11.16", "2.4.0"),
}


def _replay_environment() -> tuple[str, str, Path]:
    python_version = platform.python_version()
    try:
        resolver_version = importlib.metadata.version("mypy")
    except importlib.metadata.PackageNotFoundError as exc:
        raise MatrixEvidenceError("mypy distribution version is unavailable") from exc
    if (python_version, resolver_version) not in _SUPPORTED_REPLAY_ENVS:
        raise MatrixEvidenceError(
            "no frozen replay result for exact environment "
            f"Python {python_version} / mypy {resolver_version}"
        )
    run_dir = MATRIX_ROOT / "runs" / f"python-{python_version}-mypy-{resolver_version}"
    return python_version, resolver_version, run_dir


_PYTHON_VERSION, _RESOLVER_VERSION, _RUN_ROOT = _replay_environment()
RESULTS_PATH = _RUN_ROOT / "controlled-results.json"
PACKAGE_CASE_RESULTS_PATH = _RUN_ROOT / "package-analyzer-results.json"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OBSERVATION_STATES = {"matched", "unmatched", "ambiguous", "unresolved"}
ANALYZER_SOURCE_PATHS = (
    "benchmarks/providers/effect_preset_matrix.py",
    "src/fastapi_endpoint_detector/analyzer/effect_contract_auditor.py",
    "src/fastapi_endpoint_detector/analyzer/mypy_analyzer.py",
    "src/fastapi_endpoint_detector/models/effect_contract.py",
    "src/fastapi_endpoint_detector/models/endpoint.py",
    "src/fastapi_endpoint_detector/strict_data.py",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_json(raw: bytes, label: str) -> Any:
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise MatrixEvidenceError(f"duplicate JSON key in {label}: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise MatrixEvidenceError(f"non-finite JSON constant in {label}: {value}")

    try:
        return json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MatrixEvidenceError(f"cannot parse strict JSON for {label}") from exc


def _load_analyzer_source_snapshots() -> tuple[dict[str, str], str]:
    """Require the committed analyzer source snapshot to cover the authoritative path set."""
    try:
        raw = ANALYZER_SNAPSHOT_PATH.read_bytes()
    except OSError as exc:
        raise MatrixEvidenceError("missing committed analyzer source snapshot") from exc
    value = _strict_json(raw, "analyzer source snapshots")
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "snapshot_id", "source_files"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["snapshot_id"] != "gh97-analyzer-source-snapshot-v1"
        or not isinstance(value["source_files"], list)
    ):
        raise MatrixEvidenceError("committed analyzer source snapshot has invalid schema")
    rows = value["source_files"]
    expected = list(ANALYZER_SOURCE_PATHS)
    if (
        any(
            not isinstance(row, dict)
            or set(row) != {"path", "sha256"}
            or not _safe_relative(row["path"])
            or not _is_sha(row["sha256"])
            for row in rows
        )
        or [row["path"] for row in rows] != expected
    ):
        raise MatrixEvidenceError("committed analyzer source snapshot path set is invalid")
    hashes = {row["path"]: f"sha256:{row['sha256']}" for row in rows}
    for relpath, expected_hash in hashes.items():
        try:
            actual = f"sha256:{_sha256((PROJECT_ROOT / relpath).read_bytes())}"
        except OSError as exc:
            raise MatrixEvidenceError(f"missing analyzer snapshot source: {relpath}") from exc
        if actual != expected_hash:
            raise MatrixEvidenceError(f"analyzer source differs from committed snapshot: {relpath}")
    return hashes, f"sha256:{_sha256(raw)}"


def _is_sha(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _safe_relative(value: object, *, prefix: str | None = None) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and path.as_posix() == value
        and (prefix is None or value.startswith(prefix))
    )


def _validate_manifest(value: Any) -> dict[str, Any]:  # noqa: PLR0912, PLR0915
    if not isinstance(value, dict):
        raise MatrixEvidenceError("package matrix root must be an object")
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
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 2
        or value["matrix_id"] != "effect-preset-package-matrix-v2"
        or value["matrix_version"] != "2.0.0"
        or not isinstance(value["source_inspection_method"], str)
        or not value["source_inspection_method"]
        or value["range_compatibility"]
        != "not_evaluated; each release row is one exact artifact only"
    ):
        raise MatrixEvidenceError("unsupported or invalid package matrix identity")

    contract_sets = value["versioned_contract_sets"]
    if not isinstance(contract_sets, list) or not contract_sets:
        raise MatrixEvidenceError("matrix has no versioned preset contract sets")
    contract_ids: set[str] = set()
    for row in contract_sets:
        fields = {
            "preset_id",
            "version",
            "revision",
            "preset_path",
            "preset_sha256",
            "preset_semantic_sha256",
            "config_sha256",
            "contract_inventory_sha256",
            "contract_count",
            "symbol_scope",
        }
        if not isinstance(row, dict) or set(row) != fields:
            raise MatrixEvidenceError("versioned preset contract row has invalid fields")
        if (
            not isinstance(row["preset_id"], str)
            or not row["preset_id"]
            or row["preset_id"] in contract_ids
            or not isinstance(row["version"], str)
            or not row["version"]
            or not isinstance(row["revision"], str)
            or not row["revision"]
            or not _safe_relative(
                row["preset_path"], prefix="src/fastapi_endpoint_detector/presets/"
            )
            or any(
                not _is_sha(row[key])
                for key in (
                    "preset_sha256",
                    "preset_semantic_sha256",
                    "config_sha256",
                    "contract_inventory_sha256",
                )
            )
            or type(row["contract_count"]) is not int
            or row["contract_count"] < 1
            or row["symbol_scope"]
            != "exact preset symbols and selectors covered by preset semantic hash"
        ):
            raise MatrixEvidenceError("invalid versioned preset contract identity")
        contract_ids.add(row["preset_id"])

    packages = value["packages"]
    if not isinstance(packages, list) or not packages:
        raise MatrixEvidenceError("package matrix has no audited packages")
    package_fields = {
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
    symbols_by_package: set[tuple[str, str]] = set()
    releases: set[tuple[str, str]] = set()
    for package in packages:
        if not isinstance(package, dict) or set(package) != package_fields:
            raise MatrixEvidenceError("package rows must have the exact v2 field set")
        name, version = package["distribution"], package["version"]
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(version, str)
            or not version
            or (name, version) in releases
            or not isinstance(package["artifact"], str)
            or Path(package["artifact"]).name != package["artifact"]
            or not (
                package["artifact"].endswith(".whl")
                or package["artifact"].endswith(".tgz")
                or package["artifact"].endswith(".tar.gz")
            )
            or not isinstance(package["artifact_url"], str)
            or not package["artifact_url"].startswith("https://")
            or not isinstance(package["release_source"], str)
            or not package["release_source"].startswith("https://")
            or not _is_sha(package["artifact_sha256"])
        ):
            raise MatrixEvidenceError("invalid exact package release identity")
        releases.add((name, version))
        metadata_values = (
            package["metadata_file"],
            package["metadata_sha256"],
            package["metadata_name"],
            package["metadata_version"],
        )
        if package["artifact"].endswith(".whl"):
            if (
                any(not isinstance(item, str) or not item for item in metadata_values)
                or not _safe_relative(package["metadata_file"])
                or not package["metadata_file"].endswith(".dist-info/METADATA")
                or not _is_sha(package["metadata_sha256"])
                or package["metadata_name"] != name
                or package["metadata_version"] != version
            ):
                raise MatrixEvidenceError(f"invalid wheel metadata identity for {name}")
        elif any(item is not None for item in metadata_values):
            raise MatrixEvidenceError(f"source archive must not claim wheel metadata: {name}")

        if not isinstance(package["source_status"], str) or package["source_status"] not in {
            "inspected",
            "partially_inspected",
            "unavailable",
        }:
            raise MatrixEvidenceError(f"invalid source status for {name}")
        sources, declarations = package["inspected_sources"], package["declared_symbols"]
        if not isinstance(sources, list) or not isinstance(declarations, list):
            raise MatrixEvidenceError(f"invalid source or symbol list for {name}")
        if package["source_status"] == "unavailable" and (sources or declarations):
            raise MatrixEvidenceError(
                f"unavailable package cannot declare inspected evidence: {name}"
            )
        seen_sources: set[str] = set()
        for source in sources:
            if (
                not isinstance(source, dict)
                or set(source) != {"path", "sha256"}
                or not _safe_relative(source["path"])
                or not _is_sha(source["sha256"])
                or source["path"] in seen_sources
            ):
                raise MatrixEvidenceError(f"invalid inspected source identity for {name}")
            seen_sources.add(source["path"])
        declaration_fields = {
            "symbol",
            "receiver",
            "parameters",
            "resource",
            "value",
            "preset_contract",
            "source_signature",
            "contract_resource_selector",
            "contract_value_selector",
        }
        seen_symbols: set[str] = set()
        for declaration in declarations:
            if not isinstance(declaration, dict) or set(declaration) != declaration_fields:
                raise MatrixEvidenceError(f"declared symbol row has invalid fields for {name}")
            symbol = declaration["symbol"]
            if (
                not isinstance(symbol, str)
                or re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", symbol) is None
                or symbol in seen_symbols
                or not isinstance(declaration["receiver"], str)
                or not declaration["receiver"]
                or not isinstance(declaration["source_signature"], str)
                or not declaration["source_signature"]
                or not isinstance(declaration["resource"], str)
                or not declaration["resource"]
                or not isinstance(declaration["parameters"], list)
                or any(not isinstance(item, str) or not item for item in declaration["parameters"])
                or (declaration["value"] is not None and not isinstance(declaration["value"], str))
                or (
                    declaration["preset_contract"] is not None
                    and not isinstance(declaration["preset_contract"], str)
                )
                or (
                    declaration["contract_resource_selector"] is not None
                    and not isinstance(declaration["contract_resource_selector"], dict)
                )
                or (
                    declaration["contract_value_selector"] is not None
                    and not isinstance(declaration["contract_value_selector"], dict)
                )
            ):
                raise MatrixEvidenceError(f"invalid exact symbol evidence for {name}")
            seen_symbols.add(symbol)
            symbols_by_package.add((name, symbol))

    controlled = value["controlled_evaluation"]
    if not isinstance(controlled, dict) or set(controlled) != {
        "status",
        "analyzer_observations",
        "positive_matches",
        "negative_unrelated_same_name_calls",
        "negative_unmatched_open_constructors",
        "unresolved_calls",
        "ambiguous_calls",
        "receiver_origins",
        "real_package_execution",
        "fixture_execution",
        "note",
    }:
        raise MatrixEvidenceError("controlled evaluation summary has invalid fields")
    if controlled["status"] != "completed" or any(
        type(controlled[key]) is not int or controlled[key] < 0
        for key in (
            "analyzer_observations",
            "positive_matches",
            "negative_unrelated_same_name_calls",
            "negative_unmatched_open_constructors",
            "unresolved_calls",
            "ambiguous_calls",
        )
    ):
        raise MatrixEvidenceError("controlled evaluation summary has invalid status/counts")
    if (
        controlled["analyzer_observations"] != 1
        or not isinstance(controlled["receiver_origins"], dict)
        or controlled["receiver_origins"]
        != {
            "builtins.open.read": "exact",
            "pathlib.Path.open.read": "unavailable:receiver_origin_unsupported",
        }
        or controlled["real_package_execution"] is not False
        or controlled["fixture_execution"] is not False
        or not isinstance(controlled["note"], str)
    ):
        raise MatrixEvidenceError("controlled evaluation execution policy is invalid")

    real_world = value["real_world_evaluation"]
    if (
        not isinstance(real_world, dict)
        or set(real_world)
        != {
            "status",
            "frozen_source_diffs",
            "note",
        }
        or real_world["status"] != "not_evaluated"
        or type(real_world["frozen_source_diffs"]) is not int
        or real_world["frozen_source_diffs"] != 0
        or not isinstance(real_world["note"], str)
    ):
        raise MatrixEvidenceError("real-world evaluation status is invalid")

    unsupported = value["unsupported_cases"]
    if not isinstance(unsupported, list):
        raise MatrixEvidenceError("unsupported package cases must be an array")
    for case in unsupported:
        if (
            not isinstance(case, dict)
            or set(case)
            != {
                "distribution",
                "version",
                "status",
                "evidence",
            }
            or any(not isinstance(case[key], str) or not case[key] for key in case)
        ):
            raise MatrixEvidenceError("unsupported package case has an invalid field set")
    return value


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    """Load and structurally validate strict JSON manifest bytes."""
    try:
        value = _strict_json(path.read_bytes(), "package matrix manifest")
    except OSError as exc:
        raise MatrixEvidenceError(f"cannot read package matrix manifest: {path}") from exc
    return _validate_manifest(value)


def _validated_manifest(manifest: dict[str, Any] | None) -> dict[str, Any]:
    return _validate_manifest(manifest) if manifest is not None else load_manifest()


def verify_artifacts(artifact_dir: Path, manifest: dict[str, Any] | None = None) -> dict[str, str]:
    """Verify supplied exact wheels/source archives, metadata and inspected file bytes."""
    frozen = _validated_manifest(manifest)
    observed: dict[str, str] = {}
    for package in frozen["packages"]:
        path = artifact_dir / package["artifact"]
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise MatrixEvidenceError(f"missing frozen package artifact: {path.name}") from exc
        if _sha256(raw) != package["artifact_sha256"]:
            raise MatrixEvidenceError(f"package artifact hash mismatch: {path.name}")
        try:
            if path.suffix == ".whl":
                with zipfile.ZipFile(path) as archive:
                    metadata_raw = archive.read(package["metadata_file"])
                    metadata = Parser().parsestr(metadata_raw.decode("utf-8"))
                    if (
                        _sha256(metadata_raw) != package["metadata_sha256"]
                        or metadata.get("Name") != package["metadata_name"]
                        or metadata.get("Version") != package["metadata_version"]
                    ):
                        raise MatrixEvidenceError(
                            "distribution metadata does not match matrix: "
                            f"{package['distribution']}"
                        )
                    for source in package["inspected_sources"]:
                        if _sha256(archive.read(source["path"])) != source["sha256"]:
                            raise MatrixEvidenceError(
                                f"inspected source hash mismatch: {package['distribution']}"
                            )
            else:
                with tarfile.open(path, "r:gz") as archive:
                    for source in package["inspected_sources"]:
                        matches = [
                            member
                            for member in archive.getmembers()
                            if member.isfile() and member.name.endswith("/" + source["path"])
                        ]
                        stream = archive.extractfile(matches[0]) if len(matches) == 1 else None
                        if stream is None or _sha256(stream.read()) != source["sha256"]:
                            raise MatrixEvidenceError(
                                f"inspected source hash mismatch: {package['distribution']}"
                            )
        except MatrixEvidenceError:
            raise
        except (
            OSError,
            UnicodeDecodeError,
            KeyError,
            TypeError,
            zipfile.BadZipFile,
            tarfile.TarError,
        ) as exc:
            raise MatrixEvidenceError(f"cannot inspect frozen artifact: {path.name}") from exc
        observed[package["distribution"]] = f"sha256:{package['artifact_sha256']}"
    return observed


def _function_nodes(
    nodes: list[ast.stmt], owners: tuple[str, ...] = ()
) -> list[tuple[tuple[str, ...], ast.FunctionDef | ast.AsyncFunctionDef]]:
    found: list[tuple[tuple[str, ...], ast.FunctionDef | ast.AsyncFunctionDef]] = []
    for node in nodes:
        if isinstance(node, ast.ClassDef):
            found.extend(_function_nodes(node.body, (*owners, node.name)))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found.append(((*owners, node.name), node))
        else:
            for field in ("body", "orelse", "finalbody"):
                children = getattr(node, field, None)
                if isinstance(children, list):
                    found.extend(_function_nodes(children, owners))
            for handler in getattr(node, "handlers", ()):
                found.extend(_function_nodes(handler.body, owners))
    return found


def _formal_parameter_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = node.args
    names = [arg.arg for arg in (*args.posonlyargs, *args.args) if arg.arg != "self"]
    if args.vararg is not None:
        names.append("*" + args.vararg.arg)
    names.extend(arg.arg for arg in args.kwonlyargs)
    return names


def _selector_parameter_names(declaration: dict[str, Any]) -> list[str]:
    return [
        parameter.split("=", 1)[0]
        for parameter in declaration["parameters"]
        if not parameter.startswith("**")
    ]


def verify_declared_python_signatures(  # noqa: PLR0912, PLR0915
    artifact_dir: Path, manifest: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Reconcile callable signatures, selectors and required fields with hashed source."""
    frozen = _validated_manifest(manifest)
    verify_artifacts(artifact_dir, frozen)
    rows: list[dict[str, Any]] = []
    partial: list[dict[str, str]] = []
    for package in frozen["packages"]:
        artifact = artifact_dir / package["artifact"]
        source_modules: dict[str, tuple[str, str, ast.Module]] = {}
        for source in package["inspected_sources"]:
            if not source["path"].endswith(".py"):
                continue
            try:
                if artifact.suffix == ".whl":
                    with zipfile.ZipFile(artifact) as archive:
                        raw = archive.read(source["path"])
                else:
                    with tarfile.open(artifact, "r:gz") as archive:
                        tar_members = [
                            candidate
                            for candidate in archive.getmembers()
                            if candidate.isfile() and candidate.name.endswith("/" + source["path"])
                        ]
                        member = (
                            archive.extractfile(tar_members[0]) if len(tar_members) == 1 else None
                        )
                        if member is None:
                            raise KeyError(source["path"])
                        raw = member.read()
                tree = ast.parse(raw.decode("utf-8"), filename=source["path"])
            except (
                OSError,
                UnicodeDecodeError,
                KeyError,
                SyntaxError,
                zipfile.BadZipFile,
                tarfile.TarError,
            ) as exc:
                raise MatrixEvidenceError(
                    f"cannot parse hashed Python source: {package['distribution']}:{source['path']}"
                ) from exc
            module_path = source["path"]
            if module_path.startswith("Lib/"):
                module_path = module_path.removeprefix("Lib/")
            module = ".".join(module_path[:-3].split("/"))
            source_modules[module] = (source["path"], source["sha256"], tree)
        for declaration in package["declared_symbols"]:
            symbol = declaration["symbol"]
            module_entry = next(
                (
                    (module, data)
                    for module, data in source_modules.items()
                    if symbol.startswith(module + ".")
                ),
                None,
            )
            if module_entry is None:
                partial.append(
                    {
                        "distribution": package["distribution"],
                        "version": package["version"],
                        "symbol": symbol,
                        "status": "not_python_source_declared",
                        "source_signature": declaration["source_signature"],
                    }
                )
                continue
            module, (source_path, source_hash, tree) = module_entry
            parts = tuple(symbol[len(module) + 1 :].split("."))
            callable_matches = [
                node for owners, node in _function_nodes(tree.body) if owners == parts
            ]
            if not callable_matches:
                partial.append(
                    {
                        "distribution": package["distribution"],
                        "version": package["version"],
                        "symbol": symbol,
                        "status": "not_function_definition_in_inspected_python_source",
                        "source_signature": declaration["source_signature"],
                    }
                )
                continue
            node = callable_matches[-1]
            actual_signature = ("async " if isinstance(node, ast.AsyncFunctionDef) else "") + (
                "(" + ast.unparse(node.args) + ")"
            )
            if actual_signature != declaration["source_signature"]:
                raise MatrixEvidenceError(
                    f"source signature mismatch for {package['distribution']}:{symbol}"
                )
            unpack_match = re.search(r"Unpack\[([A-Za-z_]\w*)\]", actual_signature)
            if unpack_match is not None:
                type_name = unpack_match.group(1)
                type_module = next(
                    (
                        module
                        for module in source_modules.values()
                        if module[0].endswith("/type_defs.py")
                    ),
                    None,
                )
                if type_module is None:
                    raise MatrixEvidenceError(
                        "typed request keys lack a hashed TypeDef source: "
                        f"{package['distribution']}"
                    )
                type_path, type_hash, type_tree = type_module
                typed_dict = next(
                    (
                        node
                        for node in ast.walk(type_tree)
                        if isinstance(node, ast.ClassDef) and node.name == type_name
                    ),
                    None,
                )
                if typed_dict is None:
                    raise MatrixEvidenceError(f"missing typed request definition: {type_name}")
                selector_names = [
                    item.target.id
                    for item in typed_dict.body
                    if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)
                ]
                typed_dict_total = next(
                    (
                        keyword.value.value is True
                        for keyword in typed_dict.keywords
                        if keyword.arg == "total" and isinstance(keyword.value, ast.Constant)
                    ),
                    True,
                )
                selector_required_names = []
                for item in typed_dict.body:
                    if not isinstance(item, ast.AnnAssign) or not isinstance(item.target, ast.Name):
                        continue
                    annotation_text = ast.unparse(item.annotation)
                    explicitly_required = annotation_text.startswith("Required[")
                    explicitly_optional = annotation_text.startswith("NotRequired[")
                    if explicitly_required or (typed_dict_total and not explicitly_optional):
                        selector_required_names.append(item.target.id)
                selector_kind = "TypedDict_fields"
            else:
                type_path, type_hash = source_path, source_hash
                selector_names = _formal_parameter_names(node)
                positional_parameters = [*node.args.posonlyargs, *node.args.args]
                required_positional_count = len(positional_parameters) - len(node.args.defaults)
                selector_required_names = [
                    item.arg
                    for item in positional_parameters[:required_positional_count]
                    if item.arg != "self"
                ]
                selector_required_names.extend(
                    item.arg
                    for item, default in zip(
                        node.args.kwonlyargs, node.args.kw_defaults, strict=True
                    )
                    if default is None
                )
                selector_kind = "callable_parameters"
            if selector_names != _selector_parameter_names(declaration):
                raise MatrixEvidenceError(
                    f"argument selector parameters mismatch for {package['distribution']}:{symbol}"
                )
            rows.append(
                {
                    "distribution": package["distribution"],
                    "version": package["version"],
                    "symbol": symbol,
                    "source_path": source_path,
                    "source_sha256": f"sha256:{source_hash}",
                    "signature": actual_signature,
                    "selector_source_path": type_path,
                    "selector_source_sha256": f"sha256:{type_hash}",
                    "selector_kind": selector_kind,
                    "selector_parameters": selector_names,
                    "selector_required_parameters": selector_required_names,
                    "status": "exact_source_signature_and_selector_match",
                }
            )
    return {"verified_callable_signatures": rows, "partial_declarations": partial}


def load_source_signature_observations(
    artifact_dir: Path,
    path: Path = MATRIX_ROOT / "source-signature-observations.json",
) -> dict[str, Any]:
    """Validate source-signature rows by re-reading only their supplied pinned artifacts."""
    try:
        value = _strict_json(path.read_bytes(), "source signature observations")
    except OSError as exc:
        raise MatrixEvidenceError(f"cannot read source signature observations: {path}") from exc
    fields = {
        "schema_version",
        "report_id",
        "status",
        "manifest_sha256",
        "release_artifacts",
        "artifact_directory_verified",
        "source_execution",
        "counts",
        "verified_callable_signatures",
        "partial_declarations",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise MatrixEvidenceError("source signature report has invalid fields")
    manifest = load_manifest()
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 2
        or value["report_id"] != "effect-preset-source-signature-observations-v2"
        or value["status"] != "partial"
        or value["manifest_sha256"] != f"sha256:{_sha256(MANIFEST_PATH.read_bytes())}"
        or value["artifact_directory_verified"] is not True
        or value["source_execution"] is not False
    ):
        raise MatrixEvidenceError("source signature report provenance/status is invalid")
    expected_artifacts = [
        {
            "distribution": row["distribution"],
            "version": row["version"],
            "artifact": row["artifact"],
            "artifact_sha256": f"sha256:{row['artifact_sha256']}",
        }
        for row in manifest["packages"]
    ]
    if value["release_artifacts"] != expected_artifacts:
        raise MatrixEvidenceError("source signature report has different package artifacts")
    computed = verify_declared_python_signatures(artifact_dir, manifest)
    if (
        value["verified_callable_signatures"] != computed["verified_callable_signatures"]
        or value["partial_declarations"] != computed["partial_declarations"]
    ):
        raise MatrixEvidenceError(
            "source signature observations do not match pinned package source"
        )
    counts = value["counts"]
    expected_counts = {
        "verified_callable_signatures": len(computed["verified_callable_signatures"]),
        "partial_declarations": len(computed["partial_declarations"]),
    }
    if counts != expected_counts:
        raise MatrixEvidenceError("source signature report counts do not match observations")
    return value


def verify_preset_contracts(manifest: dict[str, Any] | None = None) -> dict[str, str]:
    """Parse each pinned preset and verify its identity, count, selectors and raw bytes."""
    frozen = _validated_manifest(manifest)
    observed: dict[str, str] = {}
    contract_lookup: dict[str, Any] = {}
    for row in frozen["versioned_contract_sets"]:
        path = (PROJECT_ROOT / row["preset_path"]).resolve()
        try:
            path.relative_to(PROJECT_ROOT.resolve())
            loaded = load_effect_contracts(path)
        except (OSError, ValueError, EffectContractError) as exc:
            raise MatrixEvidenceError(f"cannot parse frozen preset: {row['preset_id']}") from exc
        preset = loaded.document.preset
        actual = {
            "preset_id": preset.id,
            "version": preset.version,
            "revision": preset.provenance.revision,
            "contract_count": len(loaded.document.contracts),
            "preset_sha256": loaded.raw_hash.removeprefix("sha256:"),
            "preset_semantic_sha256": loaded.preset_hash.removeprefix("sha256:"),
            "config_sha256": loaded.config_hash.removeprefix("sha256:"),
            "contract_inventory_sha256": _sha256(
                json.dumps(loaded.contract_hashes, sort_keys=True, separators=(",", ":")).encode()
            ),
        }
        expected = {key: row[key] for key in actual}
        if actual != expected:
            raise MatrixEvidenceError(
                f"preset identity, count, selectors or hashes mismatch: {row['preset_id']}"
            )
        observed[row["preset_id"]] = loaded.raw_hash
        for contract in loaded.document.contracts:
            if contract.id in contract_lookup:
                raise MatrixEvidenceError(
                    f"duplicate preset contract ID across sets: {contract.id}"
                )
            contract_lookup[contract.id] = contract
    for package in frozen["packages"]:
        for declaration in package["declared_symbols"]:
            contract_id = declaration["preset_contract"]
            resource_selector = declaration["contract_resource_selector"]
            value_selector = declaration["contract_value_selector"]
            if contract_id is None:
                if resource_selector is not None or value_selector is not None:
                    raise MatrixEvidenceError("unmapped symbol cannot claim preset selectors")
                continue
            selected_contract = contract_lookup.get(contract_id)
            if selected_contract is None or selected_contract.symbol != declaration["symbol"]:
                raise MatrixEvidenceError(
                    f"package symbol does not map to exact preset contract: {declaration['symbol']}"
                )
            actual_resource = selected_contract.resource.model_dump(mode="json")
            actual_value = (
                selected_contract.value.model_dump(mode="json")
                if selected_contract.value is not None
                else None
            )
            if resource_selector != actual_resource or value_selector != actual_value:
                raise MatrixEvidenceError(
                    f"preset selector semantics mismatch: {declaration['symbol']}"
                )
    return observed


def summarize_matrix(manifest: dict[str, Any] | None = None) -> dict[str, object]:
    """Return source inspection and controlled evaluation counts as separate evidence."""
    frozen = _validated_manifest(manifest)
    packages = frozen["packages"]
    return {
        "matrix_id": frozen["matrix_id"],
        "package_releases": len(packages),
        "source_inspected": sum(row["source_status"] == "inspected" for row in packages),
        "source_partially_inspected": sum(
            row["source_status"] == "partially_inspected" for row in packages
        ),
        "source_unavailable": sum(row["source_status"] == "unavailable" for row in packages),
        "analyzer_observations": frozen["controlled_evaluation"]["analyzer_observations"],
        "unsupported_cases": len(frozen["unsupported_cases"]),
        "range_compatibility": frozen["range_compatibility"],
        "real_world_evaluation": frozen["real_world_evaluation"]["status"],
    }


def exact_release_status(
    distribution: str,
    version: str,
    manifest: dict[str, Any] | None = None,
) -> str:
    """Report only exact releases present in the audit; never infer a version range."""
    frozen = _validated_manifest(manifest)
    for package in frozen["packages"]:
        if package["distribution"] == distribution and package["version"] == version:
            return "audited_exact_release"
    return "not_audited"


def _receiver_origin(occurrence: Any) -> dict[str, Any] | None:
    origin = occurrence.receiver_origin
    if origin is None:
        return None
    return dict(origin.model_dump(mode="json"))


def _control_class(source_spelling: str) -> str:
    if source_spelling in {
        "foreign.read_text",
        "foreign.get",
        "foreign.set",
        "foreign.write",
        "foreign.send",
    }:
        return "unrelated_same_name_negative"
    if source_spelling.startswith("foreign."):
        return "unrelated_same_name_negative"
    if source_spelling in {"open", "path.open"}:
        return "unmatched_open_constructor"
    return "positive_or_neutral"


def _build_observations(audit: Any, call_sites: list[Any]) -> list[dict[str, Any]]:
    sites = {(Path(site.file_path).name, site.line, site.column): site for site in call_sites}
    rows: list[dict[str, Any]] = []
    for occurrence in audit.occurrences:
        site = sites.get((occurrence.file_path, occurrence.line, occurrence.column))
        if site is None:
            raise MatrixEvidenceError("auditor occurrence has no matching resolver call site")
        row = occurrence.model_dump(mode="json", exclude={"endpoints"})
        for field in ("canonical_symbol",):
            symbol = row[field]
            if isinstance(symbol, str) and ".main." in symbol:
                row[field] = "main." + symbol.split(".main.", 1)[1]
        row["receiver_candidates"] = [
            "main." + item.split(".main.", 1)[1] if ".main." in item else item
            for item in row["receiver_candidates"]
        ]
        row["arguments"] = [item.model_dump(mode="json") for item in site.arguments]
        row["control_class"] = _control_class(occurrence.source_spelling)
        row["receiver_origin"] = _receiver_origin(occurrence)
        rows.append(row)
    rows.sort(key=lambda row: (row["file_path"], row["line"], row["column"]))
    return rows


def _endpoint(path: Path, line_number: int = 10) -> Endpoint:
    return Endpoint(
        path="/matrix",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler",
            module="main",
            file_path=path,
            line_number=line_number,
        ),
    )


def _replay_fixture() -> dict[str, Any]:
    """Statically analyze only the frozen synthetic fixture; never execute its source."""
    try:
        python_version, expected_mypy, _ = _replay_environment()
        fixture = FIXTURE_PATH.read_bytes()
        with tempfile.TemporaryDirectory(prefix="gh97_matrix_replay_") as temp:
            root = Path(temp)
            main = root / "main.py"
            main.write_bytes(fixture)
            endpoint = _endpoint(main)
            analyzer = MypyAnalyzer(root, max_depth=1)
            if analyzer.resolver_version.removeprefix("mypy ") != expected_mypy:
                raise MatrixEvidenceError("mypy resolver differs from selected exact environment")
            dependencies = analyzer.analyze_endpoint(endpoint)
            call_sites = dependencies.get_resolved_call_sites()
            loaded = load_effect_preset("filesystem-v1")
            audit = audit_effect_contracts(
                loaded,
                source_root=root,
                inventory=EndpointInventory(endpoints=[endpoint]),
                endpoint_call_sites=[(endpoint, call_sites)],
                track_transitive=False,
                max_depth=1,
                cache_enabled=False,
                resolver_versions=(f"mypy@{analyzer.resolver_version}",),
            )
            observations = _build_observations(audit, call_sites)
            return {
                "observations": observations,
                "resolver_version": analyzer.resolver_version,
                "python_version": python_version,
                "preset_raw_hash": loaded.raw_hash,
                "preset_config_hash": loaded.config_hash,
                "preset_semantic_hash": loaded.preset_hash,
            }
    except (OSError, ValueError, RuntimeError) as exc:
        raise MatrixEvidenceError("cannot replay static controlled fixture") from exc


def _render_case_arguments(arguments: Any) -> str:
    if not isinstance(arguments, list) or not arguments:
        raise MatrixEvidenceError("package analyzer case requires call arguments")
    positional: list[str] = []
    keywords: list[str] = []
    keyword_names: set[str] = set()
    for argument in arguments:
        if not isinstance(argument, dict) or set(argument) not in (
            {"kind", "value"},
            {"kind", "name", "value"},
        ):
            raise MatrixEvidenceError("package analyzer call argument has invalid fields")
        if not isinstance(argument["value"], str):
            raise MatrixEvidenceError("package analyzer fixture values must be strings")
        if argument["kind"] == "positional" and set(argument) == {"kind", "value"}:
            positional.append(repr(argument["value"]))
        elif (
            argument["kind"] == "keyword"
            and set(argument) == {"kind", "name", "value"}
            and isinstance(argument["name"], str)
            and argument["name"].isidentifier()
        ):
            if argument["name"] in keyword_names:
                raise MatrixEvidenceError("package analyzer call repeats a keyword binding")
            keyword_names.add(argument["name"])
            keywords.append(f"{argument['name']}={argument['value']!r}")
        else:
            raise MatrixEvidenceError("package analyzer call argument kind is invalid")
    return ", ".join((*positional, *keywords))


def _package_signature_evidence(
    package: dict[str, Any], declaration: dict[str, Any]
) -> dict[str, Any]:
    """Bind a generated analyzer surface to the exact artifact source audit row."""
    try:
        report = _strict_json(SIGNATURE_REPORT_PATH.read_bytes(), "source signature observations")
    except OSError as exc:
        raise MatrixEvidenceError("missing exact-artifact signature observations") from exc
    if (
        not isinstance(report, dict)
        or type(report.get("schema_version")) is not int
        or report.get("schema_version") != 2
        or report.get("report_id") != "effect-preset-source-signature-observations-v2"
        or report.get("manifest_sha256") != f"sha256:{_sha256(MANIFEST_PATH.read_bytes())}"
        or report.get("status") != "partial"
        or report.get("artifact_directory_verified") is not True
        or report.get("source_execution") is not False
    ):
        raise MatrixEvidenceError("source signature report is not bound to the pinned manifest")
    expected_artifacts = [
        {
            "distribution": row["distribution"],
            "version": row["version"],
            "artifact": row["artifact"],
            "artifact_sha256": f"sha256:{row['artifact_sha256']}",
        }
        for row in load_manifest()["packages"]
    ]
    if report.get("release_artifacts") != expected_artifacts:
        raise MatrixEvidenceError("source signature report artifact list differs from manifest")
    rows = report.get("verified_callable_signatures")
    if not isinstance(rows, list):
        raise MatrixEvidenceError("source signature report has no verified signature rows")
    matches = [
        row
        for row in rows
        if isinstance(row, dict)
        and row.get("distribution") == package["distribution"]
        and row.get("version") == package["version"]
        and row.get("symbol") == declaration["symbol"]
    ]
    if len(matches) != 1:
        raise MatrixEvidenceError(f"no unique pinned source signature for {declaration['symbol']}")
    row = matches[0]
    inspected = {item["path"]: f"sha256:{item['sha256']}" for item in package["inspected_sources"]}
    selector_parameters = row.get("selector_parameters")
    required_selectors = row.get("selector_required_parameters")
    if (
        not isinstance(selector_parameters, list)
        or any(not isinstance(item, str) for item in selector_parameters)
        or len(selector_parameters) != len(set(selector_parameters))
        or not isinstance(required_selectors, list)
        or any(not isinstance(item, str) for item in required_selectors)
        or len(required_selectors) != len(set(required_selectors))
        or any(item not in selector_parameters for item in required_selectors)
    ):
        raise MatrixEvidenceError("pinned required selector parameters are invalid")
    if row.get("selector_kind") == "TypedDict_fields":
        expected_selectors = _selector_parameter_names(declaration)
    else:
        source_signature = declaration["source_signature"].removeprefix("async ")
        try:
            parsed = ast.parse(f"def _pinned{source_signature}: ...").body[0]
        except SyntaxError as exc:
            raise MatrixEvidenceError(
                "pinned signature cannot be parsed for selector check"
            ) from exc
        if not isinstance(parsed, ast.FunctionDef):
            raise MatrixEvidenceError("pinned signature selector source is not a function")
        expected_selectors = _formal_parameter_names(parsed)
    if (
        row.get("status") != "exact_source_signature_and_selector_match"
        or row.get("signature") != declaration["source_signature"]
        or row.get("source_sha256") != inspected.get(row.get("source_path"))
        or row.get("selector_source_sha256") != inspected.get(row.get("selector_source_path"))
        or selector_parameters != expected_selectors
    ):
        raise MatrixEvidenceError(
            f"pinned source signature or selector evidence mismatch: {declaration['symbol']}"
        )
    return {
        "source_report_sha256": f"sha256:{_sha256(SIGNATURE_REPORT_PATH.read_bytes())}",
        "source_path": row["source_path"],
        "source_sha256": row["source_sha256"],
        "source_signature": row["signature"],
        "selector_source_path": row["selector_source_path"],
        "selector_source_sha256": row["selector_source_sha256"],
        "selector_kind": row["selector_kind"],
        "selector_parameters": row["selector_parameters"],
        "selector_required_parameters": required_selectors,
    }


def _stub_method_signature(  # noqa: PLR0912
    evidence: dict[str, Any],
) -> tuple[str, set[str] | None]:
    """Render a static stub with pinned names, binding kinds and required TypedDict keys."""
    signature = evidence["source_signature"]
    async_prefix = "async " if signature.startswith("async ") else ""
    signature = signature.removeprefix("async ")
    try:
        function = ast.parse(f"def _pinned{signature}: ...").body[0]
    except SyntaxError as exc:
        raise MatrixEvidenceError("pinned source signature cannot be parsed") from exc
    if not isinstance(function, ast.FunctionDef):
        raise MatrixEvidenceError("pinned source signature is not callable")
    args = function.args
    unpacked = any(
        arg.annotation is not None and "Unpack[" in ast.unparse(arg.annotation)
        for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]
    ) or (
        args.kwarg is not None
        and args.kwarg.annotation is not None
        and "Unpack[" in ast.unparse(args.kwarg.annotation)
    )
    typed_dict_keys: set[str] | None = set(evidence["selector_parameters"]) if unpacked else None
    positional = [*args.posonlyargs, *args.args]
    defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    rendered: list[str] = []
    for arg, default in zip(positional, defaults, strict=True):
        if arg.arg == "self":
            continue
        text = arg.arg
        if default is not None:
            text += " = ..."
        rendered.append(text)
    if args.vararg is not None:
        rendered.append(f"*{args.vararg.arg}")
    elif args.kwonlyargs:
        rendered.append("*")
    for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True):
        text = arg.arg
        if default is not None:
            text += " = ..."
        rendered.append(text)
    if unpacked:
        if typed_dict_keys is None:
            raise MatrixEvidenceError("typed dictionary selector keys are unavailable")
        for key in evidence["selector_parameters"]:
            if key not in typed_dict_keys:
                raise MatrixEvidenceError("typed dictionary selector key is invalid")
            required_suffix = "" if key in evidence["selector_required_parameters"] else " = ..."
            rendered.append(f"{key}{required_suffix}")
    elif args.kwarg is not None:
        rendered.append(f"**{args.kwarg.arg}")
    return (
        f"{async_prefix}def method(self{', ' if rendered else ''}"
        f"{', '.join(rendered)}) -> object: ...",
        typed_dict_keys,
    )


def _validate_case_binding(case: dict[str, Any], typed_dict_keys: set[str] | None) -> None:
    if typed_dict_keys is None:
        return
    for argument in case["arguments"]:
        if argument["kind"] == "keyword" and argument["name"] not in typed_dict_keys:
            raise MatrixEvidenceError(
                f"fixture keyword is absent from pinned TypedDict selector: {argument['name']}"
            )


def _selector_rows(selector: dict[str, Any], role: str) -> list[dict[str, Any]]:
    if selector.get("kind") == "composite":
        components = selector.get("components")
        if not isinstance(components, list):
            raise MatrixEvidenceError("composite contract selector has invalid components")
        return [{"role": role, "component": index, **item} for index, item in enumerate(components)]
    return [{"role": role, "component": None, **selector}]


def _contract_selector_bindings(
    arguments: list[dict[str, Any]], contract_selectors: dict[str, Any]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for role in ("resource", "value"):
        selector = contract_selectors.get(role)
        if selector is None:
            continue
        for item in _selector_rows(selector, role):
            kind = item.get("kind")
            if kind in {"none", "receiver"}:
                rows.append({**item, "binding_status": "present", "argument_index": None})
                continue
            if item.get("path"):
                raise MatrixEvidenceError("nested selector paths are outside package replay scope")
            selected_index = None
            if kind == "argument":
                positional_index = item.get("index")
                position = 0
                for argument_index, argument in enumerate(arguments):
                    if argument["kind"] != "positional":
                        continue
                    if position == positional_index:
                        selected_index = argument_index
                        break
                    position += 1
            elif kind == "keyword":
                selected_index = next(
                    (
                        index
                        for index, argument in enumerate(arguments)
                        if argument["kind"] == "keyword" and argument["name"] == item.get("name")
                    ),
                    None,
                )
            else:
                raise MatrixEvidenceError(f"unsupported contract selector kind: {kind}")
            if selected_index is None:
                selected_name = item.get("name") or f"argument index {item.get('index')}"
                raise MatrixEvidenceError(
                    f"contract-selected {role} argument is absent or wrongly bound: {selected_name}"
                )
            rows.append({**item, "binding_status": "present", "argument_index": selected_index})
    return rows


def _run_selector_binding_control(
    case: dict[str, Any],
    evidence: dict[str, Any],
    contract_selectors: dict[str, Any],
    *,
    control_id: str,
    arguments: list[dict[str, Any]],
    expected_missing: str,
    expected_contract_id: str,
) -> dict[str, Any]:
    altered = {**case, "arguments": arguments, "case_id": f"{case['case_id']}:{control_id}"}
    replay = _replay_package_case(
        altered, evidence, contract_selectors, allow_selector_mismatch=True
    )
    rows = replay["observations"]
    if (
        len(rows) != 2
        or rows[0]["audit_status"] != "matched"
        or rows[0]["contract_id"] != expected_contract_id
        or replay["selector_binding_issue"] is None
        or expected_missing not in replay["selector_binding_issue"]
    ):
        raise MatrixEvidenceError(f"selector binding negative control failed: {control_id}")
    return {
        "control_id": control_id,
        "fixture_sha256": replay["fixture_sha256"],
        "analyzer_audit_status": rows[0]["audit_status"],
        "analyzer_contract_id": rows[0]["contract_id"],
        "selector_binding_status": "rejected_incomplete_or_wrong_binding",
        "selector_binding_issue": replay["selector_binding_issue"],
        "observations": rows,
    }


def _replay_package_case(
    case: dict[str, Any],
    signature_evidence: dict[str, Any],
    contract_selectors: dict[str, Any],
    *,
    allow_selector_mismatch: bool = False,
) -> dict[str, Any]:
    """Resolve a source-derived canonical receiver against one exact contract."""
    module, class_name, method = case["symbol"].rsplit(".", 2)
    module_parts = module.split(".")
    arguments = _render_case_arguments(case["arguments"])
    method_signature, typed_dict_keys = _stub_method_signature(signature_evidence)
    _validate_case_binding(case, typed_dict_keys)
    selector_binding_issue = None
    try:
        selector_bindings = _contract_selector_bindings(case["arguments"], contract_selectors)
    except MatrixEvidenceError as exc:
        if not allow_selector_mismatch:
            raise
        selector_binding_issue = str(exc)
        selector_bindings = []
    app_call = f"client.{method}({arguments})"
    negative_call = f"foreign.{method}({arguments})"
    fixture = (
        f"from {module} import {class_name} as Client\n\n"
        "class Foreign:\n"
        f"    def {method}(self, *args: object, **kwargs: object) -> object: ...\n\n"
        "def handler(client: Client, foreign: Foreign) -> None:\n"
        f"    {app_call}\n"
        f"    {negative_call}\n"
    )
    try:
        with tempfile.TemporaryDirectory(prefix="gh97_package_case_") as temp:
            top = Path(temp)
            app = top / "app"
            app.mkdir()
            main = app / "main.py"
            main.write_text(fixture, encoding="utf-8")
            current = top
            for part in module_parts[:-1]:
                current = current / part
                current.mkdir(exist_ok=True)
                (current / "__init__.py").write_text("", encoding="utf-8")
            (current / f"{module_parts[-1]}.py").write_text(
                f"class {class_name}:\n    {method_signature.replace('method', method, 1)}\n",
                encoding="utf-8",
            )
            endpoint = _endpoint(main, line_number=6)
            analyzer = MypyAnalyzer(app, max_depth=1)
            dependencies = analyzer.analyze_endpoint(endpoint)
            call_sites = dependencies.get_resolved_call_sites()
            preset = load_effect_preset(case["preset_selector"])
            audit = audit_effect_contracts(
                preset,
                source_root=app,
                inventory=EndpointInventory(endpoints=[endpoint]),
                endpoint_call_sites=[(endpoint, call_sites)],
                track_transitive=False,
                max_depth=1,
                cache_enabled=False,
                resolver_versions=(f"mypy@{analyzer.resolver_version}",),
            )
            rows = _build_observations(audit, call_sites)
            return {
                "fixture_sha256": f"sha256:{_sha256(fixture.encode())}",
                "resolver_version": analyzer.resolver_version,
                "signature_evidence": signature_evidence,
                "generated_signature": method_signature,
                "selector_bindings": selector_bindings,
                "selector_binding_issue": selector_binding_issue,
                "observations": rows,
            }
    except (OSError, ValueError, RuntimeError) as exc:
        raise MatrixEvidenceError(
            f"cannot replay controlled package case: {case['case_id']}"
        ) from exc


def replay_package_analyzer_cases() -> list[dict[str, Any]]:
    """Run analyzer cases with source-derived parameter and selector surfaces."""
    try:
        case_data = _strict_json(PACKAGE_CASES_PATH.read_bytes(), "package analyzer cases")
    except OSError as exc:
        raise MatrixEvidenceError("cannot read package analyzer case fixture") from exc
    if (
        not isinstance(case_data, dict)
        or set(case_data) != {"schema_version", "fixture_id", "cases", "unsupported_cases"}
        or type(case_data["schema_version"]) is not int
        or case_data["schema_version"] != 2
        or case_data["fixture_id"] != "gh97-package-analyzer-cases-v2"
        or not isinstance(case_data["cases"], list)
    ):
        raise MatrixEvidenceError("package analyzer case fixture has invalid schema")
    manifest = load_manifest()
    verify_preset_contracts(manifest)
    releases = {(row["distribution"], row["version"]): row for row in manifest["packages"]}
    presets = {row["preset_id"]: row for row in manifest["versioned_contract_sets"]}
    seen: set[str] = set()
    results: list[dict[str, Any]] = []
    for case in case_data["cases"]:
        fields = {"case_id", "distribution", "version", "symbol", "preset_selector", "arguments"}
        if not isinstance(case, dict) or set(case) != fields:
            raise MatrixEvidenceError("package analyzer case has invalid fields")
        if (
            not isinstance(case["case_id"], str)
            or not case["case_id"]
            or case["case_id"] in seen
            or not isinstance(case["distribution"], str)
            or not isinstance(case["version"], str)
            or not isinstance(case["symbol"], str)
            or not isinstance(case["preset_selector"], str)
        ):
            raise MatrixEvidenceError("package analyzer case identity is invalid")
        seen.add(case["case_id"])
        package = releases.get((case["distribution"], case["version"]))
        if package is None:
            raise MatrixEvidenceError("package analyzer case references an unaudited release")
        declaration = next(
            (row for row in package["declared_symbols"] if row["symbol"] == case["symbol"]), None
        )
        if declaration is None or declaration["preset_contract"] is None:
            raise MatrixEvidenceError("package analyzer case lacks a pinned preset symbol")
        contract_set_id = next(
            (
                contract_set["preset_id"]
                for contract_set in manifest["versioned_contract_sets"]
                if contract_set["preset_path"].endswith(
                    {
                        "http-clients-v1": "effects_http_clients_v1.yaml",
                        "redis-v1": "effects_redis_v1.yaml",
                        "mongodb-v1": "effects_mongodb_v1.yaml",
                        "sqlalchemy-v1": "effects_sqlalchemy_v1.yaml",
                        "object-storage-v1": "effects_object_storage_v1.yaml",
                    }.get(case["preset_selector"], "<unsupported>")
                )
            ),
            None,
        )
        if contract_set_id is None or contract_set_id not in presets:
            raise MatrixEvidenceError("package analyzer case preset is not pinned")
        signature_evidence = _package_signature_evidence(package, declaration)
        loaded_preset = load_effect_preset(case["preset_selector"])
        contract = next(
            (
                item
                for item in loaded_preset.document.contracts
                if item.id == declaration["preset_contract"]
            ),
            None,
        )
        if contract is None:
            raise MatrixEvidenceError(
                "pinned preset does not contain the selected package contract"
            )
        contract_selectors = {
            "resource": contract.resource.model_dump(mode="json"),
            "value": (
                contract.value.model_dump(mode="json") if contract.value is not None else None
            ),
        }
        result = _replay_package_case(case, signature_evidence, contract_selectors)
        result.update(
            {
                "case_id": case["case_id"],
                "distribution": package["distribution"],
                "version": package["version"],
                "artifact_sha256": f"sha256:{package['artifact_sha256']}",
                "symbol": case["symbol"],
                "contract_id": declaration["preset_contract"],
                "preset_id": contract_set_id,
                "preset_version": presets[contract_set_id]["version"],
                "preset_revision": presets[contract_set_id]["revision"],
                "preset_sha256": f"sha256:{presets[contract_set_id]['preset_sha256']}",
                "preset_semantic_sha256": (
                    f"sha256:{presets[contract_set_id]['preset_semantic_sha256']}"
                ),
                "config_sha256": f"sha256:{presets[contract_set_id]['config_sha256']}",
            }
        )
        rows = result["observations"]
        if (
            len(rows) != 2
            or rows[0]["canonical_symbol"] != case["symbol"]
            or rows[0]["audit_status"] != "matched"
            or rows[0]["contract_id"] != declaration["preset_contract"]
            or rows[1]["audit_status"] != "unmatched"
            or rows[1]["control_class"] != "unrelated_same_name_negative"
        ):
            raise MatrixEvidenceError(
                f"controlled package case failed its exact control: {case['case_id']}"
            )
        result["binding_controls"] = []
        if case["case_id"] == "typed-s3-put-object-exact-release-symbol":
            body = next(
                (
                    argument
                    for argument in case["arguments"]
                    if argument.get("kind") == "keyword" and argument.get("name") == "Body"
                ),
                None,
            )
            if body is None:
                raise MatrixEvidenceError("typed S3 positive case lacks the selected Body")
            omitted = [argument for argument in case["arguments"] if argument is not body]
            result["binding_controls"] = [
                _run_selector_binding_control(
                    case,
                    signature_evidence,
                    contract_selectors,
                    control_id="missing-selected-body",
                    arguments=omitted,
                    expected_missing="Body",
                    expected_contract_id=declaration["preset_contract"],
                ),
                _run_selector_binding_control(
                    case,
                    signature_evidence,
                    contract_selectors,
                    control_id="body-bound-positionally",
                    arguments=[
                        *[argument for argument in case["arguments"] if argument is not body],
                        {"kind": "positional", "value": body["value"]},
                    ],
                    expected_missing="Body",
                    expected_contract_id=declaration["preset_contract"],
                ),
            ]
        results.append(result)
    return results


def _package_unsupported_cases(case_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate explicit unsupported package symbols without synthesizing runtime authority."""
    if not isinstance(case_data["unsupported_cases"], list):
        raise MatrixEvidenceError("unsupported package analyzer cases must be a list")
    packages = {(row["distribution"], row["version"]): row for row in load_manifest()["packages"]}
    results: list[dict[str, Any]] = []
    case_ids: set[str] = set()
    for case in case_data["unsupported_cases"]:
        if not isinstance(case, dict) or set(case) != {
            "case_id",
            "distribution",
            "version",
            "symbol",
            "reason_code",
        }:
            raise MatrixEvidenceError("unsupported package case has invalid fields")
        if (
            not all(isinstance(case[key], str) and case[key] for key in case)
            or case["case_id"] in case_ids
            or case["reason_code"]
            not in {"descriptor_signature_unavailable", "no_exact_preset_contract"}
        ):
            raise MatrixEvidenceError("unsupported package case identity is invalid")
        expected_case = {
            "motor-async-descriptor-not-evaluated": (
                "motor",
                "3.6.0",
                "motor.core.AgnosticCollection.insert_one",
                "descriptor_signature_unavailable",
            ),
            "sqs-send-message-no-exact-contract": (
                "mypy-boto3-sqs",
                "1.35.91",
                "mypy_boto3_sqs.client.SQSClient.send_message",
                "no_exact_preset_contract",
            ),
        }.get(case["case_id"])
        observed_case = (
            case["distribution"],
            case["version"],
            case["symbol"],
            case["reason_code"],
        )
        if expected_case != observed_case:
            raise MatrixEvidenceError("unsupported package case does not match a bounded known gap")
        case_ids.add(case["case_id"])
        package = packages.get((case["distribution"], case["version"]))
        declaration = (
            next(
                (row for row in package["declared_symbols"] if row["symbol"] == case["symbol"]),
                None,
            )
            if package
            else None
        )
        if package is None or declaration is None or declaration["preset_contract"] is not None:
            raise MatrixEvidenceError(
                "unsupported package case is not backed by a no-contract symbol"
            )
        if case["reason_code"] == "descriptor_signature_unavailable" and not declaration[
            "source_signature"
        ].startswith("descriptor = Async"):
            raise MatrixEvidenceError("descriptor limitation is not backed by inspected source")
        results.append(
            {
                **case,
                "artifact_sha256": f"sha256:{package['artifact_sha256']}",
                "source_signature": declaration["source_signature"],
                "status": "not_evaluated",
            }
        )
    if case_ids != {
        "motor-async-descriptor-not-evaluated",
        "sqs-send-message-no-exact-contract",
    }:
        raise MatrixEvidenceError("unsupported package case inventory is incomplete")
    return results


def load_package_analyzer_results(
    path: Path = PACKAGE_CASE_RESULTS_PATH,
) -> dict[str, Any]:
    """Verify raw package-symbol controls by replaying each synthetic analyzer case."""
    try:
        value = _strict_json(path.read_bytes(), "package analyzer results")
    except OSError as exc:
        raise MatrixEvidenceError("cannot read package analyzer results") from exc
    fields = {
        "schema_version",
        "result_id",
        "status",
        "scope",
        "manifest_sha256",
        "case_fixture_sha256",
        "analyzer_snapshot_sha256",
        "python_version",
        "resolver_version",
        "source_execution",
        "upstream_package_code_imported_or_executed",
        "cases",
        "unsupported_cases",
        "observed",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise MatrixEvidenceError("package analyzer result has invalid fields")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 4
        or value["result_id"] != "gh97-package-selector-binding-results-v4"
        or value["status"] != "completed"
        or value["scope"]
        != (
            "source-derived signature surfaces, contract-selected argument binding, and "
            "same-name negatives; installed package compatibility not evaluated"
        )
        or value["source_execution"] is not False
        or value["upstream_package_code_imported_or_executed"] is not False
    ):
        raise MatrixEvidenceError("package analyzer result identity or scope is invalid")
    _, snapshot_sha = _load_analyzer_source_snapshots()
    python_version, mypy_version, _ = _replay_environment()
    if value["python_version"] != python_version or value["resolver_version"] != mypy_version:
        raise MatrixEvidenceError("package analyzer result exact environment is invalid")
    expected_manifest_sha = f"sha256:{_sha256(MANIFEST_PATH.read_bytes())}"
    expected_fixture_sha = f"sha256:{_sha256(PACKAGE_CASES_PATH.read_bytes())}"
    if (
        value["manifest_sha256"] != expected_manifest_sha
        or value["case_fixture_sha256"] != expected_fixture_sha
        or value["analyzer_snapshot_sha256"] != snapshot_sha
    ):
        raise MatrixEvidenceError("package analyzer result provenance does not match snapshots")
    replayed = replay_package_analyzer_cases()
    if value["cases"] != replayed:
        raise MatrixEvidenceError("package analyzer observations differ from static replay")
    case_data = _strict_json(PACKAGE_CASES_PATH.read_bytes(), "package analyzer cases")
    unsupported = _package_unsupported_cases(case_data)
    if value["unsupported_cases"] != unsupported:
        raise MatrixEvidenceError("unsupported package cases differ from exact source evidence")
    rows = [row for case in replayed for row in case["observations"]]
    expected_observed = {
        "physical_calls": len(rows),
        "matched_calls": sum(row["audit_status"] == "matched" for row in rows),
        "unmatched_calls": sum(row["audit_status"] == "unmatched" for row in rows),
        "ambiguous_calls": sum(row["audit_status"] == "ambiguous" for row in rows),
        "unresolved_calls": sum(row["audit_status"] == "unresolved" for row in rows),
        "unrelated_same_name_negative_calls": sum(
            row["control_class"] == "unrelated_same_name_negative" for row in rows
        ),
        "selector_binding_negative_controls": sum(
            len(case["binding_controls"]) for case in replayed
        ),
        "matched_exact_symbols": sorted(
            {row["canonical_symbol"] for row in rows if row["audit_status"] == "matched"}
        ),
    }
    if value["observed"] != expected_observed:
        raise MatrixEvidenceError("package analyzer aggregate does not match raw observations")
    return value


def _derive_observed(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {
        state: sum(row["audit_status"] == state for row in rows) for state in _OBSERVATION_STATES
    }
    matched_symbols = sorted(
        {row["canonical_symbol"] for row in rows if row["audit_status"] == "matched"}
    )
    same_name = [row for row in rows if row["control_class"] == "unrelated_same_name_negative"]
    open_calls = [row for row in rows if row["control_class"] == "unmatched_open_constructor"]
    if any(row["audit_status"] != "unmatched" for row in (*same_name, *open_calls)):
        raise MatrixEvidenceError("controlled negative fixture call unexpectedly matched")

    write = next((row for row in rows if row["source_spelling"] == "path.write_text"), None)
    if write is None:
        raise MatrixEvidenceError("controlled fixture lacks path.write_text observation")
    args = write["arguments"]
    argument_binding = {
        "positional_0": next((arg["status"] for arg in args if arg["positional_index"] == 0), None),
        "keyword_encoding": next(
            (arg["status"] for arg in args if arg["keyword"] == "encoding"), None
        ),
    }
    if argument_binding["positional_0"] != "exact" or argument_binding["keyword_encoding"] not in {
        "exact",
        "finite",
        "unavailable",
    }:
        raise MatrixEvidenceError("controlled argument binding observation is incomplete")

    origins: dict[str, str] = {}
    for row in rows:
        if row["source_spelling"] in {"handle.read", "opened.read"}:
            key = (
                "builtins.open.read"
                if row["source_spelling"] == "handle.read"
                else "pathlib.Path.open.read"
            )
            origin = row["receiver_origin"]
            if origin is None:
                origins[key] = "missing"
            elif origin["status"] == "unavailable":
                origins[key] = f"unavailable:{origin['reason_code']}"
            else:
                origins[key] = origin["status"]
    if set(origins) != {"builtins.open.read", "pathlib.Path.open.read"}:
        raise MatrixEvidenceError("controlled fixture lacks both open-handle origin observations")
    return {
        "physical_calls": len(rows),
        "matched_calls": counts["matched"],
        "unmatched_calls": counts["unmatched"],
        "ambiguous_calls": counts["ambiguous"],
        "unresolved_calls": counts["unresolved"],
        "matched_exact_symbols": matched_symbols,
        "unrelated_same_name_negative_calls": len(same_name),
        "unmatched_open_calls": len(open_calls),
        "write_text_argument_binding": argument_binding,
        "receiver_origin": origins,
    }


def _validate_observations(value: Any) -> list[dict[str, Any]]:  # noqa: PLR0912
    if not isinstance(value, list) or not value:
        raise MatrixEvidenceError("controlled results require raw analyzer observations")
    fields = {
        "id",
        "file_path",
        "line",
        "column",
        "end_line",
        "end_column",
        "source_spelling",
        "resolver_status",
        "audit_status",
        "canonical_symbol",
        "invocation",
        "resolver",
        "resolver_version",
        "receiver_candidates",
        "reason_code",
        "receiver_origin",
        "resource_identity",
        "contract_id",
        "contract_hash",
        "arguments",
        "control_class",
    }
    ids: set[str] = set()
    for row in value:
        if not isinstance(row, dict) or set(row) != fields:
            raise MatrixEvidenceError("raw analyzer observation has invalid fields")
        if (
            not isinstance(row["id"], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", row["id"]) is None
            or row["id"] in ids
            or row["file_path"] != "main.py"
            or type(row["line"]) is not int
            or type(row["column"]) is not int
            or not isinstance(row["source_spelling"], str)
            or not row["source_spelling"]
            or (row["end_line"] is not None and type(row["end_line"]) is not int)
            or (row["end_column"] is not None and type(row["end_column"]) is not int)
            or (
                row["canonical_symbol"] is not None and not isinstance(row["canonical_symbol"], str)
            )
            or (row["invocation"] is not None and not isinstance(row["invocation"], str))
            or (row["reason_code"] is not None and not isinstance(row["reason_code"], str))
            or not isinstance(row["resolver_status"], str)
            or row["resolver_status"] not in {"exact", "ambiguous", "unresolved"}
            or not isinstance(row["audit_status"], str)
            or row["audit_status"] not in _OBSERVATION_STATES
            or not isinstance(row["resolver"], str)
            or not isinstance(row["resolver_version"], str)
            or not isinstance(row["receiver_candidates"], list)
            or any(not isinstance(item, str) for item in row["receiver_candidates"])
            or not isinstance(row["arguments"], list)
            or row["control_class"] != _control_class(row["source_spelling"])
        ):
            raise MatrixEvidenceError("raw analyzer observation has invalid identity or status")
        ids.add(row["id"])
        for identity_field in ("receiver_origin", "resource_identity"):
            identity = row[identity_field]
            if identity is not None and (
                not isinstance(identity, dict)
                or set(identity) != {"schema_version", "status", "value_hashes", "reason_code"}
                or type(identity["schema_version"]) is not int
                or identity["schema_version"] != 1
                or not isinstance(identity["status"], str)
                or identity["status"] not in {"exact", "finite", "unavailable"}
                or not isinstance(identity["value_hashes"], list)
                or any(
                    not isinstance(item, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
                    for item in identity["value_hashes"]
                )
                or (
                    identity["reason_code"] is not None
                    and not isinstance(identity["reason_code"], str)
                )
            ):
                raise MatrixEvidenceError("raw resource-origin evidence has invalid fields")
        if row["audit_status"] == "matched":
            if not isinstance(row["contract_id"], str) or not isinstance(row["contract_hash"], str):
                raise MatrixEvidenceError("matched raw observation lacks contract identity")
        elif row["contract_id"] is not None or row["contract_hash"] is not None:
            raise MatrixEvidenceError("unmatched raw observation carries a contract identity")
        for arg in row["arguments"]:
            if not isinstance(arg, dict) or set(arg) != {
                "source_index",
                "positional_index",
                "keyword",
                "status",
                "value_hashes",
                "reason_code",
            }:
                raise MatrixEvidenceError("raw argument binding has invalid fields")
            if (
                type(arg["source_index"]) is not int
                or arg["source_index"] < 0
                or (
                    arg["positional_index"] is not None and type(arg["positional_index"]) is not int
                )
                or (arg["keyword"] is not None and not isinstance(arg["keyword"], str))
                or (arg["reason_code"] is not None and not isinstance(arg["reason_code"], str))
                or (arg["positional_index"] is not None and arg["positional_index"] < 0)
                or (arg["keyword"] is not None and not arg["keyword"])
                or (arg["positional_index"] is None) == (arg["keyword"] is None)
                or not isinstance(arg["status"], str)
                or arg["status"] not in {"exact", "finite", "unavailable"}
                or not isinstance(arg["value_hashes"], list)
                or any(
                    not isinstance(item, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
                    for item in arg["value_hashes"]
                )
            ):
                raise MatrixEvidenceError("raw argument binding has invalid values")
    if value != sorted(value, key=lambda row: (row["file_path"], row["line"], row["column"])):
        raise MatrixEvidenceError("raw analyzer observations must be source ordered")
    return value


def load_controlled_results(path: Path = RESULTS_PATH) -> dict[str, Any]:  # noqa: PLR0912, PLR0915
    """Validate result schemas, derive metrics, and replay only the frozen static fixture."""
    try:
        value = _strict_json(path.read_bytes(), "controlled result")
    except OSError as exc:
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
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 2
        or value["result_id"] != "effect-preset-controlled-results-v2"
        or value["status"] != "completed"
    ):
        raise MatrixEvidenceError("unsupported controlled result identity or status")

    manifest = load_manifest()
    verify_preset_contracts(manifest)
    audit = value["package_source_audit"]
    audit_fields = {
        "manifest_path",
        "manifest_sha256",
        "release_artifacts",
        "versioned_contract_sets",
        "artifact_directory_verified",
        "artifact_directory_note",
    }
    manifest_hash = f"sha256:{_sha256(MANIFEST_PATH.read_bytes())}"
    if not isinstance(audit, dict) or set(audit) != audit_fields:
        raise MatrixEvidenceError("controlled package source audit has invalid fields")
    if (
        audit["manifest_path"] != MANIFEST_PATH.relative_to(PROJECT_ROOT).as_posix()
        or audit["manifest_sha256"] != manifest_hash
    ):
        raise MatrixEvidenceError("controlled results do not match the frozen package manifest")
    artifacts = [
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
    contract_sets = [
        {
            "preset_id": row["preset_id"],
            "version": row["version"],
            "revision": row["revision"],
            "preset_sha256": f"sha256:{row['preset_sha256']}",
            "preset_semantic_sha256": f"sha256:{row['preset_semantic_sha256']}",
            "config_sha256": f"sha256:{row['config_sha256']}",
        }
        for row in manifest["versioned_contract_sets"]
    ]
    if audit["release_artifacts"] != artifacts or audit["versioned_contract_sets"] != contract_sets:
        raise MatrixEvidenceError("controlled result source inventory does not match matrix")
    if audit["artifact_directory_verified"] is not True or not isinstance(
        audit["artifact_directory_note"], str
    ):
        raise MatrixEvidenceError("controlled result artifact verification receipt is invalid")

    evaluation = value["controlled_evaluation"]
    eval_fields = {
        "case_id",
        "test_path",
        "test_file_sha256",
        "fixture_path",
        "fixture_sha256",
        "analyzer",
        "analyzer_snapshot_sha256",
        "analyzer_source_hashes",
        "resolver_version",
        "python_version",
        "package_runtime",
        "source_tree_executed",
        "external_client_imported_or_executed",
        "fixture_contract_set",
        "observations",
        "observed",
        "analysis_policy",
    }
    if not isinstance(evaluation, dict) or set(evaluation) != eval_fields:
        raise MatrixEvidenceError("controlled evaluation has invalid fields")
    for field, sha_key in (
        (evaluation["test_path"], "test_file_sha256"),
        (evaluation["fixture_path"], "fixture_sha256"),
    ):
        if not _safe_relative(field):
            raise MatrixEvidenceError(
                "controlled input path is not a safe repository-relative path"
            )
        source_path = PROJECT_ROOT / field
        try:
            source_hash = f"sha256:{_sha256(source_path.read_bytes())}"
        except OSError as exc:
            raise MatrixEvidenceError(f"missing controlled input source: {field}") from exc
        if source_hash != evaluation[sha_key]:
            raise MatrixEvidenceError(f"controlled input hash mismatch: {field}")
    hashes, snapshot_hash = _load_analyzer_source_snapshots()
    if evaluation["analyzer_snapshot_sha256"] != snapshot_hash:
        raise MatrixEvidenceError("controlled results do not bind the committed analyzer snapshot")
    recorded_hashes = evaluation["analyzer_source_hashes"]
    if not isinstance(recorded_hashes, dict) or set(recorded_hashes) != set(ANALYZER_SOURCE_PATHS):
        raise MatrixEvidenceError(
            "controlled analyzer source hash path set is incomplete or excessive"
        )
    if recorded_hashes != hashes:
        raise MatrixEvidenceError(
            "controlled analyzer source hashes differ from committed snapshots"
        )
    if (
        evaluation["analyzer"] != "MypyAnalyzer plus audit_effect_contracts"
        or not isinstance(evaluation["resolver_version"], str)
        or not evaluation["resolver_version"]
        or evaluation["python_version"] != _PYTHON_VERSION
        or evaluation["package_runtime"]
        != {
            "distribution": "python-stdlib",
            "version": "3.11.16",
            "artifact_sha256": next(
                f"sha256:{row['artifact_sha256']}"
                for row in manifest["packages"]
                if row["distribution"] == "python-stdlib"
            ),
        }
        or evaluation["source_tree_executed"] is not False
        or evaluation["external_client_imported_or_executed"] is not False
        or evaluation["analysis_policy"]
        != "static analyzer replay only; fixture source never executed"
    ):
        raise MatrixEvidenceError("controlled evaluation provenance/policy is invalid")
    fs_preset = next(
        row
        for row in manifest["versioned_contract_sets"]
        if row["preset_id"] == "stdlib-filesystem-effects"
    )
    fixture_contract = evaluation["fixture_contract_set"]
    expected_fixture_contract = {
        "selector": "filesystem-v1",
        "preset_id": fs_preset["preset_id"],
        "version": fs_preset["version"],
        "revision": fs_preset["revision"],
        "preset_sha256": f"sha256:{fs_preset['preset_sha256']}",
        "preset_semantic_sha256": f"sha256:{fs_preset['preset_semantic_sha256']}",
        "config_sha256": f"sha256:{fs_preset['config_sha256']}",
    }
    if fixture_contract != expected_fixture_contract:
        raise MatrixEvidenceError("controlled fixture preset/version binding mismatch")

    rows = _validate_observations(evaluation["observations"])
    observed = _derive_observed(rows)
    matrix_counts = manifest["controlled_evaluation"]
    expected_counts = {
        "positive_matches": observed["matched_calls"],
        "negative_unrelated_same_name_calls": observed["unrelated_same_name_negative_calls"],
        "negative_unmatched_open_constructors": observed["unmatched_open_calls"],
        "unresolved_calls": observed["unresolved_calls"],
        "ambiguous_calls": observed["ambiguous_calls"],
    }
    if (
        any(matrix_counts[key] != count for key, count in expected_counts.items())
        or matrix_counts["receiver_origins"] != observed["receiver_origin"]
    ):
        raise MatrixEvidenceError("package matrix controlled summary disagrees with observations")
    if evaluation["observed"] != observed:
        raise MatrixEvidenceError("controlled aggregate does not match raw call observations")
    replay = _replay_fixture()
    if replay["observations"] != rows:
        raise MatrixEvidenceError("recorded observations differ from analyzer replay")
    if (
        evaluation["resolver_version"] != replay["resolver_version"]
        or evaluation["python_version"] != replay["python_version"]
        or fixture_contract["preset_sha256"] != replay["preset_raw_hash"]
        or fixture_contract["config_sha256"] != replay["preset_config_hash"]
        or fixture_contract["preset_semantic_sha256"] != replay["preset_semantic_hash"]
    ):
        raise MatrixEvidenceError("analyzer replay provenance does not match frozen contract")

    environment = value["environment"]
    if (
        not isinstance(environment, dict)
        or set(environment)
        != {
            "python",
            "platform",
            "mypy",
            "ruff",
            "execution_policy",
        }
        or environment["python"] != evaluation["python_version"]
        or environment["mypy"] != evaluation["resolver_version"].removeprefix("mypy ")
        or not isinstance(environment["platform"], str)
        or not isinstance(environment["ruff"], str)
        or environment["execution_policy"] != evaluation["analysis_policy"]
    ):
        raise MatrixEvidenceError("controlled environment record is invalid")
    real_world = value["real_world_evaluation"]
    if (
        not isinstance(real_world, dict)
        or set(real_world)
        != {
            "status",
            "frozen_source_diffs",
            "canonical_truth_claims",
        }
        or real_world["status"] != "not_evaluated"
        or type(real_world["frozen_source_diffs"]) is not int
        or real_world["frozen_source_diffs"] != 0
        or type(real_world["canonical_truth_claims"]) is not int
        or real_world["canonical_truth_claims"] != 0
    ):
        raise MatrixEvidenceError("real-world evaluation record is invalid")
    return value
