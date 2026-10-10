"""Exact-artifact, execution-free GH97 S3 stub compatibility probe."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, cast

from mypy import build as mypy_build
from mypy.nodes import CallExpr, MemberExpr
from mypy.options import Options
from mypy.types import Instance, get_proper_type
from mypy.version import __version__ as MYPY_VERSION

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "benchmarks/results/effect-preset-matrix-v4/package-symbols.json"
MANIFEST_SHA256 = "f90c11bb5eeb2e5a4d60607438f24d4070be4c84506787e73c1b06903833df1d"
WHEEL_NAME = "mypy_boto3_s3-1.35.92-py3-none-any.whl"
WHEEL_SHA256 = "ce302a635da78e1925d8ff4809184ba55618cd7e3707156bea405cde7fdcf67a"
CANONICAL = "mypy_boto3_s3.client.S3Client.put_object"
MAX_ENTRIES = 10_000
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_WHEEL_BYTES = 16 * 1024 * 1024
EXPECTED_PYTHON_VERSION = "3.11.16"
EXPECTED_MYPY_VERSION = "1.19.1"
FIXTURE_ROOT = Path(__file__).with_name("fixtures")
FIXTURES = (
    "complete",
    "omitted_body",
    "misbound_body",
    "foreign_same_name",
    "bogus_keyword",
    "wrong_type",
)


class ProbeError(ValueError):
    """Invalid artifact, environment, or probe result."""


class _CandidatePackageFinder(importlib.abc.MetaPathFinder):
    """Resolve product modules exclusively from this checkout's src tree."""

    def __init__(self, package_root: Path) -> None:
        self.package_root = package_root

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        if fullname == "fastapi_endpoint_detector":
            return importlib.util.spec_from_file_location(
                fullname,
                self.package_root / "__init__.py",
                submodule_search_locations=[str(self.package_root)],
            )
        if fullname.startswith("fastapi_endpoint_detector."):
            search = list(path) if path else [str(self.package_root)]
            return importlib.machinery.PathFinder.find_spec(fullname, search, target)
        return None


def _load_candidate_product(root: Path) -> dict[str, Any]:
    package_root = (root / "src/fastapi_endpoint_detector").resolve()
    if not (package_root / "__init__.py").is_file():
        raise ProbeError(f"candidate product package is missing: {package_root}")
    for name in tuple(sys.modules):
        if name == "fastapi_endpoint_detector" or name.startswith("fastapi_endpoint_detector."):
            del sys.modules[name]
    finder = _CandidatePackageFinder(package_root)
    sys.meta_path.insert(0, finder)
    try:
        auditor_module = importlib.import_module(
            "fastapi_endpoint_detector.analyzer.effect_contract_auditor"
        )
        analyzer_module = importlib.import_module(
            "fastapi_endpoint_detector.analyzer.mypy_analyzer"
        )
        contract_module = importlib.import_module(
            "fastapi_endpoint_detector.models.effect_contract"
        )
        endpoint_module = importlib.import_module("fastapi_endpoint_detector.models.endpoint")
        names = (
            "fastapi_endpoint_detector.analyzer.mypy_analyzer",
            "fastapi_endpoint_detector.analyzer.effect_contract_auditor",
            "fastapi_endpoint_detector.models.effect_contract",
            "fastapi_endpoint_detector.models.endpoint",
        )
        hashes: dict[str, str] = {}
        for name in names:
            module = sys.modules[name]
            module_path = _verify_candidate_module_path(name, module, package_root)
            hashes[name] = f"sha256:{sha256(module_path.read_bytes())}"
        return {
            "MypyAnalyzer": analyzer_module.MypyAnalyzer,
            "audit_effect_contracts": auditor_module.audit_effect_contracts,
            "Endpoint": endpoint_module.Endpoint,
            "EndpointInventory": endpoint_module.EndpointInventory,
            "EndpointMethod": endpoint_module.EndpointMethod,
            "HandlerInfo": endpoint_module.HandlerInfo,
            "contracts": contract_module,
            "source_hashes": hashes,
            "module_paths": {
                name: str(Path(sys.modules[name].__file__ or "").resolve()) for name in names
            },
        }
    finally:
        sys.meta_path.remove(finder)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _revision(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ProbeError(f"cannot identify candidate product revision: {exc}") from exc
    return result.stdout.strip()


def _verify_candidate_module_path(name: str, module: Any, package_root: Path) -> Path:
    module_path = Path(module.__file__ or "").resolve()
    try:
        module_path.relative_to(package_root)
    except ValueError as exc:
        raise ProbeError(
            f"product module escaped candidate checkout: {name} at {module_path}"
        ) from exc
    return module_path


def _analyzer_hashes() -> dict[str, str]:
    modules = (mypy_build, sys.modules["mypy.nodes"], sys.modules["mypy.types"])
    hashes: dict[str, str] = {}
    for module in modules:
        module_path = module.__file__
        if module_path is None:
            raise ProbeError(f"analyzer module has no source file: {module.__name__}")
        hashes[module.__name__] = f"sha256:{sha256(Path(module_path).read_bytes())}"
    return hashes


def _verified_input_snapshot(
    wheel: Path, manifest: Path
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    manifest_bytes = manifest.read_bytes()
    if sha256(manifest_bytes) != MANIFEST_SHA256:
        raise ProbeError("matrix manifest SHA-256 does not match the pinned manifest")
    matrix = json.loads(manifest_bytes)
    package = next(
        (row for row in matrix["packages"] if row["distribution"] == "mypy-boto3-s3"), None
    )
    if package is None or package["version"] != "1.35.92":
        raise ProbeError("pinned S3 release is absent from the matrix manifest")
    if package["artifact"] != WHEEL_NAME or package["artifact_sha256"] != WHEEL_SHA256:
        raise ProbeError("matrix manifest S3 artifact identity differs from this runner")
    if wheel.name != WHEEL_NAME:
        raise ProbeError(f"wheel filename must be exactly {WHEEL_NAME}")
    if wheel.stat().st_size > MAX_WHEEL_BYTES:
        raise ProbeError("wheel file exceeds size limit")
    with wheel.open("rb") as source:
        wheel_bytes = source.read(MAX_WHEEL_BYTES + 1)
    if len(wheel_bytes) > MAX_WHEEL_BYTES:
        raise ProbeError("wheel file exceeds size limit")
    wheel_hash = sha256(wheel_bytes)
    if wheel_hash != WHEEL_SHA256:
        raise ProbeError("wheel SHA-256 does not match the pinned exact release")
    return (
        {
            "matrix_manifest_sha256": f"sha256:{MANIFEST_SHA256}",
            "wheel_sha256": f"sha256:{wheel_hash}",
        },
        matrix,
        wheel_bytes,
    )


def verify_inputs(wheel: Path, manifest: Path) -> dict[str, Any]:
    artifact, _, _ = _verified_input_snapshot(wheel, manifest)
    return artifact


def extract_wheel(wheel: Path | bytes, destination: Path) -> None:
    total = 0
    snapshot = io.BytesIO(wheel) if isinstance(wheel, bytes) else wheel
    with zipfile.ZipFile(snapshot) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ENTRIES:
            raise ProbeError("wheel has too many ZIP members")
        for info in infos:
            member = PurePosixPath(info.filename)
            mode = info.external_attr >> 16
            if member.is_absolute() or ".." in member.parts or "\\" in info.filename:
                raise ProbeError(f"unsafe ZIP member path: {info.filename!r}")
            if stat.S_ISLNK(mode) or (mode and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
                raise ProbeError(f"non-regular ZIP member: {info.filename!r}")
            if info.file_size > MAX_MEMBER_BYTES:
                raise ProbeError(f"ZIP member exceeds size limit: {info.filename!r}")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise ProbeError("wheel uncompressed size exceeds total limit")
            target = destination.joinpath(*member.parts)
            target.resolve().relative_to(destination.resolve())
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, target.open("xb") as output:
                    payload = source.read(MAX_MEMBER_BYTES + 1)
                    if len(payload) != info.file_size:
                        raise ProbeError(f"ZIP member size mismatch: {info.filename!r}")
                    output.write(payload)
    if not (destination / "mypy_boto3_s3/client.pyi").is_file():
        raise ProbeError("pinned wheel does not contain mypy_boto3_s3/client.pyi")


def _call_rows(tree: Any, fixture_name: str, types: dict[Any, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    function_symbol = tree.names.get("run")
    function_node = getattr(function_symbol, "node", None)
    for function in (function_node,) if function_node is not None else ():
        body = getattr(function, "body", None)
        for statement in getattr(body, "body", ()):
            node = getattr(statement, "expr", None)
            if isinstance(node, CallExpr):
                callee = node.callee
                if not isinstance(callee, MemberExpr) or callee.name != "put_object":
                    continue
                receiver_type = (
                    get_proper_type(types[callee.expr]) if callee.expr in types else None
                )
                receiver_info = receiver_type.type if isinstance(receiver_type, Instance) else None
                member = receiver_info.names.get(callee.name) if receiver_info is not None else None
                canonical = getattr(getattr(member, "node", None), "fullname", None)
                names = list(node.arg_names)
                keywords = [name for name in names if name is not None]
                positions = [index for index, name in enumerate(names) if name is None]
                results.append(
                    {
                        "fixture": fixture_name,
                        "line": node.line,
                        "typed_receiver_symbol": (
                            receiver_info.fullname if receiver_info is not None else None
                        ),
                        "canonical_symbol": canonical,
                        "typed_receiver_type": (
                            str(receiver_type) if receiver_type is not None else None
                        ),
                        "canonical_symbol_status": (
                            "matched" if canonical == CANONICAL else "unmatched"
                        ),
                        "keyword_bindings": keywords,
                        "positional_argument_indexes": positions,
                    }
                )
    return results


def _binding_result(row: dict[str, Any]) -> dict[str, Any]:
    bound = set(row["keyword_bindings"])
    positional = row["positional_argument_indexes"]
    bucket_key = "Bucket" in bound and "Key" in bound
    body_keyword = "Body" in bound
    statuses = {
        "resource": "bound" if bucket_key else "missing_or_misbound",
        "value": "bound" if body_keyword else "missing_or_misbound",
    }
    diagnostics = row.get("fixture_call_diagnostics", [])
    if row.get("canonical_symbol_status") != "matched":
        binding = "unvalidated_unmatched_canonical"
    elif row.get("signature_resolved") is not True:
        binding = "unvalidated_signature_unresolved"
    elif positional:
        statuses["binding_status"] = "misbound_positional_to_keyword_only_parameters"
        binding = statuses["binding_status"]
    elif diagnostics:
        binding = "invalid_call"
    elif bucket_key and body_keyword:
        binding = "complete"
    else:
        binding = "incomplete"
    statuses["binding_status"] = binding
    return statuses


def _normalize_private_paths(value: Any, private_root: Path, cwd: Path) -> Any:
    """Replace only exact known private-root path components in report strings."""
    roots = (str(private_root), str(Path(os.path.relpath(private_root, cwd))))

    def normalize(text: str) -> str:
        result = text
        for root in sorted(set(roots), key=len, reverse=True):
            if root in {".", ""}:
                continue
            pattern = re.escape(root.replace("\\", "/")).replace("/", r"[\\/]")
            result = re.sub(
                r"(?<![A-Za-z0-9_.\\/:-])" + pattern + r"(?=[\\/]|$)",
                "<private-s3-probe>",
                result,
            )
        return result

    if isinstance(value, str):
        return normalize(value)
    if isinstance(value, list):
        return [_normalize_private_paths(item, private_root, cwd) for item in value]
    if isinstance(value, dict):
        return {
            key: _normalize_private_paths(item, private_root, cwd)
            for key, item in value.items()
        }
    return value


def _product_adapter(source: Path) -> dict[str, Any]:
    """Exercise the repository analyzer and contract auditor on the controlled endpoint."""
    product = _load_candidate_product(ROOT)
    endpoint = product["Endpoint"](
        path="/controlled",
        methods=[product["EndpointMethod"].POST],
        handler=product["HandlerInfo"](
            name="run", module=source.stem, file_path=source, line_number=4
        ),
    )
    analyzer: Any = None
    call_rows: list[dict[str, Any]] = []
    loaded: Any = None
    try:
        # The verified artifact is a sibling of the fixture package. Name this
        # private root explicitly; flat-project inference intentionally excludes
        # a checkout parent's arbitrary files and site-package substitutes.
        analyzer = product["MypyAnalyzer"](
            source, module_root=source.parent.parent, no_site_packages=True
        )
        dependencies = analyzer.analyze_endpoint(endpoint)
        sites = dependencies.get_resolved_call_sites(file_path=str(source))
        call_rows = [site.model_dump(mode="json") for site in sites]
        loaded = product["contracts"].load_effect_preset("object-storage-v1")
        inventory = product["EndpointInventory"](endpoints=[endpoint])
        audit = product["audit_effect_contracts"](
            loaded,
            source_root=source.parent,
            inventory=inventory,
            endpoint_call_sites=[(endpoint, sites)],
            track_transitive=True,
            max_depth=10,
            cache_enabled=False,
            resolver_versions=[f"mypy@{analyzer._resolver_version}"],
        )
        status = (
            "completed"
            if len(call_rows) == 1
            and call_rows[0].get("canonical_symbol") == CANONICAL
            and audit.summary.physical_occurrences == 1
            and audit.summary.matched_calls == 1
            else "partially_validated"
        )
        return {
            "status": status,
            "binding_complete": status == "completed",
            "product_root": str((ROOT / "src").resolve()),
            "product_revision": _revision(ROOT),
            "product_source_sha256": product["source_hashes"],
            "product_module_paths": product["module_paths"],
            "preset": {
                "name": "object-storage-v1",
                "lookup_name": "object-storage-v1",
                "source_sha256": f"sha256:{sha256(loaded.source_path.read_bytes())}",
                "raw_hash": loaded.raw_hash,
                "config_hash": loaded.config_hash,
                "preset_hash": loaded.preset_hash,
            },
            "resolver": analyzer._resolver_version,
            "calls": call_rows,
            "audit": audit.model_dump(mode="json"),
        }
    except Exception as exc:
        return {
            "status": "unvalidated",
            "binding_complete": False,
            "reason": f"{type(exc).__name__}: {exc}",
            "product_root": str((ROOT / "src").resolve()),
            "product_revision": _revision(ROOT),
            "product_source_sha256": product["source_hashes"],
            "product_module_paths": product["module_paths"],
            "resolver": getattr(analyzer, "_resolver_version", None),
            "calls": call_rows,
            "preset": {
                "lookup_name": "object-storage-v1",
                "source_sha256": (
                    f"sha256:{sha256(loaded.source_path.read_bytes())}"
                    if loaded is not None
                    else None
                ),
                "raw_hash": loaded.raw_hash if loaded is not None else None,
                "config_hash": loaded.config_hash if loaded is not None else None,
                "preset_hash": loaded.preset_hash if loaded is not None else None,
            },
            "audit": {"status": "unvalidated", "reason": f"{type(exc).__name__}: {exc}"},
        }


def run_probe(wheel: Path, manifest: Path = DEFAULT_MANIFEST) -> dict[str, Any]:  # noqa: PLR0912, PLR0915
    if platform.python_version() != EXPECTED_PYTHON_VERSION:
        raise ProbeError(f"requires Python {EXPECTED_PYTHON_VERSION}")
    if MYPY_VERSION != EXPECTED_MYPY_VERSION:
        raise ProbeError(f"requires mypy {EXPECTED_MYPY_VERSION}")
    artifact, matrix, wheel_bytes = _verified_input_snapshot(wheel, manifest)
    package = next(row for row in matrix["packages"] if row["distribution"] == "mypy-boto3-s3")
    cases: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="gh97-s3-stub-probe-") as temp:
        private = Path(temp)
        stub_root = private / "stubtree"
        stub_root.mkdir()
        extract_wheel(wheel_bytes, stub_root)
        source_hashes: dict[str, str] = {}
        for source_info in package["inspected_sources"]:
            source_path = stub_root / source_info["path"]
            digest = sha256(source_path.read_bytes())
            if digest != source_info["sha256"]:
                raise ProbeError(
                    f"inspected stub source hash differs from manifest: {source_info['path']}"
                )
            source_hashes[source_info["path"]] = f"sha256:{digest}"
        source_root = private / "fixture"
        source_root.mkdir()
        # The product adapter explicitly selects this private artifact root.
        # Expose only the verified stub package; never import it as Python code.
        shutil.copytree(stub_root / "mypy_boto3_s3", private / "mypy_boto3_s3")
        fixture_hashes: dict[str, str] = {}
        for fixture_name in FIXTURES:
            fixture_text = (FIXTURE_ROOT / f"{fixture_name}.py").read_text(encoding="utf-8")
            fixture_hashes[fixture_name] = f"sha256:{sha256(fixture_text.encode())}"
            source = source_root / f"{fixture_name}.py"
            source.write_text(fixture_text, encoding="utf-8")
            options = Options()
            options.incremental = False
            options.follow_imports = "normal"
            options.preserve_asts = True
            options.export_types = True
            options.ignore_missing_imports = False
            options.show_traceback = True
            options.mypy_path = [str(stub_root)]
            result = mypy_build.build(
                sources=[mypy_build.BuildSource(str(source), None, None)], options=options
            )
            state = next(
                (candidate for candidate in result.graph.values() if candidate.path == str(source)),
                None,
            )
            if state is None:
                raise ProbeError(f"mypy graph lacks fixture source {source}")
            tree = state.tree
            if tree is None:
                raise ProbeError(f"mypy did not produce a typed tree for {fixture_name}")
            rows = _call_rows(tree, fixture_name, result.types)
            if len(rows) != 1:
                raise ProbeError(f"expected one put_object call in fixture {fixture_name}")
            row = rows[0]
            call_line = row["line"]
            all_diagnostics = []
            fixture_call_diagnostics = []
            imported_stub_diagnostics = []
            other_diagnostics = []
            for error in result.errors:
                item = {"raw": error}
                all_diagnostics.append(item)
                if error.startswith(f"{source}:") and f":{call_line}:" in error:
                    fixture_call_diagnostics.append(item)
                elif str(stub_root) in error:
                    imported_stub_diagnostics.append(item)
                else:
                    other_diagnostics.append(item)
            row["diagnostics"] = all_diagnostics
            row["diagnostic_classification"] = {
                "total": len(all_diagnostics),
                "fixture_call_errors": fixture_call_diagnostics,
                "imported_stub_diagnostics": imported_stub_diagnostics,
                "other_diagnostics": other_diagnostics,
            }
            row["fixture_call_diagnostics"] = fixture_call_diagnostics
            receiver_type = row["typed_receiver_type"] or ""
            row["signature_resolved"] = (
                row["canonical_symbol_status"] == "matched"
                and row["canonical_symbol"] == CANONICAL
                and "S3Client" in receiver_type
            )
            row["fixture_sha256"] = fixture_hashes[fixture_name]
            row["selector_binding_results"] = _binding_result(row)
            row["mypy_errors"] = len(result.errors)
            cases.append(row)
        product_adapter = _product_adapter(source_root / "complete.py")
    expected_resolution = {
        "complete": "matched",
        "omitted_body": "matched",
        "misbound_body": "matched",
        "foreign_same_name": "unmatched",
        "bogus_keyword": "matched",
        "wrong_type": "matched",
    }
    for row in cases:
        if row["canonical_symbol_status"] != expected_resolution[row["fixture"]]:
            raise ProbeError(f"canonical symbol control failed: {row['fixture']}")
    bindings = {row["fixture"]: row["selector_binding_results"] for row in cases}
    if bindings["complete"]["binding_status"] != "complete":
        raise ProbeError("complete selector binding control failed")
    if bindings["omitted_body"]["value"] != "missing_or_misbound":
        raise ProbeError("omitted Body selector control failed")
    if (
        bindings["misbound_body"]["binding_status"]
        != "misbound_positional_to_keyword_only_parameters"
    ):
        raise ProbeError("misbound Body selector control failed")
    report = {
        "schema_version": 1,
        "benchmark_id": "gh97-exact-release-installed-s3-stub-v1",
        "status": "completed",
        "scope": (
            "one exact S3 stub wheel and pinned analyzer environment; no compatibility range "
            "or production claims"
        ),
        "artifact": {
            "distribution": "mypy-boto3-s3",
            "version": "1.35.92",
            "filename": WHEEL_NAME,
            "source": str(wheel.resolve()),
            **artifact,
            "inspected_source_sha256": source_hashes,
        },
        "environment": {
            "python_version": platform.python_version(),
            "analyzer": "mypy",
            "analyzer_version": MYPY_VERSION,
            "analyzer_sha256": _analyzer_hashes(),
            "platform": sys.platform,
            "settings": {
                "incremental": False,
                "export_types": True,
                "preserve_asts": True,
                "follow_imports": "normal",
                "mypy_path": "private extracted wheel",
                "allow_external_dynamic_commands": False,
            },
        },
        "source_execution": False,
        "upstream_package_code_imported_or_executed": False,
        "canonical_symbol_resolution": {"expected": CANONICAL, "cases": cases},
        "selector_binding_results": [
            {"fixture": row["fixture"], **row["selector_binding_results"]} for row in cases
        ],
        "product_adapter": product_adapter,
    }
    return cast("dict[str, Any]", _normalize_private_paths(report, private, Path.cwd()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True, type=Path, help="exact pinned wheel path")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, help="write JSON here instead of stdout")
    args = parser.parse_args(argv)
    try:
        report = run_probe(args.wheel, args.manifest)
    except (OSError, ValueError, zipfile.BadZipFile, KeyError) as exc:
        parser.error(str(exc))
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
