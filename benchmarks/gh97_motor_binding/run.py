#!/usr/bin/env python3
"""Bounded source-only Motor 3.6.0 effect binding probe."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import io
import json
import platform
import subprocess
import tempfile
import textwrap
import zipfile
from pathlib import Path, PurePosixPath

from fastapi_endpoint_detector.analyzer.effect_contract_auditor import audit_effect_contracts
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.effect_contract import load_effect_preset
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointInventory,
    EndpointMethod,
    HandlerInfo,
)

ARTIFACTS = {
    "motor": ("motor-3.6.0-py3-none-any.whl", "motor", "3.6.0"),
    "pymongo": (
        "pymongo-4.10.1-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        "pymongo",
        "4.10.1",
    ),
}
ARTIFACT_SHA256 = {
    "motor": "sha256:9f07ed96f1754963d4386944e1b52d403a5350c687edc60da487d66f98dbf894",
    "pymongo": "sha256:cec237c305fcbeef75c0bcbe9d223d1e22a6e3ba1b53b2f0b79d3d29c742b45b",
}
LIMIT_FILES = 2000
LIMIT_SOURCE_BYTES = 12_000_000
LIMIT_MEMBER_BYTES = 1_000_000


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def bounded_python_sources(wheel: bytes, destination: Path, filename: str) -> dict[str, str]:
    """Extract bounded code, typing markers, and distribution metadata."""
    hashes: dict[str, str] = {}
    total = 0
    with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
        members = [
            m
            for m in archive.infolist()
            if (
                m.filename.endswith((".py", ".pyi"))
                or m.filename.endswith("/py.typed")
                or m.filename.endswith(".dist-info/METADATA")
            )
        ]
        if len(members) > LIMIT_FILES:
            raise ValueError(f"too many Python members in {filename}")
        for member in members:
            relative = PurePosixPath(member.filename)
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or member.file_size > LIMIT_MEMBER_BYTES
            ):
                raise ValueError(f"unsafe or oversized member: {member.filename}")
            if not relative.parts or not (
                relative.parts[0] in {"motor", "pymongo", "bson"}
                or relative.parts[0].endswith(".dist-info")
            ):
                continue
            data = archive.read(member)
            total += len(data)
            if total > LIMIT_SOURCE_BYTES:
                raise ValueError(f"Python source extraction limit exceeded: {filename}")
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            hashes[relative.as_posix()] = sha(data)
    return hashes


def digest_file(path: Path) -> str:
    return sha(path.read_bytes())


def verify_artifact_hash(path: Path, distribution: str) -> str:
    digest = digest_file(path)
    if digest != ARTIFACT_SHA256[distribution]:
        raise ValueError(f"artifact SHA-256 mismatch: {distribution}")
    return digest


def artifact_metadata(
    directory: Path,
) -> tuple[dict[str, dict[str, object]], dict[str, bytes]]:
    result: dict[str, dict[str, object]] = {}
    snapshots: dict[str, bytes] = {}
    for distribution, (filename, package, version) in ARTIFACTS.items():
        path = directory / filename
        artifact = path.read_bytes()
        digest = sha(artifact)
        if digest != ARTIFACT_SHA256[distribution]:
            raise ValueError(f"artifact SHA-256 mismatch: {distribution}")
        snapshots[distribution] = artifact
        with zipfile.ZipFile(io.BytesIO(artifact)) as archive:
            metadata_name = next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
            metadata = archive.read(metadata_name).decode("utf-8", "strict")
            if f"Name: {package}\n" not in metadata or f"Version: {version}\n" not in metadata:
                raise ValueError(f"artifact metadata mismatch: {filename}")
        result[distribution] = {"filename": filename, "sha256": digest}
    return result, snapshots


def verified_product_path(repo: Path, name: str, relative: str) -> Path:
    module = importlib.import_module(name)
    if module.__file__ is None:
        raise ValueError(f"product module lacks source path: {name}")
    actual = Path(module.__file__).resolve()
    expected = (repo / relative).resolve()
    if actual != expected:
        raise ValueError(f"product module escaped candidate checkout: {name}: {actual}")
    return actual


def checkout_revision(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.python_version() != "3.11.16":
        raise SystemExit(f"requires Python 3.11.16, got {platform.python_version()}")
    if importlib.metadata.version("mypy") != "1.19.1":
        raise SystemExit("requires mypy 1.19.1")

    artifact_meta, artifact_snapshots = artifact_metadata(args.artifacts)

    repo = Path(__file__).resolve().parents[2]
    product_path = verified_product_path(
        repo, "fastapi_endpoint_detector", "src/fastapi_endpoint_detector/__init__.py"
    )
    preset_path = repo / "src/fastapi_endpoint_detector/presets/effects_mongodb_v1.yaml"
    analyzer_paths = [
        repo / "src/fastapi_endpoint_detector/analyzer/mypy_analyzer.py",
        repo / "src/fastapi_endpoint_detector/analyzer/effect_contract_auditor.py",
        repo / "src/fastapi_endpoint_detector/models/effect_contract.py",
        repo / "src/fastapi_endpoint_detector/models/endpoint.py",
    ]
    product_paths = {
        ".".join(path.relative_to(repo / "src").with_suffix("").parts): verified_product_path(
            repo,
            ".".join(path.relative_to(repo / "src").with_suffix("").parts),
            path.relative_to(repo).as_posix(),
        )
        .relative_to(repo)
        .as_posix()
        for path in analyzer_paths
    }
    fixture = textwrap.dedent("""
from motor.motor_asyncio import AsyncIOMotorClient as MotorClientAlias
from motor.motor_asyncio import AsyncIOMotorCollection
from typing import Any

client: MotorClientAlias
motor_alias = client
collection: AsyncIOMotorCollection = motor_alias["database"]["collection"]
def unsupported_factory() -> Any: ...
unknown_collection = unsupported_factory()

async def handler() -> None:
    await collection.insert_one({"x": 1})
    await collection.update_one({"x": 1}, {"$set": {"x": 2}})
    await collection.delete_one({"x": 2})
    await collection.insert_one()
    await collection.insert_one(mystery={})
    await unknown_collection.insert_one({"x": 5})
    decoy.insert_one({"x": 3})
    await wrapped.insert_one({"x": 4})

from typing import final

@final
class Decoy:
    def insert_one(self, value: object) -> None: ...

@final
class Wrapper:
    def __init__(self, inner: object) -> None: self.inner = inner
    async def insert_one(self, value: object) -> object:
        return await self.inner.insert_one(value)

decoy: Decoy
wrapped: Wrapper
""")

    with tempfile.TemporaryDirectory(prefix="gh97_motor_source_") as temp:
        root = Path(temp)
        extracted: dict[str, dict[str, str]] = {}
        for distribution, (filename, _package, _version) in ARTIFACTS.items():
            extracted[distribution] = bounded_python_sources(
                artifact_snapshots[distribution], root, filename
            )
        app_root = root / "app"
        app_root.mkdir()
        main_path = app_root / "main.py"
        main_path.write_text(fixture)
        endpoint = Endpoint(
            path="/motor-probe",
            methods=[EndpointMethod.POST],
            handler=HandlerInfo(name="handler", module="main", file_path=main_path, line_number=7),
        )
        analyzer = MypyAnalyzer(app_root, module_root=root, max_depth=1)
        dependencies_by_endpoint = analyzer.analyze_endpoints([endpoint], use_cache=True)
        dependencies = next(iter(dependencies_by_endpoint.values()))
        call_sites = dependencies.get_resolved_call_sites()
        loaded = load_effect_preset("mongodb-v1")
        audit = audit_effect_contracts(
            loaded,
            source_root=root,
            inventory=EndpointInventory(endpoints=[endpoint]),
            endpoint_call_sites=[(endpoint, call_sites)],
            track_transitive=False,
            max_depth=1,
            cache_enabled=True,
            resolver_versions=(f"mypy@{analyzer.resolver_version}",),
            verified_mypy_source_hashes=analyzer.verified_mypy_source_hashes,
            verified_package_source_hashes=analyzer.verified_package_source_hashes,
            verified_package_versions=analyzer.verified_package_versions,
        )
        warm_analyzer = MypyAnalyzer(app_root, module_root=root, max_depth=1)
        warm_dependencies = warm_analyzer.analyze_endpoints([endpoint], use_cache=True)
        warm_call_sites = next(iter(warm_dependencies.values())).get_resolved_call_sites()
        warm_audit = audit_effect_contracts(
            loaded,
            source_root=root,
            inventory=EndpointInventory(endpoints=[endpoint]),
            endpoint_call_sites=[(endpoint, warm_call_sites)],
            track_transitive=False,
            max_depth=1,
            cache_enabled=True,
            resolver_versions=(f"mypy@{warm_analyzer.resolver_version}",),
            verified_mypy_source_hashes=warm_analyzer.verified_mypy_source_hashes,
            verified_package_source_hashes=warm_analyzer.verified_package_source_hashes,
            verified_package_versions=warm_analyzer.verified_package_versions,
        )
        if (
            warm_audit.provenance.package_evidence_hash
            != audit.provenance.package_evidence_hash
            or [row.model_dump(mode="json") for row in warm_audit.occurrences]
            != [row.model_dump(mode="json") for row in audit.occurrences]
        ):
            raise RuntimeError("cold and warm Motor audit evidence differ")
        arguments_by_line = {site.line: site.arguments for site in call_sites}
        occurrences = []
        for row in audit.occurrences:
            prefix = f"{root.name}.main"
            canonical_symbol = row.canonical_symbol
            if canonical_symbol and canonical_symbol.startswith(prefix + "."):
                canonical_symbol = "main" + canonical_symbol[len(prefix) :]
            receiver_candidates = [
                "main" + item[len(prefix) :] if item.startswith(prefix + ".") else item
                for item in row.receiver_candidates
            ]
            occurrences.append(
                {
                    "line": row.line,
                    "source_spelling": row.source_spelling,
                    "resolver_status": row.resolver_status.value,
                    "canonical_symbol": canonical_symbol,
                    "invocation": row.invocation.value if row.invocation else None,
                    "receiver_candidates": receiver_candidates,
                    "reason_code": row.reason_code,
                    "audit_status": row.audit_status.value,
                    "contract_id": row.contract_id,
                    "arguments": [
                        a.model_dump(mode="json") for a in arguments_by_line.get(row.line, ())
                    ],
                }
            )
        output = {
            "schema_version": 1,
            "probe_id": "gh97-motor-typed-binding-v1",
            "scope": (
                "exact artifacts only; static source and analyzer audit; "
                "no upstream import/execution"
            ),
            "python": platform.python_version(),
            "mypy": analyzer.resolver_version,
            "analyzer_revision": checkout_revision(repo),
            "runner_sha256": digest_file(Path(__file__)),
            "analysis_config": {
                "max_depth": 1,
                "track_transitive": False,
                "audit_cache_enabled": True,
                "cold_warm_audit_equal": True,
            },
            "fixture_diagnostics": [
                error.replace(str(main_path), "app/main.py")
                for error in analyzer._build_result.errors
                if str(main_path) in error
            ],
            "product_import": product_path.relative_to(repo).as_posix(),
            "product_module_paths": product_paths,
            "artifact_hashes": artifact_meta,
            "extracted_typed_source_hashes": extracted,
            "verified_target_evidence": {
                "package_versions": analyzer.verified_package_versions,
                "mypy_source_hashes": analyzer.verified_mypy_source_hashes,
                "package_metadata_hashes": analyzer.verified_package_source_hashes,
                "audit_evidence_hash": audit.provenance.package_evidence_hash,
            },
            "fixture_sha256": sha(fixture.encode()),
            "analyzer_source_hashes": {
                str(p.relative_to(repo)): digest_file(p) for p in analyzer_paths
            },
            "preset": {
                "selector": "mongodb-v1",
                "sha256": digest_file(preset_path),
                "contract_ids": [c.id for c in loaded.document.contracts],
                "symbols": [c.symbol for c in loaded.document.contracts],
            },
            "classification": {
                "exact_resolution_and_audit_binding": sum(
                    r["audit_status"] == "matched" for r in occurrences
                ),
                "unsupported_or_ambiguous_resolution": sum(
                    r["resolver_status"] in {"unresolved", "ambiguous"} for r in occurrences
                ),
                "resolved_but_unmatched": sum(
                    r["audit_status"] == "unmatched" for r in occurrences
                ),
                "all_calls": len(occurrences),
            },
            "occurrences": occurrences,
            "limitation": (
                "A match requires canonical exact symbol plus contract audit; "
                "descriptor declarations are not treated as public bindings."
            ),
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps(output["classification"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
