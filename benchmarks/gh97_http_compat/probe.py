"""Probe actual wheel Python sources without importing or executing those packages."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
import tempfile
import zipfile
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import Any

import mypy.version

from fastapi_endpoint_detector.analyzer.effect_contract_auditor import audit_effect_contracts
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.effect_contract import load_effect_preset
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointInventory,
    EndpointMethod,
    HandlerInfo,
)

PRESET = "http-clients-v1"
WHEELS = {
    "requests": Path("/tmp/gh97-wheel-audit/requests-2.32.3-py3-none-any.whl"),
    "httpx": Path("/tmp/gh97-wheel-audit/httpx-0.28.1-py3-none-any.whl"),
    "aiohttp": Path(
        "/tmp/gh97-wheel-audit/aiohttp-3.11.11-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
    ),
}
MAX_WHEEL_BYTES = 40_000_000
MAX_SOURCE_BYTES = 80_000_000
EXPECTED_DISTRIBUTIONS = {
    "requests": ("requests", "2.32.3"),
    "httpx": ("httpx", "0.28.1"),
    "aiohttp": ("aiohttp", "3.11.11"),
}
EXPECTED_WHEEL_SHA256 = {
    "requests": "70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6",
    "httpx": "d909fcccc110f8c7faf814ca82a9a4d816bc5a6dbfea25d6591d6985b8ba59ad",
    "aiohttp": "249cc6912405917344192b9f9ea5cd5b139d49e0d2f5c7f70bdfaf6b4dbf3a2e",
}
EXPECTED_MYPY = "1.19.1"
MAX_MEMBERS = 20_000
METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
CLASSES = {
    "requests": ("requests.sessions", "Session", "requests"),
    "httpx.Client": ("httpx._client", "Client", "httpx"),
    "httpx.AsyncClient": ("httpx._client", "AsyncClient", "httpx"),
    "aiohttp": ("aiohttp.client", "ClientSession", "aiohttp"),
}


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _module_source(module: str) -> Path:
    loaded = sys.modules.get(module)
    filename = getattr(loaded, "__file__", None)
    if filename is None:
        raise RuntimeError(f"cannot identify imported product module: {module}")
    return Path(filename).resolve()


def _diagnostic_line(item: str) -> int | None:
    match = re.search(r"/fixture\.py:(\d+):", item)
    return int(match.group(1)) if match else None


def _normalize_diagnostic(item: str, checkout: Path, environment: Path) -> str:
    normalized = re.sub(r"/tmp/gh97_http_wheels_[^/]+", "/tmp/<private-probe>", item)
    normalized = re.sub(r"/[^\s\"']*/mypy/typeshed/", "<typeshed>/", normalized)
    for path, label in sorted(
        ((checkout, "<analyzer-project>"), (environment, "<python-environment>")),
        key=lambda pair: len(str(pair[0])),
        reverse=True,
    ):
        normalized = normalized.replace(str(path) + "/", label + "/")
    return normalized


def _source_provenance(checkout: Path, runner: Path) -> dict[str, str]:
    """Bind the complete analyzer tree and runner to stable committed sources."""

    def git_text(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=checkout, check=True, capture_output=True, text=True
        ).stdout.strip()

    if git_text("status", "--porcelain", "--untracked-files=all", "--", "src"):
        raise RuntimeError("analyzer source tree must match committed source bytes")
    revision = git_text("log", "-1", "--format=%H", "--", "src")
    tree = git_text("rev-parse", "HEAD:src")
    if git_text("rev-parse", f"{revision}:src") != tree:
        raise RuntimeError("analyzer source revision does not contain the current source tree")
    runner_path = runner.relative_to(checkout).as_posix()
    runner_revision = git_text("log", "-1", "--format=%H", "--", runner_path)
    if not runner_revision:
        raise RuntimeError("probe runner must be committed before generating evidence")
    committed_runner = subprocess.run(
        ["git", "show", f"{runner_revision}:{runner_path}"],
        cwd=checkout,
        check=True,
        capture_output=True,
    ).stdout
    if committed_runner != runner.read_bytes():
        raise RuntimeError("probe runner must match its committed revision")
    return {
        "git_revision": revision,
        "analyzer_source_tree_sha": tree,
        "runner_revision": runner_revision,
    }


def extract_python_sources(
    wheel: Path, destination: Path, expected_distribution: str
) -> dict[str, Any]:
    if wheel.stat().st_size > MAX_WHEEL_BYTES:
        raise ValueError(f"wheel exceeds archive size limit: {wheel.name}")
    raw_hash = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if raw_hash != EXPECTED_WHEEL_SHA256[expected_distribution]:
        raise ValueError(f"wheel hash does not match pinned artifact: {wheel.name}")
    files: list[dict[str, str]] = []
    total = 0
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) > MAX_MEMBERS or len(names) != len(set(names)):
            raise ValueError(f"invalid or excessive wheel members: {wheel.name}")
        if any("\\" in name for name in names):
            raise ValueError(f"backslash in wheel member: {wheel.name}")
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise ValueError(f"wheel metadata is not unique: {wheel.name}")
        metadata = Parser().parsestr(archive.read(metadata_names[0]).decode("utf-8"))
        expected_name, expected_version = EXPECTED_DISTRIBUTIONS[expected_distribution]
        if (metadata.get("Name") or "").lower() != expected_name or metadata.get(
            "Version"
        ) != expected_version:
            raise ValueError(f"wheel identity does not match pinned artifact: {wheel.name}")
        for info in archive.infolist():
            path = PurePosixPath(info.filename)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"unsafe wheel member: {info.filename}")
            if not info.filename.endswith(".py"):
                continue
            if not info.is_dir() and info.external_attr >> 16 & 0o170000 not in {0, 0o100000}:
                raise ValueError(f"non-regular Python source member: {info.filename}")
            if info.file_size > MAX_WHEEL_BYTES:
                raise ValueError(f"oversized Python source member: {info.filename}")
            total += info.file_size
            if total > MAX_SOURCE_BYTES:
                raise ValueError(f"Python sources exceed extraction limit: {wheel.name}")
            target = destination.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            content = archive.read(info)
            target.write_bytes(content)
            files.append({"path": info.filename, "sha256": sha256(content)})
    return {
        "distribution": metadata.get("Name"),
        "version": metadata.get("Version"),
        "wheel": wheel.name,
        "wheel_sha256": "sha256:" + raw_hash,
        "python_source_files": len(files),
        "python_source_bytes": total,
        "source_manifest_sha256": sha256(
            json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
        ),
        "files": files,
    }


def fixture_source() -> str:
    imports = "\n".join(
        f"from {module} import {cls} as C{i}" for i, (module, cls, _) in enumerate(CLASSES.values())
    )
    params: list[str] = []
    calls: list[str] = []
    for i, (_, _, prefix) in enumerate(CLASSES.values()):
        arg = f"client{i}"
        params.append(f"{arg}: C{i}")
        for method in METHODS:
            control = (
                ", params={'page': 1}"
                if method == "get"
                else (", json={'ok': True}" if method in {"post", "put", "patch"} else "")
            )
            call = f"    {arg}.{method}('https://example.invalid/items'{control})  # {prefix}"
            calls.append(f"    await {call}" if i in {2, 3} else call)
    params.extend(("foreign: Foreign", "url: str"))
    calls.extend(
        (
            "    foreign.get('https://example.invalid/foreign')",
            "    client0.get(url)",
        )
    )
    return (
        f"{imports}\n\n"
        "class Foreign:\n"
        "    def get(self, url: str) -> object: ...\n\n"
        "def forwarded(client: C0, url: str) -> object:\n"
        "    return client.get(url)\n\n"
        "def unused(client: C0) -> object:\n"
        "    return client.post('https://example.invalid/unused')\n\n"
        "async def deferred(client: C0, url: str) -> None:\n"
        "    await client.get(url)\n\n"
        f"async def handler({', '.join(params)}) -> None:\n"
        + "\n".join(calls)
        + "\n    forwarded(client0, 'https://example.invalid/forwarded')"
        + "\n"
    )


def _endpoint(path: Path, line: int) -> Endpoint:
    return Endpoint(
        path="/http-compat",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="handler", module="fixture", file_path=path, line_number=line),
    )


def run(wheels: dict[str, Path] = WHEELS) -> dict[str, Any]:
    if platform.python_version() != "3.11.16":
        raise RuntimeError(f"expected pinned Python 3.11.16, found {platform.python_version()}")
    if len(wheels) != len(EXPECTED_WHEEL_SHA256) or set(wheels) != set(EXPECTED_WHEEL_SHA256):
        raise RuntimeError("wheel set does not match the three pinned distributions")
    preset = load_effect_preset(PRESET)
    product_modules = (MypyAnalyzer, audit_effect_contracts, load_effect_preset, Endpoint)
    product_paths = {obj.__module__: _module_source(obj.__module__) for obj in product_modules}
    source_root = Path(__file__).resolve().parents[2]
    for module_path in product_paths.values():
        if not module_path.is_relative_to(source_root / "src"):
            raise RuntimeError(
                f"product module did not load from candidate src tree: {module_path}"
            )
    if mypy.version.__version__ != EXPECTED_MYPY:
        raise RuntimeError(f"expected mypy {EXPECTED_MYPY}, found {mypy.version.__version__}")
    provenance = _source_provenance(source_root, Path(__file__).resolve())
    source = fixture_source()
    with tempfile.TemporaryDirectory(prefix="gh97_http_wheels_") as temp:
        root = Path(temp)
        package_root = root / "site"
        manifests = {
            name: extract_python_sources(wheel, package_root, name)
            for name, wheel in wheels.items()
        }
        app = root / "app"
        app.mkdir()
        fixture = app / "fixture.py"
        fixture.write_text(source, encoding="utf-8")
        # MypyAnalyzer prepends source_root.parent to MYPYPATH. Point its standard
        # source-root parent at extracted packages while keeping the app separate.
        # Symlink/copy-free package lookup is provided with a temporary package root.
        analyzer = MypyAnalyzer(app, max_depth=2, no_site_packages=True)
        # Analyzer's supported mypy_path is app.parent; place packages there.
        for child in package_root.iterdir():
            child.rename(root / child.name)
        handler_line = next(
            index
            for index, line in enumerate(source.splitlines(), 1)
            if line.startswith("async def handler(")
        )
        endpoint = _endpoint(fixture, handler_line)
        deps = analyzer.analyze_endpoint(endpoint)
        sites = deps.get_resolved_call_sites()
        forwarded_line = next(
            index
            for index, line in enumerate(source.splitlines(), 1)
            if line.strip() == "return client.get(url)"
        )
        control_lines = {
            name: next(
                index for index, line in enumerate(source.splitlines(), 1) if line.strip() == call
            )
            for name, call in (
                ("unused_wrapper", "return client.post('https://example.invalid/unused')"),
                ("deferred_function", "await client.get(url)"),
            )
        }
        audit = audit_effect_contracts(
            preset,
            source_root=app,
            inventory=EndpointInventory(endpoints=[endpoint]),
            endpoint_call_sites=[(endpoint, sites)],
            track_transitive=True,
            max_depth=2,
            cache_enabled=False,
            resolver_versions=(f"mypy@{analyzer.resolver_version}",),
        )
        rows: list[dict[str, Any]] = []
        sites_by_line = {site.line: site for site in sites}
        for occurrence in audit.occurrences:
            site = sites_by_line.get(occurrence.line)
            rows.append(
                {
                    "line": occurrence.line,
                    "source_spelling": occurrence.source_spelling,
                    "resolver_status": occurrence.resolver_status.value,
                    "audit_status": occurrence.audit_status.value,
                    "canonical_symbol": occurrence.canonical_symbol,
                    "invocation": occurrence.invocation.value if occurrence.invocation else None,
                    "reason_code": occurrence.reason_code,
                    "contract_id": occurrence.contract_id,
                    "resource": (
                        occurrence.resource_identity.model_dump(mode="json")
                        if occurrence.resource_identity
                        else None
                    ),
                    "receiver_candidates": list(occurrence.receiver_candidates),
                    "arguments": [item.model_dump(mode="json") for item in site.arguments]
                    if site
                    else [],
                    "receiver_origin": (
                        site.receiver_origin.model_dump(mode="json")
                        if site and site.receiver_origin
                        else None
                    ),
                }
            )
        matched = [row for row in rows if row["audit_status"] == "matched"]
        selector_supported = [
            row
            for row in matched
            if row["resource"] is not None and row["resource"]["status"] in {"exact", "finite"}
        ]
        raw_diagnostics = (
            [
                _normalize_diagnostic(str(item), source_root, Path(sys.prefix))
                for item in analyzer._build_result.errors
            ]
            if analyzer._build_result
            else []
        )
        fixture_lines = set(range(1, len(source.splitlines()) + 1))
        fixture_diagnostics = [
            item
            for item in raw_diagnostics
            if (line := _diagnostic_line(item)) is not None and line in fixture_lines
        ]
        for row in rows:
            row["call_diagnostics"] = [
                item for item in fixture_diagnostics if _diagnostic_line(item) == row["line"]
            ]
            row["call_validation"] = (
                "diagnostics_present" if row["call_diagnostics"] else "no_call_diagnostics"
            )
        missing_dependency_diagnostics = [
            item
            for item in raw_diagnostics
            if "[import-untyped]" in item or "[import-not-found]" in item
        ]
        other_global_diagnostics = [
            item for item in raw_diagnostics if item not in missing_dependency_diagnostics
        ]
        product_imports = {
            module: {
                "path": path.relative_to(source_root).as_posix(),
                "source_sha256": sha256(path.read_bytes()),
            }
            for module, path in product_paths.items()
        }
        runner_hash = sha256(Path(__file__).read_bytes())
        return {
            "schema_version": 1,
            "probe": "gh97-http-installed-artifact-source-compatibility-v1",
            "python_version": platform.python_version(),
            "mypy_version": analyzer.resolver_version,
            "product_imports": product_imports,
            "runner_sha256": runner_hash,
            **provenance,
            "analysis_config": {
                "preset": PRESET,
                "track_transitive": True,
                "max_depth": 2,
                "no_site_packages": True,
                "ambient_mypypath": "excluded",
            },
            "preset": PRESET,
            "preset_hash": preset.preset_hash,
            "preset_config_hash": preset.config_hash,
            "fixture_sha256": sha256(source.encode()),
            "fixture_controls": {"forwarded_wrapper_line": forwarded_line, **control_lines},
            "packages": manifests,
            "diagnostics": raw_diagnostics,
            "fixture_diagnostics": fixture_diagnostics,
            "global_diagnostic_count": len(raw_diagnostics),
            "other_global_diagnostic_count": len(other_global_diagnostics),
            "missing_dependency_diagnostics": missing_dependency_diagnostics,
            "diagnostic_count": len(raw_diagnostics),
            "compatibility_complete": not raw_diagnostics,
            "environment": {
                "python_version": platform.python_version(),
                "source_execution": False,
                "native_extension_extraction": False,
                "package_imports": False,
            },
            "call_count": len(rows),
            "matched_call_count": len(matched),
            "selector_supported_call_count": len(selector_supported),
            "resolution_counts": {
                status: sum(row["resolver_status"] == status for row in rows)
                for status in ("exact", "ambiguous", "unresolved")
            },
            "audit_counts": {
                status: sum(row["audit_status"] == status for row in rows)
                for status in ("matched", "unmatched", "ambiguous", "unresolved")
            },
            "observations": rows,
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run()
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
