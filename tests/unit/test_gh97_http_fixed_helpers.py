"""Pinned-wheel integration audit for exact module-level HTTP helpers."""

from __future__ import annotations

import hashlib
import io
import os
import stat
import struct
import warnings
import zipfile
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from fastapi_endpoint_detector.analyzer.effect_contract_auditor import audit_effect_contracts
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.effect_contract import load_effect_preset
from fastapi_endpoint_detector.models.effect_contract_audit import AuditCallStatus
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointInventory,
    EndpointMethod,
    HandlerInfo,
)

WHEELS = Path(os.environ.get("GH97_WHEEL_AUDIT_DIR", "/tmp/gh97-wheel-audit"))
WHEELS_REQUIRED = os.environ.get("GH97_WHEEL_AUDIT_REQUIRED") == "1"
PACKAGES = {
    "httpx": {
        "wheel": WHEELS / "httpx-0.28.1-py3-none-any.whl",
        "version": "0.28.1",
        "methods": ("get", "post", "put", "patch", "delete", "head", "options"),
        "imports": (
            "import httpx as client\n"
            "from httpx import post as post_request\n"
            "from httpx._api import put as put_request\n"
            "from httpx import patch as patch_request\n"
            "from httpx._api import delete as delete_request\n"
            "from httpx import head as head_request\n"
            "from httpx._api import options as options_request\n"
        ),
        "calls": (
            "    client.get('https://example.invalid/get')\n"
            "    post_request('https://example.invalid/post')\n"
            "    put_request('https://example.invalid/put')\n"
            "    patch_request('https://example.invalid/patch')\n"
            "    delete_request('https://example.invalid/delete')\n"
            "    head_request('https://example.invalid/head')\n"
            "    options_request('https://example.invalid/options')\n"
            "    httpx_request('GET', 'https://example.invalid/generic')\n"
        ),
        "generic_import": "from httpx import request as httpx_request\n",
        "symbol_prefix": "httpx._api",
    },
    "requests": {
        "wheel": WHEELS / "requests-2.32.3-py3-none-any.whl",
        "version": "2.32.3",
        "methods": ("get", "post", "put", "patch", "delete", "head", "options"),
        "imports": (
            "import requests as client\n"
            "from requests import post as post_request\n"
            "from requests.api import put as put_request\n"
            "from requests import patch as patch_request\n"
            "from requests.api import delete as delete_request\n"
            "from requests import head as head_request\n"
            "from requests.api import options as options_request\n"
        ),
        "calls": (
            "    client.get('https://example.invalid/get')\n"
            "    post_request('https://example.invalid/post')\n"
            "    put_request('https://example.invalid/put')\n"
            "    patch_request('https://example.invalid/patch')\n"
            "    delete_request('https://example.invalid/delete')\n"
            "    head_request('https://example.invalid/head')\n"
            "    options_request('https://example.invalid/options')\n"
            "    requests_request('GET', 'https://example.invalid/generic')\n"
        ),
        "generic_import": "from requests import request as requests_request\n",
        "symbol_prefix": "requests.api",
    },
}


def _require_or_skip_wheel(wheel: Path, package: str) -> None:
    if wheel.is_file():
        return
    message = f"pinned {package} source wheel is unavailable: {wheel}"
    if WHEELS_REQUIRED:
        pytest.fail(f"mandatory {message}")
    pytest.skip(message)


MAX_WHEEL_BYTES = 20 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 32 * 1024 * 1024
EXPECTED_WHEEL_HASHES = {
    "httpx": "d909fcccc110f8c7faf814ca82a9a4d816bc5a6dbfea25d6591d6985b8ba59ad",
    "requests": "70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6",
}


def _verified_wheel_bytes(package: str) -> bytes:
    spec = PACKAGES[package]
    with spec["wheel"].open("rb") as stream:
        content = stream.read(MAX_WHEEL_BYTES + 1)
    if len(content) > MAX_WHEEL_BYTES:
        raise ValueError("source wheel exceeds size limit")
    actual_hash = hashlib.sha256(content).hexdigest()
    if actual_hash != EXPECTED_WHEEL_HASHES[package]:
        raise ValueError(f"source wheel hash mismatch for {package}: {actual_hash}")
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        metadata_path = f"{package}-{spec['version']}.dist-info/METADATA"
        metadata = BytesParser(policy=compat32).parsebytes(archive.read(metadata_path))
    if metadata.get("Name", "").lower() != package or metadata.get("Version") != spec["version"]:
        raise ValueError(f"source wheel metadata mismatch for {package}")
    return content


def _extract_wheel(content: bytes, package: str, target: Path) -> None:
    if target.exists() or target.is_symlink():
        raise ValueError("wheel extraction target must be a fresh directory")
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise ValueError("duplicate wheel member")
        total_size = 0
        for info in infos:
            name = info.filename
            path = PurePosixPath(name)
            mode = info.external_attr >> 16
            if (
                not name
                or name.startswith(("/", "\\"))
                or "\\" in name
                or any(part in ("", ".", "..") for part in name.split("/"))
                or path.is_absolute()
                or (len(name) > 1 and name[1] == ":")
            ):
                raise ValueError(f"unsafe wheel member: {name!r}")
            if stat.S_ISLNK(mode):
                raise ValueError(f"symlink wheel member: {name!r}")
            if info.flag_bits & 0x1:
                raise ValueError(f"encrypted wheel member: {name!r}")
            if info.file_size > MAX_MEMBER_BYTES:
                raise ValueError(f"oversize wheel member: {name!r}")
            total_size += info.file_size
            if total_size > MAX_TOTAL_UNCOMPRESSED:
                raise ValueError("wheel exceeds total uncompressed size limit")
        target.mkdir(parents=True)
        target_resolved = target.resolve(strict=True)
        for info in infos:
            member = info.filename
            if (member.startswith(package + "/") and member.endswith((".py", ".pyi"))) or (
                member.startswith(package + "-")
                and member.endswith((".dist-info/METADATA", ".dist-info/top_level.txt"))
            ):
                output = target.joinpath(*PurePosixPath(member).parts)
                if not output.resolve().is_relative_to(target_resolved):
                    raise ValueError(f"wheel member escapes extraction target: {member!r}")
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(archive.read(info))


def _wheel_evidence(package: str, content: bytes) -> tuple[dict[str, str], dict[str, str]]:
    spec = PACKAGES[package]
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        source_path = f"{package}/_api.py" if package == "httpx" else "requests/api.py"
        package_init = f"{package}/__init__.py"
        metadata_path = f"{package}-{spec['version']}.dist-info/METADATA"
        sources = (source_path, package_init, metadata_path)
        hashes = {
            name: "sha256:" + hashlib.sha256(archive.read(name)).hexdigest() for name in sources
        }
        metadata = BytesParser(policy=compat32).parsebytes(archive.read(metadata_path))
    assert metadata.get("Name", "").lower() == package
    assert metadata.get("Version") == spec["version"]
    return hashes, {package: spec["version"]}


def _analyze(
    package: str, app: Path, source: str
) -> tuple[MypyAnalyzer, Endpoint, list[Any], bytes]:
    package_root = app.parent / "vendor"
    wheel_content = _verified_wheel_bytes(package)
    _extract_wheel(wheel_content, package, package_root)
    fixture = app / "fixture.py"
    fixture.write_text(source, encoding="utf-8")
    handler_line = next(
        number
        for number, line in enumerate(source.splitlines(), 1)
        if line.startswith("def handler")
    )
    endpoint = Endpoint(
        path="/pinned-http-helper",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler", module="fixture", file_path=fixture, line_number=handler_line
        ),
    )
    analyzer = MypyAnalyzer(
        app,
        module_root=package_root,
        max_depth=2,
        no_site_packages=True,
        target_platform="linux",
    )
    dependencies = analyzer.analyze_endpoint(endpoint)
    return analyzer, endpoint, dependencies.get_resolved_call_sites(), wheel_content


def _audit(
    package: str,
    app: Path,
    endpoint: Endpoint,
    sites: list[Any],
    analyzer: MypyAnalyzer,
    wheel_content: bytes,
):
    _wheel_evidence(package, wheel_content)
    return audit_effect_contracts(
        load_effect_preset("http-clients-v1"),
        source_root=app,
        inventory=EndpointInventory(endpoints=[endpoint]),
        endpoint_call_sites=[(endpoint, sites)],
        track_transitive=False,
        max_depth=2,
        cache_enabled=False,
        resolver_versions=(f"mypy@{analyzer.resolver_version}",),
        verified_mypy_source_hashes=analyzer.verified_mypy_source_hashes,
        verified_package_source_hashes=analyzer.verified_package_source_hashes,
        verified_package_versions=analyzer.verified_package_versions,
    )


@pytest.mark.parametrize("package", tuple(PACKAGES))
@pytest.mark.parametrize("url_form", ["positional", "keyword"])
def test_fixed_module_helpers_match_pinned_wheel_audit(
    package: str, url_form: str, tmp_path: Path
) -> None:
    """Seven fixed verbs bind one positional or keyword URL in the pinned release."""
    spec = PACKAGES[package]
    _require_or_skip_wheel(spec["wheel"], package)
    app = tmp_path / "app"
    app.mkdir()
    calls_source = spec["calls"]
    if url_form == "keyword":
        calls_source = calls_source.replace(
            "('https://example.invalid/", "(url='https://example.invalid/"
        )
    source = (
        spec["imports"]
        + spec["generic_import"]
        + "from typing import Any\n"
        + "class Foreign:\n    def get(self, url: str) -> object: ...\n"
        + "def handler(url: str, foreign: Foreign, anything: Any) -> None:\n"
        + calls_source
        + "    foreign.get(url)\n"
        + "    anything.get(url)\n"
    )
    analyzer, endpoint, sites, wheel_content = _analyze(package, app, source)
    wheel_hashes, versions = _wheel_evidence(package, wheel_content)
    assert analyzer.verified_package_versions == versions
    assert analyzer.verified_package_source_hashes == {
        path: digest for path, digest in wheel_hashes.items() if path.endswith("METADATA")
    }
    assert all(
        analyzer.verified_mypy_source_hashes[path] == digest
        for path, digest in wheel_hashes.items()
        if not path.endswith("METADATA")
    )
    report = _audit(package, app, endpoint, sites, analyzer, wheel_content)

    calls = {site.line: site for site in sites}
    occurrences = {item.line: item for item in report.occurrences}
    handler_line = endpoint.handler.line_number
    helper_calls = [
        item
        for item in report.occurrences
        if item.line > handler_line and item.canonical_symbol is not None
    ]
    matched = [item for item in helper_calls if item.audit_status == AuditCallStatus.MATCHED]
    assert len(matched) == 7
    assert {item.contract_id for item in matched} == {
        f"{package}-api-{method}" for method in spec["methods"]
    }
    contracts = {item.id: item for item in load_effect_preset("http-clients-v1").document.contracts}
    for occurrence in matched:
        contract = contracts[occurrence.contract_id]
        method = occurrence.contract_id.removeprefix(f"{package}-api-").upper()
        assert contract.symbol == f"{spec['symbol_prefix']}.{method.lower()}"
        assert contract.invocation.value == "function"
        assert contract.resource.index == 0
        assert contract.http_method == method
        assert contract.package is not None
        assert contract.package.version == f"=={spec['version']}"
        assert occurrence.resource_identity is not None
        assert occurrence.resource_identity.status.value == "exact"
        selected = [
            argument
            for argument in calls[occurrence.line].arguments
            if (
                argument.positional_index == 0
                if url_form == "positional"
                else argument.keyword == "url"
            )
        ]
        assert len(selected) == 1

    generic_name = "requests.api.request" if package == "requests" else "httpx._api.request"
    generic = [site for site in sites if site.canonical_symbol == generic_name]
    assert len(generic) == 1
    generic_occurrence = occurrences[generic[0].line]
    assert generic_occurrence.audit_status == AuditCallStatus.UNMATCHED
    assert generic_occurrence.contract_id is None
    assert not any(contract.symbol == generic_name for contract in contracts.values())
    assert [argument.positional_index for argument in generic[0].arguments] == [0, 1]

    foreign = [item for item in report.occurrences if item.source_spelling == "foreign.get"]
    dynamic = [item for item in report.occurrences if item.source_spelling == "anything.get"]
    assert len(foreign) == len(dynamic) == 1
    assert foreign[0].audit_status == AuditCallStatus.AMBIGUOUS
    assert dynamic[0].audit_status == AuditCallStatus.UNRESOLVED


@pytest.mark.parametrize("package", tuple(PACKAGES))
def test_helper_source_rebinding_abstains_after_guard(package: str, tmp_path: Path) -> None:
    """Direct and dynamic writes in analyzed source cannot match helper rows."""
    spec = PACKAGES[package]
    _require_or_skip_wheel(spec["wheel"], package)
    app = tmp_path / "app"
    app.mkdir()
    root = package
    source = (
        f"import {root} as client\n"
        "from typing import Any\n"
        "def helper(value: object) -> None:\n    value.get = object()\n"
        "def mutate(replacement: Any) -> None:\n"
        "    client.get = replacement\n"
        "    setattr(client, 'post', replacement)\n"
        "    delattr(client, 'put')\n"
        "    helper(client)\n"
        "def handler(url: str, replacement: Any) -> None:\n"
        "    client.get(url)\n"
        "    client.post(url)\n"
        "    client.put(url)\n"
    )
    analyzer, endpoint, sites, wheel_content = _analyze(package, app, source)
    report = _audit(package, app, endpoint, sites, analyzer, wheel_content)
    by_line = {item.line: item for item in report.occurrences}
    handler_calls = [site for site in sites if site.source_spelling.startswith("client.")]
    assert len(handler_calls) == 3
    for site in handler_calls:
        occurrence = by_line[site.line]
        assert occurrence.audit_status == AuditCallStatus.AMBIGUOUS
        assert occurrence.canonical_symbol is None
        assert occurrence.reason_code == "mutated_imported_callable"


def test_function_local_rebinding_does_not_poison_global_helper(tmp_path: Path) -> None:
    """A local imported alias rebound to a value is no longer the module object."""
    package = "requests"
    spec = PACKAGES[package]
    _require_or_skip_wheel(spec["wheel"], package)
    app = tmp_path / "app"
    app.mkdir()
    source = (
        "import requests as client\n"
        "def unrelated(replacement: object) -> None:\n"
        "    import requests as client\n"
        "    client = object()\n"
        "    client.get = replacement\n"
        "def handler(url: str) -> None:\n"
        "    client.get('https://example.invalid/global')\n"
    )
    analyzer, endpoint, sites, wheel_content = _analyze(package, app, source)
    report = _audit(package, app, endpoint, sites, analyzer, wheel_content)
    call = next(item for item in report.occurrences if item.source_spelling == "client.get")
    assert call.audit_status == AuditCallStatus.MATCHED
    assert call.canonical_symbol == "requests.api.get"
    assert call.contract_id == "requests-api-get"


def test_bad_wheel_hash_fails_before_extraction_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = tmp_path / "altered.whl"
    wheel.write_bytes(b"not the pinned wheel")
    monkeypatch.setitem(PACKAGES["requests"], "wheel", wheel)
    app = tmp_path / "app"
    app.mkdir()
    with pytest.raises(ValueError, match="hash mismatch"):
        _analyze("requests", app, "def handler() -> None:\n    pass\n")
    assert not (tmp_path / "vendor").exists()
    assert not (app / "fixture.py").exists()


@pytest.mark.parametrize("member", ["../escape.py", "/absolute.py", r"requests\\escape.py"])
def test_unsafe_wheel_member_is_rejected_before_extraction(tmp_path: Path, member: str) -> None:
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w") as archive:
        archive.writestr(member, "sentinel")
    target = tmp_path / "vendor"
    with pytest.raises(ValueError, match="unsafe wheel member"):
        _extract_wheel(content.getvalue(), "requests", target)
    assert not (tmp_path / "escape.py").exists()
    assert not target.exists()


@pytest.mark.parametrize("kind", ["duplicate", "symlink", "encrypted", "oversize", "bomb"])
def test_malformed_wheel_members_are_rejected_before_extraction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w") as archive:
        if kind == "duplicate":
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr("requests/api.py", "one")
                archive.writestr("requests/api.py", "two")
        elif kind == "symlink":
            link = zipfile.ZipInfo("requests/api.py")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, "../../outside.py")
        elif kind == "encrypted":
            archive.writestr("requests/api.py", "secret")
        elif kind == "oversize":
            archive.writestr("requests/api.py", "12345")
        else:
            archive.writestr("requests/api.py", "12345")
    if kind == "oversize":
        monkeypatch.setitem(globals(), "MAX_MEMBER_BYTES", 4)
    if kind == "bomb":
        monkeypatch.setitem(globals(), "MAX_TOTAL_UNCOMPRESSED", 4)
    if kind == "encrypted":
        encrypted_bytes = bytearray(content.getvalue())
        local_header = encrypted_bytes.find(b"PK\x03\x04")
        central_header = encrypted_bytes.find(b"PK\x01\x02")
        struct.pack_into("<H", encrypted_bytes, local_header + 6, 1)
        struct.pack_into("<H", encrypted_bytes, central_header + 8, 1)
        content = io.BytesIO(encrypted_bytes)
    target = tmp_path / "vendor"
    expected = {
        "duplicate": "duplicate",
        "symlink": "symlink",
        "encrypted": "encrypted",
        "oversize": "oversize",
        "bomb": "total uncompressed",
    }[kind]
    with pytest.raises(ValueError, match=expected):
        _extract_wheel(content.getvalue(), "requests", target)
    assert not target.exists()


def test_extraction_uses_verified_snapshot_after_wheel_path_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = PACKAGES["requests"]["wheel"]
    snapshot = _verified_wheel_bytes("requests")
    replacement = tmp_path / "requests.whl"
    replacement.write_bytes(b"changed after snapshot")
    monkeypatch.setitem(PACKAGES["requests"], "wheel", replacement)
    target = tmp_path / "vendor"
    _extract_wheel(snapshot, "requests", target)
    hashes, versions = _wheel_evidence("requests", snapshot)
    assert versions == {"requests": "2.32.3"}
    assert hashes["requests/api.py"].startswith("sha256:")
    assert (target / "requests/api.py").is_file()
    monkeypatch.setitem(PACKAGES["requests"], "wheel", original)
