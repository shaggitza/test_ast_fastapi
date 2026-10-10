"""Same-build-result reuse checks for framework phase evidence."""

from __future__ import annotations

import hashlib
import os
from types import SimpleNamespace
from typing import TYPE_CHECKING

import mypy.build
import pytest

from fastapi_endpoint_detector.analyzer import mypy_analyzer, mypy_incremental
from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper, _mypy_inventory
from fastapi_endpoint_detector.analyzer.framework_phase_integration import (
    collect_framework_phase_evidence,
)
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.analyzer.mypy_incremental import (
    BuildConfig,
    IncrementalBuildError,
    MypyIncrementalProvider,
)
from fastapi_endpoint_detector.config import AnalysisConfig, Config
from fastapi_endpoint_detector.models.endpoint import SnapshotSide
from fastapi_endpoint_detector.models.surface_contract import load_surface_preset
from fastapi_endpoint_detector.parser.custom_surface_extractor import CustomSurfaceExtractor

if TYPE_CHECKING:
    from pathlib import Path


def _write_app(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    app = root / "main.py"
    app.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.on_event('startup')\n"
        "def startup() -> None:\n"
        "    print('ready')\n",
        encoding="utf-8",
    )
    return app


def _semantic_records(records: list[dict[str, object]]) -> list[dict[str, object]]:
    ignored = {
        "typed_provider_fingerprint",
        "source_sha256",
        "inventory_sha256",
        "engine_sha256",
        "config_sha256",
    }
    return [
        {key: value for key, value in record.items() if key not in ignored} for record in records
    ]


def test_public_analyze_diff_reuses_its_exact_mypy_build(tmp_path: Path, monkeypatch) -> None:
    app = _write_app(tmp_path)
    contracts = load_surface_preset("framework-v1")
    inventory = CustomSurfaceExtractor(tmp_path, contracts).extract_inventory()
    provider = MypyIncrementalProvider(BuildConfig(tmp_path)).build({"main": app})
    baseline_analyzer = MypyAnalyzer(tmp_path)
    baseline_analyzer.analyze_endpoints([], use_cache=False)
    baseline = collect_framework_phase_evidence(inventory, contracts, baseline_analyzer, provider)

    mapper = ChangeMapper(
        app,
        config=Config(analysis=AnalysisConfig(surface_preset="framework-v1")),
        secure_ast=True,
        use_cache=False,
    )
    original_build = mypy.build.build
    calls = 0

    def counted_build(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original_build(*args, **kwargs)

    monkeypatch.setattr(mypy.build, "build", counted_build)
    monkeypatch.setattr(mypy_incremental, "build", counted_build)
    report = mapper.analyze_diff("")

    phase = report.framework_phase_report
    assert phase is not None and phase.record_count == 1
    assert calls == 1
    assert report.candidate_endpoints == report.affected_endpoints == []
    actual = _semantic_records(phase.records)[0]
    expected_record = baseline.records[0].model_dump(mode="json")
    expected_record["status"] = baseline.records[0].status
    expected = _semantic_records([expected_record])[0]
    differences = {
        key: (actual.get(key), expected.get(key))
        for key in sorted(set(actual) | set(expected))
        if actual.get(key) != expected.get(key)
    }
    assert not differences, differences


def test_public_phase_report_abstains_if_retained_source_changes(tmp_path: Path) -> None:
    app = _write_app(tmp_path)
    mapper = ChangeMapper(
        app,
        config=Config(analysis=AnalysisConfig(surface_preset="framework-v1")),
        secure_ast=True,
        use_cache=False,
    )
    original_report = mapper.map_framework_phase_report

    def edit_then_report(*, snapshot_side=SnapshotSide.TARGET):
        app.write_text(app.read_text(encoding="utf-8") + "# changed after preanalysis\n")
        return original_report(snapshot_side=snapshot_side)

    mapper.map_framework_phase_report = edit_then_report  # type: ignore[method-assign]
    report = mapper.analyze_diff("").framework_phase_report

    assert report is not None and report.backend == "unavailable"
    assert report.runtime_manifest["entries"] == []
    assert any("changed before typed build" in item for item in report.limitations)


@pytest.mark.parametrize("mismatch", ["missing", "root", "module", "source_hash"])
def test_retained_graph_identity_mismatches_fail_closed(tmp_path: Path, mismatch: str) -> None:
    app = _write_app(tmp_path)
    mapper = ChangeMapper(
        app,
        config=Config(analysis=AnalysisConfig(surface_preset="framework-v1")),
        secure_ast=True,
        use_cache=False,
    )
    selected, _module_root = _mypy_inventory(mapper.source_inventory)
    record = selected.files[0]
    analyzer = mapper.mypy_analyzer
    retained_source = record.path.read_bytes()
    graph = {}
    if mismatch != "missing":
        state_path = record.path
        fullname = record.module
        source_hash = hashlib.sha1(retained_source).hexdigest()
        if mismatch == "root":
            state_path = tmp_path / "outside.py"
        elif mismatch == "module":
            fullname = "wrong.module"
        elif mismatch == "source_hash":
            source_hash = "wrong-hash"
        graph[record.module] = SimpleNamespace(
            path=str(state_path),
            tree=SimpleNamespace(fullname=fullname),
            source_hash=source_hash,
        )
    result = SimpleNamespace(graph=graph)
    analyzer.framework_phase_build_snapshot = lambda: (  # type: ignore[method-assign]
        result,
        {str(record.path.resolve()): retained_source},
    )

    with pytest.raises(IncrementalBuildError, match="retained mypy graph"):
        mapper._framework_typed_build(analyzer)


def test_bounded_source_read_stays_limited_if_file_grows_after_stat(
    tmp_path: Path, monkeypatch
) -> None:
    app = _write_app(tmp_path)
    mapper = ChangeMapper(
        app,
        config=Config(analysis=AnalysisConfig(surface_preset="framework-v1")),
        secure_ast=True,
        use_cache=False,
    )
    analyzer = mapper.mypy_analyzer
    byte_limit = max(128, app.stat().st_size + 8)
    analyzer.MAX_LAMBDA_SOURCE_FILE_BYTES = byte_limit
    analyzer.MAX_LAMBDA_SOURCE_SNAPSHOT_BYTES = byte_limit * 2
    original_read = os.read
    requests: list[int] = []
    returned_sizes: list[int] = []

    def grow_then_read(descriptor: int, count: int) -> bytes:
        requests.append(count)
        with app.open("ab") as source:
            source.write(b"#" * (byte_limit + 16))
        data = original_read(descriptor, count)
        returned_sizes.append(len(data))
        return data

    monkeypatch.setattr(mypy_analyzer.os, "read", grow_then_read)
    with pytest.raises(IncrementalBuildError, match="byte budget"):
        mapper._framework_typed_build(analyzer)

    assert requests == [byte_limit + 1]
    assert returned_sizes == [byte_limit + 1]


def test_aggregate_source_budget_rejects_before_reading_file(tmp_path: Path, monkeypatch) -> None:
    app = _write_app(tmp_path)
    mapper = ChangeMapper(
        app,
        config=Config(analysis=AnalysisConfig(surface_preset="framework-v1")),
        secure_ast=True,
        use_cache=False,
    )
    analyzer = mapper.mypy_analyzer
    analyzer.MAX_LAMBDA_SOURCE_FILE_BYTES = app.stat().st_size + 10
    analyzer.MAX_LAMBDA_SOURCE_SNAPSHOT_BYTES = app.stat().st_size - 1
    requests: list[int] = []
    original_read = os.read

    def count_read(descriptor: int, count: int) -> bytes:
        requests.append(count)
        return original_read(descriptor, count)

    monkeypatch.setattr(mypy_analyzer.os, "read", count_read)
    with pytest.raises(IncrementalBuildError, match="byte budget"):
        mapper._framework_typed_build(analyzer)

    assert requests == []


def test_bounded_reader_rejects_parent_symlink_swap_before_outside_read(
    tmp_path: Path, monkeypatch
) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    source = package / "mod.py"
    source.write_bytes(b"original module bytes")
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_marker = outside / "mod.py"
    outside_marker.write_bytes(b"outside marker bytes")
    analyzer = MypyAnalyzer(tmp_path)

    assert analyzer.framework_phase_source_bytes(source, max_bytes=1024) == b"original module bytes"

    original_open = os.open
    original_read = os.read
    swapped = False
    outside_reads: list[int] = []
    marker_stat = outside_marker.stat()

    def swap_parent_then_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if path == "pkg" and dir_fd is not None and not swapped:
            package.rename(tmp_path / "moved_pkg")
            package.symlink_to(outside, target_is_directory=True)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    def track_outside_read(descriptor: int, count: int) -> bytes:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) == (marker_stat.st_dev, marker_stat.st_ino):
            outside_reads.append(count)
        return original_read(descriptor, count)

    monkeypatch.setattr(mypy_analyzer.os, "open", swap_parent_then_open)
    monkeypatch.setattr(
        mypy_analyzer.os,
        "supports_dir_fd",
        mypy_analyzer.os.supports_dir_fd | {swap_parent_then_open},
    )
    monkeypatch.setattr(mypy_analyzer.os, "read", track_outside_read)
    assert analyzer.framework_phase_source_bytes(source, max_bytes=1024) is None
    assert swapped
    assert outside_reads == []
