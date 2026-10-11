"""Functional checks for the opt-in Mypy cache boundary."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import textwrap
from dataclasses import replace
from pathlib import Path
from typing import cast

import mypy.build as mypy_build_module
import pytest
from mypy.build import build, get_cache_names
from mypy.modulefinder import BuildSource
from mypy.options import Options

import fastapi_endpoint_detector.analyzer.mypy_analyzer as mypy_analyzer_module
import fastapi_endpoint_detector.analyzer.typed_cache_admission as cache_admission_module
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.analyzer.source_inventory import build_source_inventory
from fastapi_endpoint_detector.analyzer.typed_cache_admission import (
    LocalTypedCachePolicy,
    copy_cache_snapshot,
    write_seed_manifest,
)


def _options(module_root: Path, cache_dir: Path) -> Options:
    options = Options()
    options.ignore_missing_imports = True
    options.no_site_packages = False
    options.follow_imports = "normal"
    options.mypy_path = [str(module_root)]
    options.namespace_packages = True
    options.explicit_package_bases = True
    options.preserve_asts = True
    options.incremental = True
    options.check_untyped_defs = True
    options.export_types = True
    options.cache_dir = str(cache_dir)
    return options


def test_analyzer_import_and_cold_fallback_without_fcntl(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("def value() -> int:\n    return 1\n")
    script = textwrap.dedent(
        """
        import importlib.abc
        import sys
        from pathlib import Path

        class BlockFcntl(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "fcntl":
                    raise ModuleNotFoundError("No module named 'fcntl'")
                return None

        sys.meta_path.insert(0, BlockFcntl())

        from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
        from fastapi_endpoint_detector.analyzer.typed_cache_admission import (
            LocalTypedCachePolicy,
        )

        project = Path(sys.argv[1])
        ordinary = MypyAnalyzer(project)
        ordinary._ensure_mypy_built()
        assert ordinary._build_result is not None
        assert ordinary.cache_admission_observation is None

        policy = LocalTypedCachePolicy.local_user_store(project / "missing-cache")
        opted_in = MypyAnalyzer(project, typed_cache_policy=policy)
        opted_in._ensure_mypy_built()
        assert opted_in._build_result is not None
        observation = opted_in.cache_admission_observation
        assert observation is not None
        assert observation["disposition"] == "cold_fallback", observation
        assert (
            observation["reason"] == "sealed in-memory cache descriptors are unsupported"
        ), observation
        """
    )
    source_root = Path(__file__).resolve().parents[2] / "src"
    env = {**os.environ, "PYTHONPATH": str(source_root)}
    result = subprocess.run(
        [sys.executable, "-c", script, str(project)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "case",
    [
        "hit",
        "unknown",
        "tamper",
        "source_tamper",
        "disabled",
        "warm_failure",
        "warm_cancel",
        "cold_failure",
        "staging_failure",
        "postproof_read_failure",
        "postproof_validation_failure",
        "artifact_list_module",
        "artifact_dict_module",
        "duplicate_module",
        "malformed_external_record",
        "external_source_budget",
        "external_source_boundary",
        "partial_hit",
    ],
)
def test_analyzer_consumes_admitted_dependency_cache_with_fresh_text_roots(  # noqa: PLR0911, PLR0912, PLR0915
    tmp_path: Path, case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    external_root = tmp_path / "external"
    external_root.mkdir()
    main = project / "main.py"
    helper = external_root / "helper.py"
    extra_consumer = "startup()\n" if case == "unknown" else ""
    main.write_text(
        "from typing import Any\nfrom helper import startup\n"
        "app: Any\napp.add_event_handler('startup', startup)\n" + extra_consumer
    )
    helper.write_text("def startup() -> None:\n    return None\n")
    inventory = build_source_inventory(project, follow_imports=True)
    assert {record.relative_path for record in inventory.files} == {"main.py"}
    assert not helper.resolve().is_relative_to(project.resolve())
    store = tmp_path / "private-store"
    store.mkdir(mode=0o700)
    store.chmod(0o700)
    seed_policy = LocalTypedCachePolicy.local_user_store(store)

    seed_cache = tmp_path / "seed-cache"
    seed_cache.mkdir()
    seed_options = _options(external_root, seed_cache)
    manifest_options = _options(external_root, seed_cache)
    seed = build(
        [BuildSource(str(main), "main", text=main.read_text())],
        seed_options,
    )
    assert "helper" in seed.graph
    meta_name, data_name, _ = get_cache_names("helper", str(helper), seed_options)
    meta_path = next(seed_cache.rglob(Path(meta_name).name))
    data_path = meta_path.with_name(Path(data_name).name)
    meta_rel = "artifacts/helper.meta.json"
    data_rel = "artifacts/helper.data.json"
    meta_hash = copy_cache_snapshot(meta_path, store, meta_rel)
    data_hash = copy_cache_snapshot(data_path, store, data_rel)
    helper_bytes = helper.read_bytes()
    graph = {module: getattr(state, "source_hash", None) for module, state in seed.graph.items()}
    graph = {module: digest for module, digest in graph.items() if isinstance(digest, str)}
    cache_row = {
        "module": "helper",
        "source_path": str(helper.resolve()),
        "meta": meta_rel,
        "data": data_rel,
        "meta_sha256": meta_hash,
        "data_sha256": data_hash,
    }
    cache_rows = [cache_row]
    external_records = {
        "helper": {
            "path": str(helper.resolve()),
            "sha256": hashlib.sha256(helper_bytes).hexdigest(),
        }
    }
    if case == "artifact_list_module":
        cache_rows = cast("list[dict[str, str]]", [{**cache_row, "module": ["helper"]}])
    elif case == "artifact_dict_module":
        cache_rows = cast("list[dict[str, str]]", [{**cache_row, "module": {"name": "helper"}}])
    elif case == "duplicate_module":
        cache_rows = [cache_row, dict(cache_row)]
    elif case == "malformed_external_record":
        external_records = cast("dict[str, dict[str, str]]", {"helper": []})
    manifest_digest = write_seed_manifest(
        seed_policy,
        _cache_dir=seed_cache,
        project_root=project,
        module_root=external_root,
        project_sources={"main": str(main.resolve())},
        source_hashes={"main": hashlib.sha256(main.read_bytes()).hexdigest()},
        options=manifest_options,
        mypy_version="1.19.1",
        graph=graph,
        cache_rows=cache_rows,
        external_sources=external_records,
    )
    policy = LocalTypedCachePolicy.local_user_store(store, expected_manifest_sha256=manifest_digest)
    if case == "tamper":
        stored_meta = store / meta_rel
        stored_meta.chmod(0o600)
        stored_meta.write_bytes(stored_meta.read_bytes() + b" ")
        stored_meta.chmod(0o400)
    elif case == "source_tamper":
        helper.write_bytes(helper_bytes + b"# changed after admission seed\n")

    initial_fd_count = len(list(Path("/proc/self/fd").iterdir()))
    initial_run_dirs = set(store.glob("r13-run-*"))
    if case in {"warm_failure", "warm_cancel", "cold_failure"}:
        original_build = mypy_build_module.build
        calls = 0
        incremental_values: list[bool] = []

        def failing_build(*args: object, **kwargs: object) -> object:
            nonlocal calls
            calls += 1
            build_options = kwargs.get("options")
            if isinstance(build_options, Options):
                incremental_values.append(build_options.incremental)
            if case == "warm_failure" and calls == 1:
                raise RuntimeError("injected warm build failure")
            if case == "warm_cancel" and calls == 1:
                raise KeyboardInterrupt("injected warm cancellation")
            if case == "cold_failure" and calls == 2:
                raise RuntimeError("injected cold fallback failure")
            return original_build(*args, **kwargs)

        monkeypatch.setattr(mypy_build_module, "build", failing_build)
    elif case == "staging_failure":
        original_fcntl = cache_admission_module.fcntl.fcntl

        def fail_seal(descriptor: int, command: int, *args: object) -> int:
            if command == cache_admission_module.fcntl.F_ADD_SEALS:
                raise OSError("injected mid-staging seal failure")
            return original_fcntl(descriptor, command, *args)

        monkeypatch.setattr(cache_admission_module.fcntl, "fcntl", fail_seal)
    elif case == "postproof_read_failure":
        original_read_bytes = Path.read_bytes

        def fail_memfd_read(path: Path) -> bytes:
            if str(path).startswith("/proc/self/fd/"):
                raise OSError("injected post-proof cache read failure")
            return original_read_bytes(path)

        monkeypatch.setattr(Path, "read_bytes", fail_memfd_read)
    elif case == "postproof_validation_failure":

        def fail_external_validation(_snapshots: dict[str, bytes]) -> bool:
            raise RuntimeError("injected post-proof validation failure")

        monkeypatch.setattr(
            mypy_analyzer_module, "external_snapshots_unchanged", fail_external_validation
        )

    if case in {"external_source_budget", "external_source_boundary", "partial_hit"}:
        original_prepare = mypy_analyzer_module.prepare_cache_run
        read_limits: list[int] = []
        original_read = cache_admission_module._read_external

        def record_read(path: Path, limit: int) -> bytes:
            read_limits.append(limit)
            return original_read(path, limit)

        def prepare_modified_plan(*args: object, **kwargs: object) -> object:
            if case in {"external_source_budget", "external_source_boundary"}:
                budget = len(helper_bytes) - (case == "external_source_budget")
                monkeypatch.setattr(cache_admission_module, "MAX_SOURCE_BYTES", budget)
            plan, snapshots = original_prepare(*args, **kwargs)
            if case == "partial_hit":
                plan = replace(
                    plan,
                    admitted_modules=plan.admitted_modules | {"missing_admitted_module"},
                )
            return plan, snapshots

        monkeypatch.setattr(cache_admission_module, "_read_external", record_read)
        monkeypatch.setattr(mypy_analyzer_module, "prepare_cache_run", prepare_modified_plan)
        if case == "external_source_budget":

            def unexpected_consumer_check(*args: object, **kwargs: object) -> bool:
                raise AssertionError(
                    "overflow reached external source decoding/consumer validation"
                )

            monkeypatch.setattr(
                cache_admission_module,
                "_known_event_registration_consumers",
                unexpected_consumer_check,
            )

    analyzer = MypyAnalyzer(
        main,
        module_root=external_root,
        source_inventory=inventory,
        typed_cache_policy=(LocalTypedCachePolicy.disabled() if case == "disabled" else policy),
    )
    if case == "cold_failure":
        with pytest.raises(RuntimeError, match="injected cold fallback failure"):
            analyzer._ensure_mypy_built()
        assert calls == 2
        assert set(store.glob("r13-run-*")) == initial_run_dirs
        assert len(list(Path("/proc/self/fd").iterdir())) == initial_fd_count
        return
    if case == "warm_cancel":
        with pytest.raises(KeyboardInterrupt, match="injected warm cancellation"):
            analyzer._ensure_mypy_built()
        assert calls == 1
        assert set(store.glob("r13-run-*")) == initial_run_dirs
        assert len(list(Path("/proc/self/fd").iterdir())) == initial_fd_count
        return
    if case in {"postproof_read_failure", "postproof_validation_failure"}:
        analyzer._ensure_mypy_built()
        observation = analyzer.cache_admission_observation
        assert observation is not None
        assert observation["disposition"] == "cold_fallback", observation
        assert observation["reason"] == "warm_build_or_proof_exception", observation
        assert "helper" in analyzer._build_result.manager.rechecked_modules
        assert set(store.glob("r13-run-*")) == initial_run_dirs
        assert len(list(Path("/proc/self/fd").iterdir())) == initial_fd_count
        analyzer.release_typed_snapshot()
        return

    analyzer._ensure_mypy_built()
    observation = analyzer.cache_admission_observation
    if case == "disabled":
        assert observation is None
        assert "helper" in analyzer._build_result.manager.rechecked_modules
        analyzer.release_typed_snapshot()
        return
    assert observation is not None
    if case == "warm_failure":
        assert observation["disposition"] == "cold_fallback", observation
        assert observation["reason"] == "warm_build_or_proof_exception", observation
        assert "helper" in analyzer._build_result.manager.rechecked_modules
        assert calls == 2
        assert incremental_values == [True, False]
        assert set(store.glob("r13-run-*")) == initial_run_dirs
        analyzer.release_typed_snapshot()
        return
    if case == "staging_failure":
        assert observation.get("disposition") == "cold_fallback", observation
        assert set(store.glob("r13-run-*")) == initial_run_dirs
        assert len(list(Path("/proc/self/fd").iterdir())) == initial_fd_count
        analyzer.release_typed_snapshot()
        return
    if case in {
        "unknown",
        "tamper",
        "source_tamper",
        "artifact_list_module",
        "artifact_dict_module",
        "duplicate_module",
        "malformed_external_record",
        "external_source_budget",
    }:
        assert observation.get("disposition") == "cold_fallback", observation
        assert "helper" in analyzer._build_result.manager.rechecked_modules
        if case == "external_source_budget":
            assert observation["reason"] == (
                "external source is not a bounded single-link regular file"
            )
            assert read_limits == [len(helper_bytes) - 1]
        assert set(store.glob("r13-run-*")) == initial_run_dirs
        assert len(list(Path("/proc/self/fd").iterdir())) == initial_fd_count
        analyzer.release_typed_snapshot()
        return
    if case == "partial_hit":
        assert observation["cache_hit_modules"] == ["helper"]
        assert observation["graph_source_hashes_match"] is False
        assert observation["fallback"] == "cache_proof_failed"
        assert "helper" in analyzer._build_result.manager.rechecked_modules
        assert set(store.glob("r13-run-*")) == initial_run_dirs
        assert len(list(Path("/proc/self/fd").iterdir())) == initial_fd_count
        analyzer.release_typed_snapshot()
        return
    if case == "external_source_boundary":
        assert read_limits[0] == len(helper_bytes)
    assert observation.get("cache_hit_modules") == ["helper"], observation
    assert observation["roots_fresh"] is True
    assert observation["graph_source_hashes_match"] is True, observation
    assert (
        observation["graph_source_hashes"]["helper"]
        == observation["manifest_source_hashes"]["helper"]
    )
    assert len(observation["cache_artifact_sha256"]) == 2
    assert "main" in analyzer._build_result.manager.rechecked_modules
    assert "main" in observation["warm_rechecked_modules"]
    assert "helper" not in observation["warm_rechecked_modules"]
    assert observation["fallback"] == "v2_identity_report_runtime_protocol_not_enabled"
    assert "helper" in analyzer._build_result.manager.rechecked_modules
    assert analyzer._build_result.graph["helper"].tree is not None
    assert analyzer._trees["helper"] is not None
    analyzer.release_typed_snapshot()
