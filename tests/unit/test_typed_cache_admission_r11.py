"""Functional checks for the opt-in Mypy cache boundary."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from mypy.build import build, get_cache_names
from mypy.modulefinder import BuildSource
from mypy.options import Options

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


@pytest.mark.parametrize("case", ["hit", "unknown", "tamper", "source_tamper", "disabled"])
def test_analyzer_consumes_admitted_dependency_cache_with_fresh_text_roots(  # noqa: PLR0915
    tmp_path: Path, case: str
) -> None:
    main = tmp_path / "main.py"
    helper = tmp_path / "helper.py"
    extra_consumer = "startup()\n" if case == "unknown" else ""
    main.write_text(
        "from typing import Any\nfrom helper import startup\n"
        "app: Any\napp.add_event_handler('startup', startup)\n" + extra_consumer
    )
    helper.write_text("def startup() -> None:\n    return None\n")
    inventory = build_source_inventory(
        tmp_path,
        exclude_patterns=("helper.py",),
        follow_imports=True,
    )
    store = tmp_path / "private-store"
    store.mkdir(mode=0o700)
    store.chmod(0o700)
    seed_policy = LocalTypedCachePolicy.local_user_store(store)

    seed_cache = tmp_path / "seed-cache"
    seed_cache.mkdir()
    seed_options = _options(tmp_path, seed_cache)
    manifest_options = _options(tmp_path, seed_cache)
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
    manifest_digest = write_seed_manifest(
        seed_policy,
        _cache_dir=seed_cache,
        project_root=tmp_path,
        module_root=tmp_path,
        project_sources={"main": str(main.resolve())},
        source_hashes={"main": hashlib.sha256(main.read_bytes()).hexdigest()},
        options=manifest_options,
        mypy_version="1.19.1",
        graph=graph,
        cache_rows=[
            {
                "module": "helper",
                "source_path": str(helper.resolve()),
                "meta": meta_rel,
                "data": data_rel,
                "meta_sha256": meta_hash,
                "data_sha256": data_hash,
            }
        ],
        external_sources={
            "helper": {
                "path": str(helper.resolve()),
                "sha256": hashlib.sha256(helper_bytes).hexdigest(),
            }
        },
    )
    policy = LocalTypedCachePolicy.local_user_store(store, expected_manifest_sha256=manifest_digest)
    if case == "tamper":
        stored_meta = store / meta_rel
        stored_meta.chmod(0o600)
        stored_meta.write_bytes(stored_meta.read_bytes() + b" ")
        stored_meta.chmod(0o400)
    elif case == "source_tamper":
        helper.write_bytes(helper_bytes + b"# changed after admission seed\n")

    analyzer = MypyAnalyzer(
        main,
        module_root=tmp_path,
        source_inventory=inventory,
        typed_cache_policy=(LocalTypedCachePolicy.disabled() if case == "disabled" else policy),
    )
    analyzer._ensure_mypy_built()
    observation = analyzer.cache_admission_observation
    if case == "disabled":
        assert observation is None
        assert "helper" in analyzer._build_result.manager.rechecked_modules
        analyzer.release_typed_snapshot()
        return
    assert observation is not None
    if case in {"unknown", "tamper", "source_tamper"}:
        assert observation.get("disposition") == "cold_fallback", observation
        assert "helper" in analyzer._build_result.manager.rechecked_modules
        analyzer.release_typed_snapshot()
        return
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
