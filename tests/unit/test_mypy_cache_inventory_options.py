"""Retained cold builds must keep the inventory policy during cache diagnostics."""

import hashlib
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import mypy.build
import pytest

from fastapi_endpoint_detector.analyzer import mypy_analyzer as analyzer_module
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.analyzer.typed_cache_admission import LocalTypedCachePolicy


def _controlled_analyzer(root: Path, monkeypatch: pytest.MonkeyPatch):
    source = root / "main.py"
    source_bytes = b"value: int = 1\n"
    digest = hashlib.sha256(source_bytes).hexdigest()
    record = SimpleNamespace(
        path=source, relative_path="main.py", module="main", sha256=digest, imports=()
    )
    inventory = SimpleNamespace(
        root=root,
        files=(record,),
        max_depth=4,
        follow_imports=True,
        excluded_files=("blocked.pyi",),
        unresolved_imports=(),
        module_collisions=(),
    )
    analyzer = MypyAnalyzer(
        source,
        module_root=root,
        source_inventory=inventory,
        typed_cache_policy=LocalTypedCachePolicy(root / "private-cache"),
    )
    analyzer._mypy_available = True
    analyzer._expected_source_fingerprint = "controlled-source-fingerprint"
    analyzer._last_source_records = [(source, "main", digest)]
    analyzer._source_record_snapshots = {str(source.resolve()): source_bytes}
    monkeypatch.setattr(
        analyzer,
        "_unselected_local_modules",
        lambda: (("blocked", True, str(root / "blocked.pyi"), True),),
    )
    monkeypatch.setattr(analyzer, "_fingerprint_typed_environment", lambda **_kwargs: "controlled")

    return analyzer, source, source_bytes


def _retained_cold_result(analyzer, calls, prepare_calls):
    expected_policy = {"follow_imports": "skip", "follow_imports_for_stubs": True}
    assert len(prepare_calls) == 1
    assert prepare_calls[0].per_module_options["blocked"] == expected_policy
    assert prepare_calls[0].per_module_options["blocked.*"] == expected_policy
    cold_calls = [options for options, _cache in calls if not options.incremental]
    assert len(cold_calls) == 1
    cold = cold_calls[0]
    assert cold.per_module_options["blocked"] == expected_policy
    assert cold.per_module_options["blocked.*"] == expected_policy
    assert cold.incremental is False
    assert not cold.cache_map
    assert analyzer._build_result.manager.options is cold
    observation = analyzer.cache_admission_observation
    assert observation is not None

    return cold, observation


@pytest.mark.parametrize("mode", ["prepare_reject", "warm_exception", "diagnostic_success"])
def test_cache_diagnostic_cold_paths_keep_inventory_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    analyzer, source, source_bytes = _controlled_analyzer(tmp_path, monkeypatch)

    cache_plan = SimpleNamespace(
        run_root=tmp_path / "private-run",
        cache_map={str(source.resolve()): ("cached.meta", "cached.data")},
        expected_graph={"external": "external-source-hash"},
        expected_roots=frozenset({"main"}),
        admitted_modules=frozenset({"external"}),
        manifest_sha256="a" * 64,
        trust_id="controlled-trust-id",
        artifact_hashes={},
    )
    prepare_calls = []

    def prepare(_policy, *, options, project_sources, source_texts, **_kwargs):
        prepare_calls.append(deepcopy(options))
        assert project_sources == {"main": str(source.resolve())}
        assert source_texts == {str(source.resolve()): source_bytes.decode()}
        if mode == "prepare_reject":
            raise analyzer_module.CacheAdmissionError("controlled cache-plan rejection")
        # Even if diagnostic preparation changes its working options, it must
        # not alter the pre-preparation policy used for the retained result.
        options.per_module_options.clear()
        return cache_plan, {}

    monkeypatch.setattr(analyzer_module, "prepare_cache_run", prepare)
    removals = []
    monkeypatch.setattr(analyzer_module, "remove_run", removals.append)
    calls = []

    def fake_build(*, sources, options, fscache, **_kwargs):
        calls.append((options, fscache))
        assert len(sources) == 1 and sources[0].module == "main"
        assert sources[0].text == source_bytes.decode()
        graph = {}
        if options.incremental:
            if mode == "warm_exception":
                raise RuntimeError("controlled warm-build failure")
            assert mode == "diagnostic_success"
            graph["external"] = SimpleNamespace(
                tree=object(), meta_source_hash="external-source-hash", path=None
            )
        return SimpleNamespace(
            graph=graph,
            manager=SimpleNamespace(options=options, rechecked_modules={"main"}),
            types={},
        )

    monkeypatch.setattr(mypy.build, "build", fake_build)
    analyzer._ensure_mypy_built()

    cold, observation = _retained_cold_result(analyzer, calls, prepare_calls)

    if mode == "prepare_reject":
        assert len(calls) == 1
        assert observation["disposition"] == "cold_fallback"
        assert removals == [None]
    else:
        assert len(calls) == 2
        warm_options, warm_cache = calls[0]
        _cold_options, cold_cache = calls[1]
        assert warm_options.incremental is True
        assert warm_options.cache_map == cache_plan.cache_map
        assert warm_cache is not cold_cache
        assert cold is not warm_options
        assert removals == [cache_plan]
        if mode == "warm_exception":
            assert observation["reason"] == "warm_build_or_proof_exception"
        else:
            assert observation["fallback"] == "v2_identity_report_runtime_protocol_not_enabled"
