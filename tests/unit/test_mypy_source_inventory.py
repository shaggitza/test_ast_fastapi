"""Explicit package roots and immutable source inventory integration."""

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer, MypyAnalyzerError
from fastapi_endpoint_detector.analyzer.source_inventory import build_source_inventory
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


@dataclass(frozen=True)
class _SourceFile:
    path: str
    relative_path: str
    module: str
    sha256: str
    imports: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Inventory:
    root: Path
    files: tuple[_SourceFile, ...]
    follow_imports: bool = True
    max_depth: int = 10
    excluded_files: tuple[str, ...] = ()
    unresolved_imports: tuple[tuple[str, str], ...] = ()


def test_module_ids_use_explicit_root_for_src_namespace_and_app_paths(tmp_path: Path) -> None:
    checkout = tmp_path / "repo.with-hyphen and spaces"
    package_root = checkout / "src"
    package = package_root / "pkg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    app_file = package / "main.py"
    helper = package / "helper.py"
    app_file.write_text("def handler():\n    return 1\n", encoding="utf-8")
    helper.write_text("def changed():\n    return 1\n", encoding="utf-8")

    directory_analyzer = MypyAnalyzer(package, module_root=package_root)
    file_analyzer = MypyAnalyzer(app_file, module_root=package_root)
    assert {module for _path, module, _digest in directory_analyzer._source_records()} == {
        "pkg",
        "pkg.helper",
        "pkg.main",
    }
    assert {module for _path, module, _digest in file_analyzer._source_records()} == {
        "pkg",
        "pkg.helper",
        "pkg.main",
    }

    namespace = checkout / "namespace" / "ns_pkg"
    namespace.mkdir(parents=True)
    (namespace / "worker.py").write_text("def changed():\n    return 1\n", encoding="utf-8")
    namespace_analyzer = MypyAnalyzer(
        namespace,
        module_root=checkout / "namespace",
    )
    assert [module for _path, module, _digest in namespace_analyzer._source_records()] == [
        "ns_pkg.worker"
    ]


def test_flat_app_module_ids_ignore_ad_hoc_root_name(tmp_path: Path) -> None:
    root = tmp_path / "repo.with-hyphen and spaces"
    root.mkdir()
    main = root / "main.py"
    main.write_text("def handler():\n    return 1\n", encoding="utf-8")

    directory_modules = {module for _path, module, _digest in MypyAnalyzer(root)._source_records()}
    file_modules = {module for _path, module, _digest in MypyAnalyzer(main)._source_records()}

    assert directory_modules == {"main"}
    assert file_modules == directory_modules


def test_canonical_inventory_controls_discovery_and_cache_identity(tmp_path: Path) -> None:
    root = tmp_path / "checkout-name-must-not-be-a-module"
    root.mkdir()
    selected = root / "pkg" / "main.py"
    selected.parent.mkdir()
    source = "def handler():\n    return 1\n"
    selected.write_text(source, encoding="utf-8")
    extra = root / "ignored.py"
    extra.write_text("def not_selected():\n    return 1\n", encoding="utf-8")
    digest = sha256(source.encode()).hexdigest()

    def analyzer(
        *,
        file_digest: str = digest,
        module: str = "pkg.main",
        follow_imports: bool = True,
        unresolved_imports: tuple[tuple[str, str], ...] = (),
        excluded: tuple[str, ...] = (),
    ) -> MypyAnalyzer:
        inventory = _Inventory(
            root=root,
            files=(
                _SourceFile(
                    path=str(selected),
                    relative_path="pkg/main.py",
                    module=module,
                    sha256=file_digest,
                    imports=("pkg.helper",),
                ),
            ),
            follow_imports=follow_imports,
            excluded_files=excluded,
            unresolved_imports=unresolved_imports,
        )
        return MypyAnalyzer(selected, source_inventory=inventory)

    baseline = analyzer()
    sources = baseline._source_records()
    assert [(path, module) for path, module, _digest in sources] == [(selected, "pkg.main")]
    fingerprint, cache_sources = baseline._cache_fingerprint()
    assert cache_sources == {"pkg/main.py": digest}

    changed_source = source + "# updated snapshot\n"
    selected.write_text(changed_source, encoding="utf-8")
    changed_digest = sha256(changed_source.encode()).hexdigest()
    changed_fingerprint = analyzer(file_digest=changed_digest)._cache_fingerprint()[0]
    selected.write_text(source, encoding="utf-8")

    variants = [
        analyzer(module="other.main"),
        analyzer(follow_imports=False),
        analyzer(unresolved_imports=(("pkg/main.py", "pkg.helper"),)),
        analyzer(excluded=("pkg/generated.py",)),
    ]
    assert changed_fingerprint != fingerprint
    assert all(candidate._cache_fingerprint()[0] != fingerprint for candidate in variants)


def test_inventory_follow_import_policy_maps_to_mypy_values(tmp_path: Path) -> None:
    path = tmp_path / "main.py"
    path.write_text("def handler():\n    return 1\n", encoding="utf-8")
    digest = sha256(path.read_bytes()).hexdigest()

    def with_policy(policy: bool) -> MypyAnalyzer:
        return MypyAnalyzer(
            path,
            source_inventory=_Inventory(
                root=tmp_path,
                files=(_SourceFile(str(path), "main.py", "main", digest),),
                follow_imports=policy,
            ),
        )

    assert with_policy(True)._effective_follow_imports() == "normal"
    assert with_policy(False)._effective_follow_imports() == "skip"


def test_stale_inventory_hash_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "main.py"
    path.write_text("def handler():\n    return 1\n", encoding="utf-8")
    inventory = _Inventory(
        root=tmp_path,
        files=(
            _SourceFile(
                path=str(path),
                relative_path="main.py",
                module="main",
                sha256="0" * 64,
            ),
        ),
    )

    try:
        MypyAnalyzer(path, source_inventory=inventory)._cache_fingerprint()
    except Exception as exc:
        assert "source inventory is stale" in str(exc)
    else:
        raise AssertionError("stale inventory hashes must not produce a cache fingerprint")


def test_followed_import_outside_inventory_is_not_project_evidence(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    main = package / "main.py"
    helper = package / "helper.py"
    main.write_text(
        "from pkg.helper import changed\n\ndef handler():\n    changed()\n",
        encoding="utf-8",
    )
    helper.write_text("def changed():\n    return None\n", encoding="utf-8")
    inventory = _Inventory(
        root=tmp_path,
        files=(
            _SourceFile(
                str(main),
                "pkg/main.py",
                "pkg.main",
                sha256(main.read_bytes()).hexdigest(),
                imports=("pkg.helper",),
            ),
        ),
        follow_imports=True,
        excluded_files=("pkg/helper.py",),
        unresolved_imports=(("pkg/main.py", "pkg.missing"),),
    )
    analyzer = MypyAnalyzer(main, source_inventory=inventory)
    endpoint = Endpoint(
        path="/test",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="handler", module="pkg.main", file_path=main, line_number=3),
    )

    deps = analyzer.analyze_endpoint(endpoint)

    assert not deps.references_file(str(helper))
    assert not analyzer._exact_project_identity("pkg.helper.changed")
    assert deps.unresolved_imports == (("pkg/main.py", "pkg.missing"),)
    assert deps.analysis_incomplete


def test_failed_build_is_not_cached_and_next_analysis_rebuilds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    main = tmp_path / "main.py"
    main.write_text("def handler():\n    return 1\n", encoding="utf-8")
    endpoint = Endpoint(
        path="/test",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="handler", module="main", file_path=main, line_number=1),
    )
    analyzer = MypyAnalyzer(tmp_path)
    cache = tmp_path / "analysis-cache.json"
    analyzer.set_cache_path(cache)

    def failed_build() -> None:
        raise MypyAnalyzerError("ambiguous local module identities")

    monkeypatch.setattr(analyzer, "_ensure_mypy_built", failed_build)
    results = analyzer.analyze_endpoints([endpoint], use_cache=True)
    failed = results[analyzer._endpoint_key(endpoint)]

    assert failed.analysis_incomplete
    assert not cache.exists()

    monkeypatch.undo()
    results = analyzer.analyze_endpoints([endpoint], use_cache=True)
    rebuilt = results[analyzer._endpoint_key(endpoint)]

    assert not rebuilt.analysis_incomplete
    assert cache.exists()


def test_schema_23_cache_without_completion_metadata_is_rebuilt(tmp_path: Path) -> None:
    main = tmp_path / "main.py"
    main.write_text("def handler():\n    return 1\n", encoding="utf-8")
    endpoint = Endpoint(
        path="/test",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="handler", module="main", file_path=main, line_number=1),
    )
    cache = tmp_path / "analysis-cache.json"
    first = MypyAnalyzer(tmp_path)
    first.set_cache_path(cache)
    first.analyze_endpoints([endpoint], use_cache=True)

    old_cache = json.loads(cache.read_text(encoding="utf-8"))
    old_cache["schema_version"] = 23
    for dependencies in old_cache["endpoints"].values():
        dependencies.pop("analysis_incomplete")
        dependencies.pop("unresolved_imports")
    cache.write_text(json.dumps(old_cache), encoding="utf-8")

    second = MypyAnalyzer(tmp_path)
    second.set_cache_path(cache)
    assert not second._load_cache()
    results = second.analyze_endpoints([endpoint], use_cache=True)
    assert not results[second._endpoint_key(endpoint)].analysis_incomplete
    assert json.loads(cache.read_text(encoding="utf-8"))["schema_version"] == 24


def test_single_endpoint_recovers_after_failed_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    main = tmp_path / "main.py"
    main.write_text("def handler():\n    return 1\n", encoding="utf-8")
    endpoint = Endpoint(
        path="/test",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="handler", module="main", file_path=main, line_number=1),
    )
    analyzer = MypyAnalyzer(tmp_path)

    def failed_build() -> None:
        raise MypyAnalyzerError("first build failed")

    monkeypatch.setattr(analyzer, "_ensure_mypy_built", failed_build)
    assert analyzer.analyze_endpoint(endpoint).analysis_incomplete
    monkeypatch.undo()
    assert not analyzer.analyze_endpoint(endpoint).analysis_incomplete


def test_public_inventory_ambiguous_module_fails_closed_then_recovers(tmp_path: Path) -> None:
    main = tmp_path / "main.py"
    main.write_text("import vendor\n\ndef handler():\n    return vendor.value\n", encoding="utf-8")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor.py").write_text("value = 1\n", encoding="utf-8")
    symlink_target = tmp_path / "outside-vendor-init.py"
    symlink_target.write_text("value = 2\n", encoding="utf-8")
    (tmp_path / "vendor" / "__init__.py").symlink_to(symlink_target)
    endpoint = Endpoint(
        path="/test",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="handler", module="main", file_path=main, line_number=3),
    )
    cache = tmp_path / "analysis-cache.json"

    inventory = build_source_inventory(tmp_path)
    assert any(name == "vendor" for name, _paths in inventory.module_collisions)
    failed_analyzer = MypyAnalyzer(main, source_inventory=inventory)
    failed_analyzer.set_cache_path(cache)
    failed = failed_analyzer.analyze_endpoints([endpoint], use_cache=True)[
        failed_analyzer._endpoint_key(endpoint)
    ]
    assert failed.analysis_incomplete
    assert not cache.exists()

    (tmp_path / "vendor.py").unlink()
    (tmp_path / "vendor" / "__init__.py").unlink()
    (tmp_path / "vendor" / "__init__.py").write_text("value = 2\n", encoding="utf-8")
    repaired_inventory = build_source_inventory(tmp_path)
    repaired_analyzer = MypyAnalyzer(main, source_inventory=repaired_inventory)
    repaired_analyzer.set_cache_path(cache)
    repaired = repaired_analyzer.analyze_endpoints([endpoint], use_cache=True)[
        repaired_analyzer._endpoint_key(endpoint)
    ]
    assert not repaired.analysis_incomplete
    assert cache.exists()
