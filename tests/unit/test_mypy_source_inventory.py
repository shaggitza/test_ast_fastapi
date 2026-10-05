"""Explicit package roots and immutable source inventory integration."""

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer


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
    follow_imports: str = "normal"
    max_depth: int = 10
    excluded_files: tuple[str, ...] = ()
    unresolved_imports: tuple[str, ...] = ()


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
        follow_imports: str = "normal",
        unresolved_imports: tuple[str, ...] = (),
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
        analyzer(follow_imports="skip"),
        analyzer(unresolved_imports=("pkg.helper",)),
        analyzer(excluded=("pkg/generated.py",)),
    ]
    assert changed_fingerprint != fingerprint
    assert all(candidate._cache_fingerprint()[0] != fingerprint for candidate in variants)


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
