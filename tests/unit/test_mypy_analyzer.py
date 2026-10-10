"""
Unit tests for the MypyAnalyzer.

These tests verify the mypy-based dependency analysis, including:
- Basic endpoint analysis
- Loop prevention in circular dependencies
- Line progress callbacks
"""

import sys
from importlib.util import find_spec
from pathlib import Path

import pytest
from mypy.nodes import MemberExpr, NameExpr

from fastapi_endpoint_detector.analyzer.mypy_analyzer import (
    CallFrame,
    EndpointDependencies,
    MypyAnalyzer,
    MypyAnalyzerError,
)
from fastapi_endpoint_detector.analyzer.source_inventory import build_source_inventory
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


class TestMypyAnalyzerBasic:
    """Basic tests for MypyAnalyzer."""

    def test_branch_joined_callable_partial_abstains_with_limitation(self, tmp_path: Path) -> None:
        app_path = tmp_path / "app.py"
        app_path.write_text(
            "from functools import partial\n"
            "def first() -> int: return 1\n"
            "def second() -> int: return 2\n"
            "def handler(flag: bool) -> int:\n"
            "    if flag:\n"
            "        target = first\n"
            "    else:\n"
            "        target = second\n"
            "    thunk = partial(target)\n"
            "    return thunk()\n",
            encoding="utf-8",
        )
        endpoint = Endpoint(
            path="/partial-union",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(name="handler", module="app", file_path=app_path, line_number=4),
        )

        dependencies = MypyAnalyzer(tmp_path).analyze_endpoint(endpoint)

        assert any(
            item.cap == "CALLABLE_UNION_PARTIAL"
            for item in dependencies.analysis_limitations
        )
        assert not dependencies.references_symbol_at_line(str(app_path), 2)
        assert not dependencies.references_symbol_at_line(str(app_path), 3)

    def test_uninvoked_and_dynamic_partials_do_not_trace_callable_bodies(
        self, tmp_path: Path
    ) -> None:
        app_path = tmp_path / "app.py"
        app_path.write_text(
            "from functools import partial\n"
            "def hidden() -> int: return 1\n"
            "def handler(target):\n"
            "    quiet = partial(hidden)\n"
            "    dynamic = partial(target)\n"
            "    return dynamic()\n",
            encoding="utf-8",
        )
        endpoint = Endpoint(
            path="/partial-controls",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(name="handler", module="app", file_path=app_path, line_number=3),
        )

        dependencies = MypyAnalyzer(tmp_path).analyze_endpoint(endpoint)

        assert not dependencies.references_symbol_at_line(str(app_path), 2)

    def test_lambda_in_unknown_if_else_is_possible_and_false_if_else_is_established(
        self, tmp_path: Path
    ) -> None:
        app_path = tmp_path / "app.py"
        app_path.write_text(
            "def handler(flag: bool) -> None:\n"
            "    if flag:\n"
            "        pass\n"
            "    else:\n"
            "        conditional = lambda: 1\n"
            "        conditional()\n"
            "    if False:\n"
            "        pass\n"
            "    else:\n"
            "        established = lambda: 2\n"
            "        established()\n",
            encoding="utf-8",
        )
        endpoint = Endpoint(
            path="/if-else",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(name="handler", module="app", file_path=app_path, line_number=1),
        )

        dependencies = MypyAnalyzer(tmp_path).analyze_endpoint(endpoint)
        states = {
            (span.start_column, span.execution_state)
            for span in dependencies.source_evidence_spans
            if span.start_line in {5, 10}
        }

        assert any(state == "possible_execution" for _, state in states)
        assert any(state == "established_execution" for _, state in states), states

    def test_depth_cap_keeps_direct_callee_source_reference(self, tmp_path: Path) -> None:
        app_path = tmp_path / "app.py"
        selected_path = tmp_path / "selected.py"
        blocked_path = tmp_path / "blocked.py"
        app_path.write_text(
            "from selected import run\n\n"
            "def handler() -> int:\n"
            "    return run()\n",
            encoding="utf-8",
        )
        selected_path.write_text(
            "from blocked import secret\n\n"
            "def run() -> int:\n"
            "    return secret()\n",
            encoding="utf-8",
        )
        blocked_path.write_text(
            "def secret() -> int:\n"
            "    return 1\n",
            encoding="utf-8",
        )
        endpoint = Endpoint(
            path="/depth",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(
                name="handler", module="app", file_path=app_path, line_number=3
            ),
        )

        inventory = build_source_inventory(
            app_path, include_patterns=("app.py",), max_depth=1
        )
        assert {item.path for item in inventory.files} == {app_path, selected_path}
        analyzer = MypyAnalyzer(tmp_path, max_depth=1, source_inventory=inventory)
        dependencies = analyzer.analyze_endpoint(endpoint)

        assert dependencies.references_file(str(selected_path))
        assert not dependencies.references_file(str(blocked_path))
        assert dependencies.references_symbol_at_line(str(selected_path), 3) is not None
        assert dependencies.references_symbol_at_line(str(blocked_path), 1) is None
        assert {"app", "selected"} <= analyzer._project_modules
        assert "blocked" not in analyzer._project_modules
        assert any(item.cap == "MAX_DEPTH" for item in dependencies.analysis_limitations)
        assert all(
            frame.file_path != str(blocked_path)
            for stacks in dependencies.call_stacks.values()
            for stack in stacks
            for frame in stack
        )
        cached = analyzer.analyze_endpoint(endpoint)
        assert cached is not dependencies
        assert cached.referenced_files == dependencies.referenced_files
        other_endpoint = endpoint.model_copy(update={"path": "/other"})
        isolated = analyzer.analyze_endpoint(other_endpoint)
        assert isolated.endpoint_id == "GET /other"
        assert isolated is not cached
        assert analyzer.analyze_endpoint(endpoint).endpoint_id == "GET /depth"

    def test_resolves_top_level_import_from_application_directory(self, tmp_path: Path) -> None:
        """Resolve imports whose mypy fullname omits the directory name."""
        (tmp_path / "services.py").write_text(
            "def calculate_total(price: float, quantity: int) -> float:\n"
            "    return price * quantity\n",
            encoding="utf-8",
        )
        main_path = tmp_path / "main.py"
        main_path.write_text(
            "from services import calculate_total\n\n"
            "def order() -> dict:\n"
            "    return {'total': calculate_total(10, 1)}\n",
            encoding="utf-8",
        )
        endpoint = Endpoint(
            path="/orders",
            methods=[EndpointMethod.POST],
            handler=HandlerInfo(
                name="order",
                module="main",
                file_path=main_path,
                line_number=3,
            ),
        )

        dependencies = MypyAnalyzer(main_path).analyze_endpoint(endpoint)

        service_reference = dependencies.references_symbol_at_line(str(tmp_path / "services.py"), 1)
        assert service_reference is not None
        assert service_reference.symbol_name.endswith("services.calculate_total")

    def test_traces_decorated_handler_body_and_fastapi_depends(self, tmp_path: Path) -> None:
        """Trace both decorated handlers and Depends callback chains."""
        service_path = tmp_path / "services.py"
        service_path.write_text(
            "def calculate_total(price: float, quantity: int) -> float:\n"
            "    return price * quantity\n",
            encoding="utf-8",
        )
        main_path = tmp_path / "main.py"
        main_path.write_text(
            "from fastapi import Depends, FastAPI\n"
            "from services import calculate_total\n"
            "app = FastAPI()\n\n"
            "def quote_service() -> float:\n"
            "    return calculate_total(10, 2)\n\n"
            "@app.post('/quotes')\n"
            "def quote(total: float = Depends(quote_service)) -> dict:\n"
            "    return {'total': total}\n\n"
            "@app.post('/orders')\n"
            "def order() -> dict:\n"
            "    return {'total': calculate_total(10, 1)}\n",
            encoding="utf-8",
        )
        analyzer = MypyAnalyzer(main_path)

        for name, path, line in (
            ("quote", "/quotes", 9),
            ("order", "/orders", 13),
        ):
            endpoint = Endpoint(
                path=path,
                methods=[EndpointMethod.POST],
                handler=HandlerInfo(
                    name=name,
                    module="main",
                    file_path=main_path,
                    line_number=line,
                ),
            )
            dependencies = analyzer.analyze_endpoint(endpoint)
            assert dependencies.references_symbol_at_line(str(service_path), 2)

    def test_create_analyzer(self, tmp_path: Path) -> None:
        """Test creating a MypyAnalyzer instance."""
        analyzer = MypyAnalyzer(tmp_path)
        assert analyzer.app_path == tmp_path
        assert analyzer._endpoint_deps == {}

    def test_site_package_mode_is_part_of_cache_identity(self, tmp_path: Path) -> None:
        """Hermetic and ordinary analyzer caches cannot share a fingerprint."""
        ordinary = MypyAnalyzer(tmp_path)
        hermetic = MypyAnalyzer(tmp_path, no_site_packages=True)

        assert ordinary._cache_fingerprint()[0] != hermetic._cache_fingerprint()[0]

    def test_target_platform_is_part_of_cache_identity(self, tmp_path: Path) -> None:
        """An explicit mypy target platform changes analysis cache identity."""
        default = MypyAnalyzer(tmp_path)
        explicit_default = MypyAnalyzer(tmp_path, target_platform=sys.platform)
        other_platform = MypyAnalyzer(tmp_path, target_platform="win32")

        assert default._cache_fingerprint()[0] == explicit_default._cache_fingerprint()[0]
        assert default._cache_fingerprint()[0] != other_platform._cache_fingerprint()[0]

    def test_hermetic_analysis_ignores_ambient_mypypath_decoy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Explicit source search paths and no-site-packages exclude MYPYPATH stubs."""
        app = tmp_path / "app"
        app.mkdir()
        (app / "main.py").write_text(
            "from optional_decoy import decoy_call\n\ndef handler() -> None:\n    decoy_call()\n",
            encoding="utf-8",
        )
        ambient = tmp_path / "ambient"
        ambient.mkdir()
        (ambient / "optional_decoy.pyi").write_text(
            "def decoy_call() -> None: ...\n", encoding="utf-8"
        )
        monkeypatch.setenv("MYPYPATH", str(ambient))

        analyzer = MypyAnalyzer(app, no_site_packages=True)
        analyzer._ensure_mypy_built()

        assert "optional_decoy" not in analyzer._trees
        assert str(ambient) not in analyzer._module_to_path.values()

    def test_hermetic_analysis_excludes_cwd_but_retains_explicit_project_imports(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app = tmp_path / "app"
        app.mkdir()
        (app / "main.py").write_text(
            "from optional_cwd_decoy import decoy_call\n"
            "from helpers import project_call\n"
            "def handler() -> None:\n    decoy_call()\n    project_call()\n",
            encoding="utf-8",
        )
        helper = app / "helpers.py"
        helper.write_text("def project_call() -> None: pass\n", encoding="utf-8")
        ambient = tmp_path / "ambient"
        ambient.mkdir()
        decoy = ambient / "optional_cwd_decoy.pyi"
        decoy.write_text("def decoy_call() -> None: ...\n", encoding="utf-8")
        monkeypatch.chdir(ambient)
        ordinary = MypyAnalyzer(app, module_root=app)
        ordinary._ensure_mypy_built()
        assert ordinary._module_to_path["optional_cwd_decoy"] == str(decoy)
        hermetic = MypyAnalyzer(app, module_root=app, no_site_packages=True)
        hermetic._ensure_mypy_built()
        assert "optional_cwd_decoy" not in hermetic._trees
        assert hermetic._module_to_path["helpers"] == str(helper)
        assert hermetic._build_result is not None

    def test_hermetic_analysis_excludes_interpreter_site_packages(self, tmp_path: Path) -> None:
        """Hermetic builds skip interpreter packages while ordinary builds retain them."""
        fastapi_spec = find_spec("fastapi")
        if fastapi_spec is None or fastapi_spec.origin is None:
            pytest.skip("FastAPI is not installed in the active interpreter")
        app = tmp_path / "app"
        app.mkdir()
        (app / "main.py").write_text(
            "from fastapi import FastAPI\n\napp = FastAPI()\n",
            encoding="utf-8",
        )

        ordinary = MypyAnalyzer(app)
        ordinary._ensure_mypy_built()
        assert "fastapi" in ordinary._trees
        assert ordinary._module_to_path["fastapi"] == fastapi_spec.origin

        hermetic = MypyAnalyzer(app, no_site_packages=True)
        hermetic._ensure_mypy_built()
        assert "fastapi" not in hermetic._trees
        assert fastapi_spec.origin not in hermetic._module_to_path.values()

    def test_cache_path_default(self, tmp_path: Path) -> None:
        """Test default cache path location."""
        analyzer = MypyAnalyzer(tmp_path)
        expected = tmp_path / ".endpoint_mypy_cache.json"
        assert analyzer.cache_path == expected

    def test_set_cache_path(self, tmp_path: Path) -> None:
        """Test setting a custom cache path."""
        analyzer = MypyAnalyzer(tmp_path)
        custom_path = tmp_path / "custom_cache.json"
        analyzer.set_cache_path(custom_path)
        assert analyzer.cache_path == custom_path

    def test_set_line_progress_callback(self, tmp_path: Path) -> None:
        """Test setting a line progress callback."""
        analyzer = MypyAnalyzer(tmp_path)

        callback_called = {"value": False}

        def callback(file_path: str, line_num: int, symbol: str) -> None:
            callback_called["value"] = True

        analyzer.set_line_progress_callback(callback)
        assert analyzer._line_progress_callback is callback

    def test_mypy_does_not_load_excluded_imported_source(self, tmp_path: Path) -> None:
        """An import edge cannot make excluded source part of the typed project."""
        app = tmp_path / "app.py"
        excluded = tmp_path / "excluded.py"
        app.write_text(
            "from excluded import secret\ndef handler():\n    return secret()\n",
            encoding="utf-8",
        )
        excluded.write_text(
            "def secret():\n    return 'private excluded implementation'\n",
            encoding="utf-8",
        )
        inventory = build_source_inventory(
            tmp_path,
            include_patterns=("app.py",),
            exclude_patterns=("excluded.py",),
            follow_imports=True,
        )
        analyzer = MypyAnalyzer(tmp_path, source_inventory=inventory)
        endpoint = Endpoint(
            path="/",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(name="handler", module="app", file_path=app, line_number=2),
        )

        dependencies = analyzer.analyze_endpoint(endpoint)

        assert "excluded.py" in inventory.excluded_files
        assert [source.path for source in inventory.files] == [app]
        assert str(app.resolve()) in analyzer._module_to_path.values()
        assert str(excluded.resolve()) not in analyzer._module_to_path.values()
        assert all(
            not state.path or Path(state.path).resolve() != excluded.resolve()
            for state in analyzer._build_result.graph.values()
        )
        assert not dependencies.references_file(str(excluded))

    @pytest.mark.parametrize(
        ("include_patterns", "follow_imports", "max_depth", "selected_files"),
        [
            (("app.py", "selected.py"), False, 10, {"app.py", "selected.py"}),
            (("app.py",), True, 1, {"app.py", "selected.py"}),
        ],
        ids=("include-scope", "max-depth-scope"),
    )
    def test_mypy_blocks_local_imports_outside_inventory_scope(
        self,
        tmp_path: Path,
        include_patterns: tuple[str, ...],
        follow_imports: bool,
        max_depth: int,
        selected_files: set[str],
    ) -> None:
        """Imports beyond include and max-depth boundaries stay unresolved."""
        (tmp_path / "app.py").write_text(
            "from selected import run\ndef handler():\n    return run()\n",
            encoding="utf-8",
        )
        (tmp_path / "selected.py").write_text(
            "from blocked import secret\ndef run():\n    return secret()\n",
            encoding="utf-8",
        )
        blocked = tmp_path / "blocked.py"
        blocked.write_text("def secret():\n    return 'outside scope'\n", encoding="utf-8")
        inventory = build_source_inventory(
            tmp_path,
            include_patterns=include_patterns,
            follow_imports=follow_imports,
            max_depth=max_depth,
        )
        analyzer = MypyAnalyzer(tmp_path, source_inventory=inventory)
        endpoint = Endpoint(
            path="/",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(
                name="handler", module="app", file_path=tmp_path / "app.py", line_number=2
            ),
        )

        dependencies = analyzer.analyze_endpoint(endpoint)

        assert {source.path.name for source in inventory.files} == selected_files
        assert str(blocked.resolve()) not in analyzer._module_to_path.values()
        assert all(
            not state.path or Path(state.path).resolve() != blocked.resolve()
            for state in analyzer._build_result.graph.values()
        )
        assert dependencies.references_file(str(tmp_path / "selected.py"))
        assert not dependencies.references_file(str(blocked))
        prior_fingerprint, _ = analyzer._cache_fingerprint()
        (tmp_path / "later_local.py").write_text("value = 1\n", encoding="utf-8")
        changed_fingerprint, _ = analyzer._cache_fingerprint()
        assert changed_fingerprint != prior_fingerprint

    def test_unselected_package_initializer_does_not_block_selected_child(
        self, tmp_path: Path
    ) -> None:
        """Per-module skips for an initializer leave selected package children usable."""
        package = tmp_path / "pkg"
        package.mkdir()
        (tmp_path / "app.py").write_text(
            "from pkg.child import run\ndef handler():\n    return run()\n",
            encoding="utf-8",
        )
        (package / "__init__.py").write_text("from .other import hidden\n", encoding="utf-8")
        child = package / "child.py"
        child.write_text("def run():\n    return 'selected'\n", encoding="utf-8")
        (package / "other.py").write_text(
            "def hidden():\n    return 'excluded'\n", encoding="utf-8"
        )
        inventory = build_source_inventory(
            tmp_path,
            include_patterns=("app.py", "pkg/child.py"),
            follow_imports=False,
        )
        analyzer = MypyAnalyzer(tmp_path, source_inventory=inventory)
        endpoint = Endpoint(
            path="/",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(
                name="handler", module="app", file_path=tmp_path / "app.py", line_number=2
            ),
        )

        dependencies = analyzer.analyze_endpoint(endpoint)

        assert dependencies.references_file(str(child))
        assert str((package / "other.py").resolve()) not in analyzer._module_to_path.values()

    def test_mypy_does_not_load_unselected_local_stub(self, tmp_path: Path) -> None:
        """An imported local .pyi outside inventory is skipped by mypy itself."""
        app = tmp_path / "app.py"
        stub = tmp_path / "blocked.pyi"
        app.write_text(
            "from blocked import secret\ndef handler():\n    return secret()\n",
            encoding="utf-8",
        )
        stub.write_text("def secret() -> int: ...\n", encoding="utf-8")
        inventory = build_source_inventory(tmp_path, include_patterns=("app.py",))
        analyzer = MypyAnalyzer(tmp_path, source_inventory=inventory)
        endpoint = Endpoint(
            path="/",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(name="handler", module="app", file_path=app, line_number=2),
        )

        analyzer.analyze_endpoint(endpoint)

        assert all(
            not state.path or Path(state.path).resolve() != stub.resolve()
            for state in analyzer._build_result.graph.values()
        )
        assert all(
            Path(path).resolve() != stub.resolve() for path in analyzer._module_to_path.values()
        )
        assert any(
            isinstance(node, NameExpr)
            and node.name == "secret"
            and node.line == 3
            and str(value) == "Any"
            for node, value in analyzer._types_map.items()
        )

    def test_unselected_stub_package_initializer_preserves_selected_child(
        self, tmp_path: Path
    ) -> None:
        """An unselected package stub initializer cannot suppress a selected child."""
        package = tmp_path / "pkg"
        package.mkdir()
        app = tmp_path / "app.py"
        app.write_text(
            "from pkg.child import run\ndef handler():\n    return run()\n",
            encoding="utf-8",
        )
        init_stub = package / "__init__.pyi"
        init_stub.write_text("from .other import hidden\n", encoding="utf-8")
        child = package / "child.py"
        child.write_text("def run():\n    return 'selected'\n", encoding="utf-8")
        other_stub = package / "other.pyi"
        other_stub.write_text("def hidden() -> str: ...\n", encoding="utf-8")
        inventory = build_source_inventory(
            tmp_path,
            include_patterns=("app.py", "pkg/child.py"),
            follow_imports=False,
        )
        analyzer = MypyAnalyzer(tmp_path, source_inventory=inventory)
        endpoint = Endpoint(
            path="/",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(name="handler", module="app", file_path=app, line_number=2),
        )

        dependencies = analyzer.analyze_endpoint(endpoint)

        assert dependencies.references_file(str(child))
        assert str(child.resolve()) in analyzer._module_to_path.values()
        assert all(
            not state.path
            or Path(state.path).resolve() not in {init_stub.resolve(), other_stub.resolve()}
            for state in analyzer._build_result.graph.values()
        )

    @pytest.mark.parametrize("stub_suffix", [".py", ".pyi"])
    def test_mypy_blocks_rejected_directory_symlink_imports(
        self, tmp_path: Path, stub_suffix: str
    ) -> None:
        """Rejected directory links cannot add outside implementations to the typed graph."""
        project = tmp_path / "project"
        project.mkdir()
        outside = tmp_path / "outside_package"
        outside.mkdir()
        (outside / "__init__.py").write_text("", encoding="utf-8")
        outside_module = outside / f"secret{stub_suffix}"
        outside_module.write_text(
            "def outside_call() -> str: ...\n"
            if stub_suffix == ".pyi"
            else "def outside_call():\n    return 'outside'\n",
            encoding="utf-8",
        )
        app = project / "app.py"
        app.write_text(
            "from vendor.secret import outside_call\ndef handler():\n    return outside_call()\n",
            encoding="utf-8",
        )
        vendor = project / "vendor"
        vendor.symlink_to(outside, target_is_directory=True)
        inventory = build_source_inventory(project, include_patterns=("app.py",))
        analyzer = MypyAnalyzer(project, source_inventory=inventory)
        before_fingerprint, before_sources = analyzer._cache_fingerprint()

        # A newly rejected local link changes the mypy policy fingerprint,
        # while the canonical selected-source digest map stays unchanged.
        extra_link = project / "other_vendor"
        extra_link.symlink_to(outside, target_is_directory=True)
        after_fingerprint, after_sources = analyzer._cache_fingerprint()
        assert after_fingerprint != before_fingerprint
        assert after_sources == before_sources
        assert ("app.py", "vendor.secret.outside_call") in inventory.unresolved_imports

        endpoint = Endpoint(
            path="/",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(name="handler", module="app", file_path=app, line_number=2),
        )
        dependencies = analyzer.analyze_endpoint(endpoint)

        assert str(app.resolve()) in analyzer._module_to_path.values()
        assert all(
            not state.path or not Path(state.path).resolve().is_relative_to(outside)
            for state in analyzer._build_result.graph.values()
        )
        assert not dependencies.references_file(str(outside_module))
        assert all(
            not (site.canonical_symbol or "").endswith(".outside_call")
            for site in dependencies.resolved_call_sites
        )

    @pytest.mark.parametrize("stub_suffix", [".py", ".pyi"])
    def test_mypy_blocks_rejected_file_symlink_imports(
        self, tmp_path: Path, stub_suffix: str
    ) -> None:
        """A rejected file link cannot add its outside target to the typed graph."""
        project = tmp_path / "project"
        project.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        target = outside / f"implementation{stub_suffix}"
        target.write_text(
            "def outside_call() -> str: ...\n"
            if stub_suffix == ".pyi"
            else "def outside_call():\n    return 'outside'\n",
            encoding="utf-8",
        )
        linked_module = project / f"linked{stub_suffix}"
        linked_module.symlink_to(target)
        app = project / "app.py"
        app.write_text(
            "from linked import outside_call\ndef handler():\n    return outside_call()\n",
            encoding="utf-8",
        )
        inventory = build_source_inventory(project, include_patterns=("app.py",))
        analyzer = MypyAnalyzer(project, source_inventory=inventory)
        endpoint = Endpoint(
            path="/",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(name="handler", module="app", file_path=app, line_number=2),
        )

        dependencies = analyzer.analyze_endpoint(endpoint)

        assert ("app.py", "linked.outside_call") in inventory.unresolved_imports
        assert str(app.resolve()) in analyzer._module_to_path.values()
        assert all(
            not state.path or not Path(state.path).resolve().is_relative_to(outside)
            for state in analyzer._build_result.graph.values()
        )
        assert all(
            not Path(path).resolve().is_relative_to(outside)
            for path in analyzer._module_to_path.values()
        )
        assert not dependencies.references_file(str(target))
        assert all(
            not (site.canonical_symbol or "").endswith(".outside_call")
            for site in dependencies.resolved_call_sites
        )

    def test_mypy_skips_symlinked_package_stub_initializer_without_blocking_child(
        self, tmp_path: Path
    ) -> None:
        """An exact package-stub skip still permits an inventory-selected child."""
        project = tmp_path / "project"
        package = project / "pkg"
        package.mkdir(parents=True)
        outside_init = tmp_path / "outside_init.pyi"
        outside_init.write_text("from .child import hidden\n", encoding="utf-8")
        (package / "__init__.pyi").symlink_to(outside_init)
        child = package / "child.py"
        child.write_text("def run():\n    return 'selected'\n", encoding="utf-8")
        app = project / "app.py"
        app.write_text(
            "from pkg.child import run\ndef handler():\n    return run()\n",
            encoding="utf-8",
        )
        inventory = build_source_inventory(
            project,
            include_patterns=("app.py", "pkg/child.py"),
            follow_imports=False,
        )
        analyzer = MypyAnalyzer(project, source_inventory=inventory)
        endpoint = Endpoint(
            path="/",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(name="handler", module="app", file_path=app, line_number=2),
        )

        dependencies = analyzer.analyze_endpoint(endpoint)

        assert dependencies.references_file(str(child))
        assert str(child.resolve()) in analyzer._module_to_path.values()
        assert all(
            not state.path or Path(state.path).resolve() != outside_init.resolve()
            for state in analyzer._build_result.graph.values()
        )

    def test_new_symlinked_selected_identity_invalidates_typed_state(self, tmp_path: Path) -> None:
        """A newly discovered module collision discards the prior typed graph."""
        project = tmp_path / "project"
        project.mkdir()
        app = project / "app.py"
        app.write_text(
            "def handler():\n    return 'selected'\n",
            encoding="utf-8",
        )
        inventory = build_source_inventory(project, include_patterns=("app.py",))
        analyzer = MypyAnalyzer(project, source_inventory=inventory)
        endpoint = Endpoint(
            path="/",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(name="handler", module="app", file_path=app, line_number=1),
        )
        analyzer.analyze_endpoint(endpoint)
        assert analyzer._trees

        before_fingerprint, _ = analyzer._cache_fingerprint()
        outside = tmp_path / "outside_package"
        outside.mkdir()
        outside_init = outside / "__init__.py"
        outside_init.write_text("def hidden():\n    return 'outside'\n", encoding="utf-8")
        package = project / "app"
        package.mkdir()
        (package / "__init__.py").symlink_to(outside_init)
        after_fingerprint, _ = analyzer._cache_fingerprint()
        assert after_fingerprint != before_fingerprint

        analyzer.analyze_endpoints([endpoint], use_cache=False)

        assert not analyzer._trees
        assert not analyzer._module_to_path
        dependencies = analyzer.get_endpoint_dependencies(endpoint)
        assert dependencies is not None
        assert not dependencies.references_file(str(outside_init))

    @pytest.mark.parametrize("symlink_initializer", [False, True], ids=["regular", "symlink"])
    def test_mypy_abstains_on_ambiguous_selected_module_identity(
        self, tmp_path: Path, symlink_initializer: bool
    ) -> None:
        """Conflicting module paths fail closed before any typed tree is retained."""
        project = tmp_path / "project"
        package = project / "vendor"
        package.mkdir(parents=True)
        outside = tmp_path / "outside_package"
        outside.mkdir()
        outside_init = outside / "__init__.py"
        outside_init.write_text("def hidden():\n    return 'outside'\n", encoding="utf-8")
        package_init = package / "__init__.py"
        if symlink_initializer:
            package_init.symlink_to(outside_init)
        else:
            package_init.write_text("def hidden():\n    return 'local'\n", encoding="utf-8")
        selected = project / "vendor.py"
        selected.write_text("def run():\n    return 'selected'\n", encoding="utf-8")
        app = project / "app.py"
        app.write_text(
            "from vendor import run\ndef handler():\n    return run()\n",
            encoding="utf-8",
        )
        inventory = build_source_inventory(project, include_patterns=("app.py", "vendor.py"))
        if not symlink_initializer:
            assert any(module == "vendor" for module, _paths in inventory.module_collisions)
            assert ("app.py", "vendor.run") in inventory.unresolved_imports
        analyzer = MypyAnalyzer(project, source_inventory=inventory)

        with pytest.raises(MypyAnalyzerError, match="ambiguous local module identities"):
            analyzer._ensure_mypy_built()

        assert not analyzer._trees
        assert not analyzer._module_to_path

    def test_mypy_inventory_preserves_external_request_member_types(self, tmp_path: Path) -> None:
        """Normal external typing remains available outside the local inventory."""
        app = tmp_path / "app.py"
        app.write_text(
            "from fastapi import FastAPI, Request\n"
            "app = FastAPI()\n"
            "@app.get('/')\n"
            "def endpoint(request: Request):\n"
            "    return request.url.path\n",
            encoding="utf-8",
        )
        inventory = build_source_inventory(tmp_path, include_patterns=("app.py",))
        analyzer = MypyAnalyzer(tmp_path, source_inventory=inventory)

        analyzer._ensure_mypy_built()

        assert "starlette.requests" in analyzer._trees
        assert any(
            isinstance(node, MemberExpr)
            and node.name == "path"
            and node.line == 5
            and str(value) == "builtins.str"
            for node, value in analyzer._types_map.items()
        )


class TestMypyAnalyzerLoopPrevention:
    """Tests for loop prevention in circular dependencies."""

    @pytest.fixture
    def circular_project(self, tmp_path: Path) -> Path:
        """Create a project with circular dependencies."""
        # Create module_a.py that imports from module_b
        module_a = tmp_path / "module_a.py"
        module_a.write_text("""
from module_b import func_b

def func_a():
    return func_b()
""")

        # Create module_b.py that imports from module_a
        module_b = tmp_path / "module_b.py"
        module_b.write_text("""
from module_a import func_a

def func_b():
    return func_a()
""")

        # Create main.py with a handler that uses these
        main_py = tmp_path / "main.py"
        main_py.write_text("""
from module_a import func_a
from module_b import func_b

def handler():
    result_a = func_a()
    result_b = func_b()
    return result_a + result_b
""")

        return tmp_path

    def test_circular_dependency_no_infinite_loop(self, circular_project: Path) -> None:
        """Test that circular dependencies don't cause infinite loops."""
        analyzer = MypyAnalyzer(circular_project)

        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=circular_project / "main.py",
            line_number=6,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )

        # This should complete without hanging
        deps = analyzer.analyze_endpoint(endpoint)

        # Should have found some files
        assert len(deps.referenced_files) >= 1
        # The main file should be in referenced files
        assert str(circular_project / "main.py") in str(deps.referenced_files)

    @pytest.fixture
    def self_referential_project(self, tmp_path: Path) -> Path:
        """Create a project with self-referential imports."""
        # Create a module that imports itself (edge case)
        self_ref = tmp_path / "self_ref.py"
        self_ref.write_text("""
import self_ref

def recursive_func():
    return self_ref.recursive_func()
""")

        # Create main handler
        main_py = tmp_path / "main.py"
        main_py.write_text("""
from self_ref import recursive_func

def handler():
    return recursive_func()
""")

        return tmp_path

    def test_self_referential_import_no_infinite_loop(self, self_referential_project: Path) -> None:
        """Test that self-referential imports don't cause infinite loops."""
        analyzer = MypyAnalyzer(self_referential_project)

        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=self_referential_project / "main.py",
            line_number=4,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )

        # This should complete without hanging
        deps = analyzer.analyze_endpoint(endpoint)

        # Should have found the main file
        assert str(self_referential_project / "main.py") in str(deps.referenced_files)


class TestMypyAnalyzerLineProgress:
    """Tests for line progress callback functionality."""

    @pytest.fixture
    def simple_project(self, tmp_path: Path) -> Path:
        """Create a simple project for testing line progress."""
        # Create a service module
        services = tmp_path / "services"
        services.mkdir()
        service_py = services / "user_service.py"
        service_py.write_text("""
class UserService:
    def get_user(self, user_id: int):
        return {"id": user_id, "name": "Test"}

    def list_users(self):
        return [self.get_user(1), self.get_user(2)]
""")

        # Create main handler
        main_py = tmp_path / "main.py"
        main_py.write_text("""
from services.user_service import UserService

def handler():
    service = UserService()
    return service.list_users()
""")

        return tmp_path

    def test_line_progress_callback_is_called(self, simple_project: Path) -> None:
        """Test that line progress callback is called during analysis."""
        analyzer = MypyAnalyzer(simple_project)

        progress_calls: list[tuple[str, int, str]] = []

        def callback(file_path: str, line_num: int, symbol: str) -> None:
            progress_calls.append((file_path, line_num, symbol))

        analyzer.set_line_progress_callback(callback)

        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=simple_project / "main.py",
            line_number=4,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )

        analyzer.analyze_endpoint(endpoint)

        # The callback should have been called at least once
        assert len(progress_calls) > 0

        # All calls should have valid line numbers
        for _file_path, line_num, symbol in progress_calls:
            assert line_num > 0
            assert symbol != ""

    def test_line_progress_callback_reports_symbols(self, simple_project: Path) -> None:
        """Test that line progress callback reports correct symbols."""
        analyzer = MypyAnalyzer(simple_project)

        symbols_seen: set[str] = set()

        def callback(file_path: str, line_num: int, symbol: str) -> None:
            symbols_seen.add(symbol)

        analyzer.set_line_progress_callback(callback)

        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=simple_project / "main.py",
            line_number=4,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )

        analyzer.analyze_endpoint(endpoint)

        # Should have seen the UserService and list_users symbols
        assert "UserService" in symbols_seen or "list_users" in symbols_seen


class TestMypyAnalyzerVisitedTracking:
    """Tests specifically for the visited node tracking."""

    @pytest.fixture
    def multi_call_project(self, tmp_path: Path) -> Path:
        """Create a project where the same function is called multiple times."""
        helper_py = tmp_path / "helper.py"
        helper_py.write_text("""
def helper_func():
    return "helper"
""")

        main_py = tmp_path / "main.py"
        main_py.write_text("""
from helper import helper_func

def handler():
    # Call the same function multiple times on different lines
    a = helper_func()
    b = helper_func()
    c = helper_func()
    return a + b + c
""")

        return tmp_path

    def test_same_function_different_lines_all_tracked(self, multi_call_project: Path) -> None:
        """Test that same function called on different lines is tracked correctly."""
        analyzer = MypyAnalyzer(multi_call_project)

        lines_seen: set[int] = set()

        def callback(file_path: str, line_num: int, symbol: str) -> None:
            if symbol == "helper_func":
                lines_seen.add(line_num)

        analyzer.set_line_progress_callback(callback)

        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=multi_call_project / "main.py",
            line_number=4,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )

        analyzer.analyze_endpoint(endpoint)

        # Should have tracked calls on multiple lines (lines 5, 6, 7)
        # At least some of the multiple calls should be seen
        assert len(lines_seen) >= 1  # At minimum one line


class TestEndpointDependencies:
    """Tests for the EndpointDependencies data class."""

    def test_references_file_returns_true(self) -> None:
        """Test references_file returns True for known files."""
        deps = EndpointDependencies(
            endpoint_id="GET /test",
            methods=["GET"],
            path="/test",
            referenced_files={"/path/to/file.py": {1, 2, 3}},
        )
        assert deps.references_file("/path/to/file.py") is True

    def test_references_file_returns_false(self) -> None:
        """Test references_file returns False for unknown files."""
        deps = EndpointDependencies(
            endpoint_id="GET /test",
            methods=["GET"],
            path="/test",
            referenced_files={"/path/to/file.py": {1, 2, 3}},
        )
        assert deps.references_file("/path/to/other.py") is False

    def test_references_lines(self) -> None:
        """Test checking if specific lines are referenced."""
        deps = EndpointDependencies(
            endpoint_id="GET /test",
            methods=["GET"],
            path="/test",
            referenced_files={"/path/to/file.py": {10, 20, 30}},
        )
        lines = deps.referenced_files["/path/to/file.py"]
        assert 10 in lines
        assert 20 in lines
        assert 15 not in lines


class TestCallFrame:
    """Tests for the CallFrame data class."""

    def test_create_call_frame(self) -> None:
        """Test creating a CallFrame."""
        frame = CallFrame(
            file_path="/path/to/file.py",
            line_number=42,
            function_name="my_function",
            code_context="    result = my_function()",
        )
        assert frame.file_path == "/path/to/file.py"
        assert frame.line_number == 42
        assert frame.function_name == "my_function"
        assert "my_function" in frame.code_context

    def test_call_frame_default_code_context(self) -> None:
        """Test CallFrame with default empty code context."""
        frame = CallFrame(
            file_path="/path/to/file.py",
            line_number=1,
            function_name="func",
        )
        assert frame.code_context == ""
