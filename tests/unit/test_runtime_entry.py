"""Exact local runtime entry selection tests."""

import sys
from pathlib import Path
from types import ModuleType

import pytest

from fastapi_endpoint_detector.parser.fastapi_extractor import FastAPIExtractor
from fastapi_endpoint_detector.parser.runtime_entry import (
    RuntimeEntryError,
    select_runtime_app,
)


def test_factory_and_bootstrap_entries_run_only_selected_local_symbols(tmp_path: Path) -> None:
    package = tmp_path / "project"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "factory.py").write_text(
        "from fastapi import FastAPI\ndef create_app():\n    return FastAPI()\n",
        encoding="utf-8",
    )
    (package / "bootstrap.py").write_text(
        "def register_routes(app):\n    app.state.selected = True\n",
        encoding="utf-8",
    )

    app = select_runtime_app(
        tmp_path,
        app_path=package / "factory.py",
        app_variable="unused",
        app_entry="project.factory:create_app",
        bootstrap_entry="project.bootstrap:register_routes",
    )

    assert app.state.selected is True


def test_factory_late_relative_import_uses_selected_root_and_restores_collisions(
    tmp_path: Path,
) -> None:
    package = tmp_path / "collision_app"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "helper.py").write_text("TOKEN = 'selected-root'\n", encoding="utf-8")
    (package / "factory.py").write_text(
        "from fastapi import FastAPI\n"
        "def create_app():\n"
        "    from .helper import TOKEN\n"
        "    app = FastAPI()\n"
        "    app.state.token = TOKEN\n"
        "    return app\n",
        encoding="utf-8",
    )

    prefix = "collision_app"
    hostile_package = ModuleType(prefix)
    hostile_package.__file__ = str(tmp_path / "hostile" / "__init__.py")
    hostile_package.__path__ = [str(tmp_path / "hostile")]
    hostile_factory = ModuleType(f"{prefix}.factory")
    hostile_helper = ModuleType(f"{prefix}.helper")
    hostile_helper.TOKEN = "preloaded-hostile-module"
    saved = {
        name: module
        for name, module in tuple(sys.modules.items())
        if name == prefix or name.startswith(prefix + ".")
    }
    saved_path = sys.path.copy()
    saved_meta_path = sys.meta_path.copy()
    sys.modules[prefix] = hostile_package
    sys.modules[f"{prefix}.factory"] = hostile_factory
    sys.modules[f"{prefix}.helper"] = hostile_helper
    try:
        app = select_runtime_app(
            tmp_path,
            app_path=package / "factory.py",
            app_variable="unused",
            app_entry=f"{prefix}.factory:create_app",
        )
        assert app.state.token == "selected-root"
        assert sys.modules[prefix] is hostile_package
        assert sys.modules[f"{prefix}.factory"] is hostile_factory
        assert sys.modules[f"{prefix}.helper"] is hostile_helper
        assert sys.path == saved_path
        assert sys.meta_path == saved_meta_path
    finally:
        for name in tuple(sys.modules):
            if name == prefix or name.startswith(prefix + "."):
                sys.modules.pop(name, None)
        sys.modules.update(saved)


def _write_flat_factory_probe(root: Path) -> tuple[Path, str, str]:
    helper_name = "gh319_flat_helper_probe"
    factory_name = "gh319_flat_factory_probe"
    (root / f"{helper_name}.py").write_text("TOKEN = 'selected-root'\n", encoding="utf-8")
    factory_path = root / f"{factory_name}.py"
    factory_path.write_text(
        "from fastapi import FastAPI\n"
        "def create_app():\n"
        f"    from {helper_name} import TOKEN\n"
        "    app = FastAPI()\n"
        "    app.state.token = TOKEN\n"
        "    return app\n",
        encoding="utf-8",
    )
    return factory_path, factory_name, helper_name


def test_flat_factory_imports_helper_from_selected_source_root(tmp_path: Path) -> None:
    factory_path, factory_name, helper_name = _write_flat_factory_probe(tmp_path)
    previous_helper = sys.modules.pop(helper_name, None)
    try:
        app = select_runtime_app(
            tmp_path,
            app_path=factory_path,
            app_variable="unused",
            app_entry=f"{factory_name}:create_app",
        )

        assert app.state.token == "selected-root"
        assert helper_name not in sys.modules
    finally:
        sys.modules.pop(helper_name, None)
        if previous_helper is not None:
            sys.modules[helper_name] = previous_helper


def test_flat_factory_ignores_and_restores_preloaded_helper_outside_source_root(
    tmp_path: Path,
) -> None:
    factory_path, factory_name, helper_name = _write_flat_factory_probe(tmp_path)
    hostile_helper = ModuleType(helper_name)
    hostile_helper.__file__ = "/tmp/other-source-root/gh319_flat_helper_probe.py"
    hostile_helper.TOKEN = "preloaded-other-root"
    previous_helper = sys.modules.get(helper_name)
    saved_path = sys.path.copy()
    saved_meta_path = sys.meta_path.copy()
    sys.modules[helper_name] = hostile_helper
    try:
        app = select_runtime_app(
            tmp_path,
            app_path=factory_path,
            app_variable="unused",
            app_entry=f"{factory_name}:create_app",
        )

        assert app.state.token == "selected-root"
        assert sys.modules[helper_name] is hostile_helper
        assert sys.path == saved_path
        assert sys.meta_path == saved_meta_path
    finally:
        sys.modules.pop(helper_name, None)
        if previous_helper is not None:
            sys.modules[helper_name] = previous_helper


def test_flat_factory_symlink_alias_ignores_and_restores_preloaded_module(
    tmp_path: Path,
) -> None:
    real_helper = tmp_path / "gh319_alias_helper_real.py"
    real_helper.write_text("TOKEN = 'selected-alias-target'\n", encoding="utf-8")
    alias_name = "gh319_alias_helper_probe"
    (tmp_path / f"{alias_name}.py").symlink_to(real_helper)
    factory_name = "gh319_alias_factory_probe"
    factory_path = tmp_path / f"{factory_name}.py"
    factory_path.write_text(
        "from fastapi import FastAPI\n"
        "def create_app():\n"
        f"    from {alias_name} import TOKEN\n"
        "    app = FastAPI()\n"
        "    app.state.token = TOKEN\n"
        "    return app\n",
        encoding="utf-8",
    )
    hostile_helper = ModuleType(alias_name)
    hostile_helper.__file__ = "/tmp/other-source-root/gh319_alias_helper_probe.py"
    hostile_helper.TOKEN = "preloaded-other-root"
    previous_helper = sys.modules.get(alias_name)
    sys.modules[alias_name] = hostile_helper
    try:
        app = select_runtime_app(
            tmp_path,
            app_path=factory_path,
            app_variable="unused",
            app_entry=f"{factory_name}:create_app",
        )
        assert app.state.token == "selected-alias-target"
        assert sys.modules[alias_name] is hostile_helper
    finally:
        sys.modules.pop(alias_name, None)
        if previous_helper is not None:
            sys.modules[alias_name] = previous_helper


def test_local_implicit_namespace_precedes_outside_regular_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    namespace_name = "gh319_local_namespace"
    local_package = tmp_path / namespace_name
    local_package.mkdir()
    (local_package / "helper.py").write_text(
        "TOKEN = 'selected-namespace-root'\n", encoding="utf-8"
    )
    factory_name = "gh319_namespace_factory_probe"
    factory_path = tmp_path / f"{factory_name}.py"
    factory_path.write_text(
        "from fastapi import FastAPI\n"
        "def create_app():\n"
        f"    from {namespace_name}.helper import TOKEN\n"
        "    app = FastAPI()\n"
        "    app.state.token = TOKEN\n"
        "    return app\n",
        encoding="utf-8",
    )
    external_root = tmp_path / "external"
    external_package = external_root / namespace_name
    external_package.mkdir(parents=True)
    (external_package / "__init__.py").write_text("SOURCE = 'outside-package'\n", encoding="utf-8")
    (external_package / "helper.py").write_text(
        "TOKEN = 'preloaded-other-root'\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(external_root))

    app = select_runtime_app(
        tmp_path,
        app_path=factory_path,
        app_variable="unused",
        app_entry=f"{factory_name}:create_app",
    )

    assert app.state.token == "selected-namespace-root"
    assert namespace_name not in sys.modules


def test_invalid_or_missing_selected_entry_fails_closed(tmp_path: Path) -> None:
    package = tmp_path / "project"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "apps.py").write_text(
        "from fastapi import FastAPI\nfirst = FastAPI()\nsecond = FastAPI()\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeEntryError, match="absent"):
        select_runtime_app(
            tmp_path,
            app_path=package / "apps.py",
            app_variable="first",
            app_entry="project.apps:missing",
        )
    with pytest.raises(RuntimeEntryError, match="exact MODULE:SYMBOL"):
        select_runtime_app(
            tmp_path,
            app_path=package / "apps.py",
            app_variable="first",
            app_entry="project.apps:first:second",
        )


def test_fresh_worker_accepts_selected_factory_and_bootstrap(tmp_path: Path) -> None:
    package = tmp_path / "project"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "factory.py").write_text(
        "from fastapi import FastAPI\ndef create_app():\n    app = FastAPI()\n    return app\n",
        encoding="utf-8",
    )
    (package / "bootstrap.py").write_text(
        "def register_routes(app):\n"
        "    @app.get('/worker-selected')\n"
        "    def handler():\n"
        "        return {'ok': True}\n",
        encoding="utf-8",
    )

    endpoints = FastAPIExtractor(
        tmp_path,
        app_entry="project.factory:create_app",
        bootstrap_entry="project.bootstrap:register_routes",
    ).extract_endpoints()

    assert [endpoint.path for endpoint in endpoints] == ["/worker-selected"]


def test_inferred_package_initializer_supports_bootstrap_without_explicit_app_entry(
    tmp_path: Path,
) -> None:
    package = tmp_path / "inferred_package"
    package.mkdir()
    initializer = package / "__init__.py"
    initializer.write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n",
        encoding="utf-8",
    )
    (package / "bootstrap.py").write_text(
        "def register(app):\n    app.state.bootstrapped = True\n",
        encoding="utf-8",
    )

    app = select_runtime_app(
        tmp_path,
        app_path=initializer,
        app_variable="app",
        bootstrap_entry="inferred_package.bootstrap:register",
    )

    assert app.state.bootstrapped is True


def test_factory_failure_restores_project_import_globals(tmp_path: Path) -> None:
    factory_name = "gh319_failing_factory_probe"
    helper_name = "gh319_failing_helper_probe"
    (tmp_path / f"{helper_name}.py").write_text("VALUE = 1\n", encoding="utf-8")
    factory_path = tmp_path / f"{factory_name}.py"
    factory_path.write_text(
        "import sys\n"
        "from fastapi import FastAPI\n"
        "def create_app():\n"
        f"    import {helper_name}\n"
        "    sys.path.append('/tmp/factory-mutated-path')\n"
        "    sys.meta_path.clear()\n"
        "    raise RuntimeError('selected fixture failure')\n",
        encoding="utf-8",
    )
    saved_path = sys.path.copy()
    saved_meta_path = sys.meta_path.copy()
    try:
        with pytest.raises(RuntimeError, match="selected fixture failure"):
            select_runtime_app(
                tmp_path,
                app_path=factory_path,
                app_variable="unused",
                app_entry=f"{factory_name}:create_app",
            )

        assert sys.path == saved_path
        assert sys.meta_path == saved_meta_path
        assert factory_name not in sys.modules
        assert helper_name not in sys.modules
    finally:
        sys.path[:] = saved_path
        sys.meta_path[:] = saved_meta_path
        sys.modules.pop(factory_name, None)
        sys.modules.pop(helper_name, None)
