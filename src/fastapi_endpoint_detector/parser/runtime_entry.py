"""Exact project-local runtime entry resolution shared by runtime producers."""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import inspect
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from types import ModuleType


class RuntimeEntryError(ValueError):
    """An entry is invalid, ambiguous, or does not produce the selected app."""


_IMPORT_CONTEXT_LOCK = threading.RLock()


def _project_module_inventory(root: Path) -> tuple[set[str], set[str]]:
    """Return importable modules and top-level names sourced under ``root``."""
    resolved_root = root.resolve()
    modules: set[str] = set()
    prefixes: set[str] = set()
    for source_path in root.rglob("*.py"):
        try:
            relative = source_path.relative_to(root)
        except (OSError, ValueError):
            continue
        parts = (
            relative.parts[:-1]
            if relative.name == "__init__.py"
            else relative.with_suffix("").parts
        )
        if not parts or not all(part.isidentifier() for part in parts):
            continue
        # Retain the lexical name even for rejected symlinks so the scoped finder
        # blocks fallback to an outside module with that same import name.
        prefixes.add(parts[0])
        try:
            source_path.resolve().relative_to(resolved_root)
        except (OSError, ValueError):
            # Symlinks outside the selected checkout do not authorize imports.
            continue
        modules.add(".".join(parts))
    for path in root.rglob("*"):
        if not path.is_symlink():
            continue
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if relative.parts and relative.parts[0].isidentifier():
            prefixes.add(relative.parts[0])
    return modules, prefixes


class _ProjectSourceFinder(importlib.abc.MetaPathFinder):
    """Resolve every cached project-local name from this root, including namespaces."""

    def __init__(self, root: Path, modules: set[str], prefixes: set[str]) -> None:
        self.root = root.resolve()
        self.modules = modules
        self.prefixes = prefixes

    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None = None,
        target: ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        del path, target
        parts = fullname.split(".")
        if parts[0] not in self.prefixes:
            return None
        module_path = self.root.joinpath(*parts)
        package_init = module_path / "__init__.py"
        module_file = module_path.with_suffix(".py")
        source_path: Path | None = None
        search_locations: list[str] | None = None
        if package_init.is_file():
            source_path = package_init
            search_locations = [str(module_path)]
        elif module_file.is_file():
            source_path = module_file
        elif module_path.is_dir() and any(name.startswith(fullname + ".") for name in self.modules):
            try:
                module_path.resolve().relative_to(self.root)
            except (OSError, ValueError) as exc:
                raise ModuleNotFoundError(
                    f"Package {fullname!r} resolves outside the configured project source"
                ) from exc
            # Returning a namespace spec here prevents an outside regular package
            # from replacing this local implicit namespace package.
            namespace = importlib.machinery.ModuleSpec(fullname, loader=None, is_package=True)
            namespace.submodule_search_locations = [str(module_path)]
            return namespace
        if source_path is None:
            raise ModuleNotFoundError(
                f"No module named {fullname!r} in the configured project source"
            )
        try:
            source_path.resolve().relative_to(self.root)
        except (OSError, ValueError) as exc:
            raise ModuleNotFoundError(
                f"Module {fullname!r} resolves outside the configured project source"
            ) from exc
        return importlib.util.spec_from_file_location(
            fullname,
            source_path,
            submodule_search_locations=search_locations,
        )


def parse_entry(value: str | None, option: str) -> tuple[str, str] | None:
    if value is None:
        return None
    parts = value.split(":")
    if (
        len(parts) != 2
        or not all(parts)
        or any(not part.isidentifier() for part in [*parts[0].split("."), parts[1]])
    ):
        raise RuntimeEntryError(f"{option} must use exact MODULE:SYMBOL syntax")
    return parts[0], parts[1]


@contextmanager
def _project_import_context(root: Path, module_names: tuple[str, ...]) -> Iterator[None]:
    """Keep selected project packages importable only for the whole invocation."""
    if not root.is_dir():
        raise RuntimeEntryError("runtime app root must be a directory")
    module_inventory, prefixes = _project_module_inventory(root)
    for module_name in module_names:
        if module_name not in module_inventory:
            raise RuntimeEntryError(
                f"selected runtime module {module_name!r} is not present in the project source"
            )
    resolved_root = root.resolve()
    root_text = str(resolved_root)
    with _IMPORT_CONTEXT_LOCK:
        original_path = sys.path.copy()
        original_meta_path = sys.meta_path.copy()
        saved_modules = {
            name: module
            for name, module in tuple(sys.modules.items())
            if any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes)
        }
        for name in saved_modules:
            sys.modules.pop(name, None)
        finder = _ProjectSourceFinder(resolved_root, module_inventory, prefixes)
        sys.meta_path.insert(0, finder)
        sys.path.insert(0, root_text)
        importlib.invalidate_caches()
        try:
            yield
        finally:
            # Entry code can mutate both process-global import structures. Restore the
            # exact pre-entry view even when loading or invocation fails.
            sys.path[:] = original_path
            sys.meta_path[:] = original_meta_path
            for name in tuple(sys.modules):
                if any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes):
                    sys.modules.pop(name, None)
            sys.modules.update(saved_modules)
            importlib.invalidate_caches()


def _load_module(root: Path, module_name: str) -> Any:
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        raise RuntimeEntryError(f"could not load selected module {module_name!r}: {exc}") from exc
    origin = getattr(module, "__file__", None)
    if not isinstance(origin, str):
        raise RuntimeEntryError("selected runtime module has no project-local source file")
    try:
        Path(origin).resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise RuntimeEntryError(
            "selected runtime module is outside the configured project"
        ) from exc
    return module


def select_runtime_app(  # noqa: PLR0912
    root: Path,
    *,
    app_path: Path,
    app_variable: str,
    app_entry: str | None = None,
    bootstrap_entry: str | None = None,
) -> FastAPI:
    """Load only the configured app or exact entry; never guess between apps."""
    selected = parse_entry(app_entry, "--app-entry")
    bootstrap = parse_entry(bootstrap_entry, "--bootstrap-entry")
    if selected is None:
        candidates = sorted(root.rglob("*.py"))
        if app_path.is_file():
            candidates = [app_path]
        matching: list[tuple[Path, str]] = []
        for file_path in candidates:
            try:
                source = file_path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            if f"{app_variable} =" in source or f"{app_variable}=" in source:
                rel = file_path.relative_to(root).with_suffix("")
                parts = rel.parts[:-1] if rel.name == "__init__" else rel.parts
                if not parts:
                    continue
                module_name = ".".join(parts)
                matching.append((file_path, module_name))
        if len(matching) != 1:
            raise RuntimeEntryError("runtime app selection is ambiguous; provide --app-entry")
        selected_module = matching[0][1]
        symbol = app_variable
    else:
        selected_module, symbol = selected
    selected_names = (selected_module, *((bootstrap[0],) if bootstrap is not None else ()))
    with _project_import_context(root, selected_names):
        module = _load_module(root, selected_module)
        if not hasattr(module, symbol):
            raise RuntimeEntryError(f"selected app symbol {selected_module}:{symbol} is absent")
        app = getattr(module, symbol)
        if callable(app) and not isinstance(app, FastAPI):
            if inspect.signature(app).parameters:
                raise RuntimeEntryError("selected app factory must take no arguments")
            app = app()
        if not isinstance(app, FastAPI):
            raise RuntimeEntryError("selected app entry did not produce a FastAPI application")
        if bootstrap is not None:
            bootstrap_module, bootstrap_symbol = bootstrap
            callback = getattr(_load_module(root, bootstrap_module), bootstrap_symbol, None)
            if not callable(callback) or inspect.iscoroutinefunction(callback):
                raise RuntimeEntryError("bootstrap entry must be a synchronous function")
            parameters = inspect.signature(callback).parameters
            if len(parameters) != 1:
                raise RuntimeEntryError("bootstrap entry must accept exactly the selected app")
            callback(app)
        return app
