"""Exact project-local runtime entry resolution shared by runtime producers."""

from __future__ import annotations

import importlib
import inspect
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI

if TYPE_CHECKING:
    from collections.abc import Iterator


class RuntimeEntryError(ValueError):
    """An entry is invalid, ambiguous, or does not produce the selected app."""


_IMPORT_CONTEXT_LOCK = threading.RLock()


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
    prefixes = {name.split(".", maxsplit=1)[0] for name in module_names}
    resolved_root = root.resolve()
    root_text = str(resolved_root)
    with _IMPORT_CONTEXT_LOCK:
        original_path = sys.path.copy()
        saved_modules = {
            name: module
            for name, module in tuple(sys.modules.items())
            if any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes)
        }
        for name in saved_modules:
            sys.modules.pop(name, None)
        sys.path.insert(0, root_text)
        importlib.invalidate_caches()
        try:
            yield
        finally:
            # Entry code can mutate both process-global import structures. Restore the
            # exact pre-entry view even when loading or invocation fails.
            sys.path[:] = original_path
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
                module_name = ".".join(rel.parts)
                if module_name == "__init__":
                    continue
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
