"""Fail-closed controls for captured callback-provider forwarding source.

These fixtures are parsed as bytes; they do not import or execute provider code.
"""

from __future__ import annotations

import hashlib
from textwrap import dedent
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer import callback_provider_origin as origin

SYMBOL_MODULES = {
    "asyncio.threads.to_thread": "asyncio.threads",
    "anyio.to_thread.run_sync": "anyio.to_thread",
    "starlette.concurrency.run_in_threadpool": "starlette.concurrency",
    "starlette.background.BackgroundTasks.add_task": "starlette.background",
    "fastapi.background.BackgroundTasks.add_task": "fastapi.background",
}

ASYNCIO_RUNTIME = dedent(
    """
    import contextvars
    import functools
    from . import events

    async def to_thread(func, /, *args, **kwargs):
        loop = events.get_running_loop()
        ctx = contextvars.copy_context()
        func_call = functools.partial(ctx.run, func, *args, **kwargs)
        return await loop.run_in_executor(None, func_call)
    """
)
ANYIO_RUNTIME = dedent(
    """
    from warnings import warn
    from ._core._eventloop import get_async_backend

    async def run_sync(
        func,
        *args,
        abandon_on_cancel=False,
        cancellable=None,
        limiter=None,
    ):
        if cancellable is not None:
            abandon_on_cancel = cancellable
            warn(
                "The `cancellable=` keyword argument to "
                "`anyio.to_thread.run_sync` is deprecated since AnyIO 4.1.0; "
                "use `abandon_on_cancel=` instead",
                DeprecationWarning,
                stacklevel=2,
            )
        return await get_async_backend().run_sync_in_worker_thread(
            func, args, abandon_on_cancel=abandon_on_cancel, limiter=limiter
        )
    """
)
CONCURRENCY_RUNTIME = dedent(
    """
    import functools
    import anyio.to_thread

    async def run_in_threadpool(func, *args, **kwargs):
        func = functools.partial(func, *args, **kwargs)
        return await anyio.to_thread.run_sync(func)
    """
)
STARLETTE_BACKGROUND_RUNTIME = dedent(
    """
    from starlette._utils import is_async_callable
    from starlette.concurrency import run_in_threadpool

    class BackgroundTask:
        def __init__(self, func, *args, **kwargs):
            self.func = func
            self.args = args
            self.kwargs = kwargs
            self.is_async = is_async_callable(func)

        async def __call__(self):
            if self.is_async:
                await self.func(*self.args, **self.kwargs)
            else:
                await run_in_threadpool(self.func, *self.args, **self.kwargs)

    class BackgroundTasks(BackgroundTask):
        def __init__(self, tasks=None):
            self.tasks = list(tasks) if tasks else []

        def add_task(self, func, *args, **kwargs):
            task = BackgroundTask(func, *args, **kwargs)
            self.tasks.append(task)

        async def __call__(self):
            for task in self.tasks:
                await task()
    """
)
FASTAPI_BACKGROUND_RUNTIME = dedent(
    """
    from fastapi.telemetry._api import _operation
    from starlette.background import BackgroundTasks as StarletteBackgroundTasks

    class BackgroundTasks(StarletteBackgroundTasks):
        def add_task(self, func, *args, **kwargs):
            return super().add_task(func, *args, **kwargs)

        async def __call__(self):
            for task in self.tasks:
                with _operation(name="background_task", function=task.func):
                    await task()
    """
)

RUNTIMES = {
    "asyncio.threads": ASYNCIO_RUNTIME,
    "anyio.to_thread": ANYIO_RUNTIME,
    "starlette.concurrency": CONCURRENCY_RUNTIME,
    "starlette.background": STARLETTE_BACKGROUND_RUNTIME,
    "fastapi.background": FASTAPI_BACKGROUND_RUNTIME,
}
STUBS = {
    "asyncio.threads": ("async def to_thread(func, /, *args, **kwargs): ...\n"),
    "anyio.to_thread": (
        "async def run_sync(func, *args, abandon_on_cancel=False, "
        "cancellable=None, limiter=None): ...\n"
    ),
    "starlette.concurrency": ("async def run_in_threadpool(func, *args, **kwargs): ...\n"),
    "starlette.background": (
        "class BackgroundTask:\n"
        "    def __init__(self, func, *args, **kwargs): ...\n"
        "    async def __call__(self): ...\n"
        "class BackgroundTasks(BackgroundTask):\n"
        "    def __init__(self, tasks=None): ...\n"
        "    def add_task(self, func, *args, **kwargs): ...\n"
        "    async def __call__(self): ...\n"
    ),
    "fastapi.background": (
        "class BackgroundTasks(StarletteBackgroundTasks):\n"
        "    def add_task(self, func, *args, **kwargs): ...\n"
        "    async def __call__(self): ...\n"
    ),
}
TAGS = {
    "asyncio.threads.to_thread": "asyncio-to-thread",
    "anyio.to_thread.run_sync": "anyio-run-sync",
    "starlette.concurrency.run_in_threadpool": "starlette-threadpool-forward",
    "starlette.background.BackgroundTasks.add_task": "background-task-register",
    "fastapi.background.BackgroundTasks.add_task": "fastapi-background-register",
}


def _snapshot(module: str, runtime_source: str | None = None):
    runtime = (runtime_source or RUNTIMES[module]).encode()
    typed = STUBS[module].encode()
    metadata = b"Name: fixture\nVersion: 1.0\n"
    kind = (
        "analysis-stdlib-environment-only"
        if module == "asyncio.threads"
        else "installed-package-runtime"
    )
    distribution = None if module == "asyncio.threads" else module.split(".", 1)[0]
    return origin.CallbackProviderSnapshot(
        module_name=module,
        typed_path=f"/verified/{module.replace('.', '/')}.pyi",
        typed_sha1=hashlib.sha1(typed).hexdigest(),
        typed_sha256=hashlib.sha256(typed).hexdigest(),
        typed_bytes=typed,
        runtime_path=f"/verified/{module.replace('.', '/')}.py",
        runtime_root="/verified",
        runtime_sha256=hashlib.sha256(runtime).hexdigest(),
        runtime_bytes=runtime,
        package_root="/verified",
        provider_kind=kind,
        distribution_name=distribution,
        distribution_version="1.0" if distribution else None,
        metadata_path="/verified/fixture-1.0.dist-info/METADATA" if distribution else None,
        metadata_sha256=hashlib.sha256(metadata).hexdigest() if distribution else None,
        metadata_bytes=metadata if distribution else None,
    )


def _capture_anyio(
    tmp_path: Path,
    *,
    typed_hash: str | None = None,
    parsed_roots: set[Path] | None = None,
    duplicate_metadata: bool = False,
    authorized_digest: str | None = None,
):
    project_root = tmp_path / "project"
    site_root = tmp_path / "site-packages"
    package_root = site_root / "anyio"
    package_root.mkdir(parents=True)
    source_path = package_root / "to_thread.py"
    stub_path = package_root / "to_thread.pyi"
    source_path.write_bytes(ANYIO_RUNTIME.encode())
    stub_bytes = STUBS["anyio.to_thread"].encode()
    stub_path.write_bytes(stub_bytes)
    metadata_path = site_root / "anyio-4.9.0.dist-info" / "METADATA"
    metadata_path.parent.mkdir()
    metadata_bytes = b"Name: anyio\nVersion: 4.9.0\n"
    metadata_path.write_bytes(metadata_bytes)
    if duplicate_metadata:
        other = site_root / "anyio-4.9.0-copy.dist-info" / "METADATA"
        other.parent.mkdir()
        other.write_bytes(metadata_bytes)
    digest = hashlib.sha256(metadata_bytes).hexdigest()
    roots = {site_root} if parsed_roots is None else parsed_roots
    snapshot = origin.capture_callback_provider(
        "anyio.to_thread",
        stub_path,
        typed_hash or hashlib.sha1(stub_bytes).hexdigest(),
        source_root=project_root,
        module_root=project_root,
        authenticated_metadata_hashes={str(metadata_path): authorized_digest or digest},
        parsed_roots_by_top_level={"anyio": roots},
    )
    return snapshot, source_path, metadata_path, site_root, project_root, stub_bytes


def test_all_five_frozen_shapes_validate_from_bytes_only() -> None:
    for symbol, module in SYMBOL_MODULES.items():
        assert origin.validate_callback_provider(_snapshot(module), symbol) == TAGS[symbol]


@pytest.mark.parametrize(
    ("module", "symbol", "source", "old", "new"),
    [
        (
            "anyio.to_thread",
            "anyio.to_thread.run_sync",
            ANYIO_RUNTIME,
            "func, args, abandon_on_cancel=",
            "callback, args, abandon_on_cancel=",
        ),
        (
            "anyio.to_thread",
            "anyio.to_thread.run_sync",
            ANYIO_RUNTIME,
            "cancellable=None",
            "cancellable=True",
        ),
        (
            "anyio.to_thread",
            "anyio.to_thread.run_sync",
            ANYIO_RUNTIME,
            "limiter=None",
            "limiter=object()",
        ),
        (
            "anyio.to_thread",
            "anyio.to_thread.run_sync",
            ANYIO_RUNTIME,
            "return await get_async_backend()",
            "return get_async_backend()",
        ),
        (
            "anyio.to_thread",
            "anyio.to_thread.run_sync",
            ANYIO_RUNTIME,
            "if cancellable is not None:",
            "if False:",
        ),
        (
            "starlette.concurrency",
            "starlette.concurrency.run_in_threadpool",
            CONCURRENCY_RUNTIME,
            "func, *args, **kwargs",
            "func, *args",
        ),
    ],
)
def test_name_default_and_forwarding_mutations_revoke_shape(
    module: str, symbol: str, source: str, old: str, new: str
) -> None:
    mutated = source.replace(old, new, 1)
    assert mutated != source
    assert origin.validate_callback_provider(_snapshot(module, mutated), symbol) is None


@pytest.mark.parametrize(
    "mutation",
    [
        lambda text: text.replace(
            "return super().add_task(func, *args, **kwargs)",
            "return super().add_task(func, *args)",
        ),
        lambda text: text.replace(
            "class BackgroundTasks(StarletteBackgroundTasks):",
            "class BackgroundTasks(object):",
        ),
        lambda text: text.replace(
            "from starlette.background import BackgroundTasks as StarletteBackgroundTasks",
            "from starlette.background import BackgroundTasks",
        ),
        lambda text: text.replace(
            "return super().add_task(func, *args, **kwargs)",
            "return super().add_task(func, *args, **kwargs)\n            audit(func)",
        ),
        lambda text: text + "\nBackgroundTasks = UntrustedTasks\n",
        lambda text: text.replace(
            "    def add_task(self, func, *args, **kwargs):",
            "    @classmethod\n    def add_task(cls, func, *args, **kwargs):",
        ),
        lambda text: text.replace(
            "    async def __call__(self):",
            "    register = add_task\n\n    async def __call__(self):",
        ),
    ],
)
def test_fastapi_alias_classmethod_base_and_global_changes_revoke_shape(mutation) -> None:
    mutated = mutation(FASTAPI_BACKGROUND_RUNTIME)
    assert mutated != FASTAPI_BACKGROUND_RUNTIME
    symbol = "fastapi.background.BackgroundTasks.add_task"
    assert (
        origin.validate_callback_provider(_snapshot("fastapi.background", mutated), symbol) is None
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda text: text.replace("await task()", "task()"),
        lambda text: text.replace("function=task.func", "function=task"),
        lambda text: text.replace(
            'with _operation(name="background_task", function=task.func):',
            "with _operation(name='other', function=task.func):",
        ),
        lambda text: text.replace(
            "from fastapi.telemetry._api import _operation",
            "from fastapi.telemetry._api import _operation as operation",
        ),
        lambda text: text.replace(
            "await task()",
            "await task()\n                    audit(task)",
        ),
    ],
)
def test_fastapi_telemetry_drop_or_mutation_revokes_shape(mutation) -> None:
    mutated = mutation(FASTAPI_BACKGROUND_RUNTIME)
    assert mutated != FASTAPI_BACKGROUND_RUNTIME
    symbol = "fastapi.background.BackgroundTasks.add_task"
    assert (
        origin.validate_callback_provider(_snapshot("fastapi.background", mutated), symbol) is None
    )


def test_provider_kind_requires_every_valid_forwarding_source(monkeypatch) -> None:
    providers = {module: _snapshot(module) for module in RUNTIMES}
    monkeypatch.setattr(origin, "callback_provider_snapshot_current", lambda _item: True)
    symbol = "fastapi.background.BackgroundTasks.add_task"
    assert origin.callback_provider_kind(symbol, providers) == "external-package-runtime"
    del providers["starlette.concurrency"]
    assert origin.callback_provider_kind(symbol, providers) is None


def test_capture_accepts_authenticated_same_root_runtime_and_stub(tmp_path: Path) -> None:
    snapshot, _runtime, _metadata, _site, _project, _stub = _capture_anyio(tmp_path)
    assert snapshot is not None
    assert (
        origin.validate_callback_provider(snapshot, "anyio.to_thread.run_sync") == "anyio-run-sync"
    )
    assert origin.callback_provider_snapshot_current(snapshot)


def test_capture_rejects_wrong_graph_hash_and_project_shadow(tmp_path: Path) -> None:
    snapshot, *_ = _capture_anyio(tmp_path / "hash", typed_hash="0" * 40)
    assert snapshot is None

    root = tmp_path / "shadow"
    project = root / "project"
    site = root / "site-packages"
    shadowed, *_ = _capture_anyio(root, parsed_roots={project, site})
    assert shadowed is None


def test_capture_rejects_duplicate_metadata_even_at_same_version(tmp_path: Path) -> None:
    snapshot, *_ = _capture_anyio(tmp_path, duplicate_metadata=True)
    assert snapshot is None


def test_capture_rejects_symlinked_runtime(tmp_path: Path) -> None:
    snapshot, runtime_path, *_ = _capture_anyio(tmp_path / "link")
    assert snapshot is not None
    outside = tmp_path / "outside.py"
    outside.write_bytes(ANYIO_RUNTIME.encode())
    runtime_path.unlink()
    runtime_path.symlink_to(outside)
    assert not origin.callback_provider_snapshot_current(snapshot)


def test_capture_rejects_unauthenticated_metadata(tmp_path: Path) -> None:
    snapshot, *_ = _capture_anyio(tmp_path, authorized_digest="0" * 64)
    assert snapshot is None


def test_runtime_and_metadata_drift_change_fingerprint_and_stale_snapshot(tmp_path: Path) -> None:
    snapshot, runtime, metadata, _site, _project, _stub = _capture_anyio(tmp_path)
    assert snapshot is not None
    key = "callback-provider:anyio.to_thread"
    before = origin.callback_provider_fingerprint_inputs({"anyio.to_thread": snapshot})
    runtime.write_bytes(ANYIO_RUNTIME.replace("func, args,", "func, (),", 1).encode())
    after_runtime = origin.callback_provider_fingerprint_inputs({"anyio.to_thread": snapshot})
    assert before[key] != after_runtime[key]
    assert not origin.callback_provider_snapshot_current(snapshot)

    runtime.write_bytes(ANYIO_RUNTIME.encode())
    restored = origin.callback_provider_fingerprint_inputs({"anyio.to_thread": snapshot})
    assert restored[key] == before[key]
    assert origin.callback_provider_snapshot_current(snapshot)
    metadata.write_bytes(metadata.read_bytes() + b"# changed\n")
    after_metadata = origin.callback_provider_fingerprint_inputs({"anyio.to_thread": snapshot})
    assert restored[key] != after_metadata[key]
    assert not origin.callback_provider_snapshot_current(snapshot)


@pytest.mark.parametrize("module", ["starlette.background", "fastapi.background"])
def test_sibling_dispatch_methods_must_match_the_complete_class(module: str) -> None:
    runtime = RUNTIMES[module].replace(
        "    def add_task(self, func, *args, **kwargs):",
        "    def __getattribute__(self, name):\n        return foreign\n\n"
        "    def add_task(self, func, *args, **kwargs):",
        1,
    )
    assert runtime != RUNTIMES[module]
    symbol = f"{module}.BackgroundTasks.add_task"
    assert origin.validate_callback_provider(_snapshot(module, runtime), symbol) is None


@pytest.mark.parametrize("module", tuple(RUNTIMES))
@pytest.mark.parametrize(
    "suffix",
    [
        "\nimport attacker_side_effect\n",
        "\nfrom attacker_side_effect import control as unrelated\n",
        "\n__builtins__ = replacement\n",
    ],
)
def test_unexpected_globals_and_builtin_rebinding_revoke_source_shape(
    module: str, suffix: str
) -> None:
    symbol = next(symbol for symbol, owner in SYMBOL_MODULES.items() if owner == module)
    runtime = RUNTIMES[module] + suffix
    assert origin.validate_callback_provider(_snapshot(module, runtime), symbol) is None


@pytest.mark.parametrize(
    "dependency",
    ["starlette.background", "starlette.concurrency", "anyio.to_thread"],
)
def test_transitive_forwarding_source_and_currentness_are_required(
    dependency: str, monkeypatch
) -> None:
    providers = {module: _snapshot(module) for module in RUNTIMES}
    symbol = "fastapi.background.BackgroundTasks.add_task"
    stale = providers[dependency]
    monkeypatch.setattr(
        origin, "callback_provider_snapshot_current", lambda item: item is not stale
    )
    assert origin.callback_provider_kind(symbol, providers) is None

    monkeypatch.setattr(origin, "callback_provider_snapshot_current", lambda _item: True)
    providers[dependency] = _snapshot(
        dependency, RUNTIMES[dependency] + "\nimport attacker_side_effect\n"
    )
    assert origin.callback_provider_kind(symbol, providers) is None


def test_unknown_summary_symbol_has_no_forwarding_chain(monkeypatch) -> None:
    providers = {module: _snapshot(module) for module in RUNTIMES}
    monkeypatch.setattr(origin, "callback_provider_snapshot_current", lambda _item: True)
    symbol = "foreign.background.BackgroundTasks.add_task"
    assert origin.callback_provider_symbols(symbol) == ()
    assert origin.callback_provider_kind(symbol, providers) is None
