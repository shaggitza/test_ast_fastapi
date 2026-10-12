"""Source-coherent, bounded origins for the private callback wrapper summaries.

These checks describe captured forwarding source at LOW confidence. They do not
authenticate an upstream release, a target interpreter, or runtime execution.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import stat
import sysconfig
from copy import deepcopy
from dataclasses import dataclass, field
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from packaging.utils import canonicalize_name

if TYPE_CHECKING:
    from collections.abc import Mapping

MAX_BYTES = 262_144
MAX_AST_NODES = 20_000
MAX_METADATA_ENTRIES = 4096
DISTRIBUTIONS = {
    "anyio.to_thread": "anyio",
    "starlette.concurrency": "starlette",
    "starlette.background": "starlette",
    "fastapi.background": "fastapi",
}
SYMBOL_MODULES = {
    "asyncio.threads.to_thread": "asyncio.threads",
    "anyio.to_thread.run_sync": "anyio.to_thread",
    "starlette.concurrency.run_in_threadpool": "starlette.concurrency",
    "starlette.background.BackgroundTasks.add_task": "starlette.background",
    "fastapi.background.BackgroundTasks.add_task": "fastapi.background",
}


@dataclass(frozen=True)
class CallbackProviderSnapshot:
    module_name: str
    typed_path: str
    typed_sha1: str
    typed_sha256: str
    typed_bytes: bytes = field(repr=False)
    runtime_path: str
    runtime_root: str
    runtime_sha256: str
    runtime_bytes: bytes = field(repr=False)
    package_root: str
    provider_kind: Literal["installed-package-runtime", "analysis-stdlib-environment-only"]
    distribution_name: str | None = None
    distribution_version: str | None = None
    metadata_path: str | None = None
    metadata_sha256: str | None = None
    metadata_bytes: bytes | None = field(default=None, repr=False)


def _absolute(path: Path) -> Path:
    if ".." in path.parts:
        raise ValueError("parent components cannot authenticate a provider path")
    return path.absolute()


def _directory(path: Path) -> int:
    if os.open not in os.supports_dir_fd or os.listdir not in os.supports_fd:
        raise OSError("descriptor-relative provider reads are unavailable")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise OSError("no-follow provider reads are unavailable")
    absolute = _absolute(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(absolute.anchor, flags)
    try:
        for component in absolute.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular(path: Path, root: Path) -> bytes | None:
    try:
        relative = _absolute(path).relative_to(_absolute(root))
        if not relative.parts:
            return None
        directory = _directory(root)
        try:
            for component in relative.parts[:-1]:
                child = os.open(
                    component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
                )
                os.close(directory)
                directory = child
            descriptor = os.open(
                relative.parts[-1],
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                dir_fd=directory,
            )
            try:
                before = os.fstat(descriptor)
                if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= MAX_BYTES:
                    return None
                chunks: list[bytes] = []
                remaining = MAX_BYTES + 1
                while remaining:
                    chunk = os.read(descriptor, min(65_536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                content = b"".join(chunks)
                after = os.fstat(descriptor)
                fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                if (
                    len(content) > MAX_BYTES
                    or len(content) != before.st_size
                    or any(getattr(before, name) != getattr(after, name) for name in fields)
                ):
                    return None
                return content
            finally:
                os.close(descriptor)
        finally:
            os.close(directory)
    except (OSError, ValueError):
        return None


def _metadata(root: Path, distribution: str) -> list[tuple[str, str, bytes, str]] | None:
    """Enumerate all matching names before authentication, including duplicates."""
    try:
        descriptor = _directory(root)
        try:
            names = sorted(os.listdir(descriptor))  # noqa: PTH208 - descriptor boundary
            if len(names) > MAX_METADATA_ENTRIES:
                return None
            result: list[tuple[str, str, bytes, str]] = []
            for name in names:
                if not name.endswith(".dist-info"):
                    continue
                path = root / name / "METADATA"
                raw = _read_regular(path, root)
                if raw is None:
                    return None
                message = BytesParser(policy=compat32).parsebytes(raw)
                labels = message.get_all("Name", [])
                versions = message.get_all("Version", [])
                if len(labels) != 1 or len(versions) != 1 or message.defects:
                    return None
                version = str(versions[0]).strip()
                if not version:
                    return None
                if canonicalize_name(str(labels[0]).strip()) == distribution:
                    result.append(
                        (str(_absolute(path)), hashlib.sha256(raw).hexdigest(), raw, version)
                    )
            return (
                result if sorted(os.listdir(descriptor)) == names else None  # noqa: PTH208
            )
        finally:
            os.close(descriptor)
    except (OSError, ValueError):
        return None


def capture_callback_provider(  # noqa: PLR0911, PLR0912 - explicit rejection gates
    module_name: str,
    typed_path: Path,
    typed_source_hash: str,
    *,
    source_root: Path,
    module_root: Path,
    authenticated_metadata_hashes: Mapping[str, str],
    parsed_roots_by_top_level: Mapping[str, set[Path]],
) -> CallbackProviderSnapshot | None:
    """Capture actual graph bytes and a same-installation runtime implementation."""
    if module_name not in DISTRIBUTIONS and module_name != "asyncio.threads":
        return None
    try:
        typed_path = _absolute(typed_path)
        if any(typed_path.is_relative_to(_absolute(root)) for root in (source_root, module_root)):
            return None
        if module_name == "asyncio.threads":
            from mypy.build import default_data_dir  # noqa: PLC0415 - optional analyzer dependency

            root = _absolute(Path(default_data_dir()) / "typeshed")
            runtime_root = _absolute(Path(sysconfig.get_path("stdlib")))
            if typed_path != root / "stdlib/asyncio/threads.pyi":
                return None
            runtime_path = runtime_root / "asyncio/threads.py"
            distribution = None
            metadata_row = None
            kind: Literal["installed-package-runtime", "analysis-stdlib-environment-only"] = (
                "analysis-stdlib-environment-only"
            )
        else:
            parts = module_name.split(".")
            relative_candidates = (
                Path(*parts).with_suffix(".py"),
                Path(*parts).with_suffix(".pyi"),
                Path(*parts) / "__init__.py",
                Path(*parts) / "__init__.pyi",
            )
            location: tuple[Path, Path] | None = None
            for relative in relative_candidates:
                candidate_root = typed_path.parents[len(relative.parts) - 1]
                if candidate_root / relative == typed_path:
                    location = candidate_root, relative
                    break
            if location is None:
                return None
            root, relative = location
            parsed_roots = {
                _absolute(candidate) for candidate in parsed_roots_by_top_level.get(parts[0], set())
            }
            if parsed_roots != {root}:
                return None
            runtime_root = root
            runtime_path = root / relative.with_suffix(".py")
            distribution = DISTRIBUTIONS[module_name]
            rows = _metadata(root, distribution)
            if rows is None or len(rows) != 1:
                return None
            metadata_row = rows[0]
            if authenticated_metadata_hashes.get(metadata_row[0]) != metadata_row[1]:
                return None
            kind = "installed-package-runtime"
        typed = _read_regular(typed_path, root)
        runtime = typed if runtime_path == typed_path else _read_regular(runtime_path, runtime_root)
        if typed is None or runtime is None or hashlib.sha1(typed).hexdigest() != typed_source_hash:
            return None
        return CallbackProviderSnapshot(
            module_name,
            str(typed_path),
            typed_source_hash,
            hashlib.sha256(typed).hexdigest(),
            typed,
            str(runtime_path),
            str(runtime_root),
            hashlib.sha256(runtime).hexdigest(),
            runtime,
            str(root),
            kind,
            distribution,
            metadata_row[3] if metadata_row else None,
            metadata_row[0] if metadata_row else None,
            metadata_row[1] if metadata_row else None,
            metadata_row[2] if metadata_row else None,
        )
    except (ImportError, OSError, ValueError, IndexError, TypeError):
        return None


def callback_provider_snapshot_current(snapshot: CallbackProviderSnapshot) -> bool:
    typed = _read_regular(Path(snapshot.typed_path), Path(snapshot.package_root))
    runtime = _read_regular(Path(snapshot.runtime_path), Path(snapshot.runtime_root))
    if (
        typed is None
        or runtime is None
        or hashlib.sha1(typed).hexdigest() != snapshot.typed_sha1
        or hashlib.sha256(typed).hexdigest() != snapshot.typed_sha256
        or hashlib.sha256(runtime).hexdigest() != snapshot.runtime_sha256
    ):
        return False
    if snapshot.distribution_name is None:
        return snapshot.provider_kind == "analysis-stdlib-environment-only"
    rows = _metadata(Path(snapshot.package_root), snapshot.distribution_name)
    return rows == [
        (
            snapshot.metadata_path,
            snapshot.metadata_sha256,
            snapshot.metadata_bytes,
            snapshot.distribution_version,
        )
    ]


def callback_provider_fingerprint_inputs(
    providers: Mapping[str, CallbackProviderSnapshot],
) -> dict[str, str]:
    result: dict[str, str] = {}
    for module, snapshot in sorted(providers.items()):
        inputs: dict[str, object] = {
            "captured": (
                snapshot.module_name,
                snapshot.typed_path,
                snapshot.typed_sha1,
                snapshot.typed_sha256,
                snapshot.runtime_path,
                snapshot.runtime_sha256,
                snapshot.runtime_root,
                snapshot.package_root,
                snapshot.provider_kind,
                snapshot.distribution_name,
                snapshot.distribution_version,
                snapshot.metadata_path,
                snapshot.metadata_sha256,
            )
        }
        for label, path, root in (
            ("typed", snapshot.typed_path, snapshot.package_root),
            ("runtime", snapshot.runtime_path, snapshot.runtime_root),
        ):
            content = _read_regular(Path(path), Path(root))
            inputs[label] = hashlib.sha256(content).hexdigest() if content is not None else None
        if snapshot.distribution_name is not None:
            rows = _metadata(Path(snapshot.package_root), snapshot.distribution_name)
            inputs["metadata"] = (
                [(path, digest, version) for path, digest, _raw, version in rows]
                if rows is not None
                else None
            )
        result["callback-provider:" + module] = hashlib.sha256(
            json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    return result


ASYNCIO_TEMPLATE = """async def to_thread(func, /, *args, **kwargs):
    loop = events.get_running_loop()
    ctx = contextvars.copy_context()
    func_call = functools.partial(ctx.run, func, *args, **kwargs)
    return await loop.run_in_executor(None, func_call)
"""
ANYIO_TEMPLATE = """async def run_sync(
    func, *args, abandon_on_cancel=False, cancellable=None, limiter=None
):
    if cancellable is not None:
        abandon_on_cancel = cancellable
        warn(
            "The `cancellable=` keyword argument to `anyio.to_thread.run_sync` is "
            "deprecated since AnyIO 4.1.0; use `abandon_on_cancel=` instead",
            DeprecationWarning,
            stacklevel=2,
        )
    return await get_async_backend().run_sync_in_worker_thread(
        func, args, abandon_on_cancel=abandon_on_cancel, limiter=limiter
    )
"""
THREADPOOL_TEMPLATE = """async def run_in_threadpool(func, *args, **kwargs):
    func = functools.partial(func, *args, **kwargs)
    return await anyio.to_thread.run_sync(func)
"""
BACKGROUND_TEMPLATE = """class BackgroundTask:
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
FASTAPI_TEMPLATE = """class BackgroundTasks(StarletteBackgroundTasks):
    def add_task(self, func, *args, **kwargs):
        return super().add_task(func, *args, **kwargs)
"""
FASTAPI_TELEMETRY = """    async def __call__(self):
        for task in self.tasks:
            with _operation(name="background_task", function=task.func):
                await task()
"""


def _parsed(source: bytes) -> ast.Module | None:
    if len(source) > MAX_BYTES:
        return None
    try:
        tree = ast.parse(source)
        for index, _node in enumerate(ast.walk(tree)):
            if index >= MAX_AST_NODES:
                return None
        return tree
    except (
        SyntaxError,
        ValueError,
        TypeError,
        UnicodeError,
        LookupError,
        RecursionError,
        MemoryError,
    ):
        return None


def _normalized(node: ast.AST) -> str:
    try:
        candidate = deepcopy(node)
        for child in ast.walk(candidate):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                child.returns = None
                child.type_comment = None
            if isinstance(child, ast.arg):
                child.annotation = None
                child.type_comment = None
            if (
                isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                and child.body
                and isinstance(child.body[0], ast.Expr)
            ):
                value = child.body[0].value
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    child.body.pop(0)
        return ast.dump(candidate, include_attributes=False)

    except (RecursionError, MemoryError):
        return "<provider normalization unavailable>"


def _matches(tree: ast.Module, template: str) -> bool:
    for expected in ast.parse(template).body:
        name = getattr(expected, "name", "")
        found = [node for node in tree.body if getattr(node, "name", "") == name]
        if len(found) != 1 or _normalized(found[0]) != _normalized(expected):
            return False
    return True


def _from_bindings(module: str, names: tuple[str, ...]) -> dict[str, set[tuple[str, ...]]]:
    return {name: {("from", module, name, "")} for name in names}


_OPTIONAL_GLOBALS: dict[str, dict[str, set[tuple[str, ...]]]] = {
    "asyncio.threads": {"__all__": {("assignment", "__all__")}},
    "anyio.to_thread": {
        **_from_bindings("collections.abc", ("Callable",)),
        **_from_bindings("typing", ("TYPE_CHECKING", "TypeVar")),
        **_from_bindings("._core._synchronization", ("CapacityLimiter",)),
        "sys": {("import", "sys", "")},
        "TypeVarTuple": {
            ("from", source, "TypeVarTuple", "") for source in ("typing", "typing_extensions")
        },
        "Unpack": {("from", source, "Unpack", "") for source in ("typing", "typing_extensions")},
        "__all__": {("assignment", "__all__")},
        "T_Retval": {("assignment", "T_Retval")},
        "PosArgsT": {("assignment", "PosArgsT")},
        "current_default_thread_limiter": {("definition", "current_default_thread_limiter")},
    },
    "starlette.concurrency": {
        **_from_bindings(
            "collections.abc", ("AsyncIterator", "Callable", "Coroutine", "Iterable", "Iterator")
        ),
        **_from_bindings("typing", ("ParamSpec", "TypeVar")),
        **_from_bindings("starlette.exceptions", ("StarletteDeprecationWarning",)),
        "warnings": {("import", "warnings", "")},
        "P": {("assignment", "P")},
        "T": {("assignment", "T")},
        "run_until_first_complete": {("definition", "run_until_first_complete")},
        "_StopIteration": {("definition", "_StopIteration")},
        "_next": {("definition", "_next")},
        "iterate_in_threadpool": {("definition", "iterate_in_threadpool")},
    },
    "starlette.background": {
        **_from_bindings("collections.abc", ("Callable", "Sequence")),
        **_from_bindings("typing", ("Any", "ParamSpec")),
        "P": {("assignment", "P")},
    },
    "fastapi.background": {
        **_from_bindings("typing", ("Any", "Annotated")),
        **_from_bindings("collections.abc", ("Callable",)),
        **_from_bindings("annotated_doc", ("Doc",)),
        **_from_bindings("typing_extensions", ("ParamSpec",)),
        "_operation": {("from", "fastapi.telemetry._api", "_operation", "")},
        "P": {("assignment", "P")},
    },
}


def _globals_verified(
    tree: ast.Module, expected: Mapping[str, tuple[str, ...]], module: str
) -> bool:
    """Require unique import/definition bindings and no executable rebinding."""
    bindings: dict[str, list[tuple[str, ...]]] = {}
    conditional_globals: dict[str, tuple[str, ...]] = {}

    def bind(name: str, identity: tuple[str, ...]) -> None:
        bindings.setdefault(name, []).append(identity)

    def visit(nodes: list[ast.stmt]) -> bool:  # noqa: PLR0911, PLR0912 - bounded statement policy
        for node in nodes:
            if isinstance(node, ast.Import):
                for item in node.names:
                    bind(
                        item.asname or item.name.partition(".")[0],
                        ("import", item.name, item.asname or ""),
                    )
            elif isinstance(node, ast.ImportFrom):
                for item in node.names:
                    if item.name == "*":
                        return False
                    bind(
                        item.asname or item.name,
                        (
                            "from",
                            "." * node.level + (node.module or ""),
                            item.name,
                            item.asname or "",
                        ),
                    )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.decorator_list:
                    return False
                bind(node.name, ("definition", node.name))
                if isinstance(node, ast.ClassDef):
                    if node.keywords or any(not isinstance(base, ast.Name) for base in node.bases):
                        return False
                    # Class executable assignments can replace forwarding descriptors.
                    if any(
                        not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Pass))
                        and not (
                            isinstance(child, ast.Expr)
                            and isinstance(child.value, ast.Constant)
                            and isinstance(child.value.value, str)
                        )
                        for child in node.body
                    ):
                        return False
            elif isinstance(node, ast.If):
                # Only the two observed typing compatibility predicates are passive.
                if isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING":
                    conditional_globals["TYPE_CHECKING"] = ("from", "typing", "TYPE_CHECKING", "")
                elif ast.dump(node.test, include_attributes=False) == ast.dump(
                    ast.parse("sys.version_info >= (3, 11)", mode="eval").body,
                    include_attributes=False,
                ):
                    conditional_globals["sys"] = ("import", "sys", "")
                else:
                    return False
                if not all(
                    isinstance(child, (ast.Import, ast.ImportFrom))
                    for child in node.body + node.orelse
                ):
                    return False
                if not visit(node.body + node.orelse):
                    return False
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(not isinstance(target, ast.Name) for target in targets):
                    return False
                for target in targets:
                    assert isinstance(target, ast.Name)
                    bind(target.id, ("assignment", target.id))
                value = node.value
                if isinstance(value, ast.Call):
                    if (
                        not isinstance(value.func, ast.Name)
                        or value.func.id not in {"TypeVar", "ParamSpec", "TypeVarTuple"}
                        or any(not isinstance(argument, ast.Constant) for argument in value.args)
                        or any(
                            not isinstance(keyword.value, ast.Constant)
                            for keyword in value.keywords
                        )
                    ):
                        return False
                else:
                    try:
                        ast.literal_eval(value) if value is not None else None
                    except (ValueError, TypeError, RecursionError):
                        return False
            elif isinstance(node, ast.Expr):
                if not isinstance(node.value, ast.Constant) or not isinstance(
                    node.value.value, str
                ):
                    return False
            else:
                return False
        return True

    if not visit(tree.body):
        return False
    expected = {**expected, **conditional_globals, "__builtins__": ("builtin",)}
    optional: dict[str, set[tuple[str, ...]]] = {
        "annotations": {("from", "__future__", "annotations", "")},
        **_OPTIONAL_GLOBALS.get(module, {}),
    }
    if set(bindings) - set(expected) - set(optional):
        return False
    for name in set(bindings) - set(expected):
        identities = bindings[name]
        if len(identities) != len(set(identities)) or not set(identities) <= optional[name]:
            return False
    return all(
        bindings.get(name, []) == ([] if identity == ("builtin",) else [identity])
        for name, identity in expected.items()
    )


def _typed_signature_matches(tree: ast.Module, symbol: str) -> bool:
    module = SYMBOL_MODULES[symbol]
    qualified = symbol[len(module) + 1 :].split(".")
    nodes = tree.body
    for name in qualified[:-1]:
        classes = [node for node in nodes if isinstance(node, ast.ClassDef) and node.name == name]
        if len(classes) != 1 or classes[0].decorator_list:
            return False
        nodes = classes[0].body
    functions = [
        node
        for node in nodes
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == qualified[-1]
    ]
    if len(functions) != 1 or functions[0].decorator_list:
        return False
    templates = {
        "asyncio.threads.to_thread": ASYNCIO_TEMPLATE,
        "anyio.to_thread.run_sync": ANYIO_TEMPLATE,
        "starlette.concurrency.run_in_threadpool": THREADPOOL_TEMPLATE,
        "starlette.background.BackgroundTasks.add_task": BACKGROUND_TEMPLATE,
        "fastapi.background.BackgroundTasks.add_task": FASTAPI_TEMPLATE,
    }
    expected_nodes = ast.parse(templates[symbol]).body
    if qualified[:-1]:
        selected = next(
            node
            for node in expected_nodes
            if isinstance(node, ast.ClassDef) and node.name == qualified[0]
        )
        expected_nodes = selected.body
    expected = next(
        node
        for node in expected_nodes
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == qualified[-1]
    )
    actual = functions[0]
    return type(actual) is type(expected) and _normalized(actual.args) == _normalized(expected.args)


def validate_callback_provider(  # noqa: PLR0911, PLR0912 - finite provider variants
    snapshot: CallbackProviderSnapshot, expected_symbol: str
) -> str | None:
    """Validate captured bytes; this function never reopens a source to parse it."""
    if SYMBOL_MODULES.get(expected_symbol) != snapshot.module_name:
        return None
    runtime = _parsed(snapshot.runtime_bytes)
    typed = _parsed(snapshot.typed_bytes)
    if runtime is None or typed is None or not _typed_signature_matches(typed, expected_symbol):
        return None
    if expected_symbol == "asyncio.threads.to_thread":
        expected_globals = {
            "functools": ("import", "functools", ""),
            "contextvars": ("import", "contextvars", ""),
            "events": ("from", ".", "events", ""),
            "to_thread": ("definition", "to_thread"),
        }
        if (
            _matches(runtime, ASYNCIO_TEMPLATE)
            and _matches(typed, "async def to_thread(func, /, *args, **kwargs): ...")
            and _globals_verified(runtime, expected_globals, snapshot.module_name)
        ):
            return "asyncio-to-thread"
    elif expected_symbol == "anyio.to_thread.run_sync":
        if _matches(runtime, ANYIO_TEMPLATE) and _globals_verified(
            runtime,
            {
                "warn": ("from", "warnings", "warn", ""),
                "get_async_backend": ("from", "._core._eventloop", "get_async_backend", ""),
                "run_sync": ("definition", "run_sync"),
                "DeprecationWarning": ("builtin",),
            },
            snapshot.module_name,
        ):
            return "anyio-run-sync"
    elif expected_symbol == "starlette.concurrency.run_in_threadpool":
        if _matches(runtime, THREADPOOL_TEMPLATE) and _globals_verified(
            runtime,
            {
                "functools": ("import", "functools", ""),
                "anyio": ("import", "anyio.to_thread", ""),
                "run_in_threadpool": ("definition", "run_in_threadpool"),
            },
            snapshot.module_name,
        ):
            return "starlette-threadpool-forward"
    elif expected_symbol == "starlette.background.BackgroundTasks.add_task":
        if _matches(runtime, BACKGROUND_TEMPLATE) and _globals_verified(
            runtime,
            {
                "BackgroundTask": ("definition", "BackgroundTask"),
                "BackgroundTasks": ("definition", "BackgroundTasks"),
                "is_async_callable": ("from", "starlette._utils", "is_async_callable", ""),
                "run_in_threadpool": ("from", "starlette.concurrency", "run_in_threadpool", ""),
                "list": ("builtin",),
            },
            snapshot.module_name,
        ):
            return "background-task-register"
    elif expected_symbol == "fastapi.background.BackgroundTasks.add_task":
        globals_expected = {
            "BackgroundTasks": ("definition", "BackgroundTasks"),
            "StarletteBackgroundTasks": (
                "from",
                "starlette.background",
                "BackgroundTasks",
                "StarletteBackgroundTasks",
            ),
            "super": ("builtin",),
        }
        if _matches(runtime, FASTAPI_TEMPLATE) and _globals_verified(
            runtime, globals_expected, snapshot.module_name
        ):
            return "fastapi-background-register"
        globals_expected["_operation"] = ("from", "fastapi.telemetry._api", "_operation", "")
        if _matches(runtime, FASTAPI_TEMPLATE + FASTAPI_TELEMETRY) and _globals_verified(
            runtime, globals_expected, snapshot.module_name
        ):
            return "fastapi-background-register"
    return None


def callback_provider_symbols(symbol: str) -> tuple[str, ...]:
    """Return the finite declarations needed for one forwarding chain."""
    if symbol not in SYMBOL_MODULES:
        return ()
    chains = {
        "asyncio.threads.to_thread": (),
        "anyio.to_thread.run_sync": (),
        "starlette.concurrency.run_in_threadpool": ("anyio.to_thread.run_sync",),
        "starlette.background.BackgroundTasks.add_task": (
            "starlette.concurrency.run_in_threadpool",
            "anyio.to_thread.run_sync",
        ),
        "fastapi.background.BackgroundTasks.add_task": (
            "starlette.background.BackgroundTasks.add_task",
            "starlette.concurrency.run_in_threadpool",
            "anyio.to_thread.run_sync",
        ),
    }
    return (symbol, *chains[symbol])


def callback_provider_kind(
    symbol: str, providers: Mapping[str, CallbackProviderSnapshot]
) -> str | None:
    required = callback_provider_symbols(symbol)
    if not required:
        return None
    for required_symbol in required:
        snapshot = providers.get(SYMBOL_MODULES[required_symbol])
        if (
            snapshot is None
            or not callback_provider_snapshot_current(snapshot)
            or validate_callback_provider(snapshot, required_symbol) is None
        ):
            return None
    if symbol == "asyncio.threads.to_thread":
        return "analysis-stdlib-environment-only"
    return "external-package-runtime"
