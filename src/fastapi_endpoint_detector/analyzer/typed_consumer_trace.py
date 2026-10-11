"""Realized access tracing for the bounded typed-cache consumer profile.

The trace is deliberately opt-in.  It observes nodes that the endpoint walker
actually visits and the declaration joined by framework-phase integration;
it does not infer use from source syntax or from a caller supplied list of
expected accesses.
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import os
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from mypy.nodes import Decorator, MypyFile, Node, OverloadedFuncDef, SymbolTableNode, TypeInfo
from mypy.types import Instance, Type, get_proper_type

from fastapi_endpoint_detector.analyzer.typed_cache_admission import CacheRunPlan

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from fastapi_endpoint_detector.analyzer.mypy_incremental import TypedBuild

MAX_TRACE_SOURCE_FILES = 20_000
MAX_TRACE_SOURCE_FILE_BYTES = 4 * 1024 * 1024
MAX_TRACE_SOURCE_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True)
class TraceSource:
    """Source bytes pinned by the cache/source-snapshot owner."""

    path: str
    data: bytes
    provenance: str

    def __post_init__(self) -> None:
        if self.provenance not in {"project_snapshot", "admitted_external_source"}:
            raise ValueError("typed trace source has no recognized snapshot provenance")
        if not Path(self.path).is_absolute():
            raise ValueError("typed trace source path must be absolute")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


@dataclass(frozen=True)
class ConsumerTraceSnapshot:
    """Immutable source-byte inputs supplied by the source/cache owner."""

    sources: Mapping[str, TraceSource]

    def __post_init__(self) -> None:
        normalized = {str(Path(path).resolve()): value for path, value in self.sources.items()}
        if len(normalized) != len(self.sources):
            raise ValueError("typed trace snapshot contains aliased source paths")
        if (
            len(normalized) > MAX_TRACE_SOURCE_FILES
            or any(len(source.data) > MAX_TRACE_SOURCE_FILE_BYTES for source in normalized.values())
            or sum(len(source.data) for source in normalized.values()) > MAX_TRACE_SOURCE_BYTES
        ):
            raise ValueError("typed trace source snapshot exceeds its structural bounds")
        if any(path != value.path for path, value in normalized.items()):
            raise ValueError("typed trace source key differs from its canonical path")
        object.__setattr__(self, "sources", MappingProxyType(normalized))

    @classmethod
    def from_owner_snapshots(
        cls,
        typed_build: TypedBuild,
        *,
        source_root: Path,
        project_sources: Mapping[str, bytes],
        external_sources: Mapping[str, bytes],
    ) -> ConsumerTraceSnapshot:
        """Bind owner-captured bytes to module paths in the retained Mypy graph.

        ``external_sources`` is the immutable mapping returned by cache/source
        admission. No source paths or cache dispositions are inferred from the
        caller's expected trace.
        """
        root = source_root.resolve()
        project = {str(Path(path).resolve()): data for path, data in project_sources.items()}
        external = {str(Path(path).resolve()): data for path, data in external_sources.items()}
        if len(project) != len(project_sources) or len(external) != len(external_sources):
            raise ValueError("owner source snapshots contain aliased paths")
        if set(project) & set(external):
            raise ValueError("project and external source snapshots overlap")
        sources: dict[str, TraceSource] = {}
        for _module, state in typed_build.modules.items():
            raw_path = getattr(state, "path", None)
            if not isinstance(raw_path, str) or not raw_path:
                continue
            path = str(Path(raw_path).resolve())
            try:
                Path(path).relative_to(root)
                data = project.get(path)
                provenance = "project_snapshot"
            except ValueError:
                data = external.get(path)
                provenance = "admitted_external_source"
            if data is not None:
                sources[path] = TraceSource(path=path, data=data, provenance=provenance)
        for path in project:
            if path not in sources:
                raise ValueError(f"captured project source is absent from typed graph: {path}")
        return cls(sources)


@dataclass(frozen=True)
class NodeShape:
    """Nonsemantic shape facts inspected by the trace verifier."""

    line: int | None
    body_present: bool | None
    arguments_present: bool | None
    argument_count: int | None
    body_child_count: int | None
    block_child_count: int | None


@dataclass(frozen=True)
class NodeAccess:
    """One node reached by a live semantic consumer hook."""

    consumer: str
    node_identity: int
    module: str
    node_type: str
    fullname: str | None
    type_identity: str | None
    shape: NodeShape
    fields: tuple[str, ...]
    cached: bool
    value_present: bool = True


@dataclass(frozen=True)
class TypedConsumerTraceResult:
    """Closed trace result for one analyzer plus framework-phase transaction."""

    accesses: tuple[NodeAccess, ...]
    source_pins: tuple[tuple[str, str], ...]
    canonical_registration_pins: tuple[tuple[str, str], ...]
    framework_registration_observed: bool
    blockers: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return (
            bool(self.accesses and self.canonical_registration_pins)
            and self.framework_registration_observed
            and not self.blockers
        )


class ConsumerTraceRejected(RuntimeError):
    """The realized semantic consumer path exceeds the pinned trace policy."""


_ACTIVE_TRACE: contextvars.ContextVar[TypedConsumerTrace | None] = contextvars.ContextVar(
    "fastapi_typed_consumer_trace", default=None
)
_AUDIT_REENTRY: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "fastapi_typed_consumer_trace_audit_reentry", default=False
)
_TYPEINFO_LOOKUP: contextvars.ContextVar[tuple[int, str] | None] = contextvars.ContextVar(
    "fastapi_typed_consumer_trace_typeinfo_lookup", default=None
)


# Mypy nodes are ordinary Python objects.  Intercepting their attribute loads
# observes the actual owner and field at the point Python returns the value;
# unlike a caller supplied field tuple, this also covers nested helper walks.
# The context variable keeps the normal analyzer path byte-for-byte semantic
# when tracing is disabled and makes concurrent contexts independent.
_NODE_GETATTRIBUTE = Node.__getattribute__
_NODE_AUDIT_LOCK = threading.RLock()
_NODE_AUDIT_USERS = 0


def _audited_nested_node_read(node: Node, field: str) -> Any:
    """Read a compiled property's child field with a fresh audit dispatch."""
    token = _AUDIT_REENTRY.set(False)
    try:
        return getattr(node, field)
    finally:
        _AUDIT_REENTRY.reset(token)


def _compiled_property_value(node: Node, field: str, trace: TypedConsumerTrace) -> tuple[bool, Any]:
    """Expand selected mypyc properties whose getters traverse typed nodes."""
    if isinstance(node, Decorator) and field in {"fullname", "name"}:
        child = _NODE_GETATTRIBUTE(node, "func")
        trace.observe_node_field(node, "func")
        return True, _audited_nested_node_read(child, field)
    if isinstance(node, Decorator) and field in {"info", "is_final", "type"}:
        member = "var" if field == "type" else "func"
        child = _NODE_GETATTRIBUTE(node, member)
        trace.observe_node_field(node, member)
        return True, _audited_nested_node_read(child, field)
    if isinstance(node, OverloadedFuncDef) and field == "name":
        items = _NODE_GETATTRIBUTE(node, "items")
        trace.observe_node_field(node, "items")
        if items:
            return True, _audited_nested_node_read(items[0], "name")
        impl = _NODE_GETATTRIBUTE(node, "impl")
        trace.observe_node_field(node, "impl")
        assert impl is not None
        return True, _audited_nested_node_read(impl, "name")
    if isinstance(node, TypeInfo) and field == "name":
        definition = _NODE_GETATTRIBUTE(node, "defn")
        trace.observe_node_field(node, "defn")
        return True, _audited_nested_node_read(definition, "name")
    return False, None


def _audited_node_getattribute(node: Node, field: str) -> Any:
    trace = _ACTIVE_TRACE.get()
    if trace is not None and not _AUDIT_REENTRY.get() and not field.startswith("__"):
        token = _AUDIT_REENTRY.set(True)
        try:
            # Mypy's compiled Decorator properties dereference ``func`` inside
            # native property code, bypassing Python attribute dispatch. Make
            # those accesses explicit while auditing is active.
            expanded, value = _compiled_property_value(node, field, trace)
            if not expanded:
                try:
                    value = _NODE_GETATTRIBUTE(node, field)
                except AttributeError:
                    trace.observe_node_field(node, field, value_present=False)
                    raise
            trace.observe_node_field(node, field, value_present=True)
        finally:
            _AUDIT_REENTRY.reset(token)
        return value
    try:
        value = _NODE_GETATTRIBUTE(node, field)
    except AttributeError:
        if trace is not None and not _AUDIT_REENTRY.get() and not field.startswith("__"):
            trace.observe_node_field(node, field, value_present=False)
        raise
    return value


def _acquire_node_audit() -> None:
    """Install the reader only while at least one trace context is active."""
    global _NODE_AUDIT_USERS  # noqa: PLW0603
    with _NODE_AUDIT_LOCK:
        expected = _audited_node_getattribute if _NODE_AUDIT_USERS else _NODE_GETATTRIBUTE
        if Node.__getattribute__ is not expected:
            raise ConsumerTraceRejected("Mypy node field audit hook conflicts with another reader")
        if not _NODE_AUDIT_USERS:
            setattr(Node, "__getattribute__", _audited_node_getattribute)  # noqa: B010
        _NODE_AUDIT_USERS += 1


def _release_node_audit() -> bool:
    """Restore our exact reader on final exit; never replace a foreign hook."""
    global _NODE_AUDIT_USERS  # noqa: PLW0603
    with _NODE_AUDIT_LOCK:
        if _NODE_AUDIT_USERS <= 0:
            raise RuntimeError("typed node audit context accounting is inconsistent")
        unchanged = Node.__getattribute__ is _audited_node_getattribute
        _NODE_AUDIT_USERS -= 1
        if not _NODE_AUDIT_USERS and unchanged:
            setattr(Node, "__getattribute__", _NODE_GETATTRIBUTE)  # noqa: B010
        return unchanged


class TypedConsumerTrace:
    """Collect actual analyzer and phase-integration node accesses.

    ``typed_build`` supplies the actual Mypy graph and recheck observations.
    ``snapshot`` must come from the source/cache snapshot owner and is used to
    bind every observed module to exact source bytes.
    """

    CANONICAL_REGISTRATION = "fastapi.applications.FastAPI.on_event"
    _CANONICAL_ALLOWED_FIELDS = frozenset({"identity", "type"})

    def __init__(
        self,
        snapshot: ConsumerTraceSnapshot,
        typed_build: TypedBuild,
        *,
        source_root: Path,
        cache_plan: CacheRunPlan | None = None,
    ) -> None:
        self.snapshot = snapshot
        self.typed_build = typed_build
        self.source_root = source_root.resolve()
        self.cache_plan = cache_plan
        self.admitted_modules = (
            cache_plan.admitted_modules if cache_plan is not None else frozenset()
        )
        self.expected_graph = MappingProxyType(
            dict(cache_plan.expected_graph) if cache_plan is not None else {}
        )
        self.cache_map = MappingProxyType(
            dict(cache_plan.cache_map) if cache_plan is not None else {}
        )
        self.artifact_hashes = MappingProxyType(
            dict(cache_plan.artifact_hashes or {}) if cache_plan is not None else {}
        )
        build_manager = getattr(typed_build, "manager", None)
        rechecked = getattr(build_manager, "rechecked_modules", None)
        if rechecked is None:
            result_manager = getattr(getattr(typed_build, "result", None), "manager", None)
            rechecked = getattr(result_manager, "rechecked_modules", ())
        if rechecked is None:
            rechecked = ()
        self.rechecked_modules = frozenset(rechecked)
        self.module_paths: dict[str, str] = {}
        for module, state in typed_build.modules.items():
            path = getattr(state, "path", None)
            if isinstance(path, str) and path:
                self.module_paths[module] = str(Path(path).resolve())
        self.node_modules = self._index_typed_nodes()
        self._accesses: list[NodeAccess] = []
        self._access_keys: set[tuple[int, str, str, bool]] = set()
        self._node_shapes: dict[int, NodeShape] = {}
        self._canonical_pins: set[tuple[str, str]] = set()
        self._framework_registration_observed = False
        self._blockers: set[str] = set()
        self._token: contextvars.Token[TypedConsumerTrace | None] | None = None
        self._validate_snapshot()

    def _index_typed_nodes(self) -> dict[int, str]:
        """Bind object identities to the exact retained Mypy module graph."""
        owners: dict[int, str] = {}
        seen: set[int] = set()
        self.node_types: set[type[Node]] = set()
        ignored = {
            "node",
            "info",
            "type",
            "unanalyzed_type",
            "original_def",
            "original_first_arg",
            "def_var",
            "expanded",
            "analyzed",
        }

        def visit_value(value: object, module: str) -> None:
            if isinstance(value, (tuple, list)):
                for child in value:
                    visit_value(child, module)
            elif isinstance(value, dict):
                for child in value.values():
                    visit_value(child, module)
            elif isinstance(value, Node):
                visit(value, module)

        def visit(node: Node, module: str) -> None:
            identity = id(node)
            if identity in seen:
                return
            seen.add(identity)
            self.node_types.add(type(node))
            owners[identity] = module
            for cls in type(node).__mro__:
                for field_name in getattr(cls, "__mypyc_attrs__", ()):
                    if field_name.startswith("_") or field_name in ignored:
                        continue
                    try:
                        child = getattr(node, field_name)
                    except (AttributeError, RuntimeError):
                        continue
                    visit_value(child, module)

        def visit_symbols(symbols: object, module: str, seen_symbols: set[int]) -> None:
            if not isinstance(symbols, dict):
                return
            for symbol in symbols.values():
                identity = id(symbol)
                if identity in seen_symbols:
                    continue
                seen_symbols.add(identity)
                node = getattr(symbol, "node", None)
                if isinstance(node, Node):
                    self.node_types.add(type(node))
                    defining_module = getattr(node, "module_name", None)
                    if (
                        not isinstance(defining_module, str)
                        or defining_module not in self.module_paths
                    ):
                        fullname = getattr(node, "fullname", None)
                        if isinstance(fullname, str):
                            candidates = [
                                name
                                for name in self.module_paths
                                if fullname == name or fullname.startswith(name + ".")
                            ]
                            defining_module = max(candidates, key=len) if candidates else module
                        else:
                            defining_module = module
                    owners.setdefault(id(node), defining_module)
                    if isinstance(node, TypeInfo):
                        visit_symbols(node.names, module, seen_symbols)

        for module, state in self.typed_build.modules.items():
            tree = getattr(state, "tree", None)
            if isinstance(tree, Node):
                visit(tree, module)
                visit_symbols(getattr(tree, "names", None), module, set())
        return owners

    def _validate_cache_binding(self) -> None:
        if self.cache_plan is not None:
            if not isinstance(self.cache_plan, CacheRunPlan):
                self._blockers.add("cache binding is not an owner-issued CacheRunPlan")
            if not self.artifact_hashes:
                self._blockers.add("cache binding has no exact staged artifact hashes")
            manager = getattr(self.typed_build, "manager", None)
            if manager is None:
                manager = getattr(getattr(self.typed_build, "result", None), "manager", None)
            options = getattr(manager, "options", None)
            actual_map = getattr(options, "cache_map", None)
            planned_map = {
                os.path.normpath(source): tuple(members)
                for source, members in self.cache_plan.cache_map.items()
            }
            built_map = (
                {os.path.normpath(source): tuple(members) for source, members in actual_map.items()}
                if isinstance(actual_map, dict)
                else None
            )
            if built_map != planned_map:
                self._blockers.add("typed build did not consume the exact planned cache map")
            expected_cache_dir = str(self.cache_plan.run_root / "output")
            if getattr(options, "cache_dir", None) != expected_cache_dir:
                self._blockers.add("typed build cache directory differs from the planned run")
            expected_artifact_keys = {
                member
                for module in self.admitted_modules
                for path in (self.module_paths.get(module),)
                if path is not None
                for member in (self.cache_map.get(os.path.normpath(path)) or ())
            }
            if set(self.artifact_hashes) != expected_artifact_keys:
                self._blockers.add("cache artifact digest keys do not exactly match staged members")

    def _validate_snapshot(self) -> None:
        self._validate_cache_binding()
        for module, path in self.module_paths.items():
            self._validate_module_snapshot(module, path)
        for module in self.admitted_modules:
            if module not in self.module_paths:
                self._blockers.add(f"admitted cache module is absent from typed graph: {module}")

    def _validate_module_snapshot(self, module: str, path: str) -> None:
        project_path = path.startswith(str(self.source_root) + "/")
        if module in self.admitted_modules and module in self.rechecked_modules:
            self._blockers.add(f"module has conflicting cached and rechecked status: {module}")
        if project_path and module not in self.rechecked_modules:
            self._blockers.add(f"project module was not rechecked: {module}")
        source = self.snapshot.sources.get(path)
        state = self.typed_build.modules[module]
        if source is None:
            if module in self.admitted_modules or project_path:
                self._blockers.add(f"source snapshot is absent for typed module: {module}")
            return
        source_hash = getattr(state, "source_hash", None) or getattr(
            state, "meta_source_hash", None
        )
        expected_mypy_hash = hashlib.sha1(source.data).hexdigest()
        if source_hash != expected_mypy_hash:
            self._blockers.add(f"typed module source differs from pinned bytes: {module}")
        if module in self.admitted_modules:
            self._validate_cached_module(module, path, state)

    def _validate_cached_module(self, module: str, path: str, state: object) -> None:
        expected_graph_hash = self.expected_graph.get(module)
        actual_graph_hash = getattr(state, "meta_source_hash", None)
        if expected_graph_hash is None or actual_graph_hash != expected_graph_hash:
            self._blockers.add(f"cached typed module differs from artifact binding: {module}")
        staged_pair = self.cache_map.get(os.path.normpath(path))
        if staged_pair is None or any(item not in self.artifact_hashes for item in staged_pair):
            self._blockers.add(f"cached typed module has no exact staged members: {module}")
            return
        for member in staged_pair:
            expected_digest = self.artifact_hashes[member]
            try:
                actual_digest = hashlib.sha256(Path(member).read_bytes()).hexdigest()
            except OSError:
                actual_digest = None
            if actual_digest != expected_digest:
                self._blockers.add(f"cached typed module staged artifact digest mismatch: {module}")

    def __enter__(self) -> TypedConsumerTrace:
        # The shared lock also serializes reuse of this instance across contexts.
        with _NODE_AUDIT_LOCK:
            if self._token is not None:
                raise RuntimeError("typed consumer trace cannot be entered twice")
            active = _ACTIVE_TRACE.get()
            if active is not None:
                active._blockers.add("nested typed consumer traces make reader closure ambiguous")
                raise ConsumerTraceRejected(
                    "nested typed consumer traces make reader closure ambiguous"
                )
            try:
                _acquire_node_audit()
            except ConsumerTraceRejected as error:
                self._blockers.add(str(error))
                raise
            try:
                self._token = _ACTIVE_TRACE.set(self)
            except BaseException:
                _release_node_audit()
                raise
            if any(
                node_type.__getattribute__ is not _audited_node_getattribute
                for node_type in self.node_types
            ):
                self._blockers.add(
                    "retained graph contains a Mypy node class outside the audited reader"
                )
            return self

    def __exit__(self, *_exc: object) -> None:
        with _NODE_AUDIT_LOCK:
            if self._token is not None:
                # A token reset in the wrong context must leave its owner active.
                _ACTIVE_TRACE.reset(self._token)
                self._token = None
                if not _release_node_audit():
                    self._blockers.add(
                        "Mypy node field audit hook was replaced during the transaction"
                    )

    def observe_node(
        self,
        node: object,
        module: str,
        consumer: str,
        _fields: tuple[str, ...],
    ) -> None:
        """Validate a node visit; actual field evidence comes from Python reads."""
        actual_module = self.node_modules.get(id(node))
        if actual_module is None:
            self._blockers.add(
                f"consumer node does not belong to the transaction's typed build: {consumer}"
            )
        else:
            module = actual_module
        if module not in self.module_paths:
            self._blockers.add(
                f"consumer reached a node outside the retained typed graph: {module}"
            )

    def observe_node_field(self, node: Node, field: str, *, value_present: bool = True) -> None:
        """Record one field whose value was just read from this real node."""
        if type(node).__getattribute__ is not _audited_node_getattribute:
            self._blockers.add(
                f"Mypy node class bypasses audited field access: {type(node).__module__}."
                f"{type(node).__qualname__}"
            )
            return
        module = self.node_modules.get(id(node))
        if module is None:
            self._blockers.add(
                "actual Mypy node field read belongs to an unknown typed node: "
                f"{type(node).__module__}.{type(node).__qualname__}.{field}"
            )
            return
        state = self.typed_build.modules.get(module)
        cached = state is not None and (
            module in self.admitted_modules or module not in self.rechecked_modules
        )
        frame = sys._getframe(2)
        consumer = f"{frame.f_globals.get('__name__', '<unknown>')}.{frame.f_code.co_name}"
        access_key = (id(node), field, consumer, value_present)
        if access_key in self._access_keys:
            return
        self._access_keys.add(access_key)
        fullname = getattr(node, "fullname", None)
        if not isinstance(fullname, str):
            fullname = None
        shape = self._node_shapes.get(id(node))
        if shape is None:
            shape = _node_shape(node)
            self._node_shapes[id(node)] = shape
        self._accesses.append(
            NodeAccess(
                consumer=consumer,
                node_identity=id(node),
                module=module,
                node_type=type(node).__name__,
                fullname=fullname,
                type_identity=None,
                shape=shape,
                fields=(field,),
                cached=cached,
                value_present=value_present,
            )
        )
        if fullname == self.CANONICAL_REGISTRATION:
            self._pin_canonical_declaration(node, module, cached=cached)
        lookup = _TYPEINFO_LOOKUP.get()
        canonical_type_lookup = (
            lookup == (id(node), "on_event")
            and fullname == "fastapi.applications.FastAPI"
            and module == "fastapi.applications"
            and field in {"fullname", "mro", "names"}
            and self.cache_plan is not None
            and module in self.admitted_modules
        )
        if (
            cached
            and fullname == self.CANONICAL_REGISTRATION
            and (self.cache_plan is None or module not in self.admitted_modules)
        ):
            self._blockers.add(
                "cached canonical registration has no matching admitted artifact binding"
            )
        elif cached and not (
            (fullname == self.CANONICAL_REGISTRATION and field in self._CANONICAL_ALLOWED_FIELDS)
            or canonical_type_lookup
        ):
            self._blockers.add(
                "cached typed node field read outside the pinned canonical registration: "
                f"{module}:{fullname or type(node).__name__}:{field}"
            )

    def observe_type_access(self, node: object, typed_value: Type | None) -> None:
        """Record the actual mypy type-map value read for a visited node."""
        module = self.node_modules.get(id(node))
        if module is None:
            self._blockers.add(
                "type-map consumer node does not belong to the transaction's typed build"
            )
            return
        proper_type = typed_value
        proper_type = get_proper_type(typed_value)
        type_identity = (
            proper_type.type.fullname
            if isinstance(proper_type, Instance)
            else type(proper_type).__name__
        )
        fullname = getattr(node, "fullname", None)
        if not isinstance(fullname, str):
            fullname = None
        state = self.typed_build.modules.get(module)
        cached = state is not None and (
            module in self.admitted_modules or module not in self.rechecked_modules
        )
        self._accesses.append(
            NodeAccess(
                consumer="MypyAnalyzer._get_type_from_node",
                node_identity=id(node),
                module=module,
                node_type=type(node).__name__,
                fullname=fullname,
                type_identity=type_identity,
                shape=_node_shape(node),
                fields=("identity", "type"),
                cached=cached,
            )
        )
        if cached and fullname != self.CANONICAL_REGISTRATION:
            self._blockers.add(
                "type evidence consumed from a cached node outside canonical registration: "
                f"{module}"
            )
        elif cached and (self.cache_plan is None or module not in self.admitted_modules):
            self._blockers.add(
                "cached canonical registration has no matching admitted artifact binding"
            )

    def observe_framework_registration(self, site: object) -> None:
        """Bind the actual FastAPI declaration and callsite to source bytes."""
        symbol = getattr(site, "canonical_symbol", None)
        if symbol != self.CANONICAL_REGISTRATION:
            self._blockers.add("framework consumer resolved a noncanonical registration")
            return
        module = "fastapi.applications"
        state = self.typed_build.modules.get(module)
        if state is None:
            self._blockers.add("canonical FastAPI module is absent from retained typed graph")
            return
        tree: MypyFile | None = getattr(state, "tree", None)
        if tree is None:
            self._blockers.add("canonical FastAPI declaration has no retained typed module")
            return
        fastapi_symbol = tree.names.get("FastAPI")
        info = getattr(fastapi_symbol, "node", None)
        methods = getattr(info, "names", None)
        method_symbol = methods.get("on_event") if methods is not None else None
        declaration = getattr(method_symbol, "node", None)
        if declaration is None:
            self._blockers.add("canonical FastAPI on_event declaration is absent")
            return
        if type(declaration).__name__ == "Decorator":
            declaration = declaration.func
        fullname = getattr(declaration, "fullname", None)
        if fullname != self.CANONICAL_REGISTRATION:
            self._blockers.add("typed FastAPI registration declaration identity differs")
            return
        pinned = self._pin_canonical_declaration(
            declaration,
            module,
            cached=module in self.admitted_modules or module not in self.rechecked_modules,
        )
        self.observe_node(
            declaration,
            module,
            "framework_phase_integration._typed_registration",
            ("identity", "type"),
        )
        if pinned:
            self._framework_registration_observed = True

    def _pin_canonical_declaration(self, declaration: object, module: str, *, cached: bool) -> bool:
        if module != "fastapi.applications":
            self._blockers.add("canonical registration identity came from an unexpected module")
            return False
        module_path = self.module_paths.get(module)
        source = self.snapshot.sources.get(module_path or "")
        if module_path is None or source is None:
            self._blockers.add("canonical FastAPI declaration has no owner-pinned source bytes")
            return False
        if source.provenance != "admitted_external_source":
            self._blockers.add("canonical FastAPI declaration lacks admitted source provenance")
            return False
        if getattr(declaration, "fullname", None) != self.CANONICAL_REGISTRATION:
            self._blockers.add("canonical declaration source identity differs")
            return False
        body = getattr(declaration, "body", None)
        if cached and body is not None:
            body_nodes = getattr(body, "body", None)
            body_line = getattr(body, "line", 0)
            if body_nodes or body_line >= 0:
                self._blockers.add("cached canonical registration unexpectedly carries a body")
                return False
        self._canonical_pins.add((module_path, source.sha256))
        return True

    def observe_call_site(self, site: object, module: str) -> None:
        """Reject dynamic or untyped consumers on the realized call path."""
        status = getattr(getattr(site, "status", None), "value", None)
        if status != "exact":
            reason = getattr(site, "reason_code", None) or "untyped_or_dynamic_consumer"
            self._blockers.add(f"nonexact typed consumer in {module}: {reason}")

    def result(self) -> TypedConsumerTraceResult:
        source_pins = tuple(
            sorted((path, source.sha256) for path, source in self.snapshot.sources.items())
        )
        return TypedConsumerTraceResult(
            accesses=tuple(self._accesses),
            source_pins=source_pins,
            canonical_registration_pins=tuple(sorted(self._canonical_pins)),
            framework_registration_observed=self._framework_registration_observed,
            blockers=tuple(sorted(self._blockers)),
        )

    def require_complete(self) -> TypedConsumerTraceResult:
        """Raise inside the caller's warm transaction when proof is incomplete."""
        if _ACTIVE_TRACE.get() is not self:
            self._blockers.add("typed consumer trace is not the active reader context")
        if Node.__getattribute__ is not _audited_node_getattribute:
            self._blockers.add("Mypy node field audit hook was replaced during the transaction")
        if any(
            node_type.__getattribute__ is not _audited_node_getattribute
            for node_type in self.node_types
        ):
            self._blockers.add("retained graph node reader changed during the transaction")
        result = self.result()
        if not result.complete:
            details = "; ".join(result.blockers)
            if not result.framework_registration_observed:
                details = "; ".join(
                    part
                    for part in (
                        details,
                        "canonical framework phase registration join was not observed",
                    )
                    if part
                )
            if not details:
                details = "canonical phase consumer was not observed"
            raise ConsumerTraceRejected(details)
        return result


@contextlib.contextmanager
def collect_typed_consumer_trace(
    snapshot: ConsumerTraceSnapshot,
    typed_build: TypedBuild,
    *,
    source_root: Path,
    cache_plan: CacheRunPlan | None = None,
) -> Iterator[TypedConsumerTrace]:
    """Opt in to one closed trace around endpoint and phase analysis."""
    trace = TypedConsumerTrace(
        snapshot,
        typed_build,
        source_root=source_root,
        cache_plan=cache_plan,
    )
    with trace:
        yield trace


def observe_node_access(node: object, module: str, consumer: str, fields: tuple[str, ...]) -> None:
    """Legacy visit marker; actual fields are captured by Node attribute reads."""
    trace = _ACTIVE_TRACE.get()
    if trace is not None:
        trace.observe_node(node, module, consumer, fields)


def observe_framework_registration(site: object) -> None:
    """Record the canonical declaration used by the active phase consumer."""
    trace = _ACTIVE_TRACE.get()
    if trace is not None:
        token = _AUDIT_REENTRY.set(True)
        try:
            trace.observe_framework_registration(site)
        finally:
            _AUDIT_REENTRY.reset(token)


def observe_call_site(site: object, module: str) -> None:
    """Record actual exactness of a call resolved by the endpoint analyzer."""
    trace = _ACTIVE_TRACE.get()
    if trace is not None:
        trace.observe_call_site(site, module)


def observe_type_access(node: object, typed_value: Type | None) -> None:
    """Low-overhead hook for actual Mypy type-map dereferences."""
    trace = _ACTIVE_TRACE.get()
    if trace is not None:
        trace.observe_type_access(node, typed_value)


def audited_typeinfo_get(info: TypeInfo, name: str) -> SymbolTableNode | None:
    """Resolve a Mypy member while exposing compiled helper reads to the audit.

    ``TypeInfo.get`` is compiled in the locked Mypy build and reads ``mro`` and
    each base's ``names`` without Python attribute dispatch. The cold path keeps
    Mypy's implementation. Under tracing, the equivalent ordered lookup is
    performed in Python so each owner field passes through the audited reader.
    """
    if _ACTIVE_TRACE.get() is None:
        return info.get(name)
    token = _TYPEINFO_LOOKUP.set((id(info), name))
    try:
        for base in info.mro:
            symbol = base.names.get(name)
            if symbol:
                return symbol
        return None
    finally:
        _TYPEINFO_LOOKUP.reset(token)


def _node_shape(node: object) -> NodeShape:
    """Capture available node shape separately from consumer-read fields."""
    shape_node = getattr(node, "func", node) if type(node).__name__ == "Decorator" else node
    line = getattr(shape_node, "line", None)
    body = getattr(shape_node, "body", None)
    arguments = getattr(shape_node, "arguments", None)
    body_present = None if not hasattr(type(shape_node), "body") else body is not None
    arguments_present = (
        None if not hasattr(type(shape_node), "arguments") else arguments is not None
    )
    argument_count = len(arguments) if isinstance(arguments, (tuple, list)) else None
    body_statements = getattr(body, "body", None)
    body_child_count = len(body_statements) if isinstance(body_statements, (tuple, list)) else None
    block_child_count = (
        len(body)
        if type(shape_node).__name__ == "Block" and isinstance(body, (tuple, list))
        else None
    )
    return NodeShape(
        line=line if isinstance(line, int) else None,
        body_present=body_present,
        arguments_present=arguments_present,
        argument_count=argument_count,
        body_child_count=body_child_count,
        block_child_count=block_child_count,
    )
