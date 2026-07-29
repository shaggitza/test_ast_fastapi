"""Runtime FastAPI extractor parity tests."""

import functools
import os
import py_compile
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from fastapi import Depends, FastAPI

from fastapi_endpoint_detector.models.endpoint import (
    DependencyCallableKind,
    DependencyDeclarationKind,
    DependencyGraphStatus,
    HandlerInfo,
)
from fastapi_endpoint_detector.parser.fastapi_extractor import (
    FastAPIExtractor,
    FastAPIExtractorError,
)
from fastapi_endpoint_detector.parser.secure_ast_extractor import SecureASTExtractor


def test_runtime_extractor_handles_websockets_and_mounted_fastapi(tmp_path: Path) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        """from fastapi import FastAPI

app = FastAPI()
sub = FastAPI()

@app.websocket("/events")
async def events(websocket):
    pass

@sub.get("/status")
def status():
    return {}

app.mount("/sub", sub)
"""
    )

    endpoints = FastAPIExtractor(app_file).extract_endpoints()

    custom = {
        endpoint.identifier for endpoint in endpoints if endpoint.path in {"/events", "/sub/status"}
    }
    assert custom == {"GET /sub/status", "WEBSOCKET /events"}


def test_runtime_extractor_preserves_slashes_websocket_dependencies_and_mount_cycles(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        """from fastapi import Depends, FastAPI

app = FastAPI()
sub = FastAPI()

def authenticate():
    return "token"

@sub.get("/")
def root():
    return {}

@app.websocket("/events/")
async def events(websocket, token=Depends(authenticate)):
    pass

app.mount("/sub", sub)
app.mount("/cycle", app)
"""
    )

    endpoints = FastAPIExtractor(app_file).extract_endpoints()

    assert {endpoint.identifier for endpoint in endpoints} >= {
        "GET /sub/",
        "WEBSOCKET /events/",
    }
    websocket = next(endpoint for endpoint in endpoints if endpoint.path == "/events/")
    assert websocket.dependencies == ["authenticate"]


def test_runtime_extractor_expands_nested_included_routers_with_effective_metadata(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "included_app.py"
    app_file.write_text(
        """from fastapi import APIRouter, Depends, FastAPI
from fastapi.routing import APIRoute


class AuditRoute(APIRoute):
    pass


def app_dependency():
    return "app"


def include_dependency():
    return "include"


def route_dependency():
    return "route"


def parameter_dependency():
    return "parameter"


inner = APIRouter(prefix="/inner", tags=["router"], route_class=AuditRoute)

@inner.get(
    "/items",
    tags=["route"],
    dependencies=[Depends(route_dependency)],
)
def items(token=Depends(parameter_dependency)):
    return {"token": token}

@inner.websocket("/socket", dependencies=[Depends(route_dependency)])
async def socket(websocket, token=Depends(parameter_dependency)):
    pass

outer = APIRouter(prefix="/outer")
outer.include_router(
    inner,
    prefix="/included",
    tags=["include"],
    dependencies=[Depends(include_dependency)],
)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(
    outer,
    prefix="/api",
    tags=["app"],
    dependencies=[Depends(app_dependency)],
)
"""
    )

    endpoints = FastAPIExtractor(app_file).extract_endpoints()

    assert {endpoint.identifier for endpoint in endpoints} == {
        "GET /api/outer/included/inner/items",
        "WEBSOCKET /api/outer/included/inner/socket",
    }
    http = next(endpoint for endpoint in endpoints if endpoint.methods[0].value == "GET")
    assert http.tags == ["app", "include", "router", "route"]
    assert http.dependencies == [
        "app_dependency",
        "include_dependency",
        "route_dependency",
        "parameter_dependency",
    ]
    assert http.handler.file_path == app_file
    assert http.handler.name == "items"

    websocket = next(endpoint for endpoint in endpoints if endpoint.path.endswith("/socket"))
    assert websocket.dependencies == [
        "app_dependency",
        "include_dependency",
        "route_dependency",
        "parameter_dependency",
    ]
    assert websocket.handler.file_path == app_file
    assert websocket.handler.name == "socket"


def test_runtime_dependency_graph_preserves_nested_repeated_security_and_callable_shapes(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "dependency_graph_app.py"
    app_file.write_text(
        """from functools import partial
from typing import Annotated
from fastapi import Depends, FastAPI, Security


def helper():
    return 1


def nested(value=Depends(helper)):
    return value


def authorize():
    return 1


class Provider:
    def __call__(self, value=Depends(nested)):
        return value


provider = Provider()
app = FastAPI(dependencies=[Depends(nested), Depends(nested)])

@app.get("/graph")
def graph(
    auth: Annotated[int, Security(authorize, scopes=["read"])],
    partial_value=Depends(partial(nested)),
    instance_value=Depends(provider),
):
    return auth
"""
    )

    endpoint = FastAPIExtractor(app_file).extract_endpoints()[0]
    graph = endpoint.dependency_graph

    assert endpoint.dependencies == ["nested", "nested", "partial", "Provider"]
    assert graph is not None
    assert graph.status == DependencyGraphStatus.ESTABLISHED
    assert graph.semantics == "declared"
    assert [item.index_path for item in graph.occurrences[:4]] == [
        (0,),
        (0, 0),
        (1,),
        (1, 0),
    ]
    assert [item.display_name for item in graph.occurrences].count("nested") == 3
    security = next(item for item in graph.occurrences if item.display_name == "authorize")
    assert security.declaration_kind in {
        DependencyDeclarationKind.SECURITY,
        DependencyDeclarationKind.DEPENDS_OR_SECURITY,
    }
    assert security.security_scopes == ("read",)
    partial_item = next(
        item for item in graph.occurrences if item.callable_kind == DependencyCallableKind.PARTIAL
    )
    assert [layer.kind for layer in partial_item.callable_structure] == [
        DependencyCallableKind.PARTIAL,
        DependencyCallableKind.FUNCTION,
    ]
    assert any(
        item.callable_kind == DependencyCallableKind.CALLABLE_INSTANCE for item in graph.occurrences
    )
    assert [item.order for item in graph.occurrences] == list(range(len(graph.occurrences)))
    assert all("0x" not in item.display_name for item in graph.occurrences)


def test_runtime_dependency_graph_cycle_and_caps_are_conditional_and_deterministic(
    tmp_path: Path,
) -> None:
    cycle_app = tmp_path / "cycle_app.py"
    cycle_app.write_text(
        """from fastapi import Depends, FastAPI


def dependency():
    return 1


app = FastAPI()

@app.get("/cycle")
def cycle(value=Depends(dependency)):
    return value

route = next(route for route in app.routes if getattr(route, "path", None) == "/cycle")
node = route.dependant.dependencies[0]
node.dependencies.append(node)
"""
    )
    cycle_endpoint = FastAPIExtractor(cycle_app).extract_endpoints()[0]
    cycle_graph = cycle_endpoint.dependency_graph
    assert cycle_graph is not None
    assert cycle_graph.status == DependencyGraphStatus.CONDITIONAL
    assert [item.index_path for item in cycle_graph.occurrences] == [(0,), (0, 0)]
    assert "cycle" in {limitation.code for limitation in cycle_graph.limitations}

    capped_app = tmp_path / "capped_app.py"
    capped_app.write_text(
        """from fastapi import Depends, FastAPI


def leaf():
    return 1


def middle(value=Depends(leaf)):
    return value


app = FastAPI()

@app.get("/capped")
def capped(value=Depends(middle)):
    return value
"""
    )
    first = FastAPIExtractor(capped_app, dependency_max_depth=1).extract_endpoints()[0]
    second = FastAPIExtractor(capped_app, dependency_max_depth=1).extract_endpoints()[0]
    assert first.dependency_graph == second.dependency_graph
    assert first.dependency_graph is not None
    assert first.dependency_graph.status == DependencyGraphStatus.CONDITIONAL
    assert [item.index_path for item in first.dependency_graph.occurrences] == [(0,)]
    assert "depth_cap" in {limitation.code for limitation in first.dependency_graph.limitations}

    node_capped = FastAPIExtractor(capped_app, dependency_max_nodes=1).extract_endpoints()[0]
    assert node_capped.dependency_graph is not None
    assert "node_cap" in {
        limitation.code for limitation in node_capped.dependency_graph.limitations
    }
    work_capped = FastAPIExtractor(capped_app, dependency_max_work=1).extract_endpoints()[0]
    assert work_capped.dependency_graph is not None
    assert "work_cap" in {
        limitation.code for limitation in work_capped.dependency_graph.limitations
    }


def test_runtime_dependency_graph_missing_shape_and_overrides_are_graph_local(
    tmp_path: Path,
) -> None:
    handler = HandlerInfo(
        name="endpoint", module="main", file_path=tmp_path / "main.py", line_number=4
    )
    extractor = FastAPIExtractor(tmp_path / "main.py")
    extractor._app = SimpleNamespace(dependency_overrides={})
    unavailable = extractor._extract_dependency_graph(SimpleNamespace(), handler)
    assert unavailable.status == DependencyGraphStatus.UNAVAILABLE
    assert unavailable.limitations[0].source_path == handler.file_path

    root = SimpleNamespace(dependencies=[])
    extractor._app = SimpleNamespace(dependency_overrides={object(): object()})
    conditional = extractor._extract_dependency_graph(SimpleNamespace(dependant=root), handler)
    assert conditional.status == DependencyGraphStatus.CONDITIONAL
    assert conditional.occurrences == ()
    assert {item.code for item in conditional.limitations} == {"dependency_overrides_visible"}


def _synthetic_old_dependency() -> int:
    return 1


def _synthetic_effective_dependency() -> int:
    return 2


def test_dependency_graph_prefers_effective_non_none_root_without_masking(
    tmp_path: Path,
) -> None:
    handler = HandlerInfo(
        name="endpoint", module="main", file_path=tmp_path / "main.py", line_number=1
    )
    extractor = FastAPIExtractor(tmp_path / "main.py")
    extractor._app = SimpleNamespace(dependency_overrides={})

    def node(call: Any) -> SimpleNamespace:
        return SimpleNamespace(
            call=call,
            dependencies=[],
            own_oauth_scopes=[],
            use_cache=True,
            name=None,
        )

    old_root = SimpleNamespace(dependencies=[node(_synthetic_old_dependency)])
    effective_root = SimpleNamespace(dependencies=[node(_synthetic_effective_dependency)])
    wrapper = SimpleNamespace(
        dependant=old_root,
        starlette_route=SimpleNamespace(dependant=effective_root),
        original_route=SimpleNamespace(dependant=old_root),
    )
    graph = extractor._extract_dependency_graph(wrapper, handler)
    assert [item.display_name for item in graph.occurrences] == ["_synthetic_effective_dependency"]

    wrapper.dependant = None
    assert extractor._extract_dependency_graph(wrapper, handler).occurrences[0].display_name == (
        "_synthetic_effective_dependency"
    )
    direct = SimpleNamespace(dependant=effective_root)
    assert extractor._extract_dependency_graph(direct, handler).occurrences[0].display_name == (
        "_synthetic_effective_dependency"
    )

    class RaisingWrapper:
        starlette_route = SimpleNamespace(dependant=effective_root)

        @property
        def dependant(self) -> Any:
            raise RuntimeError("stale wrapper")

    assert extractor._extract_dependency_graph(RaisingWrapper(), handler).occurrences


def test_normalized_http_and_websocket_routes_use_effective_dependency_roots(
    tmp_path: Path,
) -> None:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/http", dependencies=[Depends(_synthetic_effective_dependency)])
    def http_handler() -> None:
        pass

    @app.websocket("/websocket", dependencies=[Depends(_synthetic_effective_dependency)])
    async def websocket_handler(websocket: Any) -> None:
        pass

    extractor = FastAPIExtractor(tmp_path / "main.py")
    extractor._app = app
    for original in app.routes:
        direct = extractor._endpoints_from_route(original, "", frozenset())[0]
        assert direct.dependency_graph is not None
        assert direct.dependency_graph.occurrences[0].display_name == (
            "_synthetic_effective_dependency"
        )
        stale = SimpleNamespace(
            dependencies=[
                SimpleNamespace(dependency=_synthetic_old_dependency),
            ]
        )
        wrapper = SimpleNamespace(
            original_route=original,
            starlette_route=original,
            dependant=stale,
            path=original.path,
            endpoint=original.endpoint,
            methods=getattr(original, "methods", None),
            name=original.name,
            tags=getattr(original, "tags", []),
            dependencies=getattr(original, "dependencies", []),
        )
        normalized = extractor._endpoints_from_route(wrapper, "", frozenset())[0]
        assert normalized.dependency_graph is not None
        assert normalized.dependency_graph.occurrences[0].display_name == (
            "_synthetic_effective_dependency"
        )


def test_dependency_graph_rejects_arbitrary_dependency_iterables_without_pulling(
    tmp_path: Path,
) -> None:
    pulls = 0

    def infinite() -> Any:
        nonlocal pulls
        while True:
            pulls += 1
            yield object()

    handler = HandlerInfo(
        name="endpoint", module="main", file_path=tmp_path / "main.py", line_number=1
    )
    extractor = FastAPIExtractor(
        tmp_path / "main.py", dependency_max_nodes=1, dependency_max_work=1
    )
    extractor._app = SimpleNamespace(dependency_overrides={})
    graph = extractor._extract_dependency_graph(
        SimpleNamespace(dependant=SimpleNamespace(dependencies=infinite())), handler
    )
    assert graph.status == DependencyGraphStatus.UNAVAILABLE
    assert pulls == 0

    nested = SimpleNamespace(
        call=_synthetic_effective_dependency,
        dependencies=infinite(),
        own_oauth_scopes=[],
        use_cache=True,
        name=None,
    )
    nested_graph = extractor._extract_dependency_graph(
        SimpleNamespace(dependant=SimpleNamespace(dependencies=[nested])), handler
    )
    assert nested_graph.status == DependencyGraphStatus.CONDITIONAL
    assert pulls == 0
    assert "nested_dependencies_unavailable" in {item.code for item in nested_graph.limitations}


@pytest.mark.parametrize(
    ("keyword", "value"),
    [
        ("dependency_max_depth", 65),
        ("dependency_max_nodes", 4097),
        ("dependency_max_work", 65537),
        ("output_limit_bytes", 64 * 1024 * 1024 + 1),
    ],
)
def test_runtime_dependency_constructor_caps_have_finite_upper_bounds(
    tmp_path: Path, keyword: str, value: int
) -> None:
    with pytest.raises(ValueError, match=r"must not exceed|not exceeding"):
        if keyword == "dependency_max_depth":
            FastAPIExtractor(tmp_path / "main.py", dependency_max_depth=value)
        elif keyword == "dependency_max_nodes":
            FastAPIExtractor(tmp_path / "main.py", dependency_max_nodes=value)
        elif keyword == "dependency_max_work":
            FastAPIExtractor(tmp_path / "main.py", dependency_max_work=value)
        else:
            FastAPIExtractor(tmp_path / "main.py", output_limit_bytes=value)


def test_dependency_security_metadata_is_local_bounded_and_deterministic(
    tmp_path: Path,
) -> None:
    handler = HandlerInfo(
        name="endpoint", module="main", file_path=tmp_path / "main.py", line_number=1
    )
    extractor = FastAPIExtractor(tmp_path / "main.py")
    extractor._app = SimpleNamespace(dependency_overrides={})
    node = SimpleNamespace(
        call=_synthetic_effective_dependency,
        dependencies=[],
        own_oauth_scopes={"write", "read"},
        security_scopes=["inherited"],
        use_cache=True,
        name="value",
    )
    graph = extractor._extract_dependency_graph(
        SimpleNamespace(dependant=SimpleNamespace(dependencies=[node])), handler
    )
    assert graph.occurrences[0].security_scopes == ("read", "write")
    assert graph.occurrences[0].declaration_kind == DependencyDeclarationKind.SECURITY
    assert "security_scopes_unordered_shape" in {item.code for item in graph.limitations}

    del node.own_oauth_scopes
    legacy = extractor._extract_dependency_graph(
        SimpleNamespace(dependant=SimpleNamespace(dependencies=[node])), handler
    )
    assert legacy.occurrences[0].security_scopes == ("inherited",)
    assert legacy.occurrences[0].declaration_kind == DependencyDeclarationKind.DEPENDS_OR_SECURITY

    node.own_oauth_scopes = [1, "x" * 513, *(["retained"] * 254)]
    invalid = extractor._extract_dependency_graph(
        SimpleNamespace(dependant=SimpleNamespace(dependencies=[node])), handler
    )
    assert invalid.occurrences[0].security_scopes == ()
    assert {
        "security_scope_member_invalid",
        "security_scope_string_truncated",
    } <= {item.code for item in invalid.limitations}

    node.own_oauth_scopes = ["retained"] * 257
    over_cap = extractor._extract_dependency_graph(
        SimpleNamespace(dependant=SimpleNamespace(dependencies=[node])), handler
    )
    assert over_cap.occurrences[0].security_scopes == ()
    assert "security_scope_count_truncated" in {item.code for item in over_cap.limitations}

    pulls = 0

    def scopes_generator() -> Any:
        nonlocal pulls
        pulls += 1
        yield "read"

    node.own_oauth_scopes = scopes_generator()
    invalid_shape = extractor._extract_dependency_graph(
        SimpleNamespace(dependant=SimpleNamespace(dependencies=[node])), handler
    )
    assert pulls == 0
    assert "security_scopes_invalid_shape" in {item.code for item in invalid_shape.limitations}


def test_callable_and_scope_metadata_bounds_precede_iteration_and_sorting(
    tmp_path: Path,
) -> None:
    keyword_comparisons = 0
    keyword_member_reads = 0
    scope_comparisons = 0
    scope_member_reads = 0

    class Keyword(str):
        def __lt__(self, other: object) -> bool:
            nonlocal keyword_comparisons
            keyword_comparisons += 1
            return super().__lt__(other)

        def __len__(self) -> int:
            nonlocal keyword_member_reads
            keyword_member_reads += 1
            return super().__len__()

    class Scope(str):
        def __lt__(self, other: object) -> bool:
            nonlocal scope_comparisons
            scope_comparisons += 1
            return super().__lt__(other)

        def __len__(self) -> int:
            nonlocal scope_member_reads
            scope_member_reads += 1
            return super().__len__()

    structured = functools.partial(_synthetic_effective_dependency)
    assert structured.keywords is not None
    for index in range(129):
        structured.keywords[Keyword(f"key_{index:03}")] = index
    scopes = {Scope(f"scope_{index:03}") for index in range(257)}
    keyword_comparisons = keyword_member_reads = 0
    scope_comparisons = scope_member_reads = 0

    node = SimpleNamespace(
        call=structured,
        dependencies=[],
        own_oauth_scopes=scopes,
        use_cache=True,
        name=None,
    )
    handler = HandlerInfo(
        name="endpoint", module="main", file_path=tmp_path / "main.py", line_number=1
    )
    extractor = FastAPIExtractor(
        tmp_path / "main.py", dependency_max_nodes=1, dependency_max_work=1
    )
    extractor._app = SimpleNamespace(dependency_overrides={})
    graph = extractor._extract_dependency_graph(
        SimpleNamespace(dependant=SimpleNamespace(dependencies=[node])), handler
    )

    occurrence = graph.occurrences[0]
    assert occurrence.callable_structure[0].bound_keyword_names == ()
    assert occurrence.security_scopes == ()
    assert keyword_comparisons == keyword_member_reads == 0
    assert scope_comparisons == scope_member_reads == 0
    assert {
        "callable_keyword_names_truncated",
        "security_scope_count_truncated",
        "security_scopes_unordered_shape",
    } <= {item.code for item in graph.limitations}

    for ordered_scopes in ([Scope("read")] * 257, tuple([Scope("read")] * 257)):
        scope_member_reads = 0
        node.own_oauth_scopes = ordered_scopes
        ordered_graph = extractor._extract_dependency_graph(
            SimpleNamespace(dependant=SimpleNamespace(dependencies=[node])), handler
        )
        assert ordered_graph.occurrences[0].security_scopes == ()
        assert scope_member_reads == 0


def test_at_cap_metadata_validates_types_before_sorting(tmp_path: Path) -> None:
    comparisons = 0

    class ComparedString(str):
        def __lt__(self, other: object) -> bool:
            nonlocal comparisons
            comparisons += 1
            return super().__lt__(other)

    structured = functools.partial(_synthetic_effective_dependency)
    assert structured.keywords is not None
    for index in range(127):
        structured.keywords[ComparedString(f"key_{index:03}")] = index
    structured.keywords[1] = "malformed"
    scopes: set[object] = {ComparedString(f"scope_{index:03}") for index in range(255)}
    scopes.add(1)
    comparisons = 0
    node = SimpleNamespace(
        call=structured,
        dependencies=[],
        own_oauth_scopes=scopes,
        use_cache=True,
        name=None,
    )
    handler = HandlerInfo(
        name="endpoint", module="main", file_path=tmp_path / "main.py", line_number=1
    )
    extractor = FastAPIExtractor(
        tmp_path / "main.py", dependency_max_nodes=1, dependency_max_work=1
    )
    extractor._app = SimpleNamespace(dependency_overrides={})

    graph = extractor._extract_dependency_graph(
        SimpleNamespace(dependant=SimpleNamespace(dependencies=[node])), handler
    )

    assert graph.occurrences[0].callable_structure[0].bound_keyword_names == ()
    assert graph.occurrences[0].security_scopes == ()
    assert comparisons == 0
    assert {
        "callable_keyword_names_invalid_shape",
        "security_scope_member_invalid",
    } <= {item.code for item in graph.limitations}


@pytest.mark.parametrize(
    "mutation",
    [
        "registered.keywords[1] = 'malformed-after-registration'",
        "registered.keywords[''] = 'malformed-after-registration'",
    ],
)
def test_post_registration_malformed_partial_metadata_is_graph_local(
    tmp_path: Path, mutation: str
) -> None:
    app_file = tmp_path / "mutated_partial_app.py"
    app_file.write_text(
        "from functools import partial\n"
        "from fastapi import Depends, FastAPI\n\n"
        "def dependency(*, marker=1):\n    return marker\n\n"
        "registered = partial(dependency, marker=1)\n"
        "app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)\n\n"
        "@app.get('/healthy')\n"
        "def healthy():\n    return True\n\n"
        "@app.get('/partial')\n"
        "def endpoint(value=Depends(registered)):\n    return value\n\n"
        "registered.keywords.clear()\n"
        f"{mutation}\n"
    )

    endpoints = FastAPIExtractor(
        app_file, dependency_max_nodes=1, dependency_max_work=1
    ).extract_endpoints()

    assert [endpoint.identifier for endpoint in endpoints] == ["GET /healthy", "GET /partial"]
    partial = next(endpoint for endpoint in endpoints if endpoint.identifier == "GET /partial")
    assert partial.discovery_status.value == "established"
    graph = partial.dependency_graph
    assert graph is not None
    assert graph.status == DependencyGraphStatus.CONDITIONAL
    assert "callable_keyword_names_invalid_shape" in {item.code for item in graph.limitations}
    assert graph.occurrences[0].callable_structure[0].bound_keyword_names == ()


def test_callable_structure_and_display_truncations_condition_graph(tmp_path: Path) -> None:
    def dependency(*args: Any, **kwargs: Any) -> int:
        return len(args) + len(kwargs)

    dependency.__name__ = "d" * 513
    structured: Any = functools.partial(
        dependency,
        *range(1025),
        **{f"key_{index}": index for index in range(129)},
    )
    node = SimpleNamespace(
        call=structured,
        dependencies=[],
        own_oauth_scopes=[],
        use_cache=True,
        name=None,
    )
    display_node = SimpleNamespace(
        call=dependency,
        dependencies=[],
        own_oauth_scopes=[],
        use_cache=True,
        name=None,
    )
    handler = HandlerInfo(
        name="endpoint", module="main", file_path=tmp_path / "main.py", line_number=1
    )
    extractor = FastAPIExtractor(tmp_path / "main.py")
    extractor._app = SimpleNamespace(dependency_overrides={})
    graph = extractor._extract_dependency_graph(
        SimpleNamespace(dependant=SimpleNamespace(dependencies=[node, display_node])), handler
    )
    assert graph.status == DependencyGraphStatus.CONDITIONAL
    assert {
        "callable_positional_count_truncated",
        "callable_keyword_names_truncated",
        "display_name_truncated",
    } <= {item.code for item in graph.limitations}
    partial_occurrence = next(
        occurrence
        for occurrence in graph.occurrences
        if occurrence.callable_kind == DependencyCallableKind.PARTIAL
    )
    assert partial_occurrence.callable_structure[0].bound_keyword_names == ()


def test_security_set_output_is_hash_seed_deterministic(tmp_path: Path) -> None:
    script = f"""
from pathlib import Path
from types import SimpleNamespace
from fastapi_endpoint_detector.models.endpoint import HandlerInfo
from fastapi_endpoint_detector.parser.fastapi_extractor import FastAPIExtractor
node = SimpleNamespace(
    call=len, dependencies=[], own_oauth_scopes={{'write', 'read'}},
    use_cache=True, name='v',
)
extractor = FastAPIExtractor(Path({str(tmp_path / "main.py")!r}))
extractor._app = SimpleNamespace(dependency_overrides={{}})
graph = extractor._extract_dependency_graph(
    SimpleNamespace(dependant=SimpleNamespace(dependencies=[node])),
    HandlerInfo(
        name='handler', module='main',
        file_path=Path({str(tmp_path / "main.py")!r}), line_number=1,
    ),
)
print(graph.occurrences[0].security_scopes)
print(tuple(item.code for item in graph.limitations))
"""
    outputs = []
    for seed in ("1", "2", "3", "4"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = str(Path(__file__).parents[2] / "src")
        outputs.append(
            subprocess.check_output(
                [sys.executable, "-c", script],
                env=environment,
                text=True,
                timeout=10,
            )
        )
    assert len(set(outputs)) == 1


def test_nested_security_scopes_do_not_reclassify_depends_declarations(tmp_path: Path) -> None:
    app_file = tmp_path / "security_app.py"
    app_file.write_text(
        "from fastapi import Depends, FastAPI, Security\n\n"
        "def leaf() -> int:\n    return 1\n\n"
        "def auth(value: int = Depends(leaf)) -> int:\n    return value\n\n"
        "app = FastAPI()\n\n"
        "@app.get('/security')\n"
        "def endpoint(value: int = Security(auth, scopes=['read'])) -> int:\n"
        "    return value\n"
    )
    graph = FastAPIExtractor(app_file).extract_endpoints()[0].dependency_graph
    assert graph is not None
    leaf = next(item for item in graph.occurrences if item.display_name == "leaf")
    assert leaf.declaration_kind == DependencyDeclarationKind.DEPENDS_OR_SECURITY


def test_runtime_worker_payload_limit_fails_controlled(tmp_path: Path) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        """from fastapi import FastAPI
app = FastAPI()
@app.get("/payload")
def payload():
    return {}
"""
    )

    with pytest.raises(FastAPIExtractorError, match="output limit"):
        FastAPIExtractor(app_file, output_limit_bytes=128).extract_endpoints()


def test_runtime_and_secure_extractors_agree_on_static_nested_routes(tmp_path: Path) -> None:
    app_file = tmp_path / "differential_app.py"
    app_file.write_text(
        """from fastapi import APIRouter, FastAPI

inner = APIRouter(prefix="/inner")

@inner.get("/items")
def items():
    return {}

@inner.websocket("/socket")
async def socket(websocket):
    pass

outer = APIRouter(prefix="/outer")
outer.include_router(inner, prefix="/included")
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(outer, prefix="/api")
"""
    )

    runtime_endpoints = FastAPIExtractor(app_file).extract_endpoints()
    secure_endpoints = SecureASTExtractor(
        app_file, app_entry="differential_app:app"
    ).extract_endpoints()

    assert [endpoint.identifier for endpoint in runtime_endpoints] == [
        endpoint.identifier for endpoint in secure_endpoints
    ]


def test_runtime_extractor_preserves_multiple_include_occurrences_and_nested_mounts(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "reused_router_app.py"
    app_file.write_text(
        """from fastapi import APIRouter, FastAPI

shared = APIRouter()

@shared.get("/value")
def value():
    return {}

mounted = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
mounted.include_router(shared, prefix="/one")
mounted.include_router(shared, prefix="/two")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/service", mounted)
"""
    )

    endpoints = FastAPIExtractor(app_file).extract_endpoints()

    assert {endpoint.identifier for endpoint in endpoints} == {
        "GET /service/one/value",
        "GET /service/two/value",
    }


def test_runtime_extractor_handles_root_mounts(tmp_path: Path) -> None:
    app_file = tmp_path / "root_mount_app.py"
    app_file.write_text(
        """from fastapi import FastAPI

mounted = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

@mounted.get("/status")
def status():
    return {}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/", mounted)
"""
    )

    endpoints = FastAPIExtractor(app_file).extract_endpoints()

    assert {endpoint.identifier for endpoint in endpoints} == {"GET /status"}


def test_runtime_extractor_accepts_http_and_websocket_route_subclasses(tmp_path: Path) -> None:
    app_file = tmp_path / "custom_routes_app.py"
    app_file.write_text(
        """from fastapi import FastAPI
from fastapi.routing import APIRoute, APIWebSocketRoute

class AuditRoute(APIRoute):
    pass

class AuditWebSocketRoute(APIWebSocketRoute):
    pass


def custom_http():
    return {}


async def custom_websocket(websocket):
    pass


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.router.routes.append(AuditRoute("/custom", custom_http, methods=["GET"]))
app.router.routes.append(AuditWebSocketRoute("/custom-ws", custom_websocket))
"""
    )

    endpoints = FastAPIExtractor(app_file).extract_endpoints()

    assert {endpoint.identifier for endpoint in endpoints} == {
        "GET /custom",
        "WEBSOCKET /custom-ws",
    }
    assert {endpoint.handler.name for endpoint in endpoints} == {
        "custom_http",
        "custom_websocket",
    }
    assert {endpoint.handler.file_path for endpoint in endpoints} == {app_file}


def test_runtime_extractor_fails_closed_for_unsupported_http_methods(tmp_path: Path) -> None:
    app_file = tmp_path / "unsupported_method_app.py"
    app_file.write_text(
        """from fastapi import FastAPI
from fastapi.routing import APIRoute


def custom_http():
    return {}


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.router.routes.append(APIRoute("/custom", custom_http, methods=["PROPFIND"]))
"""
    )

    with pytest.raises(FastAPIExtractorError, match="Unsupported FastAPI HTTP methods: PROPFIND"):
        FastAPIExtractor(app_file).extract_endpoints()


def test_runtime_extractor_fails_closed_for_unknown_included_router_shape(
    tmp_path: Path,
) -> None:
    class UnknownIncludedRouter:
        original_router = object()
        include_context = object()

    extractor = FastAPIExtractor(tmp_path / "unused.py")
    extractor._app = SimpleNamespace(routes=[UnknownIncludedRouter()])

    with pytest.raises(
        FastAPIExtractorError,
        match="Unsupported included FastAPI router representation",
    ):
        extractor._extract_endpoints_in_process()


def test_runtime_extractor_imports_package_directory_with_relative_routes(tmp_path: Path) -> None:
    package = tmp_path / "runtime_package"
    package.mkdir()
    (package / "__init__.py").write_text(
        """from fastapi import FastAPI
from .routes import router

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)
"""
    )
    routes = package / "routes.py"
    routes.write_text(
        """from fastapi import APIRouter

router = APIRouter()

@router.get("/package")
def package_route():
    return {}
"""
    )

    endpoints = FastAPIExtractor(package).extract_endpoints()

    assert [endpoint.identifier for endpoint in endpoints] == ["GET /package"]
    assert endpoints[0].handler.module == "runtime_package.routes"
    assert endpoints[0].handler.file_path == routes
    assert "runtime_package" not in sys.modules
    assert "runtime_package.routes" not in sys.modules


def test_runtime_extractor_imports_nested_package_file_with_relative_routes(
    tmp_path: Path,
) -> None:
    package = tmp_path / "outer_package"
    nested = package / "api"
    nested.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (nested / "__init__.py").write_text("")
    routes = nested / "routes.py"
    routes.write_text(
        """from fastapi import APIRouter

router = APIRouter()

@router.get("/nested")
def nested_route():
    return {}
"""
    )
    main = nested / "main.py"
    main.write_text(
        """from fastapi import FastAPI
from .routes import router

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)
"""
    )

    endpoints = FastAPIExtractor(main).extract_endpoints()

    assert [endpoint.identifier for endpoint in endpoints] == ["GET /nested"]
    assert endpoints[0].handler.module == "outer_package.api.routes"
    assert endpoints[0].handler.file_path == routes


def test_runtime_extractor_supports_explicit_namespace_module_name(tmp_path: Path) -> None:
    namespace = tmp_path / "runtime_namespace"
    namespace.mkdir()
    routes = namespace / "routes.py"
    routes.write_text(
        """from fastapi import APIRouter

router = APIRouter()

@router.get("/namespace")
def namespace_route():
    return {}
"""
    )
    main = namespace / "main.py"
    main.write_text(
        """from fastapi import FastAPI
from .routes import router

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)
"""
    )

    endpoints = FastAPIExtractor(
        main,
        module_name="runtime_namespace.main",
    ).extract_endpoints()

    assert [endpoint.identifier for endpoint in endpoints] == ["GET /namespace"]
    assert endpoints[0].handler.module == "runtime_namespace.routes"
    assert endpoints[0].handler.file_path == routes


def test_runtime_extractor_isolates_colliding_modules_and_preserves_parent_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "runtime_collision_helper"
    sentinel = ModuleType(module_name)
    sentinel.__dict__["marker"] = "parent"
    monkeypatch.setitem(sys.modules, module_name, sentinel)
    original_path = list(sys.path)

    projects: list[Path] = []
    for project_name, route_path in (("one", "/one"), ("two", "/two")):
        project = tmp_path / project_name
        project.mkdir()
        (project / f"{module_name}.py").write_text(f"ROUTE_PATH = {route_path!r}\n")
        (project / "main.py").write_text(
            f"""from fastapi import FastAPI
from {module_name} import ROUTE_PATH

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

@app.get(ROUTE_PATH)
def endpoint():
    return {{}}
"""
        )
        projects.append(project)

    first = FastAPIExtractor(projects[0] / "main.py").extract_endpoints()
    second = FastAPIExtractor(projects[1] / "main.py").extract_endpoints()

    assert [endpoint.identifier for endpoint in first] == ["GET /one"]
    assert [endpoint.identifier for endpoint in second] == ["GET /two"]
    assert sys.modules[module_name] is sentinel
    assert sentinel.__dict__["marker"] == "parent"
    assert sys.path == original_path


def test_runtime_extractor_reloads_project_modules_on_each_extraction(tmp_path: Path) -> None:
    helper = tmp_path / "runtime_reload_helper.py"
    helper.write_text('ROUTE_PATH = "/before"\n')
    main = tmp_path / "main.py"
    main.write_text(
        """from fastapi import FastAPI
from runtime_reload_helper import ROUTE_PATH

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

@app.get(ROUTE_PATH)
def endpoint():
    return {}
"""
    )
    extractor = FastAPIExtractor(main)

    first = extractor.extract_endpoints()
    helper.write_text('ROUTE_PATH = "/after-change"\n')
    second = extractor.extract_endpoints()

    assert [endpoint.identifier for endpoint in first] == ["GET /before"]
    assert [endpoint.identifier for endpoint in second] == ["GET /after-change"]
    assert "runtime_reload_helper" not in sys.modules


def test_runtime_extractor_ignores_existing_stale_bytecode(tmp_path: Path) -> None:
    helper = tmp_path / "runtime_stale_helper.py"
    helper.write_text('ROUTE_PATH = "/before"\n')
    py_compile.compile(str(helper), doraise=True)
    original_stat = helper.stat()
    helper.write_text('ROUTE_PATH = "/afterx"\n')
    os.utime(helper, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    main = tmp_path / "main.py"
    main.write_text(
        """from fastapi import FastAPI
from runtime_stale_helper import ROUTE_PATH

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

@app.get(ROUTE_PATH)
def endpoint():
    return {}
"""
    )

    endpoints = FastAPIExtractor(main).extract_endpoints()

    assert [endpoint.identifier for endpoint in endpoints] == ["GET /afterx"]


def test_runtime_extractor_failure_and_timeout_leave_parent_state_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "runtime_failure_helper"
    sentinel = ModuleType(module_name)
    monkeypatch.setitem(sys.modules, module_name, sentinel)
    original_path = list(sys.path)
    (tmp_path / f"{module_name}.py").write_text("VALUE = 1\n")
    failing = tmp_path / "failing.py"
    failing.write_text(
        f"""from {module_name} import VALUE
raise RuntimeError(f"failed after import: {{VALUE}}")
"""
    )

    with pytest.raises(FastAPIExtractorError, match="failed after import: 1"):
        FastAPIExtractor(failing).extract_endpoints()

    hanging = tmp_path / "hanging.py"
    hanging.write_text("import time\ntime.sleep(10)\n")
    started = time.monotonic()
    with pytest.raises(FastAPIExtractorError, match="timed out"):
        FastAPIExtractor(hanging, timeout_seconds=0.2).extract_endpoints()

    assert time.monotonic() - started < 5
    assert sys.modules[module_name] is sentinel
    assert sys.path == original_path


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-session cleanup")
def test_runtime_extractor_reaps_worker_when_parent_is_interrupted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app_file = tmp_path / "hanging.py"
    app_file.write_text("import time\ntime.sleep(10)\n")
    worker_pids: list[int] = []

    def interrupt_communicate(
        process: subprocess.Popen[str],
        *_args: object,
        **_kwargs: object,
    ) -> tuple[str, str]:
        worker_pids.append(process.pid)
        raise KeyboardInterrupt

    monkeypatch.setattr(subprocess.Popen, "communicate", interrupt_communicate)

    with pytest.raises(KeyboardInterrupt):
        FastAPIExtractor(app_file).extract_endpoints()

    assert len(worker_pids) == 1
    with pytest.raises(ProcessLookupError):
        os.kill(worker_pids[0], 0)


def test_runtime_extractor_reports_worker_hard_exit(tmp_path: Path) -> None:
    app_file = tmp_path / "hard_exit.py"
    app_file.write_text("import os\nos._exit(7)\n")

    with pytest.raises(FastAPIExtractorError, match="status 7"):
        FastAPIExtractor(app_file).extract_endpoints()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"timeout_seconds": 0}, "timeout_seconds must be a finite positive number"),
        ({"timeout_seconds": float("nan")}, "timeout_seconds must be a finite positive number"),
        ({"timeout_seconds": float("inf")}, "timeout_seconds must be a finite positive number"),
        ({"timeout_seconds": True}, "timeout_seconds must be a finite positive number"),
        ({"output_limit_bytes": 0}, "output_limit_bytes must be a positive integer"),
        ({"output_limit_bytes": 1.5}, "output_limit_bytes must be a positive integer"),
        ({"output_limit_bytes": True}, "output_limit_bytes must be a positive integer"),
    ],
)
def test_runtime_extractor_rejects_invalid_worker_limits(
    tmp_path: Path,
    kwargs: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        FastAPIExtractor(tmp_path / "main.py", **kwargs)
