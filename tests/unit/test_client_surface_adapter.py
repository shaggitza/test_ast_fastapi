"""Tests for the opt-in bounded TypeScript/Svelte client adapter."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.client_surface_adapter import (
    MAX_CLIENT_SOURCE_BYTES,
    analyze_client_source,
    extract_client_references,
    join_client_references,
)
from fastapi_endpoint_detector.config import AnalysisConfig, Config
from fastapi_endpoint_detector.models.diff import ChangeType, DiffFile, DiffHunk
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointDiscoveryCondition,
    EndpointDiscoveryStatus,
    EndpointMethod,
    HandlerInfo,
)


def endpoint(
    method: EndpointMethod,
    path: str,
    *,
    conditional: bool = False,
    line: int = 1,
) -> Endpoint:
    conditions = (
        (
            EndpointDiscoveryCondition(
                source_path=Path("app.py"),
                source_line=line,
                reason="dynamic registration",
            ),
        )
        if conditional
        else ()
    )
    return Endpoint(
        path=path,
        methods=[method],
        handler=HandlerInfo(
            name=f"handler_{line}",
            module="app",
            file_path=Path("app.py"),
            line_number=line,
        ),
        discovery_status=(
            EndpointDiscoveryStatus.CONDITIONAL
            if conditional
            else EndpointDiscoveryStatus.ESTABLISHED
        ),
        discovery_conditions=conditions,
    )


def test_extracts_literal_fetch_axios_and_websocket_without_comments_or_strings() -> None:
    source = """
import axios from "axios";
// fetch("/comment")
const text = 'axios.delete("/inside-string")';
fetch("/items?limit=2", { method: "POST" });
axios.get('/health');
new WebSocket("wss://api.example.test/events?token=redacted");
fetch(dynamicUrl);
fetch('/unsafe', { method: dynamicMethod });
fetch('/nested', { headers: { method: "POST" } });
fetch('/spread', { ...options });
fetch('/dynamic-options', options);
"""

    references, limitations = extract_client_references(
        source,
        Path("ui/client.ts"),
        allowed_hosts=("api.example.test",),
    )

    assert [(item.method.value, item.normalized_path) for item in references] == [
        ("POST", "/items"),
        ("GET", "/health"),
        ("WEBSOCKET", "/events"),
        ("GET", "/nested"),
    ]
    assert references[0].raw_url == "/items?<redacted>"
    assert references[2].raw_url == "wss://api.example.test/events?<redacted>"
    assert any("dynamic fetch URL" in item for item in limitations)
    assert sum("dynamic or invalid fetch method" in item for item in limitations) == 3


@pytest.mark.parametrize("key", ["'method'", '"method"'])
def test_fetch_parses_exact_quoted_method_keys(key: str) -> None:
    references, limitations = extract_client_references(
        f"fetch('/items', {{{key}: 'POST'}})", Path("client.ts")
    )

    assert [(item.method.value, item.normalized_path) for item in references] == [
        ("POST", "/items")
    ]
    assert limitations == ()


@pytest.mark.parametrize(
    "options",
    [
        "{method: 'GET', 'method': 'POST'}",
        "{'method': 'POST', method: 'POST'}",
        "{'method': dynamicMethod}",
        "{['method']: 'POST'}",
    ],
)
def test_fetch_abstains_on_duplicate_or_ambiguous_method_options(options: str) -> None:
    references, limitations = extract_client_references(
        f"fetch('/items', {options})", Path("client.ts")
    )

    assert references == ()
    assert any("dynamic or invalid fetch method" in item for item in limitations)


def test_fetch_quoted_method_key_is_case_sensitive() -> None:
    references, limitations = extract_client_references(
        "fetch('/items', {'METHOD': 'POST'})", Path("client.ts")
    )

    assert [(item.method.value, item.normalized_path) for item in references] == [
        ("GET", "/items")
    ]
    assert limitations == ()


def test_absolute_hosts_are_exact_and_external_urls_do_not_fan_out() -> None:
    source = """
<script>
fetch("https://allowed.example/items");
fetch("https://external.example/items");
fetch("https://[invalid/items");
new WebSocket("ws://allowed.example/ws");
</script>
"""
    analysis = analyze_client_source(
        source,
        Path("src/view.svelte"),
        [
            endpoint(EndpointMethod.GET, "/items"),
            endpoint(EndpointMethod.WEBSOCKET, "/ws", line=2),
        ],
        allowed_hosts=("allowed.example",),
    )

    assert [item.endpoint.identifier for item in analysis.matches] == [
        "GET /items",
        "WEBSOCKET /ws",
    ]
    assert any("external.example" in item for item in analysis.limitations)
    assert any("<invalid-url>" in item for item in analysis.limitations)


def test_join_requires_one_established_explicit_server_surface() -> None:
    references, _limitations = extract_client_references('fetch("/items/42")', Path("client.ts"))
    matches, limitations = join_client_references(
        references,
        [
            endpoint(EndpointMethod.GET, "/items/{item_id}"),
            endpoint(EndpointMethod.GET, "/items/{other}", line=2),
            endpoint(EndpointMethod.GET, "/items/42", conditional=True, line=3),
        ],
    )

    assert matches == ()
    assert len(limitations) == 1
    assert "multiple server surfaces" in limitations[0]


def test_reference_limit_is_atomic_and_reported() -> None:
    references, limitations = extract_client_references(
        "\n".join(f'fetch("/item/{index}")' for index in range(4)),
        Path("client.ts"),
        max_references=2,
    )

    assert len(references) == 2
    assert any("reference limit 2 reached" in item for item in limitations)


def test_analysis_config_is_opt_in_and_hosts_are_exact() -> None:
    assert not AnalysisConfig().typescript_client_adapter
    with pytest.raises(ValueError, match="unique exact hosts"):
        AnalysisConfig(client_surface_allowed_hosts=("*.example.test",))
    with pytest.raises(ValueError, match="unique exact hosts"):
        AnalysisConfig(client_surface_allowed_hosts=("HOST", "host"))


def test_change_mapper_maps_only_changed_joined_calls_and_keeps_orphans(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/items')\n"
        "def items(): pass\n"
        "@app.websocket('/events')\n"
        "async def events(socket): pass\n",
        encoding="utf-8",
    )
    (tmp_path / "client.ts").write_text(
        'fetch("/items?limit=1", { method: "POST" });\n'
        'new WebSocket("ws://local.test/events");\n'
        "fetch(dynamicUrl);\n"
        'fetch("https://external.test/items", { method: "POST" });\n'
        '// fetch("/items", { method: "POST" });\n',
        encoding="utf-8",
    )
    diff_file = DiffFile(
        path=Path("client.ts"),
        change_type=ChangeType.MODIFIED,
        hunks=[
            DiffHunk(
                source_start=1,
                source_length=0,
                target_start=1,
                target_length=5,
                added_lines=[1, 2, 3, 4, 5],
            )
        ],
    )
    mapper = ChangeMapper(
        tmp_path,
        Config(
            analysis=AnalysisConfig(
                typescript_client_adapter=True,
                client_surface_allowed_hosts=("local.test",),
            )
        ),
        secure_ast=True,
        use_cache=False,
    )
    warnings: list[str] = []

    affected, orphans = mapper._analyze_client_surface_changes([diff_file], warnings)

    assert {item.endpoint.identifier for item in affected} == {
        "POST /items",
        "WEBSOCKET /events",
    }
    post = next(item for item in affected if item.endpoint.identifier == "POST /items")
    assert "/items?<redacted>" in post.reason
    assert "limit=1" not in post.reason
    assert post.dependency_chain == [
        "client:POST /items?<redacted>",
        "server:POST /items",
    ]
    assert len(orphans) == 1
    assert orphans[0].added_lines == [3, 4, 5]
    assert any("dynamic fetch URL" in item for item in warnings)
    assert any("external.test" in item for item in warnings)


def test_full_report_includes_opt_in_client_candidate(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/health')\ndef health(): pass\n",
        encoding="utf-8",
    )
    (tmp_path / "client.ts").write_text(
        'fetch("/health?verbose=1");\n',
        encoding="utf-8",
    )
    diff = """diff --git a/client.ts b/client.ts
index 1111111..2222222 100644
--- a/client.ts
+++ b/client.ts
@@ -0,0 +1 @@
+fetch("/health?verbose=1");
"""
    mapper = ChangeMapper(
        tmp_path,
        Config(analysis=AnalysisConfig(typescript_client_adapter=True)),
        secure_ast=True,
        use_cache=False,
    )

    report = mapper.analyze_diff(diff)

    assert [item.endpoint.identifier for item in report.candidate_endpoints] == ["GET /health"]
    assert "/health?<redacted>" in report.candidate_endpoints[0].reason
    assert "verbose=1" not in report.candidate_endpoints[0].reason
    assert report.orphan_changes == []


def test_svelte_scans_only_complete_bounded_script_regions() -> None:
    source = """<!-- fetch('/comment') -->
<p data-call="<script>fetch('/attribute')</script>">fetch('/text')</p>
{fetch('/markup-expression')}
{ "<script>fetch('/expression-string')</script>" }
<script>fetch('/instance')</script>
<script context="module">
fetch('/module')
</script>
"""

    references, limitations = extract_client_references(source, Path("View.svelte"))

    assert [item.normalized_path for item in references] == ["/instance", "/module"]
    assert [item.start_line for item in references] == [5, 7]
    assert any("markup expressions are unresolved" in item for item in limitations)


@pytest.mark.parametrize(
    "source, limitation",
    [
        ("function fetch(url) {}\nfetch('/health')", "fetch binding is shadowed"),
        ("function run(fetch) { fetch('/health') }", "fetch binding is shadowed"),
        ("const api = { fetch() {} };\napi.fetch('/health')", "fetch binding is shadowed"),
        (
            "const WebSocket = function () {};\nnew WebSocket('/events')",
            "WebSocket binding is shadowed",
        ),
        ("import { default as axios } from 'axios';\naxios.get('/health')", "axios binding is not"),
        (
            "import axios from 'axios';\nfunction run(axios) { axios.get('/health') }",
            "axios binding is not",
        ),
        (
            "import * as axios from 'axios';\naxios.get('/health')",
            "axios binding is not",
        ),
    ],
)
def test_shadowed_member_and_ambiguous_bindings_abstain(source: str, limitation: str) -> None:
    references, limitations = extract_client_references(source, Path("client.ts"))

    assert references == ()
    assert any(limitation in item for item in limitations)


@pytest.mark.parametrize(
    "path, source",
    [
        (
            "component.jsx",
            "export function View() { return <div>fetch('/health')</div>; }",
        ),
        (
            "component.tsx",
            "export function View() { return <span>fetch('/health')</span>; }",
        ),
    ],
)
def test_jsx_and_tsx_abstain_instead_of_scanning_rendered_text(
    path: str, source: str
) -> None:
    references, limitations = extract_client_references(source, Path(path))

    assert references == ()
    assert any("rendered text" in item for item in limitations)


def test_axios_requires_an_exact_import_or_require_binding() -> None:
    esm, _ = extract_client_references(
        "import axios from 'axios';\naxios.post('/items')", Path("esm.ts")
    )
    cjs, _ = extract_client_references(
        "const axios = require(\"axios\");\naxios.get('/health')", Path("cjs.js")
    )
    alias, _ = extract_client_references(
        "import axiosAlias from 'axios';\naxiosAlias.get('/health')", Path("alias.ts")
    )

    assert [(item.method.value, item.normalized_path) for item in esm] == [("POST", "/items")]
    assert [(item.method.value, item.normalized_path) for item in cjs] == [("GET", "/health")]
    assert alias == ()


@pytest.mark.parametrize(
    "source",
    [
        (
            "function require(name) { return fake(name); }\n"
            "const axios = require('axios');\naxios.get('/health')"
        ),
        "import axios from 'axios';\naxios.GET('/health')",
        "const axios = require('axios');\naxios.Post('/items')",
    ],
)
def test_axios_abstains_on_shadowed_require_or_non_lowercase_methods(source: str) -> None:
    references, limitations = extract_client_references(source, Path("client.ts"))

    assert references == ()
    assert any("axios binding is not" in item for item in limitations)


@pytest.mark.parametrize(
    "route, valid_path, invalid_paths",
    [
        ("/i/{value:int}", "/i/123", ("/i/\u0661", "/i/-1", "/i/1.0")),
        ("/f/{value:float}", "/f/12.50", ("/f/nan", "/f/-1", "/f/1.")),
        (
            "/v/{value:uuid}",
            "/v/123e4567-e89b-12d3-a456-426614174000",
            ("/v/not-a-uuid", "/v/123e4567-e89b-12d3-a456-42661417400"),
        ),
        ("/s/{value:str}", "/s/text", ("/s/", "/s/a/b")),
        ("/files/{value:path}", "/files/a/b", ("/files",)),
    ],
)
def test_starlette_converters_match_only_exact_supported_semantics(
    route: str, valid_path: str, invalid_paths: tuple[str, ...]
) -> None:
    paths = (valid_path, *invalid_paths)
    references, _ = extract_client_references(
        "\n".join(f"fetch('{path}')" for path in paths), Path("client.ts")
    )
    matches, _ = join_client_references(references, [endpoint(EndpointMethod.GET, route)])

    assert [item.reference.normalized_path for item in matches] == [valid_path]


def test_starlette_uuid_converter_accepts_each_optional_hyphen() -> None:
    paths = (
        "/v/123e4567e89b12d3a456426614174000",
        "/v/123e4567-e89b12d3-a456426614174000",
    )
    references, _ = extract_client_references(
        "\n".join(f"fetch('{path}')" for path in paths), Path("client.ts")
    )
    matches, _ = join_client_references(
        references, [endpoint(EndpointMethod.GET, "/v/{value:uuid}")]
    )

    assert [item.reference.normalized_path for item in matches] == list(paths)


def test_http_and_websocket_trailing_slashes_are_distinct() -> None:
    http_references, _ = extract_client_references("fetch('/x/')", Path("client.ts"))
    websocket_references, _ = extract_client_references(
        "new WebSocket('/events/')", Path("client.ts")
    )

    http_matches, _ = join_client_references(
        http_references, [endpoint(EndpointMethod.GET, "/x")]
    )
    websocket_matches, _ = join_client_references(
        websocket_references, [endpoint(EndpointMethod.WEBSOCKET, "/events")]
    )

    assert http_matches == ()
    assert websocket_matches == ()


def test_url_evidence_redacts_credentials_query_and_fragment() -> None:
    references, limitations = extract_client_references(
        'fetch("https://user:password@api.example.test/health?token=secret#private")',
        Path("client.ts"),
        allowed_hosts=("api.example.test",),
    )

    assert references[0].raw_url == "https://api.example.test/health?<redacted>#<redacted>"
    evidence = "\n".join((references[0].raw_url, *limitations))
    assert "password" not in evidence
    assert "token=secret" not in evidence
    assert "private" not in evidence


def test_change_mapper_reads_at_most_max_plus_one_bytes(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    (tmp_path / "client.ts").write_bytes(b" " * (MAX_CLIENT_SOURCE_BYTES + 2))
    diff_file = DiffFile(
        path=Path("client.ts"),
        change_type=ChangeType.MODIFIED,
        hunks=[
            DiffHunk(
                source_start=1,
                source_length=0,
                target_start=1,
                target_length=1,
                added_lines=[1],
            )
        ],
    )
    mapper = ChangeMapper(
        tmp_path,
        Config(analysis=AnalysisConfig(typescript_client_adapter=True)),
        secure_ast=True,
        use_cache=False,
    )
    warnings: list[str] = []

    affected, orphans = mapper._analyze_client_surface_changes([diff_file], warnings)

    assert affected == []
    assert len(orphans) == 1
    assert any(f"exceeds {MAX_CLIENT_SOURCE_BYTES} bytes" in item for item in warnings)


def test_readme_does_not_claim_deployment_evidence_is_implemented() -> None:
    readme = (Path(__file__).parents[2] / "README.md").read_text(encoding="utf-8")

    assert "Deployment/configuration and environment evidence\nis **not implemented" in readme
    assert "deployment configuration, and environment expansion\nremain explicit" not in readme


def test_disabled_adapter_returns_no_cross_language_evidence(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, Config(), secure_ast=True, use_cache=False)
    warnings: list[str] = []

    affected, orphans = mapper._analyze_client_surface_changes([], warnings)

    assert affected == []
    assert orphans == []
    assert warnings == []
