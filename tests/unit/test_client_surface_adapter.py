"""Tests for the opt-in bounded TypeScript/Svelte client adapter."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.client_surface_adapter import (
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
    assert references[0].raw_url == "/items?limit=2"
    assert references[2].raw_url.endswith("?token=redacted")
    assert any("dynamic fetch URL" in item for item in limitations)
    assert sum("dynamic or invalid fetch method" in item for item in limitations) == 3


def test_absolute_hosts_are_exact_and_external_urls_do_not_fan_out() -> None:
    source = """
fetch("https://allowed.example/items");
fetch("https://external.example/items");
fetch("https://[invalid/items");
new WebSocket("ws://allowed.example/ws");
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
    assert any("https://[invalid/items" in item for item in analysis.limitations)


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
    assert "/items?limit=1" in post.reason
    assert post.dependency_chain == [
        "client:POST /items?limit=1",
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
    assert "/health?verbose=1" in report.candidate_endpoints[0].reason
    assert report.orphan_changes == []


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
