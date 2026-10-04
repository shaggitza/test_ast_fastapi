from pathlib import Path

from fastapi_endpoint_detector.analyzer.client_observations import (
    EstablishedSurface,
    extract_client_observations,
    join_established_surfaces,
)


def test_extracts_finite_http_websocket_calls_and_keeps_query_evidence() -> None:
    source = '''
fetch("https://api.example.test/items?limit=10");
axios.post('/items', payload);
axios({ url: '/items', method: 'PATCH' });
new WebSocket('wss://socket.example.test/events?token=abc');
fetch(`/items/${item}`);
fetch(baseUrl + "/items");
'''
    observations = extract_client_observations(source, Path("client.ts"))
    assert [(item.method, item.route_path, item.query) for item in observations] == [
        ("GET", "/items", "limit=10"),
        ("POST", "/items", None),
        ("PATCH", "/items", None),
        ("WEBSOCKET", "/events", "token=abc"),
    ]
    assert all(item.source_path == Path("client.ts") for item in observations)


def test_join_requires_exact_explicit_surface_id_and_method() -> None:
    observations = extract_client_observations("fetch('/items?q=1'); fetch('/admin');")
    surfaces = (
        EstablishedSurface("server:items:get", "/items", "GET"),
        EstablishedSurface("server:items:post", "/items", "POST"),
    )
    matches = join_established_surfaces(observations, surfaces)
    assert [(item.surface_id, item.observation.query) for item in matches] == [
        ("server:items:get", "q=1")
    ]
