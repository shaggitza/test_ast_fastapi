from pathlib import Path

from fastapi_endpoint_detector.analyzer.client_observations import (
    EstablishedSurface,
    extract_client_observations,
    join_established_surfaces,
)


def test_extracts_finite_http_websocket_calls_and_keeps_query_evidence() -> None:
    source = r"""
fetch("https://api.example.test/items?limit=10");
axios.post('/items', payload);
axios({ url: '/items', method: 'PATCH' });
new WebSocket('wss://socket.example.test/events?token=abc');
fetch(`/items/${item}`);
fetch(baseUrl + "/items");
"""
    observations = extract_client_observations(source, Path("client.ts"))
    assert [(item.method, item.route_path, item.query) for item in observations] == [
        ("GET", "/items", "limit=10"),
        ("POST", "/items", None),
        ("PATCH", "/items", None),
        ("WEBSOCKET", "/events", "token=abc"),
    ]
    assert all(item.source_path == Path("client.ts") for item in observations)


def test_join_requires_exact_explicit_surface_id_and_method() -> None:
    observations = extract_client_observations(
        "fetch('https://api.test/items?q=1'); fetch('/admin');"
    )
    surfaces = (
        EstablishedSurface("server:items:get", "/items", "GET", "https://api.test", True),
        EstablishedSurface("server:items:post", "/items", "POST", "https://api.test", True),
    )
    matches = join_established_surfaces(observations, surfaces)
    assert [(item.surface_id, item.observation.query) for item in matches] == [
        ("server:items:get", "q=1")
    ]


def test_scanner_skips_comments_strings_dynamic_calls_receivers_and_unknown_options() -> None:
    source = """
// fetch('/admin')
const text = "fetch('/admin')";
const pattern = /fetch[(].*admin[)]/g;
fetch('/items' + suffix);
client.fetch('/admin');
fetch('/items', dynamicOptions);
fetch('/real'); fetch('/real');
"""
    calls = extract_client_observations(source)
    assert [item.route_path for item in calls] == ["/real", "/real"]
    assert calls[0].start_offset != calls[1].start_offset


def test_fetch_requires_exact_literal_method_options_and_join_needs_origin_trust() -> None:
    calls = extract_client_observations(
        "fetch('/items', {method: 'POST'}); fetch('/x', {method:'GET', headers: h}); fetch('https://api.test/items?q=1');"
    )
    assert [(item.method, item.route_path) for item in calls] == [
        ("POST", "/items"),
        ("GET", "/items"),
    ]
    relative = calls[0]
    absolute = calls[1]
    surfaces = (
        EstablishedSurface("untrusted", "/items", "POST", "https://api.test", False),
        EstablishedSurface("trusted", "/items", "GET", "https://api.test", True),
    )
    assert [
        item.surface_id for item in join_established_surfaces((relative, absolute), surfaces)
    ] == ["trusted"]
    calls = extract_client_observations("fetch('https://api.test/items?q=1');")
    matches = join_established_surfaces(calls, surfaces)
    assert [item.surface_id for item in matches] == ["trusted"]


def test_svelte_scans_script_blocks_only() -> None:
    source = """<p>fetch('/markup')</p>
<script lang="ts">
fetch('https://api.test/from-script');
</script>"""
    calls = extract_client_observations(source, Path("Component.svelte"))
    assert [item.route_path for item in calls] == ["/from-script"]
    assert calls[0].line == 3


def test_axios_receiver_access_is_not_misclassified_as_global() -> None:
    source = """
axios.get('/global-method');
axios({url: '/global-config', method: 'GET'});
client.axios.get('/member-method');
client?.axios.get('/optional-method');
client[axios].get('/computed-method');
client?.[axios].get('/optional-computed-method');
client.axios({url: '/member-config', method: 'GET'});
client?.axios({url: '/optional-config', method: 'GET'});
client['axios']({url: '/computed-config', method: 'GET'});
client?.[axios]({url: '/optional-computed-config', method: 'GET'});
"""
    calls = extract_client_observations(source)
    assert [item.route_path for item in calls] == ["/global-method", "/global-config"]


def test_nested_supported_calls_survive_rejected_dynamic_outer_calls() -> None:
    source = """
fetch(buildUrl(axios.get('/nested-axios'), suffix));
axios({url: chooseUrl(), method: 'GET', extra: fetch('/nested-fetch')});
fetch('/unrelated' + suffix);
"""
    calls = extract_client_observations(source)
    assert [(item.method, item.route_path) for item in calls] == [
        ("GET", "/nested-axios"),
        ("GET", "/nested-fetch"),
    ]


def test_shadowed_client_globals_are_not_exact_or_joinable() -> None:
    source = """
function f(fetch) { fetch('https://api.test/admin'); }
function g(axios) { axios.get('https://api.test/admin'); }
function h(WebSocket) { new WebSocket('wss://api.test/admin'); }
const before = fetch('https://api.test/items');
let axios = client;
axios.get('https://api.test/items');
"""
    observations = extract_client_observations(source)
    trusted = EstablishedSurface("server:admin", "/admin", "GET", "https://api.test", True)
    assert observations == ()
    assert join_established_surfaces(observations, (trusted,)) == ()


def test_unshadowed_browser_and_canonical_axios_imports_remain_supported() -> None:
    observations = extract_client_observations(
        "fetch('https://api.test/items'); "
        "import http from 'axios'; http.get('https://api.test/items');"
    )
    assert [(item.method, item.route_path) for item in observations] == [
        ("GET", "/items"),
        ("GET", "/items"),
    ]


def test_parenthesized_arrow_and_destructured_parameters_shadow_client_globals() -> None:
    source = """
(fetch) => fetch('https://api.test/a');
(axios) => axios.get('https://api.test/a');
({fetch}) => fetch('https://api.test/b');
({client: axios}) => axios.get('https://api.test/c');
"""
    observations = extract_client_observations(source)
    server = EstablishedSurface("server:a", "/a", "GET", "https://api.test", True)
    assert observations == ()
    assert join_established_surfaces(observations, (server,)) == ()
