from pathlib import Path

from fastapi_endpoint_detector.analyzer.client_observations import (
    EstablishedSurface,
    extract_client_observation_inventory,
    extract_client_observations,
    join_established_surfaces,
)


def test_axios_aliases_are_invalidated_by_rebinding_and_local_parameters() -> None:
    surfaces = (EstablishedSurface("admin", "/admin", "GET", "https://api.test", True),)
    for source in (
        "import http from 'axios'; http = client; http.get('https://api.test/admin');",
        "import http from 'axios'; function f(http) { http.get('https://api.test/admin'); }",
        "function f(http) { http.get('https://api.test/admin'); } import http from 'axios';",
        "import * as http from 'axios'; const f = (http) => http.get('https://api.test/admin');",
        "import http from 'axios'; http++; http.get('https://api.test/admin');",
    ):
        observations = extract_client_observations(source)
        assert observations == (), source
        assert join_established_surfaces(observations, surfaces) == (), source
    observations = extract_client_observations(
        "import http from 'axios'; http.get('https://api.test/admin');"
    )
    assert len(observations) == 1
    assert [item.surface_id for item in join_established_surfaces(observations, surfaces)] == [
        "admin"
    ]


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


def test_dynamic_urls_and_unknown_request_options_are_uncertainties_only() -> None:
    source = (
        "fetch(`${base}/items`); "
        "fetch('/items', options); "
        "axios.get('/items', options); "
        "axios.post('/items', body); "
        "axios({method: 'GET', url: '/reversed'}); "
        "axios({url: '/extra', method: 'GET', headers});"
    )
    exact, uncertain = extract_client_observation_inventory(source, Path("client.ts"))
    assert [(item.method, item.route_path) for item in exact] == [
        ("POST", "/items"),
        ("GET", "/reversed"),
    ]
    assert [item.reason for item in uncertain] == [
        "dynamic_or_nonliteral_url",
        "dynamic_or_unsupported_request_options",
        "unsupported_or_dynamic_request_options",
        "unsupported_or_dynamic_axios_options",
    ]
    assert all(item.start_offset < item.end_offset for item in uncertain)


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


def test_malformed_absolute_authorities_remain_span_bearing_uncertainties() -> None:
    invalid_urls = (
        "https://:80/items",
        "https://api.example:bad/items",
        "https://api.example:0/items",
        "https://api.example:65536/items",
        "https://api.example:/items",
        "https://api .example/items",
        "wss://:443/events",
    )
    source = "\n".join(f"fetch('{url}');" for url in invalid_urls)
    observations, issues = extract_client_observation_inventory(source, Path("client.ts"))
    assert observations == ()
    assert len(issues) == len(invalid_urls)
    assert all(issue.reason == "unsupported_url" for issue in issues)
    assert all(
        source[issue.start_offset : issue.end_offset].startswith("fetch(") for issue in issues
    )


def test_exact_absolute_authorities_accept_boundary_ports_and_ipv6() -> None:
    observations = extract_client_observations(
        "fetch('https://api.example:1/items'); "
        "fetch('https://api.example:65535/items'); "
        "new WebSocket('wss://[::1]:443/events');"
    )
    assert [item.origin for item in observations] == [
        "https://api.example:1",
        "https://api.example:65535",
        "wss://[::1]:443",
    ]


def test_nonassignment_operators_do_not_shadow_supported_client_calls() -> None:
    for operator in (
        "==",
        "===",
        "!=",
        "!==",
        "||",
        "&&",
        "??",
        "+",
        "-",
        "*",
        "/",
        "%",
        "|",
        "&",
        "^",
        "<",
        ">",
        "<<",
        ">>",
    ):
        observations = extract_client_observations(
            f"fetch {operator} fallback; axios {operator} client; WebSocket {operator} socket; "
            "fetch('/fetch'); axios.get('/axios'); new WebSocket('wss://api.test/events');"
        )
        assert [item.route_path for item in observations] == ["/fetch", "/axios", "/events"], (
            operator
        )


def test_complete_assignment_and_mutation_operators_shadow_client_globals() -> None:
    for operator in (
        "=",
        "+=",
        "-=",
        "*=",
        "/=",
        "%=",
        "**=",
        "&=",
        "|=",
        "^=",
        "&&=",
        "||=",
        "??=",
        "<<=",
        ">>=",
        ">>>=",
        "++",
        "--",
    ):
        if operator in {"++", "--"}:
            mutation = f"fetch{operator}; axios{operator}; WebSocket{operator}; "
        else:
            mutation = f"fetch {operator} fallback; axios {operator} client; "
            mutation += f"WebSocket {operator} socket; "
        observations = extract_client_observations(
            mutation
            + "fetch('/fetch'); axios.get('/axios'); new WebSocket('wss://api.test/events');"
        )
        assert observations == (), operator


def test_fetch_constructor_cannot_join_a_trusted_http_surface() -> None:
    observations = extract_client_observations(
        "new fetch('https://api.test/items'); fetch('https://api.test/items');"
    )
    assert len(observations) == 1
    assert observations[0].start_offset == 37
    surfaces = (EstablishedSurface("items", "/items", "GET", "https://api.test", True),)
    assert len(join_established_surfaces(observations, surfaces)) == 1


def test_prefix_mutation_invalidates_client_globals() -> None:
    for operator in ("++", "--"):
        for space in ("", " "):
            observations = extract_client_observations(
                f"{operator}{space}fetch; {operator}{space}axios; {operator}{space}WebSocket; "
                "fetch('/fetch'); axios.get('/axios'); new WebSocket('wss://api.test/events');"
            )
            assert observations == (), (operator, space)


def test_separate_unary_operators_do_not_count_as_prefix_mutation() -> None:
    observations = extract_client_observations(
        "+ +fetch; - -axios; + +WebSocket; "
        "fetch('/fetch'); axios.get('/axios'); new WebSocket('wss://api.test/events');"
    )
    assert [item.route_path for item in observations] == ["/fetch", "/axios", "/events"]
