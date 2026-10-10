"""Regression coverage for escaped client URL string literals."""

from __future__ import annotations

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.client_observations import (
    EstablishedSurface,
    extract_client_observation_inventory,
    join_established_surfaces,
)


def test_escaped_url_literals_remain_span_bearing_uncertainty() -> None:
    source = r"""fetch('/api\u002fitems')
fetch('/api\x2fitems')
fetch('/api\/items')
fetch('/api\'items')
fetch('/api\nitems')
fetch('/api\
items')
axios.get('/api\u002fitems')
axios({url: '/api\x2fitems', method: 'GET'})
new WebSocket('wss://api.example.test/ws\/items')
"""
    observations, issues = extract_client_observation_inventory(source, Path("client.js"))

    assert observations == ()
    assert len(issues) == 9
    assert {issue.reason for issue in issues} == {"escaped_url_literal"}
    assert all(issue.source_path == Path("client.js") for issue in issues)
    assert all(issue.start_offset < issue.end_offset for issue in issues)
    assert all(
        source[issue.start_offset : issue.end_offset].startswith(
            ("fetch(", "axios.", "axios(", "new WebSocket(")
        )
        for issue in issues
    )
    surfaces = (
        EstablishedSurface(
            "api",
            "/api/items",
            "GET",
            origin="https://api.example.test",
            trusted=True,
        ),
    )
    assert join_established_surfaces(observations, surfaces) == ()


def test_unescaped_literal_url_still_joins_trusted_surface() -> None:
    source = "fetch('https://api.example.test/api/items')"
    observations, issues = extract_client_observation_inventory(source, Path("client.js"))

    assert issues == ()
    assert len(observations) == 1
    assert observations[0].route_path == "/api/items"
    assert observations[0].literal_url == "https://api.example.test/api/items"
    surfaces = (
        EstablishedSurface(
            "api",
            "/api/items",
            "GET",
            origin="https://api.example.test",
            trusted=True,
        ),
    )
    matches = join_established_surfaces(observations, surfaces)
    assert len(matches) == 1
    assert matches[0].surface_id == "api"


def test_postfix_mutation_before_newline_does_not_shadow_client_globals() -> None:
    source = (
        "counter++\nfetch('/items')\n"
        "counter-- /* trailing comment */\naxios.get('/users')\n"
        "counter++ // line comment\nnew WebSocket('wss://api.example.test/events')\n"
    )
    observations, issues = extract_client_observation_inventory(source, Path("client.js"))

    assert issues == ()
    assert [item.route_path for item in observations] == ["/items", "/users", "/events"]
    assert [item.line for item in observations] == [2, 4, 6]


@pytest.mark.parametrize(
    ("source", "route"),
    [
        ("counter ++\nfetch('/items')", "/items"),
        ("obj[key] /*comment*/ --\naxios.get('/users')", "/users"),
        ("(counter) ++ /* comment */\nnew WebSocket('wss://api.example.test/events')", "/events"),
        ("`counter` --\nfetch('/template')", "/template"),
        ("counter /*comment*/ ++\nfetch('/line-comment')", "/line-comment"),
    ],
)
def test_postfix_operator_without_intervening_line_terminator_is_not_a_shadow(
    source: str, route: str
) -> None:
    observations, issues = extract_client_observation_inventory(source, Path("client.js"))

    assert issues == ()
    assert [item.route_path for item in observations] == [route]


@pytest.mark.parametrize(
    "source",
    [
        "++fetch; fetch('/prefix')",
        "--axios; axios.get('/prefix')",
        "--WebSocket; new WebSocket('wss://api.example.test/prefix')",
        "counter\n++fetch; fetch('/prefix')",
        "function f(){return ++fetch;} fetch('/prefix')",
        "if (ready) ++fetch; fetch('/prefix')",
        "while (ready) --axios; axios.get('/prefix')",
        "if (ready) {} else --WebSocket; new WebSocket('wss://api.example.test/prefix')",
        "++fetch('/prefix')",
        "counter\n++fetch('/prefix')",
        "counter /*\ncomment*/ ++fetch('/prefix')",
        "--axios.get('/prefix')",
        "--WebSocket\nnew WebSocket('/prefix')",
    ],
)
def test_prefix_mutation_shadows_only_its_client_global(source: str) -> None:
    observations, _issues = extract_client_observation_inventory(source, Path("client.js"))

    assert observations == ()


def test_assignment_still_shadows_fetch_globally() -> None:
    source = "fetch('/before'); fetch = customFetch; fetch('/after')"
    observations, _issues = extract_client_observation_inventory(source, Path("client.js"))

    assert observations == ()


@pytest.mark.parametrize("terminator", ["\n", "\r", "\u2028", "\u2029"])
def test_javascript_line_comment_ends_at_every_line_terminator(terminator: str) -> None:
    source = f"// ignored fetch('/comment'){terminator}fetch('/live')"
    observations, issues = extract_client_observation_inventory(source, Path("client.js"))

    assert issues == ()
    assert [item.route_path for item in observations] == ["/live"]
