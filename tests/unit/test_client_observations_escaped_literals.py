"""Regression coverage for escaped client URL string literals."""

from __future__ import annotations

from pathlib import Path

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
