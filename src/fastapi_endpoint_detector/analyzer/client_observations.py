"""Finite source-only observations of HTTP and WebSocket clients.

This deliberately recognizes a small literal subset. It never executes client
code and never infers server routes from arbitrary URLs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointDiscoveryStatus,
    EndpointMethod,
)

_LITERAL = r"(?P<quote>['\"])(?P<url>(?:https?://|wss?://|/|\./|\.\./)[^'\"`$\\]*)['\"]"
_FETCH = re.compile(r"\bfetch\s*\(\s*" + _LITERAL)
_FETCH_METHOD = re.compile(
    r"\bfetch\s*\(\s*" + _LITERAL
    + r"\s*,\s*\{[^}]*?\bmethod\s*:\s*(['\"])(?P<fetch_method>"
    + r"get|post|put|patch|delete|head|options)\3",
    re.I | re.S,
)
_AXIOS_METHOD = re.compile(
    r"\baxios\.(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*"
    + _LITERAL,
    re.I,
)
_WEBSOCKET = re.compile(r"\bnew\s+WebSocket\s*\(\s*" + _LITERAL)
_AXIOS_CONFIG = re.compile(
    r"\baxios\s*\(\s*\{[^}]*?\burl\s*:\s*" + _LITERAL
    + r"[^}]*?\bmethod\s*:\s*(['\"])(?P<config_method>get|post|put|patch|delete|head|options)\3",
    re.I | re.S,
)


@dataclass(frozen=True)
class ClientObservation:
    """One finite client call with query retained outside route identity."""

    source_path: Path
    line: int
    protocol: str
    method: str
    route_path: str
    query: str | None
    literal_url: str


@dataclass(frozen=True)
class EstablishedSurface:
    """Explicit server surface identifier and its established public method/path."""

    surface_id: str
    path: str
    method: str


@dataclass(frozen=True)
class ClientSurfaceMatch:
    observation: ClientObservation
    surface_id: str


def _parse_url(value: str) -> tuple[str, str, str, str | None] | None:
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"", "http", "https", "ws", "wss"} or parsed.fragment:
        return None
    if scheme in {"ws", "wss"}:
        protocol, method = "websocket", "WEBSOCKET"
    else:
        protocol, method = "http", "GET"
    path = parsed.path or "/"
    if not path.startswith("/") or "//" in path or any(
        part in {".", ".."} for part in path.split("/")
    ):
        return None
    return protocol, method, path, parsed.query or None


def extract_client_observations(
    source: str,
    source_path: Path | str = "<memory>",
) -> tuple[ClientObservation, ...]:
    """Extract literal fetch/axios/WebSocket calls from TS/JS source.

    Dynamic templates, concatenations and unsupported call shapes are omitted.
    Query strings are retained in ``query`` and excluded from ``route_path``.
    """
    path = Path(source_path)
    found: list[ClientObservation] = []
    patterns = (
        (_FETCH, "GET", "http"),
        (_FETCH_METHOD, None, "http"),
        (_AXIOS_METHOD, None, "http"),
        (_WEBSOCKET, "WEBSOCKET", "websocket"),
        (_AXIOS_CONFIG, None, "http"),
    )
    for pattern, fixed_method, fixed_protocol in patterns:
        for match in pattern.finditer(source):
            if pattern is _FETCH and re.match(
                r"\s*,\s*\{[^}]*?\bmethod\s*:", source[match.end() :], re.S
            ):
                continue
            parsed = _parse_url(match.group("url"))
            if parsed is None:
                continue
            protocol, default_method, route_path, query = parsed
            if fixed_protocol != protocol:
                continue
            method = (
                fixed_method
                or match.groupdict().get("method")
                or match.groupdict().get("fetch_method")
                or match.groupdict().get("config_method")
                or default_method
            )
            start = match.start()
            found.append(
                ClientObservation(
                    path,
                    source.count("\n", 0, start) + 1,
                    protocol,
                    method.upper(),
                    route_path,
                    query,
                    match.group("url"),
                )
            )
    # Overlapping syntax is possible; preserve one observation per source occurrence.
    unique = {(item.line, item.protocol, item.method, item.literal_url): item for item in found}
    return tuple(
        sorted(unique.values(), key=lambda item: (item.line, item.method, item.literal_url))
    )


def join_established_surfaces(
    observations: tuple[ClientObservation, ...],
    surfaces: tuple[EstablishedSurface, ...],
) -> tuple[ClientSurfaceMatch, ...]:
    """Join exact path/method matches to caller-supplied established surface IDs."""
    by_key: dict[tuple[str, str], list[str]] = {}
    for surface in surfaces:
        by_key.setdefault((surface.path, surface.method.upper()), []).append(surface.surface_id)
    matches: list[ClientSurfaceMatch] = []
    for observation in observations:
        for surface_id in sorted(set(by_key.get((observation.route_path, observation.method), ()))):
            matches.append(ClientSurfaceMatch(observation, surface_id))
    return tuple(matches)


def established_surfaces(
    endpoints: tuple[Endpoint, ...] | list[Endpoint],
) -> tuple[EstablishedSurface, ...]:
    """Project only established endpoints with native provenance to explicit IDs."""
    result: list[EstablishedSurface] = []
    for endpoint in endpoints:
        provenance = endpoint.native_provenance
        if endpoint.discovery_status != EndpointDiscoveryStatus.ESTABLISHED or provenance is None:
            continue
        registration = provenance.registration
        surface_id = ":".join(
            (
                provenance.root.module,
                provenance.root.symbol,
                str(registration.source_span.file_path),
                str(registration.source_span.start_line),
                registration.operation,
            )
        )
        for method in endpoint.methods:
            if method != EndpointMethod.CUSTOM:
                result.append(EstablishedSurface(surface_id, endpoint.path, method.value))
    return tuple(result)
