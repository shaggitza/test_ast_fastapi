"""Bounded opt-in extraction of explicit TypeScript client surface references.

This adapter deliberately recognizes only direct calls with literal URLs.  It
never evaluates JavaScript, expands variables, or treats an arbitrary URL as a
reference to every server endpoint.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from pathlib import Path

from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointDiscoveryStatus,
    EndpointMethod,
)

_CLIENT_SUFFIXES = frozenset({".js", ".jsx", ".ts", ".tsx", ".svelte"})
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"})
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_LIMITATIONS = 256
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_ROUTE_PARAMETER = re.compile(r"^\{[^{}:]+(?::(path|int|float|uuid|str))?\}$")


@dataclass(frozen=True)
class ClientSurfaceReference:
    """One literal HTTP or WebSocket reference in a client source file."""

    file_path: Path
    start_line: int
    end_line: int
    method: EndpointMethod
    raw_url: str
    normalized_path: str


@dataclass(frozen=True)
class ClientSurfaceMatch:
    """A unique join from a literal client reference to an established endpoint."""

    reference: ClientSurfaceReference
    endpoint: Endpoint


@dataclass(frozen=True)
class ClientSurfaceAnalysis:
    """Finite extraction/join output plus explicit unsupported-shape evidence."""

    references: tuple[ClientSurfaceReference, ...]
    matches: tuple[ClientSurfaceMatch, ...]
    limitations: tuple[str, ...]


def is_client_source(path: Path) -> bool:
    """Return whether *path* is in the bounded client-language subset."""
    return path.suffix.casefold() in _CLIENT_SUFFIXES


def _code_mask(source: str) -> list[bool]:
    """Mark code characters while excluding comments and string contents."""
    mask = [False] * len(source)
    index = 0
    while index < len(source):
        if source.startswith("//", index):
            index += 2
            while index < len(source) and source[index] != "\n":
                index += 1
            continue
        if source.startswith("/*", index):
            index += 2
            while index < len(source) and not source.startswith("*/", index):
                index += 1
            index = min(len(source), index + 2)
            continue
        if source[index] in {"'", '"', "`"}:
            quote = source[index]
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == quote:
                    index += 1
                    break
                index += 1
            continue
        mask[index] = True
        index += 1
    return mask


def _skip_space(source: str, index: int, end: int) -> int:
    while index < end and source[index].isspace():
        index += 1
    return index


def _identifier_at(source: str, mask: list[bool], index: int) -> tuple[str, int] | None:
    match = _IDENTIFIER.match(source, index)
    if match is None or not all(mask[position] for position in range(match.start(), match.end())):
        return None
    return match.group(), match.end()


def _literal_at(source: str, index: int, end: int) -> tuple[str, int] | None:
    if index >= end or source[index] not in {"'", '"', "`"}:
        return None
    quote = source[index]
    cursor = index + 1
    while cursor < end:
        char = source[cursor]
        if char == "\\" or (quote == "`" and source.startswith("${", cursor)):
            return None
        if char == quote:
            return source[index + 1 : cursor], cursor + 1
        cursor += 1
    return None


def _call_end(source: str, mask: list[bool], opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(source)):
        if not mask[index]:
            continue
        if source[index] == "(":
            depth += 1
        elif source[index] == ")":
            depth -= 1
            if depth == 0:
                return index + 1
    return None


def _method_option(  # noqa: PLR0911, PLR0912
    source: str,
    mask: list[bool],
    start: int,
    end: int,
) -> tuple[bool, str | None]:
    """Return whether method semantics are present and their exact value, if safe."""
    cursor = _skip_space(source, start, end)
    if cursor >= end or source[cursor] == ")":
        return False, None
    if source[cursor] != ",":
        return True, None
    cursor = _skip_space(source, cursor + 1, end)
    if cursor >= end or source[cursor] != "{":
        return True, None

    methods: list[str] = []
    seen_method = False
    brace_depth = 0
    while cursor < end:
        if not mask[cursor]:
            cursor += 1
            continue
        if source.startswith("...", cursor) and brace_depth == 1:
            return True, None
        if source[cursor] == "{":
            brace_depth += 1
            cursor += 1
            continue
        if source[cursor] == "}":
            brace_depth -= 1
            cursor += 1
            if brace_depth == 0:
                break
            continue
        if source[cursor] == "[" and brace_depth == 1:
            return True, None
        found = _identifier_at(source, mask, cursor)
        if found is None:
            cursor += 1
            continue
        name, after_name = found
        cursor = after_name
        if brace_depth != 1 or name != "method":
            continue
        seen_method = True
        value_start = _skip_space(source, after_name, end)
        if value_start >= end or source[value_start] != ":":
            continue
        value_start = _skip_space(source, value_start + 1, end)
        literal = _literal_at(source, value_start, end)
        if literal is not None:
            methods.append(literal[0].upper())
            cursor = literal[1]
    if not seen_method:
        return False, None
    if len(methods) == 1 and methods[0] in _HTTP_METHODS:
        return True, methods[0]
    return True, None


def _normalized_url(
    raw_url: str,
    *,
    websocket: bool,
    allowed_hosts: frozenset[str],
) -> str | None:
    if not raw_url or len(raw_url) > 4096 or "\x00" in raw_url or "\\" in raw_url:
        return None
    try:
        parsed = urlsplit(raw_url)
        hostname = (parsed.hostname or "").casefold()
    except ValueError:
        return None
    if parsed.scheme:
        allowed_schemes = {"ws", "wss"} if websocket else {"http", "https"}
        if parsed.scheme.casefold() not in allowed_schemes or hostname not in allowed_hosts:
            return None
        path = parsed.path
    else:
        if parsed.netloc or not raw_url.startswith("/") or raw_url.startswith("//"):
            return None
        path = parsed.path
    if not path or any(segment == ".." for segment in path.split("/")):
        return None
    return path


def _line_number(line_starts: list[int], offset: int) -> int:
    return bisect.bisect_right(line_starts, offset)


def extract_client_references(  # noqa: PLR0912, PLR0915
    source: str,
    file_path: Path,
    *,
    allowed_hosts: tuple[str, ...] = (),
    max_references: int = 256,
) -> tuple[tuple[ClientSurfaceReference, ...], tuple[str, ...]]:
    """Extract direct literal fetch/axios/WebSocket references without execution."""
    if not is_client_source(file_path):
        return (), ()
    if len(source.encode("utf-8")) > _MAX_SOURCE_BYTES:
        return (), (f"{file_path}: client source exceeds {_MAX_SOURCE_BYTES} bytes",)

    hosts = frozenset(host.casefold() for host in allowed_hosts)
    mask = _code_mask(source)
    line_starts = [0]
    line_starts.extend(index + 1 for index, char in enumerate(source) if char == "\n")
    references: list[ClientSurfaceReference] = []
    limitations: list[str] = []
    cursor = 0

    def limitation(offset: int, reason: str) -> None:
        if len(limitations) < _MAX_LIMITATIONS:
            limitations.append(f"{file_path}:{_line_number(line_starts, offset)}: {reason}")

    while cursor < len(source):
        token = _identifier_at(source, mask, cursor)
        if token is None:
            cursor += 1
            continue
        name, after_name = token
        opening: int | None = None
        method: EndpointMethod | None = None
        websocket = False

        if name == "fetch":
            opening = _skip_space(source, after_name, len(source))
            if opening >= len(source) or source[opening] != "(":
                cursor = after_name
                continue
            call_end = _call_end(source, mask, opening)
            if call_end is None:
                limitation(cursor, "unterminated fetch call")
                break
            argument_start = _skip_space(source, opening + 1, call_end)
            literal = _literal_at(source, argument_start, call_end)
            if literal is None:
                limitation(cursor, "dynamic fetch URL is outside the finite client subset")
                cursor = call_end
                continue
            raw_url, literal_end = literal
            has_method, option_method = _method_option(source, mask, literal_end, call_end)
            if has_method and option_method is None:
                limitation(cursor, "dynamic or invalid fetch method is outside the finite subset")
                cursor = call_end
                continue
            method = EndpointMethod(option_method or "GET")
        elif name == "axios":
            dot = _skip_space(source, after_name, len(source))
            if dot >= len(source) or source[dot] != ".":
                cursor = after_name
                continue
            method_token = _identifier_at(source, mask, dot + 1)
            if method_token is None or method_token[0].upper() not in _HTTP_METHODS:
                cursor = after_name
                continue
            opening = _skip_space(source, method_token[1], len(source))
            if opening >= len(source) or source[opening] != "(":
                cursor = method_token[1]
                continue
            call_end = _call_end(source, mask, opening)
            if call_end is None:
                limitation(cursor, "unterminated axios call")
                break
            argument_start = _skip_space(source, opening + 1, call_end)
            literal = _literal_at(source, argument_start, call_end)
            if literal is None:
                limitation(cursor, "dynamic axios URL is outside the finite client subset")
                cursor = call_end
                continue
            raw_url, _literal_end = literal
            method = EndpointMethod(method_token[0].upper())
        elif name == "new":
            constructor_start = _skip_space(source, after_name, len(source))
            constructor = _identifier_at(source, mask, constructor_start)
            if constructor is None or constructor[0] != "WebSocket":
                cursor = after_name
                continue
            opening = _skip_space(source, constructor[1], len(source))
            if opening >= len(source) or source[opening] != "(":
                cursor = constructor[1]
                continue
            call_end = _call_end(source, mask, opening)
            if call_end is None:
                limitation(cursor, "unterminated WebSocket call")
                break
            argument_start = _skip_space(source, opening + 1, call_end)
            literal = _literal_at(source, argument_start, call_end)
            if literal is None:
                limitation(cursor, "dynamic WebSocket URL is outside the finite client subset")
                cursor = call_end
                continue
            raw_url, _literal_end = literal
            method = EndpointMethod.WEBSOCKET
            websocket = True
        else:
            cursor = after_name
            continue

        normalized = _normalized_url(raw_url, websocket=websocket, allowed_hosts=hosts)
        if normalized is None:
            limitation(cursor, f"client URL {raw_url!r} is dynamic, external, or not allowlisted")
            cursor = call_end
            continue
        references.append(
            ClientSurfaceReference(
                file_path=file_path,
                start_line=_line_number(line_starts, cursor),
                end_line=_line_number(line_starts, call_end - 1),
                method=method,
                raw_url=raw_url,
                normalized_path=normalized,
            )
        )
        if len(references) >= max_references:
            limitation(cursor, f"client reference limit {max_references} reached")
            break
        cursor = call_end

    return tuple(references), tuple(limitations)


def _route_matches(route: str, path: str) -> bool:  # noqa: PLR0911
    if route == path:
        return True
    route_segments = route.strip("/").split("/")
    path_segments = path.strip("/").split("/")
    route_index = 0
    path_index = 0
    while route_index < len(route_segments) and path_index < len(path_segments):
        route_segment = route_segments[route_index]
        parameter = _ROUTE_PARAMETER.fullmatch(route_segment)
        if parameter is None:
            if route_segment != path_segments[path_index]:
                return False
        else:
            converter = parameter.group(1)
            value = path_segments[path_index]
            if not value:
                return False
            if converter == "int" and not value.isdecimal():
                return False
            if converter == "float":
                try:
                    float(value)
                except ValueError:
                    return False
            if converter == "path":
                return route_index == len(route_segments) - 1
        route_index += 1
        path_index += 1
    return route_index == len(route_segments) and path_index == len(path_segments)


def join_client_references(
    references: tuple[ClientSurfaceReference, ...],
    endpoints: list[Endpoint],
) -> tuple[tuple[ClientSurfaceMatch, ...], tuple[str, ...]]:
    """Join each reference only when exactly one established native endpoint matches."""
    matches: list[ClientSurfaceMatch] = []
    limitations: list[str] = []
    for reference in references:
        candidates = [
            endpoint
            for endpoint in endpoints
            if endpoint.surface is None
            and endpoint.discovery_status == EndpointDiscoveryStatus.ESTABLISHED
            and reference.method in endpoint.methods
            and _route_matches(endpoint.path, reference.normalized_path)
        ]
        if len(candidates) == 1:
            matches.append(ClientSurfaceMatch(reference=reference, endpoint=candidates[0]))
        elif len(candidates) > 1:
            limitations.append(
                f"{reference.file_path}:{reference.start_line}: client reference "
                f"{reference.method.value} {reference.raw_url!r} matches multiple server surfaces"
            )
    return tuple(matches), tuple(limitations)


def analyze_client_source(
    source: str,
    file_path: Path,
    endpoints: list[Endpoint],
    *,
    allowed_hosts: tuple[str, ...] = (),
    max_references: int = 256,
) -> ClientSurfaceAnalysis:
    """Extract and uniquely join one client source snapshot."""
    references, extraction_limitations = extract_client_references(
        source,
        file_path,
        allowed_hosts=allowed_hosts,
        max_references=max_references,
    )
    matches, join_limitations = join_client_references(references, endpoints)
    return ClientSurfaceAnalysis(
        references=references,
        matches=matches,
        limitations=(*extraction_limitations, *join_limitations),
    )
