"""Bounded, source-only observations of literal JavaScript/TypeScript calls.

This scanner intentionally supports a small grammar instead of trying to
interpret JavaScript. Unknown syntax is skipped or rejected conservatively.
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


@dataclass(frozen=True)
class ClientObservation:
    source_path: Path
    line: int
    protocol: str
    method: str
    route_path: str
    query: str | None
    literal_url: str
    start_offset: int = 0
    end_offset: int = 0
    origin: str | None = None


@dataclass(frozen=True)
class EstablishedSurface:
    surface_id: str
    path: str
    method: str
    origin: str | None = None
    trusted: bool = False


@dataclass(frozen=True)
class ClientSurfaceMatch:
    observation: ClientObservation
    surface_id: str


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str
    start: int
    end: int


_IDENT = re.compile(r"[A-Za-z_$][\w$]*")


def _tokens(source: str) -> list[_Token]:  # noqa: PLR0912, PLR0915
    out: list[_Token] = []
    i, n = 0, len(source)
    while i < n:
        c = source[i]
        if c.isspace():
            i += 1
            continue
        if source.startswith("//", i):
            j = source.find("\n", i + 2)
            i = n if j < 0 else j + 1
            continue
        if source.startswith("/*", i):
            j = source.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        regex_prefix = not out or (out[-1].kind == "punct" and out[-1].value in "=(:,[!&|?{};>")
        regex_prefix = regex_prefix or (
            out[-1].kind == "id" and out[-1].value in {"return", "case", "throw", "yield", "await"}
        )
        if c == "/" and regex_prefix:
            # A slash in expression-start position can begin a regex literal.
            # Consume through its unescaped closing slash so contents are never
            # mistaken for executable calls. Division after an expression is
            # left as punctuation.
            start = i
            i += 1
            escaped = False
            in_class = False
            while i < n:
                ch = source[i]
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == "[":
                    in_class = True
                elif ch == "]":
                    in_class = False
                elif ch == "/" and not in_class:
                    i += 1
                    while i < n and source[i].isalpha():
                        i += 1
                    break
                elif ch == "\n":
                    break
                i += 1
            out.append(_Token("regex", "", start, i))
            continue
        if c in "'\"`":
            quote, start = c, i
            i += 1
            escaped = False
            while i < n:
                ch = source[i]
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    i += 1
                    break
                i += 1
            else:
                out.append(_Token("invalid", "", start, n))
                break
            raw = source[start + 1 : i - 1]
            # Templates are only accepted if they contain no interpolation.
            out.append(
                _Token(
                    "string"
                    if quote != "`" or ("${" not in raw and "`" not in raw)
                    else "template",
                    raw,
                    start,
                    i,
                )
            )
            continue
        m = _IDENT.match(source, i)
        if m:
            out.append(_Token("id", m.group(), i, m.end()))
            i = m.end()
            continue
        out.append(_Token("punct", c, i, i + 1))
        i += 1
    return out


def _split_args(tokens: list[_Token], opening: int) -> tuple[list[list[_Token]], int] | None:
    pairs = {"(": ")", "{": "}", "[": "]"}
    if opening >= len(tokens) or tokens[opening].value != "(":
        return None
    stack = [")"]
    args: list[list[_Token]] = []
    begin = opening + 1
    for pos in range(opening + 1, len(tokens)):
        v = tokens[pos].value
        if v in pairs:
            stack.append(pairs[v])
        elif v in ")}]":
            if not stack or stack[-1] != v:
                return None
            stack.pop()
            if not stack:
                if pos > begin or args:
                    args.append(tokens[begin:pos])
                return args, pos
        elif v == "," and len(stack) == 1:
            args.append(tokens[begin:pos])
            begin = pos + 1
    return None


def _literal(arg: list[_Token]) -> str | None:
    if len(arg) == 1 and arg[0].kind == "string":
        return arg[0].value
    return None


def _parse_url(  # noqa: PLR0911
    value: str,
) -> tuple[str, str, str, str | None, str | None] | None:
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if (
            scheme not in {"", "http", "https", "ws", "wss"}
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            return None
        if scheme and not parsed.netloc:
            return None
        if not scheme and (parsed.netloc or not value.startswith(("/", "./", "../"))):
            return None
        protocol = "websocket" if scheme in {"ws", "wss"} else "http"
        if protocol == "websocket" and scheme not in {"ws", "wss"}:
            return None
        path = parsed.path or "/"
        if (
            not path.startswith("/")
            or "//" in path
            or any(p in {".", ".."} for p in path.split("/"))
        ):
            return None
        origin = f"{scheme}://{parsed.netloc.lower()}" if scheme else None
        return (
            protocol,
            "WEBSOCKET" if protocol == "websocket" else "GET",
            path,
            parsed.query or None,
            origin,
        )
    except (ValueError, UnicodeError):
        return None


def _method_option(arg: list[_Token]) -> str | None:
    # Deliberately allow only an object containing the single literal method.
    if len(arg) < 5 or arg[0].value != "{" or arg[-1].value != "}":
        return None
    inner = arg[1:-1]
    if (
        len(inner) == 3
        and inner[0].value == "method"
        and inner[1].value == ":"
        and inner[2].kind == "string"
    ):
        method = inner[2].value.upper()
        return (
            method
            if method in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
            else None
        )
    return None


def extract_client_observations(  # noqa: PLR0912, PLR0915
    source: str, source_path: Path | str = "<memory>"
) -> tuple[ClientObservation, ...]:
    """Extract exactly supported call forms; unsupported expressions are omitted."""
    path = Path(source_path)
    lexical_source = source
    if path.suffix.lower() == ".svelte":
        # Preserve offsets and line numbers while excluding markup and text.
        mask = list(source)
        for match in re.finditer(r"(?is)<script\b[^>]*>(.*?)</script\s*>", source):
            for pos in range(match.start(), match.start(1)):
                if mask[pos] != "\n":
                    mask[pos] = " "
            for pos in range(match.end(1), match.end()):
                if mask[pos] != "\n":
                    mask[pos] = " "
        covered = [False] * len(source)
        for match in re.finditer(r"(?is)<script\b[^>]*>(.*?)</script\s*>", source):
            covered[match.start(1) : match.end(1)] = [True] * (match.end(1) - match.start(1))
        for pos, is_code in enumerate(covered):
            if not is_code and mask[pos] != "\n":
                mask[pos] = " "
        lexical_source = "".join(mask)
    ts = _tokens(lexical_source)
    found: list[ClientObservation] = []
    i = 0
    while i < len(ts):
        start_i = i
        name, fixed, protocol = "", None, "http"
        if (
            ts[i].kind == "id"
            and ts[i].value == "fetch"
            and (i == 0 or ts[i - 1].value != ".")
            and i + 1 < len(ts)
            and ts[i + 1].value == "("
        ):
            name, opening = "fetch", i + 1
        elif (
            ts[i].kind == "id"
            and ts[i].value == "new"
            and i + 3 < len(ts)
            and ts[i + 1].value == "WebSocket"
            and ts[i + 2].value == "("
        ):
            name, opening, fixed, protocol = "websocket", i + 2, "WEBSOCKET", "websocket"
        elif (
            ts[i].kind == "id"
            and ts[i].value == "axios"
            and i + 3 < len(ts)
            and ts[i + 1].value == "."
            and ts[i + 2].value.lower()
            in {"get", "post", "put", "patch", "delete", "head", "options"}
            and ts[i + 3].value == "("
        ):
            name, opening, fixed = "axios_method", i + 3, ts[i + 2].value.upper()
        elif (
            ts[i].kind == "id"
            and ts[i].value == "axios"
            and i + 1 < len(ts)
            and ts[i + 1].value == "("
        ):
            name, opening = "axios_config", i + 1
        else:
            i += 1
            continue
        parsed_args = _split_args(ts, opening)
        if parsed_args is None:
            i += 1
            continue
        args, close_i = parsed_args
        url = None
        method = fixed or "GET"
        if name in {"fetch", "websocket"}:
            if 1 <= len(args) <= 2:
                url = _literal(args[0])
                if len(args) == 2:
                    method = _method_option(args[1]) or ""
        elif name == "axios_method":
            if 1 <= len(args) <= 2:
                url = _literal(args[0])
        elif name == "axios_config" and len(args) == 1:
            a = args[0]
            # Only {url: literal, method: literal} in either order.
            if a and a[0].value == "{" and a[-1].value == "}":
                props = a[1:-1]
                if (
                    len(props) == 7
                    and props[0].value == "url"
                    and props[1].value == ":"
                    and props[2].kind == "string"
                    and props[3].value == ","
                    and props[4].value == "method"
                    and props[5].value == ":"
                    and props[6].kind == "string"
                ):
                    url = props[2].value
                    method = props[6].value.upper()
        parsed_url = _parse_url(url) if url is not None else None
        if parsed_url and method:
            pr, default, route, query, origin = parsed_url
            if pr == protocol and (
                method in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "WEBSOCKET"}
            ):
                first = ts[start_i]
                last = ts[close_i]
                found.append(
                    ClientObservation(
                        path,
                        source.count("\n", 0, first.start) + 1,
                        pr,
                        method or default,
                        route,
                        query,
                        url or "",
                        first.start,
                        last.end,
                        origin,
                    )
                )
        i = close_i + 1
    return tuple(found)


def join_established_surfaces(
    observations: tuple[ClientObservation, ...], surfaces: tuple[EstablishedSurface, ...]
) -> tuple[ClientSurfaceMatch, ...]:
    """Join only trusted server IDs with explicit origins and exact path/method."""
    index: dict[tuple[str, str, str], list[str]] = {}
    for surface in surfaces:
        if surface.trusted and surface.origin:
            index.setdefault(
                (surface.origin.lower(), surface.path, surface.method.upper()), []
            ).append(surface.surface_id)
    out: list[ClientSurfaceMatch] = []
    for obs in observations:
        if obs.origin is None:
            continue
        for sid in sorted(set(index.get((obs.origin.lower(), obs.route_path, obs.method), ()))):
            out.append(ClientSurfaceMatch(obs, sid))
    return tuple(out)


def established_surfaces(
    endpoints: tuple[Endpoint, ...] | list[Endpoint],
    *,
    origin: str | None = None,
    trusted: bool = False,
) -> tuple[EstablishedSurface, ...]:
    """Project established native surfaces; callers must attest origin and trust."""
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
                result.append(
                    EstablishedSurface(surface_id, endpoint.path, method.value, origin, trusted)
                )
    return tuple(result)
