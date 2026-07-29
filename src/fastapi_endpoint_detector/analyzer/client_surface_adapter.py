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
_AXIOS_METHODS = frozenset(method.casefold() for method in _HTTP_METHODS)
MAX_CLIENT_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_LIMITATIONS = 256
_MAX_SVELTE_SCRIPT_REGIONS = 16
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_ROUTE_PARAMETER = re.compile(r"^\{[^{}:]+(?::(path|int|float|uuid|str))?\}$")
_SVELTE_SCRIPT_CLOSE = re.compile(r"</script\s*>")
_EXACT_AXIOS_IMPORT = re.compile(
    r"(?m)^[ \t]*import[ \t]+(?P<local>axios)[ \t]+from[ \t]+"
    r"(?P<quote>['\"])axios(?P=quote)[ \t]*;?[ \t]*(?://[^\n]*)?$"
)
_EXACT_AXIOS_REQUIRE = re.compile(
    r"(?m)^[ \t]*(?:const|let|var)[ \t]+(?P<local>axios)[ \t]*=[ \t]*require\([ \t]*"
    r"(?P<quote>['\"])axios(?P=quote)[ \t]*\)[ \t]*;?[ \t]*(?://[^\n]*)?$"
)
_UUID_SEGMENT = r"[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}"


@dataclass(frozen=True)
class _AxiosBinding:
    """One exact axios binding and its source-order activation point."""

    definition_start: int
    activation_offset: int | None


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


def _code_mask(source: str, *, start: int = 0, end: int | None = None) -> list[bool]:
    """Mark code characters while excluding comments and string contents."""
    if end is None:
        end = len(source)
    mask = [False] * len(source)
    index = start
    while index < end:
        if source.startswith("//", index):
            index += 2
            while index < end and source[index] != "\n":
                index += 1
            continue
        if source.startswith("/*", index):
            index += 2
            while index < end and not source.startswith("*/", index):
                index += 1
            index = min(end, index + 2)
            continue
        if source[index] in {"'", '"', "`"}:
            quote = source[index]
            index += 1
            while index < end:
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == quote:
                    index += 1
                    break
                index += 1
            continue
        mask[index] = not source[index].isspace()
        index += 1
    return mask


def _tag_end(source: str, start: int) -> int | None:
    """Return the end of one markup tag without interpreting its attributes."""
    quote: str | None = None
    for index in range(start, len(source)):
        char = source[index]
        if quote is not None:
            if char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == ">":
            return index + 1
    return None


def _markup_expression_end(source: str, start: int) -> int:
    """Skip one balanced Svelte markup expression without treating it as script."""
    depth = 0
    quote: str | None = None
    index = start
    while index < len(source):
        char = source[index]
        if quote is not None:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in {"'", '"', "`"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return len(source)


def _svelte_code_mask(source: str) -> tuple[list[bool], bool]:
    """Mask only finitely many complete Svelte script regions."""
    mask = [False] * len(source)
    cursor = 0
    regions = 0
    truncated = False
    while cursor < len(source):
        if source.startswith("<!--", cursor):
            comment_close = source.find("-->", cursor + 4)
            cursor = len(source) if comment_close < 0 else comment_close + 3
            continue
        if source.startswith("<script", cursor) and (
            cursor + 7 == len(source) or source[cursor + 7].isspace() or source[cursor + 7] == ">"
        ):
            opening_end = _tag_end(source, cursor + 7)
            if opening_end is None:
                break
            script_close = _SVELTE_SCRIPT_CLOSE.search(source, opening_end)
            if script_close is None:
                break
            if regions >= _MAX_SVELTE_SCRIPT_REGIONS:
                truncated = True
                break
            region_mask = _code_mask(source, start=opening_end, end=script_close.start())
            for index in range(opening_end, script_close.start()):
                mask[index] = region_mask[index]
            regions += 1
            cursor = script_close.end()
            continue
        if source[cursor] == "{":
            cursor = _markup_expression_end(source, cursor)
            continue
        if source[cursor] == "<":
            markup_tag_end = _tag_end(source, cursor + 1)
            cursor = len(source) if markup_tag_end is None else markup_tag_end
            continue
        cursor += 1
    return mask, truncated


def _skip_space(source: str, index: int, end: int) -> int:
    while index < end and source[index].isspace():
        index += 1
    return index


def _skip_trivia(source: str, index: int, end: int) -> int:
    """Skip whitespace and JavaScript comments between grammar tokens."""
    while index < end:
        index = _skip_space(source, index, end)
        if source.startswith("//", index):
            newline = source.find("\n", index + 2, end)
            index = end if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            closing = source.find("*/", index + 2, end)
            index = end if closing < 0 else closing + 2
            continue
        return index
    return end


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


def _code_identifier_offsets(source: str, mask: list[bool], name: str) -> list[int]:
    offsets: list[int] = []
    cursor = 0
    while cursor < len(source):
        found = _identifier_at(source, mask, cursor)
        if found is None:
            cursor += 1
            continue
        identifier, end = found
        if identifier == name:
            offsets.append(cursor)
        cursor = end
    return offsets


def _previous_code_index(mask: list[bool], index: int) -> int | None:
    index -= 1
    while index >= 0:
        if mask[index]:
            return index
        index -= 1
    return None


def _next_code_index(mask: list[bool], index: int) -> int | None:
    while index < len(mask):
        if mask[index]:
            return index
        index += 1
    return None


def _previous_identifier(source: str, mask: list[bool], index: int) -> tuple[str, int] | None:
    end = _previous_code_index(mask, index)
    if end is None or not (source[end].isalnum() or source[end] in {"_", "$"}):
        return None
    start = end
    while start > 0 and mask[start - 1] and (
        source[start - 1].isalnum() or source[start - 1] in {"_", "$"}
    ):
        start -= 1
    found = _identifier_at(source, mask, start)
    if found is None or found[1] != end + 1:
        return None
    return found[0], start


def _is_direct_call_use(source: str, mask: list[bool], start: int, end: int) -> bool:
    previous = _previous_code_index(mask, start)
    if previous is not None and source[previous] == ".":
        return False
    previous_identifier = _previous_identifier(source, mask, start)
    if previous_identifier is not None and previous_identifier[0] in {
        "class",
        "function",
        "interface",
        "new",
        "type",
    }:
        return False
    opening = _skip_space(source, end, len(source))
    if opening >= len(source) or source[opening] != "(":
        return False
    call_end = _call_end(source, mask, opening)
    following = _next_code_index(mask, call_end) if call_end is not None else None
    return following is None or source[following] != "{"


def _global_binding_is_unambiguous(source: str, mask: list[bool], name: str) -> bool:
    """Require every mention of a supported global to be its direct call shape."""
    for start in _code_identifier_offsets(source, mask, name):
        end = start + len(name)
        if name == "fetch":
            if not _is_direct_call_use(source, mask, start, end):
                return False
            continue
        previous = _previous_identifier(source, mask, start)
        if previous is None or previous[0] != "new":
            return False
        before_new = _previous_code_index(mask, previous[1])
        if before_new is not None and source[before_new] == ".":
            return False
        opening = _skip_space(source, end, len(source))
        if opening >= len(source) or source[opening] != "(":
            return False
    return True


def _brace_depth(mask: list[bool], source: str, end: int) -> int:
    depth = 0
    for index in range(end):
        if not mask[index]:
            continue
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth = max(0, depth - 1)
    return depth


def _require_binding_is_unambiguous(source: str, mask: list[bool]) -> bool:
    """Require every CommonJS ``require`` mention to remain a direct global call."""
    offsets = _code_identifier_offsets(source, mask, "require")
    return bool(offsets) and all(
        _is_direct_call_use(source, mask, start, start + len("require")) for start in offsets
    )


def _axios_binding(source: str, mask: list[bool]) -> _AxiosBinding | None:
    definitions: list[_AxiosBinding] = []
    patterns: list[tuple[re.Pattern[str], bool]] = [(_EXACT_AXIOS_IMPORT, False)]
    if _require_binding_is_unambiguous(source, mask):
        patterns.append((_EXACT_AXIOS_REQUIRE, True))
    for pattern, source_ordered in patterns:
        for match in pattern.finditer(source):
            start, end = match.span("local")
            if (
                all(mask[index] for index in range(start, end))
                and _brace_depth(mask, source, start) == 0
            ):
                definitions.append(
                    _AxiosBinding(
                        definition_start=start,
                        activation_offset=match.end() if source_ordered else None,
                    )
                )
    if len(definitions) != 1:
        return None
    definition = definitions[0]
    for start in _code_identifier_offsets(source, mask, "axios"):
        if start == definition.definition_start:
            continue
        previous = _previous_code_index(mask, start)
        if previous is not None and source[previous] == ".":
            return None
        dot = _skip_space(source, start + len("axios"), len(source))
        if dot >= len(source) or source[dot] != ".":
            return None
        method = _identifier_at(source, mask, dot + 1)
        if method is None or method[0] not in _AXIOS_METHODS:
            return None
        opening = _skip_space(source, method[1], len(source))
        if opening >= len(source) or source[opening] != "(":
            return None
    return definition


def _method_option(  # noqa: PLR0911, PLR0912, PLR0915
    source: str,
    mask: list[bool],
    start: int,
    end: int,
) -> tuple[bool, str | None]:
    """Return whether method semantics are present and their exact value, if safe."""
    cursor = _skip_trivia(source, start, end)
    if cursor >= end or source[cursor] == ")":
        return False, None
    if source[cursor] != ",":
        return True, None
    cursor = _skip_trivia(source, cursor + 1, end)
    if cursor >= end or source[cursor] != "{":
        return True, None

    methods: list[str] = []
    method_occurrences = 0
    brace_depth = 0
    while cursor < end:
        if source.startswith(("//", "/*"), cursor):
            cursor = _skip_trivia(source, cursor, end)
            continue
        if not mask[cursor]:
            if brace_depth == 1 and source[cursor] in {"'", '"', "`"}:
                key = _literal_at(source, cursor, end)
                if key is None:
                    return True, None
                after_key = _skip_trivia(source, key[1], end)
                if key[0] == "method" and after_key < end and source[after_key] == ":":
                    method_occurrences += 1
                    value_start = _skip_trivia(source, after_key + 1, end)
                    literal = _literal_at(source, value_start, end)
                    if literal is not None:
                        methods.append(literal[0].upper())
                        cursor = literal[1]
                        continue
                cursor = key[1]
                continue
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
        method_occurrences += 1
        value_start = _skip_trivia(source, after_name, end)
        if value_start >= end or source[value_start] != ":":
            continue
        value_start = _skip_trivia(source, value_start + 1, end)
        literal = _literal_at(source, value_start, end)
        if literal is not None:
            methods.append(literal[0].upper())
            cursor = literal[1]
    if method_occurrences == 0:
        return False, None
    if method_occurrences == 1 and len(methods) == 1 and methods[0] in _HTTP_METHODS:
        return True, methods[0]
    return True, None


def _redacted_url(raw_url: str) -> str:
    """Remove credentials and query/fragment values from report-facing evidence."""
    try:
        parsed = urlsplit(raw_url)
        if parsed.scheme:
            hostname = parsed.hostname or "<invalid-host>"
            if ":" in hostname:
                hostname = f"[{hostname}]"
            try:
                port = f":{parsed.port}" if parsed.port is not None else ""
            except ValueError:
                port = ":<invalid-port>"
            result = f"{parsed.scheme}://{hostname}{port}{parsed.path}"
        else:
            result = parsed.path
        if parsed.query:
            result += "?<redacted>"
        if parsed.fragment:
            result += "#<redacted>"
        return result
    except ValueError:
        return "<invalid-url>"


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
    if len(source.encode("utf-8")) > MAX_CLIENT_SOURCE_BYTES:
        return (), (f"{file_path}: client source exceeds {MAX_CLIENT_SOURCE_BYTES} bytes",)

    hosts = frozenset(host.casefold() for host in allowed_hosts)
    suffix = file_path.suffix.casefold()
    if suffix in {".jsx", ".tsx"}:
        return (), (
            f"{file_path}:1: JSX/TSX source is unresolved to avoid scanning rendered text as code",
        )
    if suffix == ".svelte":
        mask, scripts_truncated = _svelte_code_mask(source)
    else:
        mask = _code_mask(source)
        scripts_truncated = False
    line_starts = [0]
    line_starts.extend(index + 1 for index, char in enumerate(source) if char == "\n")
    references: list[ClientSurfaceReference] = []
    limitations: list[str] = []
    cursor = 0

    def limitation(offset: int, reason: str) -> None:
        if len(limitations) < _MAX_LIMITATIONS:
            limitations.append(f"{file_path}:{_line_number(line_starts, offset)}: {reason}")

    if suffix == ".svelte":
        limitation(
            0,
            "Svelte markup expressions are unresolved; only complete script regions are scanned",
        )
        if scripts_truncated:
            limitation(0, f"Svelte script region limit {_MAX_SVELTE_SCRIPT_REGIONS} reached")

    fetch_is_global = _global_binding_is_unambiguous(source, mask, "fetch")
    websocket_is_global = _global_binding_is_unambiguous(source, mask, "WebSocket")
    axios_binding = _axios_binding(source, mask)
    if _code_identifier_offsets(source, mask, "fetch") and not fetch_is_global:
        limitation(0, "fetch binding is shadowed or ambiguous; fetch calls were not resolved")
    if _code_identifier_offsets(source, mask, "WebSocket") and not websocket_is_global:
        limitation(
            0,
            "WebSocket binding is shadowed or ambiguous; constructor calls were not resolved",
        )
    if _code_identifier_offsets(source, mask, "axios") and axios_binding is None:
        limitation(
            0,
            "axios binding is not one exact unshadowed axios import; calls were not resolved",
        )

    while cursor < len(source):
        token = _identifier_at(source, mask, cursor)
        if token is None:
            cursor += 1
            continue
        name, after_name = token
        opening: int | None = None
        method: EndpointMethod | None = None
        websocket = False

        if name == "fetch" and fetch_is_global:
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
        elif name == "axios" and axios_binding is not None:
            if cursor == axios_binding.definition_start:
                cursor = after_name
                continue
            if (
                axios_binding.activation_offset is not None
                and cursor < axios_binding.activation_offset
            ):
                limitation(
                    cursor,
                    "axios CommonJS binding is not initialized at this use; call was not resolved",
                )
                cursor = after_name
                continue
            dot = _skip_space(source, after_name, len(source))
            if dot >= len(source) or source[dot] != ".":
                cursor = after_name
                continue
            method_token = _identifier_at(source, mask, dot + 1)
            if method_token is None or method_token[0] not in _AXIOS_METHODS:
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
        elif name == "new" and websocket_is_global:
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
            limitation(
                cursor,
                f"client URL {_redacted_url(raw_url)!r} is dynamic, external, or not allowlisted",
            )
            cursor = call_end
            continue
        references.append(
            ClientSurfaceReference(
                file_path=file_path,
                start_line=_line_number(line_starts, cursor),
                end_line=_line_number(line_starts, call_end - 1),
                method=method,
                raw_url=_redacted_url(raw_url),
                normalized_path=normalized,
            )
        )
        if len(references) >= max_references:
            limitation(cursor, f"client reference limit {max_references} reached")
            break
        cursor = call_end

    return tuple(references), tuple(limitations)


def _route_matches(route: str, path: str) -> bool:
    """Match only route shapes whose Starlette converter semantics are modeled exactly."""
    if route == path:
        return True
    route_segments = route.split("/")
    pattern: list[str] = []
    for index, segment in enumerate(route_segments):
        parameter = _ROUTE_PARAMETER.fullmatch(segment)
        if parameter is None:
            if "{" in segment or "}" in segment:
                return False
            pattern.append(re.escape(segment))
            continue
        converter = parameter.group(1) or "str"
        if converter == "str":
            pattern.append(r"[^/]+")
        elif converter == "int":
            pattern.append(r"[0-9]+")
        elif converter == "float":
            pattern.append(r"[0-9]+(?:\.[0-9]+)?")
        elif converter == "uuid":
            pattern.append(_UUID_SEGMENT)
        elif converter == "path":
            if index != len(route_segments) - 1:
                return False
            pattern.append(r".*")
        else:  # pragma: no cover - guarded by _ROUTE_PARAMETER
            return False
    return re.fullmatch("/".join(pattern), path) is not None


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
