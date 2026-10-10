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
class ClientObservationIssue:
    """Recognized HTTP call syntax that cannot yield an exact route observation."""

    source_path: Path
    line: int
    method: str | None
    reason: str
    start_offset: int
    end_offset: int


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
_LINE_END = re.compile(r"[\r\n\u2028\u2029]")


def _tokens(source: str) -> list[_Token]:  # noqa: PLR0912, PLR0915
    out: list[_Token] = []
    i, n = 0, len(source)
    while i < n:
        c = source[i]
        if c.isspace():
            i += 1
            continue
        if source.startswith("//", i):
            end = _LINE_END.search(source, i + 2)
            i = n if end is None else end.end()
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


def _has_string_escape(arg: list[_Token]) -> bool:
    return len(arg) == 1 and arg[0].kind == "string" and "\\" in arg[0].value


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
        if scheme:
            port = parsed.port
            if (
                not parsed.hostname
                or any(char.isspace() for char in parsed.netloc)
                or parsed.netloc.endswith(":")
                or (port is not None and not 1 <= port <= 65535)
            ):
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


def _axios_config(arg: list[_Token]) -> tuple[str, str] | None:
    """Accept only the fully consumed literal url/method object."""
    if len(arg) != 9 or arg[0].value != "{" or arg[-1].value != "}":
        return None
    props = arg[1:-1]
    if props[3].value != ",":
        return None
    if (
        props[0].value == "url"
        and props[1].value == ":"
        and props[2].kind == "string"
        and props[4].value == "method"
        and props[5].value == ":"
        and props[6].kind == "string"
    ):
        return props[2].value, props[6].value
    if (
        props[0].value == "method"
        and props[1].value == ":"
        and props[2].kind == "string"
        and props[4].value == "url"
        and props[5].value == ":"
        and props[6].kind == "string"
    ):
        return props[6].value, props[2].value
    return None


def _is_global_axios(tokens: list[_Token], index: int) -> bool:
    """Reject axios references selected through an object/property receiver."""
    if index == 0:
        return True
    previous = tokens[index - 1]
    # Covers obj.axios, obj?.axios, obj[axios], and obj?.[axios]. A string
    # property such as obj["axios"] never has an axios identifier token.
    return previous.value not in {".", "["}


def _can_end_postfix_operand(tokens: list[_Token], index: int) -> bool:
    token = tokens[index]
    if token.kind == "id":
        # A keyword can be a property name, but a bare keyword starts or
        # separates expressions rather than supplying an update operand.
        if index and tokens[index - 1].value == ".":
            return True
        return token.value not in {
            "return",
            "throw",
            "yield",
            "await",
            "else",
            "do",
            "case",
            "new",
            "typeof",
            "void",
            "delete",
            "in",
            "instanceof",
            "of",
            "break",
            "continue",
        }
    if token.kind == "punct" and token.value == ")":
        depth = 1
        for opening in range(index - 1, -1, -1):
            if tokens[opening].kind != "punct":
                continue
            if tokens[opening].value == ")":
                depth += 1
            elif tokens[opening].value == "(":
                depth -= 1
                if depth == 0:
                    return not (
                        opening
                        and tokens[opening - 1].value
                        in {"if", "while", "for", "with", "switch", "catch"}
                    )
        return False
    return token.kind in {"string", "template", "regex"} or token.value == "]"


def _has_assignment_operator(tokens: list[_Token], index: int, source: str) -> bool:
    """Read complete contiguous JS operators, excluding equality and arrows."""
    if index >= 2:
        previous, first = tokens[index - 1], tokens[index - 2]
        if (
            first.kind == previous.kind == "punct"
            and first.value == previous.value
            and first.value in {"+", "-"}
            and first.end == previous.start
        ):
            # Maximal munch groups a contiguous run left to right. In `x+++fetch`
            # the final plus is binary, rather than part of `++fetch`.
            run_start = index - 2
            while (
                run_start > 0
                and tokens[run_start - 1].kind == "punct"
                and tokens[run_start - 1].value == first.value
                and tokens[run_start - 1].end == tokens[run_start].start
            ):
                run_start -= 1
            # Whitespace and comments may separate a postfix operator from
            # its operand. A line terminator in that gap makes it a prefix
            # operator under JavaScript's automatic semicolon rules.
            before_operator = tokens[index - 3] if index >= 3 else None
            postfix = (
                before_operator is not None
                and not any(
                    char in source[before_operator.end : first.start] for char in "\r\n\u2028\u2029"
                )
                and _can_end_postfix_operand(tokens, index - 3)
            )
            if (index - run_start) % 2 == 0:
                return not postfix
    operator = ""
    cursor = index + 1
    while cursor < len(tokens) and len(operator) < 4 and tokens[cursor].kind == "punct":
        if cursor > index + 1 and tokens[cursor - 1].end != tokens[cursor].start:
            break
        operator += tokens[cursor].value
        cursor += 1
    if operator.startswith(("++", "--")) and any(
        char in source[tokens[index].end : tokens[index + 1].start] for char in "\r\n\u2028\u2029"
    ):
        # Postfix updates cannot cross a line terminator; the operator belongs
        # to the following expression under automatic semicolon insertion.
        return False
    if operator.startswith("="):
        return not operator.startswith(("==", "=>"))
    return operator.startswith(
        (
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
        )
    )


def _shadowed_client_names(tokens: list[_Token], source: str) -> tuple[set[str], set[str]]:  # noqa: PLR0912, PLR0915
    """Fail closed file-wide when a client global has any local binding.

    This deliberately sacrifices some observations: proving JavaScript lexical
    scope correctly requires a full parser, so one declaration or assignment
    anywhere suppresses that global name throughout the file.
    """
    names = {"fetch", "axios", "WebSocket"}
    shadowed: set[str] = set()
    axios_imports: set[str] = set()

    def bind(token: _Token) -> None:
        if token.kind == "id" and token.value in names:
            shadowed.add(token.value)

    def bind_parameters(start: int, end: int) -> None:
        # Mark every client-like identifier in the parameter pattern. This can
        # suppress a global for a type/default reference too, but never guesses
        # that a destructured local is the browser global.
        begin = start
        depth = 0
        for pos in range(start, end + 1):
            at_end = pos == end
            value = tokens[pos].value if not at_end else ","
            if value in {"(", "[", "{"}:
                depth += 1
            elif value in {")", "]", "}"}:
                depth -= 1
            elif value == "," and depth == 0:
                for candidate in tokens[begin:pos]:
                    if candidate.kind == "id" and candidate.value in names:
                        bind(candidate)
                begin = pos + 1

    # Discover canonical import aliases before checking bindings anywhere in
    # the file, including function declarations placed before the import.
    for index, token in sorted(enumerate(tokens), key=lambda item: item[1].value != "import"):
        names.update(axios_imports)
        # This structural check must run for punctuation tokens too; arrow
        # parameters are enclosed by the closing-parenthesis token.
        if (
            token.value == ")"
            and index + 2 < len(tokens)
            and tokens[index + 1].value == "="
            and tokens[index + 2].value == ">"
        ):
            opening = index - 1
            depth = 1
            while opening >= 0 and depth:
                if tokens[opening].value == ")":
                    depth += 1
                elif tokens[opening].value == "(":
                    depth -= 1
                opening -= 1
            if depth == 0:
                bind_parameters(opening + 2, index)
        if token.kind != "id":
            continue
        if token.value in {"const", "let", "var", "class", "function"} and index + 1 < len(tokens):
            bind(tokens[index + 1])
        if token.value in {"const", "let", "var"}:
            # Destructured declarations: conservatively treat every matching
            # identifier before the initializer as a local binding.
            cursor = index + 1
            while cursor < len(tokens) and tokens[cursor].value not in {"=", ";"}:
                bind(tokens[cursor])
                cursor += 1
        if token.value == "function":
            opening = index + 1
            while opening < len(tokens) and tokens[opening].value not in {"(", "{", ";"}:
                opening += 1
            if opening < len(tokens) and tokens[opening].value == "(":
                parsed = _split_args(tokens, opening)
                if parsed is not None:
                    _args, closing = parsed
                    bind_parameters(opening + 1, closing)
        if token.value == "catch" and index + 1 < len(tokens) and tokens[index + 1].value == "(":
            parsed = _split_args(tokens, index + 1)
            if parsed is not None:
                _args, closing = parsed
                bind_parameters(index + 2, closing)
        if token.value == "for" and index + 2 < len(tokens):
            opening = index + 1 if tokens[index + 1].value == "(" else index
            candidate = opening + 1
            while candidate < len(tokens) and tokens[candidate].value not in {"of", "in", ";", "}"}:
                candidate += 1
            if (
                candidate < len(tokens)
                and tokens[candidate].value in {"of", "in"}
                and opening + 1 < len(tokens)
            ):
                for binding in tokens[opening + 1 : candidate]:
                    bind(binding)
        # Single-identifier arrow parameter.
        if (
            index + 2 < len(tokens)
            and tokens[index + 1].value == "="
            and tokens[index + 2].value == ">"
        ):
            bind(token)
        # Any direct assignment may rebind a global before or after a call.
        if token.value in names and _has_assignment_operator(tokens, index, source):
            bind(token)
        # Imported axios default/namespace bindings are accepted only from the
        # canonical package. Other imported names shadow browser globals.
        if token.value == "import":
            cursor = index + 1
            source_index = cursor
            while source_index < len(tokens) and tokens[source_index].value not in {";"}:
                if tokens[source_index].kind == "string":
                    break
                source_index += 1
            if source_index >= len(tokens) or tokens[source_index].kind != "string":
                continue
            import_names = tokens[cursor:source_index]
            module_name = tokens[source_index].value
            if module_name == "axios":
                local_names: list[_Token] = []
                if (
                    import_names
                    and import_names[0].kind == "id"
                    and import_names[0].value
                    not in {
                        "type",
                        "{",
                    }
                ):
                    local_names.append(import_names[0])
                for offset, imported in enumerate(import_names[:-1]):
                    if (
                        imported.value == "*"
                        and import_names[offset + 1].value == "as"
                        and offset + 2 < len(import_names)
                    ):
                        local_names.append(import_names[offset + 2])
                if "{" in [item.value for item in import_names]:
                    in_named_imports = False
                    named_specifier: list[_Token] = []
                    for item in import_names:
                        if item.value == "{":
                            in_named_imports = True
                            continue
                        if item.value == "}":
                            in_named_imports = False
                            if named_specifier:
                                local = named_specifier[-1]
                                if local.kind == "id" and local.value in names:
                                    shadowed.add(local.value)
                                named_specifier.clear()
                            continue
                        if not in_named_imports:
                            continue
                        if item.value == ",":
                            if named_specifier:
                                local = named_specifier[-1]
                                if local.kind == "id" and local.value in names:
                                    shadowed.add(local.value)
                            named_specifier.clear()
                        else:
                            named_specifier.append(item)
                for local in local_names:
                    if local.kind == "id":
                        axios_imports.add(local.value)
                        if local.value in {"fetch", "WebSocket"}:
                            shadowed.add(local.value)
            else:
                # The local side of imports consists of identifiers before
                # `from`; excluding syntax words leaves bindings and aliases.
                for imported in import_names:
                    if imported.value in {"type", "as", "from", "import"}:
                        continue
                    if imported.kind == "id":
                        bind(imported)
            cursor = source_index + 1
    return shadowed, axios_imports


def extract_client_observation_inventory(  # noqa: PLR0912, PLR0915
    source: str, source_path: Path | str = "<memory>"
) -> tuple[tuple[ClientObservation, ...], tuple[ClientObservationIssue, ...]]:
    """Return exact observations and separate uncertainties for supported call names."""
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
    shadowed, axios_imports = _shadowed_client_names(ts, lexical_source)
    found: list[ClientObservation] = []
    uncertain: list[ClientObservationIssue] = []
    i = 0
    while i < len(ts):
        start_i = i
        name, fixed, protocol = "", None, "http"
        if (
            ts[i].kind == "id"
            and ts[i].value == "fetch"
            and "fetch" not in shadowed
            and (i == 0 or ts[i - 1].value not in {".", "new"})
            and i + 1 < len(ts)
            and ts[i + 1].value == "("
        ):
            name, opening = "fetch", i + 1
        elif (
            ts[i].kind == "id"
            and ts[i].value == "new"
            and i + 3 < len(ts)
            and ts[i + 1].value == "WebSocket"
            and "WebSocket" not in shadowed
            and ts[i + 2].value == "("
        ):
            name, opening, fixed, protocol = "websocket", i + 2, "WEBSOCKET", "websocket"
        elif (
            ts[i].kind == "id"
            and (ts[i].value == "axios" or ts[i].value in axios_imports)
            and ts[i].value not in shadowed
            and _is_global_axios(ts, i)
            and i + 3 < len(ts)
            and ts[i + 1].value == "."
            and ts[i + 2].value.lower()
            in {"get", "post", "put", "patch", "delete", "head", "options"}
            and ts[i + 3].value == "("
        ):
            name, opening, fixed = "axios_method", i + 3, ts[i + 2].value.upper()
        elif (
            ts[i].kind == "id"
            and (ts[i].value == "axios" or ts[i].value in axios_imports)
            and ts[i].value not in shadowed
            and _is_global_axios(ts, i)
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
        url: str | None = None
        method = fixed or "GET"
        uncertainty: str | None = None
        if name in {"fetch", "websocket"}:
            if 1 <= len(args) <= 2:
                url = _literal(args[0])
                if url is None:
                    uncertainty = "dynamic_or_nonliteral_url"
                elif _has_string_escape(args[0]):
                    uncertainty = "escaped_url_literal"
                if len(args) == 2:
                    parsed_method = _method_option(args[1])
                    if parsed_method is None:
                        method = ""
                        uncertainty = "dynamic_or_unsupported_request_options"
                    else:
                        method = parsed_method
            else:
                uncertainty = "unsupported_argument_shape"
        elif name == "axios_method":
            method_name = ts[start_i + 2].value.lower()
            config_method = method_name in {"get", "delete", "head", "options"}
            max_args = 1 if config_method else 2
            if 1 <= len(args) <= max_args:
                url = _literal(args[0])
                if url is None:
                    uncertainty = "dynamic_or_nonliteral_url"
                elif _has_string_escape(args[0]):
                    uncertainty = "escaped_url_literal"
            elif config_method and len(args) == 2:
                url = _literal(args[0])
                uncertainty = "unsupported_or_dynamic_request_options"
            else:
                uncertainty = "unsupported_argument_shape"
        elif name == "axios_config" and len(args) == 1:
            parsed_config = _axios_config(args[0])
            if parsed_config is not None:
                url, method_value = parsed_config
                method = method_value.upper()
                if "\\" in url:
                    uncertainty = "escaped_url_literal"
            else:
                uncertainty = "unsupported_or_dynamic_axios_options"
        else:
            uncertainty = "unsupported_argument_shape"
        parsed_url = _parse_url(url) if url is not None else None
        if parsed_url is None and uncertainty is None:
            uncertainty = "unsupported_url"
        if parsed_url and method and uncertainty is None:
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
            else:
                uncertainty = "unsupported_protocol_or_method"
        if uncertainty is not None:
            first = ts[start_i]
            last = ts[close_i]
            uncertain.append(
                ClientObservationIssue(
                    path,
                    source.count("\n", 0, first.start) + 1,
                    method or None,
                    uncertainty,
                    first.start,
                    last.end,
                )
            )
        # Continue inside the argument list. An unsupported outer call may
        # contain an independently supported nested call that remains useful
        # evidence (for example, fetch(makeRequest(axios.get('/inner')))).
        i += 1
    return tuple(found), tuple(uncertain)


def extract_client_observations(
    source: str, source_path: Path | str = "<memory>"
) -> tuple[ClientObservation, ...]:
    """Extract exact supported calls; dynamic and unsupported shapes stay uncertain."""
    observations, _uncertain = extract_client_observation_inventory(source, source_path)
    return observations


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
