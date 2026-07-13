from __future__ import annotations

from benchmarks.real_world.semantic_normalization import match_records


def record(*items: tuple[str, str]) -> dict:
    return {
        "affected_entrypoints": [{"id": identifier, "kind": kind} for identifier, kind in items]
    }


def score(expected: dict, predicted: dict, repository: str = "owner/repo") -> tuple[int, int, int]:
    result = match_records(repository, expected, predicted)
    return result["tp"], result["fp"], result["fn"]


def test_expands_composite_methods_without_double_counting() -> None:
    expected = record(("HTTP GET|POST|PUT|DELETE /openai/{path:path}", "http"))
    predicted = record(
        ("HTTP GET /openai/{value:path}", "http"),
        ("HTTP POST /openai/{value:path}", "http"),
        ("HTTP PUT /openai/{value:path}", "http"),
        ("HTTP DELETE /openai/{value:path}", "http"),
    )
    assert score(expected, predicted) == (4, 0, 0)


def test_partial_composite_retains_missing_atoms() -> None:
    expected = record(("HTTP GET|POST /items", "http"))
    predicted = record(("HTTP GET /items", "http"))
    assert score(expected, predicted) == (1, 0, 1)


def test_composite_prediction_is_also_expanded() -> None:
    expected = record(("HTTP GET /items", "http"), ("HTTP POST /items", "http"))
    predicted = record(("HTTP GET|POST /items", "http"))
    assert score(expected, predicted) == (2, 0, 0)


def test_preserves_slashes_case_encoding_and_dot_segments() -> None:
    for left, right in [
        ("HTTP GET /x", "HTTP GET /x/"),
        ("HTTP GET /x//y", "HTTP GET /x/y"),
        ("HTTP GET /Case", "HTTP GET /case"),
        ("HTTP GET /a%2Fb", "HTTP GET /a/b"),
        ("HTTP GET /a/../b", "HTTP GET /b"),
    ]:
        assert score(record((left, "http")), record((right, "http"))) == (0, 1, 1)


def test_normalizes_template_names_but_preserves_converters() -> None:
    assert score(
        record(("HTTP GET /users/{id}", "http")),
        record(("HTTP GET /users/{user_id:str}", "http")),
    ) == (1, 0, 0)
    assert score(
        record(("HTTP GET /files/{id:path}", "http")),
        record(("HTTP GET /files/{id:int}", "http")),
    ) == (0, 1, 1)


def test_normalizes_websocket_token_only() -> None:
    assert score(
        record(("WebSocket /events", "event")),
        record(("WEBSOCKET /events", "event")),
    ) == (1, 0, 0)
    assert score(
        record(("WebSocket /Events", "event")),
        record(("WEBSOCKET /events", "event")),
    ) == (0, 1, 1)


def test_relaxes_one_unique_qualifier_but_not_ambiguous_qualifiers() -> None:
    assert score(
        record(("HTTP GET /items?detailed=true", "http")),
        record(("HTTP GET /items", "http")),
    ) == (1, 0, 0)
    assert score(
        record(
            ("HTTP GET /items?detailed=true", "http"),
            ("HTTP GET /items?detailed=false", "http"),
        ),
        record(("HTTP GET /items", "http")),
    ) == (0, 1, 2)


def test_uses_only_frozen_repository_scoped_aliases() -> None:
    expected = record(("HTTP POST /api/chat/completions", "http"))
    predicted = record(("HTTP POST /api/v1/chat/completions", "http"))
    assert score(expected, predicted) == (0, 1, 1)
    assert score(expected, predicted, "open-webui/open-webui") == (1, 0, 0)


def test_collapses_explicit_alias_duplicate_predictions() -> None:
    expected = record(("HTTP POST /api/chat/completions", "http"))
    predicted = record(
        ("HTTP POST /api/chat/completions", "http"),
        ("HTTP POST /api/v1/chat/completions", "http"),
    )
    assert score(expected, predicted, "open-webui/open-webui") == (1, 0, 0)


def test_collapses_canonical_duplicate_predictions() -> None:
    expected = record(("HTTP GET /users/{id}", "http"))
    predicted = record(
        ("HTTP GET /users/{id}", "http"),
        ("HTTP GET /users/{user_id:str}", "http"),
    )
    assert score(expected, predicted) == (1, 0, 0)


def test_opaque_labels_match_raw_only() -> None:
    expected = record(("HTTP * (all routes using middleware)", "http"))
    assert score(expected, expected) == (1, 0, 0)
    assert score(expected, record(("HTTP GET /items", "http"))) == (0, 1, 1)
