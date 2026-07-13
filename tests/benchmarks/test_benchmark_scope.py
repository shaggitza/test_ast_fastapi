from __future__ import annotations

from benchmarks.real_world.benchmark_scope import filter_record, is_fastapi_entrypoint


def test_fastapi_scope_includes_http_aliases_and_websocket_event_labels() -> None:
    items = [
        {"id": "HTTP GET /items", "kind": "http"},
        {"id": "Web UI routes using shared layouts", "kind": "http"},
        {"id": "WEBSOCKET /api/chat/ws", "kind": "event"},
        {"id": "Socket.IO connect event", "kind": "event"},
        {"id": "CLI command", "kind": "cli"},
    ]

    assert [is_fastapi_entrypoint(item) for item in items] == [
        True,
        False,
        True,
        False,
        False,
    ]

    record = {"affected_entrypoints": items}
    assert filter_record(record, "fastapi")["affected_entrypoints"] == [items[0], items[2]]
    assert filter_record(record, "out-of-scope")["affected_entrypoints"] == [
        items[1],
        items[3],
        items[4],
    ]
