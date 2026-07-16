"""Bounded fake-transport tests for pilot live source bindings."""

from __future__ import annotations

import hashlib
import io
import json
import time
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from typing import Any, cast

import pytest
from benchmarks.real_world import pilot_protocol_v2
from benchmarks.real_world import pilot_source_v2 as source

_ROOT = Path(__file__).resolve().parents[2]


def _digest(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


class FakeTransport:
    def __init__(
        self,
        selected: list[dict[str, object]],
        budget: source.NetworkBudget,
        *,
        wrong_identity: bool = False,
        wrong_timestamp: bool = False,
        bad_parents: bool = False,
        mutate_confirmation: bool = False,
    ) -> None:
        self.selected = selected
        self.budget = budget
        self.wrong_identity = wrong_identity
        self.wrong_timestamp = wrong_timestamp
        self.bad_parents = bad_parents
        self.mutate_confirmation = mutate_confirmation
        self.pull_reads: dict[str, int] = {}
        self.payloads: dict[str, dict[str, Any]] = {}
        for index, item in enumerate(selected, 1):
            repository = str(item["repository"])
            number_value = item["number"]
            assert isinstance(number_value, int)
            number = number_value
            base = f"{index:x}" * 40
            target = f"{index + 3:x}" * 40
            merge = f"{index + 6:x}" * 40
            baseline = f"{index + 9:x}" * 40
            pull_url = source._api_url(repository, f"pulls/{number}")
            self.payloads[pull_url] = {
                "number": number + (1 if wrong_identity and index == 1 else 0),
                "html_url": f"https://github.com/{repository}/pull/{number}",
                "merged_at": (
                    "2020-01-01T00:00:00Z" if wrong_timestamp and index == 1 else item["merged_at"]
                ),
                "base": {"sha": base},
                "head": {"sha": target},
                "merge_commit_sha": merge,
            }
            self.payloads[source._api_url(repository, f"git/commits/{merge}")] = {
                "sha": merge,
                "tree": {"sha": f"{(index + 12) % 16:x}" * 40},
                "parents": []
                if bad_parents and index == 1
                else [{"sha": baseline}, {"sha": target}],
            }
            self.payloads[source._api_url(repository, f"git/commits/{baseline}")] = {
                "sha": baseline,
                "tree": {"sha": f"{(index + 12) % 16:x}" * 40},
            }
            self.payloads[source._api_url(repository, f"git/commits/{target}")] = {
                "sha": target,
                "tree": {"sha": f"{(index + 13) % 16:x}" * 40},
            }

    def get_json(self, url: str) -> tuple[dict[str, Any], str]:
        self.budget.reserve_request()
        payload = json.loads(json.dumps(self.payloads[url]))
        if "/pulls/" in url:
            count = self.pull_reads.get(url, 0)
            self.pull_reads[url] = count + 1
            if self.mutate_confirmation and count == 1:
                payload["head"]["sha"] = "f" * 40
        raw = json.dumps(payload, sort_keys=True).encode()
        self.budget.consume(len(raw))
        return payload, _digest(raw)

    def hash_diff(self, repository: str, number: int) -> tuple[str, int, str, str]:
        self.budget.reserve_request()
        self.budget.reserve_request()
        raw = f"diff --git a/{number}.py b/{number}.py\n".encode()
        if len(raw) > self.budget.max_diff_bytes:
            raise source.PilotSourceError("one diff exceeded byte bound")
        self.budget.consume(len(raw), diff=True)
        return (
            _digest(raw),
            len(raw),
            f"https://patch-diff.githubusercontent.com/raw/{repository}/pull/{number}.diff",
            "text/plain; charset=utf-8",
        )


def _selected() -> list[dict[str, object]]:
    value = pilot_protocol_v2.validate_preregistration(_ROOT)["selected"]
    assert isinstance(value, list)
    return value


def _payload(**transport_options: bool) -> dict[str, Any]:
    selected = _selected()
    budget = source.NetworkBudget()
    transport = FakeTransport(selected, budget, **transport_options)
    return source.collect_source_bindings(
        selected,
        transport,
        budget,
        collected_at="2026-07-16T20:00:00Z",
        collector_sha256=source.collector_sha256(),
    )


def test_fake_transport_success_and_exact_semantics() -> None:
    selected = _selected()
    payload = _payload()
    source.validate_payload(payload, selected)
    assert len(payload["records"]) == 3
    assert payload["network_budget"]["requests"] == 21
    assert all(
        record["baseline_commit"] == record["merge_parent_shas"][0] for record in payload["records"]
    )


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"wrong_identity": True}, "PR identity"),
        ({"wrong_timestamp": True}, "merged_at differs"),
        ({"bad_parents": True}, "no first parent"),
    ],
)
def test_identity_timestamp_and_parent_fail_closed(options: dict[str, bool], message: str) -> None:
    with pytest.raises(source.PilotSourceError, match=message):
        _payload(**options)


def test_pull_mutation_during_diff_fails_closed() -> None:
    with pytest.raises(source.PilotSourceError, match="changed while streaming diff"):
        _payload(mutate_confirmation=True)


def test_redirect_identity_and_credential_stripping() -> None:
    api_redirects = source._RejectRedirects()
    api_redirects.redirect_request(
        urllib.request.Request("https://api.github.com/repos/owner/repo/pulls/7"),
        None,
        302,
        "Found",
        {},
        "https://evil.example/redirect",
    )
    handler = source._SafeDiffRedirects("owner/repo", 7, source.NetworkBudget())
    with pytest.raises(source.PilotSourceError, match="exact PR identity"):
        handler.validate_final("https://evil.example/raw/owner/repo/pull/7.diff")
    request = urllib.request.Request(
        "https://github.com/owner/repo/pull/7.diff",
        headers={"Authorization": "Bearer secret", "Host": "github.com", "X-Test": "ok"},
    )
    redirected = handler.redirect_request(
        request,
        None,
        302,
        "Found",
        {},
        "https://patch-diff.githubusercontent.com/raw/owner/repo/pull/7.diff",
    )
    headers = {key.casefold(): value for key, value in redirected.header_items()}
    assert headers == {"x-test": "ok"}


class _Response(io.BytesIO):
    def __init__(self, raw: bytes, url: str, content_type: str = "application/json") -> None:
        super().__init__(raw)
        self.url = url
        self.headers = {"Content-Type": content_type}

    def geturl(self) -> str:
        return self.url

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class _SequenceOpener:
    def __init__(self, responses: list[object]) -> None:
        self.responses = responses
        self.requests: list[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, timeout: float) -> Any:
        del timeout
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def test_redirect_body_is_bounded_counted_and_only_followed_once() -> None:
    budget = source.NetworkBudget()
    handler = source._SafeDiffRedirects("owner/repo", 7, budget)
    parent = _SequenceOpener(
        [
            _Response(
                b"diff\n",
                "https://patch-diff.githubusercontent.com/raw/owner/repo/pull/7.diff",
                "text/plain",
            )
        ]
    )
    handler.parent = cast("Any", parent)
    request = urllib.request.Request(handler.origin_url, headers={"Host": "github.com"})
    response = handler.http_error_302(
        request,
        io.BytesIO(b"redirect"),
        302,
        "Found",
        {"Location": handler.patch_url},
    )
    assert response.read() == b"diff\n"
    assert budget.requests == 1
    assert budget.response_bytes == len(b"redirect")
    assert handler.followed is True
    with pytest.raises(source.PilotSourceError, match="exact PR identity"):
        handler.http_error_302(
            request,
            io.BytesIO(b"again"),
            302,
            "Found",
            {"Location": handler.patch_url},
        )

    oversized = source._SafeDiffRedirects("owner/repo", 7, source.NetworkBudget())
    with pytest.raises(source.PilotSourceError, match="body exceeded"):
        oversized.http_error_302(
            request,
            io.BytesIO(b"x" * (source._MAX_REDIRECT_BODY_BYTES + 1)),
            302,
            "Found",
            {"Location": oversized.patch_url},
        )


def test_api_redirect_retry_bytes_and_oversized_response(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://api.github.com/repos/owner/repo/pulls/7"
    redirect_error = urllib.error.HTTPError(
        url,
        302,
        "Found",
        Message(),
        io.BytesIO(b"redirect"),
    )
    transport = source.GitHubTransport("secret", source.NetworkBudget())
    transport.api_opener = cast("Any", _SequenceOpener([redirect_error]))
    with pytest.raises(source.PilotSourceError, match="API request failed"):
        transport.get_json(url)
    assert transport.budget.requests == 1
    assert transport.budget.response_bytes == len(b"redirect")

    retry_error = urllib.error.HTTPError(url, 500, "retry", Message(), io.BytesIO(b"retry"))
    raw = b'{"ok":true}'
    budget = source.NetworkBudget()
    transport = source.GitHubTransport("secret", budget)
    transport.api_opener = cast("Any", _SequenceOpener([retry_error, _Response(raw, url)]))
    monkeypatch.setattr(transport, "_sleep", lambda _attempt: None)
    payload, response_hash = transport.get_json(url)
    assert payload == {"ok": True}
    assert response_hash == _digest(raw)
    assert budget.requests == 2
    assert budget.response_bytes == len(b"retry") + len(raw)

    oversized_budget = source.NetworkBudget()
    oversized_transport = source.GitHubTransport("secret", oversized_budget)
    oversized_transport.api_opener = cast(
        "Any",
        _SequenceOpener([_Response(b"x" * (source._MAX_API_BYTES + 1), url)]),
    )
    with pytest.raises(source.PilotSourceError, match="API response exceeded"):
        oversized_transport.get_json(url)
    assert oversized_budget.requests == 1
    assert oversized_budget.response_bytes > source._MAX_API_BYTES


def test_slow_http_error_body_is_wall_bounded() -> None:
    class SlowBody:
        def read(self, _size: int = -1) -> bytes:
            time.sleep(0.2)
            return b"late"

        def close(self) -> None:
            pass

    url = "https://api.github.com/repos/owner/repo/pulls/7"
    error = urllib.error.HTTPError(url, 500, "slow", Message(), cast("Any", SlowBody()))
    budget = source.NetworkBudget(max_wall_seconds=1, started=time.monotonic() - 0.95)
    transport = source.GitHubTransport("secret", budget)
    started = time.monotonic()
    with pytest.raises(source.PilotSourceError, match="wall-clock"):
        transport._consume_http_error(error)
    assert time.monotonic() - started < 0.5


def test_expired_wall_budget_fails_before_request() -> None:
    budget = source.NetworkBudget(max_wall_seconds=1, started=time.monotonic() - 2)
    with pytest.raises(source.PilotSourceError, match="wall-clock"):
        budget.reserve_request()


def test_request_and_diff_bounds_fail_closed() -> None:
    selected = _selected()
    budget = source.NetworkBudget(max_requests=1)
    with pytest.raises(source.PilotSourceError, match="request budget"):
        source.collect_source_bindings(
            selected,
            FakeTransport(selected, budget),
            budget,
            collected_at="2026-07-16T20:00:00Z",
            collector_sha256=source.collector_sha256(),
        )
    budget = source.NetworkBudget(max_diff_bytes=1)
    with pytest.raises(source.PilotSourceError, match="one diff exceeded"):
        number = selected[0]["number"]
        assert isinstance(number, int)
        FakeTransport(selected, budget).hash_diff(str(selected[0]["repository"]), number)


def test_atomic_no_clobber(tmp_path: Path) -> None:
    output = tmp_path / "bindings.json"
    raw = source._canonical_bytes(_payload())
    source._publish_no_clobber(output, raw)
    with pytest.raises(source.PilotSourceError, match="refusing to overwrite"):
        source._publish_no_clobber(output, b"changed\n")
    assert output.read_bytes() == raw


def test_authenticated_validation_rejects_tampering(tmp_path: Path) -> None:
    bindings = tmp_path / "bindings.json"
    bindings.write_bytes(source._canonical_bytes(_payload()))
    checksums = tmp_path / "checksums.json"
    profile = {
        "schema_version": 1,
        "id": "blind-review-pilot-source-bindings-checksums-v1",
        "preregistration_profile_sha256": source._PILOT_PROFILE_SHA256,
        "collector_sha256": source.collector_sha256(),
        "source_bindings_sha256": _digest(bindings.read_bytes()),
    }
    checksums.write_text(json.dumps(profile), encoding="utf-8")
    validated = source.validate_authenticated(_ROOT, bindings, checksums)
    assert len(validated["records"]) == 3
    bindings.write_bytes(bindings.read_bytes().replace(b'"pr": 2164', b'"pr": 2165', 1))
    with pytest.raises(source.PilotSourceError, match="exact-byte checksum"):
        source.validate_authenticated(_ROOT, bindings, checksums)


def test_duplicate_nonfinite_and_unbalanced_json_are_rejected() -> None:
    with pytest.raises(source.PilotSourceError, match="duplicate JSON key"):
        source._parse_json(b'{"a":1,"a":2}', "duplicate")
    with pytest.raises(source.PilotSourceError, match="non-finite"):
        source._parse_json(b'{"a":NaN}', "nan")
    with pytest.raises(source.PilotSourceError, match="unbalanced"):
        source._parse_json(b'{"a":[1}', "unbalanced")
