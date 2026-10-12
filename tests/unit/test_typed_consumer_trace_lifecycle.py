"""The typed reader is passive outside explicit, isolated audit contexts."""

from __future__ import annotations

import contextvars
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from mypy.nodes import NameExpr, Node

from fastapi_endpoint_detector.analyzer import typed_consumer_trace as reader
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.effect_contract import (
    CallResolutionStatus,
    InvocationKind,
    ResolvedCallSite,
)


def _trace() -> reader.TypedConsumerTrace:
    build = SimpleNamespace(modules={}, manager=SimpleNamespace(rechecked_modules=set()))
    return reader.TypedConsumerTrace(
        reader.ConsumerTraceSnapshot({}), build, source_root=Path.cwd()
    )


def test_import_and_construction_leave_node_reader_unchanged() -> None:
    original = Node.__getattribute__
    assert original is reader._NODE_GETATTRIBUTE
    trace = _trace()
    assert Node.__getattribute__ is original
    assert reader._ACTIVE_TRACE.get() is None
    assert not trace.result().complete


def test_activation_restores_exact_reader_after_body_exception() -> None:
    original = Node.__getattribute__
    trace = _trace()
    error = LookupError("body must remain visible")
    with pytest.raises(LookupError) as caught, trace:
        assert Node.__getattribute__ is reader._audited_node_getattribute
        assert reader._ACTIVE_TRACE.get() is trace
        raise error
    assert caught.value is error
    assert Node.__getattribute__ is original
    assert reader._ACTIVE_TRACE.get() is None
    assert reader._NODE_AUDIT_USERS == 0


def test_failed_field_read_is_observed_and_reraised(monkeypatch: pytest.MonkeyPatch) -> None:
    trace = _trace()
    node = NameExpr("actual_node")
    reads: list[tuple[Node, str, bool]] = []

    def record(owner: Node, field: str, *, value_present: bool = True) -> None:
        reads.append((owner, field, value_present))

    monkeypatch.setattr(trace, "observe_node_field", record)
    with trace:
        value = node.name
        assert value == "actual_node"
        with pytest.raises(AttributeError):
            getattr(node, "definitely_absent_audit_field")  # noqa: B009
    assert reads == [
        (node, "name", True),
        (node, "definitely_absent_audit_field", False),
    ]


def test_overlapping_contexts_keep_their_reader_until_last_exit() -> None:
    outer, inner = _trace(), _trace()
    entered, release = threading.Event(), threading.Event()
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            with inner:
                assert reader._ACTIVE_TRACE.get() is inner
                assert Node.__getattribute__ is reader._audited_node_getattribute
                entered.set()
                assert release.wait(5)
            assert reader._ACTIVE_TRACE.get() is None
        except BaseException as error:
            errors.append(error)
            entered.set()

    with outer:
        thread = threading.Thread(target=worker)
        thread.start()
        try:
            assert entered.wait(5)
            assert reader._ACTIVE_TRACE.get() is outer
            assert Node.__getattribute__ is reader._audited_node_getattribute
        finally:
            release.set()
            thread.join(5)
        assert not thread.is_alive()
        assert not errors, errors
        assert reader._ACTIVE_TRACE.get() is outer
        assert Node.__getattribute__ is reader._audited_node_getattribute
        assert reader._NODE_AUDIT_USERS == 1
    assert reader._NODE_AUDIT_USERS == 0
    assert Node.__getattribute__ is reader._NODE_GETATTRIBUTE


def test_nested_trace_rejection_keeps_outer_context_active() -> None:
    outer, inner = _trace(), _trace()
    with outer:
        with pytest.raises(reader.ConsumerTraceRejected, match="nested"):
            inner.__enter__()
        assert reader._ACTIVE_TRACE.get() is outer
        assert reader._NODE_AUDIT_USERS == 1
        assert "nested" in " ".join(outer.result().blockers)
    assert Node.__getattribute__ is reader._NODE_GETATTRIBUTE


def test_same_trace_cannot_be_reused_from_another_context() -> None:
    trace = _trace()
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            with pytest.raises(RuntimeError, match="entered twice"):
                trace.__enter__()
            assert reader._ACTIVE_TRACE.get() is None
        except BaseException as error:
            errors.append(error)

    with trace:
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(5)
        assert not thread.is_alive()
        assert not errors, errors
        assert reader._ACTIVE_TRACE.get() is trace
        assert reader._NODE_AUDIT_USERS == 1
    assert Node.__getattribute__ is reader._NODE_GETATTRIBUTE
    with pytest.raises(RuntimeError, match="entered twice"):
        trace.__enter__()
    assert reader._ACTIVE_TRACE.get() is None
    assert reader._NODE_AUDIT_USERS == 0


def test_foreign_reader_before_enter_is_rejected_without_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace = _trace()

    def foreign(node: Node, field: str) -> object:
        return reader._NODE_GETATTRIBUTE(node, field)

    monkeypatch.setattr(Node, "__getattribute__", foreign)
    with pytest.raises(reader.ConsumerTraceRejected, match="conflicts"):
        trace.__enter__()
    assert Node.__getattribute__ is foreign
    assert reader._ACTIVE_TRACE.get() is None
    assert reader._NODE_AUDIT_USERS == 0


def test_foreign_reader_during_context_does_not_hide_body_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace = _trace()
    original = Node.__getattribute__

    def foreign(node: Node, field: str) -> object:
        return original(node, field)

    error = LookupError("original body exception")
    try:
        with pytest.raises(LookupError) as caught, trace:
            monkeypatch.setattr(Node, "__getattribute__", foreign)
            raise error
        assert caught.value is error
        assert Node.__getattribute__ is foreign
        assert "replaced during the transaction" in " ".join(trace.result().blockers)
        assert reader._NODE_AUDIT_USERS == 0
        assert reader._ACTIVE_TRACE.get() is None
        with pytest.raises(reader.ConsumerTraceRejected, match="conflicts"):
            _trace().__enter__()
    finally:
        # monkeypatch saw the active wrapper; restore the original method explicitly.
        monkeypatch.undo()
        Node.__getattribute__ = original


def test_failed_context_activation_releases_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    trace = _trace()

    class FailedContext:
        @staticmethod
        def get() -> None:
            return None

        @staticmethod
        def set(_value: object) -> None:
            raise ValueError("activation failed")

    monkeypatch.setattr(reader, "_ACTIVE_TRACE", FailedContext())
    with pytest.raises(ValueError, match="activation failed"):
        trace.__enter__()
    assert trace._token is None
    assert reader._NODE_AUDIT_USERS == 0
    assert Node.__getattribute__ is reader._NODE_GETATTRIBUTE


def test_exit_from_wrong_context_preserves_owner_until_correct_exit() -> None:
    trace = _trace()
    other = contextvars.Context()
    trace.__enter__()
    try:
        with pytest.raises(ValueError):
            other.run(trace.__exit__)
        assert reader._ACTIVE_TRACE.get() is trace
        assert reader._NODE_AUDIT_USERS == 1
        assert Node.__getattribute__ is reader._audited_node_getattribute
    finally:
        trace.__exit__()
    assert reader._NODE_AUDIT_USERS == 0
    assert Node.__getattribute__ is reader._NODE_GETATTRIBUTE


@pytest.mark.parametrize("status", ["exact", "unresolved", "ambiguous"])
def test_cached_call_resolution_is_observed_without_changing_identity(status: str) -> None:
    source = Path.cwd() / "readonly_trace_call.py"
    exact = status == "exact"
    site = ResolvedCallSite(
        file_path=str(source.resolve()),
        line=1,
        column=0,
        end_line=1,
        end_column=5,
        source_spelling="probe",
        canonical_symbol="pkg.mod.probe" if exact else None,
        invocation=InvocationKind.FUNCTION if exact else None,
        status=CallResolutionStatus(status),
        resolver="mypy",
        resolver_version="test",
        reason_code=None if exact else "test_nonexact",
    )
    call = object()
    analyzer = object.__new__(MypyAnalyzer)
    analyzer._resolved_call_site_cache = {id(call): site}
    analyzer._modules_by_canonical_path = {str(source.resolve()): ("pkg.mod",)}
    trace = _trace()
    with trace:
        observed = analyzer._resolved_call_site(call, str(source), {})
    assert observed is site
    blockers = trace.result().blockers
    assert any("nonexact typed consumer in pkg.mod" in blocker for blocker in blockers) is (
        not exact
    )


def test_absent_cached_call_resolution_is_preserved() -> None:
    call = object()
    analyzer = object.__new__(MypyAnalyzer)
    analyzer._resolved_call_site_cache = {id(call): None}
    trace = _trace()
    with trace:
        assert analyzer._resolved_call_site(call, str(Path.cwd() / "absent.py"), {}) is None
    assert not trace.result().blockers
