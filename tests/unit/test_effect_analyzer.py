from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi_endpoint_detector.analyzer.effect_analyzer import EffectAnalyzer
from fastapi_endpoint_detector.models.report import (
    CallStackFrame,
    ConfidenceLevel,
    DataObservationKind,
    EffectDisposition,
    ImpactChannel,
)

if TYPE_CHECKING:
    from pathlib import Path


def _service(tmp_path: Path) -> Path:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload):\n"
        "    payload = {**payload}\n"
        "    payload['model'] = 'base'\n"
        "    return {'ok': True}\n"
    )
    return service


def _stack(main: Path, service: Path, call_line: int) -> list[CallStackFrame]:
    return [
        CallStackFrame(file_path=str(main), line_number=1, function_name="main.endpoint"),
        CallStackFrame(
            file_path=str(service),
            line_number=1,
            function_name="service.dispatch",
            caller_file_path=str(main),
            caller_line_number=call_line,
        ),
    ]


def test_defensive_copy_with_dead_local_argument_is_low_but_retained(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n"
        "    payload = {'model': 'preset'}\n"
        "    response = dispatch(payload)\n"
        "    return response\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.LOW
    assert result.evidence[0].observations == [DataObservationKind.NOT_OBSERVED_AFTER_CALL]
    assert result.evidence[0].disposition == EffectDisposition.NOT_OBSERVED_BY_CALLER


def test_defensive_copy_with_returned_original_argument_is_high(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n"
        "    payload = {'model': 'preset'}\n"
        "    dispatch(payload)\n"
        "    return payload\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.HIGH
    assert result.evidence[0].observations == [DataObservationKind.RETURNED]
    assert result.evidence[0].disposition == EffectDisposition.OBSERVABLE_BEHAVIOR


def test_defensive_copy_distinguishes_logging_from_public_response(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n"
        "    payload = {'model': 'preset'}\n"
        "    dispatch(payload)\n"
        "    logger.info(payload)\n"
        "    return {'ok': True}\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.MEDIUM
    assert result.evidence[0].observations == [DataObservationKind.LOGGED]
    assert result.evidence[0].disposition == EffectDisposition.OPERATIONAL_ONLY


def test_argument_observation_propagates_through_parameter_forwarding(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def wrapper(payload):\n"
        "    return dispatch(payload)\n\n"
        "def endpoint():\n"
        "    payload = {'model': 'preset'}\n"
        "    wrapper(payload)\n"
        "    return payload\n"
    )
    stack = [
        CallStackFrame(file_path=str(main), line_number=4, function_name="main.endpoint"),
        CallStackFrame(
            file_path=str(main),
            line_number=1,
            function_name="main.wrapper",
            caller_file_path=str(main),
            caller_line_number=6,
        ),
        CallStackFrame(
            file_path=str(service),
            line_number=1,
            function_name="service.dispatch",
            caller_file_path=str(main),
            caller_line_number=2,
        ),
    ]

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [stack])

    assert result is not None
    assert result.confidence == ConfidenceLevel.HIGH
    assert result.evidence[0].observations == [DataObservationKind.RETURNED]


def test_returned_nested_continuation_reaches_endpoint_response(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n"
        "    def process(payload):\n"
        "        dispatch(payload)\n"
        "        return payload\n"
        "    original = {'model': 'preset'}\n"
        "    return process(original)\n"
    )
    stack = [
        CallStackFrame(file_path=str(main), line_number=1, function_name="main.endpoint"),
        CallStackFrame(
            file_path=str(main),
            line_number=2,
            function_name="main.endpoint.process",
            caller_file_path=str(main),
            caller_line_number=6,
        ),
        CallStackFrame(
            file_path=str(service),
            line_number=1,
            function_name="service.dispatch",
            caller_file_path=str(main),
            caller_line_number=3,
        ),
    ]

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [stack])

    assert result is not None
    assert result.confidence == ConfidenceLevel.HIGH
    assert result.evidence[0].observations == [DataObservationKind.RETURNED]


def test_same_named_nested_invocations_do_not_cross_credit_returns(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n"
        "    def process(payload):\n"
        "        dispatch(payload)\n"
        "        return payload\n"
        "    first = {'model': 'first'}\n"
        "    second = {'model': 'second'}\n"
        "    process(first)\n"
        "    return process(second)\n"
    )
    stack = [
        CallStackFrame(file_path=str(main), line_number=1, function_name="main.endpoint"),
        CallStackFrame(
            file_path=str(main),
            line_number=2,
            function_name="main.endpoint.process",
            caller_file_path=str(main),
            caller_line_number=7,
        ),
        CallStackFrame(
            file_path=str(service),
            line_number=1,
            function_name="service.dispatch",
            caller_file_path=str(main),
            caller_line_number=3,
        ),
    ]

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [stack])

    assert result is not None
    assert result.confidence != ConfidenceLevel.HIGH


def test_indirect_nested_call_is_not_credited_from_same_named_attribute(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint(other):\n"
        "    def process(payload):\n"
        "        dispatch(payload)\n"
        "        return payload\n"
        "    callbacks = [process]\n"
        "    first = {'model': 'first'}\n"
        "    callbacks[0](first)\n"
        "    second = {'model': 'second'}\n"
        "    return other.process(second)\n"
    )
    stack = [
        CallStackFrame(file_path=str(main), line_number=1, function_name="main.endpoint"),
        CallStackFrame(
            file_path=str(main),
            line_number=2,
            function_name="main.endpoint.process",
            caller_file_path=str(main),
            caller_line_number=7,
        ),
        CallStackFrame(
            file_path=str(service),
            line_number=1,
            function_name="service.dispatch",
            caller_file_path=str(main),
            caller_line_number=3,
        ),
    ]

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [stack])

    assert result is not None
    assert result.confidence != ConfidenceLevel.HIGH


def test_intermediate_return_ignored_by_endpoint_is_not_high(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def wrapper(payload):\n"
        "    dispatch(payload)\n"
        "    return payload\n\n"
        "def endpoint():\n"
        "    payload = {'model': 'preset'}\n"
        "    wrapper(payload)\n"
        "    return {'ok': True}\n"
    )
    stack = [
        CallStackFrame(file_path=str(main), line_number=5, function_name="main.endpoint"),
        CallStackFrame(
            file_path=str(main),
            line_number=1,
            function_name="main.wrapper",
            caller_file_path=str(main),
            caller_line_number=7,
        ),
        CallStackFrame(
            file_path=str(service),
            line_number=1,
            function_name="service.dispatch",
            caller_file_path=str(main),
            caller_line_number=2,
        ),
    ]

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [stack])

    assert result is not None
    assert result.confidence == ConfidenceLevel.LOW
    assert result.evidence[0].observations == [DataObservationKind.NOT_OBSERVED_AFTER_CALL]


def test_mutually_exclusive_call_and_return_are_not_established(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint(flag):\n"
        "    payload = {'model': 'preset'}\n"
        "    if flag:\n"
        "        dispatch(payload)\n"
        "    else:\n"
        "        return payload\n"
        "    return {'ok': True}\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 4)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.LOW


def test_use_in_conditional_branch_is_not_established_for_every_call(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint(flag):\n"
        "    payload = {'model': 'preset'}\n"
        "    dispatch(payload)\n"
        "    if flag:\n"
        "        return payload\n"
        "    return {'ok': True}\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.MEDIUM
    assert result.evidence[0].status.value == "conditional"


def test_match_and_loop_observations_are_conditional(tmp_path: Path) -> None:
    service = _service(tmp_path)
    for body in (
        "    match flag:\n        case True:\n            return payload\n",
        "    for _ in values:\n        return payload\n",
    ):
        main = tmp_path / "main.py"
        main.write_text(
            "def endpoint(flag=True, values=(1,)):\n"
            "    payload = {'model': 'preset'}\n"
            "    dispatch(payload)\n"
            f"{body}"
            "    return {'ok': True}\n"
        )
        result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])
        assert result is not None
        assert result.confidence == ConfidenceLevel.MEDIUM
        assert result.evidence[0].status.value == "conditional"


def test_name_only_insert_is_dynamic_forwarding_not_persistence(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint(items):\n"
        "    payload = {'model': 'preset'}\n"
        "    dispatch(payload)\n"
        "    items.insert(0, payload)\n"
        "    return {'ok': True}\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.MEDIUM
    assert result.evidence[0].observations == [DataObservationKind.FORWARDED]
    assert result.evidence[0].channel == ImpactChannel.DYNAMIC_EXTENSION


def test_function_name_containing_print_is_not_classified_as_logging(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n"
        "    payload = {'model': 'preset'}\n"
        "    dispatch(payload)\n"
        "    fingerprint(payload)\n"
        "    return {'ok': True}\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.evidence[0].observations == [DataObservationKind.FORWARDED]
    assert result.evidence[0].disposition == EffectDisposition.DYNAMIC_OR_UNRESOLVED


def test_bare_warning_is_dynamic_forwarding_not_logging(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n"
        "    payload = {'model': 'preset'}\n"
        "    dispatch(payload)\n"
        "    warning(payload)\n"
        "    return {'ok': True}\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.evidence[0].observations == [DataObservationKind.FORWARDED]


def test_derived_context_return_is_an_observable_response(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n"
        "    payload = {'model': 'preset'}\n"
        "    response = dispatch(payload)\n"
        "    context = build_context(payload)\n"
        "    return finish(response, context)\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.HIGH
    assert result.evidence[0].observations == [DataObservationKind.RETURNED]


def test_unrecognized_change_does_not_invent_effect_evidence(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text("def dispatch(payload):\n    return payload\n")

    assert EffectAnalyzer(tmp_path).analyze(str(service), {2}, []) is None
