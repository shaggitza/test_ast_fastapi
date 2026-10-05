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


def test_never_called_nested_mutation_does_not_qualify_copy_change(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload):\n"
        "    payload = payload.copy()\n"
        "    def deferred():\n"
        "        payload.update({'x': 1})\n"
        "    return {'ok': True}\n"
    )
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    return dispatch({'x': 0})\n")

    assert EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 2)]) is None


def test_reassignment_kills_returned_alias_observation(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n"
        "    payload = {'model': 'preset'}\n"
        "    dispatch(payload)\n"
        "    payload = {'model': 'replacement'}\n"
        "    return payload\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.LOW
    assert result.evidence[0].observations == [DataObservationKind.NOT_OBSERVED_AFTER_CALL]


def test_annotation_only_assignment_preserves_returned_argument_alias(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n"
        "    payload = {'x': 0}\n"
        "    dispatch(payload)\n"
        "    payload: dict\n"
        "    return payload\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.HIGH
    assert result.evidence[0].observations == [DataObservationKind.RETURNED]


def test_rebinding_in_dead_literal_branch_does_not_kill_returned_alias(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n"
        "    payload = {'x': 0}\n"
        "    dispatch(payload)\n"
        "    if False:\n"
        "        payload = {'x': 1}\n"
        "    return payload\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.HIGH
    assert result.evidence[0].observations == [DataObservationKind.RETURNED]


def test_branch_reassignment_does_not_join_old_alias_as_definite(tmp_path: Path) -> None:
    service = _service(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint(flag):\n"
        "    payload = {'model': 'preset'}\n"
        "    dispatch(payload)\n"
        "    if flag:\n"
        "        payload = {'model': 'replacement'}\n"
        "    return payload\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.LOW
    assert result.evidence[0].observations == [DataObservationKind.NOT_OBSERVED_AFTER_CALL]


def test_unknown_copy_method_does_not_claim_defensive_copy(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload):\n"
        "    payload = payload.copy()\n"
        "    payload.update({'x': 1})\n"
        "    return payload\n"
    )
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    return dispatch({'x': 0})\n")

    assert EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 2)]) is None


def test_literal_dead_branch_mutation_does_not_qualify_copy(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload):\n"
        "    payload = {**payload}\n"
        "    if False:\n"
        "        payload.update({'x': 1})\n"
        "    return {'ok': True}\n"
    )
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    return dispatch({'x': 0})\n")

    assert EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 2)]) is None


def test_shadowed_dict_constructor_does_not_qualify_copy(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload):\n"
        "    dict = custom_copy\n"
        "    payload = dict(payload)\n"
        "    payload.update({'x': 1})\n"
        "    return payload\n"
    )
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    return dispatch({'x': 0})\n")

    assert EffectAnalyzer(tmp_path).analyze(str(service), {3}, [_stack(main, service, 2)]) is None


def test_dict_constructor_capture_and_wildcard_import_are_not_builtin_proof(
    tmp_path: Path,
) -> None:
    service = tmp_path / "service.py"
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    return dispatch({'x': 0})\n")
    shadows = (
        (
            "def dispatch(payload):\n"
            "    match payload:\n"
            "        case dict:\n"
            "            pass\n"
            "    payload = dict(payload)\n"
            "    payload.update({'x': 1})\n",
            6,
        ),
        (
            "def dispatch(payload):\n"
            "    try:\n"
            "        pass\n"
            "    except Exception as dict:\n"
            "        pass\n"
            "    payload = dict(payload)\n"
            "    payload.update({'x': 1})\n",
            6,
        ),
        (
            "from helpers import *\n"
            "def dispatch(payload):\n"
            "    payload = dict(payload)\n"
            "    payload.update({'x': 1})\n",
            3,
        ),
    )
    for source, copy_line in shadows:
        service.write_text(source)
        assert (
            EffectAnalyzer(tmp_path).analyze(str(service), {copy_line}, [_stack(main, service, 2)])
            is None
        )


def test_invoked_local_helper_mutation_qualifies_copy(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload):\n"
        "    payload = {**payload}\n"
        "    def mutate_captured():\n"
        "        payload.update({'x': 1})\n"
        "    mutate_captured()\n"
        "    return payload\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n    payload = {'x': 0}\n    dispatch(payload)\n    return payload\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.HIGH


def test_uninvoked_local_helper_mutation_does_not_qualify_copy(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload):\n"
        "    payload = {**payload}\n"
        "    def mutate_captured():\n"
        "        payload.update({'x': 1})\n"
        "    return {'ok': True}\n"
    )
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    return dispatch({'x': 0})\n")

    assert EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 2)]) is None


def test_invoked_helper_maps_argument_to_formal_mutation_target(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload):\n"
        "    payload = {**payload}\n"
        "    def mutate(x):\n"
        "        x.update({'x': 1})\n"
        "    mutate(payload)\n"
        "    return payload\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n    payload = {'x': 0}\n    dispatch(payload)\n    return payload\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.HIGH


def test_helper_local_rebinding_does_not_mutate_captured_copy(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    examples = (
        "def dispatch(payload):\n"
        "    payload = {**payload}\n"
        "    def mutate_captured():\n"
        "        payload = {}\n"
        "        payload.update({'x': 1})\n"
        "    mutate_captured()\n"
        "    return payload\n",
        "def dispatch(payload):\n"
        "    payload = {**payload}\n"
        "    def mutate_captured():\n"
        "        payload.update({'x': 1})\n"
        "        payload = {}\n"
        "    mutate_captured()\n"
        "    return payload\n",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n    payload = {}\n    dispatch(payload)\n    return payload\n"
    )

    for source in examples:
        service.write_text(source)
        assert (
            EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)]) is None
        )


def test_branch_alias_join_is_uncertain_when_only_one_arm_aliases_subject(
    tmp_path: Path,
) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload, enabled):\n"
        "    payload = {**payload}\n"
        "    alias = {}\n"
        "    if enabled:\n"
        "        alias = payload\n"
        "    alias.update({'x': 1})\n"
        "    return payload\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n    payload = {}\n    dispatch(payload, False)\n    return payload\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.MEDIUM
    assert result.evidence[0].status.value == "conditional"


def test_alias_assigned_to_subject_on_both_branch_arms_remains_provable(
    tmp_path: Path,
) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload, enabled):\n"
        "    payload = {**payload}\n"
        "    if enabled:\n"
        "        alias = payload\n"
        "    else:\n"
        "        alias = payload\n"
        "    alias.update({'x': 1})\n"
        "    return payload\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n    payload = {}\n    dispatch(payload, False)\n    return payload\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.HIGH
    assert result.evidence[0].status.value == "established"


def test_dead_and_post_terminal_mutations_do_not_qualify_copy(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n    payload = {'x': 0}\n    dispatch(payload)\n    return payload\n"
    )
    dead_blocks = (
        "if False:\n        payload.update({'x': 1})",
        "if 0:\n        payload.update({'x': 1})",
        "if None:\n        payload.update({'x': 1})",
        "while False:\n        payload.update({'x': 1})",
        "return {'ok': True}\n    payload.update({'x': 1})",
        "raise RuntimeError()\n    payload.update({'x': 1})",
        "with nullcontext():\n            if False:\n                payload.update({'x': 1})",
        "with nullcontext():\n            return payload\n        payload.update({'x': 1})",
        (
            "try:\n            return payload\n        finally:\n"
            "            return {'ok': True}\n        payload.update({'x': 1})"
        ),
        "while True:\n            return payload\n        payload.update({'x': 1})",
        "False and payload.update({'x': 1})",
        "items = (payload.update({'x': 1}) for _ in ())",
    )
    for block in dead_blocks:
        service.write_text(
            "def dispatch(payload):\n"
            "    payload = {**payload}\n"
            f"    {block.replace(chr(10), chr(10) + '    ')}\n"
            "    return {'ok': True}\n"
        )
        assert (
            EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 2)]) is None
        )


def test_reassigned_helper_binding_is_not_used_as_mutation_proof(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload):\n"
        "    payload = {**payload}\n"
        "    def mutate(x):\n"
        "        x.update({'x': 1})\n"
        "    mutate = replacement\n"
        "    mutate(payload)\n"
        "    return payload\n"
    )
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    return dispatch({'x': 0})\n")

    assert EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 2)]) is None


def test_helper_mutation_after_terminal_or_formal_rebinding_is_not_proof(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    return dispatch({'x': 0})\n")
    helpers = (
        "def mutate(x):\n        return\n        x.update({'x': 1})",
        "def mutate(x):\n        x = {}\n        x.update({'x': 1})",
    )
    for helper in helpers:
        service.write_text(
            "def dispatch(payload):\n"
            "    payload = {**payload}\n"
            f"    {helper.replace(chr(10), chr(10) + '    ')}\n"
            "    mutate(payload)\n"
        )
        assert (
            EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 2)]) is None
        )


def test_unawaited_async_helper_is_not_an_executed_mutation(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "async def dispatch(payload):\n"
        "    payload = {**payload}\n"
        "    async def mutate(x):\n"
        "        x.update({'x': 1})\n"
        "    mutate(payload)\n"
        "    return payload\n"
    )
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    return dispatch({'x': 0})\n")

    assert EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 2)]) is None


def test_awaited_async_helper_argument_mutation_qualifies_copy(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "async def dispatch(payload):\n"
        "    payload = {**payload}\n"
        "    async def mutate(x):\n"
        "        x.update({'x': 1})\n"
        "    await mutate(payload)\n"
        "    return payload\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n    payload = {'x': 0}\n    dispatch(payload)\n    return payload\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.HIGH


def test_dead_and_conditional_copy_assignments_do_not_claim_established_copy(
    tmp_path: Path,
) -> None:
    service = tmp_path / "service.py"
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    return dispatch({'x': 0})\n")
    service.write_text(
        "def dispatch(payload):\n"
        "    if False:\n"
        "        payload = {**payload}\n"
        "    payload.update({'x': 1})\n"
    )
    assert EffectAnalyzer(tmp_path).analyze(str(service), {3}, [_stack(main, service, 2)]) is None

    service.write_text(
        "def dispatch(payload, enabled):\n"
        "    if enabled:\n"
        "        payload = {**payload}\n"
        "    payload.update({'x': 1})\n"
    )
    result = EffectAnalyzer(tmp_path).analyze(str(service), {3}, [_stack(main, service, 2)])
    assert result is not None
    assert result.evidence[0].status.value == "conditional"
    assert result.confidence == ConfidenceLevel.MEDIUM


def test_branch_alias_join_is_conditional_and_excludes_mutually_exclusive_alias(
    tmp_path: Path,
) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload, flag):\n"
        "    payload = {**payload}\n"
        "    if flag:\n"
        "        alias = payload\n"
        "    else:\n"
        "        alias = {}\n"
        "    alias.update({'x': 1})\n"
        "    return payload\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n    value = {}\n    dispatch(value, True)\n    return value\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.MEDIUM
    assert result.evidence[0].status.value == "conditional"


def test_unknown_match_mutation_is_conditional(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload, selector):\n"
        "    payload = {**payload}\n"
        "    match selector:\n"
        "        case 1:\n"
        "            payload.update({'x': 1})\n"
        "    return payload\n"
    )
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    value = {}\n    dispatch(value, 1)\n    return value\n")

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.MEDIUM
    assert result.evidence[0].status.value == "conditional"


def test_helper_formal_and_capture_rebindings_do_not_inherit_caller_alias(
    tmp_path: Path,
) -> None:
    service = tmp_path / "service.py"
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    return dispatch({'x': 0})\n")
    examples = (
        "def dispatch(payload):\n"
        "    payload = {**payload}\n"
        "    payload = {}\n"
        "    def mutate(x):\n"
        "        payload.update({'x': 1})\n"
        "    mutate(payload)\n",
        "def dispatch(payload, other):\n"
        "    payload = {**payload}\n"
        "    def mutate(payload):\n"
        "        payload.update({'x': 1})\n"
        "    mutate(other)\n",
        "def dispatch(payload):\n"
        "    payload = {**payload}\n"
        "    def mutate(x):\n"
        "        x = {}\n"
        "        x['x'] = 1\n"
        "    mutate(payload)\n",
    )
    for source in examples:
        service.write_text(source)
        assert (
            EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 2)]) is None
        )


def test_helper_definition_must_remain_callable_and_execute_body(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    return dispatch({'x': 0})\n")
    examples = (
        "def dispatch(payload):\n"
        "    payload = {**payload}\n"
        "    def mutate(x):\n"
        "        yield x\n"
        "        x.update({'x': 1})\n"
        "    mutate(payload)\n",
        "def dispatch(payload):\n"
        "    payload = {**payload}\n"
        "    def mutate(x):\n"
        "        x.update({'x': 1})\n"
        "    mutate = replacement\n"
        "    mutate(payload)\n",
        "def dispatch(payload):\n"
        "    payload = {**payload}\n"
        "    def mutate(x):\n"
        "        x.update({'x': 1})\n"
        "    del mutate\n"
        "    mutate(payload)\n",
    )
    for source in examples:
        service.write_text(source)
        assert (
            EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 2)]) is None
        )


def test_helper_mapping_rejects_starred_and_missing_required_arguments(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    return dispatch({'x': 0})\n")
    for call in ("mutate(*[payload])", "mutate()"):
        service.write_text(
            "def dispatch(payload):\n"
            "    payload = {**payload}\n"
            "    def mutate(x):\n"
            "        x.update({'x': 1})\n"
            f"    {call}\n"
        )
        assert (
            EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 2)]) is None
        )


def test_only_shallow_mutations_of_copy_are_accepted(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    return dispatch({'items': []})\n")
    service.write_text(
        "def dispatch(payload):\n    payload = {**payload}\n    payload['items'].append(1)\n"
    )
    assert EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 2)]) is None

    service.write_text(
        "def dispatch(payload):\n    payload = {**payload}\n    payload |= {'x': 1}\n"
    )
    assert (
        EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 2)]) is not None
    )


def test_conditional_effect_proof_does_not_raise_low_observation_confidence(
    tmp_path: Path,
) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload, enabled):\n"
        "    payload = {**payload}\n"
        "    if enabled:\n"
        "        payload.update({'x': 1})\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n"
        "    payload = {}\n"
        "    dispatch(payload, True)\n"
        "    payload = {}\n"
        "    return {'ok': True}\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.LOW


def test_conditional_mutation_proof_caps_observation_confidence(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload, enabled):\n"
        "    payload = {**payload}\n"
        "    if enabled:\n"
        "        payload.update({'x': 1})\n"
        "    return payload\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n    payload = {'x': 0}\n    dispatch(payload, True)\n    return payload\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.MEDIUM
    assert result.evidence[0].status.value == "conditional"
    assert any("conditional path" in item for item in result.evidence[0].conditions)


def test_mutation_after_conditional_return_is_reported_as_conditional(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload, stop):\n"
        "    payload = {**payload}\n"
        "    if stop:\n"
        "        return payload\n"
        "    payload.update({'x': 1})\n"
        "    return payload\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n"
        "    payload = {'x': 0}\n"
        "    dispatch(payload, False)\n"
        "    return payload\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.MEDIUM
    assert result.evidence[0].status.value == "conditional"


def test_scope_scan_cap_fails_closed(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload):\n"
        "    payload = {**payload}\n" + "    pass\n" * 2200 + "    payload.update({'x': 1})\n"
    )
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    return dispatch({'x': 0})\n")

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 2)])
    assert result is not None
    assert result.evidence[0].status.value == "unresolved"
    assert "2,000 node cap" in result.evidence[0].summary


def test_local_helper_cap_is_reported_as_unresolved(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload):\n"
        "    payload = {**payload}\n"
        + "".join(
            f"    def mutate{index}(value):\n        value.update({{'x{index}': 1}})\n"
            for index in range(9)
        )
        + "".join(f"    mutate{index}(payload)\n" for index in range(9))
    )
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    return dispatch({'x': 0})\n")

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 2)])

    assert result is not None
    assert result.evidence[0].status.value == "unresolved"
    assert "eight helper cap" in result.evidence[0].summary


def test_unused_local_helpers_do_not_consume_invoked_helper_cap(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload):\n"
        "    payload = {**payload}\n"
        + "".join(f"    def unused{index}():\n        pass\n" for index in range(8))
        + "    def mutate(value):\n"
        "        value.update({'x': 1})\n"
        "    mutate(payload)\n"
        "    return payload\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "def endpoint():\n    payload = {}\n    dispatch(payload)\n    return payload\n"
    )

    result = EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 3)])

    assert result is not None
    assert result.confidence == ConfidenceLevel.HIGH
    assert result.evidence[0].status.value == "established"


def test_copy_subject_reassignment_kills_mutation_proof(tmp_path: Path) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload):\n"
        "    payload = {**payload}\n"
        "    payload = {}\n"
        "    payload.update({'x': 1})\n"
        "    return payload\n"
    )
    main = tmp_path / "main.py"
    main.write_text("def endpoint():\n    return dispatch({'x': 0})\n")

    assert EffectAnalyzer(tmp_path).analyze(str(service), {2}, [_stack(main, service, 2)]) is None


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
