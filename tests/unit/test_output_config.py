"""Configured formatter behavior and presentation-only invariants."""

import json
import re
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from fastapi_endpoint_detector.config import Config, OutputConfig
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo
from fastapi_endpoint_detector.models.report import (
    AffectedEndpoint,
    AnalysisLimitationReport,
    AnalysisReport,
    ConfidenceLevel,
    ExecutionEvidence,
)
from fastapi_endpoint_detector.output.formatters import get_formatter


@pytest.mark.parametrize("value", [True, False, 1.0, "1"])
def test_analysis_limitation_call_column_requires_strict_nonnegative_int(value: object) -> None:
    with pytest.raises(ValidationError):
        AnalysisLimitationReport(
            file_path="service.py",
            call_line=1,
            call_column=value,
            cap="MAX_DEPTH",
        )


@pytest.mark.parametrize("value", [None, 0, 7])
def test_analysis_limitation_call_column_accepts_optional_int(value: int | None) -> None:
    item = AnalysisLimitationReport(
        file_path="service.py",
        call_line=1,
        call_column=value,
        cap="MAX_DEPTH",
    )
    assert item.call_column == value


@pytest.mark.parametrize(
    "field", ["show_confidence", "show_dependency_chain", "colorize", "verbose"]
)
@pytest.mark.parametrize("raw", ['"false"', '"yes"', "1", "0"])
def test_raw_yaml_output_options_reject_non_booleans_before_coercion(field: str, raw: str) -> None:
    payload = yaml.safe_load(f"output:\n  {field}: {raw}\n")
    with pytest.raises(ValidationError):
        Config.model_validate(payload)
    with pytest.raises(ValidationError):
        OutputConfig.model_validate(payload["output"])


@pytest.mark.parametrize("value", [True, False])
def test_output_options_accept_actual_booleans(value: bool) -> None:
    options = dict.fromkeys(OutputConfig.model_fields, value)
    assert Config.model_validate({"output": options}).output.model_dump() == options


def make_report(changed_files: list[str] | None = None) -> AnalysisReport:
    endpoint = Endpoint(
        path="/items",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="items", module="api.items", file_path=Path("/app/api.py"), line_number=12
        ),
    )
    affected = AffectedEndpoint(
        endpoint=endpoint,
        confidence=ConfidenceLevel.LOW,
        reason="bounded dependency evidence",
        dependency_chain=["service.py", "items"],
        changed_files=["service.py"] if changed_files is None else changed_files,
    )
    return AnalysisReport(
        app_path="/app",
        diff_source="change.diff",
        total_endpoints=1,
        affected_endpoints=[affected],
        candidate_endpoints=[affected],
    )


@pytest.mark.parametrize("name", ["text", "markdown", "html"])
def test_human_presentation_options_do_not_change_report_accounting(name: str) -> None:
    report = make_report()
    before = report.model_dump(mode="json")
    output = get_formatter(
        name,
        {
            "show_confidence": False,
            "show_dependency_chain": False,
            "verbose": True,
        },
    ).format(report)

    assert report.model_dump(mode="json") == before
    assert report.affected_count == 1
    assert report.candidate_endpoints[0].confidence is ConfidenceLevel.LOW
    assert "LOW Confidence" not in output
    assert "service.py → items" not in output
    assert "Changed files:" in output
    if name == "html":
        assert "Condensed static call graph" not in output
        assert "Show linear tracebacks" not in output


def test_text_colorize_false_emits_no_terminal_ansi() -> None:
    output = get_formatter("text", {"colorize": False}).format(make_report())
    assert re.search(r"\x1b\[[0-?]*[ -/]*[@-~]", output) is None


def test_text_verbose_changed_paths_are_literal_and_single_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    paths = ["src/[bold]handler.py", r"C:\service\api.py", "line\nbreak.py"]
    output = get_formatter("text", {"verbose": True}).format(make_report(paths))

    assert "src/[bold]handler.py" in output
    assert r"C:\service\api.py" in output
    assert r"line\nbreak.py" in output
    assert "line\nbreak.py" not in output
    # Other Rich-authored labels still use their intended styles.
    assert "\x1b[1m" in output


@pytest.mark.parametrize("name", ["json", "yaml"])
@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("show_confidence", False),
        ("show_dependency_chain", True),
        ("colorize", False),
        ("verbose", True),
    ],
)
def test_structured_formats_reject_non_default_presentation_options(
    name: str, option: str, value: bool
) -> None:
    with pytest.raises(ValueError, match=rf"option '{option}'.*'{name}'"):
        get_formatter(name, {option: value})


def test_structured_default_output_preserves_validated_schema() -> None:
    report = make_report()
    default_output = json.loads(get_formatter("json").format(report))
    configured_output = json.loads(
        get_formatter(
            "json",
            {"show_confidence": True, "show_dependency_chain": False, "colorize": True},
        ).format(report)
    )
    assert configured_output == default_output
    assert configured_output["affected_endpoints"][0]["dependency_chain"] == [
        "service.py",
        "items",
    ]


def test_unknown_format_option_and_unsupported_color_errors_are_specific() -> None:
    with pytest.raises(ValueError, match="Unknown formatter: csv"):
        get_formatter("csv")
    with pytest.raises(ValueError, match=r"Unknown output option 'rainbow'.*'text'"):
        get_formatter("text", {"rainbow": True})
    with pytest.raises(ValueError, match=r"'colorize'.*only supported by 'text'"):
        get_formatter("markdown", {"colorize": False})


def test_unconfigured_factory_and_direct_formatter_constructors_remain_compatible() -> None:
    report = make_report()
    assert "Chain: service.py → items" in get_formatter("text").format(report)
    assert "**Chain:**" in get_formatter("markdown").format(report)
    assert "Chain:" in get_formatter("html").format(report)


@pytest.mark.parametrize("name", ["json", "yaml"])
def test_structured_formats_preserve_bounded_execution_evidence(name: str) -> None:
    report = make_report()
    report.analysis_limitations = [
        AnalysisLimitationReport(
            file_path="service.py",
            call_line=17,
            call_column=9,
            cap="MAX_DEPTH",
            target_count=2,
            limit=1,
        ),
        AnalysisLimitationReport(
            file_path="service.py",
            call_line=17,
            call_column=31,
            cap="MAX_POINTS_TO_EDGES",
            target_count=3,
            limit=2,
        ),
    ]
    execution_evidence = tuple(
        ExecutionEvidence(
            file_path="service.py",
            start_line=17,
            start_column=4,
            end_line=17,
            end_column=20,
            execution_state=state,
            provenance="bounded source callable evidence",
        )
        for state in (
            "lexical_reference",
            "possible_execution",
            "established_execution",
            "deferred_execution",
        )
    )
    affected_data = report.affected_endpoints[0].model_dump()
    affected_data["execution_evidence"] = execution_evidence
    affected = AffectedEndpoint.model_validate(affected_data)
    report.affected_endpoints = [affected]
    report.candidate_endpoints = [affected]
    before = report.model_dump(mode="json")
    output = get_formatter(name).format(report)
    assert [
        item["call_column"] for item in report.model_dump(mode="json")["analysis_limitations"]
    ] == [9, 31]
    data = json.loads(output) if name == "json" else yaml.safe_load(output)
    assert data["analysis_limitations"] == before["analysis_limitations"]
    for collection in ("affected_endpoints", "candidate_endpoints"):
        assert (
            data[collection][0]["execution_evidence"] == before[collection][0]["execution_evidence"]
        )
    assert report.model_dump(mode="json") == before


@pytest.mark.parametrize("name", ["text", "markdown", "html", "json", "yaml"])
@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("show_confidence", "false"),
        ("show_dependency_chain", 1),
        ("colorize", None),
        ("verbose", []),
    ],
)
def test_formatter_factory_rejects_non_boolean_presentation_values(
    name: str, option: str, value: object
) -> None:
    with pytest.raises(ValueError, match=f"Output option '{option}'.*'{name}'.*must be a bool"):
        get_formatter(name, {option: value})
