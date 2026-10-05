"""Configured formatter behavior and presentation-only invariants."""

import json
import re
from pathlib import Path

import pytest

from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo
from fastapi_endpoint_detector.models.report import (
    AffectedEndpoint,
    AnalysisReport,
    ConfidenceLevel,
)
from fastapi_endpoint_detector.output.formatters import get_formatter


def make_report() -> AnalysisReport:
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
        changed_files=["service.py"],
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


@pytest.mark.parametrize("name", ["text", "markdown", "html", "json", "yaml"])
@pytest.mark.parametrize(
    "option", ["show_confidence", "show_dependency_chain", "colorize", "verbose"]
)
@pytest.mark.parametrize("value", ["false", None, [], 42])
def test_formatter_rejects_non_boolean_mapping_values(
    name: str, option: str, value: object
) -> None:
    with pytest.raises(
        ValueError,
        match=rf"Output option '{option}' for formatter '{name}' must be a bool",
    ):
        get_formatter(name, {option: value})


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
