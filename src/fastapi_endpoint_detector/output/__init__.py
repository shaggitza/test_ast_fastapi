"""
Output package for FastAPI Endpoint Change Detector.

This package contains formatters for displaying analysis results
in various formats (text, JSON, YAML, Markdown, HTML).
"""

from fastapi_endpoint_detector.output.formatters import (
    BaseFormatter,
    get_formatter,
)
from fastapi_endpoint_detector.output.text_output import TextFormatter
from fastapi_endpoint_detector.output.json_output import JsonFormatter
from fastapi_endpoint_detector.output.yaml_output import YamlFormatter
from fastapi_endpoint_detector.output.markdown_output import MarkdownFormatter
from fastapi_endpoint_detector.output.html_output import HtmlFormatter

__all__ = [
    "BaseFormatter",
    "get_formatter",
    "TextFormatter",
    "JsonFormatter",
    "YamlFormatter",
    "MarkdownFormatter",
    "HtmlFormatter",
]
