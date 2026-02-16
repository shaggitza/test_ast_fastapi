"""
HTML output formatter with interactive features.
"""

import html
import re
from pathlib import Path

from fastapi_endpoint_detector.models.endpoint import Endpoint
from fastapi_endpoint_detector.models.report import AnalysisReport, ConfidenceLevel
from fastapi_endpoint_detector.output.formatters import BaseFormatter, register_formatter


@register_formatter("html")
class HtmlFormatter(BaseFormatter):
    """
    Format output as interactive HTML with hover features.
    """

    def __init__(self) -> None:
        """Initialize the HTML formatter."""
        self._file_cache: dict[str, list[str]] = {}

    def _get_file_lines(self, file_path: str) -> list[str]:
        """
        Get lines from a file, caching the result.

        Args:
            file_path: Path to the file to read.

        Returns:
            List of lines in the file.
        """
        if file_path not in self._file_cache:
            try:
                path = Path(file_path)
                if path.exists():
                    self._file_cache[file_path] = path.read_text(encoding="utf-8").splitlines()
                else:
                    self._file_cache[file_path] = []
            except (OSError, UnicodeDecodeError):
                self._file_cache[file_path] = []
        return self._file_cache[file_path]

    def _get_code_context(self, file_path: str, line_number: int, context: int = 3) -> str:
        """
        Get code context around a line number.

        Args:
            file_path: Path to the file.
            line_number: Line number (1-indexed).
            context: Number of lines before and after to include.

        Returns:
            HTML string with escaped code context and basic line highlighting.
        """
        return self._get_code_context_range(file_path, line_number, line_number, context)
    
    def _get_code_context_range(
        self, 
        file_path: str, 
        start_line: int, 
        end_line: int, 
        context: int = 3
    ) -> str:
        """
        Get code context around a line range, highlighting all lines in the range.

        Args:
            file_path: Path to the file.
            start_line: Starting line number (1-indexed).
            end_line: Ending line number (1-indexed).
            context: Number of lines before and after to include.

        Returns:
            HTML string with escaped code context and basic line highlighting.
        """
        lines = self._get_file_lines(file_path)
        if not lines:
            return "<pre>File not found or could not be read</pre>"

        # Convert to 0-indexed
        start_idx = start_line - 1
        end_idx = end_line - 1
        
        # Calculate display range with context
        display_start = max(0, start_idx - context)
        display_end = min(len(lines), end_idx + context + 1)

        html_lines = []
        html_lines.append('<pre class="code-context">')
        for i in range(display_start, display_end):
            line_num = i + 1
            line_content = html.escape(lines[i])
            # Highlight all lines in the range
            if start_idx <= i <= end_idx:
                html_lines.append(
                    f'<span class="highlight-line">'
                    f'<span class="line-num">{line_num:4d}</span> {line_content}'
                    f"</span>"
                )
            else:
                html_lines.append(f'<span class="line-num">{line_num:4d}</span> {line_content}')
        html_lines.append("</pre>")
        return "\n".join(html_lines)

    def _parse_line_range(self, code_context: str | None) -> tuple[int, int] | None:
        """
        Parse line range from code_context field.
        
        The code_context field may contain a '[lines X-Y]' prefix when
        consecutive lines are grouped together in call stack frames.
        
        Args:
            code_context: The code context string that may contain range notation.
            
        Returns:
            Tuple of (start_line, end_line) if range found, None otherwise.
        """
        if not code_context or not code_context.startswith("[lines "):
            return None
            
        match = re.match(r'\[lines (\d+)-(\d+)\]', code_context)
        if match:
            return (int(match.group(1)), int(match.group(2)))
        return None
    
    def _format_frame_label(
        self, 
        file_path: str, 
        start_line: int, 
        end_line: int | None, 
        function_name: str
    ) -> str:
        """
        Format a call stack frame label.
        
        Args:
            file_path: Path to the file.
            start_line: Starting line number.
            end_line: Optional ending line number for ranges.
            function_name: Name of the function.
            
        Returns:
            Formatted frame label string.
        """
        file_name = Path(file_path).name
        if end_line and end_line > start_line:
            return f'File "{file_name}", lines {start_line}-{end_line}, in {function_name}'
        else:
            return f'File "{file_name}", line {start_line}, in {function_name}'
    
    def _confidence_color(self, confidence: ConfidenceLevel) -> str:
        """Get CSS color class for a confidence level."""
        colors = {
            ConfidenceLevel.HIGH: "confidence-high",
            ConfidenceLevel.MEDIUM: "confidence-medium",
            ConfidenceLevel.LOW: "confidence-low",
        }
        return colors.get(confidence, "confidence-unknown")

    def _confidence_emoji(self, confidence: ConfidenceLevel) -> str:
        """Get an emoji for a confidence level."""
        emojis = {
            ConfidenceLevel.HIGH: "🔴",
            ConfidenceLevel.MEDIUM: "🟡",
            ConfidenceLevel.LOW: "🟢",
        }
        return emojis.get(confidence, "⚪")

    def _get_html_template(self) -> str:
        """Get the HTML template with inline CSS."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FastAPI Endpoint Change Detector - Analysis Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }

        h2 {
            color: #34495e;
            margin-top: 30px;
            margin-bottom: 15px;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 8px;
        }

        h3 {
            color: #7f8c8d;
            margin-top: 20px;
            margin-bottom: 10px;
        }

        .summary {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }

        .summary-item {
            margin: 5px 0;
        }

        .summary-label {
            font-weight: bold;
            color: #2c3e50;
        }

        .endpoint-card {
            background: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
            transition: box-shadow 0.2s;
        }

        .endpoint-card:hover {
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }

        .endpoint-header {
            font-size: 1.1em;
            margin-bottom: 10px;
        }

        .method-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 0.85em;
            margin-right: 5px;
        }

        .method-GET { background: #61affe; color: white; }
        .method-POST { background: #49cc90; color: white; }
        .method-PUT { background: #fca130; color: white; }
        .method-DELETE { background: #f93e3e; color: white; }
        .method-PATCH { background: #50e3c2; color: white; }
        .method-OPTIONS { background: #9012fe; color: white; }
        .method-HEAD { background: #0d5aa7; color: white; }

        .endpoint-path {
            font-family: "Courier New", monospace;
            background: #f8f9fa;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 0.95em;
        }

        .confidence-high {
            border-left: 4px solid #e74c3c;
        }

        .confidence-medium {
            border-left: 4px solid #f39c12;
        }

        .confidence-low {
            border-left: 4px solid #27ae60;
        }

        .info-item {
            margin: 8px 0;
            padding-left: 10px;
        }

        .label {
            font-weight: bold;
            color: #555;
        }

        .code-ref {
            font-family: "Courier New", monospace;
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.9em;
            cursor: help;
            position: relative;
            display: inline-block;
        }

        .code-ref:hover {
            background: #e9ecef;
        }

        .hover-tooltip {
            display: none;
            position: absolute;
            top: 100%;
            left: 0;
            z-index: 1000;
            background: #2c3e50;
            color: #ecf0f1;
            padding: 10px;
            border-radius: 5px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            margin-top: 5px;
            min-width: 400px;
            max-width: 600px;
        }

        .code-ref:hover .hover-tooltip {
            display: block;
        }

        .code-context {
            font-family: "Courier New", Consolas, Monaco, monospace;
            font-size: 0.85em;
            line-height: 1.4;
            white-space: pre;
            overflow-x: auto;
            margin: 0;
            padding: 8px;
            background: #1e1e1e;
            color: #d4d4d4;
            border-radius: 3px;
        }

        .line-num {
            color: #858585;
            margin-right: 10px;
            user-select: none;
        }

        .highlight-line {
            background: #264f78;
            display: block;
        }

        .call-stack {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
            font-family: "Courier New", monospace;
            font-size: 0.9em;
        }

        .dependency-chain {
            background: #e8f4f8;
            padding: 8px;
            border-radius: 4px;
            margin-top: 8px;
            font-family: "Courier New", monospace;
            font-size: 0.9em;
        }

        .error-box {
            background: #fee;
            border: 1px solid #fcc;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }

        .error-box h3 {
            color: #c33;
            margin-top: 0;
        }

        .warning-box {
            background: #fffbea;
            border: 1px solid #ffd700;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }

        .warning-box h3 {
            color: #cc8800;
            margin-top: 0;
        }

        .no-endpoints {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
            font-size: 1.1em;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }

        th {
            background: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }

        td {
            padding: 10px 12px;
            border-bottom: 1px solid #e0e0e0;
        }

        tr:hover {
            background: #f8f9fa;
        }

        code {
            font-family: "Courier New", monospace;
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
{CONTENT}
    </div>
</body>
</html>
"""

    def _format_code_ref(
        self,
        file_path: str,
        line_number: int,
        label: str | None = None,
        end_line_number: int | None = None,
    ) -> str:
        """
        Format a code reference with hover tooltip.

        Args:
            file_path: Path to the file.
            line_number: Starting line number.
            label: Optional label to display (defaults to file:line).
            end_line_number: Optional ending line number for ranges.

        Returns:
            HTML string with hover tooltip.
        """
        if label is None:
            if end_line_number and end_line_number > line_number:
                label = f"{Path(file_path).name}:{line_number}-{end_line_number}"
            else:
                label = f"{Path(file_path).name}:{line_number}"

        context = self._get_code_context_range(
            file_path, line_number, end_line_number or line_number
        )
        return (
            f'<span class="code-ref">'
            f"{html.escape(label)}"
            f'<span class="hover-tooltip">{context}</span>'
            f"</span>"
        )

    def format(self, report: AnalysisReport) -> str:
        """Format an analysis report as interactive HTML."""
        content_lines = []

        # Header
        content_lines.append("<h1>FastAPI Endpoint Change Detector</h1>")
        content_lines.append("<p style='color: #7f8c8d; font-size: 1.1em;'>Analysis Report</p>")

        # Summary
        content_lines.append("<h2>Summary</h2>")
        content_lines.append('<div class="summary">')
        content_lines.append(
            '<div class="summary-item">'
            '<span class="summary-label">App Path:</span> '
            f"<code>{html.escape(report.app_path)}</code>"
            "</div>"
        )
        content_lines.append(
            '<div class="summary-item">'
            '<span class="summary-label">Diff Source:</span> '
            f"<code>{html.escape(report.diff_source)}</code>"
            "</div>"
        )
        content_lines.append(
            f'<div class="summary-item">'
            f'<span class="summary-label">Total Endpoints:</span> {report.total_endpoints}'
            f"</div>"
        )
        content_lines.append(
            f'<div class="summary-item">'
            f'<span class="summary-label">Files Changed:</span> '
            f"{report.total_files_changed} ({report.python_files_changed} Python)"
            f"</div>"
        )
        content_lines.append(
            f'<div class="summary-item">'
            f'<span class="summary-label">Affected Endpoints:</span> {report.affected_count}'
            f"</div>"
        )
        content_lines.append(
            f'<div class="summary-item">'
            f'<span class="summary-label">Orphan Changes:</span> '
            f'{report.total_orphan_lines} lines in {report.orphan_count} files'
            f"</div>"
        )
        if report.analysis_duration_ms:
            content_lines.append(
                f'<div class="summary-item">'
                f'<span class="summary-label">Analysis Time:</span> {report.analysis_duration_ms:.2f}ms'
                f"</div>"
            )
        content_lines.append("</div>")

        # Affected endpoints
        if report.affected_endpoints:
            content_lines.append("<h2>Affected Endpoints</h2>")

            # Group by confidence
            for confidence in [ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW]:
                endpoints = report.get_endpoints_by_confidence(confidence)
                if not endpoints:
                    continue

                emoji = self._confidence_emoji(confidence)
                content_lines.append(
                    f"<h3>{emoji} {confidence.value.upper()} Confidence ({len(endpoints)})</h3>"
                )

                for ae in endpoints:
                    ep = ae.endpoint
                    confidence_class = self._confidence_color(ae.confidence)

                    content_lines.append(f'<div class="endpoint-card {confidence_class}">')

                    # Endpoint header
                    content_lines.append('<div class="endpoint-header">')
                    for method in ep.methods:
                        content_lines.append(
                            f'<span class="method-badge method-{method.value}">{method.value}</span>'
                        )
                    content_lines.append(
                        f'<span class="endpoint-path">{html.escape(ep.path)}</span>'
                    )
                    content_lines.append("</div>")

                    # Handler info with hover
                    handler_label = (
                        f"{ep.handler.name} "
                        f"({Path(ep.handler.file_path).name}:{ep.handler.line_number})"
                    )
                    handler_ref = self._format_code_ref(
                        str(ep.handler.file_path),
                        ep.handler.line_number,
                        handler_label,
                    )
                    content_lines.append(
                        f'<div class="info-item">'
                        f'<span class="label">Handler:</span> {handler_ref}'
                        f"</div>"
                    )

                    # Reason
                    content_lines.append(
                        f'<div class="info-item">'
                        f'<span class="label">Reason:</span> {html.escape(ae.reason)}'
                        f"</div>"
                    )

                    # Dependency chain
                    if ae.dependency_chain and len(ae.dependency_chain) > 1:
                        chain_html = " → ".join(
                            f"<code>{html.escape(dep)}</code>" for dep in ae.dependency_chain
                        )
                        content_lines.append(
                            f'<div class="dependency-chain">'
                            f'<span class="label">Chain:</span> {chain_html}'
                            f"</div>"
                        )

                    # Call stack with hover on each frame
                    if ae.call_stack:
                        content_lines.append('<div class="call-stack">')
                        content_lines.append("<strong>Call Stack:</strong><br>")
                        for frame in ae.call_stack:
                            # Extract line range from code_context if present
                            # Code context uses '[lines X-Y]' notation for grouped consecutive lines
                            line_range = self._parse_line_range(frame.code_context)
                            
                            if line_range:
                                start_line, end_line = line_range
                            else:
                                start_line = frame.line_number
                                end_line = frame.line_number
                            
                            frame_label = self._format_frame_label(
                                frame.file_path,
                                start_line,
                                end_line if end_line > start_line else None,
                                frame.function_name
                            )
                            
                            frame_ref = self._format_code_ref(
                                frame.file_path,
                                start_line,
                                frame_label,
                                end_line,
                            )
                            content_lines.append(f"{frame_ref}<br>")
                        content_lines.append("</div>")

                    content_lines.append("</div>")  # end endpoint-card
        else:
            content_lines.append('<div class="no-endpoints">')
            content_lines.append("✅ No endpoints were affected by the changes.")
            content_lines.append("</div>")

        # Orphan changes
        if report.orphan_changes:
            content_lines.append('<div class="warning-box">')
            content_lines.append("<h3>⚠️ Orphan Code Changes</h3>")
            content_lines.append(
                f'<p><em>Changes not related to any endpoint '
                f'({report.total_orphan_lines} lines in {report.orphan_count} files)</em></p>'
            )
            
            for oc in report.orphan_changes:
                file_name = Path(oc.file_path).name
                content_lines.append('<div style="margin: 15px 0; padding: 10px; background: #fff; border-radius: 5px;">')
                content_lines.append(f'<div style="font-weight: bold; margin-bottom: 5px;">📄 {html.escape(file_name)}</div>')
                content_lines.append(f'<div style="font-size: 0.9em; color: #666;"><code>{html.escape(oc.file_path)}</code></div>')
                content_lines.append(f'<div style="margin-top: 8px; font-family: monospace; font-size: 0.9em;">{html.escape(oc.format_lines())}</div>')
                content_lines.append(f'<div style="margin-top: 5px; font-size: 0.85em; color: #777; font-style: italic;">{html.escape(oc.reason)}</div>')
                content_lines.append('</div>')
            
            content_lines.append('<div style="margin-top: 15px; padding: 10px; background: #f0f0f0; border-radius: 5px; font-size: 0.9em;">')
            content_lines.append('<strong>💡 Tip:</strong> Orphan changes may indicate:')
            content_lines.append('<ul style="margin: 5px 0 0 20px;">')
            content_lines.append('<li>Unused or dead code</li>')
            content_lines.append('<li>Code with incorrect types preventing dependency analysis</li>')
            content_lines.append('<li>Utility code not called by any endpoint</li>')
            content_lines.append('<li>Code outside the analyzed application scope</li>')
            content_lines.append('</ul>')
            content_lines.append('</div>')
            content_lines.append("</div>")

        # Errors
        if report.errors:
            content_lines.append('<div class="error-box">')
            content_lines.append("<h3>❌ Errors</h3>")
            content_lines.append("<ul>")
            for error in report.errors:
                content_lines.append(f"<li>{html.escape(error)}</li>")
            content_lines.append("</ul>")
            content_lines.append("</div>")

        # Warnings
        if report.warnings:
            content_lines.append('<div class="warning-box">')
            content_lines.append("<h3>⚠️ Warnings</h3>")
            content_lines.append("<ul>")
            for warning in report.warnings:
                content_lines.append(f"<li>{html.escape(warning)}</li>")
            content_lines.append("</ul>")
            content_lines.append("</div>")

        # Wrap in template
        content = "\n".join(content_lines)
        return self._get_html_template().replace("{CONTENT}", content)

    def format_endpoints(self, endpoints: list[Endpoint]) -> str:
        """Format a list of endpoints as an HTML table."""
        content_lines = []

        content_lines.append("<h1>FastAPI Endpoints</h1>")

        if not endpoints:
            content_lines.append('<p class="no-endpoints">No endpoints found.</p>')
        else:
            content_lines.append(f"<p><strong>Total:</strong> {len(endpoints)} endpoints</p>")

            content_lines.append("<table>")
            content_lines.append("<thead>")
            content_lines.append("<tr>")
            content_lines.append("<th>Method(s)</th>")
            content_lines.append("<th>Path</th>")
            content_lines.append("<th>Handler</th>")
            content_lines.append("<th>Location</th>")
            content_lines.append("</tr>")
            content_lines.append("</thead>")
            content_lines.append("<tbody>")

            for ep in endpoints:
                content_lines.append("<tr>")

                # Methods
                content_lines.append("<td>")
                for method in ep.methods:
                    content_lines.append(
                        f'<span class="method-badge method-{method.value}">{method.value}</span> '
                    )
                content_lines.append("</td>")

                # Path
                content_lines.append(f"<td><code>{html.escape(ep.path)}</code></td>")

                # Handler
                content_lines.append(f"<td><code>{html.escape(ep.handler.name)}</code></td>")

                # Location with hover
                location_ref = self._format_code_ref(
                    str(ep.handler.file_path),
                    ep.handler.line_number,
                )
                content_lines.append(f"<td>{location_ref}</td>")

                content_lines.append("</tr>")

            content_lines.append("</tbody>")
            content_lines.append("</table>")

        content = "\n".join(content_lines)
        return self._get_html_template().replace("{CONTENT}", content)
