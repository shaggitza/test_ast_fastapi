"""
HTML output formatter with interactive features.
"""

import html
import re
from dataclasses import dataclass, field
from pathlib import Path

from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointInventory
from fastapi_endpoint_detector.models.report import (
    AffectedEndpoint,
    AnalysisReport,
    CallStackFrame,
    CodeReference,
    ConfidenceLevel,
)
from fastapi_endpoint_detector.output.formatters import BaseFormatter, register_formatter


@dataclass(frozen=True)
class _CallPathLocation:
    """A normalized source location used as a graph node identity."""

    role: str
    role_label: str
    function_name: str
    file_path: str
    display_path: str
    line_number: int
    end_line_number: int | None
    source_context: str

    @property
    def identity(self) -> tuple[str, str, int, int, str]:
        """Return a contextual identity, never just a function or basename."""
        return (
            self.role,
            self.file_path,
            self.line_number,
            self.end_line_number or 0,
            self.function_name,
        )

    @property
    def label(self) -> str:
        """Return the full node label for details and accessibility."""
        location = f"{self.display_path}:{self.line_number}"
        if self.end_line_number and self.end_line_number > self.line_number:
            location = f"{self.display_path}:{self.line_number}-{self.end_line_number}"
        return f"{self.function_name} ({location})"


@dataclass
class _CallPathGraphNode:
    """A shared node in the condensed many-to-many call-path graph."""

    node_id: str
    location: _CallPathLocation
    path_indexes: set[int] = field(default_factory=set)
    incoming: set[str] = field(default_factory=set)
    outgoing: set[str] = field(default_factory=set)
    layer: int = 0
    x: int = 0
    y: int = 0


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
            except (OSError, UnicodeDecodeError, ValueError):
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
        self, file_path: str, start_line: int, end_line: int, context: int = 3
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

        match = re.match(r"\[lines (\d+)-(\d+)\]", code_context)
        if match:
            return (int(match.group(1)), int(match.group(2)))
        return None

    def _format_frame_label(
        self, file_path: str, start_line: int, end_line: int | None, function_name: str
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

    def _display_file_path(self, file_path: str, app_path: str) -> str:
        """Return a portable, non-absolute path for the graph labels."""
        path = Path(file_path)
        try:
            candidate = path.resolve(strict=False)
            root = Path(app_path).resolve(strict=False)
            if candidate != root:
                return str(candidate.relative_to(root))
        except (OSError, ValueError):
            pass

        if path.is_absolute():
            return path.name or str(path)
        return str(path)

    @staticmethod
    def _same_file(left: str, right: str) -> bool:
        """Compare report paths while tolerating relative/absolute spellings."""
        try:
            return Path(left).resolve(strict=False) == Path(right).resolve(strict=False)
        except OSError:
            return left == right

    def _normalize_call_path(
        self, call_stack: list[CallStackFrame], app_path: str
    ) -> list[_CallPathLocation]:
        """Normalize a path while retaining source context and semantic roles."""
        frames: list[CallStackFrame] = []
        for index, frame in enumerate(call_stack):
            # The mapper adds an endpoint marker before mypy's stack, which can
            # itself begin with the same handler. Keep one contextual node.
            if (
                index == 1
                and frames
                and call_stack[0].function_name.startswith("[ENDPOINT]")
                and self._same_file(frame.file_path, frames[0].file_path)
                and frame.line_number == frames[0].line_number
            ):
                continue
            frames.append(frame)

        role_labels = {
            "endpoint": "Endpoint handler",
            "intermediate": "Static reachable frame",
            "changed": "Changed source location",
        }
        locations: list[_CallPathLocation] = []
        for index, frame in enumerate(frames):
            line_range = self._parse_line_range(frame.code_context)
            start_line = line_range[0] if line_range else frame.line_number
            end_line = line_range[1] if line_range else None
            role = (
                "endpoint"
                if index == 0
                else "changed"
                if index == len(frames) - 1
                else "intermediate"
            )
            locations.append(
                _CallPathLocation(
                    role=role,
                    role_label=role_labels[role],
                    function_name=frame.function_name or "unknown",
                    file_path=frame.file_path,
                    display_path=self._display_file_path(frame.file_path, app_path),
                    line_number=start_line,
                    end_line_number=end_line,
                    source_context=frame.code_context
                    or "Source context unavailable in report.",
                )
            )
        return locations

    def _build_call_path_graph(
        self,
        call_stacks: list[list[CallStackFrame]],
        app_path: str,
        view_id: str,
    ) -> tuple[list[_CallPathGraphNode], set[tuple[str, str]]]:
        """Condense all paths into shared nodes and many-to-many edges."""
        nodes_by_identity: dict[tuple[str, str, int, int, str], _CallPathGraphNode] = {}
        edges: set[tuple[str, str]] = set()
        paths: list[list[_CallPathLocation]] = [
            self._normalize_call_path(stack, app_path) for stack in call_stacks
        ]

        for path_index, locations in enumerate(paths, 1):
            previous: _CallPathGraphNode | None = None
            for depth, location in enumerate(locations):
                node = nodes_by_identity.get(location.identity)
                if node is None:
                    node = _CallPathGraphNode(
                        node_id=f"{view_id}-n{len(nodes_by_identity) + 1}",
                        location=location,
                        layer=depth,
                    )
                    nodes_by_identity[location.identity] = node
                node.path_indexes.add(path_index)
                node.layer = max(node.layer, depth)
                if previous is not None and previous.node_id != node.node_id:
                    edge = (previous.node_id, node.node_id)
                    if edge not in edges:
                        edges.add(edge)
                        previous.outgoing.add(node.node_id)
                        node.incoming.add(previous.node_id)
                previous = node

        # Shared nodes can occur at different depths on different paths. Push
        # targets rightward until ordinary forward edges have a stable layout.
        node_by_id = {node.node_id: node for node in nodes_by_identity.values()}
        for _ in range(max(1, len(node_by_id))):
            changed = False
            for source_id, target_id in sorted(edges):
                source = node_by_id[source_id]
                target = node_by_id[target_id]
                if target.layer <= source.layer and source.layer < len(node_by_id) - 1:
                    target.layer = source.layer + 1
                    changed = True
            if not changed:
                break

        layers: dict[int, list[_CallPathGraphNode]] = {}
        for node in node_by_id.values():
            layers.setdefault(node.layer, []).append(node)
        for layer, members in layers.items():
            for index, node in enumerate(sorted(members, key=lambda item: item.node_id)):
                node.x = 40 + layer * 270
                node.y = 72 + index * 120

        max_layer = max((node.layer for node in node_by_id.values()), default=0)
        max_nodes_in_layer = max((len(members) for members in layers.values()), default=1)
        # The SVG is horizontally scrollable for deep graphs but remains compact
        # when many paths collapse into a few shared nodes.
        self._last_graph_dimensions = (
            max(920, 80 + (max_layer + 1) * 270),
            max(250, 145 + max_nodes_in_layer * 120),
        )
        return sorted(node_by_id.values(), key=lambda node: (node.layer, node.y, node.node_id)), edges

    @staticmethod
    def _svg_text(value: str, limit: int = 35) -> str:
        """Shorten SVG labels while keeping full values in the details pane."""
        flattened = " ".join(value.split())
        if len(flattened) <= limit:
            return flattened
        return f"{flattened[: limit - 1]}…"

    @staticmethod
    def _path_membership(path_indexes: set[int], path_count: int) -> str:
        """Explain whether a node is common or belongs to a small branch."""
        ordered = sorted(path_indexes)
        if len(ordered) == path_count:
            return f"shared by all {path_count} paths"
        if len(ordered) == 1:
            return f"only path {ordered[0]}"
        if len(ordered) <= 8:
            return f"shared by {len(ordered)} paths ({', '.join(str(item) for item in ordered)})"
        sample = ", ".join(str(item) for item in ordered[:8])
        return f"shared by {len(ordered)} paths (for example {sample}, …)"

    def _format_call_path_fallback(self, affected: AffectedEndpoint, view_id: str) -> str:
        """Render evidence locations when no static call path was recorded."""
        endpoint = affected.endpoint
        evidence = affected.effect_evidence
        references: list[CodeReference] = []
        for item in evidence:
            reference = item.changed_location
            if reference not in references:
                references.append(reference)

        lines = [
            f'<section class="call-path-view call-path-fallback" id="{html.escape(view_id)}">',
            "<h4>Static call paths</h4>",
            '<p><strong>No static call path available.</strong> '
            "The evidence locations below are shown without fabricating intermediate frames.</p>",
        ]
        if references:
            lines.append('<ul class="call-path-fallback-list">')
            for reference in references:
                label = reference.symbol or "Changed/evidence location"
                location = self._format_code_ref(
                    reference.file_path,
                    reference.line_number,
                    f"{label} ({Path(reference.file_path).name}:{reference.line_number})",
                    reference.end_line_number,
                )
                lines.append(
                    f"<li><span class=\"call-path-role call-path-role-changed\">"
                    f"Evidence location</span> {location}</li>"
                )
            lines.append("</ul>")
        else:
            lines.append("<p>There are no embedded changed-source locations for this result.</p>")

        handler = endpoint.handler
        direct_references = [
            reference
            for reference in references
            if self._same_file(reference.file_path, str(handler.file_path))
            and handler.line_number
            <= reference.line_number
            <= (handler.end_line_number or handler.line_number)
        ]
        if direct_references:
            reference = direct_references[0]
            location = self._format_code_ref(
                reference.file_path,
                reference.line_number,
                f"changed evidence ({Path(reference.file_path).name}:{reference.line_number})",
                reference.end_line_number,
            )
            lines.append(
                '<div class="call-path-direct-edge" aria-label="Direct handler change evidence">'
                '<span class="call-path-role call-path-role-endpoint">Endpoint handler</span>'
                '<span class="call-path-direct-arrow" aria-hidden="true">→</span>'
                '<span class="call-path-role call-path-role-changed">Changed evidence</span> '
                f"{location}</div>"
            )
            lines.append(
                '<p class="call-path-direct-note"><strong>Direct handler change.</strong> '
                "No intermediate static path is inferred.</p>"
            )
        lines.append("</section>")
        return "\n".join(lines)

    def _format_call_path_view(
        self, affected: AffectedEndpoint, app_path: str, view_id: str
    ) -> str:
        """Render one condensed, interactive many-to-many call-path graph."""
        call_stacks = affected.call_stacks
        if not call_stacks:
            return self._format_call_path_fallback(affected, view_id)

        nodes, edges = self._build_call_path_graph(call_stacks, app_path, view_id)
        node_by_id = {node.node_id: node for node in nodes}
        width, height = getattr(self, "_last_graph_dimensions", (920, 250))
        marker_id = f"{view_id}-arrow"
        fork_count = sum(len(node.outgoing) > 1 for node in nodes)
        merge_count = sum(len(node.incoming) > 1 for node in nodes)
        path_count = len(call_stacks)
        lines = [
            f'<section class="call-path-view" id="{html.escape(view_id)}" '
            "data-call-path-view>",
            '<div class="call-path-toolbar">',
            '<div><h4>Condensed static call graph</h4>'
            '<p class="call-path-semantics">Arrows show static reachability: endpoint handler '
            "→ shared/intermediate logic → changed source location. This is not runtime execution.</p></div>",
            f'<label for="{html.escape(view_id)}-search">Search nodes '
            f'<input id="{html.escape(view_id)}-search" type="search" '
            'data-call-path-search placeholder="function, file, or source text"></label>',
            '<button type="button" data-call-path-reset>Reset</button>',
            "</div>",
            '<div class="call-path-summary">',
            f'<strong>{path_count} static paths</strong> condensed into '
            f'<strong>{len(nodes)} shared nodes</strong> and <strong>{len(edges)} connections</strong>.',
        ]
        if fork_count or merge_count:
            lines.append(
                f" <span class=\"call-path-branch-summary\">"
                f"{fork_count} fork(s), {merge_count} merge point(s)</span>"
            )
        lines.extend(
            [
                "</div>",
                '<div class="call-path-legend" aria-label="Call graph legend">'
                '<span class="call-path-role call-path-role-endpoint">Endpoint handler</span>'
                '<span class="call-path-role call-path-role-intermediate">Shared/intermediate logic</span>'
                '<span class="call-path-role call-path-role-changed">Changed source location</span>'
                "</div>",
                '<div class="call-path-canvas">',
                f'<svg class="call-path-svg" viewBox="0 0 {width} {height}" '
                'role="img" aria-label="Condensed many-to-many static call graph">'
                f'<defs><marker id="{html.escape(marker_id)}" markerWidth="8" markerHeight="8" '
                'refX="7" refY="3" orient="auto" markerUnits="strokeWidth">'
                '<path d="M0,0 L0,6 L7,3 z" class="call-path-arrow"></path></marker></defs>',
            ]
        )
        for source_id, target_id in sorted(edges):
            source = node_by_id[source_id]
            target = node_by_id[target_id]
            start_x = source.x + 225
            start_y = source.y + 38
            end_x = target.x
            end_y = target.y + 38
            middle_x = (start_x + end_x) // 2
            lines.append(
                f'<path class="call-path-edge" data-call-path-edge-source="{html.escape(source_id)}" '
                f'data-call-path-edge-target="{html.escape(target_id)}" '
                f'd="M {start_x} {start_y} C {middle_x} {start_y}, {middle_x} {end_y}, '
                f'{end_x} {end_y}" marker-end="url(#{html.escape(marker_id)})"></path>'
            )
        for node in nodes:
            location = node.location
            extra_classes = []
            if len(node.outgoing) > 1:
                extra_classes.append("call-path-node-fork")
            if len(node.incoming) > 1:
                extra_classes.append("call-path-node-merge")
            classes = " ".join(extra_classes)
            shared_text = self._path_membership(node.path_indexes, path_count)
            branch_text = ""
            if len(node.outgoing) > 1:
                branch_text = f" · {len(node.outgoing)} branches"
            elif len(node.incoming) > 1:
                branch_text = f" · {len(node.incoming)} incoming"
            node_id = html.escape(node.node_id)
            lines.append(
                f'<g class="call-path-node call-path-node-{location.role} {classes}" '
                f'data-call-path-node="{node_id}" role="button" tabindex="0" '
                f'aria-label="{html.escape(location.role_label + ": " + location.label)}">'
                f'<title>{html.escape(location.label + "; " + shared_text)}</title>'
                f'<rect x="{node.x}" y="{node.y}" width="225" height="76" rx="8"></rect>'
                f'<text class="call-path-node-role" x="{node.x + 12}" y="{node.y + 20}">'
                f'{html.escape(location.role_label)}</text>'
                f'<text class="call-path-node-label" x="{node.x + 12}" y="{node.y + 42}">'
                f'{html.escape(self._svg_text(location.function_name))}</text>'
                f'<text class="call-path-node-meta" x="{node.x + 12}" y="{node.y + 62}">'
                f'{html.escape(self._svg_text(location.display_path + ":" + str(location.line_number), 31))}'
                f'{html.escape(branch_text)}</text></g>'
            )
        lines.extend(["</svg>", "</div>"])
        lines.append('<ol class="call-path-text" aria-label="Shared graph nodes">')
        for node in nodes:
            location = node.location
            shared_text = self._path_membership(node.path_indexes, path_count)
            lines.append(
                f'<li><button type="button" class="call-path-text-node '
                f'call-path-node-{location.role}" data-call-path-node="{html.escape(node.node_id)}">'
                f'<span class="call-path-role">{html.escape(location.role_label)}</span> '
                f'<strong>{html.escape(location.function_name)}</strong> '
                f'<code>{html.escape(location.display_path)}:{location.line_number}</code> '
                f'<small>{html.escape(shared_text)} · '
                f'{len(node.incoming)} in / {len(node.outgoing)} out</small></button></li>'
            )
        lines.append("</ol>")
        lines.extend(
            [
                '<p class="call-path-no-match" data-call-path-no-match hidden>'
                "No nodes match the search.</p>",
                '<aside class="call-path-details" data-call-path-details aria-live="polite">',
                '<p data-call-path-default>Select a node to inspect its source and connections.</p>',
            ]
        )
        for node in nodes:
            location = node.location
            incoming = ", ".join(
                node_by_id[item].location.function_name for item in sorted(node.incoming)
            ) or "none"
            outgoing = ", ".join(
                node_by_id[item].location.function_name for item in sorted(node.outgoing)
            ) or "none"
            lines.append(
                f'<div data-call-path-detail="{html.escape(node.node_id)}" hidden>'
                f'<h4>{html.escape(location.role_label)}: '
                f'{html.escape(location.function_name)}</h4>'
                f'<p><code>{html.escape(location.display_path)}:{location.line_number}'
                f'{("-" + str(location.end_line_number)) if location.end_line_number else ""}'
                f"</code> · {html.escape(self._path_membership(node.path_indexes, path_count))}; "
                f"{len(node.incoming)} incoming / {len(node.outgoing)} outgoing</p>"
                f'<p><strong>Incoming:</strong> {html.escape(incoming)}<br>'
                f'<strong>Outgoing:</strong> {html.escape(outgoing)}</p>'
                f'<pre class="call-path-source">{html.escape(location.source_context)}</pre>'
                "</div>"
            )
        lines.extend(["</aside>", "</section>"])
        return "\n".join(lines)

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

        .legacy-call-stack summary {
            color: #52606d;
            cursor: pointer;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            font-weight: 600;
        }

        .legacy-call-stack[open] summary {
            margin-bottom: 10px;
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

        .call-path-view {
            margin-top: 16px;
            padding: 14px;
            border: 1px solid #d9e2ec;
            border-radius: 6px;
            background: #fbfdff;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }

        .call-path-toolbar {
            display: flex;
            align-items: flex-end;
            gap: 12px;
            flex-wrap: wrap;
        }

        .call-path-toolbar h4 {
            margin: 0;
            color: #2c3e50;
        }

        .call-path-semantics {
            margin: 2px 0 0;
            color: #52606d;
            font-size: 0.9em;
        }

        .call-path-toolbar label {
            display: flex;
            flex-direction: column;
            gap: 3px;
            color: #52606d;
            font-size: 0.85em;
        }

        .call-path-toolbar input {
            min-width: 240px;
            padding: 6px 8px;
            border: 1px solid #bcccdc;
            border-radius: 4px;
            font: inherit;
        }

        .call-path-toolbar button {
            padding: 6px 10px;
            border: 1px solid #829ab1;
            border-radius: 4px;
            background: white;
            color: #243b53;
            cursor: pointer;
        }

        .call-path-toolbar button:hover,
        .call-path-toolbar button:focus-visible {
            background: #e3f2fd;
        }

        .call-path-summary {
            margin-top: 10px;
            padding: 8px 10px;
            border-left: 4px solid #63b3ed;
            background: #ebf8ff;
            color: #243b53;
        }

        .call-path-branch-summary {
            margin-left: 8px;
            color: #7b341e;
            font-weight: 600;
        }

        .call-path-legend {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin: 12px 0 8px;
        }

        .call-path-role {
            display: inline-block;
            padding: 2px 7px;
            border-radius: 10px;
            font-size: 0.78em;
            font-weight: 600;
        }

        .call-path-role-endpoint,
        .call-path-node-endpoint rect {
            background: #dbeafe;
            fill: #dbeafe;
            color: #1e3a8a;
        }

        .call-path-role-intermediate,
        .call-path-node-intermediate rect {
            background: #fef3c7;
            fill: #fef3c7;
            color: #92400e;
        }

        .call-path-role-changed,
        .call-path-node-changed rect {
            background: #dcfce7;
            fill: #dcfce7;
            color: #166534;
        }

        .call-path-node:focus-visible,
        .call-path-text-node:focus-visible {
            outline: 3px solid #63b3ed;
            outline-offset: 2px;
        }

        .call-path-canvas {
            width: 100%;
            overflow-x: auto;
            background: #f8fafc;
        }

        .call-path-svg {
            display: block;
            width: 100%;
            min-width: 920px;
            min-height: 250px;
            padding: 4px 8px;
            background: #f8fafc;
        }

        .call-path-edge {
            fill: none;
            stroke: #829ab1;
            stroke-width: 2;
            transition: opacity 0.15s;
        }

        .call-path-edge-muted {
            opacity: 0.12;
        }

        .call-path-arrow {
            fill: #829ab1;
        }

        .call-path-node {
            cursor: pointer;
        }

        .call-path-node rect {
            stroke: #829ab1;
            stroke-width: 1.5;
        }

        .call-path-node-fork rect {
            stroke: #c05621;
            stroke-width: 2.5;
        }

        .call-path-node-merge rect {
            stroke: #805ad5;
            stroke-width: 2.5;
        }

        .call-path-node:hover rect,
        .call-path-node-selected rect {
            stroke: #1976d2;
            stroke-width: 3;
        }

        .call-path-node-role {
            font-size: 13px;
            font-weight: 600;
        }

        .call-path-node-label {
            fill: #243b53;
            font-family: "Courier New", monospace;
            font-size: 14px;
        }

        .call-path-node-meta {
            fill: #52606d;
            font-family: "Courier New", monospace;
            font-size: 11px;
        }

        .call-path-node-endpoint .call-path-node-role {
            fill: #1e3a8a;
        }

        .call-path-node-intermediate .call-path-node-role {
            fill: #92400e;
        }

        .call-path-node-changed .call-path-node-role {
            fill: #166534;
        }

        .call-path-text {
            margin: 0;
            padding: 8px 28px 12px 38px;
            background: #f8fafc;
        }

        .call-path-text-node {
            width: 100%;
            padding: 6px;
            border: 0;
            border-bottom: 1px solid #e4e7eb;
            background: transparent;
            color: #243b53;
            text-align: left;
            cursor: pointer;
            font: inherit;
        }

        .call-path-text-node:hover,
        .call-path-text-node.call-path-node-selected {
            background: #e3f2fd;
        }

        .call-path-text-node code {
            margin-left: 5px;
        }

        .call-path-text-node small {
            margin-left: 5px;
            color: #627d98;
        }

        .call-path-node-muted {
            opacity: 0.35;
        }

        .call-path-details {
            margin-top: 10px;
            padding: 10px;
            border-left: 4px solid #90cdf4;
            background: #f0f7ff;
        }

        .call-path-details h4 {
            margin: 0 0 4px;
            color: #2c3e50;
        }

        .call-path-details p {
            margin: 4px 0 8px;
        }

        .call-path-source {
            max-height: 260px;
            overflow: auto;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            font-family: "Courier New", Consolas, Monaco, monospace;
            font-size: 0.85em;
            line-height: 1.4;
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 8px;
            border-radius: 3px;
        }

        .call-path-no-match {
            margin: 10px 0 0;
            color: #7b341e;
        }

        .call-path-fallback {
            background: #fffaf0;
            border-color: #f6ad55;
        }

        .call-path-fallback-list {
            margin: 8px 0 0 22px;
        }

        .call-path-fallback-list li {
            margin: 5px 0;
        }

        .call-path-direct-edge {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
            margin-top: 10px;
            padding: 8px;
            border: 1px dashed #f6ad55;
            background: #fffaf0;
        }

        .call-path-direct-arrow {
            color: #c05621;
            font-size: 1.2em;
            font-weight: 700;
        }

        .call-path-direct-note {
            color: #7b341e;
        }

        @media (max-width: 700px) {
            .call-path-toolbar {
                align-items: stretch;
            }

            .call-path-toolbar input {
                min-width: 0;
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
{CONTENT}
    </div>
    <script>
    (function () {
        "use strict";

        document.querySelectorAll("[data-call-path-view]").forEach(function (view) {
            var search = view.querySelector("[data-call-path-search]");
            var reset = view.querySelector("[data-call-path-reset]");
            var nodes = Array.from(view.querySelectorAll("[data-call-path-node]"));
            var details = Array.from(view.querySelectorAll("[data-call-path-detail]"));
            var edges = Array.from(view.querySelectorAll("[data-call-path-edge-source]"));
            var defaultDetails = view.querySelector("[data-call-path-default]");
            var noMatch = view.querySelector("[data-call-path-no-match]");

            function nodeMatches(nodeId, query) {
                var matchingNodes = nodes.filter(function (node) {
                    return node.getAttribute("data-call-path-node") === nodeId;
                });
                var detail = details.find(function (item) {
                    return item.getAttribute("data-call-path-detail") === nodeId;
                });
                var nodeText = matchingNodes.map(function (node) {
                    return node.textContent || "";
                }).join(" ");
                var detailText = detail ? detail.textContent || "" : "";
                return (nodeText + " " + detailText).toLowerCase().indexOf(query) !== -1;
            }

            function selectNode(nodeId) {
                nodes.forEach(function (node) {
                    node.classList.toggle(
                        "call-path-node-selected",
                        node.getAttribute("data-call-path-node") === nodeId
                    );
                });
                details.forEach(function (detail) {
                    var selected = detail.getAttribute("data-call-path-detail") === nodeId;
                    detail.hidden = !selected;
                });
                if (defaultDetails) {
                    defaultDetails.hidden = Boolean(nodeId);
                }
            }

            function filterGraph() {
                var query = search ? search.value.trim().toLowerCase() : "";
                var matchingIds = new Set();
                var allIds = new Set(nodes.map(function (node) {
                    return node.getAttribute("data-call-path-node");
                }));
                allIds.forEach(function (nodeId) {
                    if (!query || nodeMatches(nodeId, query)) {
                        matchingIds.add(nodeId);
                    }
                });
                nodes.forEach(function (node) {
                    var nodeId = node.getAttribute("data-call-path-node");
                    node.classList.toggle("call-path-node-muted", !matchingIds.has(nodeId));
                });
                edges.forEach(function (edge) {
                    var source = edge.getAttribute("data-call-path-edge-source");
                    var target = edge.getAttribute("data-call-path-edge-target");
                    edge.classList.toggle(
                        "call-path-edge-muted",
                        !matchingIds.has(source) || !matchingIds.has(target)
                    );
                });
                if (noMatch) {
                    noMatch.hidden = matchingIds.size !== 0;
                }
            }

            nodes.forEach(function (node) {
                node.addEventListener("click", function () {
                    selectNode(node.getAttribute("data-call-path-node"));
                });
                node.addEventListener("keydown", function (event) {
                    if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        selectNode(node.getAttribute("data-call-path-node"));
                    }
                });
            });
            if (search) {
                search.addEventListener("input", filterGraph);
            }
            if (reset) {
                reset.addEventListener("click", function () {
                    if (search) {
                        search.value = "";
                    }
                    nodes.forEach(function (node) {
                        node.classList.remove("call-path-node-muted");
                    });
                    edges.forEach(function (edge) {
                        edge.classList.remove("call-path-edge-muted");
                    });
                    if (noMatch) {
                        noMatch.hidden = true;
                    }
                    selectNode(null);
                });
            }
        });
    }());
    </script>
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
            f'<span class="summary-label">Reachable Candidates:</span> '
            f"{report.candidate_count}"
            f"</div>"
        )
        content_lines.append(
            f'<div class="summary-item">'
            f'<span class="summary-label">Orphan Changes:</span> '
            f"{report.total_orphan_lines} lines in {report.orphan_count} files"
            f"</div>"
        )
        if report.analysis_duration_ms:
            content_lines.append(
                f'<div class="summary-item">'
                f'<span class="summary-label">Analysis Time:</span> {report.analysis_duration_ms:.2f}ms'
                f"</div>"
            )
        if report.effect_contract_audit is not None:
            audit = report.effect_contract_audit
            content_lines.append(
                '<div class="summary-item"><span class="summary-label">'
                "Effect Contract Audit:</span> "
                f"{audit.summary.matched_calls} matched calls / "
                f"{audit.summary.physical_occurrences} physical calls</div>"
            )
        if report.resource_coupling_graph is not None:
            graph = report.resource_coupling_graph
            policy = (
                "report-only; does not change candidates"
                if graph.mode == "report_only"
                else "exact-callsite LOW candidate mode"
            )
            content_lines.append(
                '<div class="summary-item"><span class="summary-label">'
                "Resource Coupling:</span> "
                f"{len(graph.edges)} edges / {len(graph.diagnostics)} diagnostics; "
                f"{policy}</div>"
            )
        if report.sql_transaction_report is not None:
            transaction = report.sql_transaction_report
            content_lines.append(
                '<div class="summary-item"><span class="summary-label">'
                "SQL Transactions:</span> "
                f"{transaction.summary.endpoints_with_staging} staged endpoints / "
                f"{transaction.summary.transaction_begins} transaction begins / "
                f"{transaction.summary.savepoint_begins} savepoints / "
                f"{transaction.summary.outcome_unresolved} unresolved outcomes; "
                "diagnostic only, persistence not established</div>"
            )
        if report.sql_transaction_path_report is not None:
            paths = report.sql_transaction_path_report
            content_lines.append(
                '<div class="summary-item"><span class="summary-label">'
                "SQL Ordered Paths:</span> "
                f"{paths.summary.ordered_paths} explicit boundaries / "
                f"{paths.summary.context_manager_paths} context exits / "
                f"{paths.summary.unresolved_pairs} unresolved pairs; "
                "lexical and conditional only, persistence not established</div>"
            )
        content_lines.append("</div>")

        # Affected endpoints
        call_path_index = 0
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
                    call_path_index += 1
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

                    if ep.surface is not None:
                        surface = ep.surface
                        content_lines.append(
                            '<div class="info-item"><span class="label">'
                            "Surface contract:</span> "
                            f"{html.escape(surface.contract_id)} "
                            f"({html.escape(surface.match_kind.value)}) at "
                            f"{html.escape(str(surface.registration_file))}:"
                            f"{surface.registration_line}; callback "
                            f"{html.escape(surface.callback_mode.value)}; execution "
                            f"{html.escape(surface.execution_mode.value)}; config "
                            f"<code>{html.escape(surface.config_hash)}</code></div>"
                        )

                    # Reason
                    content_lines.append(
                        f'<div class="info-item">'
                        f'<span class="label">Reason:</span> {html.escape(ae.reason)}'
                        f"</div>"
                    )

                    for evidence in ae.effect_evidence:
                        content_lines.append(
                            '<div class="info-item">'
                            '<span class="label">Effect:</span> '
                            f"[{html.escape(evidence.status.value)} / "
                            f"{html.escape(evidence.disposition.value)}] "
                            f"{html.escape(evidence.summary)}"
                            "</div>"
                        )
                    for contract_evidence in ae.contract_evidence:
                        content_lines.append(
                            '<div class="info-item"><span class="label">'
                            "Declared contract:</span> "
                            f"{html.escape(contract_evidence.contract.id)} "
                            "(change-to-call flow not established)</div>"
                        )
                    for coupling in ae.resource_coupling_evidence:
                        content_lines.append(
                            '<div class="info-item"><span class="label">'
                            "Potential cross-request coupling:</span> exact added producer "
                            f"callsite; {html.escape(coupling.strength.value)}; LOW-only</div>"
                        )

                    if ep.discovery_conditions:
                        content_lines.append(
                            '<div class="info-item"><span class="label">Discovery:</span> '
                            "<strong>CONDITIONAL</strong></div>"
                        )
                        for condition in ep.discovery_conditions:
                            content_lines.append(
                                '<div class="info-item">'
                                f"{html.escape(str(condition.source_path))}:"
                                f"{condition.source_line}: {html.escape(condition.reason)}</div>"
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

                    # Keep the verbose traceback as an optional diagnostic fallback.
                    # The condensed graph below is the primary way to inspect many paths.
                    if ae.call_stacks:
                        content_lines.append(
                            '<details class="call-stack legacy-call-stack">'
                            f"<summary>Show linear tracebacks ({len(ae.call_stacks)} paths)</summary>"
                        )
                        for stack_idx, call_stack in enumerate(ae.call_stacks, 1):
                            if len(ae.call_stacks) > 1:
                                content_lines.append(
                                    f"<div class='stack-path'><em>Linear path {stack_idx} of "
                                    f"{len(ae.call_stacks)}:</em></div>"
                                )

                            for frame in call_stack:
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
                                    frame.function_name,
                                )
                                frame_ref = self._format_code_ref(
                                    frame.file_path,
                                    start_line,
                                    frame_label,
                                    end_line,
                                )
                                content_lines.append(f"{frame_ref}<br>")
                            if stack_idx < len(ae.call_stacks):
                                content_lines.append("<br>")
                        content_lines.append("</details>")

                    content_lines.append(
                        self._format_call_path_view(
                            ae,
                            report.app_path,
                            f"affected-call-path-{call_path_index}",
                        )
                    )
                    content_lines.append("</div>")  # end endpoint-card
        else:
            content_lines.append('<div class="no-endpoints">')
            content_lines.append("No endpoints selected by the confidence threshold.")
            content_lines.append("</div>")

        additional = [
            candidate
            for candidate in report.candidate_endpoints
            if candidate not in report.affected_endpoints
        ]
        if additional:
            content_lines.append("<h2>Additional Reachable Candidates</h2>")
            content_lines.append(
                "<p><em>Retained for inspection; not selected by the legacy threshold.</em></p>"
            )
            for candidate in additional:
                call_path_index += 1
                endpoint = candidate.endpoint
                methods = ", ".join(method.value for method in endpoint.methods)
                content_lines.append('<div class="endpoint-card confidence-low">')
                content_lines.append(
                    f'<div class="endpoint-header"><strong>{html.escape(methods)}</strong> '
                    f'<span class="endpoint-path">{html.escape(endpoint.path)}</span></div>'
                )
                content_lines.append(
                    f'<div class="info-item"><span class="label">Confidence:</span> '
                    f"{html.escape(candidate.confidence.value)}</div>"
                )
                if endpoint.surface is not None:
                    surface = endpoint.surface
                    content_lines.append(
                        '<div class="info-item"><span class="label">'
                        "Surface contract:</span> "
                        f"{html.escape(surface.contract_id)} "
                        f"({html.escape(surface.match_kind.value)}) at "
                        f"{html.escape(str(surface.registration_file))}:"
                        f"{surface.registration_line}; callback "
                        f"{html.escape(surface.callback_mode.value)}; execution "
                        f"{html.escape(surface.execution_mode.value)}; config "
                        f"<code>{html.escape(surface.config_hash)}</code></div>"
                    )
                if endpoint.discovery_conditions:
                    content_lines.append(
                        '<div class="info-item"><span class="label">Discovery:</span> '
                        "<strong>CONDITIONAL</strong></div>"
                    )
                    for condition in endpoint.discovery_conditions:
                        content_lines.append(
                            '<div class="info-item">'
                            f"{html.escape(str(condition.source_path))}:"
                            f"{condition.source_line}: {html.escape(condition.reason)}</div>"
                        )
                for evidence in candidate.effect_evidence:
                    content_lines.append(
                        '<div class="info-item"><span class="label">Effect:</span> '
                        f"[{html.escape(evidence.status.value)} / "
                        f"{html.escape(evidence.disposition.value)}] "
                        f"{html.escape(evidence.summary)}</div>"
                    )
                for contract_evidence in candidate.contract_evidence:
                    content_lines.append(
                        '<div class="info-item"><span class="label">'
                        "Declared contract:</span> "
                        f"{html.escape(contract_evidence.contract.id)} "
                        "(change-to-call flow not established)</div>"
                    )
                for coupling in candidate.resource_coupling_evidence:
                    content_lines.append(
                        '<div class="info-item"><span class="label">'
                        "Potential cross-request coupling:</span> exact added producer "
                        f"callsite; {html.escape(coupling.strength.value)}; LOW-only</div>"
                    )
                content_lines.append(
                    self._format_call_path_view(
                        candidate,
                        report.app_path,
                        f"candidate-call-path-{call_path_index}",
                    )
                )
                content_lines.append("</div>")

        # Orphan changes
        if report.orphan_changes:
            content_lines.append('<div class="warning-box">')
            content_lines.append("<h3>⚠️ Orphan Code Changes</h3>")
            content_lines.append(
                f"<p><em>Changes not related to any endpoint "
                f"({report.total_orphan_lines} lines in {report.orphan_count} files)</em></p>"
            )

            for oc in report.orphan_changes:
                file_name = Path(oc.file_path).name
                content_lines.append(
                    '<div style="margin: 15px 0; padding: 10px; background: #fff; border-radius: 5px;">'
                )
                content_lines.append(
                    f'<div style="font-weight: bold; margin-bottom: 5px;">📄 {html.escape(file_name)}</div>'
                )
                content_lines.append(
                    f'<div style="font-size: 0.9em; color: #666;"><code>{html.escape(oc.file_path)}</code></div>'
                )
                content_lines.append(
                    f'<div style="margin-top: 8px; font-family: monospace; font-size: 0.9em;">{html.escape(oc.format_lines())}</div>'
                )
                content_lines.append(
                    f'<div style="margin-top: 5px; font-size: 0.85em; color: #777; font-style: italic;">{html.escape(oc.reason)}</div>'
                )
                content_lines.append("</div>")

            content_lines.append(
                '<div style="margin-top: 15px; padding: 10px; background: #f0f0f0; border-radius: 5px; font-size: 0.9em;">'
            )
            content_lines.append("<strong>💡 Tip:</strong> Orphan changes may indicate:")
            content_lines.append('<ul style="margin: 5px 0 0 20px;">')
            content_lines.append("<li>Unused or dead code</li>")
            content_lines.append(
                "<li>Code with incorrect types preventing dependency analysis</li>"
            )
            content_lines.append("<li>Utility code not called by any endpoint</li>")
            content_lines.append("<li>Code outside the analyzed application scope</li>")
            content_lines.append("</ul>")
            content_lines.append("</div>")
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

    def format_inventory(self, inventory: EndpointInventory) -> str:
        """Format endpoints with visible whole-inventory strength."""
        rendered = self.format_endpoints(inventory.endpoints)
        details = [
            '<div class="warning-box">',
            "<h3>Inventory strength</h3>",
            f"<p>{html.escape(inventory.status.value)}</p>",
        ]
        if inventory.limitations:
            details.append("<ul>")
            for item in inventory.limitations:
                details.append(
                    f"<li>{html.escape(str(item.source_path))}:{item.source_line}: "
                    f"{html.escape(item.reason)}</li>"
                )
            details.append("</ul>")
        details.append("</div>")
        return rendered.replace("</body>", "\n".join(details) + "\n</body>")

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
            content_lines.append("<th>Discovery</th>")
            content_lines.append("<th>Surface contract</th>")
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
                content_lines.append(f"<td>{html.escape(ep.discovery_status.value)}</td>")
                content_lines.append(
                    "<td>"
                    + (
                        f"{html.escape(ep.surface.contract_id)} "
                        f"({html.escape(ep.surface.match_kind.value)}; "
                        f"{html.escape(ep.surface.callback_mode.value)}/"
                        f"{html.escape(ep.surface.execution_mode.value)}) "
                        f"<code>{html.escape(ep.surface.config_hash)}</code>"
                        if ep.surface is not None
                        else ""
                    )
                    + "</td>"
                )

                content_lines.append("</tr>")

            content_lines.append("</tbody>")
            content_lines.append("</table>")

        content = "\n".join(content_lines)
        return self._get_html_template().replace("{CONTENT}", content)
