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
    def display_name(self) -> str:
        """Return a compact symbol without its module/import qualification."""
        value = " ".join(self.function_name.split()) or "unknown"
        if value.startswith("[ENDPOINT]"):
            endpoint_label = value.removeprefix("[ENDPOINT]").strip()
            return endpoint_label or "endpoint"
        value = value.rsplit(":", 1)[-1]
        parts = [part for part in value.split(".") if part and part != "<locals>"]
        if not parts:
            return "unknown"
        if len(parts) >= 2 and (parts[-2][:1].isupper() or parts[-1] == "__call__"):
            return ".".join(parts[-2:])
        return parts[-1]

    @property
    def label(self) -> str:
        """Return a compact node label for details and accessibility."""
        location = f"{self.display_path}:{self.line_number}"
        if self.end_line_number and self.end_line_number > self.line_number:
            location = f"{self.display_path}:{self.line_number}-{self.end_line_number}"
        return f"{self.display_name} ({location})"


@dataclass
class _CallPathGraphNode:
    """A shared node in the condensed many-to-many call-path graph."""

    node_id: str
    location: _CallPathLocation
    path_indexes: set[int] = field(default_factory=set)
    incoming: set[str] = field(default_factory=set)
    outgoing: set[str] = field(default_factory=set)
    layer: int = 0
    order: int = 0
    x: int = 0
    y: int = 0


_CALL_PATH_NODE_WIDTH = 220
_CALL_PATH_NODE_HEIGHT = 104
_CALL_PATH_LAYER_STEP = 280
_CALL_PATH_ROW_STEP = 132
_CALL_PATH_GRAPH_TOP = 72
_THEME_STORAGE_KEY = "fastapi-endpoint-detector.theme.v1"
_DEFAULT_HTML_THEME = "ember"
_HTML_THEMES = (
    ("harbor", "Harbor"),
    ("obsidian", "Obsidian"),
    ("terminal", "Terminal"),
    ("parchment", "Parchment"),
    ("blueprint", "Blueprint"),
    ("forest", "Forest"),
    ("ember", "Ember"),
    ("lavender", "Lavender"),
    ("monochrome", "Monochrome"),
    ("rose-quartz", "Rose Quartz"),
)


@register_formatter("html")
class HtmlFormatter(BaseFormatter):
    """
    Format output as interactive HTML with hover features.
    """

    def __init__(self) -> None:
        """Initialize the HTML formatter."""
        self._file_cache: dict[str, list[str]] = {}
        self._code_ref_index = 0

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
            return '<span class="code-context">File not found or could not be read</span>'

        # Convert to 0-indexed
        start_idx = start_line - 1
        end_idx = end_line - 1

        # Calculate display range with context
        display_start = max(0, start_idx - context)
        display_end = min(len(lines), end_idx + context + 1)

        html_lines = []
        html_lines.append('<span class="code-context">')
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
        html_lines.append("</span>")
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
        self,
        call_stack: list[CallStackFrame],
        app_path: str,
        endpoint_handler_name: str,
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
                # Prefer the real handler symbol over the synthetic route marker.
                frames[0] = frame
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
            function_name = frame.function_name or "unknown"
            if index == 0 and function_name.startswith("[ENDPOINT]"):
                function_name = endpoint_handler_name or function_name
            locations.append(
                _CallPathLocation(
                    role=role,
                    role_label=role_labels[role],
                    function_name=function_name,
                    file_path=frame.file_path,
                    display_path=self._display_file_path(frame.file_path, app_path),
                    line_number=start_line,
                    end_line_number=end_line,
                    source_context=frame.code_context or "Source context unavailable in report.",
                )
            )
        return locations

    def _build_call_path_graph(
        self,
        call_stacks: list[list[CallStackFrame]],
        app_path: str,
        view_id: str,
        endpoint_handler_name: str,
    ) -> tuple[list[_CallPathGraphNode], set[tuple[str, str]]]:
        """Condense all paths into shared nodes and many-to-many edges."""
        nodes_by_identity: dict[tuple[str, str, int, int, str], _CallPathGraphNode] = {}
        edges: set[tuple[str, str]] = set()
        paths: list[list[_CallPathLocation]] = [
            self._normalize_call_path(stack, app_path, endpoint_handler_name)
            for stack in call_stacks
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
                node.order = index
                node.x = 40 + layer * _CALL_PATH_LAYER_STEP
                node.y = _CALL_PATH_GRAPH_TOP + index * _CALL_PATH_ROW_STEP

        max_layer = max((node.layer for node in node_by_id.values()), default=0)
        max_nodes_in_layer = max((len(members) for members in layers.values()), default=1)
        # The SVG is horizontally scrollable for deep graphs but remains compact
        # when many paths collapse into a few shared nodes.
        self._last_graph_dimensions = (
            max(1050, 100 + (max_layer + 1) * _CALL_PATH_LAYER_STEP),
            max(300, 145 + max_nodes_in_layer * _CALL_PATH_ROW_STEP),
        )
        return sorted(
            node_by_id.values(), key=lambda node: (node.layer, node.y, node.node_id)
        ), edges

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

    def _render_call_tree_node(
        self,
        node_id: str,
        node_by_id: dict[str, _CallPathGraphNode],
        path_count: int,
        visited: set[str],
    ) -> str:
        """Render one collapsed PyInstrument-style node in the text tree."""
        node = node_by_id[node_id]
        location = node.location
        membership = self._path_membership(node.path_indexes, path_count)
        children = sorted(
            node.outgoing,
            key=lambda child_id: (
                node_by_id[child_id].layer,
                node_by_id[child_id].y,
                child_id,
            ),
        )
        node_markup = (
            f'<span class="call-path-role call-path-role-{location.role}">'
            f"{html.escape(location.role_label)}</span> "
            f"<strong>{html.escape(location.display_name)}</strong> "
            f"<code>{html.escape(Path(location.display_path).name)}:{location.line_number}</code> "
            f"<small>{html.escape(membership)} · {len(node.outgoing)} child(s)</small>"
        )
        escaped_id = html.escape(node_id)
        if node_id in visited:
            return (
                f'<li><button type="button" class="call-tree-shared-ref" '
                f'data-call-path-node="{escaped_id}">↗ {node_markup}</button></li>'
            )
        visited.add(node_id)
        if not children:
            return (
                f'<li><button type="button" class="call-tree-leaf call-path-node-'
                f'{location.role}" data-call-path-node="{escaped_id}">'
                f'<span class="call-tree-caret" aria-hidden="true"> </span>{node_markup}'
                "</button></li>"
            )
        children_markup = "".join(
            self._render_call_tree_node(child_id, node_by_id, path_count, visited)
            for child_id in children
        )
        return (
            '<li><details class="call-tree-node">'
            f'<summary class="call-tree-summary call-path-node-{location.role}" '
            f'data-call-path-node="{escaped_id}">'
            f'<span class="call-tree-caret" aria-hidden="true">&gt;</span>{node_markup}</summary>'
            f'<ol class="call-tree-children">{children_markup}</ol>'
            "</details></li>"
        )

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
            "<p><strong>No static call path available.</strong> "
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
                    f'<li><span class="call-path-role call-path-role-changed">'
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

        nodes, edges = self._build_call_path_graph(
            call_stacks,
            app_path,
            view_id,
            affected.endpoint.handler.name,
        )
        node_by_id = {node.node_id: node for node in nodes}
        width, height = getattr(self, "_last_graph_dimensions", (1050, 300))
        marker_id = f"{view_id}-arrow"
        graph_title_id = f"{view_id}-graph-title"
        graph_desc_id = f"{view_id}-graph-desc"
        fork_count = sum(len(node.outgoing) > 1 for node in nodes)
        merge_count = sum(len(node.incoming) > 1 for node in nodes)
        path_count = len(call_stacks)
        lines = [
            f'<section class="call-path-view" id="{html.escape(view_id)}" data-call-path-view>',
            '<div class="call-path-toolbar">',
            "<div><h4>Condensed static call graph</h4>"
            '<p class="call-path-semantics">Arrows show static reachability: endpoint handler '
            "→ shared/intermediate logic → changed source location. This is not runtime execution.</p></div>",
            f'<label for="{html.escape(view_id)}-search">Search nodes '
            f'<input id="{html.escape(view_id)}-search" type="search" '
            'data-call-path-search placeholder="function, file, or source text"></label>',
            f'<label for="{html.escape(view_id)}-layout">Graph type '
            f'<select id="{html.escape(view_id)}-layout" data-call-path-layout>'
            '<option value="flow-lr">Flow</option>'
            '<option value="flow-tb">Top-down</option>'
            '<option value="radial">Radial</option>'
            '<option value="files">File groups</option>'
            "</select></label>",
            '<button type="button" data-call-path-reset>Reset view</button>',
            '<div class="call-path-zoom-controls" aria-label="Graph navigation">'
            '<button type="button" data-call-path-zoom-out aria-label="Zoom out">-</button>'
            "<span data-call-path-zoom-label>100%</span>"
            '<button type="button" data-call-path-zoom-in aria-label="Zoom in">+</button>'
            '<button type="button" data-call-path-fit>Fit</button>'
            '<button type="button" data-call-path-touch-pan aria-pressed="false" '
            'title="Enable two-axis touch panning">Touch pan</button></div>',
            "</div>",
            '<div class="call-path-summary">',
            f"<strong>{path_count} static paths</strong> condensed into "
            f"<strong>{len(nodes)} shared nodes</strong> and <strong>{len(edges)} connections</strong>.",
        ]
        if fork_count or merge_count:
            lines.append(
                f' <span class="call-path-branch-summary">'
                f"{fork_count} fork(s), {merge_count} merge point(s)</span>"
            )
        lines.extend(
            [
                "</div>",
                '<div class="call-path-legend" aria-label="Call graph legend">'
                '<span class="call-path-role call-path-role-endpoint">Endpoint handler</span>'
                '<span class="call-path-role call-path-role-intermediate">Shared/intermediate logic</span>'
                '<span class="call-path-role call-path-role-changed">Changed source location</span>'
                '<span class="call-path-topology-key call-path-topology-key-fork">Fork</span>'
                '<span class="call-path-topology-key call-path-topology-key-merge">Merge</span>'
                "</div>",
                '<output class="call-path-layout-status" data-call-path-layout-status '
                'aria-live="polite">Flow layout · layers read left to right</output>',
                '<p class="call-path-gesture-hint">Drag to pan · Ctrl/⌘ + wheel to zoom · '
                "arrow keys pan when the canvas is focused</p>",
                '<div class="call-path-canvas" data-call-path-viewport>',
                f'<svg class="call-path-svg" width="{width}" height="{height}" '
                f'viewBox="0 0 {width} {height}" '
                f'data-graph-width="{width}" data-graph-height="{height}" '
                f'data-call-path-svg role="group" tabindex="0" '
                f'aria-labelledby="{html.escape(graph_title_id)} {html.escape(graph_desc_id)}">'
                f'<title id="{html.escape(graph_title_id)}">Condensed static call graph</title>'
                f'<desc id="{html.escape(graph_desc_id)}">Selectable layouts preserve the same '
                "static reachability nodes and directed connections.</desc>"
                f'<defs><marker id="{html.escape(marker_id)}" markerWidth="8" markerHeight="8" '
                'refX="7" refY="3" orient="auto" markerUnits="strokeWidth">'
                '<path d="M0,0 L0,6 L7,3 z" class="call-path-arrow"></path></marker></defs>'
                "<g data-call-path-stage><g data-call-path-clusters></g>",
            ]
        )
        for source_id, target_id in sorted(edges):
            source = node_by_id[source_id]
            target = node_by_id[target_id]
            start_x = source.x + _CALL_PATH_NODE_WIDTH
            start_y = source.y + _CALL_PATH_NODE_HEIGHT // 2
            end_x = target.x
            end_y = target.y + _CALL_PATH_NODE_HEIGHT // 2
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
            topology_parts = []
            if len(node.outgoing) > 1:
                topology_parts.append(f"{len(node.outgoing)} branches")
            if len(node.incoming) > 1:
                topology_parts.append(f"{len(node.incoming)} incoming")
            topology_text = " · ".join(topology_parts)
            membership_text = shared_text
            if topology_text:
                membership_text = f"{shared_text} · {topology_text}"
            node_id = html.escape(node.node_id)
            file_label = Path(location.display_path).name
            search_text = f"{location.function_name} {location.display_path}"
            aria_label = (
                f"{location.role_label}: {location.display_name}; qualified symbol "
                f"{location.function_name}; {location.display_path}:{location.line_number}; "
                f"{membership_text}"
            )
            topology_markers = ""
            if len(node.outgoing) > 1:
                topology_markers += (
                    f'<circle class="call-path-topology-fork" '
                    f'cx="{_CALL_PATH_NODE_WIDTH - 14}" cy="14" r="5"></circle>'
                )
            if len(node.incoming) > 1:
                merge_x = _CALL_PATH_NODE_WIDTH - 35
                topology_markers += (
                    f'<rect class="call-path-topology-merge" x="{merge_x}" y="9" '
                    f'width="10" height="10" transform="rotate(45 '
                    f'{merge_x + 5} 14)"></rect>'
                )
            lines.append(
                f'<g class="call-path-node call-path-node-{location.role} {classes}" '
                f'data-call-path-node="{node_id}" data-call-path-layer="{node.layer}" '
                f'data-call-path-order="{node.order}" '
                f'data-call-path-file="{html.escape(location.file_path)}" '
                f'data-call-path-file-label="{html.escape(location.display_path)}" '
                f'data-call-path-search-text="{html.escape(search_text)}" '
                f'transform="translate({node.x} {node.y})" role="button" tabindex="0" '
                f'aria-pressed="false" aria-label="{html.escape(aria_label)}">'
                f"<title>{html.escape(location.label + '; ' + membership_text)}</title>"
                f'<rect x="0" y="0" width="{_CALL_PATH_NODE_WIDTH}" '
                f'height="{_CALL_PATH_NODE_HEIGHT}" rx="8"></rect>'
                f"{topology_markers}"
                '<text class="call-path-node-role" x="12" y="20">'
                f"{html.escape(location.role_label)}</text>"
                '<text class="call-path-node-label" x="12" y="45">'
                f"{html.escape(self._svg_text(location.display_name, 22))}</text>"
                '<text class="call-path-node-meta" x="12" y="67">'
                f"{html.escape(self._svg_text(file_label + ':' + str(location.line_number), 28))}"
                "</text>"
                '<text class="call-path-node-meta" x="12" y="88">'
                f"{html.escape(self._svg_text(membership_text, 31))}</text></g>"
            )
        lines.append("</g>")
        lines.append("</svg>")
        lines.append("</div>")
        roots = (
            sorted(
                (node for node in nodes if not node.incoming),
                key=lambda node: (node.layer, node.y, node.node_id),
            )
            or nodes[:1]
        )
        lines.extend(
            [
                '<details class="call-tree-panel">',
                '<summary class="call-tree-panel-summary">'
                '<span class="call-tree-caret" aria-hidden="true">&gt;</span>'
                f"Condensed call stack ({len(nodes)} shared nodes)</summary>",
                '<div class="call-tree-toolbar">'
                '<button type="button" data-call-tree-expand>Expand all</button>'
                '<button type="button" data-call-tree-collapse>Collapse all</button>'
                "</div>",
                '<ol class="call-tree-root" aria-label="Condensed shared call stack">',
            ]
        )
        visited: set[str] = set()
        for root in roots:
            lines.append(self._render_call_tree_node(root.node_id, node_by_id, path_count, visited))
        lines.extend(["</ol>", "</details>"])
        lines.extend(
            [
                '<p class="call-path-no-match" data-call-path-no-match hidden>'
                "No nodes match the search.</p>",
                '<aside class="call-path-details" data-call-path-details aria-live="polite">',
                "<p data-call-path-default>Select a node to inspect its source and connections.</p>",
            ]
        )
        for node in nodes:
            location = node.location
            incoming = (
                ", ".join(
                    f"{node_by_id[item].location.display_name} "
                    f"({node_by_id[item].location.display_path}:"
                    f"{node_by_id[item].location.line_number})"
                    for item in sorted(node.incoming)
                )
                or "none"
            )
            outgoing = (
                ", ".join(
                    f"{node_by_id[item].location.display_name} "
                    f"({node_by_id[item].location.display_path}:"
                    f"{node_by_id[item].location.line_number})"
                    for item in sorted(node.outgoing)
                )
                or "none"
            )
            lines.append(
                f'<div data-call-path-detail="{html.escape(node.node_id)}" hidden>'
                f"<h4>{html.escape(location.role_label)}: "
                f"{html.escape(location.display_name)}</h4>"
                f'<span class="sr-only">Qualified symbol: '
                f"{html.escape(location.function_name)}.</span>"
                f"<p><code>{html.escape(location.display_path)}:{location.line_number}"
                f"{('-' + str(location.end_line_number)) if location.end_line_number else ''}"
                f"</code> · {html.escape(self._path_membership(node.path_indexes, path_count))}; "
                f"{len(node.incoming)} incoming / {len(node.outgoing)} outgoing</p>"
                f"<p><strong>Incoming:</strong> {html.escape(incoming)}<br>"
                f"<strong>Outgoing:</strong> {html.escape(outgoing)}</p>"
                f'<pre class="call-path-source">{html.escape(location.source_context)}</pre>'
                "</div>"
            )
        lines.extend(["</aside>", "</section>"])
        return "\n".join(lines)

    @staticmethod
    def _theme_options() -> str:
        """Render the allow-listed visual themes for the standalone report."""
        return "".join(
            f'<option value="{theme_id}"'
            f"{' selected' if theme_id == _DEFAULT_HTML_THEME else ''}>"
            f"{html.escape(label)}</option>"
            for theme_id, label in _HTML_THEMES
        )

    def _get_html_template(self) -> str:
        """Get the standalone HTML shell, theme system, and interactions."""
        template = """<!DOCTYPE html>
<html lang="en" data-theme="{DEFAULT_THEME}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="report-theme-ids" content="{THEME_IDS}">
    <title>FastAPI Endpoint Change Detector - Analysis Report</title>
    <script>
    (function () {
        "use strict";
        document.documentElement.classList.add("js");
        try {
            var themeMeta = document.querySelector('meta[name="report-theme-ids"]');
            var allowed = themeMeta ? themeMeta.content.split(",") : [];
            var stored = window.localStorage.getItem("{THEME_STORAGE_KEY}");
            if (stored && allowed.indexOf(stored) !== -1) {
                document.documentElement.setAttribute("data-theme", stored);
            }
        } catch (error) {
            // The deterministic Harbor default remains active when file: storage is denied.
        }
    }());
    </script>
    <style>
        :root,
        html[data-theme="harbor"] {
            color-scheme: light;
            --font-ui: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            --font-heading: var(--font-ui);
            --font-code: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
            --canvas: #eef4f8;
            --canvas-image: radial-gradient(circle at 12% 0%, rgba(14, 116, 144, 0.12), transparent 31rem);
            --surface: #ffffff;
            --surface-raised: #ffffff;
            --surface-subtle: #f4f8fb;
            --surface-strong: #e7f0f5;
            --text: #172a3a;
            --muted: #526879;
            --heading: #102a3a;
            --border: #cbd9e2;
            --border-strong: #6b8799;
            --accent: #075985;
            --accent-hover: #0c4a6e;
            --accent-ink: #ffffff;
            --accent-soft: #e0f2fe;
            --focus: #0369a1;
            --danger: #991b1b;
            --danger-soft: #fef2f2;
            --warning: #854d0e;
            --warning-soft: #fefce8;
            --success: #166534;
            --success-soft: #f0fdf4;
            --info: #075985;
            --info-soft: #e0f2fe;
            --code-bg: #0f1f2b;
            --code-fg: #e6f2f8;
            --code-muted: #9ab2c1;
            --code-highlight: #164e63;
            --tooltip-bg: #102a3a;
            --tooltip-fg: #f8fbfd;
            --graph-bg: #f6fafc;
            --graph-edge: #6b8799;
            --graph-node-text: #172a3a;
            --graph-endpoint-bg: #dbeafe;
            --graph-endpoint-fg: #1e3a8a;
            --graph-intermediate-bg: #fef3c7;
            --graph-intermediate-fg: #78350f;
            --graph-changed-bg: #dcfce7;
            --graph-changed-fg: #14532d;
            --graph-fork: #c2410c;
            --graph-merge: #6d28d9;
            --graph-selected: #0369a1;
            --radius-sm: 8px;
            --radius-md: 14px;
            --radius-lg: 22px;
            --shadow-sm: 0 1px 2px rgba(16, 42, 58, 0.08);
            --shadow-lg: 0 22px 60px rgba(16, 42, 58, 0.13);
            --page-width: 1480px;
            --card-border-width: 1px;
            --section-rule: linear-gradient(90deg, var(--accent), transparent);
        }

        html[data-theme="obsidian"] {
            color-scheme: dark;
            --canvas: #0a0f17;
            --canvas-image: radial-gradient(circle at 18% -8%, rgba(34, 211, 238, 0.16), transparent 34rem);
            --surface: #111923;
            --surface-raised: #151f2c;
            --surface-subtle: #0d151f;
            --surface-strong: #1c2a39;
            --text: #edf5ff;
            --muted: #a9bdcf;
            --heading: #f7fbff;
            --border: #32475a;
            --border-strong: #54738b;
            --accent: #67e8f9;
            --accent-hover: #a5f3fc;
            --accent-ink: #083344;
            --accent-soft: #123847;
            --focus: #67e8f9;
            --danger: #fecaca;
            --danger-soft: #411b23;
            --warning: #fde68a;
            --warning-soft: #3b3013;
            --success: #bbf7d0;
            --success-soft: #143425;
            --info: #bae6fd;
            --info-soft: #123446;
            --code-bg: #060a10;
            --code-fg: #dbeafe;
            --code-muted: #8ba1b6;
            --code-highlight: #164e63;
            --tooltip-bg: #020617;
            --tooltip-fg: #f8fafc;
            --graph-bg: #0b121b;
            --graph-edge: #708ba0;
            --graph-node-text: #f1f7fb;
            --graph-endpoint-bg: #153a63;
            --graph-endpoint-fg: #bfdbfe;
            --graph-intermediate-bg: #4a3511;
            --graph-intermediate-fg: #fde68a;
            --graph-changed-bg: #123d2a;
            --graph-changed-fg: #bbf7d0;
            --graph-fork: #fb923c;
            --graph-merge: #c4b5fd;
            --graph-selected: #67e8f9;
            --radius-sm: 7px;
            --radius-md: 13px;
            --radius-lg: 20px;
            --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.45);
            --shadow-lg: 0 25px 70px rgba(0, 0, 0, 0.48);
        }

        html[data-theme="terminal"] {
            color-scheme: dark;
            --font-ui: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
            --font-heading: var(--font-ui);
            --canvas: #050806;
            --canvas-image: repeating-linear-gradient(0deg, rgba(74, 222, 128, 0.025) 0 1px, transparent 1px 4px);
            --surface: #0a100c;
            --surface-raised: #0c140f;
            --surface-subtle: #071009;
            --surface-strong: #102019;
            --text: #d8ffe3;
            --muted: #92c9a0;
            --heading: #a7f3d0;
            --border: #285b38;
            --border-strong: #4ade80;
            --accent: #4ade80;
            --accent-hover: #86efac;
            --accent-ink: #052e16;
            --accent-soft: #12301d;
            --focus: #facc15;
            --danger: #fca5a5;
            --danger-soft: #351313;
            --warning: #fde047;
            --warning-soft: #312b0c;
            --success: #86efac;
            --success-soft: #102d19;
            --info: #a7f3d0;
            --info-soft: #102d20;
            --code-bg: #020403;
            --code-fg: #b7ffc9;
            --code-muted: #65a373;
            --code-highlight: #14532d;
            --tooltip-bg: #020403;
            --tooltip-fg: #d8ffe3;
            --graph-bg: #050a06;
            --graph-edge: #4f9664;
            --graph-node-text: #d8ffe3;
            --graph-endpoint-bg: #0b3420;
            --graph-endpoint-fg: #a7f3d0;
            --graph-intermediate-bg: #30300d;
            --graph-intermediate-fg: #fef08a;
            --graph-changed-bg: #10351b;
            --graph-changed-fg: #bbf7d0;
            --graph-fork: #fb923c;
            --graph-merge: #d8b4fe;
            --graph-selected: #facc15;
            --radius-sm: 0;
            --radius-md: 0;
            --radius-lg: 0;
            --shadow-sm: none;
            --shadow-lg: 0 0 0 1px #285b38;
            --card-border-width: 1px;
        }

        html[data-theme="parchment"] {
            color-scheme: light;
            --font-ui: Georgia, "Times New Roman", serif;
            --font-heading: Georgia, "Times New Roman", serif;
            --canvas: #efe6d2;
            --canvas-image: repeating-linear-gradient(0deg, rgba(92, 67, 42, 0.025) 0 1px, transparent 1px 5px);
            --surface: #fffaf0;
            --surface-raised: #fffdf7;
            --surface-subtle: #f7efdf;
            --surface-strong: #eadcc2;
            --text: #33291f;
            --muted: #6e5c49;
            --heading: #40291e;
            --border: #cdbb9d;
            --border-strong: #9e8060;
            --accent: #8f3f20;
            --accent-hover: #713018;
            --accent-ink: #ffffff;
            --accent-soft: #f6dfcc;
            --focus: #713018;
            --danger: #8b1e1e;
            --danger-soft: #fbe8df;
            --warning: #754c0d;
            --warning-soft: #f8edcf;
            --success: #365c2a;
            --success-soft: #eaf0dc;
            --info: #5a456f;
            --info-soft: #eee5f2;
            --code-bg: #2c241d;
            --code-fg: #f8ecd8;
            --code-muted: #c8b79d;
            --code-highlight: #68472e;
            --tooltip-bg: #33291f;
            --tooltip-fg: #fffaf0;
            --graph-bg: #fbf3e3;
            --graph-edge: #8c7259;
            --graph-node-text: #33291f;
            --graph-endpoint-bg: #dce5ec;
            --graph-endpoint-fg: #263f56;
            --graph-intermediate-bg: #f2dfb5;
            --graph-intermediate-fg: #65410b;
            --graph-changed-bg: #dce8cc;
            --graph-changed-fg: #365c2a;
            --graph-fork: #9a3412;
            --graph-merge: #6b3e82;
            --graph-selected: #8f3f20;
            --radius-sm: 2px;
            --radius-md: 4px;
            --radius-lg: 6px;
            --shadow-sm: 0 1px 2px rgba(64, 41, 30, 0.08);
            --shadow-lg: 0 18px 45px rgba(64, 41, 30, 0.14);
        }

        html[data-theme="blueprint"] {
            color-scheme: dark;
            --font-ui: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            --font-heading: var(--font-code);
            --canvas: #062c68;
            --canvas-image: linear-gradient(rgba(125, 211, 252, 0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(125, 211, 252, 0.08) 1px, transparent 1px);
            --surface: #0b3b82;
            --surface-raised: #0e4698;
            --surface-subtle: #082f6d;
            --surface-strong: #1151a6;
            --text: #f4f9ff;
            --muted: #c4dcf5;
            --heading: #ffffff;
            --border: #5ca7df;
            --border-strong: #bae6fd;
            --accent: #7dd3fc;
            --accent-hover: #bae6fd;
            --accent-ink: #082f49;
            --accent-soft: #12569c;
            --focus: #fef08a;
            --danger: #fecaca;
            --danger-soft: #702b43;
            --warning: #fef08a;
            --warning-soft: #5a5113;
            --success: #bbf7d0;
            --success-soft: #18583e;
            --info: #e0f2fe;
            --info-soft: #1559a3;
            --code-bg: #031c43;
            --code-fg: #e0f2fe;
            --code-muted: #9ec9e9;
            --code-highlight: #0e5a9f;
            --tooltip-bg: #031c43;
            --tooltip-fg: #f4f9ff;
            --graph-bg: #072c62;
            --graph-edge: #9cd9f7;
            --graph-node-text: #f4f9ff;
            --graph-endpoint-bg: #164f91;
            --graph-endpoint-fg: #dbeafe;
            --graph-intermediate-bg: #66550d;
            --graph-intermediate-fg: #fef9c3;
            --graph-changed-bg: #176044;
            --graph-changed-fg: #dcfce7;
            --graph-fork: #fdba74;
            --graph-merge: #e9d5ff;
            --graph-selected: #fef08a;
            --radius-sm: 0;
            --radius-md: 0;
            --radius-lg: 0;
            --shadow-sm: none;
            --shadow-lg: 0 0 0 2px #5ca7df;
        }

        html[data-theme="forest"] {
            color-scheme: light;
            --canvas: #edf2e7;
            --canvas-image: radial-gradient(circle at 85% 0%, rgba(39, 103, 73, 0.12), transparent 31rem);
            --surface: #fbfdf7;
            --surface-raised: #ffffff;
            --surface-subtle: #f0f5e9;
            --surface-strong: #dfe9d7;
            --text: #1d2b20;
            --muted: #536558;
            --heading: #173c27;
            --border: #c0d0b8;
            --border-strong: #789277;
            --accent: #276749;
            --accent-hover: #1f513a;
            --accent-ink: #ffffff;
            --accent-soft: #dff1e5;
            --focus: #276749;
            --danger: #9b2c2c;
            --danger-soft: #fff0ed;
            --warning: #744c0c;
            --warning-soft: #fff8dd;
            --success: #276749;
            --success-soft: #e8f5e9;
            --info: #285e61;
            --info-soft: #e2f1ef;
            --code-bg: #17241a;
            --code-fg: #e8f5df;
            --code-muted: #9eb29f;
            --code-highlight: #315f3c;
            --tooltip-bg: #173c27;
            --tooltip-fg: #f7fff7;
            --graph-bg: #f4f8ef;
            --graph-edge: #708a72;
            --graph-node-text: #1d2b20;
            --graph-endpoint-bg: #dcebea;
            --graph-endpoint-fg: #184e51;
            --graph-intermediate-bg: #f0e5ba;
            --graph-intermediate-fg: #654b0b;
            --graph-changed-bg: #d9edda;
            --graph-changed-fg: #22543d;
            --graph-fork: #9c4221;
            --graph-merge: #553c9a;
            --graph-selected: #276749;
            --radius-sm: 10px;
            --radius-md: 16px;
            --radius-lg: 28px;
            --shadow-sm: 0 1px 3px rgba(23, 60, 39, 0.08);
            --shadow-lg: 0 24px 70px rgba(23, 60, 39, 0.12);
        }

        html[data-theme="ember"] {
            color-scheme: dark;
            --canvas: #130d0a;
            --canvas-image: radial-gradient(circle at 50% -12%, rgba(251, 146, 60, 0.2), transparent 30rem);
            --surface: #211713;
            --surface-raised: #291d18;
            --surface-subtle: #1a120f;
            --surface-strong: #38251e;
            --text: #fff3e8;
            --muted: #d8b8a5;
            --heading: #fff7ed;
            --border: #6a4938;
            --border-strong: #a76b48;
            --accent: #fb923c;
            --accent-hover: #fdba74;
            --accent-ink: #431407;
            --accent-soft: #4a2515;
            --focus: #fdba74;
            --danger: #fecaca;
            --danger-soft: #481d1d;
            --warning: #fde68a;
            --warning-soft: #45300e;
            --success: #bbf7d0;
            --success-soft: #183623;
            --info: #fed7aa;
            --info-soft: #462616;
            --code-bg: #090605;
            --code-fg: #ffedd5;
            --code-muted: #be9b87;
            --code-highlight: #7c2d12;
            --tooltip-bg: #090605;
            --tooltip-fg: #fff7ed;
            --graph-bg: #170e0b;
            --graph-edge: #a7775b;
            --graph-node-text: #fff3e8;
            --graph-endpoint-bg: #253a50;
            --graph-endpoint-fg: #dbeafe;
            --graph-intermediate-bg: #533814;
            --graph-intermediate-fg: #fef3c7;
            --graph-changed-bg: #1c432d;
            --graph-changed-fg: #dcfce7;
            --graph-fork: #fb923c;
            --graph-merge: #d8b4fe;
            --graph-selected: #fdba74;
            --radius-sm: 5px;
            --radius-md: 8px;
            --radius-lg: 12px;
            --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.4);
            --shadow-lg: 0 26px 70px rgba(0, 0, 0, 0.5);
            --section-rule: linear-gradient(90deg, #fb923c, #7c2d12, transparent);
        }

        html[data-theme="lavender"] {
            color-scheme: light;
            --canvas: #f2eefb;
            --canvas-image: radial-gradient(circle at 84% 4%, rgba(109, 40, 217, 0.13), transparent 32rem);
            --surface: #ffffff;
            --surface-raised: #ffffff;
            --surface-subtle: #f8f5ff;
            --surface-strong: #ebe4fa;
            --text: #302747;
            --muted: #665c7d;
            --heading: #3b2368;
            --border: #d7cbea;
            --border-strong: #80699f;
            --accent: #6d28d9;
            --accent-hover: #5b21b6;
            --accent-ink: #ffffff;
            --accent-soft: #ede9fe;
            --focus: #6d28d9;
            --danger: #9f1239;
            --danger-soft: #fff1f2;
            --warning: #854d0e;
            --warning-soft: #fefce8;
            --success: #166534;
            --success-soft: #f0fdf4;
            --info: #5b21b6;
            --info-soft: #f3e8ff;
            --code-bg: #241b36;
            --code-fg: #f5f3ff;
            --code-muted: #b8aed0;
            --code-highlight: #4c1d95;
            --tooltip-bg: #302747;
            --tooltip-fg: #faf8ff;
            --graph-bg: #faf8ff;
            --graph-edge: #8b7aa8;
            --graph-node-text: #302747;
            --graph-endpoint-bg: #e0e7ff;
            --graph-endpoint-fg: #3730a3;
            --graph-intermediate-bg: #fef3c7;
            --graph-intermediate-fg: #78350f;
            --graph-changed-bg: #dcfce7;
            --graph-changed-fg: #14532d;
            --graph-fork: #c2410c;
            --graph-merge: #6d28d9;
            --graph-selected: #6d28d9;
            --radius-sm: 12px;
            --radius-md: 20px;
            --radius-lg: 32px;
            --shadow-sm: 0 2px 5px rgba(59, 35, 104, 0.08);
            --shadow-lg: 0 28px 75px rgba(59, 35, 104, 0.14);
        }

        html[data-theme="monochrome"] {
            color-scheme: light;
            --font-ui: Arial, Helvetica, sans-serif;
            --font-heading: Arial, Helvetica, sans-serif;
            --canvas: #eeeeee;
            --canvas-image: none;
            --surface: #ffffff;
            --surface-raised: #ffffff;
            --surface-subtle: #f5f5f5;
            --surface-strong: #e4e4e4;
            --text: #111111;
            --muted: #4b4b4b;
            --heading: #000000;
            --border: #9b9b9b;
            --border-strong: #111111;
            --accent: #111111;
            --accent-hover: #333333;
            --accent-ink: #ffffff;
            --accent-soft: #e5e5e5;
            --focus: #000000;
            --danger: #111111;
            --danger-soft: #f4f4f4;
            --warning: #111111;
            --warning-soft: #eeeeee;
            --success: #111111;
            --success-soft: #f7f7f7;
            --info: #111111;
            --info-soft: #eeeeee;
            --code-bg: #111111;
            --code-fg: #ffffff;
            --code-muted: #cccccc;
            --code-highlight: #444444;
            --tooltip-bg: #000000;
            --tooltip-fg: #ffffff;
            --graph-bg: #fafafa;
            --graph-edge: #444444;
            --graph-node-text: #111111;
            --graph-endpoint-bg: #ffffff;
            --graph-endpoint-fg: #111111;
            --graph-intermediate-bg: #e4e4e4;
            --graph-intermediate-fg: #111111;
            --graph-changed-bg: #cccccc;
            --graph-changed-fg: #111111;
            --graph-fork: #111111;
            --graph-merge: #555555;
            --graph-selected: #000000;
            --radius-sm: 0;
            --radius-md: 0;
            --radius-lg: 0;
            --shadow-sm: none;
            --shadow-lg: none;
            --card-border-width: 2px;
            --section-rule: linear-gradient(90deg, #111111, #111111);
        }

        html[data-theme="rose-quartz"] {
            color-scheme: light;
            --canvas: #f9edf1;
            --canvas-image: radial-gradient(circle at 15% -5%, rgba(159, 18, 57, 0.11), transparent 32rem);
            --surface: #fffafa;
            --surface-raised: #ffffff;
            --surface-subtle: #fff3f6;
            --surface-strong: #f5dce4;
            --text: #3b2029;
            --muted: #755461;
            --heading: #5f1831;
            --border: #e1bec9;
            --border-strong: #b77b8e;
            --accent: #9f1239;
            --accent-hover: #881337;
            --accent-ink: #ffffff;
            --accent-soft: #ffe4e6;
            --focus: #9f1239;
            --danger: #9f1239;
            --danger-soft: #fff1f2;
            --warning: #854d0e;
            --warning-soft: #fefce8;
            --success: #166534;
            --success-soft: #f0fdf4;
            --info: #7e2254;
            --info-soft: #fce7f3;
            --code-bg: #341822;
            --code-fg: #fff1f2;
            --code-muted: #d4aeb9;
            --code-highlight: #7f1d3b;
            --tooltip-bg: #3b2029;
            --tooltip-fg: #fffafa;
            --graph-bg: #fff8fa;
            --graph-edge: #987181;
            --graph-node-text: #3b2029;
            --graph-endpoint-bg: #e4e9fb;
            --graph-endpoint-fg: #3730a3;
            --graph-intermediate-bg: #f8e3bd;
            --graph-intermediate-fg: #713f12;
            --graph-changed-bg: #dcecdf;
            --graph-changed-fg: #14532d;
            --graph-fork: #c2410c;
            --graph-merge: #86198f;
            --graph-selected: #9f1239;
            --radius-sm: 11px;
            --radius-md: 18px;
            --radius-lg: 28px;
            --shadow-sm: 0 2px 5px rgba(95, 24, 49, 0.08);
            --shadow-lg: 0 25px 68px rgba(95, 24, 49, 0.14);
        }

        *, *::before, *::after { box-sizing: border-box; }
        html { min-width: 0; scroll-behavior: smooth; }
        body {
            min-width: 0;
            margin: 0;
            color: var(--text);
            background-color: var(--canvas);
            background-image: var(--canvas-image);
            background-attachment: fixed;
            font-family: var(--font-ui);
            font-size: 16px;
            line-height: 1.55;
            overflow-wrap: anywhere;
        }
        ::selection { color: var(--accent-ink); background: var(--accent); }
        :focus-visible { outline: 3px solid var(--focus); outline-offset: 3px; }
        [hidden] { display: none !important; }

        .sr-only {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip: rect(0, 0, 0, 0);
            white-space: nowrap;
            border: 0;
        }
        .skip-link {
            position: fixed;
            top: 8px;
            left: 8px;
            z-index: 10000;
            padding: 10px 14px;
            color: var(--accent-ink);
            background: var(--accent);
            border-radius: var(--radius-sm);
            transform: translateY(-160%);
        }
        .skip-link:focus { transform: translateY(0); }

        .report-toolbar {
            position: sticky;
            top: 0;
            z-index: 100;
            color: var(--text);
            background: var(--surface);
            background: color-mix(in srgb, var(--surface) 92%, transparent);
            border-bottom: 1px solid var(--border);
            box-shadow: var(--shadow-sm);
            backdrop-filter: blur(16px);
        }
        .report-toolbar-inner {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 18px;
            width: min(100% - 32px, var(--page-width));
            min-height: 68px;
            margin: 0 auto;
        }
        .report-brand { display: flex; align-items: center; gap: 11px; min-width: 0; }
        .report-brand-mark {
            display: grid;
            flex: 0 0 auto;
            width: 34px;
            height: 34px;
            place-items: center;
            color: var(--accent-ink);
            background: var(--accent);
            border-radius: calc(var(--radius-sm) + 2px);
            font-family: var(--font-code);
            font-weight: 800;
        }
        .report-brand-copy { display: grid; line-height: 1.15; }
        .report-brand-copy strong { color: var(--heading); font-size: 0.95rem; }
        .report-brand-copy span { color: var(--muted); font-size: 0.76rem; letter-spacing: 0.04em; text-transform: uppercase; }
        .theme-control { display: flex; align-items: center; gap: 9px; }
        .theme-control label { color: var(--muted); font-size: 0.78rem; font-weight: 750; letter-spacing: 0.08em; text-transform: uppercase; }
        .theme-control select {
            min-height: 42px;
            padding: 8px 34px 8px 12px;
            color: var(--text);
            background: var(--surface-raised);
            border: 1px solid var(--border-strong);
            border-radius: var(--radius-sm);
            font: 650 0.92rem var(--font-ui);
            cursor: pointer;
        }
        .theme-status {
            min-width: 65px;
            color: var(--muted);
            font: 0.76rem var(--font-code);
            text-align: right;
        }

        .container {
            width: min(100% - 32px, var(--page-width));
            margin: 26px auto 52px;
            padding: clamp(22px, 4vw, 56px);
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-lg);
        }
        .report-hero {
            position: relative;
            margin: calc(clamp(22px, 4vw, 56px) * -1) calc(clamp(22px, 4vw, 56px) * -1) 38px;
            padding: clamp(34px, 6vw, 78px) clamp(22px, 4vw, 56px);
            overflow: hidden;
            background: var(--surface-subtle);
            border-bottom: 1px solid var(--border);
            border-radius: var(--radius-lg) var(--radius-lg) 0 0;
        }
        .report-hero::after {
            position: absolute;
            right: -80px;
            bottom: -130px;
            width: 320px;
            height: 320px;
            background: var(--accent-soft);
            border-radius: 50%;
            content: "";
            opacity: 0.65;
        }
        .report-kicker { position: relative; z-index: 1; margin: 0 0 12px; color: var(--accent); font: 750 0.78rem var(--font-code); letter-spacing: 0.13em; text-transform: uppercase; }
        h1, h2, h3, h4 { color: var(--heading); font-family: var(--font-heading); line-height: 1.2; }
        h1 { position: relative; z-index: 1; max-width: 900px; margin: 0; font-size: clamp(2rem, 5vw, 4.6rem); letter-spacing: -0.045em; }
        .report-subtitle { position: relative; z-index: 1; max-width: 760px; margin: 15px 0 0; color: var(--muted); font-size: clamp(1rem, 2vw, 1.22rem); }
        h2 { margin: 42px 0 18px; padding-bottom: 11px; border-bottom: 1px solid var(--border); font-size: clamp(1.35rem, 2vw, 1.7rem); }
        h2::after { display: block; width: 92px; height: 3px; margin-top: 11px; background: var(--section-rule); content: ""; }
        h3 { margin: 30px 0 13px; font-size: 1.05rem; letter-spacing: 0.025em; }
        p { margin: 0 0 12px; }
        ul { padding-left: 22px; }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 1px;
            margin-bottom: 30px;
            overflow: hidden;
            background: var(--border);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-sm);
        }
        .summary-item {
            min-height: 92px;
            padding: 18px;
            background: var(--surface-raised);
        }
        .summary-label { display: block; margin-bottom: 7px; color: var(--muted); font-size: 0.74rem; font-weight: 800; letter-spacing: 0.075em; text-transform: uppercase; }
        .summary-item code { display: block; width: fit-content; max-width: 100%; margin-top: 3px; }

        .endpoint-card {
            position: relative;
            margin-bottom: 20px;
            padding: clamp(18px, 3vw, 28px);
            background: var(--surface-raised);
            border: var(--card-border-width) solid var(--border);
            border-left-width: 5px;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-sm);
            transition: border-color 150ms ease, box-shadow 150ms ease, transform 150ms ease;
        }
        .endpoint-card:hover { border-color: var(--border-strong); box-shadow: var(--shadow-lg); transform: translateY(-1px); }
        .confidence-high { border-left-color: var(--danger); }
        .confidence-medium { border-left-color: var(--warning); }
        .confidence-low { border-left-color: var(--success); }
        .endpoint-header { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 18px; }
        .method-badge { display: inline-flex; min-height: 28px; align-items: center; padding: 3px 9px; color: #fff; background: #334155; border-radius: calc(var(--radius-sm) / 1.5); font: 800 0.74rem var(--font-code); letter-spacing: 0.045em; }
        .method-GET { background: #0c4a6e; }
        .method-POST { background: #14532d; }
        .method-PUT { background: #7c2d12; }
        .method-DELETE { background: #7f1d1d; }
        .method-PATCH { background: #134e4a; }
        .method-OPTIONS { background: #581c87; }
        .method-HEAD { background: #1e3a8a; }
        .method-TRACE { background: #374151; }
        .method-WEBSOCKET { background: #4c1d95; }
        .method-CUSTOM { background: #3f3f46; }
        .endpoint-path { min-width: 0; color: var(--heading); background: var(--surface-strong); border: 1px solid var(--border); border-radius: var(--radius-sm); font: 700 0.96rem var(--font-code); padding: 5px 10px; }
        .info-item { margin: 9px 0; padding-left: 12px; border-left: 2px solid var(--border); }
        .label { color: var(--muted); font-weight: 800; }
        code { max-width: 100%; padding: 2px 6px; color: var(--text); background: var(--surface-strong); border-radius: calc(var(--radius-sm) / 2); font-family: var(--font-code); font-size: 0.88em; overflow-wrap: anywhere; }

        .code-ref { position: relative; display: inline-block; max-width: 100%; padding: 2px 6px; color: var(--text); background: var(--surface-strong); border: 1px solid transparent; border-radius: calc(var(--radius-sm) / 2); font: 0.88em var(--font-code); cursor: help; }
        .code-ref:hover, .code-ref:focus { border-color: var(--accent); background: var(--accent-soft); }
        .hover-tooltip {
            position: absolute;
            top: calc(100% + 7px);
            left: 0;
            z-index: 1000;
            display: none;
            width: min(620px, calc(100vw - 48px));
            max-height: 420px;
            padding: 11px;
            overflow: auto;
            color: var(--tooltip-fg);
            background: var(--tooltip-bg);
            border: 1px solid var(--border-strong);
            border-radius: var(--radius-sm);
            box-shadow: var(--shadow-lg);
        }
        .code-ref:hover:not(.tooltip-dismissed) .hover-tooltip,
        .code-ref:focus-within:not(.tooltip-dismissed) .hover-tooltip { display: block; }
        .code-context, .call-path-source { display: block; max-width: 100%; margin: 0; padding: 11px; overflow: auto; color: var(--code-fg); background: var(--code-bg); border-radius: var(--radius-sm); font: 0.83rem/1.48 var(--font-code); white-space: pre; }
        .line-num { margin-right: 10px; color: var(--code-muted); user-select: none; }
        .highlight-line { display: block; background: var(--code-highlight); }

        .call-stack, .dependency-chain { margin-top: 12px; padding: 11px 13px; background: var(--surface-subtle); border: 1px solid var(--border); border-radius: var(--radius-sm); font: 0.86rem var(--font-code); }
        .legacy-call-stack summary { color: var(--muted); cursor: pointer; font: 750 0.88rem var(--font-ui); }
        .legacy-call-stack[open] summary { margin-bottom: 10px; }
        .error-box, .warning-box, .no-endpoints { margin: 18px 0; padding: 18px; border: 1px solid; border-radius: var(--radius-md); }
        .error-box { color: var(--danger); background: var(--danger-soft); border-color: var(--danger); }
        .warning-box { color: var(--warning); background: var(--warning-soft); border-color: var(--warning); }
        .error-box h3, .warning-box h3 { margin-top: 0; color: currentColor; }
        .no-endpoints { color: var(--success); background: var(--success-soft); border-color: var(--success); text-align: center; font-size: 1.04rem; }
        .orphan-change { margin: 15px 0; padding: 13px; color: var(--text); background: var(--surface-raised); border: 1px solid var(--border); border-radius: var(--radius-sm); }
        .orphan-change-title { margin-bottom: 5px; color: var(--heading); font-weight: 800; }
        .orphan-change-path, .orphan-change-reason { color: var(--muted); font-size: 0.86rem; }
        .orphan-change-lines { margin-top: 8px; font: 0.87rem var(--font-code); }
        .orphan-tip { margin-top: 15px; padding: 13px; color: var(--text); background: var(--surface-subtle); border: 1px solid var(--border); border-radius: var(--radius-sm); font-size: 0.9rem; }

        .table-wrap { max-width: 100%; overflow-x: auto; border: 1px solid var(--border); border-radius: var(--radius-md); }
        .table-wrap .hover-tooltip { position: static; width: min(620px, 80vw); margin-top: 7px; }
        table { width: 100%; margin: 0; border-collapse: collapse; background: var(--surface-raised); }
        th { padding: 13px; color: var(--accent-ink); background: var(--accent); font-weight: 800; text-align: left; }
        td { padding: 11px 13px; border-bottom: 1px solid var(--border); }
        tbody tr:hover { background: var(--surface-subtle); }

        .call-path-view { margin-top: 20px; padding: clamp(14px, 2vw, 22px); background: var(--surface-subtle); border: 1px solid var(--border); border-radius: var(--radius-md); }
        .call-path-toolbar { display: flex; align-items: flex-end; gap: 12px; flex-wrap: wrap; }
        .call-path-toolbar > div:first-child { flex: 1 1 420px; }
        .call-path-toolbar h4 { margin: 0; font-size: 1.05rem; }
        .call-path-semantics { margin: 4px 0 0; color: var(--muted); font-size: 0.86rem; }
        .call-path-toolbar label { display: grid; gap: 4px; color: var(--muted); font-size: 0.76rem; font-weight: 750; letter-spacing: 0.04em; }
        .call-path-toolbar input, .call-path-toolbar select { min-width: min(220px, 100%); min-height: 40px; padding: 7px 10px; color: var(--text); background: var(--surface-raised); border: 1px solid var(--border-strong); border-radius: var(--radius-sm); font: inherit; }
        button { min-height: 38px; padding: 6px 11px; color: var(--text); background: var(--surface-raised); border: 1px solid var(--border-strong); border-radius: var(--radius-sm); font: 700 0.84rem var(--font-ui); cursor: pointer; }
        button:hover { color: var(--accent-ink); background: var(--accent); border-color: var(--accent); }
        .call-path-zoom-controls { display: flex; align-items: center; gap: 5px; margin-left: auto; }
        .call-path-zoom-controls span { min-width: 48px; color: var(--muted); font: 0.8rem var(--font-code); text-align: center; }
        .call-path-touch-pan [data-call-path-touch-pan] { color: var(--accent-ink); background: var(--accent); border-color: var(--accent); }
        .call-path-summary { margin-top: 13px; padding: 10px 12px; color: var(--info); background: var(--info-soft); border-left: 4px solid var(--info); border-radius: 0 var(--radius-sm) var(--radius-sm) 0; }
        .call-path-layout-status { display: block; margin: 10px 0 2px; color: var(--heading); font: 750 0.82rem var(--font-ui); }
        .call-path-gesture-hint { margin: 0 0 9px; color: var(--muted); font-size: 0.76rem; }
        .call-path-branch-summary { margin-left: 8px; color: var(--warning); font-weight: 800; }
        .call-path-legend { display: flex; gap: 7px; flex-wrap: wrap; margin: 13px 0 9px; }
        .call-path-role { display: inline-flex; align-items: center; padding: 3px 8px; border-radius: 999px; font-size: 0.73rem; font-weight: 800; }
        .call-path-role-endpoint { color: var(--graph-endpoint-fg); background: var(--graph-endpoint-bg); }
        .call-path-role-intermediate { color: var(--graph-intermediate-fg); background: var(--graph-intermediate-bg); }
        .call-path-role-changed { color: var(--graph-changed-fg); background: var(--graph-changed-bg); }
        .call-path-node-endpoint > rect:first-of-type { fill: var(--graph-endpoint-bg); }
        .call-path-node-intermediate > rect:first-of-type { fill: var(--graph-intermediate-bg); }
        .call-path-node-changed > rect:first-of-type { fill: var(--graph-changed-bg); }
        .call-path-node-endpoint .call-path-node-role { fill: var(--graph-endpoint-fg); }
        .call-path-node-intermediate .call-path-node-role { fill: var(--graph-intermediate-fg); }
        .call-path-node-changed .call-path-node-role { fill: var(--graph-changed-fg); }
        .call-path-canvas { width: 100%; overflow: auto; background: var(--graph-bg); border: 1px solid var(--border); border-radius: var(--radius-sm); }
        .call-path-svg { display: block; width: auto; min-width: 100%; height: auto; min-height: 300px; padding: 5px; background: var(--graph-bg); cursor: grab; touch-action: pan-y; user-select: none; }
        html.js .call-path-canvas { overflow: hidden; }
        html.js .call-path-svg { width: 100%; height: 620px; max-height: 70vh; }
        .call-path-view.call-path-touch-pan .call-path-svg { touch-action: none; }
        .call-path-svg.call-path-panning { cursor: grabbing; }
        .call-path-edge { fill: none; stroke: var(--graph-edge); stroke-width: 2; transition: opacity 150ms ease, stroke-width 150ms ease; }
        .call-path-arrow { fill: var(--graph-edge); }
        .call-path-edge-muted { opacity: 0.12; }
        .call-path-edge-selected { stroke: var(--graph-selected); stroke-width: 3.5; opacity: 1; }
        .call-path-cluster rect { fill: var(--surface-raised); fill-opacity: 0.42; stroke: var(--border-strong); stroke-width: 1.5; stroke-dasharray: 7 5; }
        .call-path-cluster text { fill: var(--graph-node-text); font: 750 13px var(--font-code); }
        .call-path-node { cursor: pointer; }
        .call-path-node > rect:first-of-type { stroke: var(--border-strong); stroke-width: 1.5; }
        .call-path-node-fork > rect:first-of-type { stroke: var(--graph-fork); stroke-width: 2.5; }
        .call-path-node-merge > rect:first-of-type { stroke: var(--graph-merge); stroke-width: 2.5; }
        .call-path-node:hover > rect:first-of-type,
        .call-path-node-selected > rect:first-of-type { stroke: var(--graph-selected); stroke-width: 3; }
        .call-path-node-role { font-size: 13px; font-weight: 800; }
        .call-path-node-label { fill: var(--graph-node-text); font: 700 14px var(--font-code); }
        .call-path-node-meta { fill: var(--graph-node-text); font: 11px var(--font-code); opacity: 0.78; }
        .call-path-topology-fork { fill: var(--graph-fork); }
        .call-path-topology-merge { fill: var(--graph-merge); stroke: none; }
        .call-path-topology-key { display: inline-flex; align-items: center; gap: 5px; color: var(--muted); font-size: 0.74rem; font-weight: 750; }
        .call-path-topology-key::before { display: inline-block; width: 10px; height: 10px; background: var(--topology-color); content: ""; }
        .call-path-topology-key-fork { --topology-color: var(--graph-fork); }
        .call-path-topology-key-fork::before { border-radius: 50%; }
        .call-path-topology-key-merge { --topology-color: var(--graph-merge); }
        .call-path-topology-key-merge::before { transform: rotate(45deg); }
        .call-path-node-muted { opacity: 0.3; }

        .call-tree-panel { margin-top: 13px; overflow: hidden; background: var(--surface-raised); border: 1px solid var(--border); border-radius: var(--radius-sm); }
        .call-tree-panel > summary { padding: 11px 13px; color: var(--heading); cursor: pointer; font-weight: 800; list-style: none; }
        .call-tree-panel > summary::-webkit-details-marker, .call-tree-node > summary::-webkit-details-marker { display: none; }
        .call-tree-caret { display: inline-block; width: 17px; margin-right: 3px; color: var(--muted); font-size: 1.1em; text-align: center; transition: transform 150ms ease; }
        .call-tree-panel[open] > summary .call-tree-caret, .call-tree-node[open] > .call-tree-summary .call-tree-caret { transform: rotate(90deg); }
        .call-tree-toolbar { display: flex; gap: 6px; padding: 7px 12px; background: var(--surface-subtle); border-top: 1px solid var(--border); border-bottom: 1px solid var(--border); }
        .call-tree-root, .call-tree-children { margin: 0; padding: 0; list-style: none; }
        .call-tree-children { margin-left: 24px; border-left: 1px solid var(--border); }
        .call-tree-summary, .call-tree-leaf, .call-tree-shared-ref { display: flex; align-items: center; gap: 4px; width: 100%; min-height: 42px; padding: 7px 12px; color: var(--text); background: transparent; border: 0; border-bottom: 1px solid var(--border); border-radius: 0; font: inherit; text-align: left; cursor: pointer; }
        .call-tree-summary:hover, .call-tree-leaf:hover, .call-tree-shared-ref:hover, .call-tree-summary.call-path-node-selected, .call-tree-leaf.call-path-node-selected, .call-tree-shared-ref.call-path-node-selected { color: var(--text); background: var(--accent-soft); }
        .call-tree-summary small, .call-tree-leaf small, .call-tree-shared-ref small { margin-left: auto; color: var(--muted); font-size: 0.76rem; }
        .call-path-details { margin-top: 12px; padding: 13px; color: var(--info); background: var(--info-soft); border-left: 4px solid var(--info); border-radius: 0 var(--radius-sm) var(--radius-sm) 0; }
        .call-path-details h4 { margin: 0 0 5px; color: currentColor; }
        .call-path-details p { margin: 4px 0 8px; }
        .call-path-source { max-height: 280px; white-space: pre-wrap; overflow-wrap: anywhere; }
        .call-path-no-match { margin-top: 10px; color: var(--danger); }
        .call-path-fallback { background: var(--warning-soft); border-color: var(--warning); }
        .call-path-fallback-list { margin: 8px 0 0 22px; }
        .call-path-direct-edge { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 10px; padding: 9px; background: var(--warning-soft); border: 1px dashed var(--warning); border-radius: var(--radius-sm); }
        .call-path-direct-arrow, .call-path-direct-note { color: var(--warning); }
        .call-path-direct-arrow { font-size: 1.2em; font-weight: 800; }

        @media (max-width: 760px) {
            .report-toolbar-inner { width: min(100% - 20px, var(--page-width)); min-height: 62px; }
            .report-brand-copy span, .theme-status { display: none; }
            .theme-control label { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0, 0, 0, 0); }
            .theme-control select { max-width: 150px; }
            .container { width: min(100% - 16px, var(--page-width)); margin-top: 10px; padding: 18px; }
            .report-hero { margin: -18px -18px 28px; padding: 34px 18px; }
            .summary { grid-template-columns: 1fr; }
            .call-path-toolbar { align-items: stretch; }
            .call-path-toolbar > * { width: 100%; }
            .call-path-toolbar input, .call-path-toolbar select { width: 100%; min-width: 0; }
            .call-path-zoom-controls { width: 100%; margin-left: 0; }
            .call-path-zoom-controls button { flex: 1; }
            html.js .call-path-svg { height: 440px; }
            .call-tree-children { margin-left: 12px; }
            .call-tree-summary, .call-tree-leaf, .call-tree-shared-ref { align-items: flex-start; flex-wrap: wrap; }
            .call-tree-summary small, .call-tree-leaf small, .call-tree-shared-ref small { width: 100%; margin-left: 21px; }
            .hover-tooltip { position: fixed; top: 76px; right: 12px; left: 12px; width: auto; max-height: calc(100dvh - 96px); }
            .table-wrap .hover-tooltip { position: static; width: min(620px, 80vw); max-height: calc(100dvh - 96px); }
        }

        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after { scroll-behavior: auto !important; transition-duration: 0.01ms !important; animation-duration: 0.01ms !important; animation-iteration-count: 1 !important; }
        }

        @media (forced-colors: active) {
            .endpoint-card, .summary, .call-path-view, .call-path-canvas, .call-tree-panel { border: 1px solid CanvasText; }
            .call-path-node-selected { outline: 3px solid Highlight; }
            .method-badge { border: 1px solid ButtonText; }
        }

        @page { margin: 12mm; }
        @media print {
            html[data-theme] { color-scheme: light; --canvas: #fff; --surface: #fff; --surface-raised: #fff; --surface-subtle: #fff; --surface-strong: #f3f3f3; --text: #111; --muted: #444; --heading: #000; --border: #999; --border-strong: #333; --shadow-sm: none; --shadow-lg: none; }
            body { background: #fff; font-size: 10pt; }
            .report-toolbar, .skip-link, .call-path-toolbar label, [data-call-path-reset], .call-path-zoom-controls, .call-tree-toolbar, .hover-tooltip { display: none !important; }
            .container { width: 100%; margin: 0; padding: 0; border: 0; box-shadow: none; }
            .report-hero { margin: 0 0 20px; padding: 0 0 18px; background: #fff; border-radius: 0; }
            .report-hero::after { display: none; }
            .endpoint-card, .summary-item, .warning-box, .error-box { break-inside: avoid; box-shadow: none; }
            h1, h2, h3 { break-after: avoid; }
            .call-path-svg { width: 100%; height: auto; max-height: none; }
            .call-path-canvas, .table-wrap { overflow: visible; }
        }
    </style>
</head>
<body>
    <a class="skip-link" href="#report-content">Skip to report</a>
    <header class="report-toolbar" aria-label="Report appearance">
        <div class="report-toolbar-inner">
            <div class="report-brand" aria-label="FastAPI Endpoint Change Detector">
                <span class="report-brand-mark" aria-hidden="true">BR</span>
                <span class="report-brand-copy"><strong>Blast Radius</strong><span>Static analysis report</span></span>
            </div>
            <div class="theme-control">
                <label for="report-theme">Theme</label>
                <select id="report-theme" data-theme-select aria-describedby="theme-status">
                    {THEME_OPTIONS}
                </select>
                <output class="theme-status" id="theme-status" data-theme-status aria-live="polite">{DEFAULT_THEME_POSITION} / 10</output>
            </div>
        </div>
    </header>
    <main class="container" id="report-content" tabindex="-1">
{CONTENT}
    </main>
    <script>
    (function () {
        "use strict";

        var themeSelect = document.querySelector("[data-theme-select]");
        var themeStatus = document.querySelector("[data-theme-status]");
        if (themeSelect) {
            var themeOptions = Array.from(themeSelect.options);
            var allowedThemes = themeOptions.map(function (option) {
                return option.value;
            });
            var activeTheme = document.documentElement.getAttribute("data-theme") || "{DEFAULT_THEME}";
            if (allowedThemes.indexOf(activeTheme) === -1) {
                activeTheme = "{DEFAULT_THEME}";
            }

            function applyTheme(themeId, persist) {
                var index = allowedThemes.indexOf(themeId);
                if (index === -1) {
                    themeId = "{DEFAULT_THEME}";
                    index = allowedThemes.indexOf(themeId);
                }
                document.documentElement.setAttribute("data-theme", themeId);
                themeSelect.value = themeId;
                if (themeStatus) {
                    themeStatus.textContent = (index + 1) + " / " + allowedThemes.length;
                    themeStatus.setAttribute(
                        "aria-label",
                        "Theme " + themeOptions[index].text + ", " + (index + 1) +
                        " of " + allowedThemes.length
                    );
                }
                if (persist) {
                    try {
                        window.localStorage.setItem("{THEME_STORAGE_KEY}", themeId);
                    } catch (error) {
                        // Theme switching remains functional when local file storage is denied.
                    }
                }
            }

            themeSelect.addEventListener("change", function () {
                applyTheme(themeSelect.value, true);
            });
            applyTheme(activeTheme, false);
        }

        document.querySelectorAll(".code-ref[tabindex]").forEach(function (reference) {
            reference.addEventListener("keydown", function (event) {
                if (event.key === "Escape") {
                    event.preventDefault();
                    reference.classList.add("tooltip-dismissed");
                }
            });
            reference.addEventListener("focusout", function () {
                reference.classList.remove("tooltip-dismissed");
            });
            reference.addEventListener("mouseenter", function () {
                reference.classList.remove("tooltip-dismissed");
            });
        });

        var printDisclosureState = [];
        window.addEventListener("beforeprint", function () {
            var disclosures = Array.from(
                document.querySelectorAll(".call-tree-panel, .call-tree-node")
            );
            printDisclosureState = disclosures.map(function (disclosure) {
                return disclosure.open;
            });
            disclosures.forEach(function (disclosure) {
                disclosure.open = true;
            });
        });
        window.addEventListener("afterprint", function () {
            document.querySelectorAll(".call-tree-panel, .call-tree-node").forEach(
                function (disclosure, index) {
                    disclosure.open = Boolean(printDisclosureState[index]);
                }
            );
        });

        document.querySelectorAll("[data-call-path-view]").forEach(function (view) {
            var search = view.querySelector("[data-call-path-search]");
            var reset = view.querySelector("[data-call-path-reset]");
            var nodes = Array.from(view.querySelectorAll("[data-call-path-node]"));
            var details = Array.from(view.querySelectorAll("[data-call-path-detail]"));
            var edges = Array.from(view.querySelectorAll("[data-call-path-edge-source]"));
            var defaultDetails = view.querySelector("[data-call-path-default]");
            var noMatch = view.querySelector("[data-call-path-no-match]");
            var svg = view.querySelector("[data-call-path-svg]");
            var stage = view.querySelector("[data-call-path-stage]");
            var graphNodes = svg ? Array.from(svg.querySelectorAll("g[data-call-path-node]")) : [];
            var clusterLayer = view.querySelector("[data-call-path-clusters]");
            var layoutSelect = view.querySelector("[data-call-path-layout]");
            var layoutStatus = view.querySelector("[data-call-path-layout-status]");
            var zoomLabel = view.querySelector("[data-call-path-zoom-label]");
            var zoomIn = view.querySelector("[data-call-path-zoom-in]");
            var zoomOut = view.querySelector("[data-call-path-zoom-out]");
            var fit = view.querySelector("[data-call-path-fit]");
            var touchPan = view.querySelector("[data-call-path-touch-pan]");
            var treeBranches = Array.from(view.querySelectorAll(".call-tree-node"));
            var treeExpand = view.querySelector("[data-call-tree-expand]");
            var treeCollapse = view.querySelector("[data-call-tree-collapse]");
            var graphScale = 1;
            var graphX = 0;
            var graphY = 0;
            var graphWidth = svg ? Number(svg.getAttribute("data-graph-width")) : 1050;
            var graphHeight = svg ? Number(svg.getAttribute("data-graph-height")) : 300;
            var currentLayout = "flow-lr";
            var currentPositions = new Map();
            var nodeWidth = 220;
            var nodeHeight = 104;
            var svgNamespace = "http://www.w3.org/2000/svg";
            var printGraphView = null;

            window.addEventListener("beforeprint", function () {
                printGraphView = { scale: graphScale, x: graphX, y: graphY };
                fitGraph();
            });
            window.addEventListener("afterprint", function () {
                if (printGraphView) {
                    graphScale = printGraphView.scale;
                    graphX = printGraphView.x;
                    graphY = printGraphView.y;
                    updateGraphTransform();
                    printGraphView = null;
                }
            });

            function sortedGraphNodes() {
                return graphNodes.slice().sort(function (left, right) {
                    var layerDifference = Number(left.dataset.callPathLayer) -
                        Number(right.dataset.callPathLayer);
                    if (layerDifference !== 0) {
                        return layerDifference;
                    }
                    var orderDifference = Number(left.dataset.callPathOrder) -
                        Number(right.dataset.callPathOrder);
                    if (orderDifference !== 0) {
                        return orderDifference;
                    }
                    return left.dataset.callPathNode.localeCompare(right.dataset.callPathNode);
                });
            }

            function layerGroups() {
                var groups = new Map();
                sortedGraphNodes().forEach(function (node) {
                    var layer = Number(node.dataset.callPathLayer);
                    if (!groups.has(layer)) {
                        groups.set(layer, []);
                    }
                    groups.get(layer).push(node);
                });
                return Array.from(groups.entries()).sort(function (left, right) {
                    return left[0] - right[0];
                });
            }

            function rankedLayout(vertical) {
                var groups = layerGroups();
                var positions = new Map();
                var maxMembers = groups.reduce(function (maximum, entry) {
                    return Math.max(maximum, entry[1].length);
                }, 1);
                var layerStep = vertical ? 160 : 280;
                var memberStep = vertical ? 250 : 132;
                groups.forEach(function (entry, layerIndex) {
                    var members = entry[1];
                    var offset = (maxMembers - members.length) * memberStep / 2;
                    members.forEach(function (node, memberIndex) {
                        var primary = 52 + layerIndex * layerStep;
                        var secondary = 52 + offset + memberIndex * memberStep;
                        positions.set(node.dataset.callPathNode, vertical ?
                            { x: secondary, y: primary } : { x: primary, y: secondary });
                    });
                });
                return {
                    positions: positions,
                    width: vertical ? 104 + maxMembers * memberStep :
                        104 + Math.max(groups.length, 1) * layerStep,
                    height: vertical ? 104 + Math.max(groups.length, 1) * layerStep :
                        104 + maxMembers * memberStep,
                    clusters: []
                };
            }

            function radialLayout() {
                var groups = layerGroups();
                var positions = new Map();
                var diagonal = Math.hypot(nodeWidth, nodeHeight);
                var radii = [];
                var previousRadius = 0;
                groups.forEach(function (entry, index) {
                    var count = entry[1].length;
                    if (index === 0 && count === 1) {
                        radii.push(0);
                        return;
                    }
                    var collisionRadius = count > 1 ?
                        (diagonal + 54) / (2 * Math.sin(Math.PI / count)) : 0;
                    previousRadius = Math.max(previousRadius + diagonal + 54, collisionRadius);
                    radii.push(previousRadius);
                });
                var maxRadius = radii.reduce(function (maximum, radius) {
                    return Math.max(maximum, radius);
                }, 0);
                var side = Math.max(720, 2 * (maxRadius + diagonal / 2 + 72));
                var center = side / 2;
                groups.forEach(function (entry, groupIndex) {
                    var members = entry[1];
                    var radius = radii[groupIndex];
                    members.forEach(function (node, memberIndex) {
                        var angle = -Math.PI / 2 + 2 * Math.PI * memberIndex / members.length;
                        positions.set(node.dataset.callPathNode, {
                            x: center + radius * Math.cos(angle) - nodeWidth / 2,
                            y: center + radius * Math.sin(angle) - nodeHeight / 2
                        });
                    });
                });
                return { positions: positions, width: side, height: side, clusters: [] };
            }

            function fileGroupLayout() {
                var grouped = new Map();
                sortedGraphNodes().forEach(function (node) {
                    var key = node.dataset.callPathFile || "unknown";
                    if (!grouped.has(key)) {
                        grouped.set(key, {
                            label: node.dataset.callPathFileLabel || "unknown",
                            nodes: []
                        });
                    }
                    grouped.get(key).nodes.push(node);
                });
                var groups = Array.from(grouped.entries()).sort(function (left, right) {
                    return left[1].label.localeCompare(right[1].label) ||
                        left[0].localeCompare(right[0]);
                });
                var positions = new Map();
                var clusters = [];
                var cursorX = 44;
                var cursorY = 44;
                var rowHeight = 0;
                var maximumX = 0;
                var targetWidth = 1560;
                groups.forEach(function (entry) {
                    var group = entry[1];
                    var columns = Math.ceil(Math.sqrt(group.nodes.length));
                    var rows = Math.ceil(group.nodes.length / columns);
                    var clusterWidth = 48 + columns * nodeWidth + (columns - 1) * 28;
                    var clusterHeight = 76 + rows * nodeHeight + (rows - 1) * 28;
                    if (cursorX > 44 && cursorX + clusterWidth > targetWidth) {
                        cursorX = 44;
                        cursorY += rowHeight + 38;
                        rowHeight = 0;
                    }
                    clusters.push({
                        x: cursorX,
                        y: cursorY,
                        width: clusterWidth,
                        height: clusterHeight,
                        label: group.label
                    });
                    group.nodes.forEach(function (node, index) {
                        var row = Math.floor(index / columns);
                        var offset = index % columns;
                        var column = row % 2 === 0 ? offset : columns - 1 - offset;
                        positions.set(node.dataset.callPathNode, {
                            x: cursorX + 24 + column * (nodeWidth + 28),
                            y: cursorY + 48 + row * (nodeHeight + 28)
                        });
                    });
                    cursorX += clusterWidth + 38;
                    rowHeight = Math.max(rowHeight, clusterHeight);
                    maximumX = Math.max(maximumX, cursorX);
                });
                return {
                    positions: positions,
                    width: Math.max(720, maximumX + 6),
                    height: Math.max(360, cursorY + rowHeight + 44),
                    clusters: clusters
                };
            }

            function renderClusters(clusters) {
                if (!clusterLayer) {
                    return;
                }
                clusterLayer.replaceChildren();
                clusters.forEach(function (cluster) {
                    var group = document.createElementNS(svgNamespace, "g");
                    var rectangle = document.createElementNS(svgNamespace, "rect");
                    var label = document.createElementNS(svgNamespace, "text");
                    group.setAttribute("class", "call-path-cluster");
                    rectangle.setAttribute("x", cluster.x);
                    rectangle.setAttribute("y", cluster.y);
                    rectangle.setAttribute("width", cluster.width);
                    rectangle.setAttribute("height", cluster.height);
                    rectangle.setAttribute("rx", "14");
                    label.setAttribute("x", cluster.x + 18);
                    label.setAttribute("y", cluster.y + 27);
                    label.textContent = cluster.label;
                    group.appendChild(rectangle);
                    group.appendChild(label);
                    clusterLayer.appendChild(group);
                });
            }

            function boundaryPoint(from, to) {
                var dx = to.x - from.x;
                var dy = to.y - from.y;
                if (dx === 0 && dy === 0) {
                    return { x: from.x, y: from.y };
                }
                var denominator = Math.max(
                    Math.abs(dx) / (nodeWidth / 2),
                    Math.abs(dy) / (nodeHeight / 2)
                );
                return {
                    x: from.x + dx / denominator,
                    y: from.y + dy / denominator
                };
            }

            function routeEdges(layoutId) {
                edges.forEach(function (edge, index) {
                    var sourcePosition = currentPositions.get(
                        edge.getAttribute("data-call-path-edge-source")
                    );
                    var targetPosition = currentPositions.get(
                        edge.getAttribute("data-call-path-edge-target")
                    );
                    if (!sourcePosition || !targetPosition) {
                        return;
                    }
                    var sourceCenter = {
                        x: sourcePosition.x + nodeWidth / 2,
                        y: sourcePosition.y + nodeHeight / 2
                    };
                    var targetCenter = {
                        x: targetPosition.x + nodeWidth / 2,
                        y: targetPosition.y + nodeHeight / 2
                    };
                    var start = boundaryPoint(sourceCenter, targetCenter);
                    var end = boundaryPoint(targetCenter, sourceCenter);
                    var path;
                    if (layoutId === "flow-lr") {
                        var middleX = (start.x + end.x) / 2;
                        path = "M " + start.x + " " + start.y + " C " + middleX + " " +
                            start.y + ", " + middleX + " " + end.y + ", " + end.x + " " + end.y;
                    } else if (layoutId === "flow-tb") {
                        var middleY = (start.y + end.y) / 2;
                        path = "M " + start.x + " " + start.y + " C " + start.x + " " +
                            middleY + ", " + end.x + " " + middleY + ", " + end.x + " " + end.y;
                    } else {
                        var dx = end.x - start.x;
                        var dy = end.y - start.y;
                        var length = Math.max(Math.hypot(dx, dy), 1);
                        var bend = ((index % 3) - 1) * 24;
                        var controlX = (start.x + end.x) / 2 - dy / length * bend;
                        var controlY = (start.y + end.y) / 2 + dx / length * bend;
                        path = "M " + start.x + " " + start.y + " Q " + controlX + " " +
                            controlY + ", " + end.x + " " + end.y;
                    }
                    edge.setAttribute("d", path);
                });
            }

            function applyLayout(layoutId) {
                var result;
                if (layoutId === "flow-tb") {
                    result = rankedLayout(true);
                } else if (layoutId === "radial") {
                    result = radialLayout();
                } else if (layoutId === "files") {
                    result = fileGroupLayout();
                } else {
                    layoutId = "flow-lr";
                    result = rankedLayout(false);
                }
                currentLayout = layoutId;
                currentPositions = result.positions;
                graphWidth = result.width;
                graphHeight = result.height;
                graphNodes.forEach(function (node) {
                    var position = currentPositions.get(node.dataset.callPathNode);
                    if (position) {
                        node.setAttribute("transform", "translate(" + position.x + " " + position.y + ")");
                    }
                });
                if (svg) {
                    svg.setAttribute("data-graph-width", graphWidth);
                    svg.setAttribute("data-graph-height", graphHeight);
                }
                renderClusters(result.clusters);
                routeEdges(layoutId);
                var descriptions = {
                    "flow-lr": "Flow layout · layers read left to right",
                    "flow-tb": "Top-down layout · layers read from top to bottom",
                    "radial": "Radial layout · shared layers arranged in rings",
                    "files": "File groups layout · nodes grouped by source filename"
                };
                if (layoutStatus) {
                    layoutStatus.textContent = descriptions[layoutId] + " · " +
                        graphNodes.length + " nodes · " + edges.length + " connections";
                }
                view.setAttribute("data-call-path-layout-active", layoutId);
                fitGraph();
            }

            function updateGraphTransform() {
                if (stage) {
                    stage.setAttribute(
                        "transform",
                        "translate(" + graphX + " " + graphY + ") scale(" + graphScale + ")"
                    );
                }
                if (zoomLabel) {
                    zoomLabel.textContent = Math.round(graphScale * 100) + "%";
                }
            }

            function syncViewportCoordinates() {
                if (!svg) {
                    return;
                }
                var rectangle = svg.getBoundingClientRect();
                var viewportWidth = Math.max(320, Math.round(rectangle.width));
                var viewportHeight = Math.max(300, Math.round(rectangle.height));
                svg.setAttribute(
                    "viewBox",
                    "0 0 " + viewportWidth + " " + viewportHeight
                );
            }

            function viewBoxPoint(event) {
                if (!svg) {
                    return { x: 0, y: 0 };
                }
                var matrix = svg.getScreenCTM();
                if (!matrix) {
                    return { x: 0, y: 0 };
                }
                var point = svg.createSVGPoint();
                point.x = event.clientX;
                point.y = event.clientY;
                var transformed = point.matrixTransform(matrix.inverse());
                return { x: transformed.x, y: transformed.y };
            }

            function zoomAt(factor, point) {
                if (!svg) {
                    return;
                }
                var nextScale = Math.max(0.01, Math.min(4, graphScale * factor));
                var contentX = (point.x - graphX) / graphScale;
                var contentY = (point.y - graphY) / graphScale;
                graphScale = nextScale;
                graphX = point.x - contentX * graphScale;
                graphY = point.y - contentY * graphScale;
                updateGraphTransform();
            }

            function fitGraph() {
                if (!svg) {
                    return;
                }
                var viewBox = svg.viewBox.baseVal;
                graphScale = Math.max(
                    0.01,
                    Math.min(
                        1,
                        (viewBox.width - 48) / graphWidth,
                        (viewBox.height - 48) / graphHeight
                    )
                );
                graphX = (viewBox.width - graphWidth * graphScale) / 2;
                graphY = (viewBox.height - graphHeight * graphScale) / 2;
                updateGraphTransform();
            }

            function initialGraphView() {
                fitGraph();
            }

            function nodeMatches(nodeId, query) {
                var matchingNodes = nodes.filter(function (node) {
                    return node.getAttribute("data-call-path-node") === nodeId;
                });
                var detail = details.find(function (item) {
                    return item.getAttribute("data-call-path-detail") === nodeId;
                });
                var nodeText = matchingNodes.map(function (node) {
                    return (node.textContent || "") + " " +
                        (node.getAttribute("data-call-path-search-text") || "");
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
                graphNodes.forEach(function (node) {
                    node.setAttribute(
                        "aria-pressed",
                        node.getAttribute("data-call-path-node") === nodeId ? "true" : "false"
                    );
                });
                edges.forEach(function (edge) {
                    var incident = edge.getAttribute("data-call-path-edge-source") === nodeId ||
                        edge.getAttribute("data-call-path-edge-target") === nodeId;
                    edge.classList.toggle("call-path-edge-selected", Boolean(nodeId) && incident);
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
                        !matchingIds.has(source) && !matchingIds.has(target)
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
                if (node.matches('g[role="button"]')) {
                    node.addEventListener("keydown", function (event) {
                        if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            selectNode(node.getAttribute("data-call-path-node"));
                        }
                    });
                }
            });
            if (search) {
                search.addEventListener("input", filterGraph);
            }
            if (layoutSelect) {
                layoutSelect.addEventListener("change", function () {
                    applyLayout(layoutSelect.value);
                });
            }
            if (zoomIn) {
                zoomIn.addEventListener("click", function () {
                    if (svg) {
                        zoomAt(1.25, { x: svg.viewBox.baseVal.width / 2, y: svg.viewBox.baseVal.height / 2 });
                    }
                });
            }
            if (zoomOut) {
                zoomOut.addEventListener("click", function () {
                    if (svg) {
                        zoomAt(0.8, { x: svg.viewBox.baseVal.width / 2, y: svg.viewBox.baseVal.height / 2 });
                    }
                });
            }
            if (fit) {
                fit.addEventListener("click", fitGraph);
            }
            if (touchPan) {
                touchPan.addEventListener("click", function () {
                    var enabled = !view.classList.contains("call-path-touch-pan");
                    view.classList.toggle("call-path-touch-pan", enabled);
                    touchPan.setAttribute("aria-pressed", enabled ? "true" : "false");
                    touchPan.textContent = enabled ? "Touch pan on" : "Touch pan";
                });
            }
            if (svg && stage) {
                var dragging = false;
                var lastPoint = null;
                svg.addEventListener("wheel", function (event) {
                    if (!event.ctrlKey && !event.metaKey) {
                        return;
                    }
                    event.preventDefault();
                    zoomAt(event.deltaY < 0 ? 1.15 : 0.87, viewBoxPoint(event));
                }, { passive: false });
                svg.addEventListener("pointerdown", function (event) {
                    if (event.button !== 0 || event.target.closest("[data-call-path-node]")) {
                        return;
                    }
                    dragging = true;
                    lastPoint = viewBoxPoint(event);
                    svg.classList.add("call-path-panning");
                    svg.setPointerCapture(event.pointerId);
                });
                svg.addEventListener("pointermove", function (event) {
                    if (!dragging || !lastPoint) {
                        return;
                    }
                    var currentPoint = viewBoxPoint(event);
                    graphX += currentPoint.x - lastPoint.x;
                    graphY += currentPoint.y - lastPoint.y;
                    lastPoint = currentPoint;
                    updateGraphTransform();
                });
                svg.addEventListener("pointerup", function (event) {
                    dragging = false;
                    lastPoint = null;
                    svg.classList.remove("call-path-panning");
                    svg.releasePointerCapture(event.pointerId);
                });
                svg.addEventListener("pointercancel", function () {
                    dragging = false;
                    lastPoint = null;
                    svg.classList.remove("call-path-panning");
                });
                svg.addEventListener("keydown", function (event) {
                    if (event.target !== svg) {
                        return;
                    }
                    var panStep = 42;
                    if (event.key === "ArrowLeft") {
                        graphX += panStep;
                    } else if (event.key === "ArrowRight") {
                        graphX -= panStep;
                    } else if (event.key === "ArrowUp") {
                        graphY += panStep;
                    } else if (event.key === "ArrowDown") {
                        graphY -= panStep;
                    } else if (event.key === "+" || event.key === "=") {
                        zoomAt(1.2, {
                            x: svg.viewBox.baseVal.width / 2,
                            y: svg.viewBox.baseVal.height / 2
                        });
                        event.preventDefault();
                        return;
                    } else if (event.key === "-" || event.key === "_") {
                        zoomAt(0.8, {
                            x: svg.viewBox.baseVal.width / 2,
                            y: svg.viewBox.baseVal.height / 2
                        });
                        event.preventDefault();
                        return;
                    } else if (event.key === "0") {
                        fitGraph();
                        event.preventDefault();
                        return;
                    } else {
                        return;
                    }
                    event.preventDefault();
                    updateGraphTransform();
                });
            }
            if (treeExpand) {
                treeExpand.addEventListener("click", function () {
                    treeBranches.forEach(function (branch) {
                        branch.open = true;
                    });
                });
            }
            if (treeCollapse) {
                treeCollapse.addEventListener("click", function () {
                    treeBranches.forEach(function (branch) {
                        branch.open = false;
                    });
                });
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
                    applyLayout(currentLayout);
                });
            }
            syncViewportCoordinates();
            if (layoutSelect) {
                applyLayout(layoutSelect.value);
            } else {
                initialGraphView();
            }
            if (svg && "ResizeObserver" in window) {
                new ResizeObserver(function () {
                    syncViewportCoordinates();
                    fitGraph();
                }).observe(svg);
            }
        });
    }());
    </script>
</body>
</html>
"""
        theme_ids = ",".join(theme_id for theme_id, _ in _HTML_THEMES)
        default_position = next(
            index
            for index, (theme_id, _) in enumerate(_HTML_THEMES, 1)
            if theme_id == _DEFAULT_HTML_THEME
        )
        return (
            template.replace("{THEME_OPTIONS}", self._theme_options())
            .replace("{THEME_IDS}", theme_ids)
            .replace("{THEME_STORAGE_KEY}", _THEME_STORAGE_KEY)
            .replace("{DEFAULT_THEME_POSITION}", str(default_position))
            .replace("{DEFAULT_THEME}", _DEFAULT_HTML_THEME)
        )

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
        self._code_ref_index += 1
        tooltip_id = f"code-preview-{self._code_ref_index}"
        return (
            f'<span class="code-ref" tabindex="0" aria-describedby="{tooltip_id}">'
            f"{html.escape(label)}"
            f'<span class="hover-tooltip" id="{tooltip_id}" role="tooltip">{context}</span>'
            f"</span>"
        )

    def format(self, report: AnalysisReport) -> str:
        """Format an analysis report as interactive HTML."""
        self._code_ref_index = 0
        content_lines = []

        # Header
        content_lines.extend(
            [
                '<header class="report-hero">',
                '<p class="report-kicker">Static blast-radius analysis</p>',
                "<h1>FastAPI Endpoint Change Detector</h1>",
                '<p class="report-subtitle">Explore affected routes, evidence, and condensed '
                "static call paths without implying runtime execution.</p>",
                "</header>",
            ]
        )

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
                confidence_class = self._confidence_color(candidate.confidence)
                content_lines.append(f'<div class="endpoint-card {confidence_class}">')
                content_lines.append('<div class="endpoint-header">')
                for method in endpoint.methods:
                    content_lines.append(
                        f'<span class="method-badge method-{method.value}">{method.value}</span>'
                    )
                content_lines.append(
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
                content_lines.append('<div class="orphan-change">')
                content_lines.append(
                    f'<div class="orphan-change-title">📄 {html.escape(file_name)}</div>'
                )
                content_lines.append(
                    f'<div class="orphan-change-path"><code>{html.escape(oc.file_path)}</code></div>'
                )
                content_lines.append(
                    f'<div class="orphan-change-lines">{html.escape(oc.format_lines())}</div>'
                )
                content_lines.append(
                    f'<div class="orphan-change-reason"><em>{html.escape(oc.reason)}</em></div>'
                )
                content_lines.append("</div>")

            content_lines.append('<div class="orphan-tip">')
            content_lines.append("<strong>💡 Tip:</strong> Orphan changes may indicate:")
            content_lines.append("<ul>")
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
        return rendered.replace("</main>", "\n".join(details) + "\n</main>", 1)

    def format_endpoints(self, endpoints: list[Endpoint]) -> str:
        """Format a list of endpoints as an HTML table."""
        self._code_ref_index = 0
        content_lines = []

        content_lines.extend(
            [
                '<header class="report-hero">',
                '<p class="report-kicker">Endpoint inventory</p>',
                "<h1>FastAPI Endpoints</h1>",
                '<p class="report-subtitle">Discovered routes, handlers, locations, and '
                "surface contracts.</p>",
                "</header>",
            ]
        )

        if not endpoints:
            content_lines.append('<p class="no-endpoints">No endpoints found.</p>')
        else:
            content_lines.append(f"<p><strong>Total:</strong> {len(endpoints)} endpoints</p>")

            content_lines.append('<div class="table-wrap">')
            content_lines.append("<table>")
            content_lines.append('<caption class="sr-only">Discovered FastAPI endpoints</caption>')
            content_lines.append("<thead>")
            content_lines.append("<tr>")
            content_lines.append('<th scope="col">Method(s)</th>')
            content_lines.append('<th scope="col">Path</th>')
            content_lines.append('<th scope="col">Handler</th>')
            content_lines.append('<th scope="col">Location</th>')
            content_lines.append('<th scope="col">Discovery</th>')
            content_lines.append('<th scope="col">Surface contract</th>')
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
            content_lines.append("</div>")

        content = "\n".join(content_lines)
        return self._get_html_template().replace("{CONTENT}", content)
