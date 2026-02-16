"""
Markdown output formatter.
"""

from fastapi_endpoint_detector.models.endpoint import Endpoint
from fastapi_endpoint_detector.models.report import AnalysisReport, ConfidenceLevel
from fastapi_endpoint_detector.output.formatters import BaseFormatter, register_formatter


@register_formatter("markdown")
class MarkdownFormatter(BaseFormatter):
    """
    Format output as Markdown.
    """

    def _confidence_emoji(self, confidence: ConfidenceLevel) -> str:
        """Get an emoji for a confidence level."""
        emojis = {
            ConfidenceLevel.HIGH: "🔴",
            ConfidenceLevel.MEDIUM: "🟡",
            ConfidenceLevel.LOW: "🟢",
        }
        return emojis.get(confidence, "⚪")

    def format(self, report: AnalysisReport) -> str:
        """Format an analysis report as Markdown."""
        lines = []

        # Header
        lines.append("# FastAPI Endpoint Change Detector")
        lines.append("")
        lines.append("## Analysis Report")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **App Path:** `{report.app_path}`")
        lines.append(f"- **Diff Source:** `{report.diff_source}`")
        lines.append(f"- **Total Endpoints:** {report.total_endpoints}")
        lines.append(
            f"- **Files Changed:** {report.total_files_changed} ({report.python_files_changed} Python)"
        )
        lines.append(f"- **Affected Endpoints:** {report.affected_count}")
        lines.append(f"- **Orphan Changes:** {report.total_orphan_lines} lines in {report.orphan_count} files")
        if report.analysis_duration_ms:
            lines.append(f"- **Analysis Time:** {report.analysis_duration_ms:.2f}ms")
        lines.append("")

        # Affected endpoints
        if report.affected_endpoints:
            lines.append("## Affected Endpoints")
            lines.append("")

            # Group by confidence
            for confidence in [ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW]:
                endpoints = report.get_endpoints_by_confidence(confidence)
                if not endpoints:
                    continue

                emoji = self._confidence_emoji(confidence)
                lines.append(
                    f"### {emoji} {confidence.value.upper()} Confidence ({len(endpoints)})"
                )
                lines.append("")

                for ae in endpoints:
                    ep = ae.endpoint
                    methods = ", ".join(m.value for m in ep.methods)
                    lines.append(f"#### {methods} `{ep.path}`")
                    lines.append("")
                    lines.append(f"- **Handler:** `{ep.handler.name}`")
                    lines.append(
                        f"- **Location:** `{ep.handler.file_path}:{ep.handler.line_number}`"
                    )
                    lines.append(f"- **Reason:** {ae.reason}")

                    if ae.dependency_chain and len(ae.dependency_chain) > 1:
                        chain = " → ".join(f"`{dep}`" for dep in ae.dependency_chain)
                        lines.append(f"- **Chain:** {chain}")

                    # Show call stack if available
                    if ae.call_stack:
                        lines.append("")
                        lines.append("**Call Stack:**")
                        lines.append("")
                        lines.append("```python")
                        traceback_lines = ae.format_traceback().strip().split("\n")
                        for line in traceback_lines:
                            lines.append(line)
                        lines.append("```")

                    lines.append("")
        else:
            lines.append("## ✅ No Affected Endpoints")
            lines.append("")
            lines.append("No endpoints were affected by the changes.")
            lines.append("")

        # Orphan changes
        if report.orphan_changes:
            lines.append("## ⚠️ Orphan Code Changes")
            lines.append("")
            lines.append(
                f"_Changes not related to any endpoint "
                f"({report.total_orphan_lines} lines in {report.orphan_count} files)_"
            )
            lines.append("")
            
            for oc in report.orphan_changes:
                from pathlib import Path
                file_name = Path(oc.file_path).name
                lines.append(f"### 📄 `{file_name}`")
                lines.append("")
                lines.append(f"- **File:** `{oc.file_path}`")
                lines.append(f"- **Changes:** {oc.format_lines()}")
                lines.append(f"- **Reason:** {oc.reason}")
                lines.append("")
            
            lines.append("> **💡 Tip:** Orphan changes may indicate:")
            lines.append("> - Unused or dead code")
            lines.append("> - Code with incorrect types preventing dependency analysis")
            lines.append("> - Utility code not called by any endpoint")
            lines.append("> - Code outside the analyzed application scope")
            lines.append("")

        # Errors and warnings
        if report.errors:
            lines.append("## ❌ Errors")
            lines.append("")
            for error in report.errors:
                lines.append(f"- {error}")
            lines.append("")

        if report.warnings:
            lines.append("## ⚠️ Warnings")
            lines.append("")
            for warning in report.warnings:
                lines.append(f"- {warning}")
            lines.append("")

        return "\n".join(lines)

    def format_endpoints(self, endpoints: list[Endpoint]) -> str:
        """Format a list of endpoints as a Markdown table."""
        if not endpoints:
            return "_No endpoints found._\n"

        lines = []
        lines.append("# FastAPI Endpoints")
        lines.append("")
        lines.append(f"**Total:** {len(endpoints)} endpoints")
        lines.append("")

        # Create table
        lines.append("| Method(s) | Path | Handler | File | Line |")
        lines.append("|-----------|------|---------|------|------|")

        for ep in endpoints:
            methods = ", ".join(m.value for m in ep.methods)
            file_name = ep.handler.file_path.name
            lines.append(
                f"| {methods} | `{ep.path}` | `{ep.handler.name}` | "
                f"`{file_name}` | {ep.handler.line_number} |"
            )

        lines.append("")
        return "\n".join(lines)
