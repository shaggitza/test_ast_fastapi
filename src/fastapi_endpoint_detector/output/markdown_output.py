"""
Markdown output formatter.
"""

from pathlib import Path

from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointInventory
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
        if report.candidate_endpoints:
            lines.append(f"- **Reachable Candidates:** {len(report.candidate_endpoints)}")
        lines.append(
            f"- **Orphan Changes:** {report.total_orphan_lines} lines in {report.orphan_count} files"
        )
        if report.analysis_duration_ms:
            lines.append(f"- **Analysis Time:** {report.analysis_duration_ms:.2f}ms")
        if report.effect_contract_audit is not None:
            audit = report.effect_contract_audit
            lines.append(
                f"- **Effect Contract Audit:** {audit.summary.matched_calls} matched calls / "
                f"{audit.summary.physical_occurrences} physical calls"
            )
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
                    if ep.surface is not None:
                        lines.append(
                            f"- **Surface contract:** `{ep.surface.contract_id}` "
                            f"({ep.surface.match_kind.value}) at "
                            f"`{ep.surface.registration_file}:{ep.surface.registration_line}`; "
                            f"callback `{ep.surface.callback_mode.value}`; execution "
                            f"`{ep.surface.execution_mode.value}`; config "
                            f"`{ep.surface.config_hash}`"
                        )
                    lines.append(f"- **Reason:** {ae.reason}")
                    if ep.discovery_conditions:
                        lines.append("- **Discovery:** `CONDITIONAL`")
                        for condition in ep.discovery_conditions:
                            lines.append(
                                f"  - `{condition.source_path}:{condition.source_line}`: "
                                f"{condition.reason}"
                            )
                    for evidence in ae.effect_evidence:
                        lines.append(
                            f"- **Effect ({evidence.status.value}/{evidence.disposition.value}):** "
                            f"{evidence.summary}"
                        )
                    for contract_evidence in ae.contract_evidence:
                        lines.append(
                            f"- **Declared contract `{contract_evidence.contract.id}`:** "
                            f"{contract_evidence.contract.operation.value}/"
                            f"{contract_evidence.contract.channel.value}; "
                            "change-to-call flow not established"
                        )

                    if ae.dependency_chain and len(ae.dependency_chain) > 1:
                        chain = " → ".join(f"`{dep}`" for dep in ae.dependency_chain)
                        lines.append(f"- **Chain:** {chain}")

                    # Show call stack if available
                    if ae.call_stacks:
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

        additional = [
            candidate
            for candidate in report.candidate_endpoints
            if candidate not in report.affected_endpoints
        ]
        if additional:
            lines.append("## Additional Reachable Candidates")
            lines.append("")
            lines.append("_Retained for inspection; not selected by the legacy threshold._")
            lines.append("")
            for candidate in additional:
                methods = ", ".join(method.value for method in candidate.endpoint.methods)
                discovery = (
                    " — **CONDITIONAL DISCOVERY**"
                    if candidate.endpoint.discovery_conditions
                    else ""
                )
                lines.append(
                    f"- **{methods} `{candidate.endpoint.path}`** "
                    f"({candidate.confidence.value}){discovery}"
                )
                if candidate.endpoint.surface is not None:
                    surface = candidate.endpoint.surface
                    lines.append(
                        f"  - Surface contract `{surface.contract_id}` "
                        f"({surface.match_kind.value}) at "
                        f"`{surface.registration_file}:{surface.registration_line}`; "
                        f"callback `{surface.callback_mode.value}`; execution "
                        f"`{surface.execution_mode.value}`; config `{surface.config_hash}`"
                    )
                for condition in candidate.endpoint.discovery_conditions:
                    lines.append(
                        f"  - Discovery condition: `{condition.source_path}:"
                        f"{condition.source_line}` — {condition.reason}"
                    )
                for evidence in candidate.effect_evidence:
                    lines.append(f"  - {evidence.disposition.value}: {evidence.summary}")
                for contract_evidence in candidate.contract_evidence:
                    lines.append(
                        f"  - Declared contract `{contract_evidence.contract.id}`: "
                        "change-to-call flow not established"
                    )
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

    def format_inventory(self, inventory: EndpointInventory) -> str:
        """Format endpoints with visible whole-inventory strength."""
        lines = [f"**Inventory status:** `{inventory.status.value}`", ""]
        for item in inventory.limitations:
            lines.append(f"- Limitation: `{item.source_path}:{item.source_line}` — {item.reason}")
        if inventory.limitations:
            lines.append("")
        lines.append(self.format_endpoints(inventory.endpoints))
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
        lines.append("| Method(s) | Path | Handler | File | Line | Discovery | Surface contract |")
        lines.append("|-----------|------|---------|------|------|-----------|------------------|")

        for ep in endpoints:
            methods = ", ".join(m.value for m in ep.methods)
            file_name = ep.handler.file_path.name
            surface = (
                f"`{ep.surface.contract_id}` ({ep.surface.match_kind.value}; "
                f"{ep.surface.callback_mode.value}/{ep.surface.execution_mode.value})"
                if ep.surface is not None
                else ""
            )
            lines.append(
                f"| {methods} | `{ep.path}` | `{ep.handler.name}` | "
                f"`{file_name}` | {ep.handler.line_number} | "
                f"{ep.discovery_status.value} | {surface} |"
            )

        lines.append("")
        return "\n".join(lines)
