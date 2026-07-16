"""
Human-readable text output formatter.
"""

from io import StringIO
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointInventory
from fastapi_endpoint_detector.models.report import AnalysisReport, ConfidenceLevel
from fastapi_endpoint_detector.output.formatters import BaseFormatter, register_formatter


@register_formatter("text")
class TextFormatter(BaseFormatter):
    """
    Format output as human-readable text using Rich.
    """

    def __init__(self, colorize: bool = True) -> None:
        """
        Initialize the text formatter.

        Args:
            colorize: Whether to use colors in output.
        """
        self.colorize = colorize

    def _confidence_style(self, confidence: ConfidenceLevel) -> str:
        """Get the style for a confidence level."""
        if not self.colorize:
            return ""

        styles = {
            ConfidenceLevel.HIGH: "bold red",
            ConfidenceLevel.MEDIUM: "yellow",
            ConfidenceLevel.LOW: "dim",
        }
        return styles.get(confidence, "")

    def _confidence_icon(self, confidence: ConfidenceLevel) -> str:
        """Get an icon for a confidence level."""
        icons = {
            ConfidenceLevel.HIGH: "🔴",
            ConfidenceLevel.MEDIUM: "🟡",
            ConfidenceLevel.LOW: "🟢",
        }
        return icons.get(confidence, "⚪")

    def format(self, report: AnalysisReport) -> str:
        """Format an analysis report as text."""
        output = StringIO()
        console = Console(file=output, force_terminal=self.colorize, width=120)

        # Header
        console.print()
        console.print(
            Panel.fit(
                "[bold]FastAPI Endpoint Change Detector[/bold]\nAnalysis Report",
                border_style="blue",
            )
        )
        console.print()

        # Summary
        console.print("[bold]Summary[/bold]")
        console.print(f"  App Path: {report.app_path}")
        console.print(f"  Diff Source: {report.diff_source}")
        console.print(f"  Total Endpoints: {report.total_endpoints}")
        console.print(
            f"  Files Changed: {report.total_files_changed} ({report.python_files_changed} Python)"
        )
        console.print(f"  Affected Endpoints: {report.affected_count}")
        if report.candidate_endpoints:
            console.print(f"  Reachable Candidates: {len(report.candidate_endpoints)}")
        if report.analysis_duration_ms:
            console.print(f"  Analysis Time: {report.analysis_duration_ms:.2f}ms")
        if report.effect_contract_audit is not None:
            audit = report.effect_contract_audit
            console.print(
                "  Effect Contract Audit: "
                f"{audit.summary.matched_calls} matched calls / "
                f"{audit.summary.physical_occurrences} physical calls"
            )
        if report.resource_coupling_graph is not None:
            graph = report.resource_coupling_graph
            policy = (
                "report-only; does not change candidates"
                if graph.mode == "report_only"
                else "exact-callsite LOW candidate mode"
            )
            console.print(
                "  Resource Coupling: "
                f"{len(graph.edges)} edges / {len(graph.diagnostics)} diagnostics ({policy})"
            )
        if report.sql_transaction_report is not None:
            transaction = report.sql_transaction_report
            console.print(
                "  SQL Transactions: "
                f"{transaction.summary.endpoints_with_staging} staged endpoints / "
                f"{transaction.summary.transaction_begins} transaction begins / "
                f"{transaction.summary.savepoint_begins} savepoints / "
                f"{transaction.summary.outcome_unresolved} unresolved outcomes "
                "(diagnostic only; persistence not established)"
            )
        if report.sql_transaction_path_report is not None:
            paths = report.sql_transaction_path_report
            console.print(
                "  SQL Ordered Paths: "
                f"{paths.summary.ordered_paths} explicit boundaries / "
                f"{paths.summary.context_manager_paths} context exits / "
                f"{paths.summary.unresolved_pairs} unresolved pairs "
                "(lexical and conditional only; persistence not established)"
            )
        console.print()

        # Affected endpoints
        if report.affected_endpoints:
            console.print("[bold]Affected Endpoints[/bold]")
            console.print()

            # Group by confidence
            for confidence in [ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW]:
                endpoints = report.get_endpoints_by_confidence(confidence)
                if not endpoints:
                    continue

                icon = self._confidence_icon(confidence)
                style = self._confidence_style(confidence)
                console.print(
                    f"  {icon} [bold]{confidence.value.upper()} Confidence[/bold] ({len(endpoints)})"
                )

                for ae in endpoints:
                    ep = ae.endpoint
                    methods = ",".join(m.value for m in ep.methods)
                    console.print(f"    [{style}]{methods} {ep.path}[/{style}]")
                    console.print(
                        f"      Handler: {ep.handler.name} ({ep.handler.file_path}:{ep.handler.line_number})"
                    )
                    if ep.surface is not None:
                        console.print(
                            f"      Surface contract: {ep.surface.contract_id} "
                            f"({ep.surface.match_kind.value}) at "
                            f"{ep.surface.registration_file}:{ep.surface.registration_line}; "
                            f"callback {ep.surface.callback_mode.value}; execution "
                            f"{ep.surface.execution_mode.value}; config {ep.surface.config_hash}"
                        )
                    console.print(f"      Reason: {ae.reason}")
                    if ep.discovery_conditions:
                        console.print("      Discovery: CONDITIONAL")
                        for condition in ep.discovery_conditions:
                            console.print(
                                f"        {condition.source_path}:{condition.source_line}: "
                                f"{condition.reason}"
                            )
                    if ae.dependency_chain and len(ae.dependency_chain) > 1:
                        chain = " → ".join(ae.dependency_chain)
                        console.print(f"      Chain: {chain}")
                    for evidence in ae.effect_evidence:
                        console.print(
                            f"      Effect: [{evidence.status.value} / "
                            f"{evidence.disposition.value}] {evidence.summary}"
                        )
                    for contract_evidence in ae.contract_evidence:
                        console.print(
                            "      Declared contract: "
                            f"{contract_evidence.contract.id} "
                            f"({contract_evidence.contract.operation.value}/"
                            f"{contract_evidence.contract.channel.value}); "
                            "change-to-call flow not established"
                        )
                    for coupling in ae.resource_coupling_evidence:
                        console.print(
                            "      Potential cross-request coupling: exact added producer "
                            f"callsite; {coupling.strength.value}; LOW-only"
                        )

                    # Show traceback-style call stack if available
                    if ae.call_stacks:
                        console.print()
                        console.print("      [bold cyan]Call Stack (traceback style):[/bold cyan]")
                        traceback_lines = ae.format_traceback().strip().split("\n")
                        for line in traceback_lines:
                            console.print(f"      {line}")
                    console.print()
        else:
            console.print("[green]No endpoints selected by the confidence threshold.[/green]")
            console.print()

        additional = [
            candidate
            for candidate in report.candidate_endpoints
            if candidate not in report.affected_endpoints
        ]
        if additional:
            console.print("[bold]Additional Reachable Candidates[/bold]")
            console.print(
                "[dim]Retained for inspection; not selected by the legacy threshold.[/dim]"
            )
            for candidate in additional:
                methods = ",".join(method.value for method in candidate.endpoint.methods)
                discovery = (
                    " [CONDITIONAL DISCOVERY]" if candidate.endpoint.discovery_conditions else ""
                )
                console.print(
                    f"  {methods} {candidate.endpoint.path} "
                    f"({candidate.confidence.value}){discovery}"
                )
                if candidate.endpoint.surface is not None:
                    surface = candidate.endpoint.surface
                    console.print(
                        f"    surface contract {surface.contract_id} "
                        f"({surface.match_kind.value}) at "
                        f"{surface.registration_file}:{surface.registration_line}; "
                        f"callback {surface.callback_mode.value}; execution "
                        f"{surface.execution_mode.value}; config {surface.config_hash}"
                    )
                for condition in candidate.endpoint.discovery_conditions:
                    console.print(
                        f"    {condition.source_path}:{condition.source_line}: {condition.reason}",
                        markup=False,
                    )
                for evidence in candidate.effect_evidence:
                    console.print(f"    {evidence.disposition.value}: {evidence.summary}")
                for contract_evidence in candidate.contract_evidence:
                    console.print(
                        f"    declared contract {contract_evidence.contract.id}: "
                        "change-to-call flow not established"
                    )
                for coupling in candidate.resource_coupling_evidence:
                    console.print(
                        "    potential cross-request coupling: exact added producer "
                        f"callsite; {coupling.strength.value}; LOW-only"
                    )
            console.print()

        # Orphan changes
        if report.orphan_changes:
            console.print("[bold yellow]⚠️  Orphan Code Changes[/bold yellow]")
            console.print(
                f"[dim]Changes not related to any endpoint ({report.total_orphan_lines} lines in {report.orphan_count} files)[/dim]"
            )
            console.print()

            for oc in report.orphan_changes:
                file_name = Path(oc.file_path).name
                console.print(f"  📄 [cyan]{file_name}[/cyan] ({oc.file_path})")
                console.print(f"     {oc.format_lines()}")
                console.print(f"     [dim]Reason: {oc.reason}[/dim]")
                console.print()

            console.print("[dim]💡 Tip: Orphan changes may indicate:[/dim]")
            console.print("[dim]   • Unused or dead code[/dim]")
            console.print(
                "[dim]   • Code with incorrect types preventing dependency analysis[/dim]"
            )
            console.print("[dim]   • Utility code not called by any endpoint[/dim]")
            console.print("[dim]   • Code outside the analyzed application scope[/dim]")
            console.print()

        # Errors and warnings
        if report.errors:
            console.print("[bold red]Errors[/bold red]")
            for error in report.errors:
                console.print(f"  ❌ {error}")
            console.print()

        if report.warnings:
            console.print("[bold yellow]Warnings[/bold yellow]")
            for warning in report.warnings:
                console.print(f"  ⚠️  {warning}")
            console.print()

        return output.getvalue()

    def format_inventory(self, inventory: EndpointInventory) -> str:
        """Format endpoints with visible whole-inventory strength."""
        details = [f"Inventory status: {inventory.status.value}"]
        details.extend(
            f"Limitation: {item.source_path}:{item.source_line}: {item.reason}"
            for item in inventory.limitations
        )
        return "\n".join(details) + "\n" + self.format_endpoints(inventory.endpoints)

    def format_endpoints(self, endpoints: list[Endpoint]) -> str:
        """Format a list of endpoints as a table."""
        output = StringIO()
        console = Console(file=output, force_terminal=self.colorize, width=120)

        if not endpoints:
            console.print("[dim]No endpoints found.[/dim]")
            return output.getvalue()

        table = Table(title="FastAPI Endpoints", show_header=True, header_style="bold")
        table.add_column("Method(s)", style="cyan")
        table.add_column("Path", style="green")
        table.add_column("Handler", style="yellow")
        table.add_column("File", style="dim")
        table.add_column("Line", justify="right")
        table.add_column("Discovery")
        table.add_column("Surface contract")

        for ep in endpoints:
            methods = ",".join(m.value for m in ep.methods)
            file_name = ep.handler.file_path.name
            table.add_row(
                methods,
                ep.path,
                ep.handler.name,
                file_name,
                str(ep.handler.line_number),
                ep.discovery_status.value,
                (
                    f"{ep.surface.contract_id} ({ep.surface.match_kind.value}) "
                    f"{ep.surface.callback_mode.value}/{ep.surface.execution_mode.value} "
                    f"{ep.surface.config_hash}"
                    if ep.surface is not None
                    else ""
                ),
            )

        console.print(table)
        console.print(f"\nTotal: {len(endpoints)} endpoints")

        return output.getvalue()
